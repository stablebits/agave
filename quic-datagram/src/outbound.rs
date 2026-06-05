//! Outbound (dialer) side: egress always dials.
//!
//! The first datagram to a peer opens a connection; concurrent egress while a
//! dial is in flight is dropped; an address change redials the new address; and
//! a connection that completes under a rotated local identity is discarded.
//!
//! Connections here are **send-only** - the peer sends to us over its own
//! outbound connection (which is our inbound). So the dial task sends the
//! trigger datagram and then just waits for the connection to close in order to
//! reap its slot; it never reads. At most one entry exists per peer we send to.

use {
    crate::{
        MAX_PEERS, close_codes,
        error::Error,
        stats::{QuicDatagramStats, add, record_error},
    },
    bytes::Bytes,
    log::{error, info},
    parking_lot::Mutex,
    quinn::{Connection, Endpoint},
    solana_pubkey::Pubkey,
    solana_tls_utils::{get_remote_pubkey, socket_addr_to_quic_server_name},
    std::{
        collections::{HashMap, hash_map::Entry},
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    },
};

/// Monotonic counter bumped on every local identity rotation. A dial task
/// captures the generation when its slot is reserved and passes it back into
/// [`Outbound::install`]; a mismatch means our identity rotated mid-dial and
/// the connection (authenticated under our previous cert) must be discarded.
pub(crate) type IdGeneration = u64;

/// Per-peer outbound connection map. Holds up to [`crate::MAX_PEERS`] entries.
///
/// A plain `Mutex<HashMap>`: the control loop (egress) is the dominant
/// accessor, with dial tasks installing / reaping on connection-lifecycle
/// events. Every access is brief, synchronous, and never held across an
/// `.await`, so a single lock neither deadlocks the runtime nor contends
/// meaningfully at handshake / egress rates. `generation` stays a standalone
/// atomic: it is read before the map is locked (so a rotation can be detected
/// without taking the lock) and bumped first in [`Self::clear_for_id_change`].
pub(crate) struct Outbound {
    inner: Mutex<HashMap<Pubkey, OutboundEntry>>,
    generation: AtomicU64,
}

enum OutboundEntry {
    /// A slot reserved by the control loop before spawning a dial task,
    /// tagged with the generation live at reservation time.
    Dialing(IdGeneration),
    /// A live send connection for one peer.
    Established(Connection),
}

/// What the control loop should do with an egress datagram.
pub(crate) enum Dispatch {
    /// A cached connection to the right address existed; the datagram was
    /// queued on it inside [`Outbound::dispatch`] (caller does nothing more).
    Sent,
    /// A dial for this peer is already in flight; the datagram was dropped.
    Dialing,
    /// The slot now holds `Dialing`; the caller must spawn a dial task with
    /// the returned generation and carry the datagram in as the trigger.
    Dial { generation: IdGeneration },
}

/// Outcome of a dial task installing its completed connection.
enum Install {
    /// Connection installed (fresh slot, or replacing our own placeholder /
    /// a stale connection at a changed address).
    Installed,
    /// Table at cap and this is a fresh peer; caller closes with `TABLE_FULL`.
    Rejected,
    /// Identity rotated mid-dial; caller closes with `IDENTITY_ROTATED`.
    Stale,
}

impl Outbound {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
        }
    }

    /// Live entry count (`Dialing` + `Established`).
    pub(crate) fn len(&self) -> u64 {
        self.inner.lock().len() as u64
    }

    fn current_generation(&self) -> IdGeneration {
        self.generation.load(Ordering::SeqCst)
    }

    /// Decide what to do with an egress datagram for `peer` at `addr`:
    /// * vacant -> reserve a `Dialing` slot and ask for a dial task,
    /// * dial already in flight -> drop,
    /// * established to `addr` -> send,
    /// * established to a different address -> the peer moved: close it with
    ///   `PEER_MOVED`, reserve a fresh `Dialing` slot, and ask for a redial.
    pub(crate) fn dispatch(
        &self,
        peer: Pubkey,
        addr: SocketAddr,
        bytes: &Bytes,
        stats: &QuicDatagramStats,
    ) -> Dispatch {
        let generation = self.current_generation();
        match self.inner.lock().entry(peer) {
            Entry::Vacant(slot) => {
                slot.insert(OutboundEntry::Dialing(generation));
                Dispatch::Dial { generation }
            }
            Entry::Occupied(mut slot) => match slot.get() {
                OutboundEntry::Dialing(_) => {
                    stats
                        .egress_dropped_dial_in_progress
                        .fetch_add(1, Ordering::Relaxed);
                    Dispatch::Dialing
                }
                OutboundEntry::Established(conn) if conn.remote_address() == addr => {
                    match conn.send_datagram(bytes.clone()) {
                        Ok(()) => add(&stats.datagrams_sent),
                        Err(e) => record_error(&Error::from(e), stats),
                    }
                    Dispatch::Sent
                }
                OutboundEntry::Established(_) => {
                    let old =
                        std::mem::replace(slot.get_mut(), OutboundEntry::Dialing(generation));
                    if let OutboundEntry::Established(old_conn) = old {
                        close_codes::PEER_MOVED.close(&old_conn);
                        stats
                            .connection_evicted_peer_moved
                            .fetch_add(1, Ordering::Relaxed);
                        info!("peer {peer} moved; re-dialing at {addr}");
                    }
                    Dispatch::Dial { generation }
                }
            },
        }
    }

    /// Install a dial task's completed `conn` for `peer`. The slot normally
    /// holds our own `Dialing` placeholder; we replace it with `Established`.
    fn install(&self, peer: Pubkey, conn: Connection, gen_at_start: IdGeneration) -> Install {
        if self.current_generation() != gen_at_start {
            return Install::Stale;
        }
        let mut map = self.inner.lock();
        let at_cap = map.len() as u64 >= MAX_PEERS;
        match map.entry(peer) {
            Entry::Vacant(slot) => {
                if at_cap {
                    return Install::Rejected;
                }
                slot.insert(OutboundEntry::Established(conn));
                Install::Installed
            }
            Entry::Occupied(mut slot) => {
                let old = std::mem::replace(slot.get_mut(), OutboundEntry::Established(conn));
                // Replacing our own `Dialing` placeholder (normal) or a stale
                // `Established` left at a changed address.
                if let OutboundEntry::Established(old_conn) = old {
                    close_codes::PEER_MOVED.close(&old_conn);
                }
                Install::Installed
            }
        }
    }

    /// Drop the slot for `peer` iff it still holds a `Dialing` placeholder at
    /// the same generation (a dial that failed before installing).
    fn clear_dialing(&self, peer: &Pubkey, generation: IdGeneration) {
        if let Entry::Occupied(slot) = self.inner.lock().entry(*peer)
            && matches!(slot.get(), OutboundEntry::Dialing(g) if *g == generation)
        {
            slot.remove();
        }
    }

    /// Drop the slot for `peer` iff it still holds the `Established` with this
    /// `stable_id` (a later redial may already have taken the slot).
    fn reap(&self, peer: &Pubkey, stable_id: usize) {
        if let Entry::Occupied(slot) = self.inner.lock().entry(*peer)
            && matches!(slot.get(), OutboundEntry::Established(c) if c.stable_id() == stable_id)
        {
            slot.remove();
        }
    }

    /// Bump the identity generation and wipe the table, closing every live
    /// connection with `IDENTITY_ROTATED`. Any in-flight dial that completes
    /// afterwards hits `Stale` in [`Self::install`] and bails. Returns the
    /// number of entries dropped.
    pub(crate) fn clear_for_id_change(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::SeqCst);
        let mut map = self.inner.lock();
        let evicted = map.len() as u64;
        for entry in map.values() {
            if let OutboundEntry::Established(conn) = entry {
                close_codes::IDENTITY_ROTATED.close(conn);
            }
        }
        map.clear();
        evicted
    }
}

/// Spawn a task that dials `peer` at `addr`, installs the connection, sends the
/// `trigger` datagram, then waits for the connection to close and reaps its
/// slot so the next egress redials. Returns immediately.
pub(crate) fn spawn_dial(
    endpoint: Endpoint,
    outbound: Arc<Outbound>,
    peer: Pubkey,
    addr: SocketAddr,
    generation: IdGeneration,
    trigger: Bytes,
    stats: Arc<QuicDatagramStats>,
) {
    tokio::spawn(async move {
        if let Err(e) = dial(&endpoint, &outbound, peer, addr, generation, trigger, &stats).await {
            error!("dial to ({peer}, {addr}) failed: {e:?}");
            record_error(&e, &stats);
            // Release the reserved slot so a later egress can redial.
            outbound.clear_dialing(&peer, generation);
        }
    });
}

async fn dial(
    endpoint: &Endpoint,
    outbound: &Outbound,
    peer: Pubkey,
    addr: SocketAddr,
    generation: IdGeneration,
    trigger: Bytes,
    stats: &QuicDatagramStats,
) -> Result<(), Error> {
    let server_name = socket_addr_to_quic_server_name(addr);
    let connection = endpoint.connect(addr, &server_name)?.await?;

    // The peer's attested identity must match the pubkey we targeted.
    let attested = get_remote_pubkey(&connection).ok_or(Error::InvalidIdentity(addr))?;
    if attested != peer {
        close_codes::INVALID_IDENTITY.close(&connection);
        return Err(Error::InvalidIdentity(addr));
    }

    match outbound.install(peer, connection.clone(), generation) {
        Install::Rejected => {
            close_codes::TABLE_FULL.close(&connection);
            return Err(Error::TableFull);
        }
        Install::Stale => {
            close_codes::IDENTITY_ROTATED.close(&connection);
            return Err(Error::IdentityRotated(peer));
        }
        Install::Installed => stats.record_connection_count(outbound.len()),
    }

    // Send the trigger that started this dial. A quinn-level failure is
    // recorded but not fatal - the connection is healthy.
    match connection.send_datagram(trigger) {
        Ok(()) => add(&stats.datagrams_sent),
        Err(e) => record_error(&Error::from(e), stats),
    }

    // Send-only: wait for the connection to close, then reap.
    let stable_id = connection.stable_id();
    connection.closed().await;
    outbound.reap(&peer, stable_id);
    Ok(())
}
