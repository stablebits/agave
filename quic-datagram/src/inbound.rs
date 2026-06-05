//! Inbound (acceptor) side: accept a handshake, gate by banlist + allowlist,
//! then run the receive loop.
//!
//! Inbound connections are **receive-only**. A sender may hold more than one at
//! once (e.g. a redial racing a not-yet-timed-out idle connection) and that is
//! harmless: duplicate votes/certs are idempotent downstream, and a sender that
//! delivers an invalid message is banned by pubkey at the BLS-sigverify layer -
//! the shared banlist then closes every connection it holds. So we keep no
//! per-peer connection table; the only shared state is the admission limiter
//! ([`Inbound`]) - a global cap plus a small per-identity cap that stops one
//! sender from monopolizing inbound capacity and starving others. The handshake
//! is CPU-heavy, so each inbound runs on its own task and never blocks accept.

use {
    crate::{
        Banlist, MAX_CONNECTIONS_PER_PEER, MAX_PEERS,
        allowlist::Allowlist,
        close_codes,
        endpoint::Datagram,
        error::Error,
        read_loop::read_datagram_loop,
        stats::{QuicDatagramStats, record_error},
    },
    crossbeam_channel::Sender,
    log::debug,
    parking_lot::Mutex,
    quinn::Incoming,
    solana_pubkey::Pubkey,
    solana_tls_utils::get_remote_pubkey,
    std::{
        collections::{HashMap, hash_map::Entry},
        sync::Arc,
    },
};

/// Inbound admission limiter: a hard global cap ([`MAX_PEERS`]) plus a small
/// per-identity cap ([`MAX_CONNECTIONS_PER_PEER`]). The per-identity cap is the
/// load-bearing one against abuse - the global counter alone lets a few
/// allowlisted-but-hostile identities open connections up to the ceiling and
/// starve honest peers, whereas the per-identity cap bounds any single sender's
/// footprint, so exhausting the global budget would require controlling a large
/// fraction of the staked set.
///
/// `per_id` holds only a small integer per connected peer (not connection
/// handles); it is NOT a connection table. Entries are removed when their count
/// reaches zero, so the map is bounded by the live peer set.
pub(crate) struct Inbound {
    inner: Mutex<InboundState>,
}

/// The two counts under one lock, so the global total and the per-identity map
/// can never drift apart.
struct InboundState {
    total: u64,
    per_id: HashMap<Pubkey, u32>,
}

impl Inbound {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(InboundState {
                total: 0,
                per_id: HashMap::new(),
            }),
        }
    }

    /// Total live inbound connections (for the metrics gauge).
    pub(crate) fn len(&self) -> u64 {
        self.inner.lock().total
    }

    /// Reserve a slot for a connection from `peer`: global cap first, then the
    /// per-identity cap. Returns an RAII [`InboundSlot`] that releases both
    /// counts on drop, or `None` if either cap is hit (caller closes the
    /// connection).
    pub(crate) fn admit(self: &Arc<Self>, peer: Pubkey) -> Option<InboundSlot> {
        let mut state = self.inner.lock();
        if state.total >= MAX_PEERS {
            return None;
        }
        {
            let count = state.per_id.entry(peer).or_insert(0);
            if *count >= MAX_CONNECTIONS_PER_PEER {
                return None;
            }
            *count = count.saturating_add(1);
        }
        state.total = state.total.saturating_add(1);
        Some(InboundSlot {
            inbound: Arc::clone(self),
            peer,
        })
    }

    fn release(&self, peer: &Pubkey) {
        let mut state = self.inner.lock();
        state.total = state.total.saturating_sub(1);
        if let Entry::Occupied(mut e) = state.per_id.entry(*peer) {
            let remaining = e.get().saturating_sub(1);
            if remaining == 0 {
                e.remove();
            } else {
                *e.get_mut() = remaining;
            }
        }
    }
}

/// RAII guard for one admitted inbound connection. Releases the global and
/// per-identity counts when dropped - i.e. when the inbound task's read loop
/// returns, on every exit path.
pub(crate) struct InboundSlot {
    inbound: Arc<Inbound>,
    peer: Pubkey,
}

impl Drop for InboundSlot {
    fn drop(&mut self) {
        self.inbound.release(&self.peer);
    }
}

/// One accepted inbound connection's lifecycle: handshake, gate, receive loop.
pub(crate) struct InboundConnection {
    pub(crate) incoming: Incoming,
    pub(crate) ingress: Sender<Datagram>,
    pub(crate) allowlist: Arc<dyn Allowlist>,
    pub(crate) banlist: Arc<Banlist<Pubkey>>,
    /// Shared inbound admission limiter (global + per-identity caps).
    pub(crate) inbound: Arc<Inbound>,
    pub(crate) stats: Arc<QuicDatagramStats>,
}

impl InboundConnection {
    /// Spawn a task that drives this connection to completion. Returns
    /// immediately; the task logs and records any error before exiting.
    pub(crate) fn spawn(self) {
        let remote_addr = self.incoming.remote_address();
        let stats = self.stats.clone();
        tokio::spawn(async move {
            if let Err(err) = self.run().await {
                debug!("Failed processing incoming connection from ({remote_addr}): {err:?}");
                record_error(&err, &stats);
            }
        });
    }

    async fn run(self) -> Result<(), Error> {
        let remote_addr = self.incoming.remote_address();
        let connection = self.incoming.accept()?.await?;
        let Some(peer) = get_remote_pubkey(&connection) else {
            close_codes::INVALID_IDENTITY.close(&connection);
            return Err(Error::InvalidIdentity(remote_addr));
        };
        if self.banlist.is_banned(&peer) {
            close_codes::BANNED.close(&connection);
            return Err(Error::Banned(peer));
        }
        if !self.allowlist.allow(&peer) {
            close_codes::NOT_ADMITTED.close(&connection);
            return Err(Error::NotAdmitted(peer));
        }

        // Anti-DoS admission: per-identity cap then global cap. The returned
        // guard releases both counts when it drops at the end of this task.
        let Some(_slot) = self.inbound.admit(peer) else {
            close_codes::TABLE_FULL.close(&connection);
            return Err(Error::TableFull);
        };
        self.stats.record_connection_count(self.inbound.len());

        read_datagram_loop(
            connection,
            peer,
            remote_addr,
            self.ingress,
            self.allowlist,
            self.banlist,
            self.stats,
        )
        .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{
            allowlist::{AllowAll, StakedNodesAllowlist},
            endpoint::Datagram,
            testutils::{
                drain_matching, keypair_below, make_runtime, send_until_received, spawn_node_with,
            },
        },
        bytes::Bytes,
        solana_keypair::{Keypair, Signer},
        std::{collections::HashMap, sync::Arc, time::Duration},
    };

    #[test]
    fn staked_peer_is_admitted_unstaked_is_rejected() {
        let rt = make_runtime();

        let server_kp = Keypair::new();
        let server_pk = server_kp.pubkey();
        let a_kp = keypair_below(&server_pk);
        let a_pk = a_kp.pubkey();
        let admit_map: HashMap<_, _> = std::iter::once((a_pk, 100u64)).collect();
        let server = spawn_node_with(
            &rt,
            Arc::new(StakedNodesAllowlist::new(admit_map)),
            server_kp,
        );

        // Client A - admitted.
        let client_a = spawn_node_with(&rt, Arc::new(AllowAll), a_kp);
        // Client B - not admitted by the server's allowlist.
        let client_b = spawn_node_with(&rt, Arc::new(AllowAll), keypair_below(&server_pk));

        let payload_a = Bytes::from_static(b"hello-from-A");
        send_until_received(
            &rt,
            &client_a.endpoint,
            server.pubkey(),
            server.addr,
            payload_a.clone(),
            &server.ingress_rx,
            Duration::from_secs(5),
            |d| (d.peer_pubkey == a_pk && d.message == payload_a).then_some(()),
            "server never received payload from admitted peer A",
        );
        drain_matching(&server.ingress_rx, Duration::from_millis(200), |d| {
            d.message == payload_a
        });

        let payload_b = Bytes::from_static(b"hello-from-B");
        rt.block_on(async {
            client_b
                .endpoint
                .egress
                .send(Datagram {
                    peer_pubkey: server.pubkey(),
                    peer_address: server.addr,
                    message: payload_b.clone(),
                })
                .await
                .expect("egress send B");
        });

        // Server must close the handshake before any datagram from B is queued.
        let bad = server.ingress_rx.recv_timeout(Duration::from_millis(800));
        assert!(
            bad.is_err(),
            "unstaked peer B's datagram should not reach server ingress, got {bad:?}"
        );
    }
}
