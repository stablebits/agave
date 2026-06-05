//! QUIC datagram endpoint: public handle ([`QuicDatagramEndpoint`]) plus
//! its unified control loop ([`EndpointLoop`]). One tokio task handles
//! server accept, client egress, banlist eviction, identity rotation,
//! and metrics. Each event source is an arm of a single `tokio::select!`;
//! heavy per-event work is spawned onto its own task so a slow handshake
//! or dial does not block dispatch of the next event.

use {
    crate::{
        Banlist, EGRESS_CHANNEL_CAP,
        allowlist::Allowlist,
        close_codes,
        error::Error,
        inbound::{Inbound, InboundConnection},
        outbound::{Dispatch, Outbound, spawn_dial},
        stats::{self, QuicDatagramStats, add},
        subnet_rate_limit::SubnetRateLimiter,
        transport::{new_client_config, new_server_config},
    },
    bytes::Bytes,
    crossbeam_channel::Sender,
    log::{debug, info, warn},
    quinn::{Endpoint, EndpointConfig, Incoming, TokioRuntime},
    rustls::pki_types::{CertificateDer, PrivateKeyDer},
    solana_keypair::{Keypair, Signer},
    solana_pubkey::Pubkey,
    solana_tls_utils::{NotifyKeyUpdate, new_dummy_x509_certificate},
    std::{
        net::{SocketAddr, UdpSocket},
        sync::{Arc, atomic::Ordering},
        time::Duration,
    },
    tokio::{
        sync::{mpsc, watch},
        task::JoinHandle,
        time::MissedTickBehavior,
    },
};

/// Identity material derived from a keypair: the ed25519 pubkey plus the
/// self-signed TLS cert/key that the endpoint presents to peers.
pub(crate) struct IdentitySnapshot {
    pub pubkey: Pubkey,
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

impl IdentitySnapshot {
    pub fn from_keypair(keypair: &Keypair) -> Self {
        let (cert, key) = new_dummy_x509_certificate(keypair);
        Self {
            pubkey: keypair.pubkey(),
            cert,
            key,
        }
    }
}

/// Handle for caller-driven identity rotation. Cloneable and thread-safe.
/// Implements [`NotifyKeyUpdate`] so it slots into the validator's existing
/// key-rotation plumbing.
pub struct KeyUpdater {
    tx: watch::Sender<Option<Arc<IdentitySnapshot>>>,
}

impl KeyUpdater {
    pub(crate) fn new() -> (Self, watch::Receiver<Option<Arc<IdentitySnapshot>>>) {
        let (tx, rx) = watch::channel(None);
        (Self { tx }, rx)
    }
}

impl NotifyKeyUpdate for KeyUpdater {
    fn update_key(&self, keypair: &Keypair) -> Result<(), Box<dyn std::error::Error>> {
        let snap = Arc::new(IdentitySnapshot::from_keypair(keypair));
        self.tx
            .send(Some(snap))
            .map_err(|_| -> Box<dyn std::error::Error> {
                "quic-datagram endpoint has shut down; identity update rejected".into()
            })?;
        Ok(())
    }
}

const BANLIST_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);
const METRICS_INTERVAL: Duration = Duration::from_secs(2);

/// Datagram envelope used on both directions of the endpoint.
#[derive(Debug)]
pub struct Datagram {
    pub peer_pubkey: Pubkey,
    pub peer_address: SocketAddr,
    pub message: Bytes,
}

/// Datagram-only QUIC endpoint bound to UDP socket. The single control
/// loop task is spawned by [`Self::new`]; await `task` after
/// [`Self::close`] to observe full drain.
pub struct QuicDatagramEndpoint {
    pub endpoint: Endpoint,
    pub egress: mpsc::Sender<Datagram>,
    /// Handle for rotating the local identity (TLS cert / pubkey). Wraps a
    /// `tokio::sync::watch` channel; the actual swap happens asynchronously
    /// in the control loop. Implements `solana_tls_utils::NotifyKeyUpdate`
    /// so it slots into the validator's `KeyUpdaters` registry.
    pub key_updater: Arc<KeyUpdater>,
    pub task: JoinHandle<()>,
}

impl QuicDatagramEndpoint {
    /// Construct a datagram-only QUIC endpoint bound to `socket`. Spawns the
    /// unified control loop on `runtime`. Received datagrams flow into
    /// `ingress` via `try_send`; full ingress channel results in a drop
    /// (counted in `datagram_ingress_dropped_channel_full`).
    ///
    /// `allowlist` gates inbound connections (accept-time and on a periodic
    /// re-check). `banlist` is consulted on every send and at handshake.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime: &tokio::runtime::Handle,
        keypair: &Keypair,
        socket: UdpSocket,
        alpn_protocol_id: &'static [u8],
        ingress: Sender<Datagram>,
        allowlist: Arc<dyn Allowlist>,
        banlist: Arc<Banlist<Pubkey>>,
    ) -> Result<Self, Error> {
        let local_pubkey = keypair.pubkey();
        let (cert, key) = new_dummy_x509_certificate(keypair);
        let server_config = new_server_config(cert.clone(), key.clone_key(), alpn_protocol_id);
        let client_config = new_client_config(cert, key, alpn_protocol_id);

        let mut endpoint = {
            // Endpoint::new requires being inside the runtime context, else it
            // panics on its first internal `tokio::spawn`.
            let _guard = runtime.enter();
            Endpoint::new(
                EndpointConfig::default(),
                Some(server_config),
                socket,
                Arc::new(TokioRuntime),
            )
            .map_err(Error::Endpoint)?
        };
        endpoint.set_default_client_config(client_config);

        let outbound = Arc::new(Outbound::new());
        let inbound = Arc::new(Inbound::new());
        let stats = Arc::<QuicDatagramStats>::default();
        let (egress_tx, egress_rx) = mpsc::channel(EGRESS_CHANNEL_CAP);
        let (key_updater, identity_rx) = KeyUpdater::new();
        let key_updater = Arc::new(key_updater);

        let control = EndpointLoop {
            endpoint: endpoint.clone(),
            local_pubkey,
            egress_rx,
            ingress,
            allowlist,
            banlist,
            identity_rx,
            outbound,
            inbound,
            stats,
            alpn: alpn_protocol_id,
        };
        let task = runtime.spawn(control.run());

        Ok(Self {
            endpoint,
            egress: egress_tx,
            key_updater,
            task,
        })
    }

    /// Initiate endpoint shutdown. The control loop exits on its next
    /// `endpoint.accept()` resolution (returns `None` once closed); in-flight
    /// connections are closed with `SHUTDOWN`. Callers should `await`
    /// [`Self::task`] to ensure all connections are terminated gracefully.
    pub fn close(&self) {
        self.endpoint
            .close(close_codes::SHUTDOWN.code, close_codes::SHUTDOWN.reason);
    }
}

struct EndpointLoop {
    endpoint: Endpoint,
    local_pubkey: Pubkey,
    egress_rx: mpsc::Receiver<Datagram>,
    ingress: Sender<Datagram>,
    /// Inbound admission policy; handed to each inbound task for the accept
    /// gate and the read loop's periodic re-check.
    allowlist: Arc<dyn Allowlist>,
    banlist: Arc<Banlist<Pubkey>>,
    identity_rx: watch::Receiver<Option<Arc<IdentitySnapshot>>>,
    /// Outbound (dialer) connections - the only per-peer connection table.
    outbound: Arc<Outbound>,
    /// Inbound admission limiter (global + per-identity caps), shared with
    /// every inbound task.
    inbound: Arc<Inbound>,
    stats: Arc<QuicDatagramStats>,
    /// Held so that an identity rotation can rebuild server + client TLS
    /// configs without revisiting the caller.
    alpn: &'static [u8],
}

impl EndpointLoop {
    async fn run(mut self) {
        let subnet_limit = Arc::new(SubnetRateLimiter::new());

        let mut prune = tokio::time::interval(BANLIST_PRUNE_INTERVAL);
        prune.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut metrics = tokio::time::interval(METRICS_INTERVAL);
        metrics.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // The loop exits when egress / accept channels close - running a
        // half-broken endpoint after one of those has gone away is
        // pointless. The `identity_rx` arm is the lone exception: when
        // the `KeyUpdater`-side `watch::Sender` is dropped we disable the
        // arm via `id_closed` and keep running without identity rotation.
        //
        // TODO: this tolerance exists only to paper over `local-cluster`
        // passing a throwaway `Arc::new(RwLock::new(None))` for the
        // `admin_rpc_service_post_init` parameter to `Validator::new`.
        // That Arc drops the moment `Validator::new` returns, taking the
        // whole `Arc<KeyUpdaters> → Arc<KeyUpdater> → watch::Sender`
        // chain with it. Fix on the caller side is very invasive, so
        // was not applied.
        let mut id_closed = false;
        loop {
            tokio::select! {
                biased;
                // If identity is changed we should reconnect immediately
                // to maintain coherent state. Any existing backlog of packets
                // is probably invalid/irrelevant.
                changed = self.identity_rx.changed(), if !id_closed => {
                    if changed.is_err() {
                        // See TODO at top of loop
                        warn!("identity rotation channel closed; endpoint will run without rotation support");
                        id_closed = true;
                        continue;
                    }
                    let snap = self.identity_rx.borrow_and_update().clone();
                    if let Some(snap) = snap {
                        self.apply_identity_change(snap);
                    }
                }
                // egress to existing peers more important than accepting new
                maybe_datagram = self.egress_rx.recv() => {
                    let Some(datagram) = maybe_datagram else { break };
                    self.handle_datagram(datagram);
                }
                maybe_incoming = self.endpoint.accept() => {
                    let Some(incoming) = maybe_incoming else { break };
                    self.accept_connection(incoming, &subnet_limit);
                }
                // when idle we can take care of bookkeeping. If these are delayed
                // it is usually not a problem.
                _ = prune.tick() => self.banlist.prune(),
                _ = metrics.tick() => {
                    let live = self.outbound.len().saturating_add(self.inbound.len());
                    stats::report(&self.stats, live);
                }
            }
        }
    }

    /// Rebuild TLS configs against the new identity and swap them into the
    /// quinn endpoint. Clear the outbound table so we redial every peer under
    /// the new identity; in-flight dials that completed under the old cert hit
    /// `Stale` and bail. Inbound connections carry the *peers'* identities
    /// (unaffected by our rotation) and idle out as peers redial us under the
    /// new identity, so they are left in place.
    fn apply_identity_change(&mut self, snap: Arc<IdentitySnapshot>) {
        let server_config = new_server_config(snap.cert.clone(), snap.key.clone_key(), self.alpn);
        let client_config = new_client_config(snap.cert.clone(), snap.key.clone_key(), self.alpn);

        self.local_pubkey = snap.pubkey;
        self.endpoint.set_default_client_config(client_config);
        self.endpoint.set_server_config(Some(server_config));

        let evicted = self.outbound.clear_for_id_change();
        self.stats
            .connection_evicted_identity_rotated
            .fetch_add(evicted, Ordering::Relaxed);
        info!(
            "identity rotated to {} ({} outbound connection(s) evicted)",
            snap.pubkey, evicted
        );
    }

    fn handle_datagram(&self, datagram: Datagram) {
        let Datagram {
            peer_pubkey: peer,
            peer_address: addr,
            message: bytes,
        } = datagram;
        debug_assert_ne!(self.local_pubkey, peer, "egress to self is a caller bug");
        if self.banlist.is_banned(&peer) {
            return;
        }

        // Always dial to send. Ask the outbound table whether a usable
        // connection exists (send on it), a dial is already in flight (drop),
        // or the address changed / no connection exists (open one). The
        // trigger datagram is carried into the dial task and sent the moment
        // the connection lands - this is what lets a standstill broadcast (one
        // cert every `DELTA_STANDSTILL`) reach a peer whose connection had
        // died. Followers arriving during `Dialing` drop on the floor.
        let generation = match self.outbound.dispatch(peer, addr, &bytes, &self.stats) {
            Dispatch::Sent | Dispatch::Dialing => return,
            Dispatch::Dial { generation } => generation,
        };

        spawn_dial(
            self.endpoint.clone(),
            self.outbound.clone(),
            peer,
            addr,
            generation,
            bytes,
            self.stats.clone(),
        );
    }

    /// Performs the non-expensive checks to handle incoming connections.
    /// Then spawns the statemachine to handle the handshake and serve connection.
    fn accept_connection(&self, incoming: Incoming, subnet_limit: &Arc<SubnetRateLimiter>) {
        let remote_addr = incoming.remote_address();
        if remote_addr.is_ipv6() || remote_addr.ip().is_multicast() {
            incoming.ignore();
            return;
        }
        if !incoming.remote_address_validated() {
            match incoming.retry() {
                Ok(()) => add(&self.stats.handshake_retry_sent),
                Err(e) => {
                    debug!("retry() failed for {remote_addr}");
                    e.into_incoming().ignore();
                }
            }
            return;
        }
        // Post-RETRY: Gate per-subnet here,
        // *before* spending CPU on the TLS handshake. An attacker with a
        // large IP pool can complete RETRY on each address but is bounded
        // by the per-/24 burst budget (100 attempts, refilling 1/min).
        if !subnet_limit.admit(remote_addr.ip()) {
            add(&self.stats.handshake_rejected_overload);
            incoming.refuse();
            return;
        }
        InboundConnection {
            incoming,
            ingress: self.ingress.clone(),
            allowlist: self.allowlist.clone(),
            banlist: self.banlist.clone(),
            inbound: self.inbound.clone(),
            stats: self.stats.clone(),
        }
        .spawn();
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{
            allowlist::AllowAll,
            testutils::{
                clone_keypair, drain_matching, keypair_below, make_runtime, send_until_received,
                spawn_node, spawn_node_with,
            },
        },
        bytes::Bytes,
        solana_keypair::Signer,
        solana_tls_utils::NotifyKeyUpdate,
        std::{sync::Arc, time::Duration},
    };

    #[test]
    fn rotation_evicts_connections_and_resends_under_new_identity() {
        let rt = make_runtime();
        let server = spawn_node(&rt, Arc::new(AllowAll));

        let k1 = keypair_below(&server.pubkey());
        let k1_pk = k1.pubkey();
        let client = spawn_node_with(&rt, Arc::new(AllowAll), k1);

        // Send under K1. Server should observe message attributed to K1.
        let p1 = Bytes::from_static(b"under-K1");
        send_until_received(
            &rt,
            &client.endpoint,
            server.pubkey(),
            server.addr,
            p1.clone(),
            &server.ingress_rx,
            Duration::from_secs(5),
            |d| (d.peer_pubkey == k1_pk && d.message == p1).then_some(()),
            "server never received message attributed to K1",
        );
        drain_matching(&server.ingress_rx, Duration::from_millis(200), |d| {
            d.message == p1
        });

        // Rotate to K2. Pick K2 also below the server so dial direction stays.
        let k2 = keypair_below(&server.pubkey());
        let k2_pk = k2.pubkey();
        assert_ne!(k1_pk, k2_pk, "K1 and K2 must differ");
        client
            .endpoint
            .key_updater
            .update_key(&k2)
            .expect("identity rotation accepted");

        // The control loop applies the rotation asynchronously: rebuild TLS
        // configs, evict cached connections (server sees IDENTITY_ROTATED).
        // Give it a beat.
        std::thread::sleep(Duration::from_millis(500));

        // Send under K2. Server's table no longer holds the K1 entry; a
        // fresh handshake under K2 establishes a new connection, and the
        // server observes the message attributed to K2.
        let p2 = Bytes::from_static(b"under-K2");
        send_until_received(
            &rt,
            &client.endpoint,
            server.pubkey(),
            server.addr,
            p2.clone(),
            &server.ingress_rx,
            Duration::from_secs(5),
            |d| (d.peer_pubkey == k2_pk && d.message == p2).then_some(()),
            "server never received message attributed to K2 after rotation",
        );

        // Client side: the rotated client should NOT have soft-banned the
        // server (rotation is a local event, not a HANDOVER-style takeover).
        assert!(
            !client.banlist.is_banned(&server.pubkey()),
            "rotation must not soft-ban peers we close ourselves"
        );
    }

    #[test]
    fn outbound_addr_change_redials_new_addr() {
        let rt = make_runtime();

        // S1 establishes the lex order. Client will be lex-lower.
        let s1 = spawn_node(&rt, Arc::new(AllowAll));
        let s_key = clone_keypair(&s1.keypair);
        let s_pubkey = s1.pubkey();

        let client_kp = keypair_below(&s_pubkey);
        let client = spawn_node_with(&rt, Arc::new(AllowAll), client_kp);

        // Initial send: client dials S1 at its addr A1.
        let p1 = Bytes::from_static(b"p1");
        send_until_received(
            &rt,
            &client.endpoint,
            s_pubkey,
            s1.addr,
            p1.clone(),
            &s1.ingress_rx,
            Duration::from_secs(5),
            |d| (d.message == p1).then_some(()),
            "S1 did not receive p1",
        );
        drain_matching(&s1.ingress_rx, Duration::from_millis(200), |d| {
            d.message == p1
        });

        // S2 takes the same identity at a new addr - simulates a peer host
        // move with gossip publishing a new SocketAddr for the same pubkey.
        let s2 = spawn_node_with(&rt, Arc::new(AllowAll), s_key);
        assert_ne!(s1.addr, s2.addr, "S1 and S2 must bind distinct addrs");

        // Send to the new addr. Client must observe the addr mismatch,
        // evict its cached conn to A1, and re-dial A2.
        let p2 = Bytes::from_static(b"p2");
        send_until_received(
            &rt,
            &client.endpoint,
            s_pubkey,
            s2.addr,
            p2.clone(),
            &s2.ingress_rx,
            Duration::from_secs(5),
            |d| (d.message == p2).then_some(()),
            "S2 (post-move) did not receive p2",
        );

        // Stale conn to S1 was evicted; S1 must not see post-move datagrams.
        let stray = s1.ingress_rx.recv_timeout(Duration::from_millis(800));
        assert!(
            stray.is_err(),
            "S1 must not see post-move datagrams; got {stray:?}"
        );
    }

    #[test]
    fn chained_address_changes_each_redial() {
        // Three servers sharing one identity, distinct addrs. Each egress to
        // a new addr evicts the prior `Established` with PEER_MOVED and dials
        // the new addr. Verifies the state machine can roll through
        // Established(A1) → Dialing → Established(A2) → Dialing →
        // Established(A3) without corruption.
        let rt = make_runtime();
        let s1 = spawn_node(&rt, Arc::new(AllowAll));
        let s_key = clone_keypair(&s1.keypair);
        let s_pubkey = s1.pubkey();
        let client = spawn_node_with(&rt, Arc::new(AllowAll), keypair_below(&s_pubkey));

        let s2 = spawn_node_with(&rt, Arc::new(AllowAll), clone_keypair(&s_key));
        let s3 = spawn_node_with(&rt, Arc::new(AllowAll), clone_keypair(&s_key));
        assert!(
            s1.addr != s2.addr && s2.addr != s3.addr && s1.addr != s3.addr,
            "the three servers must bind distinct addrs",
        );

        let p1 = Bytes::from_static(b"to-s1");
        let p2 = Bytes::from_static(b"to-s2");
        let p3 = Bytes::from_static(b"to-s3");

        send_until_received(
            &rt,
            &client.endpoint,
            s_pubkey,
            s1.addr,
            p1.clone(),
            &s1.ingress_rx,
            Duration::from_secs(5),
            |d| (d.message == p1).then_some(()),
            "s1 did not receive p1",
        );
        drain_matching(&s1.ingress_rx, Duration::from_millis(200), |d| {
            d.message == p1
        });

        send_until_received(
            &rt,
            &client.endpoint,
            s_pubkey,
            s2.addr,
            p2.clone(),
            &s2.ingress_rx,
            Duration::from_secs(5),
            |d| (d.message == p2).then_some(()),
            "s2 did not receive p2 - first address change failed",
        );
        drain_matching(&s2.ingress_rx, Duration::from_millis(200), |d| {
            d.message == p2
        });

        send_until_received(
            &rt,
            &client.endpoint,
            s_pubkey,
            s3.addr,
            p3.clone(),
            &s3.ingress_rx,
            Duration::from_secs(5),
            |d| (d.message == p3).then_some(()),
            "s3 did not receive p3 - chained address change failed",
        );

        // Each server saw only its targeted datagram (plus retry duplicates
        // we already drained), nothing else.
        let stray1 = s1.ingress_rx.recv_timeout(Duration::from_millis(500));
        assert!(
            stray1.is_err(),
            "s1 unexpectedly received extra {stray1:?} after move",
        );
        let stray2 = s2.ingress_rx.recv_timeout(Duration::from_millis(500));
        assert!(
            stray2.is_err(),
            "s2 unexpectedly received extra {stray2:?} after move",
        );
    }
}
