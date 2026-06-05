//! Inbound (acceptor) side: accept a handshake, gate by banlist + allowlist,
//! then run the receive loop.
//!
//! Inbound connections are **receive-only** and are deliberately NOT tracked
//! per-peer. A sender may hold several at once (e.g. a hot spare, or a redial
//! racing an idle one) and that is harmless: duplicate votes/certs are
//! idempotent downstream, and a sender that delivers an invalid message is
//! banned by pubkey at the BLS-sigverify layer - the shared banlist then closes
//! every connection it holds. The only shared state is a global live-connection
//! counter, used purely as an anti-DoS cap. The handshake is CPU-heavy, so each
//! inbound runs on its own task and never blocks the accept loop.

use {
    crate::{
        Banlist, MAX_PEERS,
        allowlist::Allowlist,
        close_codes,
        endpoint::Datagram,
        error::Error,
        read_loop::read_datagram_loop,
        stats::{QuicDatagramStats, record_error},
    },
    crossbeam_channel::Sender,
    log::debug,
    quinn::Incoming,
    solana_pubkey::Pubkey,
    solana_tls_utils::get_remote_pubkey,
    std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

/// One accepted inbound connection's lifecycle: handshake, gate, receive loop.
pub(crate) struct InboundConnection {
    pub(crate) incoming: Incoming,
    pub(crate) ingress: Sender<Datagram>,
    pub(crate) allowlist: Arc<dyn Allowlist>,
    pub(crate) banlist: Arc<Banlist<Pubkey>>,
    /// Global live inbound-connection count, shared across all inbound tasks.
    pub(crate) live: Arc<AtomicU64>,
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

        // Global cap (anti-DoS). `fetch_add` returns the prior value; if we
        // were already at cap, undo and refuse. The count is not per-peer -
        // multiple connections from one sender are fine (see module docs).
        if self.live.fetch_add(1, Ordering::Relaxed) >= MAX_PEERS {
            self.live.fetch_sub(1, Ordering::Relaxed);
            close_codes::TABLE_FULL.close(&connection);
            return Err(Error::TableFull);
        }
        self.stats
            .record_connection_count(self.live.load(Ordering::Relaxed));

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
        self.live.fetch_sub(1, Ordering::Relaxed);
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
