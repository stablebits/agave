//! Per-connection lifecycles: outbound (client) and inbound (server).

use {
    crate::{
        Banlist,
        allowlist::Allowlist,
        close_codes,
        connection_table::{ConnectionTable, IdGeneration, InsertOutcome},
        endpoint::Datagram,
        error::Error,
        read_loop::read_datagram_loop,
        stats::{QuicDatagramStats, add, record_error},
    },
    bytes::Bytes,
    crossbeam_channel::Sender,
    log::{debug, error},
    quinn::{Endpoint, Incoming},
    solana_pubkey::Pubkey,
    solana_tls_utils::{get_remote_pubkey, socket_addr_to_quic_server_name},
    std::{net::SocketAddr, sync::Arc},
};

/// A client-side connection's full lifecycle: dial, validate identity,
/// install in the table, run the read loop, reap on exit. Built by the
/// control loop and dispatched via [`Self::spawn`].
pub(crate) struct ClientConnection<A: Allowlist> {
    pub(crate) endpoint: Endpoint,
    pub(crate) peer: Pubkey,
    pub(crate) addr: SocketAddr,
    pub(crate) id_generation: IdGeneration,
    /// The egress that triggered this dial. Carried into the dial task
    /// and sent the moment `insert_connection` succeeds, before the
    /// read loop starts. Cold-start traffic (standstill) needs this to
    /// reach the peer reliably.
    pub(crate) trigger: Bytes,
    pub(crate) ingress: Sender<Datagram>,
    pub(crate) allowlist: Arc<A>,
    pub(crate) banlist: Arc<Banlist<Pubkey>>,
    pub(crate) table: Arc<ConnectionTable>,
    pub(crate) stats: Arc<QuicDatagramStats>,
}

impl<A: Allowlist> ClientConnection<A> {
    /// Spawn a tokio task that drives this connection to completion.
    /// Returns immediately; the task logs and records any error before
    /// exiting.
    pub(crate) fn spawn(self) {
        let peer = self.peer;
        let addr = self.addr;
        let stats = self.stats.clone();
        tokio::spawn(async move {
            if let Err(e) = self.run().await {
                error!("Connection attempt to ({peer}, {addr}) failed: {e:?}");
                record_error(&e, &stats);
            }
        });
    }

    async fn run(self) -> Result<(), Error> {
        // Clone the needed data for cleanup
        let table_ref_for_cleanup = self.table.clone();
        let peer = self.peer;
        let id_generation = self.id_generation;

        let result: Result<(), Error> = async move {
            let server_name = socket_addr_to_quic_server_name(self.addr);
            let connection = self.endpoint.connect(self.addr, &server_name)?.await?;

            // Server identity must match the pubkey the caller targeted.
            let attested =
                get_remote_pubkey(&connection).ok_or(Error::InvalidIdentity(self.addr))?;
            if attested != self.peer {
                close_codes::INVALID_IDENTITY.close(&connection);
                return Err(Error::InvalidIdentity(self.addr));
            }

            // On cap-induced Rejected, the table will try to evict a
            // now-unadmitted peer before giving up - epoch-boundary churn
            // can momentarily push the staked-set union past `MAX_PEERS`.
            match self.table.insert_connection_or_evict(
                self.peer,
                connection.clone(),
                id_generation,
                |pk| self.allowlist.allow(pk),
                &self.stats,
            ) {
                InsertOutcome::Rejected => {
                    close_codes::TABLE_FULL.close(&connection);
                    return Err(Error::TableFull);
                }
                InsertOutcome::Stale => {
                    close_codes::IDENTITY_ROTATED.close(&connection);
                    return Err(Error::IdentityRotated(self.peer));
                }
                InsertOutcome::Inserted | InsertOutcome::Replaced => {
                    self.stats.record_connection_count(self.table.len());
                }
            }

            // Send the trigger packet that started this dial. Quinn-level
            // failures are recorded but not propagated - the connection
            // itself is healthy and the read loop should still run.
            match connection.send_datagram(self.trigger) {
                Ok(()) => add(&self.stats.datagrams_sent),
                Err(e) => record_error(&Error::from(e), &self.stats),
            }

            // Drive the read loop.
            let stable_id = connection.stable_id();
            read_datagram_loop(
                connection,
                self.peer,
                self.addr,
                self.ingress,
                self.banlist,
                self.stats,
            )
            .await;
            // Reap our slot only if it still points at *this* connection
            self.table.maybe_reap_connection(&self.peer, stable_id);
            Ok(())
        }
        .await;

        if result.is_err() {
            table_ref_for_cleanup.clear_dialing_placeholder(&peer, id_generation);
        }
        result
    }
}

/// A server-side connection representation
pub(crate) struct ServerConnection<A: Allowlist> {
    pub(crate) incoming: Incoming,
    pub(crate) local_pubkey: Pubkey,
    pub(crate) ingress: Sender<Datagram>,
    pub(crate) allowlist: Arc<A>,
    pub(crate) banlist: Arc<Banlist<Pubkey>>,
    pub(crate) table: Arc<ConnectionTable>,
    pub(crate) stats: Arc<QuicDatagramStats>,
}

impl<A: Allowlist> ServerConnection<A> {
    /// Spawn a tokio task that drives this connection to completion.
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

    /// post-RETRY accept, validate identity / banlist / allowlist,
    /// install in the table, run the read loop, reap on exit.
    async fn run(self) -> Result<(), Error> {
        // Snapshot the identity generation BEFORE the handshake starts.
        // If our identity rotates while quinn is driving the handshake,
        // `insert_connection` below will see a mismatched gen and
        // return `Stale`, and we close the resulting (wrong-identity)
        // connection.
        let gen_at_start = self.table.current_generation();
        let remote_addr = self.incoming.remote_address();
        let connecting = self.incoming.accept()?;
        let connection = connecting.await?;
        let Some(peer) = get_remote_pubkey(&connection) else {
            close_codes::INVALID_IDENTITY.close(&connection);
            return Err(Error::InvalidIdentity(remote_addr));
        };

        if peer >= self.local_pubkey {
            close_codes::WRONG_DIRECTION.close(&connection);
            return Err(Error::WrongDirection(peer));
        }
        if self.banlist.is_banned(&peer) {
            close_codes::BANNED.close(&connection);
            return Err(Error::Banned(peer));
        }
        if !self.allowlist.allow(&peer) {
            close_codes::NOT_ADMITTED.close(&connection);
            return Err(Error::NotAdmitted(peer));
        }

        match self.table.insert_connection_or_evict(
            peer,
            connection.clone(),
            gen_at_start,
            |pk| self.allowlist.allow(pk),
            &self.stats,
        ) {
            InsertOutcome::Rejected => {
                close_codes::TABLE_FULL.close(&connection);
                return Err(Error::TableFull);
            }
            InsertOutcome::Stale => {
                close_codes::IDENTITY_ROTATED.close(&connection);
                return Err(Error::IdentityRotated(peer));
            }
            InsertOutcome::Inserted | InsertOutcome::Replaced => {
                self.stats.record_connection_count(self.table.len());
            }
        }

        // We're already on the per-incoming task; run the read loop
        // inline rather than chaining another spawn.
        let stable_id = connection.stable_id();
        read_datagram_loop(
            connection,
            peer,
            remote_addr,
            self.ingress,
            self.banlist,
            self.stats,
        )
        .await;
        // Reap our slot only if it still points at *this* connection
        // (a newer one may have taken our place via HANDOVER).
        self.table.maybe_reap_connection(&peer, stable_id);
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

        // Lex tiebreaker requires the dialing client's pubkey < server's. Pick
        // the server keypair first, then derive client A's keypair below it.
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

        // Client A - admitted (pubkey < server's, so handshake passes lex check).
        let client_a = spawn_node_with(&rt, Arc::new(AllowAll), a_kp);
        // Client B - not admitted. Pick below server so the rejection is by the
        // allowlist check, not the lex check.
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
        // send_until_received may have left retry duplicates of payload_a
        // in the channel; drain them before asserting B's rejection.
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
