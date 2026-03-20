use {
    crate::{
        nonblocking::{
            load_debt_tracker::LoadDebtTracker,
            qos::{
                ConnectionContext, MaxStreamsAction, OpaqueStreamerCounter, QosController,
                StreamAcceptedAction,
            },
            quic::{
                CONNECTION_CLOSE_CODE_DISALLOWED, CONNECTION_CLOSE_REASON_DISALLOWED,
                ClientConnectionTracker, ConnectionHandlerError, ConnectionPeerType,
                ConnectionTable, ConnectionTableKey, ConnectionTableType, get_connection_stake,
                update_open_connections_stat,
            },
        },
        quic::{
            DEFAULT_MAX_QUIC_CONNECTIONS_PER_STAKED_PEER,
            DEFAULT_MAX_QUIC_CONNECTIONS_PER_UNSTAKED_PEER, DEFAULT_MAX_STAKED_CONNECTIONS,
            DEFAULT_MAX_STREAMS_PER_MS, DEFAULT_MAX_UNSTAKED_CONNECTIONS, StreamerStats,
        },
        streamer::StakedNodes,
    },
    percentage::Percentage,
    quinn::Connection,
    solana_net_utils::token_bucket::TokenBucket,
    solana_time_utils as timing,
    std::{
        future::Future,
        sync::{
            Arc, Mutex as StdMutex, OnceLock, RwLock,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    },
    tokio::sync::{Mutex, MutexGuard},
    tokio_util::sync::CancellationToken,
};

/// Reference RTT for BDP scaling
const REFERENCE_RTT: Duration = Duration::from_millis(100);

/// Max RTT for BDP scaling. Caps MAX_STREAMS growth on high-latency links.
const MAX_RTT: Duration = Duration::from_millis(200);

/// Min RTT for BDP scaling.
const MIN_RTT: Duration = Duration::from_millis(1);

/// Backward-compat RTT floor for unsaturated staked peers.  Matches the old
/// SWQoS REFERENCE_RTT_MS so that low-RTT staked connections keep the same
/// MAX_STREAMS as before.
const MIN_RTT_STAKED_UNSATURATED: Duration = Duration::from_millis(50);

/// Base MAX_STREAMS at REFERENCE_RTT. At 100ms, 1024 matches the old SWQoS
/// ceiling for the highest-staked peers; scaling remains linear with RTT.
const DEFAULT_BASE_MAX_STREAMS_STAKED: u32 = 1024;
const DEFAULT_BASE_MAX_STREAMS_UNSTAKED: u32 = 20;
/// Burst window for emergency sender token buckets. Senders have different
/// RTTs, but saturated MAX_STREAMS is scaled and then capped at MAX_RTT, so
/// Phase 2 normalizes all senders to the same MAX_RTT-sized fair-share window
/// instead of tracking per-sender RTT here.
const EMERGENCY_BUCKET_WINDOW: Duration = MAX_RTT;

struct EmergencySenderBucketState {
    /// Monotonic identifier of the emergency episode that initialized the
    /// current snapshot.
    bucket_generation: u64,
    /// Snapshot sender bucket for `bucket_generation`. We do not adjust it for
    /// later connection-count churn until the next emergency generation.
    sender_bucket: Option<Arc<TokenBucket>>,
    /// Sender-wide bucket capacity snapped for `bucket_generation`, in streams
    /// per fixed emergency bucket window.
    bucket_capacity_streams: u64,
}

/// Per-key sender state shared across that sender's live connections in one
/// table.
///
/// The Phase 2 sender bucket lives in this table-local state, so it is dropped
/// when the sender's last tracked connection is removed. If the sender
/// reconnects during the same emergency generation, it gets a fresh Phase 2
/// bucket.
///
/// This is intentional. Phase 2 exists to limit MAX_STREAMS credit that was
/// already issued and can no longer be taken back, especially credit granted
/// before saturated mode turned on. After a hard reconnect, new credit is
/// issued under saturated MAX_STREAMS again, so Phase 1 is already enforced by
/// QUIC flow control. Reconnecting again mostly trades waiting about one RTT
/// for new credit for spending about one RTT on the handshake.
pub(crate) struct SwQosMaxStreamsStreamerCounter {
    connection_count: AtomicUsize,
    emergency_state: StdMutex<EmergencySenderBucketState>,
}

impl SwQosMaxStreamsStreamerCounter {
    fn new() -> Self {
        Self {
            connection_count: AtomicUsize::new(0),
            emergency_state: StdMutex::new(EmergencySenderBucketState {
                bucket_generation: 0,
                sender_bucket: None,
                bucket_capacity_streams: 0,
            }),
        }
    }
}
impl OpaqueStreamerCounter for SwQosMaxStreamsStreamerCounter {}

#[derive(Clone)]
pub struct SwQosMaxStreamsConfig {
    pub max_streams_per_ms: u64,
    pub max_staked_connections: usize,
    pub max_unstaked_connections: usize,
    pub max_connections_per_staked_peer: usize,
    pub max_connections_per_unstaked_peer: usize,
    pub base_max_streams_staked: u32,
    pub base_max_streams_unstaked: u32,
    /// Bucket level at which emergency sender buckets begin.
    /// `None` = disabled. `Some(0)` = auto (`-burst_capacity`).
    pub emergency_debt_threshold: Option<i64>,
}

impl Default for SwQosMaxStreamsConfig {
    fn default() -> Self {
        SwQosMaxStreamsConfig {
            max_streams_per_ms: DEFAULT_MAX_STREAMS_PER_MS,
            max_staked_connections: DEFAULT_MAX_STAKED_CONNECTIONS,
            max_unstaked_connections: DEFAULT_MAX_UNSTAKED_CONNECTIONS,
            max_connections_per_staked_peer: DEFAULT_MAX_QUIC_CONNECTIONS_PER_STAKED_PEER,
            max_connections_per_unstaked_peer: DEFAULT_MAX_QUIC_CONNECTIONS_PER_UNSTAKED_PEER,
            base_max_streams_staked: DEFAULT_BASE_MAX_STREAMS_STAKED,
            base_max_streams_unstaked: DEFAULT_BASE_MAX_STREAMS_UNSTAKED,
            emergency_debt_threshold: Some(0),
        }
    }
}

impl SwQosMaxStreamsConfig {
    #[cfg(feature = "dev-context-only-utils")]
    pub fn default_for_tests() -> Self {
        Self {
            max_connections_per_unstaked_peer: 1,
            max_connections_per_staked_peer: 1,
            ..Self::default()
        }
    }
}

pub struct SwQosMaxStreams {
    config: SwQosMaxStreamsConfig,
    capacity_tps: u64,
    /// Resolved threshold for emergency sender buckets (`None` = disabled).
    emergency_debt_threshold: Option<i64>,
    /// Sticky while saturated. Exit is evaluated lazily on accepted streams, so
    /// this flag can remain true during idle recovery until the next stream.
    emergency_active: AtomicBool,
    emergency_generation: AtomicU64,
    emergency_entered_us: AtomicU64,
    emergency_transition_lock: StdMutex<()>,
    load_tracker: Arc<LoadDebtTracker>,
    stats: Arc<StreamerStats>,
    staked_nodes: Arc<RwLock<StakedNodes>>,
    unstaked_connection_table: Arc<Mutex<ConnectionTable<SwQosMaxStreamsStreamerCounter>>>,
    staked_connection_table: Arc<Mutex<ConnectionTable<SwQosMaxStreamsStreamerCounter>>>,
}

#[derive(Clone)]
pub struct SwQosMaxStreamsConnectionContext {
    peer_type: ConnectionPeerType,
    remote_pubkey: Option<solana_pubkey::Pubkey>,
    total_stake: u64,
    in_staked_table: bool,
    last_update: Arc<AtomicU64>,
    stream_counter: Option<Arc<SwQosMaxStreamsStreamerCounter>>,
}

impl ConnectionContext for SwQosMaxStreamsConnectionContext {
    fn peer_type(&self) -> ConnectionPeerType {
        self.peer_type
    }

    fn remote_pubkey(&self) -> Option<solana_pubkey::Pubkey> {
        self.remote_pubkey
    }
}

impl SwQosMaxStreams {
    fn monotonic_now_us() -> u64 {
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        EPOCH
            .get_or_init(Instant::now)
            .elapsed()
            .as_micros()
            .min(u64::MAX as u128) as u64
    }

    pub fn load_tracker(&self) -> &LoadDebtTracker {
        &self.load_tracker
    }

    pub fn new(
        config: SwQosMaxStreamsConfig,
        stats: Arc<StreamerStats>,
        staked_nodes: Arc<RwLock<StakedNodes>>,
        cancel: CancellationToken,
    ) -> Self {
        let max_streams_per_second = config.max_streams_per_ms.saturating_mul(1000);
        let burst_capacity = max_streams_per_second / 10;

        // Resolve threshold: None → disabled, Some(0) → -burst_capacity.
        let emergency_debt_threshold = config
            .emergency_debt_threshold
            .map(|t| if t == 0 { -(burst_capacity as i64) } else { t });

        Self {
            config,
            capacity_tps: max_streams_per_second,
            emergency_debt_threshold,
            emergency_active: AtomicBool::new(false),
            emergency_generation: AtomicU64::new(0),
            emergency_entered_us: AtomicU64::new(0),
            emergency_transition_lock: StdMutex::new(()),
            load_tracker: Arc::new(LoadDebtTracker::new(
                max_streams_per_second,
                burst_capacity,
                Duration::from_millis(1),
            )),
            stats,
            staked_nodes,
            unstaked_connection_table: Arc::new(Mutex::new(ConnectionTable::new(
                ConnectionTableType::Unstaked,
                cancel.clone(),
            ))),
            staked_connection_table: Arc::new(Mutex::new(ConnectionTable::new(
                ConnectionTableType::Staked,
                cancel,
            ))),
        }
    }

    /// Core MAX_STREAMS computation (testable without a quinn::Connection).
    pub(crate) fn compute_max_streams_for_rtt(
        &self,
        context: &SwQosMaxStreamsConnectionContext,
        rtt: Duration,
        saturated: bool,
    ) -> Option<u32> {
        let scale = |base_max_streams: u32, rtt: Duration| {
            (base_max_streams as f64 * rtt.as_secs_f64() / REFERENCE_RTT.as_secs_f64()) as u32
        };

        let unsat_max = match context.peer_type {
            ConnectionPeerType::Unstaked => {
                let rtt = rtt.clamp(MIN_RTT, MAX_RTT);
                scale(self.config.base_max_streams_unstaked, rtt)
            }
            ConnectionPeerType::Staked(_) => {
                let rtt = rtt.clamp(MIN_RTT_STAKED_UNSATURATED, MAX_RTT);
                scale(self.config.base_max_streams_staked, rtt)
            }
        };

        if saturated {
            match context.peer_type {
                ConnectionPeerType::Unstaked => Some(0), // park
                ConnectionPeerType::Staked(stake) => {
                    // Saturated quota uses true BDP (no 50ms floor) for tight
                    // flow control under load.
                    let sat_rtt = rtt.clamp(MIN_RTT, MAX_RTT);
                    let share_tps = (self.capacity_tps as u128)
                        .saturating_mul(stake as u128)
                        .checked_div(context.total_stake as u128)
                        .unwrap_or(0) as u64;
                    let quota = (share_tps as f64 * sat_rtt.as_secs_f64()) as u32;
                    let num_connections = Self::sender_connection_count(context);
                    // At least 1: peers that passed the min-stake threshold in
                    // build_connection_context should not be parked.
                    let per_conn = (quota / num_connections).max(1);
                    // Don't exceed the unsaturated limit.
                    Some(per_conn.min(unsat_max.max(1)))
                }
            }
        } else {
            Some(unsat_max.max(1))
        }
    }

    fn sender_connection_count(context: &SwQosMaxStreamsConnectionContext) -> u32 {
        context
            .stream_counter
            .as_ref()
            .map(|c| c.connection_count.load(Ordering::Relaxed))
            .unwrap_or(1)
            .max(1) as u32
    }

    fn compute_sender_bucket_capacity_streams(
        &self,
        context: &SwQosMaxStreamsConnectionContext,
    ) -> u64 {
        let Some(per_connection_quota) =
            self.compute_max_streams_for_rtt(context, EMERGENCY_BUCKET_WINDOW, true)
        else {
            return 0;
        };

        u64::from(per_connection_quota)
            .saturating_mul(u64::from(Self::sender_connection_count(context)))
    }

    fn get_or_init_sender_bucket_snapshot(
        &self,
        context: &SwQosMaxStreamsConnectionContext,
        generation: u64,
    ) -> Option<(Arc<TokenBucket>, u64)> {
        let stream_counter = context.stream_counter.as_ref()?;
        let mut state = stream_counter.emergency_state.lock().unwrap();

        if state.bucket_generation != generation {
            state.bucket_generation = generation;
            state.bucket_capacity_streams = self.compute_sender_bucket_capacity_streams(context);
            state.sender_bucket = (state.bucket_capacity_streams > 0).then(|| {
                let refill_per_second =
                    state.bucket_capacity_streams as f64 / EMERGENCY_BUCKET_WINDOW.as_secs_f64();
                Arc::new(TokenBucket::new(
                    state.bucket_capacity_streams,
                    state.bucket_capacity_streams,
                    refill_per_second,
                ))
            });
        }

        state
            .sender_bucket
            .as_ref()
            .map(|bucket| (bucket.clone(), state.bucket_capacity_streams))
    }

    fn update_emergency_mode(&self, level: i64, saturated: bool) -> Option<u64> {
        let threshold = self.emergency_debt_threshold?;

        if self.emergency_active.load(Ordering::Relaxed) {
            // Keep emergency active until saturation fully clears. The flag may
            // therefore stay true during idle recovery until a later stream
            // re-enters this path and observes that saturation is gone.
            if saturated {
                return Some(self.emergency_generation.load(Ordering::Relaxed));
            }

            let exited_generation = {
                let _guard = self.emergency_transition_lock.lock().unwrap();
                if self.emergency_active.load(Ordering::Relaxed)
                    && !self.load_tracker.is_saturated()
                {
                    self.emergency_active.store(false, Ordering::Relaxed);
                    Some(self.emergency_generation.load(Ordering::Relaxed))
                } else {
                    None
                }
            };
            if let Some(generation) = exited_generation {
                log::info!(
                    "SwQosMaxStreams: emergency sender-bucket mode exited (bucket={level}, \
                     generation={generation})"
                );
                return None;
            }

            return Some(self.emergency_generation.load(Ordering::Relaxed));
        }

        if level <= threshold {
            let entered_generation = {
                let _guard = self.emergency_transition_lock.lock().unwrap();
                if !self.emergency_active.load(Ordering::Relaxed) {
                    let entered_us = Self::monotonic_now_us();
                    let generation = self.emergency_generation.fetch_add(1, Ordering::Relaxed) + 1;
                    self.emergency_active.store(true, Ordering::Relaxed);
                    self.emergency_entered_us
                        .store(entered_us, Ordering::Relaxed);
                    Some(generation)
                } else {
                    None
                }
            };
            if let Some(generation) = entered_generation {
                log::warn!(
                    "SwQosMaxStreams: emergency sender-bucket mode entered (bucket={level}, \
                     generation={generation})"
                );
                return Some(generation);
            }

            return Some(self.emergency_generation.load(Ordering::Relaxed));
        }

        None
    }

    fn should_close_due_to_phase2_bucket_exhaustion(
        &self,
        context: &SwQosMaxStreamsConnectionContext,
    ) -> bool {
        let Some(threshold) = self.emergency_debt_threshold else {
            return false;
        };

        if !self.emergency_active.load(Ordering::Relaxed)
            && self.load_tracker.bucket_level() > threshold
        {
            return false;
        }

        // Refresh the lazily refilled load tracker only when Phase 2 might
        // enter or exit. Without this, an idle connection can observe stale
        // deep debt after the system has already recovered.
        let saturated = self.load_tracker.is_saturated();
        let level = self.load_tracker.bucket_level();
        let debt_still_deep = level <= threshold;
        let Some(generation) = self.update_emergency_mode(level, saturated) else {
            return false;
        };

        let log_bucket_exhausted = |remaining_streams: u64, capacity_streams: u64| {
            let peer = context
                .remote_pubkey
                .map_or_else(|| "unknown".to_string(), |pk| pk.to_string());
            let window_ms = EMERGENCY_BUCKET_WINDOW.as_millis();
            let now_us = Self::monotonic_now_us();
            let emergency_entered_ms_ago =
                now_us.saturating_sub(self.emergency_entered_us.load(Ordering::Relaxed)) as f64
                    / 1_000.0;
            log::warn!(
                "SwQosMaxStreams: emergency sender bucket exhausted for peer={peer} \
                 (bucket={level}, generation={generation}, remaining_streams={remaining_streams}, \
                 allocated_streams_per_{window_ms}ms={capacity_streams}, \
                 refill_streams_per_{window_ms}ms={capacity_streams}, \
                 emergency_entered_ms_ago={emergency_entered_ms_ago:.3})",
            );
        };
        let Some((bucket, capacity_streams)) =
            self.get_or_init_sender_bucket_snapshot(context, generation)
        else {
            // A snapshot bucket is absent when the sender-wide emergency
            // capacity is zero. In practice this is how unstaked senders
            // appear in Phase 2, since saturated MAX_STREAMS parks them.
            //
            // An exhausted Phase 2 bucket only closes while the global debt is
            // still below the deep emergency threshold.
            if !debt_still_deep {
                return false;
            }
            log_bucket_exhausted(0, 0);
            return true;
        };

        if bucket.consume_tokens(1).is_ok() {
            return false;
        }

        // An exhausted Phase 2 bucket only closes while the global debt is
        // still below the deep emergency threshold.
        if !debt_still_deep {
            return false;
        }

        log_bucket_exhausted(bucket.current_tokens(), capacity_streams);
        true
    }

    fn handle_accepted_stream(
        &self,
        context: &SwQosMaxStreamsConnectionContext,
    ) -> StreamAcceptedAction {
        if self.should_close_due_to_phase2_bucket_exhaustion(context) {
            StreamAcceptedAction::CloseConnection
        } else {
            // Only charge debt for streams that actually enter processing. This
            // means emergency entry can lag by one stream, which is acceptable
            // because the tracker is already intentionally approximate.
            self.load_tracker.acquire();
            let saturated = self.load_tracker.is_saturated();
            if matches!(context.peer_type, ConnectionPeerType::Staked(_)) && saturated {
                self.stats
                    .saturated_staked_streams
                    .fetch_add(1, Ordering::Relaxed);
            }
            StreamAcceptedAction::Continue
        }
    }
}

impl SwQosMaxStreams {
    fn cache_new_connection(
        &self,
        client_connection_tracker: ClientConnectionTracker,
        connection: &Connection,
        mut connection_table_l: MutexGuard<ConnectionTable<SwQosMaxStreamsStreamerCounter>>,
        conn_context: &SwQosMaxStreamsConnectionContext,
    ) -> Result<
        (
            Arc<AtomicU64>,
            CancellationToken,
            Arc<SwQosMaxStreamsStreamerCounter>,
        ),
        ConnectionHandlerError,
    > {
        let remote_addr = connection.remote_address();

        let max_connections_per_peer = match conn_context.peer_type() {
            ConnectionPeerType::Unstaked => self.config.max_connections_per_unstaked_peer,
            ConnectionPeerType::Staked(_) => self.config.max_connections_per_staked_peer,
        };
        if let Some((last_update, cancel_connection, stream_counter)) = connection_table_l
            .try_add_connection(
                ConnectionTableKey::new(remote_addr.ip(), conn_context.remote_pubkey),
                remote_addr.port(),
                client_connection_tracker,
                Some(connection.clone()),
                conn_context.peer_type(),
                conn_context.last_update.clone(),
                max_connections_per_peer,
                || Arc::new(SwQosMaxStreamsStreamerCounter::new()),
            )
        {
            stream_counter
                .connection_count
                .fetch_add(1, Ordering::Relaxed);
            update_open_connections_stat(&self.stats, &connection_table_l);
            drop(connection_table_l);

            debug!(
                "Peer type {:?}, total stake {}, from peer {}",
                conn_context.peer_type(),
                conn_context.total_stake,
                remote_addr,
            );
            Ok((last_update, cancel_connection, stream_counter))
        } else {
            self.stats
                .connection_add_failed
                .fetch_add(1, Ordering::Relaxed);
            Err(ConnectionHandlerError::ConnectionAddError)
        }
    }

    fn prune_unstaked_connection_table(
        &self,
        unstaked_connection_table: &mut ConnectionTable<SwQosMaxStreamsStreamerCounter>,
        max_unstaked_connections: usize,
        stats: Arc<StreamerStats>,
    ) {
        if unstaked_connection_table.total_size >= max_unstaked_connections {
            const PRUNE_TABLE_TO_PERCENTAGE: u8 = 90;
            let max_percentage_full = Percentage::from(PRUNE_TABLE_TO_PERCENTAGE);

            let max_connections = max_percentage_full.apply_to(max_unstaked_connections);
            let num_pruned = unstaked_connection_table.prune_oldest(max_connections);
            stats
                .num_evictions_unstaked
                .fetch_add(num_pruned, Ordering::Relaxed);
        }
    }

    async fn prune_unstaked_connections_and_add_new_connection(
        &self,
        client_connection_tracker: ClientConnectionTracker,
        connection: &Connection,
        connection_table: Arc<Mutex<ConnectionTable<SwQosMaxStreamsStreamerCounter>>>,
        max_connections: usize,
        conn_context: &SwQosMaxStreamsConnectionContext,
    ) -> Result<
        (
            Arc<AtomicU64>,
            CancellationToken,
            Arc<SwQosMaxStreamsStreamerCounter>,
        ),
        ConnectionHandlerError,
    > {
        let stats = self.stats.clone();
        if max_connections > 0 {
            let mut connection_table = connection_table.lock().await;
            self.prune_unstaked_connection_table(&mut connection_table, max_connections, stats);
            self.cache_new_connection(
                client_connection_tracker,
                connection,
                connection_table,
                conn_context,
            )
        } else {
            connection.close(
                CONNECTION_CLOSE_CODE_DISALLOWED.into(),
                CONNECTION_CLOSE_REASON_DISALLOWED,
            );
            Err(ConnectionHandlerError::ConnectionAddError)
        }
    }
}

impl QosController<SwQosMaxStreamsConnectionContext> for SwQosMaxStreams {
    fn build_connection_context(
        &self,
        connection: &Connection,
    ) -> SwQosMaxStreamsConnectionContext {
        get_connection_stake(connection, &self.staked_nodes).map_or(
            SwQosMaxStreamsConnectionContext {
                peer_type: ConnectionPeerType::Unstaked,
                total_stake: 0,
                remote_pubkey: None,
                in_staked_table: false,
                last_update: Arc::new(AtomicU64::new(timing::timestamp())),
                stream_counter: None,
            },
            |(pubkey, stake, total_stake)| {
                // Demote ultra-low-stake peers to unstaked: must earn at
                // least 1 stream per 100ms at full capacity.
                let min_stake_ratio = 1_f64 / (self.config.max_streams_per_ms * 100) as f64;
                let stake_ratio = stake as f64 / total_stake as f64;
                let peer_type = if stake_ratio < min_stake_ratio {
                    ConnectionPeerType::Unstaked
                } else {
                    ConnectionPeerType::Staked(stake)
                };

                SwQosMaxStreamsConnectionContext {
                    peer_type,
                    total_stake,
                    remote_pubkey: Some(pubkey),
                    in_staked_table: false,
                    last_update: Arc::new(AtomicU64::new(timing::timestamp())),
                    stream_counter: None,
                }
            },
        )
    }

    #[allow(clippy::manual_async_fn)]
    fn try_add_connection(
        &self,
        client_connection_tracker: ClientConnectionTracker,
        connection: &quinn::Connection,
        conn_context: &mut SwQosMaxStreamsConnectionContext,
    ) -> impl Future<Output = Option<CancellationToken>> + Send {
        async move {
            const PRUNE_RANDOM_SAMPLE_SIZE: usize = 2;

            match conn_context.peer_type() {
                ConnectionPeerType::Staked(stake) => {
                    let mut connection_table_l = self.staked_connection_table.lock().await;

                    if connection_table_l.total_size >= self.config.max_staked_connections {
                        let num_pruned =
                            connection_table_l.prune_random(PRUNE_RANDOM_SAMPLE_SIZE, stake);
                        self.stats
                            .num_evictions_staked
                            .fetch_add(num_pruned, Ordering::Relaxed);
                        update_open_connections_stat(&self.stats, &connection_table_l);
                    }

                    if connection_table_l.total_size < self.config.max_staked_connections {
                        if let Ok((last_update, cancel_connection, stream_counter)) = self
                            .cache_new_connection(
                                client_connection_tracker,
                                connection,
                                connection_table_l,
                                conn_context,
                            )
                        {
                            self.stats
                                .connection_added_from_staked_peer
                                .fetch_add(1, Ordering::Relaxed);
                            conn_context.in_staked_table = true;
                            conn_context.last_update = last_update;
                            conn_context.stream_counter = Some(stream_counter);
                            return Some(cancel_connection);
                        }
                    } else {
                        // If we couldn't prune a connection in the staked connection table, let's
                        // put this connection in the unstaked connection table. If needed, prune a
                        // connection from the unstaked connection table.
                        //
                        // NOTE: This fallback can place the same staked pubkey in both tables.
                        // The per-peer stream counter is table-local, so saturated per-connection
                        // quota division and emergency buckets can temporarily over-allocate
                        // for that pubkey (bounded in practice by two tables). This is an
                        // accepted approximation.
                        if let Ok((last_update, cancel_connection, stream_counter)) = self
                            .prune_unstaked_connections_and_add_new_connection(
                                client_connection_tracker,
                                connection,
                                self.unstaked_connection_table.clone(),
                                self.config.max_unstaked_connections,
                                conn_context,
                            )
                            .await
                        {
                            self.stats
                                .connection_added_from_staked_peer
                                .fetch_add(1, Ordering::Relaxed);
                            conn_context.in_staked_table = false;
                            conn_context.last_update = last_update;
                            conn_context.stream_counter = Some(stream_counter);
                            return Some(cancel_connection);
                        } else {
                            self.stats
                                .connection_add_failed_on_pruning
                                .fetch_add(1, Ordering::Relaxed);
                            self.stats
                                .connection_add_failed_staked_node
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                ConnectionPeerType::Unstaked => {
                    if let Ok((last_update, cancel_connection, stream_counter)) = self
                        .prune_unstaked_connections_and_add_new_connection(
                            client_connection_tracker,
                            connection,
                            self.unstaked_connection_table.clone(),
                            self.config.max_unstaked_connections,
                            conn_context,
                        )
                        .await
                    {
                        self.stats
                            .connection_added_from_unstaked_peer
                            .fetch_add(1, Ordering::Relaxed);
                        conn_context.in_staked_table = false;
                        conn_context.last_update = last_update;
                        conn_context.stream_counter = Some(stream_counter);
                        return Some(cancel_connection);
                    } else {
                        self.stats
                            .connection_add_failed_unstaked_node
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            None
        }
    }

    fn compute_max_streams(
        &self,
        context: &SwQosMaxStreamsConnectionContext,
        rtt: Duration,
    ) -> MaxStreamsAction {
        let saturated = self.load_tracker.is_saturated();
        match self.compute_max_streams_for_rtt(context, rtt, saturated) {
            Some(0) => MaxStreamsAction::Park,
            Some(max_streams) => MaxStreamsAction::Set(max_streams),
            None => MaxStreamsAction::Unmanaged,
        }
    }

    fn on_stream_accepted(
        &self,
        context: &SwQosMaxStreamsConnectionContext,
    ) -> StreamAcceptedAction {
        self.handle_accepted_stream(context)
    }

    fn on_stream_error(&self, _conn_context: &SwQosMaxStreamsConnectionContext) {}

    fn on_stream_closed(&self, _conn_context: &SwQosMaxStreamsConnectionContext) {}

    #[allow(clippy::manual_async_fn)]
    fn remove_connection(
        &self,
        conn_context: &SwQosMaxStreamsConnectionContext,
        connection: Connection,
    ) -> impl Future<Output = usize> + Send {
        async move {
            if let Some(ref counter) = conn_context.stream_counter {
                counter.connection_count.fetch_sub(1, Ordering::Relaxed);
            }

            let mut lock = if conn_context.in_staked_table {
                self.staked_connection_table.lock().await
            } else {
                self.unstaked_connection_table.lock().await
            };

            let stable_id = connection.stable_id();
            let remote_addr = connection.remote_address();

            let removed_count = lock.remove_connection(
                ConnectionTableKey::new(remote_addr.ip(), conn_context.remote_pubkey()),
                remote_addr.port(),
                stable_id,
            );
            update_open_connections_stat(&self.stats, &lock);
            removed_count
        }
    }

    fn on_stream_finished(&self, context: &SwQosMaxStreamsConnectionContext) {
        context
            .last_update
            .store(timing::timestamp(), Ordering::Relaxed);
    }

    #[allow(clippy::manual_async_fn)]
    fn on_new_stream(
        &self,
        _context: &SwQosMaxStreamsConnectionContext,
    ) -> impl Future<Output = ()> + Send {
        async {}
    }

    fn max_concurrent_connections(&self) -> usize {
        // Allow 25% more connections than required to allow for handshake
        (self.config.max_staked_connections + self.config.max_unstaked_connections) * 5 / 4
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    fn make_swqos(config: SwQosMaxStreamsConfig) -> SwQosMaxStreams {
        let cancel = CancellationToken::new();
        let stats = Arc::new(StreamerStats::default());
        let staked_nodes = Arc::new(RwLock::new(crate::streamer::StakedNodes::default()));
        SwQosMaxStreams::new(config, stats, staked_nodes, cancel)
    }

    fn shared_counter(num_connections: usize) -> Arc<SwQosMaxStreamsStreamerCounter> {
        let counter = Arc::new(SwQosMaxStreamsStreamerCounter::new());
        counter
            .connection_count
            .store(num_connections, Ordering::Relaxed);
        counter
    }

    fn accept_stream(
        swqos: &SwQosMaxStreams,
        ctx: &SwQosMaxStreamsConnectionContext,
    ) -> StreamAcceptedAction {
        swqos.handle_accepted_stream(ctx)
    }

    fn emergency_sender_bucket(counter: &Arc<SwQosMaxStreamsStreamerCounter>) -> Arc<TokenBucket> {
        counter
            .emergency_state
            .lock()
            .unwrap()
            .sender_bucket
            .as_ref()
            .cloned()
            .expect("emergency bucket should be initialized")
    }

    fn wait_for_emergency_bucket_tokens(
        counter: &Arc<SwQosMaxStreamsStreamerCounter>,
        tokens: u64,
    ) {
        // Real time is intentional here. TokenBucket refill uses Instant-based
        // wall-clock time in ordinary unit tests; it does not expose a manual
        // test clock outside shuttle-test.
        let bucket = emergency_sender_bucket(counter);
        let start = Instant::now();
        let timeout = Duration::from_secs(1);

        loop {
            if bucket.current_tokens() >= tokens {
                return;
            }

            assert!(
                start.elapsed() < timeout,
                "timed out waiting for {tokens} emergency bucket tokens; current={}",
                bucket.current_tokens()
            );

            let sleep_for = bucket
                .us_to_have_tokens(tokens)
                .map(Duration::from_micros)
                .unwrap_or_else(|| Duration::from_millis(1))
                .max(Duration::from_millis(1));
            std::thread::sleep(sleep_for + Duration::from_millis(5));
        }
    }

    fn force_load_tracker_recovery(swqos: &SwQosMaxStreams, delta: Duration) {
        swqos.load_tracker().advance_time_for_tests(delta);
        assert!(
            !swqos.load_tracker().is_saturated(),
            "load tracker did not recover after {:?}; bucket={}",
            delta,
            swqos.load_tracker().bucket_level()
        );
    }

    fn unstaked_context() -> SwQosMaxStreamsConnectionContext {
        unstaked_context_with_counter(shared_counter(1))
    }

    fn unstaked_context_with_counter(
        counter: Arc<SwQosMaxStreamsStreamerCounter>,
    ) -> SwQosMaxStreamsConnectionContext {
        SwQosMaxStreamsConnectionContext {
            peer_type: ConnectionPeerType::Unstaked,
            remote_pubkey: None,
            total_stake: 0,
            in_staked_table: false,
            last_update: Arc::new(AtomicU64::new(0)),
            stream_counter: Some(counter),
        }
    }

    fn staked_context(
        stake: u64,
        total_stake: u64,
        num_connections: usize,
    ) -> SwQosMaxStreamsConnectionContext {
        staked_context_with_counter(stake, total_stake, shared_counter(num_connections))
    }

    fn staked_context_with_counter(
        stake: u64,
        total_stake: u64,
        counter: Arc<SwQosMaxStreamsStreamerCounter>,
    ) -> SwQosMaxStreamsConnectionContext {
        staked_context_with_pubkey_and_counter(
            stake,
            total_stake,
            solana_pubkey::Pubkey::new_unique(),
            counter,
        )
    }

    fn staked_context_with_pubkey_and_counter(
        stake: u64,
        total_stake: u64,
        pubkey: solana_pubkey::Pubkey,
        counter: Arc<SwQosMaxStreamsStreamerCounter>,
    ) -> SwQosMaxStreamsConnectionContext {
        SwQosMaxStreamsConnectionContext {
            peer_type: ConnectionPeerType::Staked(stake),
            remote_pubkey: Some(pubkey),
            total_stake,
            in_staked_table: true,
            last_update: Arc::new(AtomicU64::new(0)),
            stream_counter: Some(counter),
        }
    }

    // -- Saturated path --

    #[test]
    fn test_saturated_unstaked_returns_zero() {
        let swqos = make_swqos(SwQosMaxStreamsConfig::default());
        let ctx = unstaked_context();
        assert_eq!(
            swqos.compute_max_streams_for_rtt(&ctx, Duration::from_millis(50), true),
            Some(0),
        );
    }

    #[test]
    fn test_saturated_quota_scales_with_rtt() {
        // Same stake, double RTT -> double quota (throughput stays the same)
        let swqos = make_swqos(SwQosMaxStreamsConfig::default());
        let ctx = staked_context(1_000, 100_000, 1);
        let q50 = swqos
            .compute_max_streams_for_rtt(&ctx, Duration::from_millis(50), true)
            .unwrap();
        let q100 = swqos
            .compute_max_streams_for_rtt(&ctx, Duration::from_millis(100), true)
            .unwrap();
        assert_eq!(q100, q50 * 2);
    }

    #[test]
    fn test_saturated_quota_scales_with_stake() {
        // Saturated quotas are stake-proportional, but keep stakes low so that
        // we don't hit the max cap
        let swqos = make_swqos(SwQosMaxStreamsConfig::default());
        let ctx1 = staked_context(100, 100_000, 1);
        let ctx2 = staked_context(300, 100_000, 1);
        let q1 = swqos
            .compute_max_streams_for_rtt(&ctx1, Duration::from_millis(100), true)
            .unwrap();
        let q2 = swqos
            .compute_max_streams_for_rtt(&ctx2, Duration::from_millis(100), true)
            .unwrap();
        assert_eq!(q1 * 3, q2);
    }

    #[test]
    fn test_saturated_quota_shared_by_connections() {
        let swqos = make_swqos(SwQosMaxStreamsConfig {
            max_streams_per_ms: 1000,
            ..SwQosMaxStreamsConfig::default()
        });
        let rtt = Duration::from_millis(100);
        let ctx1 = staked_context(1_000, 100_000, 1);
        let ctx4 = staked_context(1_000, 100_000, 4);
        let q1 = swqos.compute_max_streams_for_rtt(&ctx1, rtt, true).unwrap();
        let q4 = swqos.compute_max_streams_for_rtt(&ctx4, rtt, true).unwrap();
        assert!(q4 * 4 == q1);
    }

    #[test]
    fn test_saturated_tiny_stake_gets_minimum_one() {
        // Stake so small that quota rounds to 0, but .max(1) ensures at least 1
        let swqos = make_swqos(SwQosMaxStreamsConfig {
            max_streams_per_ms: 500,
            ..SwQosMaxStreamsConfig::default()
        });
        let ctx = staked_context(1, 1_000_000_000, 1);
        assert_eq!(
            swqos.compute_max_streams_for_rtt(&ctx, Duration::from_millis(50), true),
            Some(1),
        );
    }

    #[test]
    fn test_saturated_total_stake_zero_no_panic() {
        let swqos = make_swqos(SwQosMaxStreamsConfig::default());
        let ctx = staked_context(1_000, 0, 1);
        assert_eq!(
            swqos.compute_max_streams_for_rtt(&ctx, Duration::from_millis(50), true),
            Some(1),
        );
    }

    // -- Unsaturated path --

    #[test]
    fn test_unsaturated_base_at_reference_rtt() {
        let swqos = make_swqos(SwQosMaxStreamsConfig::default());
        let ctx = staked_context(1_000, 100_000, 1);
        // At REFERENCE_RTT (100ms): rtt_scale=1.0 -> base_max_streams_staked
        assert_eq!(
            swqos.compute_max_streams_for_rtt(&ctx, REFERENCE_RTT, false),
            Some(DEFAULT_BASE_MAX_STREAMS_STAKED),
        );
    }

    #[test]
    fn test_unsaturated_scales_linearly_with_rtt() {
        let swqos = make_swqos(SwQosMaxStreamsConfig::default());
        let ctx = staked_context(1_000, 100_000, 1);
        let q100 = swqos
            .compute_max_streams_for_rtt(&ctx, Duration::from_millis(100), false)
            .unwrap();
        let q200 = swqos
            .compute_max_streams_for_rtt(&ctx, Duration::from_millis(200), false)
            .unwrap();
        assert_eq!(q100 * 2, q200);
    }

    #[test]
    fn test_unsaturated_low_rtt_clamped_for_staked() {
        let swqos = make_swqos(SwQosMaxStreamsConfig::default());
        let ctx = staked_context(1_000, 100_000, 1);
        // Staked RTT is clamped to MIN_RTT_STAKED_UNSATURATED
        assert_eq!(
            swqos.compute_max_streams_for_rtt(&ctx, Duration::from_millis(1), false),
            swqos.compute_max_streams_for_rtt(&ctx, MIN_RTT_STAKED_UNSATURATED, false),
        );
    }

    #[test]
    fn test_unsaturated_low_rtt_scales_down_for_unstaked() {
        let swqos = make_swqos(SwQosMaxStreamsConfig::default());
        let ctx = unstaked_context();
        // Unstaked uses true BDP, no MIN_RTT floor.
        assert_eq!(
            swqos
                .compute_max_streams_for_rtt(&ctx, Duration::from_millis(25), false)
                .unwrap()
                * 2,
            swqos
                .compute_max_streams_for_rtt(&ctx, Duration::from_millis(50), false)
                .unwrap(),
        );
    }

    #[test]
    fn test_unsaturated_rtt_clamped_at_max() {
        let swqos = make_swqos(SwQosMaxStreamsConfig::default());
        let ctx = staked_context(1_000, 100_000, 1);
        assert_eq!(
            swqos.compute_max_streams_for_rtt(&ctx, 2 * MAX_RTT, false),
            swqos.compute_max_streams_for_rtt(&ctx, MAX_RTT, false)
        );
    }

    #[test]
    fn test_unsaturated_ignores_stake() {
        // In unsaturated mode, quota depends only on RTT, not stake
        let swqos = make_swqos(SwQosMaxStreamsConfig::default());
        let rtt = Duration::from_millis(100);
        let big = staked_context(900_000, 1_000_000, 1);
        let small = staked_context(1_000, 1_000_000, 1);
        assert_eq!(
            swqos.compute_max_streams_for_rtt(&big, rtt, false),
            swqos.compute_max_streams_for_rtt(&small, rtt, false),
        );
    }

    // -- Hard cap --

    #[test]
    fn test_saturated_quota_capped_by_unsaturated_max() {
        // 100% stake at 100ms: proportional = 100_000, but must be capped at unsaturated max.
        let swqos = make_swqos(SwQosMaxStreamsConfig {
            max_streams_per_ms: 1000,
            ..SwQosMaxStreamsConfig::default()
        });
        let ctx = staked_context(1_000_000, 1_000_000, 1);
        assert_eq!(
            swqos.compute_max_streams_for_rtt(&ctx, Duration::from_millis(100), true),
            Some(DEFAULT_BASE_MAX_STREAMS_STAKED),
        );
    }

    #[test]
    fn test_saturated_large_lamport_stakes_preserve_proportionality() {
        // Regression: without u128, capacity_tps * stake overflows above ~37K SOL,
        // collapsing all large stakers to the same share_tps.
        let swqos = make_swqos(SwQosMaxStreamsConfig {
            max_streams_per_ms: 500,
            ..SwQosMaxStreamsConfig::default()
        });
        const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
        let stake_large = 10_000_000 * LAMPORTS_PER_SOL; // 10M SOL
        let stake_small = 10_000 * LAMPORTS_PER_SOL; // 10K SOL
        let total = stake_large + stake_small;
        let rtt = Duration::from_millis(100);

        let ctx_large = staked_context(stake_large, total, 1);
        let ctx_small = staked_context(stake_small, total, 1);

        // 10M SOL -> quota capped at DEFAULT_BASE_MAX_STREAMS_STAKED; 10K SOL -> quota 49.
        // Without u128: 10M SOL overflows to quota ~ 183, destroying proportionality.
        let q_large = swqos
            .compute_max_streams_for_rtt(&ctx_large, rtt, true)
            .unwrap();
        let q_small = swqos
            .compute_max_streams_for_rtt(&ctx_small, rtt, true)
            .unwrap();
        // Large staker hits the cap, proving no overflow.
        assert_eq!(q_large, DEFAULT_BASE_MAX_STREAMS_STAKED);
        assert!(q_large > q_small, "expected large staker to dominate");
    }

    // -- Emergency sender bucket --

    /// Helper: build SwQosMaxStreams with a deep-negative bucket for emergency tests.
    fn make_swqos_with_debt(config: SwQosMaxStreamsConfig, debt: u64) -> SwQosMaxStreams {
        let swqos = make_swqos(config);
        // Drive the bucket negative by acquiring many tokens.
        let burst = swqos.load_tracker().bucket_level() as u64;
        for _ in 0..burst.saturating_add(debt) {
            swqos.load_tracker().acquire();
        }
        swqos
    }

    #[test]
    fn emergency_bucket_stays_inactive_above_threshold() {
        let swqos = make_swqos(SwQosMaxStreamsConfig {
            emergency_debt_threshold: Some(-10_000),
            ..SwQosMaxStreamsConfig::default()
        });
        let ctx = staked_context(1_000, 100_000, 1);
        assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);
    }

    #[test]
    fn emergency_bucket_can_be_disabled() {
        let swqos = make_swqos_with_debt(
            SwQosMaxStreamsConfig {
                emergency_debt_threshold: None,
                ..SwQosMaxStreamsConfig::default()
            },
            200_000,
        );
        let ctx = staked_context(1_000, 100_000, 1);
        assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);
    }

    #[test]
    fn emergency_bucket_closes_sender_that_overspends_burst() {
        let swqos = make_swqos_with_debt(
            SwQosMaxStreamsConfig {
                max_streams_per_ms: 1,
                emergency_debt_threshold: Some(-10),
                ..SwQosMaxStreamsConfig::default()
            },
            200,
        );
        let ctx = staked_context(10, 100, 1);
        for _ in 0..swqos.compute_sender_bucket_capacity_streams(&ctx) {
            assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);
        }
        assert_eq!(
            accept_stream(&swqos, &ctx),
            StreamAcceptedAction::CloseConnection
        );
    }

    #[test]
    fn phase2_only_closes_while_debt_is_still_deep() {
        let swqos = make_swqos_with_debt(
            SwQosMaxStreamsConfig {
                max_streams_per_ms: 1,
                emergency_debt_threshold: Some(-10),
                ..SwQosMaxStreamsConfig::default()
            },
            200,
        );
        let ctx = staked_context(10, 100, 1);

        for _ in 0..swqos.compute_sender_bucket_capacity_streams(&ctx) {
            assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);
        }

        swqos
            .load_tracker()
            .advance_time_for_tests(Duration::from_millis(211));
        assert!(swqos.load_tracker().bucket_level() > -10);
        assert!(swqos.load_tracker().bucket_level() <= 0);
        assert!(swqos.load_tracker().is_saturated());
        assert!(swqos.emergency_active.load(Ordering::Relaxed));

        // The sender has exhausted its emergency bucket, but closes are gated
        // on the current global debt still being below the deep threshold.
        assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);

        while swqos.load_tracker().bucket_level() > -10 {
            swqos.load_tracker().acquire();
        }

        // Once debt falls back to the deep threshold, the still-exhausted
        // sender bucket triggers a close on the next stream.
        assert_eq!(
            accept_stream(&swqos, &ctx),
            StreamAcceptedAction::CloseConnection
        );
    }

    #[test]
    fn phase2_zero_capacity_sender_only_closes_while_debt_is_still_deep() {
        let swqos = make_swqos_with_debt(
            SwQosMaxStreamsConfig {
                max_streams_per_ms: 1,
                emergency_debt_threshold: Some(-10),
                ..SwQosMaxStreamsConfig::default()
            },
            200,
        );
        let ctx = unstaked_context();

        assert_eq!(
            accept_stream(&swqos, &ctx),
            StreamAcceptedAction::CloseConnection
        );
        assert!(swqos.emergency_active.load(Ordering::Relaxed));

        swqos
            .load_tracker()
            .advance_time_for_tests(Duration::from_millis(250));
        assert!(swqos.load_tracker().bucket_level() > -10);
        assert!(swqos.load_tracker().bucket_level() < 90);
        assert!(swqos.load_tracker().is_saturated());
        assert!(swqos.emergency_active.load(Ordering::Relaxed));

        // Zero-capacity Phase 2 senders still only close while the global
        // debt is below the deep emergency threshold.
        assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);

        while swqos.load_tracker().bucket_level() > -10 {
            swqos.load_tracker().acquire();
        }

        assert_eq!(
            accept_stream(&swqos, &ctx),
            StreamAcceptedAction::CloseConnection
        );
    }

    #[test]
    fn emergency_bucket_exits_after_idle_recovery_before_sender_bucket_refills() {
        let swqos = make_swqos_with_debt(
            SwQosMaxStreamsConfig {
                max_streams_per_ms: 1,
                emergency_debt_threshold: Some(-10),
                ..SwQosMaxStreamsConfig::default()
            },
            20,
        );
        let counter = shared_counter(1);
        let ctx = staked_context_with_counter(1, 10_000, counter.clone());
        assert_eq!(swqos.compute_sender_bucket_capacity_streams(&ctx), 1);

        assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);
        assert!(swqos.emergency_active.load(Ordering::Relaxed));

        // Real sleep is intentional: the sender bucket is a TokenBucket, and
        // it does not provide a manual test clock for ordinary unit tests.
        //
        // This wait is chosen to let the global load tracker recover while the
        // sender's Phase 2 bucket is still empty. The point of the test is to
        // prove that Phase 2 exits on global recovery rather than on sender
        // bucket refill.
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(emergency_sender_bucket(&counter).current_tokens(), 0);

        // The sender bucket still has no tokens, but the next stream should be
        // accepted because global recovery disarms Phase 2 before bucket
        // exhaustion can force a close.
        assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);
        assert!(!swqos.emergency_active.load(Ordering::Relaxed));
    }

    #[test]
    fn emergency_bucket_refills_for_fair_share_sender() {
        let swqos = make_swqos_with_debt(
            SwQosMaxStreamsConfig {
                max_streams_per_ms: 10,
                emergency_debt_threshold: Some(-10),
                ..SwQosMaxStreamsConfig::default()
            },
            2_000,
        );
        let counter = shared_counter(1);
        let ctx = staked_context_with_counter(1, 400, counter.clone());
        let burst = swqos.compute_sender_bucket_capacity_streams(&ctx);

        for _ in 0..burst {
            assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);
        }
        assert_eq!(
            accept_stream(&swqos, &ctx),
            StreamAcceptedAction::CloseConnection
        );

        wait_for_emergency_bucket_tokens(&counter, 1);
        assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);
        assert_eq!(
            accept_stream(&swqos, &ctx),
            StreamAcceptedAction::CloseConnection
        );
    }

    #[test]
    fn emergency_bucket_is_shared_across_connections() {
        let swqos = make_swqos_with_debt(
            SwQosMaxStreamsConfig {
                max_streams_per_ms: 1,
                emergency_debt_threshold: Some(-10),
                ..SwQosMaxStreamsConfig::default()
            },
            200,
        );
        let pubkey = solana_pubkey::Pubkey::new_unique();
        let counter = shared_counter(2);
        let ctx1 = staked_context_with_pubkey_and_counter(10, 100, pubkey, counter.clone());
        let ctx2 = staked_context_with_pubkey_and_counter(10, 100, pubkey, counter);

        for i in 0..swqos.compute_sender_bucket_capacity_streams(&ctx1) {
            let ctx = if i % 2 == 0 { &ctx1 } else { &ctx2 };
            assert_eq!(accept_stream(&swqos, ctx), StreamAcceptedAction::Continue);
        }
        assert_eq!(
            accept_stream(&swqos, &ctx1),
            StreamAcceptedAction::CloseConnection
        );
    }

    #[test]
    fn emergency_bucket_closes_unstaked_immediately() {
        let swqos = make_swqos_with_debt(
            SwQosMaxStreamsConfig {
                max_streams_per_ms: 1,
                emergency_debt_threshold: Some(-10),
                ..SwQosMaxStreamsConfig::default()
            },
            200,
        );
        let ctx = unstaked_context();
        assert_eq!(
            accept_stream(&swqos, &ctx),
            StreamAcceptedAction::CloseConnection
        );
    }

    #[test]
    fn emergency_bucket_close_does_not_charge_load_debt_or_stats() {
        let stats = Arc::new(StreamerStats::default());
        let swqos = SwQosMaxStreams::new(
            SwQosMaxStreamsConfig {
                max_streams_per_ms: 1,
                emergency_debt_threshold: Some(-10),
                ..SwQosMaxStreamsConfig::default()
            },
            stats.clone(),
            Arc::new(RwLock::new(crate::streamer::StakedNodes::default())),
            CancellationToken::new(),
        );
        let burst = swqos.load_tracker().bucket_level() as u64;
        for _ in 0..burst.saturating_add(200) {
            swqos.load_tracker().acquire();
        }

        let ctx = staked_context(10, 100, 1);
        for _ in 0..swqos.compute_sender_bucket_capacity_streams(&ctx) {
            assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);
        }

        let bucket_before_close = swqos.load_tracker().bucket_level();
        let saturated_before_close = stats.saturated_staked_streams.load(Ordering::Relaxed);
        assert_eq!(
            accept_stream(&swqos, &ctx),
            StreamAcceptedAction::CloseConnection
        );
        assert_eq!(swqos.load_tracker().bucket_level(), bucket_before_close);
        assert_eq!(
            stats.saturated_staked_streams.load(Ordering::Relaxed),
            saturated_before_close
        );
    }

    #[test]
    fn emergency_bucket_reentry_resets_sender_burst() {
        let swqos = make_swqos_with_debt(
            SwQosMaxStreamsConfig {
                max_streams_per_ms: 1,
                emergency_debt_threshold: Some(-10),
                ..SwQosMaxStreamsConfig::default()
            },
            20,
        );
        let counter = shared_counter(1);
        let ctx = staked_context_with_counter(1, 10_000, counter.clone());
        let threshold = swqos.emergency_debt_threshold.unwrap();
        let generation1_burst = swqos.compute_sender_bucket_capacity_streams(&ctx);
        assert_eq!(generation1_burst, 1);

        for _ in 0..generation1_burst {
            assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);
        }
        assert_eq!(
            accept_stream(&swqos, &ctx),
            StreamAcceptedAction::CloseConnection
        );
        assert_eq!(swqos.emergency_generation.load(Ordering::Relaxed), 1);
        {
            let state = counter.emergency_state.lock().unwrap();
            assert_eq!(state.bucket_generation, 1);
            assert_eq!(state.bucket_capacity_streams, generation1_burst);
        }

        force_load_tracker_recovery(&swqos, Duration::from_millis(250));
        assert!(!swqos.should_close_due_to_phase2_bucket_exhaustion(&ctx));
        assert!(!swqos.emergency_active.load(Ordering::Relaxed));

        // Re-enter Phase 2 with a different connection count. For this tiny
        // staker, the min-1-per-connection floor makes the sender-wide Phase 2
        // burst scale from 1 to 5 streams across generations.
        counter.connection_count.store(5, Ordering::Relaxed);
        let generation2_burst = swqos.compute_sender_bucket_capacity_streams(&ctx);
        assert_eq!(generation2_burst, 5);

        while swqos.load_tracker().bucket_level() > threshold {
            swqos.load_tracker().acquire();
        }

        assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);
        assert_eq!(swqos.emergency_generation.load(Ordering::Relaxed), 2);
        {
            let state = counter.emergency_state.lock().unwrap();
            assert_eq!(state.bucket_generation, 2);
            assert_eq!(state.bucket_capacity_streams, generation2_burst);
        }
        for _ in 1..generation2_burst {
            assert_eq!(accept_stream(&swqos, &ctx), StreamAcceptedAction::Continue);
        }
        assert_eq!(
            accept_stream(&swqos, &ctx),
            StreamAcceptedAction::CloseConnection
        );
    }
}
