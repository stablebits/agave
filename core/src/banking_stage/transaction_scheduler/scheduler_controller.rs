//! Control flow for BankingStage's transaction scheduler.
//!

use {
    super::{
        receive_and_buffer::{DisconnectedError, ReceiveAndBuffer},
        scheduler::Scheduler,
        scheduler_error::SchedulerError,
        scheduler_metrics::{SchedulerCountMetrics, SchedulerTimingMetrics, SchedulingDetails},
    },
    crate::{
        banking_stage::{
            TOTAL_BUFFERED_PACKETS,
            consume_worker::ConsumeWorkerMetrics,
            decision_maker::{BufferedPacketsDecision, DecisionMaker},
            transaction_scheduler::{
                receive_and_buffer::ReceivingStats, transaction_priority_id::TransactionPriorityId,
                transaction_state_container::StateContainer,
            },
        },
        validator::SchedulerPacing,
    },
    agave_banking_stage_ingress_types::BankingStageFeedback,
    solana_clock::DEFAULT_MS_PER_SLOT,
    solana_cost_model::cost_tracker::SharedBlockCost,
    solana_measure::measure_us,
    solana_net_utils::token_bucket::TokenBucket,
    solana_runtime::bank_forks::SharableBanks,
    solana_svm::transaction_error_metrics::TransactionErrorMetrics,
    std::{
        num::{NonZeroU64, Saturating},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    },
};

const CHECK_CHUNK: usize = 128;

/// Default token-bucket refill rate (packets per second) for the pf-floor
/// saturation signal. Approximates the rate at which the scheduler can drain
/// its receive+parse+schedule loop.
pub const DEFAULT_TOKEN_BUCKET_REFILL_TPS: u64 = 100_000;
/// Default token-bucket burst capacity (packets). Controls how much of a
/// short-term spike is absorbed before saturation triggers.
pub const DEFAULT_TOKEN_BUCKET_BURST: u64 = 25_000;
/// Default AND-guard on saturation entry: require the scheduler queue to hold
/// at least this percentage of `TOTAL_BUFFERED_PACKETS` before the token
/// bucket is allowed to drive saturation. This prevents publishing a stale
/// floor when the queue is near-empty (the min priority of a tiny set of
/// stragglers is noise, not signal).
pub const DEFAULT_SATURATION_MIN_QUEUE_PCT: u8 = 90;

#[derive(Clone)]
pub struct SchedulerConfig {
    pub scheduler_pacing: SchedulerPacing,
    /// When true, the scheduler publishes a priority floor when saturated,
    /// and sigverify drops incoming packets whose approximated priority is
    /// below that floor. When false, the mechanism is a no-op.
    pub pf_floor_enabled: bool,
    /// Token-bucket refill rate (packets per second). Incoming arrivals above
    /// this rate deplete the bucket and drive saturation.
    pub token_bucket_refill_tps: u64,
    /// Token-bucket burst capacity (packets). Short-term arrival spikes up to
    /// this many packets are absorbed before saturation triggers.
    pub token_bucket_burst: u64,
    /// AND-guard on saturation entry: the token bucket must be empty AND the
    /// scheduler queue must contain at least this percentage of
    /// `TOTAL_BUFFERED_PACKETS` for saturation to fire.
    pub saturation_min_queue_pct: u8,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            scheduler_pacing: SchedulerPacing::FillTimeMillis(
                DEFAULT_SCHEDULER_PACING_FILL_TIME_MILLIS,
            ),
            pf_floor_enabled: true,
            token_bucket_refill_tps: DEFAULT_TOKEN_BUCKET_REFILL_TPS,
            token_bucket_burst: DEFAULT_TOKEN_BUCKET_BURST,
            saturation_min_queue_pct: DEFAULT_SATURATION_MIN_QUEUE_PCT,
        }
    }
}

const DEFAULT_SCHEDULER_PACING_NON_FILL_TIME_MILLIS: u64 = 50;
pub(crate) const DEFAULT_SCHEDULER_PACING_FILL_TIME_MILLIS: NonZeroU64 =
    NonZeroU64::new(DEFAULT_MS_PER_SLOT - DEFAULT_SCHEDULER_PACING_NON_FILL_TIME_MILLIS).unwrap();

/// Controls packet and transaction flow into scheduler, and scheduling execution.
pub(crate) struct SchedulerController<R, S>
where
    R: ReceiveAndBuffer,
    S: Scheduler<R::Transaction>,
{
    /// Exit signal for the scheduler thread.
    exit: Arc<AtomicBool>,
    config: SchedulerConfig,
    /// Decision maker for determining what should be done with transactions.
    decision_maker: DecisionMaker,
    receive_and_buffer: R,
    sharable_banks: SharableBanks,
    /// Container for transaction state.
    /// Shared resource between `packet_receiver` and `scheduler`.
    container: R::Container,
    /// State for scheduling and communicating with worker threads.
    scheduler: S,
    /// Metrics tracking counts on transactions in different states
    /// over an interval and during a leader slot.
    count_metrics: SchedulerCountMetrics,
    /// Metrics tracking time spent in difference code sections
    /// over an interval and during a leader slot.
    timing_metrics: SchedulerTimingMetrics,
    /// Metric report handles for the worker threads.
    worker_metrics: Vec<Arc<ConsumeWorkerMetrics>>,
    /// Detailed scheduling metrics.
    scheduling_details: SchedulingDetails,
    /// Cursor for incremental recheck sweep of the priority queue.
    recheck_cursor: Option<TransactionPriorityId>,
    /// Recheck IDs scratch space.
    recheck_chunk: Vec<TransactionPriorityId>,
    /// Shared feedback with sigverify: the scheduler publishes a priority
    /// floor in sigverify's comparison space (read by sigverify to drop
    /// at-or-below-floor txs) and reads a
    /// monotonic arrivals counter (written by sigverify) to drive the token
    /// bucket.
    feedback: Arc<BankingStageFeedback>,
    /// Whether the scheduler is currently in the saturated state (simple
    /// boolean latch for hysteresis bookkeeping).
    saturated: bool,
    /// Token bucket driving the pf-floor saturation signal. `None` when
    /// `pf_floor_enabled` is false to keep the mechanism fully zero-cost.
    saturation_token_bucket: Option<TokenBucket>,
    /// Last observed value of `BankingStageFeedback::total_arrivals`,
    /// used to compute per-tick arrivals for the token bucket.
    prev_total_received: u64,
    /// Precomputed from config: buffer occupancy (absolute packets, i.e.
    /// `id_to_transaction_state.len()`) at which the AND-guard on saturation
    /// entry is satisfied. Uses buffer size rather than priority-queue size
    /// so that saturation still fires when the scheduler is actively
    /// scheduling and the priority queue is momentarily near-empty while the
    /// full buffer remains under pressure.
    buffer_guard_threshold: usize,
    /// Precomputed from config: token-bucket level at which saturation
    /// de-asserts (hysteresis), currently `token_bucket_burst / 2`.
    desaturate_tokens_threshold: u64,
}

impl<R, S> SchedulerController<R, S>
where
    R: ReceiveAndBuffer,
    S: Scheduler<R::Transaction>,
{
    pub fn new(
        exit: Arc<AtomicBool>,
        config: SchedulerConfig,
        decision_maker: DecisionMaker,
        receive_and_buffer: R,
        sharable_banks: SharableBanks,
        scheduler: S,
        worker_metrics: Vec<Arc<ConsumeWorkerMetrics>>,
        feedback: Arc<BankingStageFeedback>,
    ) -> Self {
        let saturation_token_bucket = config.pf_floor_enabled.then(|| {
            // Start full: the bucket represents slack for absorbing a burst,
            // not work done. At startup the scheduler isn't behind on
            // anything, so give it its full burst budget to absorb the first
            // wave of arrivals (e.g. a backlog accumulated during a preceding
            // non-leader period).
            TokenBucket::new(
                config.token_bucket_burst,
                config.token_bucket_burst,
                config.token_bucket_refill_tps as f64,
            )
        });
        let prev_total_received = feedback.total_arrivals();
        let buffer_guard_threshold =
            TOTAL_BUFFERED_PACKETS.saturating_mul(config.saturation_min_queue_pct as usize) / 100;
        let desaturate_tokens_threshold = config.token_bucket_burst.saturating_div(2);
        Self {
            exit,
            config,
            decision_maker,
            receive_and_buffer,
            sharable_banks,
            container: R::Container::with_capacity(TOTAL_BUFFERED_PACKETS),
            scheduler,
            count_metrics: SchedulerCountMetrics::default(),
            timing_metrics: SchedulerTimingMetrics::default(),
            worker_metrics,
            scheduling_details: SchedulingDetails::default(),
            recheck_cursor: None,
            recheck_chunk: Vec::with_capacity(CHECK_CHUNK),
            feedback,
            saturated: false,
            saturation_token_bucket,
            prev_total_received,
            buffer_guard_threshold,
            desaturate_tokens_threshold,
        }
    }

    pub fn run(&mut self) -> Result<(), SchedulerError> {
        let mut most_recent_leader_slot = None;
        let mut cost_pacer = None;

        while !self.exit.load(Ordering::Relaxed) {
            let now = Instant::now();
            // BufferedPacketsDecision is shared with legacy BankingStage, which will forward
            // packets. Initially, not renaming these decision variants but the actions taken
            // are different, since new BankingStage will not forward packets.
            // For `Forward` and `ForwardAndHold`, we want to receive packets but will not
            // forward them to the next leader. In this case, `ForwardAndHold` is
            // indistinguishable from `Hold`.
            //
            // `Forward` will drop packets from the buffer instead of forwarding.
            // During receiving, since packets would be dropped from buffer anyway, we can
            // bypass sanitization and buffering and immediately drop the packets.
            let (decision, decision_time_us) =
                measure_us!(self.decision_maker.make_consume_or_forward_decision());
            self.timing_metrics.update(|timing_metrics| {
                timing_metrics.decision_time_us += decision_time_us;
            });
            let new_leader_slot = decision.bank().map(|b| b.slot());
            self.count_metrics
                .maybe_report_and_reset_slot(new_leader_slot);
            self.timing_metrics
                .maybe_report_and_reset_slot(new_leader_slot);

            if most_recent_leader_slot != new_leader_slot {
                self.container.flush_held_transactions();
                most_recent_leader_slot = new_leader_slot;
                cost_pacer = decision.bank().map(|b| {
                    let cost_tracker = b.read_cost_tracker().unwrap();
                    let block_limit = cost_tracker.get_block_limit();
                    let shared_block_cost = cost_tracker.shared_block_cost();
                    drop(cost_tracker);

                    // If pacing_fill_time is greater than the bank's slot time,
                    // adjust the pacing_fill_time to be the slot time, and warn.
                    let fill_time = self.config.scheduler_pacing.fill_time();
                    if let Some(pacing_fill_time) = fill_time.as_ref() {
                        if pacing_fill_time.as_nanos() > b.ns_per_slot {
                            warn!(
                                "scheduler pacing config pacing_fill_time {:?} is greater than \
                                 the bank's slot time {}, setting to slot time",
                                pacing_fill_time, b.ns_per_slot,
                            );
                            self.config.scheduler_pacing = SchedulerPacing::FillTimeMillis(
                                NonZeroU64::new(
                                    (b.ns_per_slot as u64 / 1_000_000).saturating_sub(
                                        DEFAULT_SCHEDULER_PACING_NON_FILL_TIME_MILLIS,
                                    ),
                                )
                                .unwrap_or(NonZeroU64::new(1).unwrap()),
                            );
                        }
                    }

                    CostPacer {
                        block_limit,
                        shared_block_cost,
                        detection_time: now,
                        fill_time,
                    }
                });
            }

            self.receive_completed()?;
            let scheduled = self.process_transactions(&decision, cost_pacer.as_ref(), &now)?;
            if scheduled == 0 {
                let (_, clean_time_us) = measure_us!(self.incremental_recheck());
                self.timing_metrics.update(|timing_metrics| {
                    timing_metrics.clean_time_us += clean_time_us;
                });
            }
            self.receive_and_buffer_packets(&decision).map_err(|_| {
                SchedulerError::DisconnectedRecvChannel("receive and buffer disconnected")
            })?;
            // Report metrics only if there is data.
            // Reset intervals when appropriate, regardless of report.
            let should_report = self.count_metrics.interval_has_data();
            let priority_min_max = self.container.get_min_max_priority();
            self.count_metrics.update(|count_metrics| {
                count_metrics.update_priority_stats(priority_min_max);
            });
            self.update_scheduler_saturation_feedback();
            self.count_metrics
                .maybe_report_and_reset_interval(should_report);
            self.timing_metrics
                .maybe_report_and_reset_interval(should_report);
            self.worker_metrics
                .iter()
                .for_each(|metrics| metrics.maybe_report_and_reset());
            self.scheduling_details.maybe_report();
        }

        Ok(())
    }

    /// Process packets based on decision.
    fn process_transactions(
        &mut self,
        decision: &BufferedPacketsDecision,
        cost_pacer: Option<&CostPacer>,
        now: &Instant,
    ) -> Result<usize, SchedulerError> {
        let scheduled = match decision {
            BufferedPacketsDecision::Consume(_bank) => {
                let scheduling_budget = cost_pacer
                    .expect("cost pacer must be set for Consume")
                    .scheduling_budget(now);
                let (scheduling_summary, schedule_time_us) = measure_us!(
                    self.scheduler
                        .schedule(&mut self.container, scheduling_budget,)?
                );

                self.count_metrics.update(|count_metrics| {
                    count_metrics.num_scheduled += scheduling_summary.num_scheduled;
                    count_metrics.num_unschedulable_conflicts +=
                        scheduling_summary.num_unschedulable_conflicts;
                    count_metrics.num_unschedulable_threads +=
                        scheduling_summary.num_unschedulable_threads;
                });

                self.timing_metrics.update(|timing_metrics| {
                    timing_metrics.schedule_time_us += schedule_time_us;
                });
                self.scheduling_details.update(&scheduling_summary);

                scheduling_summary.num_scheduled
            }
            BufferedPacketsDecision::Forward => {
                let (_, clear_time_us) = measure_us!(self.clear_container());
                self.timing_metrics.update(|timing_metrics| {
                    timing_metrics.clear_time_us += clear_time_us;
                });

                0
            }
            BufferedPacketsDecision::ForwardAndHold => 0,
            BufferedPacketsDecision::Hold => 0,
        };

        Ok(scheduled)
    }

    /// Update the scheduler saturation feedback channel based on incoming
    /// packet arrivals and the current queue state.
    ///
    /// Saturation is driven by a token bucket fed at
    /// `config.token_bucket_refill_tps` and consumed by actual arrivals. The
    /// bucket going empty under pressure is the primary "over-capacity"
    /// signal. It is AND-guarded with a minimum queue-occupancy check so
    /// that we only publish a floor when there is a meaningful set of
    /// in-queue transactions to derive it from (otherwise the min priority
    /// of a near-empty queue is arbitrary and the floor would be noise).
    ///
    /// **Published floor:** the bank-context full-formula priority of the
    /// scheduler queue's lowest-priority transaction (the same number
    /// the BTreeSet ranks by — `reward * 1_000_000 / (cost + 1)` from
    /// `priority_formula::calculate_priority_and_cost`). Sigverify
    /// approximates the same formula per-packet against
    /// `MAINNET_FEE_CONTEXT` (see
    /// `priority_formula::calculate_pf_drop_priority`). Bank-vs-mainnet
    /// fee-context drift is small (mainnet defaults match real mainnet
    /// `lamports_per_signature` and `burn_percent`); the comparison is
    /// effectively unit-consistent.
    ///
    /// Semantics: "drop arrivals that are worse than what we'd evict
    /// anyway." The scheduler's BTreeSet evicts the lowest-priority entry
    /// on overflow, so any incoming tx below the queue-min is one we
    /// would have evicted on insertion — sigverify cuts those off
    /// upstream to save signature-verification CPU. The floor is
    /// self-stabilizing: when the queue evicts low-priority entries,
    /// queue-min rises and the published floor with it; when the queue
    /// drains, the floor falls and sigverify lets more through.
    ///
    /// We do *not* try to drive `num_dropped_on_capacity` to zero —
    /// capacity drops are how the scheduler enforces priority-aware
    /// admission (lowest queue entry yields to a higher-priority arrival),
    /// so a non-zero counter under load is the expected behavior.
    ///
    /// When the bucket is replenished past half of its burst capacity (or
    /// the buffer drains below the guard), we clear the published floor.
    fn update_scheduler_saturation_feedback(&mut self) {
        // Observe the sigverify→scheduler channel depth every tick,
        // independent of the pf-floor feature. Useful on its own for
        // spotting upstream backpressure, and reported whether or not
        // the token bucket is enabled.
        let channel_in_flight_packets = self.feedback.in_flight_packets();
        self.count_metrics.update(|count_metrics| {
            count_metrics.channel_in_flight_packets = channel_in_flight_packets;
        });

        let Some(bucket) = self.saturation_token_bucket.as_ref() else {
            return; // feature disabled
        };

        // Consume this tick's arrivals from the bucket, taking whatever is
        // available. The remainder (requested - consumed) is the amount by
        // which arrivals exceeded the bucket this tick, i.e. "over budget."
        let total_received = self.feedback.total_arrivals();
        let arrivals = total_received.saturating_sub(self.prev_total_received);
        self.prev_total_received = total_received;
        let consumed = bucket.consume_tokens_saturating(arrivals);
        let over_budget = arrivals.saturating_sub(consumed);
        let current_tokens = bucket.current_tokens();

        // Record observability metrics regardless of saturation state.
        self.count_metrics.update(|count_metrics| {
            count_metrics.rate_limiter_tokens_remaining = current_tokens;
        });

        // Buffer guard: require a meaningfully full buffer before publishing
        // a floor. Uses the full buffer (priority-queue + held/in-flight) so
        // that saturation stays active while the scheduler is actively
        // scheduling and the priority queue is momentarily near-empty.
        let buffer_guard_met = self.container.buffer_size() >= self.buffer_guard_threshold;

        if self.saturated {
            // Refresh the floor from the queue's current min (in sigverify
            // simple-priority units). If the priority queue is momentarily
            // empty (heavy in-flight scheduling) or the queue-min tx parses
            // to a zero simple-priority, keep the previous floor implicitly
            // rather than clearing — the buffer is still under pressure.
            if let Some(floor) = self.compute_pf_floor() {
                self.feedback.set_priority_floor(floor);
                self.count_metrics.update(|count_metrics| {
                    count_metrics.current_priority_fee_floor = floor;
                });
            }
            // Exit hysteresis: bucket refilled past threshold, or buffer
            // drained below guard (pressure is gone).
            if current_tokens >= self.desaturate_tokens_threshold || !buffer_guard_met {
                self.saturated = false;
                self.feedback.clear_priority_floor();
            }
        } else if over_budget > 0 && buffer_guard_met {
            self.saturated = true;
            if let Some(floor) = self.compute_pf_floor() {
                self.feedback.set_priority_floor(floor);
                self.count_metrics.update(|count_metrics| {
                    count_metrics.current_priority_fee_floor = floor;
                });
            }
        }
    }

    /// Compute the pf-floor to publish: bank-context full-formula priority
    /// of the queue's lowest-priority tx. Reads the priority directly off
    /// the `TransactionPriorityId` (cached on the BTreeSet entry — same
    /// number the scheduler ranks by, no re-derivation). Returns `None`
    /// when the queue is empty or the priority is zero (the feedback
    /// channel rejects a zero floor — `0` is the "not saturated" sentinel).
    fn compute_pf_floor(&self) -> Option<u64> {
        let priority_id = self.container.get_min_priority_id()?;
        (priority_id.priority > 0).then_some(priority_id.priority)
    }

    /// Clears the transaction state container.
    /// This only clears pending transactions, and does **not** clear in-flight transactions.
    fn clear_container(&mut self) {
        let mut num_dropped_on_clear = Saturating::<usize>(0);
        while let Some(id) = self.container.pop() {
            self.container.remove_by_id(id.id);
            num_dropped_on_clear += 1;
        }

        self.count_metrics.update(|count_metrics| {
            count_metrics.num_dropped_on_clear += num_dropped_on_clear;
        });
    }

    /// Incrementally recheck queued transactions for validity. A cursor walks the
    /// priority queue from highest to lowest priority. When the cursor reaches the end it
    /// wraps back to the top, continuously sweeping the queue.
    fn incremental_recheck(&mut self) {
        let bank = self.sharable_banks.working();

        // Walk the cursor to collect up to one chunk of valid IDs.
        self.recheck_chunk.clear();
        let mut last_seen = None;
        for id in self.container.recheck_iter(self.recheck_cursor.as_ref()) {
            last_seen = Some(*id);

            self.recheck_chunk.push(*id);
            if self.recheck_chunk.len() >= CHECK_CHUNK {
                break;
            }
        }

        // Update cursor: if we hit the chunk limit, continue from last seen;
        // otherwise we exhausted the range, so wrap back to start.
        self.recheck_cursor = if self.recheck_chunk.len() >= CHECK_CHUNK {
            last_seen
        } else {
            None
        };

        // Bail if no work to do (should only happen if container is empty).
        if self.recheck_chunk.is_empty() {
            return;
        }

        // Build our recheck batch & feed it through bank.
        let txs = {
            // NB: Always allocate a the same size chunk to help jemalloc predict us.
            let mut txs = Vec::with_capacity(CHECK_CHUNK);
            txs.extend(self.recheck_chunk.iter().map(|pid| {
                self.container
                    .get_transaction(pid.id)
                    .expect("transaction must exist")
            }));

            txs
        };
        let lock_results = vec![Ok(()); txs.len()];
        let mut error_counters = TransactionErrorMetrics::default();
        let results = bank.check_transactions::<R::Transaction>(
            &txs,
            &lock_results,
            bank.max_processing_age(),
            &mut error_counters,
        );

        let mut num_dropped = Saturating(0usize);
        for (result, pid) in results.iter().zip(self.recheck_chunk.iter()) {
            if result.is_err() {
                num_dropped += 1;
                self.container.remove_by_id(pid.id);
            }
        }

        self.count_metrics.update(|count_metrics| {
            count_metrics.num_dropped_on_clean += num_dropped;
        });
    }

    /// Receives completed transactions from the workers and updates metrics.
    fn receive_completed(&mut self) -> Result<(), SchedulerError> {
        let ((num_transactions, num_retryable), receive_completed_time_us) =
            measure_us!(self.scheduler.receive_completed(&mut self.container)?);

        self.count_metrics.update(|count_metrics| {
            count_metrics.num_finished += num_transactions;
            count_metrics.num_retryable += num_retryable;
        });
        self.timing_metrics.update(|timing_metrics| {
            timing_metrics.receive_completed_time_us += receive_completed_time_us;
        });

        Ok(())
    }

    /// Returns whether the packet receiver is still connected.
    fn receive_and_buffer_packets(
        &mut self,
        decision: &BufferedPacketsDecision,
    ) -> Result<ReceivingStats, DisconnectedError> {
        let receiving_stats = self
            .receive_and_buffer
            .receive_and_buffer_packets(&mut self.container, decision)?;

        // Drained from the sigverify→scheduler channel, counted including
        // packets marked `discard` so the gauge reflects true transport
        // depth (sigverify bumps by the same total via `add_in_flight`).
        self.feedback
            .sub_in_flight(receiving_stats.num_total_packets_drained);

        self.count_metrics.update(|count_metrics| {
            let ReceivingStats {
                num_received,
                num_total_packets_drained: _,
                num_dropped_without_parsing: num_dropped_without_buffering,
                num_dropped_on_parsing_and_sanitization,
                num_dropped_on_lock_validation,
                num_dropped_on_compute_budget,
                num_dropped_on_age,
                num_dropped_on_already_processed,
                num_dropped_on_fee_payer,
                num_dropped_on_capacity,
                num_dropped_below_priority_floor,
                num_buffered,
                receive_time_us: _,
                buffer_time_us: _,
            } = &receiving_stats;

            count_metrics.num_received += *num_received;
            count_metrics.num_dropped_on_receive += *num_dropped_without_buffering;
            count_metrics.num_dropped_on_parsing_and_sanitization +=
                *num_dropped_on_parsing_and_sanitization;
            count_metrics.num_dropped_on_validate_locks += *num_dropped_on_lock_validation;
            count_metrics.num_dropped_on_receive_compute_budget += *num_dropped_on_compute_budget;
            count_metrics.num_dropped_on_receive_age += *num_dropped_on_age;
            count_metrics.num_dropped_on_receive_already_processed +=
                *num_dropped_on_already_processed;
            count_metrics.num_dropped_on_receive_fee_payer += *num_dropped_on_fee_payer;
            count_metrics.num_dropped_on_capacity += *num_dropped_on_capacity;
            count_metrics.num_dropped_below_priority_floor += *num_dropped_below_priority_floor;
            count_metrics.num_buffered += *num_buffered;
        });

        self.timing_metrics.update(|timing_metrics| {
            timing_metrics.receive_time_us += receiving_stats.receive_time_us;
            timing_metrics.buffer_time_us += receiving_stats.buffer_time_us;
        });

        Ok(receiving_stats)
    }
}

struct CostPacer {
    block_limit: u64,
    shared_block_cost: SharedBlockCost,
    detection_time: Instant,
    fill_time: Option<Duration>,
}

impl CostPacer {
    fn scheduling_budget(&self, current_time: &Instant) -> u64 {
        let target = if let Some(fill_time) = &self.fill_time {
            let time_since = current_time.saturating_duration_since(self.detection_time);
            if time_since >= *fill_time {
                self.block_limit
            } else {
                // on millisecond granularity, pace the cost linearly.
                let allocation_per_milli = self.block_limit / fill_time.as_millis() as u64;
                let millis_since_detection = time_since.as_millis() as u64;
                allocation_per_milli * millis_since_detection
            }
        } else {
            self.block_limit
        };

        target.saturating_sub(self.shared_block_cost.load())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::banking_stage::{
            TransactionViewReceiveAndBuffer,
            consumer::{RetryableIndex, TARGET_NUM_TRANSACTIONS_PER_BATCH},
            scheduler_messages::{ConsumeWork, FinishedConsumeWork, TransactionBatchId},
            tests::create_slow_genesis_config,
            transaction_scheduler::greedy_scheduler::{GreedyScheduler, GreedySchedulerConfig},
        },
        agave_banking_stage_ingress_types::{BankingPacketBatch, BankingPacketReceiver},
        crossbeam_channel::{Receiver, Sender, unbounded},
        itertools::Itertools,
        solana_compute_budget_interface::ComputeBudgetInstruction,
        solana_fee_calculator::FeeRateGovernor,
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_ledger::genesis_utils::GenesisConfigInfo,
        solana_message::Message,
        solana_perf::packet::{NUM_PACKETS, PacketBatch, to_packet_batches},
        solana_poh::poh_recorder::{LeaderState, SharedLeaderState},
        solana_pubkey::Pubkey,
        solana_runtime::{bank::Bank, bank_forks::BankForks},
        solana_runtime_transaction::transaction_meta::TransactionMeta,
        solana_signer::Signer,
        solana_system_interface::instruction as system_instruction,
        solana_transaction::Transaction,
        std::sync::{Arc, RwLock},
    };

    fn create_channels<T>(num: usize) -> (Vec<Sender<T>>, Vec<Receiver<T>>) {
        (0..num).map(|_| unbounded()).unzip()
    }

    // Helper struct to create tests that hold channels, files, etc.
    // such that our tests can be more easily set up and run.
    struct TestFrame<Tx> {
        bank: Arc<Bank>,
        #[allow(dead_code)]
        bank_forks: Arc<RwLock<BankForks>>,
        mint_keypair: Keypair,
        banking_packet_sender: Sender<Arc<Vec<PacketBatch>>>,
        shared_leader_state: SharedLeaderState,
        consume_work_receivers: Vec<Receiver<ConsumeWork<Tx>>>,
        finished_consume_work_sender: Sender<FinishedConsumeWork<Tx>>,
    }

    fn test_create_transaction_view_receive_and_buffer(
        receiver: BankingPacketReceiver,
        bank_forks: Arc<RwLock<BankForks>>,
    ) -> TransactionViewReceiveAndBuffer {
        TransactionViewReceiveAndBuffer {
            receiver,
            sharable_banks: bank_forks.read().unwrap().sharable_banks(),
            feedback: Arc::new(BankingStageFeedback::default()),
        }
    }

    #[allow(clippy::type_complexity)]
    fn create_test_frame<R: ReceiveAndBuffer>(
        num_threads: usize,
        create_receive_and_buffer: impl FnOnce(BankingPacketReceiver, Arc<RwLock<BankForks>>) -> R,
    ) -> (
        TestFrame<R::Transaction>,
        SchedulerController<R, GreedyScheduler<R::Transaction>>,
    ) {
        let GenesisConfigInfo {
            mut genesis_config,
            mint_keypair,
            ..
        } = create_slow_genesis_config(u64::MAX);
        genesis_config.fee_rate_governor = FeeRateGovernor::new(5000, 0);
        let (bank, bank_forks) = Bank::new_with_bank_forks_for_tests(&genesis_config);

        let shared_leader_state = SharedLeaderState::new(0, None, None);

        let decision_maker = DecisionMaker::new(shared_leader_state.clone());

        let (banking_packet_sender, banking_packet_receiver) = unbounded();
        let receive_and_buffer =
            create_receive_and_buffer(banking_packet_receiver, bank_forks.clone());

        let (consume_work_senders, consume_work_receivers) = create_channels(num_threads);
        let (finished_consume_work_sender, finished_consume_work_receiver) = unbounded();

        let test_frame = TestFrame {
            bank,
            bank_forks: bank_forks.clone(),
            mint_keypair,
            shared_leader_state,
            banking_packet_sender,
            consume_work_receivers,
            finished_consume_work_sender,
        };

        let scheduler = GreedyScheduler::new(
            consume_work_senders,
            finished_consume_work_receiver,
            GreedySchedulerConfig::default(),
        );
        let exit = Arc::new(AtomicBool::new(false));
        let scheduler_controller = SchedulerController::new(
            exit,
            SchedulerConfig::default(),
            decision_maker,
            receive_and_buffer,
            bank_forks.read().unwrap().sharable_banks(),
            scheduler,
            vec![], // no actual workers with metrics to report, this can be empty
            Arc::new(BankingStageFeedback::default()),
        );

        (test_frame, scheduler_controller)
    }

    fn create_and_fund_prioritized_transfer(
        bank: &Bank,
        mint_keypair: &Keypair,
        from_keypair: &Keypair,
        to_pubkey: &Pubkey,
        lamports: u64,
        compute_unit_price: u64,
        recent_blockhash: Hash,
    ) -> Transaction {
        // Fund the sending key, so that the transaction does not get filtered by the fee-payer check.
        {
            let transfer = solana_system_transaction::transfer(
                mint_keypair,
                &from_keypair.pubkey(),
                500_000, // just some amount that will always be enough
                bank.last_blockhash(),
            );
            bank.process_transaction(&transfer).unwrap();
        }

        let transfer = system_instruction::transfer(&from_keypair.pubkey(), to_pubkey, lamports);
        let prioritization = ComputeBudgetInstruction::set_compute_unit_price(compute_unit_price);
        let message = Message::new(&[transfer, prioritization], Some(&from_keypair.pubkey()));
        Transaction::new(&vec![from_keypair], message, recent_blockhash)
    }

    fn to_banking_packet_batch(txs: &[Transaction]) -> BankingPacketBatch {
        BankingPacketBatch::new(to_packet_batches(txs, NUM_PACKETS))
    }

    // Helper function to let test receive and then schedule packets.
    // The order of operations here is convenient for testing, but does not
    // match the order of operations in the actual scheduler.
    // The actual scheduler will process immediately after the decision,
    // in order to keep the decision as recent as possible for processing.
    // In the tests, the decision will not become stale, so it is more convenient
    // to receive first and then schedule.
    fn test_receive_then_schedule<R: ReceiveAndBuffer>(
        scheduler_controller: &mut SchedulerController<R, impl Scheduler<R::Transaction>>,
    ) {
        let decision = scheduler_controller
            .decision_maker
            .make_consume_or_forward_decision();
        assert!(matches!(decision, BufferedPacketsDecision::Consume(_)));
        assert!(scheduler_controller.receive_completed().is_ok());

        // Time is not a reliable way for deterministic testing.
        // Loop here until no more packets are received, this avoids parallel
        // tests from inconsistently timing out and not receiving
        // from the channel.
        while scheduler_controller
            .receive_and_buffer_packets(&decision)
            .map(|n| n.num_received > 0)
            .unwrap_or_default()
        {}
        let now = Instant::now();
        let slot_time = decision
            .bank()
            .map(|bank| Duration::from_nanos_u128(bank.ns_per_slot))
            .unwrap();
        assert!(
            scheduler_controller
                .process_transactions(
                    &decision,
                    Some(&CostPacer {
                        block_limit: u64::MAX,
                        shared_block_cost: SharedBlockCost::new(0),
                        detection_time: now.checked_sub(slot_time).unwrap(),
                        fill_time: Some(slot_time.saturating_sub(Duration::from_millis(
                            DEFAULT_SCHEDULER_PACING_NON_FILL_TIME_MILLIS
                        ))),
                    }),
                    &now
                )
                .is_ok()
        );
    }

    #[test]
    #[should_panic(expected = "batch id 0 is not being tracked")]
    fn test_unexpected_batch_id() {
        let (test_frame, mut scheduler_controller) =
            create_test_frame(1, test_create_transaction_view_receive_and_buffer);
        let TestFrame {
            finished_consume_work_sender,
            ..
        } = &test_frame;

        finished_consume_work_sender
            .send(FinishedConsumeWork {
                work: ConsumeWork {
                    batch_id: TransactionBatchId::new(0),
                    ids: vec![],
                    transactions: vec![],
                    max_ages: vec![],
                },
                retryable_indexes: vec![],
            })
            .unwrap();

        scheduler_controller.run().unwrap();
    }

    #[test]
    fn test_schedule_consume_single_threaded_no_conflicts() {
        let (mut test_frame, mut scheduler_controller) =
            create_test_frame(1, test_create_transaction_view_receive_and_buffer);
        let TestFrame {
            bank,
            mint_keypair,
            shared_leader_state,
            banking_packet_sender,
            consume_work_receivers,
            ..
        } = &mut test_frame;

        shared_leader_state.store(Arc::new(LeaderState::new(
            Some(bank.clone()),
            bank.tick_height(),
            None,
            None,
        )));

        // Send packet batch to the scheduler - should do nothing until we become the leader.
        let tx1 = create_and_fund_prioritized_transfer(
            bank,
            mint_keypair,
            &Keypair::new(),
            &Pubkey::new_unique(),
            1,
            1000,
            bank.last_blockhash(),
        );
        let tx2 = create_and_fund_prioritized_transfer(
            bank,
            mint_keypair,
            &Keypair::new(),
            &Pubkey::new_unique(),
            1,
            2000,
            bank.last_blockhash(),
        );
        let tx1_hash = tx1.message().hash();
        let tx2_hash = tx2.message().hash();

        let txs = vec![tx1, tx2];
        banking_packet_sender
            .send(to_banking_packet_batch(&txs))
            .unwrap();

        test_receive_then_schedule(&mut scheduler_controller);
        let consume_work = consume_work_receivers[0].try_recv().unwrap();
        assert_eq!(consume_work.ids.len(), 2);
        assert_eq!(consume_work.transactions.len(), 2);
        let message_hashes = consume_work
            .transactions
            .iter()
            .map(|tx| tx.message_hash())
            .collect_vec();
        assert_eq!(message_hashes, vec![&tx2_hash, &tx1_hash]);
    }

    #[test]
    fn test_schedule_consume_single_threaded_conflict() {
        let (mut test_frame, mut scheduler_controller) =
            create_test_frame(1, test_create_transaction_view_receive_and_buffer);
        let TestFrame {
            bank,
            mint_keypair,
            shared_leader_state,
            banking_packet_sender,
            consume_work_receivers,
            ..
        } = &mut test_frame;

        shared_leader_state.store(Arc::new(LeaderState::new(
            Some(bank.clone()),
            bank.tick_height(),
            None,
            None,
        )));

        let pk = Pubkey::new_unique();
        let tx1 = create_and_fund_prioritized_transfer(
            bank,
            mint_keypair,
            &Keypair::new(),
            &pk,
            1,
            1000,
            bank.last_blockhash(),
        );
        let tx2 = create_and_fund_prioritized_transfer(
            bank,
            mint_keypair,
            &Keypair::new(),
            &pk,
            1,
            2000,
            bank.last_blockhash(),
        );
        let tx1_hash = tx1.message().hash();
        let tx2_hash = tx2.message().hash();

        let txs = vec![tx1, tx2];
        banking_packet_sender
            .send(to_banking_packet_batch(&txs))
            .unwrap();

        // We expect 2 batches to be scheduled
        test_receive_then_schedule(&mut scheduler_controller);
        let consume_work = consume_work_receivers[0].try_recv().unwrap();
        assert!(consume_work_receivers[0].try_recv().is_err());

        let num_txs_per_batch = consume_work.ids.len();
        let message_hashes = consume_work
            .transactions
            .iter()
            .map(|tx| tx.message_hash())
            .collect_vec();
        assert_eq!(num_txs_per_batch, 2);
        assert_eq!(message_hashes, vec![&tx2_hash, &tx1_hash]);
    }

    #[test]
    fn test_schedule_consume_single_threaded_multi_batch() {
        let (mut test_frame, mut scheduler_controller) =
            create_test_frame(1, test_create_transaction_view_receive_and_buffer);
        let TestFrame {
            bank,
            mint_keypair,
            shared_leader_state,
            banking_packet_sender,
            consume_work_receivers,
            ..
        } = &mut test_frame;

        shared_leader_state.store(Arc::new(LeaderState::new(
            Some(bank.clone()),
            bank.tick_height(),
            None,
            None,
        )));

        // Send multiple batches - all get scheduled
        let txs1 = (0..2 * TARGET_NUM_TRANSACTIONS_PER_BATCH)
            .map(|i| {
                create_and_fund_prioritized_transfer(
                    bank,
                    mint_keypair,
                    &Keypair::new(),
                    &Pubkey::new_unique(),
                    i as u64,
                    1,
                    bank.last_blockhash(),
                )
            })
            .collect_vec();
        let txs2 = (0..2 * TARGET_NUM_TRANSACTIONS_PER_BATCH)
            .map(|i| {
                create_and_fund_prioritized_transfer(
                    bank,
                    mint_keypair,
                    &Keypair::new(),
                    &Pubkey::new_unique(),
                    i as u64,
                    2,
                    bank.last_blockhash(),
                )
            })
            .collect_vec();

        banking_packet_sender
            .send(to_banking_packet_batch(&txs1))
            .unwrap();
        banking_packet_sender
            .send(to_banking_packet_batch(&txs2))
            .unwrap();

        // We expect 4 batches to be scheduled
        test_receive_then_schedule(&mut scheduler_controller);
        let consume_works = (0..4)
            .map(|_| consume_work_receivers[0].try_recv().unwrap())
            .collect_vec();

        assert_eq!(
            consume_works.iter().map(|cw| cw.ids.len()).collect_vec(),
            vec![TARGET_NUM_TRANSACTIONS_PER_BATCH; 4]
        );
    }

    #[test]
    fn test_schedule_consume_simple_thread_selection() {
        let (mut test_frame, mut scheduler_controller) =
            create_test_frame(2, test_create_transaction_view_receive_and_buffer);
        let TestFrame {
            bank,
            mint_keypair,
            shared_leader_state,
            banking_packet_sender,
            consume_work_receivers,
            ..
        } = &mut test_frame;

        shared_leader_state.store(Arc::new(LeaderState::new(
            Some(bank.clone()),
            bank.tick_height(),
            None,
            None,
        )));

        // Send 4 transactions w/o conflicts. 2 should be scheduled on each thread
        let txs = (0..4)
            .map(|i| {
                create_and_fund_prioritized_transfer(
                    bank,
                    mint_keypair,
                    &Keypair::new(),
                    &Pubkey::new_unique(),
                    1,
                    i * 10,
                    bank.last_blockhash(),
                )
            })
            .collect_vec();
        banking_packet_sender
            .send(to_banking_packet_batch(&txs))
            .unwrap();

        // Priority Expectation:
        // Thread 0: [3, 1]
        // Thread 1: [2, 0]
        let t0_expected = [3, 1]
            .into_iter()
            .map(|i| txs[i].message().hash())
            .collect_vec();
        let t1_expected = [2, 0]
            .into_iter()
            .map(|i| txs[i].message().hash())
            .collect_vec();

        test_receive_then_schedule(&mut scheduler_controller);
        let t0_actual = consume_work_receivers[0]
            .try_recv()
            .unwrap()
            .transactions
            .iter()
            .map(|tx| *tx.message_hash())
            .collect_vec();
        let t1_actual = consume_work_receivers[1]
            .try_recv()
            .unwrap()
            .transactions
            .iter()
            .map(|tx| *tx.message_hash())
            .collect_vec();

        assert_eq!(t0_actual, t0_expected);
        assert_eq!(t1_actual, t1_expected);
    }

    #[test]
    fn test_schedule_consume_retryable() {
        let (mut test_frame, mut scheduler_controller) =
            create_test_frame(1, test_create_transaction_view_receive_and_buffer);
        let TestFrame {
            bank,
            mint_keypair,
            shared_leader_state,
            banking_packet_sender,
            consume_work_receivers,
            finished_consume_work_sender,
            ..
        } = &mut test_frame;

        shared_leader_state.store(Arc::new(LeaderState::new(
            Some(bank.clone()),
            bank.tick_height(),
            None,
            None,
        )));

        // Send packet batch to the scheduler - should do nothing until we become the leader.
        let tx1 = create_and_fund_prioritized_transfer(
            bank,
            mint_keypair,
            &Keypair::new(),
            &Pubkey::new_unique(),
            1,
            1000,
            bank.last_blockhash(),
        );
        let tx2 = create_and_fund_prioritized_transfer(
            bank,
            mint_keypair,
            &Keypair::new(),
            &Pubkey::new_unique(),
            1,
            2000,
            bank.last_blockhash(),
        );
        let tx1_hash = tx1.message().hash();
        let tx2_hash = tx2.message().hash();

        let txs = vec![tx1, tx2];
        banking_packet_sender
            .send(to_banking_packet_batch(&txs))
            .unwrap();

        test_receive_then_schedule(&mut scheduler_controller);
        let consume_work = consume_work_receivers[0].try_recv().unwrap();
        assert_eq!(consume_work.ids.len(), 2);
        assert_eq!(consume_work.transactions.len(), 2);
        let message_hashes = consume_work
            .transactions
            .iter()
            .map(|tx| tx.message_hash())
            .collect_vec();
        assert_eq!(message_hashes, vec![&tx2_hash, &tx1_hash]);

        // Complete the batch - marking the second transaction as retryable
        finished_consume_work_sender
            .send(FinishedConsumeWork {
                work: consume_work,
                retryable_indexes: vec![RetryableIndex::new(1, true)],
            })
            .unwrap();

        // Transaction should be rescheduled
        test_receive_then_schedule(&mut scheduler_controller);
        let consume_work = consume_work_receivers[0].try_recv().unwrap();
        assert_eq!(consume_work.ids.len(), 1);
        assert_eq!(consume_work.transactions.len(), 1);
        let message_hashes = consume_work
            .transactions
            .iter()
            .map(|tx| tx.message_hash())
            .collect_vec();
        assert_eq!(message_hashes, vec![&tx1_hash]);
    }
}
