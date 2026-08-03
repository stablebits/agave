//! The `sigverify` module provides digital signature verification functions.
//! By default, signatures are verified in parallel using all available CPU
//! cores.

use {
    crate::{
        banking_trace::BankingPacketSender, sigverify_stage::SigVerifyServiceError,
        transaction_priority::calculate_priority_from_bytes,
    },
    agave_banking_stage_ingress_types::{BankingPacketBatch, SchedulerPriorityFloor},
    crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TryRecvError, TrySendError, bounded},
    solana_measure::measure_us,
    solana_perf::{
        deduper::{self, Deduper},
        packet::{BytesPacket, PacketBatch},
        sigverify::{self},
    },
    solana_runtime::{bank::Bank, bank_forks::SharableBanks},
    solana_transaction::Transaction,
    std::{
        num::NonZeroUsize,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread::JoinHandle,
        time::Duration,
    },
};

pub(crate) struct GossipVerifyTask {
    batch: PacketBatch,
    transaction: Transaction,
}

pub(crate) struct GossipVerifiedVoteBatch {
    pub(crate) transaction: Transaction,
    pub(crate) packet_batch: PacketBatch,
}

#[derive(Clone)]
pub(crate) struct SigVerifyWorkerStats {
    pub(crate) total_batches: Arc<AtomicUsize>,
    pub(crate) total_packets: Arc<AtomicUsize>,
    pub(crate) total_dedup: Arc<AtomicUsize>,
    pub(crate) total_dedup_time_us: Arc<AtomicUsize>,
    pub(crate) total_valid_packets: Arc<AtomicUsize>,
    pub(crate) total_verify_time_us: Arc<AtomicUsize>,
    /// Max occupancy of the banking_stage channel sampled immediately before each send.
    pub(crate) max_pre_send_len: Arc<AtomicUsize>,
    /// Count of sends where the EvictingSender had to drop a batch to make room.
    pub(crate) eviction_drops: Arc<AtomicUsize>,
    pub(crate) total_dropped_below_priority_floor: Arc<AtomicUsize>,
    pub(crate) total_priority_floor_time_us: Arc<AtomicUsize>,
}

#[derive(Clone)]
pub(crate) struct SigVerifyWorkerState {
    banking_stage_sender: BankingPacketSender,
    deduper: Arc<Deduper<2, [u8]>>,
    stats: SigVerifyWorkerStats,
    /// Scheduler-published priority floor: when saturated, the scheduler publishes
    /// the queue-min transaction's priority and workers drop at-or-below-floor
    /// arrivals here, ahead of signature verification. `None` disables the
    /// check (e.g. for the vote worker, which is governed by a separate
    /// priority policy in banking stage).
    priority_floor: Option<Arc<SchedulerPriorityFloor>>,
}

impl SigVerifyWorkerState {
    pub(crate) fn new(
        banking_stage_sender: BankingPacketSender,
        deduper: Arc<Deduper<2, [u8]>>,
        stats: SigVerifyWorkerStats,
        priority_floor: Option<Arc<SchedulerPriorityFloor>>,
    ) -> Self {
        Self {
            banking_stage_sender,
            deduper,
            stats,
            priority_floor,
        }
    }
}

pub(crate) struct GossipSigVerifier {
    worker_sender: Sender<GossipVerifyTask>,
}

impl GossipSigVerifier {
    #[cfg(test)]
    pub(crate) fn new_for_tests(worker_sender: Sender<GossipVerifyTask>) -> Self {
        Self { worker_sender }
    }

    pub(crate) fn send_votes_to_worker_pool(
        &self,
        votes: Vec<Transaction>,
        packet_batches: Vec<PacketBatch>,
    ) -> Result<usize, SigVerifyServiceError> {
        assert_eq!(votes.len(), packet_batches.len());

        let num_votes = votes.len();
        let mut num_sent = 0;
        for (transaction, batch) in votes.into_iter().zip(packet_batches) {
            match self
                .worker_sender
                .try_send(GossipVerifyTask { batch, transaction })
            {
                Ok(()) => {
                    num_sent += 1;
                }
                Err(TrySendError::Full(_)) => {
                    warn!(
                        "gossip sigverify worker queue is full, dropping {} votes.",
                        num_votes.saturating_sub(num_sent)
                    );
                    break;
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(SigVerifyServiceError::WorkerQueueClosed);
                }
            }
        }

        Ok(num_sent)
    }
}

/// Gossip votes use a bounded queue into the worker pool.
const SIGVERIFY_GOSSIP_VOTE_WORK_CHANNEL_SIZE: usize = 50_000;

/// Max packets the drainer coalesces into a single work batch. Only packets
/// already sitting in the ingress channel are merged -- the drainer never
/// waits for a batch to fill, so an idle channel adds no latency.
const NON_VOTE_COALESCE_LIMIT: usize = 64;
/// Coalesced work batches queued between the drainer and the workers.
const NON_VOTE_WORK_CHANNEL_SIZE: usize = 4_096;

pub(crate) struct SigVerifyWorkerSenders {
    pub(crate) gossip_verified_vote_sender: Sender<GossipVerifiedVoteBatch>,
    pub(crate) forward_stage_sender: Sender<(BankingPacketBatch, bool)>,
}

#[derive(Clone)]
struct WorkerPoolChannels {
    non_vote_receiver: Receiver<PacketBatch>,
    tpu_vote_receiver: Receiver<PacketBatch>,
    gossip_receiver: Receiver<GossipVerifyTask>,
    gossip_verified_vote_sender: Sender<GossipVerifiedVoteBatch>,
    forward_stage_sender: Sender<(BankingPacketBatch, bool)>,
    sharable_banks: SharableBanks,
    non_vote_state: SigVerifyWorkerState,
    tpu_vote_state: SigVerifyWorkerState,
}

pub(crate) struct SigVerifyWorkerPool {
    exit: Arc<AtomicBool>,
    gossip_sender: Sender<GossipVerifyTask>,
    worker_hdls: Vec<JoinHandle<()>>,
}

impl Drop for SigVerifyWorkerPool {
    fn drop(&mut self) {
        self.exit.store(true, Ordering::Relaxed);
        self.worker_hdls.drain(..).for_each(|hdl| {
            if let Err(err) = hdl.join() {
                error!("sigverify worker encountered unexpected error: {err:?}");
            }
        });
    }
}

impl SigVerifyWorkerPool {
    pub(crate) fn new(
        num_workers: NonZeroUsize,
        non_vote_receiver: Receiver<PacketBatch>,
        tpu_vote_receiver: Receiver<PacketBatch>,
        senders: SigVerifyWorkerSenders,
        forward_non_votes: bool,
        sharable_banks: SharableBanks,
        non_vote_state: SigVerifyWorkerState,
        tpu_vote_state: SigVerifyWorkerState,
    ) -> Self {
        let (gossip_sender, gossip_receiver) = bounded(SIGVERIFY_GOSSIP_VOTE_WORK_CHANNEL_SIZE);
        let (non_vote_work_sender, non_vote_work_receiver) = bounded(NON_VOTE_WORK_CHANNEL_SIZE);
        let exit = Arc::new(AtomicBool::new(false));
        // A single drainer consumes the ingress channel, coalescing queued
        // packets into larger batches for the workers. Keeping exactly one
        // blocking receiver on the ingress channel lets producers take the
        // wakeup fast path (no waker lock) whenever the drainer is awake.
        let drainer_hdl = {
            let exit = exit.clone();
            let non_vote_state = non_vote_state.clone();
            std::thread::Builder::new()
                .name("solSigDrain".to_string())
                .spawn(move || {
                    Self::non_vote_drainer(
                        exit,
                        non_vote_receiver,
                        non_vote_work_sender,
                        non_vote_state,
                    )
                })
                .expect("failed to spawn sigverify drainer thread")
        };
        let channels = WorkerPoolChannels {
            non_vote_receiver: non_vote_work_receiver,
            tpu_vote_receiver,
            gossip_receiver,
            gossip_verified_vote_sender: senders.gossip_verified_vote_sender,
            forward_stage_sender: senders.forward_stage_sender,
            sharable_banks,
            non_vote_state,
            tpu_vote_state,
        };
        let mut worker_hdls: Vec<JoinHandle<()>> = (0..num_workers.get())
            .map(|idx| {
                let exit = exit.clone();
                let channels = channels.clone();

                std::thread::Builder::new()
                    .name(format!("solSigVerify{idx:02}"))
                    .spawn(move || Self::worker(exit, channels, forward_non_votes))
                    .expect("failed to spawn sigverify worker thread")
            })
            .collect();
        worker_hdls.push(drainer_hdl);
        Self {
            exit,
            gossip_sender,
            worker_hdls,
        }
    }

    pub(crate) fn gossip_verifier(&self) -> GossipSigVerifier {
        GossipSigVerifier {
            worker_sender: self.gossip_sender.clone(),
        }
    }

    /// Drains the non-vote ingress channel, merging queued packets into
    /// larger batches for the worker pool. Coalescing is opportunistic: only
    /// packets already in the channel are merged, so batch size adapts to
    /// load (1 when idle, up to the limit under bursts) without adding
    /// latency.
    ///
    /// The drainer also dedups (a cheap bloom-filter lookup), so duplicate
    /// floods are absorbed here without ever waking a worker. The costlier
    /// per-packet work (priority-floor parsing, signature verification) stays
    /// in the workers to keep this single thread off the throughput-critical
    /// path.
    fn non_vote_drainer(
        exit: Arc<AtomicBool>,
        non_vote_receiver: Receiver<PacketBatch>,
        work_sender: Sender<PacketBatch>,
        state: SigVerifyWorkerState,
    ) {
        const RECV_TIMEOUT: Duration = Duration::from_millis(10);
        while !exit.load(Ordering::Relaxed) {
            let first = match non_vote_receiver.recv_timeout(RECV_TIMEOUT) {
                Ok(batch) => batch,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return,
            };

            let mut merged: Vec<BytesPacket> = Vec::new();
            let mut out: Vec<PacketBatch> = Vec::new();
            let mut num_packets = first.len();
            Self::absorb_batch(first, &mut merged, &mut out);
            while num_packets < NON_VOTE_COALESCE_LIMIT {
                match non_vote_receiver.try_recv() {
                    Ok(batch) => {
                        num_packets = num_packets.saturating_add(batch.len());
                        Self::absorb_batch(batch, &mut merged, &mut out);
                    }
                    // Forward what was drained; a disconnect is picked up by
                    // the recv_timeout in the next iteration.
                    Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
                }
            }
            if !merged.is_empty() {
                out.push(merged.into());
            }

            for mut batch in out {
                if !Self::dedup_batch(&mut batch, &state) {
                    continue;
                }
                if work_sender.send(batch).is_err() {
                    return;
                }
            }
        }
    }

    fn absorb_batch(
        batch: PacketBatch,
        merged: &mut Vec<BytesPacket>,
        out: &mut Vec<PacketBatch>,
    ) {
        match batch {
            PacketBatch::Single(packet) => merged.push(packet),
            PacketBatch::Bytes(mut batch) => merged.append(&mut batch),
            // Pinned batches cannot be merged without copying; flush merged
            // packets first to preserve arrival order.
            batch @ PacketBatch::Pinned(_) => {
                if !merged.is_empty() {
                    out.push(std::mem::take(merged).into());
                }
                out.push(batch);
            }
        }
    }

    fn worker(exit: Arc<AtomicBool>, channels: WorkerPoolChannels, forward_non_votes: bool) {
        while !exit.load(Ordering::Relaxed) {
            if !Self::worker_iteration(&channels, forward_non_votes) {
                break;
            }
        }
    }

    /// Returns false if some channel connection is disconnected.
    fn worker_iteration(channels: &WorkerPoolChannels, forward_non_votes: bool) -> bool {
        crossbeam_channel::select! {
            recv(&channels.non_vote_receiver) -> maybe_work => {
                match maybe_work {
                    Ok(batch) => Self::run_transaction_task(
                        batch,
                        false,
                        &channels.forward_stage_sender,
                        forward_non_votes,
                        false,
                        true, // deduped: the drainer already deduped this batch
                        &channels.sharable_banks,
                        &channels.non_vote_state,
                    ),
                    Err(_) => false,
                }
            }
            recv(&channels.tpu_vote_receiver) -> maybe_work => {
                match maybe_work {
                    Ok(batch) => Self::run_transaction_task(
                        batch,
                        true,
                        &channels.forward_stage_sender,
                        true,
                        true,
                        false, // deduped: votes are deduped here
                        &channels.sharable_banks,
                        &channels.tpu_vote_state,
                    ),
                    Err(_) => false,
                }
            }
            recv(&channels.gossip_receiver) -> maybe_work => {
                match maybe_work {
                    Ok(work) => Self::run_gossip_task(
                        work,
                        &channels.gossip_verified_vote_sender,
                    ),
                    Err(_) => false,
                }
            }
            default(Duration::from_millis(10)) => { true }
        }
    }

    /// Accounts for received packets and dedups them. Returns false when the
    /// entire batch was discarded and nothing is left to verify or forward.
    fn dedup_batch(batch: &mut PacketBatch, state: &SigVerifyWorkerState) -> bool {
        let batch_len = batch.len();
        state.stats.total_batches.fetch_add(1, Ordering::Relaxed);
        state
            .stats
            .total_packets
            .fetch_add(batch_len, Ordering::Relaxed);

        let (discard_or_dedup_fail, dedup_time_us) =
            measure_us!(deduper::dedup_packets_and_count_discards(
                &state.deduper,
                std::slice::from_mut(batch)
            ));
        state
            .stats
            .total_dedup
            .fetch_add(discard_or_dedup_fail as usize, Ordering::Relaxed);
        state
            .stats
            .total_dedup_time_us
            .fetch_add(dedup_time_us as usize, Ordering::Relaxed);

        discard_or_dedup_fail as usize != batch_len
    }

    fn run_transaction_task(
        mut batch: PacketBatch,
        reject_non_vote: bool,
        forward_stage_sender: &Sender<(BankingPacketBatch, bool)>,
        should_forward: bool,
        is_tpu_vote: bool,
        deduped: bool,
        sharable_banks: &SharableBanks,
        state: &SigVerifyWorkerState,
    ) -> bool {
        // Non-vote batches are already deduped by the drainer; vote batches
        // are deduped here.
        if !deduped && !Self::dedup_batch(&mut batch, state) {
            return true;
        }

        let working_bank = sharable_banks.working();

        // The priority floor stays in the workers rather than the drainer: it
        // parses every packet, and spreading that cost across the pool keeps
        // the single drainer off the throughput-critical path. Coalesced
        // batches keep the work done per wakeup meaningful.
        if let Some(floor) = state.priority_floor.as_ref() {
            let floor = floor.get();
            if floor > 0 {
                let ((dropped, all_below), priority_floor_time_us) = measure_us!(
                    apply_priority_floor_to_batch(&mut batch, floor, &working_bank)
                );
                state
                    .stats
                    .total_priority_floor_time_us
                    .fetch_add(priority_floor_time_us as usize, Ordering::Relaxed);
                if dropped > 0 {
                    state
                        .stats
                        .total_dropped_below_priority_floor
                        .fetch_add(dropped, Ordering::Relaxed);
                }
                if all_below {
                    // Entire batch went below-floor: nothing left to verify or
                    // forward.
                    return true;
                }
            }
        }

        let enable_tx_v1 = working_bank.feature_set.snapshot().enable_tx_v1;
        let (_, verify_time_us) = measure_us!(sigverify::ed25519_verify_serial(
            &mut batch,
            reject_non_vote,
            enable_tx_v1,
        ));
        let num_valid_packets = sigverify::count_valid_packets(std::iter::once(&batch));
        state
            .stats
            .total_valid_packets
            .fetch_add(num_valid_packets, Ordering::Relaxed);
        state
            .stats
            .total_verify_time_us
            .fetch_add(verify_time_us as usize, Ordering::Relaxed);

        if num_valid_packets == 0 {
            return true;
        }

        let banking_packet_batch = BankingPacketBatch::new(batch);
        // Sample backlog before the push: measures consumer health without
        // including this batch's own contribution.
        state
            .stats
            .max_pre_send_len
            .fetch_max(state.banking_stage_sender.len(), Ordering::Relaxed);
        match state
            .banking_stage_sender
            .send(banking_packet_batch.clone())
        {
            Ok(0) => {} // avoid poking atomics if nothing was evicted (typical case)
            Ok(evicted) => {
                // record evicted amount into metrics
                state
                    .stats
                    .eviction_drops
                    .fetch_add(evicted, Ordering::Relaxed);
            }
            Err(err) => {
                error!("sigverify send to banking failed: {err:?}");
                return false;
            }
        }
        if should_forward {
            Self::try_forward(forward_stage_sender, banking_packet_batch, is_tpu_vote);
        }

        true
    }

    fn run_gossip_task(
        mut work: GossipVerifyTask,
        verified_vote_sender: &Sender<GossipVerifiedVoteBatch>,
    ) -> bool {
        // Gossip votes are legacy Transaction values, not tx-v1 packets.
        sigverify::ed25519_verify_serial(&mut work.batch, true, false);

        if let Err(err) = verified_vote_sender.send(GossipVerifiedVoteBatch {
            transaction: work.transaction,
            packet_batch: work.batch,
        }) {
            debug!("gossip sigverify response send failed: {err:?}");
        }

        true
    }

    fn try_forward(
        forward_stage_sender: &Sender<(BankingPacketBatch, bool)>,
        banking_packet_batch: BankingPacketBatch,
        is_tpu_vote: bool,
    ) {
        if let Err(TrySendError::Full(_)) =
            forward_stage_sender.try_send((banking_packet_batch, is_tpu_vote))
        {
            warn!("forwarding stage channel is full, dropping packets.");
        }
    }
}

/// Apply the scheduler-published priority floor to a single batch in place.
///
/// Below-floor packets are marked `discard`. Returns `(dropped, all_below)`,
/// where `dropped` is the number of packets newly marked and `all_below` is
/// true iff no useful packets remain in the batch (so the caller can skip
/// downstream work for this batch entirely).
fn apply_priority_floor_to_batch(
    batch: &mut PacketBatch,
    floor: u64,
    bank: &Bank,
) -> (usize, bool) {
    let mut dropped: usize = 0;
    let mut any_kept = false;
    for mut packet in batch.iter_mut() {
        if packet.meta().discard() {
            continue;
        }
        let Some(data) = packet.data(..) else {
            // Zero-length or otherwise unreadable: leave to downstream
            // stages to reject.
            any_kept = true;
            continue;
        };
        // Unparseable packets are kept and left for downstream rejection.
        match calculate_priority_from_bytes(bank, data) {
            Some(priority) if priority <= floor => {
                packet.meta_mut().set_discard(true);
                dropped = dropped.saturating_add(1);
            }
            _ => any_kept = true,
        }
    }
    (dropped, !any_kept)
}
