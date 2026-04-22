//! The `sigverify_stage` implements the signature verification stage of the TPU. It
//! receives a list of lists of packets and outputs the same list, but tags each
//! top-level list with a list of booleans, telling the next stage whether the
//! signature in that packet is valid. It assumes each packet contains one
//! transaction. All processing is done on the CPU by default.

use {
    crate::sigverify,
    agave_feature_set::FeatureSet,
    agave_transaction_view::transaction_view::SanitizedTransactionView,
    core::time::Duration,
    crossbeam_channel::{Receiver, RecvTimeoutError},
    itertools::Itertools,
    rayon::ThreadPool,
    solana_measure::measure::Measure,
    solana_perf::{
        deduper::{self, Deduper},
        packet::{PacketBatch, PacketFlags},
        sigverify::count_valid_packets,
    },
    solana_runtime_transaction::{
        runtime_transaction::RuntimeTransaction, transaction_meta::TransactionMeta,
    },
    solana_streamer::{
        quic::SchedulerSaturationFeedback,
        streamer::{self, StreamerError},
    },
    solana_time_utils as timing,
    solana_transaction::sanitized::MessageHash,
    std::{
        sync::{
            Arc, LazyLock,
            atomic::{AtomicUsize, Ordering},
        },
        thread::{self, Builder, JoinHandle},
        time::Instant,
    },
    thiserror::Error,
};

#[derive(Error, Debug)]
pub enum SigVerifyServiceError {
    #[error("streamer error")]
    Streamer(#[from] StreamerError),
}

type Result<T> = std::result::Result<T, SigVerifyServiceError>;

pub struct SigVerifyStage {
    thread_hdl: JoinHandle<()>,
}

pub trait SigVerifier {
    fn verify_and_send_packets(
        &mut self,
        batches: Vec<PacketBatch>,
        valid_packets: usize,
        in_flight_count: Arc<AtomicUsize>,
        total_valid_packets: Arc<AtomicUsize>,
        total_verify_time_us: Arc<AtomicUsize>,
    ) -> Result<()>;

    /// Return maximum number of packets that are allowed to be in the verification pool.
    fn capacity(&self) -> usize;
}

#[derive(Clone)]
pub struct DisabledSigVerifier {
    pub thread_pool: Arc<ThreadPool>,
}

#[derive(Default)]
struct SigVerifierStats {
    recv_batches_us_hist: histogram::Histogram, // time to call recv_batch
    dedup_packets_pp_us_hist: histogram::Histogram, // per-packet time to call verify_batch
    batches_hist: histogram::Histogram,         // number of packet batches per verify call
    packets_hist: histogram::Histogram,         // number of packets per verify call
    num_deduper_saturations: usize,
    total_batches: usize,
    total_packets: usize,
    total_dedup: usize,
    total_valid_packets: Arc<AtomicUsize>,
    total_dedup_time_us: usize,
    total_verify_time_us: Arc<AtomicUsize>,
    total_dropped_on_capacity: usize,
    total_dropped_below_priority_floor: usize,
}

impl SigVerifierStats {
    fn maybe_report_and_reset(&mut self, name: &'static str) {
        // No need to report a datapoint if no batches/packets received
        if self.total_batches == 0 {
            return;
        }

        datapoint_info!(
            name,
            (
                "recv_batches_us_90pct",
                self.recv_batches_us_hist.percentile(90.0).unwrap_or(0),
                i64
            ),
            (
                "recv_batches_us_min",
                self.recv_batches_us_hist.minimum().unwrap_or(0),
                i64
            ),
            (
                "recv_batches_us_max",
                self.recv_batches_us_hist.maximum().unwrap_or(0),
                i64
            ),
            (
                "recv_batches_us_mean",
                self.recv_batches_us_hist.mean().unwrap_or(0),
                i64
            ),
            (
                "dedup_packets_pp_us_90pct",
                self.dedup_packets_pp_us_hist.percentile(90.0).unwrap_or(0),
                i64
            ),
            (
                "dedup_packets_pp_us_min",
                self.dedup_packets_pp_us_hist.minimum().unwrap_or(0),
                i64
            ),
            (
                "dedup_packets_pp_us_max",
                self.dedup_packets_pp_us_hist.maximum().unwrap_or(0),
                i64
            ),
            (
                "dedup_packets_pp_us_mean",
                self.dedup_packets_pp_us_hist.mean().unwrap_or(0),
                i64
            ),
            (
                "batches_90pct",
                self.batches_hist.percentile(90.0).unwrap_or(0),
                i64
            ),
            ("batches_min", self.batches_hist.minimum().unwrap_or(0), i64),
            ("batches_max", self.batches_hist.maximum().unwrap_or(0), i64),
            ("batches_mean", self.batches_hist.mean().unwrap_or(0), i64),
            (
                "packets_90pct",
                self.packets_hist.percentile(90.0).unwrap_or(0),
                i64
            ),
            ("packets_min", self.packets_hist.minimum().unwrap_or(0), i64),
            ("packets_max", self.packets_hist.maximum().unwrap_or(0), i64),
            ("packets_mean", self.packets_hist.mean().unwrap_or(0), i64),
            (
                "num_deduper_saturations",
                core::mem::take(&mut self.num_deduper_saturations),
                i64
            ),
            (
                "total_batches",
                core::mem::take(&mut self.total_batches),
                i64
            ),
            (
                "total_packets",
                core::mem::take(&mut self.total_packets),
                i64
            ),
            ("total_dedup", core::mem::take(&mut self.total_dedup), i64),
            (
                "total_dedup_time_us",
                core::mem::take(&mut self.total_dedup_time_us),
                i64
            ),
            (
                "total_dropped_on_capacity",
                core::mem::take(&mut self.total_dropped_on_capacity),
                i64
            ),
            (
                "total_dropped_below_priority_floor",
                core::mem::take(&mut self.total_dropped_below_priority_floor),
                i64
            ),
            (
                "total_valid_packets",
                self.total_valid_packets.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "total_verify_time_us",
                self.total_verify_time_us.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
        );

        self.recv_batches_us_hist = histogram::Histogram::new();
        self.dedup_packets_pp_us_hist = histogram::Histogram::new();
        self.batches_hist = histogram::Histogram::new();
        self.packets_hist = histogram::Histogram::new();
    }
}

impl SigVerifier for DisabledSigVerifier {
    fn verify_and_send_packets(
        &mut self,
        mut batches: Vec<PacketBatch>,
        _valid_packets: usize,
        _in_flight_count: Arc<AtomicUsize>,
        total_valid_packets: Arc<AtomicUsize>,
        total_verify_time_us: Arc<AtomicUsize>,
    ) -> Result<()> {
        let mut verify_time = Measure::start("sigverify_batch_time");
        sigverify::ed25519_verify_disabled(&self.thread_pool, &mut batches);
        verify_time.stop();
        total_valid_packets.fetch_add(count_valid_packets(&batches), Ordering::Relaxed);
        total_verify_time_us.fetch_add(verify_time.as_us() as usize, Ordering::Relaxed);
        Ok(())
    }

    fn capacity(&self) -> usize {
        usize::MAX
    }
}

// The priority pre-check parses ComputeBudget instructions using a static,
// all-enabled feature set. This is intentional:
// - For tx-v1 transactions the priority fee is read directly from the config
//   frame; the feature set is not consulted.
// - For legacy/v0 an all-enabled feature set parses every known ComputeBudget
//   instruction, which is at most as permissive as the running bank. A marginal
//   over/under-estimate only affects whether a packet is dropped at saturation;
//   it never affects correctness of accepted transactions.
static APPROX_PRIORITY_FEATURE_SET: LazyLock<FeatureSet> = LazyLock::new(FeatureSet::all_enabled);

/// Approximate the banking-stage priority for a packet from its raw bytes.
///
/// Banking stage computes `priority = reward * 1e6 / (cost + 1)`. At leading
/// order, reward is dominated by the prioritization fee and cost by the
/// requested compute-unit limit, so the ratio collapses to
/// `compute_unit_price_in_microlamports`.
///
/// Returns `None` if the packet cannot be parsed; callers should leave such
/// packets alone (they will be rejected downstream if genuinely invalid).
pub(crate) fn approximate_priority(data: &[u8]) -> Option<u64> {
    let view = SanitizedTransactionView::try_new_sanitized(data, true).ok()?;
    let runtime_tx =
        RuntimeTransaction::<SanitizedTransactionView<_>>::try_new(view, MessageHash::Compute, None)
            .ok()?;
    let config = runtime_tx
        .transaction_configuration(&APPROX_PRIORITY_FEATURE_SET)
        .ok()?;
    Some(config.compute_unit_price_in_microlamports())
}

/// True if this packet should be dropped by the priority-floor filter: it is
/// not already discarded, not a simple-vote packet, parseable, and its
/// approximate priority is strictly below `floor`.
fn packet_below_floor(meta: &solana_packet::Meta, data: Option<&[u8]>, floor: u64) -> bool {
    if meta.discard() || meta.flags.contains(PacketFlags::SIMPLE_VOTE_TX) {
        return false;
    }
    let Some(data) = data else {
        return false;
    };
    approximate_priority(data).is_some_and(|priority| priority < floor)
}

/// Apply the scheduler's published priority floor to freshly-received batches.
///
/// For `PacketBatch::Single` entries (the shape produced by the QUIC-TPU
/// streamer), below-floor packets are removed from the outer `Vec` entirely —
/// the batch never reaches dedup, sig verification, or the banking channel.
///
/// For multi-packet batches (forwarded packets, UDP coalesced batches),
/// below-floor packets are marked `discard` in place; downstream stages skip
/// them as they would any other discarded packet.
///
/// Returns the number of packets newly dropped.
pub(crate) fn apply_priority_floor(batches: &mut Vec<PacketBatch>, floor: u64) -> usize {
    let mut dropped: usize = 0;
    batches.retain_mut(|batch| {
        if let PacketBatch::Single(packet) = batch {
            let data = packet.data(..);
            if packet_below_floor(packet.meta(), data, floor) {
                dropped = dropped.saturating_add(1);
                return false;
            }
            return true;
        }
        for mut packet in batch.iter_mut() {
            let data = packet.data(..);
            // Rebind meta after dropping `data` because the borrow checker
            // can't let us hold a shared borrow and call meta_mut().
            let should_drop = packet_below_floor(packet.meta(), data, floor);
            if should_drop {
                packet.meta_mut().set_discard(true);
                dropped = dropped.saturating_add(1);
            }
        }
        true
    });
    dropped
}

impl SigVerifyStage {
    pub fn new<T: SigVerifier + 'static + Send>(
        packet_receiver: Receiver<PacketBatch>,
        verifier: T,
        thread_name: &'static str,
        metrics_name: &'static str,
        scheduler_saturation_feedback: Option<Arc<SchedulerSaturationFeedback>>,
    ) -> Self {
        let thread_hdl = Self::verifier_service(
            packet_receiver,
            verifier,
            thread_name,
            metrics_name,
            scheduler_saturation_feedback,
        );
        Self { thread_hdl }
    }

    pub fn discard_excess_packets(batches: &mut [PacketBatch], mut max_packets: usize) {
        // Group packets by their incoming IP address.
        let mut addrs = batches
            .iter_mut()
            .rev()
            .flat_map(|batch| batch.iter_mut().rev())
            .filter(|packet| !packet.meta().discard())
            .map(|packet| (packet.meta().addr, packet))
            .into_group_map();
        // Allocate max_packets evenly across addresses.
        while max_packets > 0 && !addrs.is_empty() {
            let num_addrs = addrs.len();
            addrs.retain(|_, packets| {
                let cap = max_packets.div_ceil(num_addrs);
                max_packets -= packets.len().min(cap);
                packets.truncate(packets.len().saturating_sub(cap));
                !packets.is_empty()
            });
        }
        // Discard excess packets from each address.
        for mut packet in addrs.into_values().flatten() {
            packet.meta_mut().set_discard(true);
        }
    }

    fn verifier<const K: usize, T: SigVerifier>(
        deduper: &Deduper<K, [u8]>,
        recvr: &Receiver<PacketBatch>,
        verifier: &mut T,
        stats: &mut SigVerifierStats,
        in_flight_count: &Arc<AtomicUsize>,
        scheduler_saturation_feedback: Option<&Arc<SchedulerSaturationFeedback>>,
    ) -> Result<()> {
        const SOFT_RECEIVE_CAP: usize = 5_000;
        let (mut batches, mut num_packets, recv_duration) =
            streamer::recv_packet_batches(recvr, SOFT_RECEIVE_CAP)?;

        // Apply the scheduler's priority floor *at dequeue*, before dedup and
        // sig verification. For Single batches (QUIC-TPU's shape) this removes
        // below-floor packets from the outer vec entirely, relieving both CPU
        // and the unbounded sigverify→banking channel downstream.
        if let Some(feedback) = scheduler_saturation_feedback {
            let (saturated, floor) = feedback.get();
            if saturated {
                let dropped = apply_priority_floor(&mut batches, floor);
                if dropped > 0 {
                    stats.total_dropped_below_priority_floor = stats
                        .total_dropped_below_priority_floor
                        .saturating_add(dropped);
                    num_packets = num_packets.saturating_sub(dropped);
                }
            }
        }

        // If we're already at capacity immediately drop the packets
        let mut should_drop = false;
        if in_flight_count.load(Ordering::Relaxed) >= verifier.capacity() {
            stats.total_dropped_on_capacity += num_packets;
            should_drop = true;
        }

        let batches_len = batches.len();

        stats
            .recv_batches_us_hist
            .increment(recv_duration.as_micros() as u64)
            .unwrap();
        stats.batches_hist.increment(batches_len as u64).unwrap();
        stats.packets_hist.increment(num_packets as u64).unwrap();
        stats.total_batches += batches_len;
        stats.total_packets += num_packets;

        if !should_drop {
            debug!(
                "@{:?} verifier: verifying: {}",
                timing::timestamp(),
                num_packets,
            );
            let mut dedup_time = Measure::start("sigverify_dedup_time");
            let discard_or_dedup_fail =
                deduper::dedup_packets_and_count_discards(deduper, &mut batches) as usize;
            dedup_time.stop();
            let num_unique = num_packets.saturating_sub(discard_or_dedup_fail);
            let num_packets_to_verify = num_unique;

            verifier.verify_and_send_packets(
                batches,
                num_packets_to_verify,
                in_flight_count.clone(),
                stats.total_valid_packets.clone(),
                stats.total_verify_time_us.clone(),
            )?;
            debug!(
                "@{:?} verifier: done. batches: {} packets: {}",
                timing::timestamp(),
                batches_len,
                num_packets
            );
            if num_packets > 0 {
                stats
                    .dedup_packets_pp_us_hist
                    .increment(dedup_time.as_us() / (num_packets as u64))
                    .unwrap();
            }
            stats.total_dedup += discard_or_dedup_fail;
            stats.total_dedup_time_us += dedup_time.as_us() as usize;
        }

        Ok(())
    }

    fn verifier_service<T: SigVerifier + 'static + Send>(
        packet_receiver: Receiver<PacketBatch>,
        mut verifier: T,
        thread_name: &'static str,
        metrics_name: &'static str,
        scheduler_saturation_feedback: Option<Arc<SchedulerSaturationFeedback>>,
    ) -> JoinHandle<()> {
        let mut stats = SigVerifierStats::default();
        let mut last_print = Instant::now();
        const MAX_DEDUPER_AGE: Duration = Duration::from_secs(2);
        const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
        const DEDUPER_NUM_BITS: u64 = 63_999_979;
        Builder::new()
            .name(thread_name.to_string())
            .spawn(move || {
                let mut rng = rand::rng();
                let mut deduper = Deduper::<2, [u8]>::new(&mut rng, DEDUPER_NUM_BITS);
                let in_flight_count = Arc::new(AtomicUsize::new(0));
                loop {
                    if deduper.maybe_reset(&mut rng, DEDUPER_FALSE_POSITIVE_RATE, MAX_DEDUPER_AGE) {
                        stats.num_deduper_saturations += 1;
                    }
                    if let Err(e) = Self::verifier(
                        &deduper,
                        &packet_receiver,
                        &mut verifier,
                        &mut stats,
                        &in_flight_count,
                        scheduler_saturation_feedback.as_ref(),
                    ) {
                        match e {
                            SigVerifyServiceError::Streamer(StreamerError::RecvTimeout(
                                RecvTimeoutError::Disconnected,
                            )) => break,
                            SigVerifyServiceError::Streamer(StreamerError::RecvTimeout(
                                RecvTimeoutError::Timeout,
                            )) => (),
                            _ => error!("{e:?}"),
                        }
                    }
                    if last_print.elapsed().as_secs() > 2 {
                        stats.maybe_report_and_reset(metrics_name);
                        last_print = Instant::now();
                    }
                }
            })
            .unwrap()
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{banking_trace::BankingTracer, sigverify::TransactionSigVerifier},
        crossbeam_channel::unbounded,
        solana_compute_budget_interface::ComputeBudgetInstruction,
        solana_hash::Hash,
        solana_keypair::Keypair,
        solana_message::Message,
        solana_perf::{
            packet::{BytesPacket, BytesPacketBatch, Packet, RecycledPacketBatch, to_packet_batches},
            sigverify,
            test_tx::test_tx,
        },
        solana_pubkey::Pubkey,
        solana_signer::Signer,
        solana_system_interface::instruction as system_instruction,
        solana_transaction::Transaction,
        std::sync::Arc,
    };

    fn count_non_discard(packet_batches: &[PacketBatch]) -> usize {
        packet_batches
            .iter()
            .flatten()
            .filter(|p| !p.meta().discard())
            .count()
    }

    fn build_tx_with_cu_price(cu_price_microlamports: u64, cu_limit: u32) -> Vec<u8> {
        let payer = Keypair::new();
        let to = Pubkey::new_unique();
        let transfer_ix = system_instruction::transfer(&payer.pubkey(), &to, 1);
        let cu_price_ix = ComputeBudgetInstruction::set_compute_unit_price(cu_price_microlamports);
        let cu_limit_ix = ComputeBudgetInstruction::set_compute_unit_limit(cu_limit);
        let message = Message::new(
            &[transfer_ix, cu_price_ix, cu_limit_ix],
            Some(&payer.pubkey()),
        );
        let tx = Transaction::new(&[&payer], message, Hash::new_unique());
        bincode::serialize(&tx).unwrap()
    }

    fn packet_for_bytes(bytes: &[u8]) -> BytesPacket {
        let mut packet =
            BytesPacket::from_bytes(None, solana_perf::packet::bytes::Bytes::copy_from_slice(bytes));
        packet.meta_mut().set_discard(false);
        packet
    }

    fn single_batch(bytes: &[u8]) -> PacketBatch {
        PacketBatch::Single(packet_for_bytes(bytes))
    }

    fn multi_batch(packets: Vec<BytesPacket>) -> PacketBatch {
        let batch: BytesPacketBatch = packets.into();
        PacketBatch::from(batch)
    }

    #[test]
    fn test_packet_discard() {
        agave_logger::setup();
        let batch_size = 10;
        let mut batch = RecycledPacketBatch::with_capacity(batch_size);
        let packet = Packet::default();
        batch.resize(batch_size, packet);
        batch[3].meta_mut().addr = std::net::IpAddr::from([1u16; 8]);
        batch[3].meta_mut().set_discard(true);
        batch[4].meta_mut().addr = std::net::IpAddr::from([2u16; 8]);
        let mut batches = vec![PacketBatch::from(batch)];
        let max = 3;
        SigVerifyStage::discard_excess_packets(&mut batches, max);
        let total_non_discard = count_non_discard(&batches);
        assert_eq!(total_non_discard, max);
        assert!(!batches[0].get(0).unwrap().meta().discard());
        assert!(batches[0].get(3).unwrap().meta().discard());
        assert!(!batches[0].get(4).unwrap().meta().discard());
    }

    #[test]
    fn test_approximate_priority_matches_cu_price() {
        let cu_price = 1_234u64;
        let cu_limit = 10_000u32;
        let bytes = build_tx_with_cu_price(cu_price, cu_limit);
        let priority = approximate_priority(&bytes).expect("parseable transaction");
        assert!(priority >= cu_price);
    }

    #[test]
    fn test_approximate_priority_unparseable_returns_none() {
        let garbage = vec![0xFFu8; 16];
        assert!(approximate_priority(&garbage).is_none());
    }

    #[test]
    fn test_apply_priority_floor_drops_single_batch_whole() {
        let low = build_tx_with_cu_price(100, 1_000);
        let high = build_tx_with_cu_price(10_000, 1_000);
        let low_priority = approximate_priority(&low).unwrap();
        let high_priority = approximate_priority(&high).unwrap();
        assert!(low_priority < high_priority);

        let mut batches = vec![single_batch(&low), single_batch(&high)];
        let dropped = apply_priority_floor(&mut batches, (low_priority + high_priority) / 2);
        assert_eq!(dropped, 1);
        // The below-floor Single batch is removed from the outer Vec entirely.
        assert_eq!(batches.len(), 1);
        // And the remaining batch is the high-priority one, untouched.
        assert!(!batches[0].first().unwrap().meta().discard());
    }

    #[test]
    fn test_apply_priority_floor_marks_inside_multi_batch() {
        let low = build_tx_with_cu_price(100, 1_000);
        let high = build_tx_with_cu_price(10_000, 1_000);
        let low_priority = approximate_priority(&low).unwrap();
        let high_priority = approximate_priority(&high).unwrap();

        let mut batches = vec![multi_batch(vec![
            packet_for_bytes(&low),
            packet_for_bytes(&high),
        ])];
        let dropped = apply_priority_floor(&mut batches, (low_priority + high_priority) / 2);
        assert_eq!(dropped, 1);
        // Multi-packet batches are kept in the Vec; below-floor packets are marked.
        assert_eq!(batches.len(), 1);
        assert!(batches[0].get(0).unwrap().meta().discard());
        assert!(!batches[0].get(1).unwrap().meta().discard());
    }

    #[test]
    fn test_apply_priority_floor_skips_unparseable() {
        let garbage =
            BytesPacket::from_bytes(None, solana_perf::packet::bytes::Bytes::copy_from_slice(&[0xFFu8; 16]));
        let mut batches = vec![PacketBatch::Single(garbage)];
        let dropped = apply_priority_floor(&mut batches, 1_000_000);
        assert_eq!(dropped, 0);
        assert_eq!(batches.len(), 1);
    }

    #[test]
    fn test_apply_priority_floor_skips_vote_flagged() {
        let low = build_tx_with_cu_price(100, 1_000);
        let mut packet = packet_for_bytes(&low);
        packet.meta_mut().flags |= PacketFlags::SIMPLE_VOTE_TX;
        let mut batches = vec![PacketBatch::Single(packet)];
        let dropped = apply_priority_floor(&mut batches, u64::MAX);
        assert_eq!(dropped, 0);
        assert_eq!(batches.len(), 1);
    }

    fn gen_batches(
        use_same_tx: bool,
        packets_per_batch: usize,
        total_packets: usize,
    ) -> Vec<PacketBatch> {
        if use_same_tx {
            let tx = test_tx();
            to_packet_batches(&vec![tx; total_packets], packets_per_batch)
        } else {
            let txs: Vec<_> = (0..total_packets).map(|_| test_tx()).collect();
            to_packet_batches(&txs, packets_per_batch)
        }
    }

    #[test]
    fn test_sigverify_stage_with_same_tx() {
        test_sigverify_stage(true)
    }

    #[test]
    fn test_sigverify_stage_without_same_tx() {
        test_sigverify_stage(false)
    }

    fn test_sigverify_stage(use_same_tx: bool) {
        agave_logger::setup();
        trace!("start");
        let (packet_s, packet_r) = unbounded();
        let (verified_s, verified_r) = BankingTracer::channel_for_test();
        let threadpool = Arc::new(sigverify::threadpool_for_tests());
        let verifier = TransactionSigVerifier::new(threadpool, verified_s, None, None);
        let stage = SigVerifyStage::new(packet_r, verifier, "solSigVerTest", "test", None);

        let now = Instant::now();
        let packets_per_batch = 128;
        let total_packets = 1920;

        let batches = gen_batches(use_same_tx, packets_per_batch, total_packets);
        trace!(
            "starting... generation took: {} ms batches: {}",
            now.elapsed().as_millis(),
            batches.len()
        );

        let mut sent_len = 0;
        for batch in batches.into_iter() {
            sent_len += batch.len();
            assert_eq!(batch.len(), packets_per_batch);
            packet_s.send(batch).unwrap();
        }
        let mut packet_s = Some(packet_s);
        let mut valid_received = 0;
        trace!("sent: {sent_len}");
        loop {
            if let Ok(verifieds) = verified_r.recv() {
                valid_received += verifieds
                    .iter()
                    .map(|batch| batch.iter().filter(|p| !p.meta().discard()).count())
                    .sum::<usize>();
            } else {
                break;
            }

            // Check if all the sent batches have been picked up by sigverify stage.
            // Drop sender to exit the loop on next receive call, once the channel is
            // drained.
            if packet_s.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                packet_s.take();
            }
        }
        trace!("received: {valid_received}");

        if use_same_tx {
            assert_eq!(valid_received, 1);
        } else {
            assert_eq!(valid_received, total_packets);
        }
        stage.join().unwrap();
    }
}
