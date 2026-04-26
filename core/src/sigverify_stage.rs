//! The `sigverify_stage` implements the signature verification stage of the TPU. It
//! receives a list of lists of packets and outputs the same list, but tags each
//! top-level list with a list of booleans, telling the next stage whether the
//! signature in that packet is valid. It assumes each packet contains one
//! transaction. All processing is done on the CPU by default.

use {
    crate::{
        priority_formula::calculate_simple_pf_priority, sigverify::TransactionSigVerifier,
    },
    agave_banking_stage_ingress_types::BankingStageFeedback,
    agave_transaction_view::transaction_view::SanitizedTransactionView,
    core::time::Duration,
    crossbeam_channel::{Receiver, RecvTimeoutError},
    solana_measure::measure::Measure,
    solana_perf::{
        deduper::{self, Deduper},
        packet::{PacketBatch, PacketFlags},
    },
    solana_runtime_transaction::runtime_transaction::RuntimeTransaction,
    solana_streamer::streamer::{self, StreamerError},
    solana_time_utils as timing,
    solana_transaction::sanitized::MessageHash,
    std::{
        sync::{
            Arc,
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
    const REPORT_INTERVAL: Duration = Duration::from_secs(2);

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

/// Approximate banking-stage priority for a packet from its raw bytes.
///
/// Delegates to [`calculate_simple_pf_priority`], which returns
/// `priority_fee_lamports * 1_000_000 / compute_unit_limit`. The
/// scheduler publishes the floor using the same simple formula on its
/// queue-min tx, so the comparison is unit-consistent. The simple
/// shape is empirically more aggressive than the full priority formula
/// — desired load-shedding behavior. The full-formula alternative
/// ([`crate::priority_formula::calculate_pf_drop_priority`]) is kept
/// for future use.
///
/// Returns `None` if the packet cannot be parsed; callers should leave
/// such packets alone (they will be rejected downstream if genuinely
/// invalid).
pub(crate) fn approximate_priority(data: &[u8]) -> Option<u64> {
    let view = SanitizedTransactionView::try_new_sanitized(data, true).ok()?;
    let runtime_tx = RuntimeTransaction::<SanitizedTransactionView<_>>::try_new(
        view,
        MessageHash::Compute,
        None,
    )
    .ok()?;
    calculate_simple_pf_priority(&runtime_tx)
}

/// Apply the scheduler's published priority floor to freshly-received
/// batches. Below-floor packets are marked `discard`; a batch is removed
/// from the outer `Vec` entirely when no packets survive (which covers the
/// `PacketBatch::Single` below-floor case uniformly and also reclaims
/// multi-packet batches whose packets all got dropped).
///
/// Returns the number of packets newly dropped.
pub(crate) fn apply_priority_floor(batches: &mut Vec<PacketBatch>, floor: u64) -> usize {
    let mut dropped: usize = 0;
    batches.retain_mut(|batch| {
        let mut any_kept = false;
        for mut packet in batch.iter_mut() {
            if packet.meta().discard() {
                // Pre-existing discard: stays discarded, doesn't count as
                // kept (so an all-prediscarded batch is dropped too).
                continue;
            }
            if packet.meta().flags.contains(PacketFlags::SIMPLE_VOTE_TX) {
                // Votes are immune to the priority floor (vote priority is
                // governed by a separate policy in banking stage).
                any_kept = true;
                continue;
            }
            let Some(data) = packet.data(..) else {
                // Zero-length or otherwise unreadable: leave to downstream
                // stages to reject.
                any_kept = true;
                continue;
            };
            match approximate_priority(data) {
                Some(priority) if priority < floor => {
                    packet.meta_mut().set_discard(true);
                    dropped = dropped.saturating_add(1);
                }
                _ => any_kept = true,
            }
        }
        any_kept
    });
    dropped
}

impl SigVerifyStage {
    pub fn new(
        packet_receiver: Receiver<PacketBatch>,
        verifier: TransactionSigVerifier,
        thread_name: &'static str,
        metrics_name: &'static str,
        banking_stage_feedback: Option<Arc<BankingStageFeedback>>,
    ) -> Self {
        let thread_hdl = Self::verifier_service(
            packet_receiver,
            verifier,
            thread_name,
            metrics_name,
            banking_stage_feedback,
        );
        Self { thread_hdl }
    }

    fn verifier<const K: usize>(
        deduper: &Deduper<K, [u8]>,
        recvr: &Receiver<PacketBatch>,
        verifier: &mut TransactionSigVerifier,
        stats: &mut SigVerifierStats,
        in_flight_count: &Arc<AtomicUsize>,
        banking_stage_feedback: Option<&Arc<BankingStageFeedback>>,
    ) -> Result<()> {
        const SOFT_RECEIVE_CAP: usize = 5_000;
        let (mut batches, num_packets_received, recv_duration) =
            streamer::recv_packet_batches(recvr, SOFT_RECEIVE_CAP)?;

        // Count every packet that reached sigverify intake (proxy for
        // streamer output).
        if let Some(feedback) = banking_stage_feedback {
            feedback.add_streamer_received(num_packets_received);
        }

        // Apply the scheduler's priority floor *at dequeue*, before dedup and
        // sig verification. For Single batches (QUIC-TPU's shape) this
        // removes below-floor packets from the outer vec entirely, relieving
        // both CPU and the sigverify→banking channel downstream.
        //
        // `num_packets` tracks packets that continue through the pipeline;
        // `num_packets_received` is preserved for the received-count stats so
        // drop counters remain subsets of total_packets.
        let mut num_packets = num_packets_received;
        if let Some(floor) = banking_stage_feedback.and_then(|f| f.get_priority_floor()) {
            let dropped = apply_priority_floor(&mut batches, floor);
            if dropped > 0 {
                stats.total_dropped_below_priority_floor = stats
                    .total_dropped_below_priority_floor
                    .saturating_add(dropped);
                num_packets = num_packets.saturating_sub(dropped);
                if let Some(feedback) = banking_stage_feedback {
                    feedback.add_sigverify_dropped(dropped);
                }
            }
        }

        // If we're already at capacity immediately drop the packets
        let mut should_drop = false;
        if in_flight_count.load(Ordering::Relaxed) >= verifier.capacity() {
            stats.total_dropped_on_capacity += num_packets;
            should_drop = true;
            if let Some(feedback) = banking_stage_feedback {
                feedback.add_sigverify_dropped(num_packets);
            }
        }

        let batches_len = batches.len();

        stats
            .recv_batches_us_hist
            .increment(recv_duration.as_micros() as u64)
            .unwrap();
        stats.batches_hist.increment(batches_len as u64).unwrap();
        stats
            .packets_hist
            .increment(num_packets_received as u64)
            .unwrap();
        stats.total_batches += batches_len;
        stats.total_packets += num_packets_received;

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
            verifier.verify_and_send_packets(
                batches,
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
            if let Some(feedback) = banking_stage_feedback {
                feedback.add_sigverify_dropped(discard_or_dedup_fail);
            }
        }

        Ok(())
    }

    fn verifier_service(
        packet_receiver: Receiver<PacketBatch>,
        mut verifier: TransactionSigVerifier,
        thread_name: &'static str,
        metrics_name: &'static str,
        banking_stage_feedback: Option<Arc<BankingStageFeedback>>,
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
                        banking_stage_feedback.as_ref(),
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
                    if last_print.elapsed() > SigVerifierStats::REPORT_INTERVAL {
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
        solana_perf::{packet::to_packet_batches, sigverify, test_tx::test_tx},
        std::sync::Arc,
    };

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
