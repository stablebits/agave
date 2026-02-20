//! The `sigverify_stage` implements the signature verification stage of the TPU. It
//! receives a list of lists of packets and outputs the same list, but tags each
//! top-level list with a list of booleans, telling the next stage whether the
//! signature in that packet is valid. It assumes each packet contains one
//! transaction. All processing is done on the CPU by default.

use {
    crate::sigverify,
    core::time::Duration,
    crossbeam_channel::{Receiver, RecvTimeoutError, SendError, TryRecvError},
    solana_measure::measure::Measure,
    solana_perf::{
        deduper::{self, Deduper},
        packet::PacketBatch,
        sigverify::{
            count_discarded_packets, count_packets_in_batches, count_valid_packets, shrink_batches,
        },
    },
    solana_streamer::streamer::StreamerError,
    std::{
        thread::{self, Builder, JoinHandle},
        time::Instant,
    },
    thiserror::Error,
};

const VERIFY_BATCH_TARGET: usize = 1000;

// Packet batch shrinker will reorganize packets into compacted batches if 10%
// or more of the packets in a group of packet batches have been discarded.
const MAX_DISCARDED_PACKET_RATE: f64 = 0.10;

#[derive(Error, Debug)]
pub enum SigVerifyServiceError<SendType> {
    #[error("send packets batch error")]
    Send(#[from] SendError<SendType>),

    #[error("streamer error")]
    Streamer(#[from] StreamerError),
}

type Result<T, SendType> = std::result::Result<T, SigVerifyServiceError<SendType>>;

pub struct SigVerifyStage {
    thread_hdl: JoinHandle<()>,
}

pub trait SigVerifier {
    type SendType: std::fmt::Debug;
    fn verify_batches(&self, batches: &mut [PacketBatch], valid_packets: usize);
    fn send_packets(&mut self, packet_batches: Vec<PacketBatch>) -> Result<(), Self::SendType>;
}

#[derive(Default, Clone)]
pub struct DisabledSigVerifier {}

#[derive(Default)]
struct SigVerifierStats {
    recv_batches_us_hist: histogram::Histogram, // time to call recv_batch
    verify_batches_pp_us_hist: histogram::Histogram, // per-packet time to call verify_batch
    dedup_packets_pp_us_hist: histogram::Histogram, // per-packet time to call dedup
    batches_hist: histogram::Histogram,         // number of packet batches per verify call
    packets_hist: histogram::Histogram,         // number of packets per verify call
    num_deduper_saturations: usize,
    total_batches: usize,
    total_packets: usize,
    total_dedup: usize,
    total_valid_packets: usize,
    total_dedup_time_us: usize,
    total_verify_time_us: usize,
}

impl SigVerifierStats {
    fn maybe_report(&self, name: &'static str) {
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
                "verify_batches_pp_us_90pct",
                self.verify_batches_pp_us_hist.percentile(90.0).unwrap_or(0),
                i64
            ),
            (
                "verify_batches_pp_us_min",
                self.verify_batches_pp_us_hist.minimum().unwrap_or(0),
                i64
            ),
            (
                "verify_batches_pp_us_max",
                self.verify_batches_pp_us_hist.maximum().unwrap_or(0),
                i64
            ),
            (
                "verify_batches_pp_us_mean",
                self.verify_batches_pp_us_hist.mean().unwrap_or(0),
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
            ("num_deduper_saturations", self.num_deduper_saturations, i64),
            ("total_batches", self.total_batches, i64),
            ("total_packets", self.total_packets, i64),
            ("total_dedup", self.total_dedup, i64),
            ("total_valid_packets", self.total_valid_packets, i64),
            ("total_dedup_time_us", self.total_dedup_time_us, i64),
            ("total_verify_time_us", self.total_verify_time_us, i64),
        );
    }
}

impl SigVerifier for DisabledSigVerifier {
    type SendType = ();
    fn verify_batches(&self, batches: &mut [PacketBatch], _valid_packets: usize) {
        sigverify::ed25519_verify_disabled(batches);
    }

    fn send_packets(&mut self, _packet_batches: Vec<PacketBatch>) -> Result<(), Self::SendType> {
        Ok(())
    }
}

impl SigVerifyStage {
    pub fn new<T: SigVerifier + 'static + Send>(
        packet_receiver: Receiver<PacketBatch>,
        verifier: T,
        thread_name: &'static str,
        metrics_name: &'static str,
    ) -> Self {
        let thread_hdl =
            Self::verifier_service(packet_receiver, verifier, thread_name, metrics_name);
        Self { thread_hdl }
    }

    /// make this function public so that it is available for benchmarking
    pub fn maybe_shrink_batches(
        packet_batches: Vec<PacketBatch>,
    ) -> (u64, usize, Vec<PacketBatch>) {
        let mut shrink_time = Measure::start("sigverify_shrink_time");
        let num_packets = count_packets_in_batches(&packet_batches);
        let num_discarded_packets = count_discarded_packets(&packet_batches);
        let pre_packet_batches_len = packet_batches.len();
        let discarded_packet_rate = (num_discarded_packets as f64) / (num_packets as f64);
        let packet_batches = if discarded_packet_rate >= MAX_DISCARDED_PACKET_RATE {
            shrink_batches(packet_batches)
        } else {
            packet_batches
        };
        let post_packet_batches_len = packet_batches.len();
        let shrink_total = pre_packet_batches_len.saturating_sub(post_packet_batches_len);
        shrink_time.stop();
        (shrink_time.as_us(), shrink_total, packet_batches)
    }

    fn verifier<const K: usize, T: SigVerifier>(
        deduper: &Deduper<K, [u8]>,
        recvr: &Receiver<PacketBatch>,
        verifier: &mut T,
        stats: &mut SigVerifierStats,
        accumulated: &mut Vec<PacketBatch>,
    ) -> Result<(), T::SendType> {
        accumulated.clear();

        // 1. Blocking recv for first batch
        let recv_start = Instant::now();
        let mut batch = recvr
            .recv_timeout(Duration::new(1, 0))
            .map_err(|e| SigVerifyServiceError::Streamer(StreamerError::RecvTimeout(e)))?;
        let recv_duration = recv_start.elapsed();

        let mut total_packets = batch.len();
        let mut total_dedup = 0;
        let mut valid_count = 0;

        // 2. Dedup + accumulate batches until VERIFY_BATCH_TARGET valid packets or channel empty
        let mut dedup_time = Measure::start("sigverify_dedup_time");

        let dedup_fail =
            deduper::dedup_packets_and_count_discards(deduper, std::slice::from_mut(&mut batch));
        total_dedup += dedup_fail as usize;
        let batch_valid = batch.len() - dedup_fail as usize;
        if batch_valid > 0 {
            valid_count += batch_valid;
            accumulated.push(batch);
        }

        while valid_count < VERIFY_BATCH_TARGET {
            match recvr.try_recv() {
                Ok(mut batch) => {
                    let batch_len = batch.len();
                    total_packets += batch_len;
                    let dedup_fail = deduper::dedup_packets_and_count_discards(
                        deduper,
                        std::slice::from_mut(&mut batch),
                    );
                    total_dedup += dedup_fail as usize;
                    let batch_valid = batch_len - dedup_fail as usize;
                    if batch_valid > 0 {
                        valid_count += batch_valid;
                        accumulated.push(batch);
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err(SigVerifyServiceError::Streamer(
                        StreamerError::RecvTimeout(RecvTimeoutError::Disconnected),
                    ));
                }
            }
        }
        dedup_time.stop();
        let batches_len = accumulated.len();

        // 3. Verify in-place
        let mut verify_time = Measure::start("sigverify_batch_time");
        verifier.verify_batches(accumulated, valid_count);
        let num_valid_packets = count_valid_packets(&*accumulated);
        verify_time.stop();

        // 4. Send
        let to_send: Vec<PacketBatch> = accumulated.drain(..).collect();
        if !to_send.is_empty() {
            verifier.send_packets(to_send)?;
        }

        // 5. Update stats
        stats
            .recv_batches_us_hist
            .increment(recv_duration.as_micros() as u64)
            .unwrap();
        if total_packets > 0 {
            stats
                .verify_batches_pp_us_hist
                .increment(verify_time.as_us() / (total_packets as u64))
                .unwrap();
            stats
                .dedup_packets_pp_us_hist
                .increment(dedup_time.as_us() / (total_packets as u64))
                .unwrap();
        }
        stats.batches_hist.increment(batches_len as u64).unwrap();
        stats
            .packets_hist
            .increment(total_packets as u64)
            .unwrap();
        stats.total_batches += batches_len;
        stats.total_packets += total_packets;
        stats.total_dedup += total_dedup;
        stats.total_valid_packets += num_valid_packets;
        stats.total_dedup_time_us += dedup_time.as_us() as usize;
        stats.total_verify_time_us += verify_time.as_us() as usize;

        Ok(())
    }

    fn verifier_service<T: SigVerifier + 'static + Send>(
        packet_receiver: Receiver<PacketBatch>,
        mut verifier: T,
        thread_name: &'static str,
        metrics_name: &'static str,
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
                let mut accumulated = Vec::with_capacity(16);
                loop {
                    if deduper.maybe_reset(&mut rng, DEDUPER_FALSE_POSITIVE_RATE, MAX_DEDUPER_AGE) {
                        stats.num_deduper_saturations += 1;
                    }
                    if let Err(e) = Self::verifier(
                        &deduper,
                        &packet_receiver,
                        &mut verifier,
                        &mut stats,
                        &mut accumulated,
                    ) {
                        match e {
                            SigVerifyServiceError::Streamer(StreamerError::RecvTimeout(
                                RecvTimeoutError::Disconnected,
                            )) => break,
                            SigVerifyServiceError::Streamer(StreamerError::RecvTimeout(
                                RecvTimeoutError::Timeout,
                            )) => (),
                            SigVerifyServiceError::Send(_) => {
                                break;
                            }
                            _ => error!("{e:?}"),
                        }
                    }
                    if last_print.elapsed().as_secs() > 2 {
                        stats.maybe_report(metrics_name);
                        stats = SigVerifierStats::default();
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
        solana_perf::{packet::to_packet_batches, test_tx::test_tx},
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
        let verifier = TransactionSigVerifier::new(verified_s, None);
        let stage = SigVerifyStage::new(packet_r, verifier, "solSigVerTest", "test");

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

    #[test]
    fn test_maybe_shrink_batches() {
        let packets_per_batch = 128;
        let total_packets = 4096;
        let batches = gen_batches(true, packets_per_batch, total_packets);
        let num_generated_batches = batches.len();
        let num_packets = count_packets_in_batches(&batches);
        let (_, num_shrunk_batches, mut batches) = SigVerifyStage::maybe_shrink_batches(batches);
        assert_eq!(num_shrunk_batches, 0);

        // discard until the threshold is met but not exceeded
        {
            let mut index = 0;
            batches.iter_mut().for_each(|batch| {
                batch.iter_mut().for_each(|mut p| {
                    if ((index + 1) as f64 / num_packets as f64) < MAX_DISCARDED_PACKET_RATE {
                        p.meta_mut().set_discard(true);
                    }
                    index += 1;
                })
            });
        }

        let (_, num_shrunk_batches, mut batches) = SigVerifyStage::maybe_shrink_batches(batches);
        assert_eq!(num_shrunk_batches, 0);

        // discard one more to exceed shrink threshold
        batches
            .last_mut()
            .unwrap()
            .first_mut()
            .unwrap()
            .meta_mut()
            .set_discard(true);

        let expected_num_shrunk_batches =
            1.max((num_generated_batches as f64 * MAX_DISCARDED_PACKET_RATE) as usize);
        let (_, num_shrunk_batches, batches) = SigVerifyStage::maybe_shrink_batches(batches);
        assert_eq!(num_shrunk_batches, expected_num_shrunk_batches);
        let expected_remaining_batches = num_generated_batches - expected_num_shrunk_batches;
        assert_eq!(batches.len(), expected_remaining_batches);
    }
}
