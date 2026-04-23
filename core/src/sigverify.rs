//! The `sigverify` module provides digital signature verification functions.
//! By default, signatures are verified in parallel using all available CPU
//! cores.

pub use solana_perf::sigverify::{count_packets_in_batches, ed25519_verify};
use {
    crate::{banking_trace::BankingPacketSender, sigverify_stage::SigVerifyServiceError},
    agave_banking_stage_ingress_types::{BankingPacketBatch, BankingStageFeedback},
    crossbeam_channel::{Sender, TrySendError},
    solana_measure::measure::Measure,
    solana_perf::{
        packet::PacketBatch,
        sigverify::{self},
    },
    std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub struct TransactionSigVerifier {
    thread_pool: Arc<rayon::ThreadPool>,
    banking_stage_sender: BankingPacketSender,
    forward_stage_sender: Option<Sender<(BankingPacketBatch, bool)>>,
    reject_non_vote: bool,
    /// Shared feedback with the banking-stage scheduler. Writer side:
    /// `add_arrivals` is bumped only after a successful send, while the
    /// in-flight gauge is bumped immediately before send and rolled back on
    /// send failure. `None` for the vote path (which has its own channel).
    feedback: Option<Arc<BankingStageFeedback>>,
}

impl TransactionSigVerifier {
    pub fn new_reject_non_vote(
        thread_pool: Arc<rayon::ThreadPool>,
        packet_sender: BankingPacketSender,
        forward_stage_sender: Option<Sender<(BankingPacketBatch, bool)>>,
    ) -> Self {
        let mut new_self = Self::new(thread_pool, packet_sender, forward_stage_sender, None);
        new_self.reject_non_vote = true;
        new_self
    }

    pub fn new(
        thread_pool: Arc<rayon::ThreadPool>,
        banking_stage_sender: BankingPacketSender,
        forward_stage_sender: Option<Sender<(BankingPacketBatch, bool)>>,
        feedback: Option<Arc<BankingStageFeedback>>,
    ) -> Self {
        Self {
            thread_pool,
            banking_stage_sender,
            forward_stage_sender,
            reject_non_vote: false,
            feedback,
        }
    }

    pub(crate) fn verify_and_send_packets(
        &mut self,
        batches: Vec<PacketBatch>,
        valid_packets: usize,
        in_flight_count: Arc<AtomicUsize>,
        total_valid_packets: Arc<AtomicUsize>,
        total_verify_time_us: Arc<AtomicUsize>,
    ) -> Result<(), SigVerifyServiceError> {
        let banking_stage_sender = self.banking_stage_sender.clone();
        let forward_stage_sender = self.forward_stage_sender.clone();
        let reject_non_vote = self.reject_non_vote;
        let feedback = self.feedback.clone();

        in_flight_count.fetch_add(valid_packets, Ordering::Release);

        self.thread_pool.spawn(move || {
            let mut verify_time = Measure::start("sigverify_batch_time");
            let mut batches = batches;
            sigverify::ed25519_verify(&mut batches, reject_non_vote, valid_packets);
            verify_time.stop();
            let num_valid_packets = sigverify::count_valid_packets(&batches);
            let num_total_packets = count_packets_in_batches(&batches);

            let banking_packet_batch = BankingPacketBatch::new(batches);
            // Bump in-flight BEFORE the channel send so the scheduler's
            // drain-side `sub_in_flight` is guaranteed to observe it
            // (the crossbeam send→recv edge synchronizes the prior
            // store). On send failure, undo to avoid a phantom
            // permanent positive on the gauge.
            if let Some(feedback) = feedback.as_ref() {
                feedback.add_in_flight(num_total_packets);
            }
            if let Some(forward_stage_sender) = &forward_stage_sender {
                if let Err(err) = banking_stage_sender.send(banking_packet_batch.clone()) {
                    error!("sigverify send failed: {err:?}");
                    if let Some(feedback) = feedback.as_ref() {
                        feedback.sub_in_flight(num_total_packets);
                    }
                    in_flight_count.fetch_sub(valid_packets, Ordering::Release);
                    return;
                }
                if let Err(TrySendError::Full(_)) =
                    forward_stage_sender.try_send((banking_packet_batch, reject_non_vote))
                {
                    warn!("forwarding stage channel is full, dropping packets.");
                }
            } else if let Err(err) = banking_stage_sender.send(banking_packet_batch) {
                error!("sigverify send failed: {err:?}");
                if let Some(feedback) = feedback.as_ref() {
                    feedback.sub_in_flight(num_total_packets);
                }
                in_flight_count.fetch_sub(valid_packets, Ordering::Release);
                return;
            }
            // `add_arrivals` is a monotonic counter for the scheduler's
            // token bucket; only count packets that actually reached
            // the channel (so it stays after a successful send).
            if let Some(feedback) = feedback.as_ref() {
                feedback.add_arrivals(num_valid_packets);
            }

            total_valid_packets.fetch_add(num_valid_packets, Ordering::Relaxed);
            total_verify_time_us.fetch_add(verify_time.as_us() as usize, Ordering::Relaxed);
            in_flight_count.fetch_sub(valid_packets, Ordering::Release);
        });

        Ok(())
    }

    pub(crate) fn capacity(&self) -> usize {
        const CAPACITY_PER_THREAD: usize = {
            15_000 // ~15k packets per second throughput
            * 2 // 2 seconds worth
        };
        self.thread_pool
            .current_num_threads()
            .saturating_mul(CAPACITY_PER_THREAD)
    }
}
