#![cfg(feature = "agave-unstable-api")]
use {
    crossbeam_channel::Receiver,
    solana_perf::packet::PacketBatch,
    std::sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

pub type BankingPacketBatch = Arc<Vec<PacketBatch>>;
pub type BankingPacketReceiver = Receiver<BankingPacketBatch>;

/// Shared coordination channel between the banking-stage scheduler and the
/// sigverify stage. Carries three signals across the boundary:
///
/// - **Saturation floor** (scheduler → sigverify). When saturated, the
///   scheduler publishes the sigverify-space simple priority of the
///   queue's lowest-priority transaction (`priority_fee * 1_000_000 /
///   compute_unit_limit` — same shape sigverify computes per packet).
///   Sigverify drops below-floor arrivals: anything cheaper than what
///   the scheduler would itself evict on overflow. Unit-consistent on
///   both sides. `0` means "not saturated."
///
/// - **Arrivals counter** (sigverify → scheduler). Monotonic count of
///   non-discard packets sigverify has handed off to the banking
///   channel. Scheduler diffs per-tick to drive the token-bucket
///   saturation signal.
///
/// - **In-flight counter** (sigverify → scheduler). Total packets
///   currently in the unbounded `sigverify → banking` channel,
///   including those marked `discard`. Sigverify bumps before send
///   (rolling back on failure); scheduler subs on drain. Reported as a
///   transport-depth gauge — kept separate from arrivals so the bucket
///   measures real work and the gauge measures what's physically in
///   the channel.
#[derive(Debug, Default)]
pub struct BankingStageFeedback {
    // `0` is the "not saturated" sentinel; published floors are positive.
    priority_floor: AtomicU64,
    total_arrivals: AtomicU64,
    in_flight_packets: AtomicUsize,
    // Monotonic count of packets dropped because the bounded (test-mode)
    // sigverify→scheduler channel was full at send time. Writer is the
    // traced sender on `TrySendError::Full`; reader is the scheduler for
    // reporting.
    channel_full_drops: AtomicU64,

    // --- pipeline traffic counters (cumulative, never reset) ----------
    // Absolute counters at successive boundaries so the user can read the
    // growth rate at each step and localize where a queue is building.
    // `received_by_streamer` is measured at the *sigverify intake* — the
    // first place inside the validator that packets are counted without
    // touching cross-crate streamer code. It's a close proxy for
    // streamer output (the fetch_stage→sigverify bounded channel is
    // either transiently small or drops would show).
    packets_received_by_streamer: AtomicU64,
    packets_dropped_by_sigverify: AtomicU64,
    packets_received_by_scheduler: AtomicU64,
    packets_dropped_by_scheduler: AtomicU64,
}

impl BankingStageFeedback {
    // --- priority floor (scheduler writes, sigverify reads) -----------------

    pub fn set_priority_floor(&self, floor: u64) {
        debug_assert!(floor > 0, "published priority floor must be positive");
        self.priority_floor.store(floor, Ordering::Relaxed);
    }

    pub fn clear_priority_floor(&self) {
        self.priority_floor.store(0, Ordering::Relaxed);
    }

    /// Currently-published floor, or `None` if not saturated.
    pub fn get_priority_floor(&self) -> Option<u64> {
        let priority_floor = self.priority_floor.load(Ordering::Relaxed);
        (priority_floor != 0).then_some(priority_floor)
    }

    // --- arrivals counter (sigverify writes, scheduler reads) ---------------

    pub fn add_arrivals(&self, n: usize) {
        self.total_arrivals.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn total_arrivals(&self) -> u64 {
        self.total_arrivals.load(Ordering::Relaxed)
    }

    // --- in-flight channel-depth counter (sigverify adds, scheduler subs) ---

    pub fn add_in_flight(&self, n: usize) {
        self.in_flight_packets.fetch_add(n, Ordering::Relaxed);
    }

    /// Saturating sub tolerates the benign race where the receiver
    /// drains before the matching `add_in_flight` becomes visible, and
    /// guards against future mis-paired callers.
    pub fn sub_in_flight(&self, n: usize) {
        let mut current = self.in_flight_packets.load(Ordering::Relaxed);
        loop {
            let new = current.saturating_sub(n);
            match self.in_flight_packets.compare_exchange_weak(
                current,
                new,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    pub fn in_flight_packets(&self) -> usize {
        self.in_flight_packets.load(Ordering::Relaxed)
    }

    // --- channel-full drop counter (test-mode bounded non-vote channel) -----

    pub fn add_channel_full_drops(&self, n: usize) {
        self.channel_full_drops
            .fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn channel_full_drops(&self) -> u64 {
        self.channel_full_drops.load(Ordering::Relaxed)
    }

    // --- pipeline traffic counters -----------------------------------------

    pub fn add_streamer_received(&self, n: usize) {
        self.packets_received_by_streamer
            .fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn add_sigverify_dropped(&self, n: usize) {
        self.packets_dropped_by_sigverify
            .fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn add_scheduler_received(&self, n: usize) {
        self.packets_received_by_scheduler
            .fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn add_scheduler_dropped(&self, n: usize) {
        self.packets_dropped_by_scheduler
            .fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn packets_received_by_streamer(&self) -> u64 {
        self.packets_received_by_streamer.load(Ordering::Relaxed)
    }

    pub fn packets_dropped_by_sigverify(&self) -> u64 {
        self.packets_dropped_by_sigverify.load(Ordering::Relaxed)
    }

    pub fn packets_received_by_scheduler(&self) -> u64 {
        self.packets_received_by_scheduler.load(Ordering::Relaxed)
    }

    pub fn packets_dropped_by_scheduler(&self) -> u64 {
        self.packets_dropped_by_scheduler.load(Ordering::Relaxed)
    }
}
