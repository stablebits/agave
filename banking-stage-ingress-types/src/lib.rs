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
///   scheduler publishes `simple_priority(queue_min_tx) * k`, where
///   `simple_priority` is the same `priority_fee * 1_000_000 /
///   compute_unit_limit` shape sigverify computes per packet (see
///   `priority_formula::calculate_simple_pf_priority`). Comparison is
///   unit-consistent on both sides. `k` is an adaptive multiplier
///   maintained by the scheduler — bumped while it's still hitting
///   `num_dropped_on_capacity`, decayed when not. `0` means "not
///   saturated."
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
}
