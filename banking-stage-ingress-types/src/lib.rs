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
/// sigverify stage. Carries two complementary signals across the boundary:
///
/// - **Saturation floor** (scheduler → sigverify). When the scheduler is
///   saturated, it publishes the bank-context priority of its queue-min
///   transaction. Sigverify reads this and cheaply drops below-floor
///   transactions before signature verification using a deliberately
///   simpler approximation that is empirically more aggressive than a
///   unit-correct comparison would be. `0` means "not saturated."
///
/// - **Arrivals counter** (sigverify → scheduler). Sigverify bumps a
///   monotonic counter on each successful send to the banking channel. The
///   scheduler diffs it per tick to compute the incoming arrival rate,
///   which drives the token-bucket saturation signal on the scheduler side.
///
/// - **In-flight counter** (sigverify → scheduler). Tracks the total
///   number of packets currently queued in the unbounded `sigverify →
///   banking` channel, *including packets marked `discard`*. Sigverify
///   increments immediately before send, rolls back on send failure, and
///   the scheduler decrements as it drains each batch. Kept separate from
///   `total_arrivals` so the token-bucket arrival rate remains a measure
///   of *real* work while the gauge reflects transport-level depth (the
///   two differ whenever sigverify retains partly-discarded multi-packet
///   batches).
///
/// Both atomics are bundled on a single struct because every consumer pair
/// uses them together in practice, and they share the same Arc plumbing from
/// `tpu.rs` through `BankingStage` and into `SchedulerController` /
/// `SigVerifyStage`.
#[derive(Debug, Default)]
pub struct BankingStageFeedback {
    // `0` means "not saturated"; published priority floors are expected
    // to be strictly positive in practice.
    priority_floor: AtomicU64,
    // Monotonic (never wraps in the lifetime of a validator process). Writer
    // is sigverify; reader is the scheduler.
    total_arrivals: AtomicU64,
    // Current depth of the sigverify→scheduler unbounded channel in total
    // packets (includes packets currently marked `discard`). Sigverify
    // bumps this immediately before send and compensates on send failure;
    // the scheduler decrements on drain and reads for reporting.
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

    /// Return the currently published floor, or `None` if the scheduler is
    /// not saturated. A stored value of `0` is used internally as the
    /// "not-saturated" sentinel; callers see it as `None`.
    pub fn get_priority_floor(&self) -> Option<u64> {
        let priority_floor = self.priority_floor.load(Ordering::Relaxed);
        (priority_floor != 0).then_some(priority_floor)
    }

    // --- arrivals counter (sigverify writes, scheduler reads) ---------------

    /// Record that `n` non-discard ("valid") packets have just entered the
    /// banking channel. Takes `usize` to match sigverify's own packet-count
    /// types; internally widened to `u64` to match the scheduler's
    /// arithmetic domain (monotonic counter that must not wrap for the
    /// lifetime of a validator process).
    pub fn add_arrivals(&self, n: usize) {
        self.total_arrivals.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn total_arrivals(&self) -> u64 {
        self.total_arrivals.load(Ordering::Relaxed)
    }

    // --- in-flight channel-depth counter (sigverify adds, scheduler subs) ---

    /// Record that `n` packets are being handed off to the banking channel
    /// (total — includes packets currently marked `discard`). In sigverify
    /// this bump happens immediately before `send()` and is rolled back on
    /// send failure. Paired with `sub_in_flight` on the drain side to yield
    /// a channel-depth gauge.
    pub fn add_in_flight(&self, n: usize) {
        self.in_flight_packets.fetch_add(n, Ordering::Relaxed);
    }

    /// Called after a batch is known not to be in the channel anymore:
    /// by the scheduler after drain, or by sigverify to compensate a
    /// failed send. Uses `saturating_sub` defensively to keep the gauge
    /// non-negative even if future callers mis-pair adds/subs.
    pub fn sub_in_flight(&self, n: usize) {
        // Fetch-and-update loop for saturating subtraction.
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
