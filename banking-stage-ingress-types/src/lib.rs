#![cfg(feature = "agave-unstable-api")]
use {
    crossbeam_channel::Receiver,
    solana_perf::packet::PacketBatch,
    std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

pub type BankingPacketBatch = Arc<Vec<PacketBatch>>;
pub type BankingPacketReceiver = Receiver<BankingPacketBatch>;

/// Shared coordination channel between the banking-stage scheduler and the
/// sigverify stage. Carries two complementary signals across the boundary:
///
/// - **Saturation floor** (scheduler → sigverify). When the scheduler is
///   saturated, it publishes the minimum priority currently admitted to its
///   queue. Sigverify reads this and cheaply drops below-floor transactions
///   before signature verification. `0` means "not saturated."
///
/// - **Arrivals counter** (sigverify → scheduler). Sigverify bumps a
///   monotonic counter on each successful send to the banking channel. The
///   scheduler diffs it per tick to compute the incoming arrival rate,
///   which drives the token-bucket saturation signal on the scheduler side.
///
/// Both atomics are bundled on a single struct because every consumer pair
/// uses them together in practice, and they share the same Arc plumbing from
/// `tpu.rs` through `BankingStage` and into `SchedulerController` /
/// `SigVerifyStage`.
#[derive(Debug, Default)]
pub struct BankingStageFeedback {
    // `0` means "not saturated"; published scheduler priority floors are
    // expected to be strictly positive in practice.
    priority_floor: AtomicU64,
    // Monotonic (never wraps in the lifetime of a validator process). Writer
    // is sigverify; reader is the scheduler.
    total_arrivals: AtomicU64,
}

impl BankingStageFeedback {
    // --- priority floor (scheduler writes, sigverify reads) -----------------

    pub fn set_priority_floor(&self, floor: u64) {
        debug_assert!(floor > 0, "scheduler priority floor must be positive");
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

    /// Record that `n` packets have just entered the banking channel. Takes
    /// `usize` to match sigverify's own packet-count types; internally
    /// widened to `u64` to match the scheduler's arithmetic domain
    /// (monotonic counter that must not wrap for the lifetime of a
    /// validator process).
    pub fn add_arrivals(&self, n: usize) {
        self.total_arrivals
            .fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn total_arrivals(&self) -> u64 {
        self.total_arrivals.load(Ordering::Relaxed)
    }
}
