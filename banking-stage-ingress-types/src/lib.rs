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
/// sigverify stage. Carries a single signal across the boundary:
///
/// - **Saturation floor** (scheduler → sigverify). When saturated, the
///   scheduler publishes the queue-min tx's mainnet-context full-formula
///   priority (see `priority_formula::calculate_pf_drop_priority`).
///   Sigverify drops at-or-below-floor arrivals: anything no better than
///   what the scheduler would evict on overflow. `0` means "not saturated."
///
/// Other coordination signals the scheduler needs (per-tick arrivals for
/// saturation detection, etc.) are tracked scheduler-side rather than
/// shared, to keep this struct read-only on the sigverify path.
#[derive(Debug, Default)]
pub struct BankingStageFeedback {
    // `0` is the "not saturated" sentinel; published floors are positive.
    priority_floor: AtomicU64,
}

impl BankingStageFeedback {
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
}
