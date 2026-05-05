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

/// Priority floor shared from the banking-stage scheduler to sigverify.
///
/// When saturated, the scheduler publishes the queue-min transaction's
/// priority. Sigverify drops at-or-below-floor arrivals. `0` means "not saturated".
#[derive(Debug)]
pub struct SchedulerPriorityFloor {
    priority_floor: AtomicU64,
}

impl SchedulerPriorityFloor {
    /// Construct a new floor in the "not saturated" state (`0`).
    pub fn new() -> Self {
        Self {
            priority_floor: AtomicU64::new(0),
        }
    }

    /// Publish a new floor or clear with `0`.
    pub fn publish(&self, floor: u64) {
        self.priority_floor.store(floor, Ordering::Relaxed);
    }

    pub fn clear(&self) {
        self.publish(0);
    }

    /// Currently-published floor, or `None` if not saturated.
    pub fn get(&self) -> Option<u64> {
        let priority_floor = self.priority_floor.load(Ordering::Relaxed);
        (priority_floor != 0).then_some(priority_floor)
    }
}

impl Default for SchedulerPriorityFloor {
    fn default() -> Self {
        Self::new()
    }
}
