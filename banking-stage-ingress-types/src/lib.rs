#![cfg(feature = "agave-unstable-api")]
use {
    crossbeam_channel::Receiver,
    solana_perf::packet::PacketBatch,
    std::sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
};

/// Number of log2-spaced buckets covering the simple-priority histogram.
/// Bucket `i` covers `[2^i, 2^(i+1))` for `i >= 1`; bucket 0 holds 0..=1.
pub const SIMPLE_PRIORITY_NUM_BUCKETS: usize = 64;

pub type BankingPacketBatch = Arc<Vec<PacketBatch>>;
pub type BankingPacketReceiver = Receiver<BankingPacketBatch>;

/// Shared coordination channel between the banking-stage scheduler and the
/// sigverify stage. Carries four signals across the boundary:
///
/// - **Saturation floor** (scheduler → sigverify). When saturated, the
///   scheduler publishes `histogram.percentile(p) * k`, where the
///   histogram is the simple-priority histogram on this struct (fed by
///   sigverify) and `k` is an adaptive multiplier. The unit
///   (`priority_fee * 1_000_000 / compute_unit_limit`) matches
///   sigverify's per-packet check — the comparison is unit-consistent.
///   `0` means "not saturated."
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
///
/// - **Simple-priority histogram** (sigverify → scheduler). Log2-bucket
///   counts of arriving packets' simple-priorities. Sigverify bumps the
///   bucket *before* applying the floor, so the histogram reflects the
///   true input distribution rather than the post-filter survivor set.
///   Scheduler reads (snapshot + decay) each tick to compute the
///   percentile for the floor.
#[derive(Debug)]
pub struct BankingStageFeedback {
    // `0` is the "not saturated" sentinel; published floors are positive.
    priority_floor: AtomicU64,
    total_arrivals: AtomicU64,
    in_flight_packets: AtomicUsize,
    // Log2-spaced histogram of pre-filter simple-priorities. See
    // `add_simple_priority` / `snapshot_simple_priority_buckets` /
    // `decay_simple_priority_buckets`. Lives here (not on the scheduler
    // side) so the writer is sigverify, which sees every arrival before
    // any drop decision — avoids the feedback loop where post-filter
    // survivors bias the percentile upward.
    simple_priority_buckets: [AtomicU32; SIMPLE_PRIORITY_NUM_BUCKETS],
}

impl Default for BankingStageFeedback {
    fn default() -> Self {
        Self {
            priority_floor: AtomicU64::new(0),
            total_arrivals: AtomicU64::new(0),
            in_flight_packets: AtomicUsize::new(0),
            // `[AtomicU32; 64]` doesn't implement `Default` (only sizes <= 32
            // do); construct each slot explicitly.
            simple_priority_buckets: std::array::from_fn(|_| AtomicU32::new(0)),
        }
    }
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

    // --- simple-priority histogram (sigverify writes, scheduler reads) ------

    /// Increment the histogram bucket containing `simple_priority`.
    /// Bucket `i` covers `[2^i, 2^(i+1))`; bucket 0 holds 0..=1; values
    /// past bucket 63 are clamped to 63. Called from sigverify on every
    /// arriving packet, *before* the floor is applied — so the histogram
    /// reflects the true input distribution.
    pub fn add_simple_priority(&self, simple_priority: u64) {
        let bucket = if simple_priority <= 1 {
            0
        } else {
            (simple_priority.ilog2() as usize).min(SIMPLE_PRIORITY_NUM_BUCKETS - 1)
        };
        self.simple_priority_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot of the histogram buckets. Each load is independent so the
    /// snapshot is not atomic across buckets — fine for percentile
    /// estimation, where small inter-bucket skew is irrelevant.
    pub fn snapshot_simple_priority_buckets(&self) -> [u32; SIMPLE_PRIORITY_NUM_BUCKETS] {
        std::array::from_fn(|i| self.simple_priority_buckets[i].load(Ordering::Relaxed))
    }

    /// Multiply each bucket by `factor`, implementing the rolling window
    /// without per-tx remove tracking. Race with `add_simple_priority` is
    /// benign: at most a few counts lost per decay cycle, which is
    /// invisible against per-bucket counts in the thousands.
    pub fn decay_simple_priority_buckets(&self, factor: f32) {
        for bucket in &self.simple_priority_buckets {
            let old = bucket.load(Ordering::Relaxed);
            let new = (old as f32 * factor) as u32;
            bucket.store(new, Ordering::Relaxed);
        }
    }
}
