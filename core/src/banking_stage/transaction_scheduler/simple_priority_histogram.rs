//! Snapshot view of the simple-priority histogram. The actual buckets live
//! on `BankingStageFeedback` as atomic counters (writer is sigverify, which
//! sees every arrival before any drop decision); this type just wraps a
//! snapshot of those counters and provides percentile / formatting helpers.
//!
//! Buckets are log2-spaced over the u64 range. Bucket `i` covers
//! `[2^i, 2^(i+1))` for `i >= 1`; bucket 0 holds 0..=1; bucket 63 is the
//! open-ended top.

use {
    agave_banking_stage_ingress_types::SIMPLE_PRIORITY_NUM_BUCKETS,
    std::fmt::Write,
};

#[derive(Debug)]
pub(crate) struct SimplePriorityHistogram {
    buckets: [u32; SIMPLE_PRIORITY_NUM_BUCKETS],
}

impl SimplePriorityHistogram {
    pub(crate) fn from_snapshot(buckets: [u32; SIMPLE_PRIORITY_NUM_BUCKETS]) -> Self {
        Self { buckets }
    }

    /// Estimated value at percentile `p` (0.0..=1.0). Returns `None` when
    /// the histogram is effectively empty. The returned value is the lower
    /// edge of the bucket that contains the percentile — coarse but
    /// sufficient for a pf-floor.
    pub(crate) fn percentile(&self, p: f32) -> Option<u64> {
        let total = self.total_weight();
        if total == 0 {
            return None;
        }
        let target = (total as f64 * p.clamp(0.0, 1.0) as f64) as u64;
        let mut acc: u64 = 0;
        for (i, &count) in self.buckets.iter().enumerate() {
            acc = acc.saturating_add(count as u64);
            if acc >= target {
                return Some(Self::bucket_lower_edge(i));
            }
        }
        Some(Self::bucket_lower_edge(SIMPLE_PRIORITY_NUM_BUCKETS - 1))
    }

    /// Sum of bucket counts. Useful as a "warmup done" check.
    pub(crate) fn total_weight(&self) -> u64 {
        self.buckets.iter().map(|&c| c as u64).sum()
    }

    /// One-line summary: total weight + a few key percentiles. Used by the
    /// controller's periodic debug log.
    pub(crate) fn format_summary(&self) -> String {
        let total = self.total_weight();
        let p10 = self.percentile(0.10).unwrap_or(0);
        let p25 = self.percentile(0.25).unwrap_or(0);
        let p50 = self.percentile(0.50).unwrap_or(0);
        let p75 = self.percentile(0.75).unwrap_or(0);
        let p90 = self.percentile(0.90).unwrap_or(0);
        format!("weight={total} p10={p10} p25={p25} p50={p50} p75={p75} p90={p90}")
    }

    /// Render every non-empty bucket on its own line: `[lo, hi): count`.
    /// For ad-hoc debugging when you want the full shape.
    #[allow(dead_code)]
    pub(crate) fn format_full(&self) -> String {
        let mut out = String::new();
        for (i, &count) in self.buckets.iter().enumerate() {
            if count == 0 {
                continue;
            }
            let lo = Self::bucket_lower_edge(i);
            let hi = if i == SIMPLE_PRIORITY_NUM_BUCKETS - 1 {
                u64::MAX
            } else {
                Self::bucket_lower_edge(i + 1)
            };
            let _ = writeln!(&mut out, "  [{lo}, {hi}): {count}");
        }
        out
    }

    fn bucket_lower_edge(i: usize) -> u64 {
        if i == 0 { 0 } else { 1u64 << i }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_none() {
        let h = SimplePriorityHistogram::from_snapshot([0; SIMPLE_PRIORITY_NUM_BUCKETS]);
        assert_eq!(h.percentile(0.5), None);
    }

    #[test]
    fn percentile_walks_buckets() {
        // 100 samples in bucket 2 (4..=7), 100 in bucket 4 (16..=31).
        let mut buckets = [0u32; SIMPLE_PRIORITY_NUM_BUCKETS];
        buckets[2] = 100;
        buckets[4] = 100;
        let h = SimplePriorityHistogram::from_snapshot(buckets);
        assert_eq!(h.percentile(0.25), Some(4));
        assert_eq!(h.percentile(0.75), Some(16));
    }

    #[test]
    fn total_weight_sums_buckets() {
        let mut buckets = [0u32; SIMPLE_PRIORITY_NUM_BUCKETS];
        buckets[3] = 7;
        buckets[10] = 13;
        let h = SimplePriorityHistogram::from_snapshot(buckets);
        assert_eq!(h.total_weight(), 20);
    }
}
