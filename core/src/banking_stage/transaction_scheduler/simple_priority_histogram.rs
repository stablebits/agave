//! Rolling log-bucket histogram of simple-priority values, used by the
//! scheduler to publish a percentile-based pf-floor in sigverify's comparison
//! space.
//!
//! 64 buckets, log2-spaced over the u64 range. Each bucket holds an `f32`
//! weight; multiplicative decay per tick implements a rolling window without
//! tracking individual evictions. The histogram is fed by sampling the
//! scheduler's buffer each feedback tick (one sample per call to
//! [`SimplePriorityHistogram::add`]); over many ticks the bucket weights
//! converge to the buffer's simple-priority distribution.

use std::fmt::{self, Write};

/// log2-spaced buckets covering the full u64 range. Bucket `i` covers
/// `[2^i, 2^(i+1))` for `i in 0..63`, plus bucket 0 holds zero values
/// and 63 holds the open top end.
const NUM_BUCKETS: usize = 64;

#[derive(Debug)]
pub(crate) struct SimplePriorityHistogram {
    buckets: [f32; NUM_BUCKETS],
}

impl Default for SimplePriorityHistogram {
    fn default() -> Self {
        Self {
            buckets: [0.0; NUM_BUCKETS],
        }
    }
}

impl SimplePriorityHistogram {
    /// Add one observation to the histogram.
    pub(crate) fn add(&mut self, simple_priority: u64) {
        self.buckets[Self::bucket_index(simple_priority)] += 1.0;
    }

    /// Multiply every bucket by `factor` (typically ~0.95 per tick) to
    /// implement a rolling window.
    pub(crate) fn decay(&mut self, factor: f32) {
        for b in &mut self.buckets {
            *b *= factor;
        }
    }

    /// Estimated value at percentile `p` (0.0..=1.0). Returns `None` when
    /// the histogram is empty (no samples accumulated yet, or fully decayed).
    /// The returned value is the lower edge of the bucket that contains
    /// the percentile — coarse but sufficient for a pf-floor.
    pub(crate) fn percentile(&self, p: f32) -> Option<u64> {
        let total: f32 = self.buckets.iter().sum();
        // Threshold for "effectively empty": single observation could decay
        // below 1.0, so use a small floor to avoid noise-driven reads.
        if total < 1.0 {
            return None;
        }
        let target = total * p.clamp(0.0, 1.0);
        let mut acc = 0.0;
        for (i, &count) in self.buckets.iter().enumerate() {
            acc += count;
            if acc >= target {
                return Some(Self::bucket_lower_edge(i));
            }
        }
        // Floating-point drift could under-shoot; fall back to top bucket.
        Some(Self::bucket_lower_edge(NUM_BUCKETS - 1))
    }

    /// Total accumulated weight across all buckets. Useful as a "warmup
    /// done" check before relying on percentile readings.
    pub(crate) fn total_weight(&self) -> f32 {
        self.buckets.iter().sum()
    }

    /// Render the distribution as a compact one-line summary suitable for
    /// log output: total weight followed by a few key percentiles.
    pub(crate) fn format_summary(&self) -> String {
        let total = self.total_weight();
        let p10 = self.percentile(0.10).unwrap_or(0);
        let p25 = self.percentile(0.25).unwrap_or(0);
        let p50 = self.percentile(0.50).unwrap_or(0);
        let p75 = self.percentile(0.75).unwrap_or(0);
        let p90 = self.percentile(0.90).unwrap_or(0);
        format!(
            "weight={total:.0} p10={p10} p25={p25} p50={p50} p75={p75} p90={p90}"
        )
    }

    /// Render every non-empty bucket on its own line: `[lo, hi): weight`.
    /// For ad-hoc debugging when you want the full shape.
    pub(crate) fn format_full(&self) -> String {
        let mut out = String::new();
        for (i, &count) in self.buckets.iter().enumerate() {
            if count <= 0.0 {
                continue;
            }
            let lo = Self::bucket_lower_edge(i);
            let hi = if i == NUM_BUCKETS - 1 {
                u64::MAX
            } else {
                Self::bucket_lower_edge(i + 1)
            };
            let _ = writeln!(&mut out, "  [{lo}, {hi}): {count:.1}");
        }
        out
    }

    fn bucket_index(simple_priority: u64) -> usize {
        if simple_priority <= 1 {
            return 0;
        }
        // ilog2 of u64 is in 0..=63; floor(log2(v)) places `v` in bucket
        // `ilog2(v)` so values 2..3 land in bucket 1, 4..7 in bucket 2, etc.
        (simple_priority.ilog2() as usize).min(NUM_BUCKETS - 1)
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
        let h = SimplePriorityHistogram::default();
        assert_eq!(h.percentile(0.5), None);
    }

    #[test]
    fn bucket_index_boundaries() {
        assert_eq!(SimplePriorityHistogram::bucket_index(0), 0);
        assert_eq!(SimplePriorityHistogram::bucket_index(1), 0);
        assert_eq!(SimplePriorityHistogram::bucket_index(2), 1);
        assert_eq!(SimplePriorityHistogram::bucket_index(3), 1);
        assert_eq!(SimplePriorityHistogram::bucket_index(4), 2);
        assert_eq!(SimplePriorityHistogram::bucket_index(u64::MAX), 63);
    }

    #[test]
    fn percentile_walks_buckets() {
        let mut h = SimplePriorityHistogram::default();
        // 100 samples at value 4 (bucket 2), 100 at value 16 (bucket 4).
        for _ in 0..100 {
            h.add(4);
        }
        for _ in 0..100 {
            h.add(16);
        }
        // p25 lands in the lower bucket (bucket 2 lo=4).
        assert_eq!(h.percentile(0.25), Some(4));
        // p75 lands in the upper bucket (bucket 4 lo=16).
        assert_eq!(h.percentile(0.75), Some(16));
    }

    #[test]
    fn decay_reduces_weight() {
        let mut h = SimplePriorityHistogram::default();
        for _ in 0..100 {
            h.add(8);
        }
        let before = h.total_weight();
        h.decay(0.5);
        assert!((h.total_weight() - before * 0.5).abs() < 0.001);
    }

    #[test]
    fn fully_decayed_returns_none() {
        let mut h = SimplePriorityHistogram::default();
        h.add(8);
        for _ in 0..1000 {
            h.decay(0.5);
        }
        assert_eq!(h.percentile(0.5), None);
    }
}
