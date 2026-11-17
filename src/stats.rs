use std::sync::atomic::{AtomicU64, Ordering};

/// Upper bounds, in seconds, of the clock-offset histogram buckets. Offsets
/// above the last bound land in an implicit +Inf bucket.
pub const SKEW_BUCKETS_SECS: [u64; 7] = [60, 300, 900, 1800, 3600, 21_600, 86_400];

const BUCKET_COUNT: usize = SKEW_BUCKETS_SECS.len() + 1;

/// Histogram of absolute clock offsets, in seconds.
#[derive(Default)]
pub struct SkewHistogram {
    buckets: [AtomicU64; BUCKET_COUNT],
    sum_secs: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkewSnapshot {
    /// Per-bucket counts (not cumulative); the last entry is the +Inf bucket.
    pub buckets: [u64; BUCKET_COUNT],
    pub count: u64,
    pub sum_secs: u64,
}

impl SkewHistogram {
    fn record(&self, offset_secs: u64) {
        let bucket = SKEW_BUCKETS_SECS
            .iter()
            .position(|bound| offset_secs <= *bound)
            .unwrap_or(SKEW_BUCKETS_SECS.len());
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.sum_secs.fetch_add(offset_secs, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> SkewSnapshot {
        let mut buckets = [0u64; BUCKET_COUNT];
        for (out, bucket) in buckets.iter_mut().zip(&self.buckets) {
            *out = bucket.load(Ordering::Relaxed);
        }
        SkewSnapshot {
            buckets,
            count: buckets.iter().sum(),
            sum_secs: self.sum_secs.load(Ordering::Relaxed),
        }
    }
}

/// Process-wide counters. Exported by the metrics endpoint in a later phase.
#[derive(Default)]
pub struct Stats {
    /// Handshakes rejected because the client clock was behind the proxy.
    pub skew_rejected_behind: SkewHistogram,
    /// Handshakes rejected because the client clock was ahead of the proxy.
    pub skew_rejected_ahead: SkewHistogram,
}

impl Stats {
    /// `skew_secs` is client time minus proxy time: negative means behind.
    pub fn record_skew_rejection(&self, skew_secs: i64) {
        let histogram = if skew_secs < 0 {
            &self.skew_rejected_behind
        } else {
            &self.skew_rejected_ahead
        };
        histogram.record(skew_secs.unsigned_abs());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejections_are_split_by_direction() {
        let stats = Stats::default();
        stats.record_skew_rejection(-700);
        stats.record_skew_rejection(-900);
        stats.record_skew_rejection(1300);

        let behind = stats.skew_rejected_behind.snapshot();
        assert_eq!(behind.count, 2);
        assert_eq!(behind.sum_secs, 1600);
        assert_eq!(behind.buckets, [0, 0, 2, 0, 0, 0, 0, 0]);

        let ahead = stats.skew_rejected_ahead.snapshot();
        assert_eq!(ahead.count, 1);
        assert_eq!(ahead.sum_secs, 1300);
        assert_eq!(ahead.buckets, [0, 0, 0, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn bucket_bounds_are_inclusive() {
        let stats = Stats::default();
        for offset in [0, 60, 61, 86_400, 86_401, i64::MAX] {
            stats.record_skew_rejection(offset);
        }
        let ahead = stats.skew_rejected_ahead.snapshot();
        assert_eq!(ahead.buckets, [2, 1, 0, 0, 0, 0, 1, 2]);
        assert_eq!(ahead.count, 6);
    }

    #[test]
    fn extreme_offsets_do_not_panic() {
        let stats = Stats::default();
        stats.record_skew_rejection(i64::MIN);
        stats.record_skew_rejection(i64::MIN);
        let behind = stats.skew_rejected_behind.snapshot();
        assert_eq!(behind.count, 2);
        assert_eq!(behind.buckets[7], 2);
    }
}
