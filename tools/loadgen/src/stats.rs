use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const BUCKETS: usize = 128;

/// Latency histogram with two buckets per power of two of microseconds.
/// Recording is one atomic add; percentiles are read from the bucket counts
/// and are accurate to about 25%.
pub struct Histogram {
    buckets: [AtomicU64; BUCKETS],
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

fn bucket_of(micros: u64) -> usize {
    if micros < 2 {
        return micros as usize;
    }
    let top = micros.ilog2();
    let half = (micros >> (top - 1)) & 1;
    ((top * 2 + half as u32) as usize).min(BUCKETS - 1)
}

/// Middle of a bucket, in microseconds.
fn bucket_value(index: usize) -> f64 {
    if index < 2 {
        return index as f64;
    }
    let low = (1u128 << (index / 2)) as f64 * if index % 2 == 1 { 1.5 } else { 1.0 };
    low * 1.25
}

impl Histogram {
    pub fn record(&self, value: Duration) {
        let micros = u64::try_from(value.as_micros()).unwrap_or(u64::MAX);
        self.buckets[bucket_of(micros)].fetch_add(1, Ordering::Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum()
    }

    /// The value below which `p` (0 to 1) of the samples fall.
    pub fn percentile(&self, p: f64) -> Option<Duration> {
        let counts: Vec<u64> = self
            .buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect();
        let total: u64 = counts.iter().sum();
        if total == 0 {
            return None;
        }
        let rank = ((total as f64 * p).ceil() as u64).clamp(1, total);
        let mut seen = 0;
        for (index, count) in counts.iter().enumerate() {
            seen += count;
            if seen >= rank {
                return Some(Duration::from_secs_f64(bucket_value(index) / 1e6));
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// TCP connect to the proxy failed.
    Connect,
    /// No complete answer within the handshake timeout.
    Timeout,
    /// The proxy closed the connection during the handshake.
    Closed,
    /// The answer was not a valid fake-tls ServerHello for this secret.
    BadServerHello,
    /// The far end is not the fake DC.
    NotLoadgenDc,
    Io,
}

impl Failure {
    pub const ALL: [Self; 6] = [
        Self::Connect,
        Self::Timeout,
        Self::Closed,
        Self::BadServerHello,
        Self::NotLoadgenDc,
        Self::Io,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::Closed => "closed",
            Self::BadServerHello => "bad_server_hello",
            Self::NotLoadgenDc => "not_loadgen_dc",
            Self::Io => "io",
        }
    }
}

#[derive(Default)]
pub struct ClientStats {
    pub attempted: AtomicU64,
    pub established: AtomicU64,
    failures: [AtomicU64; Failure::ALL.len()],
    /// Sessions currently open, idle or active.
    pub open: AtomicU64,
    /// Established sessions that the proxy closed later.
    pub closed_by_peer: AtomicU64,
    /// Active sessions that stopped because of an error.
    pub active_errors: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    /// Completed echo round trips or download requests.
    pub requests: AtomicU64,
    pub handshake_time: Histogram,
    pub request_time: Histogram,
}

/// Counter values at one moment, for computing rates between two reports.
#[derive(Debug, Clone, Copy, Default)]
pub struct Snapshot {
    pub established: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub requests: u64,
}

fn millis(value: Option<Duration>) -> String {
    value.map_or_else(
        || "-".to_owned(),
        |d| format!("{:.1}", d.as_secs_f64() * 1e3),
    )
}

impl ClientStats {
    pub fn fail(&self, failure: Failure) {
        self.failures[failure as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub fn failures(&self, failure: Failure) -> u64 {
        self.failures[failure as usize].load(Ordering::Relaxed)
    }

    pub fn failed(&self) -> u64 {
        Failure::ALL.into_iter().map(|f| self.failures(f)).sum()
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            established: self.established.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            requests: self.requests.load(Ordering::Relaxed),
        }
    }

    fn failure_breakdown(&self) -> String {
        let parts: Vec<String> = Failure::ALL
            .into_iter()
            .filter(|f| self.failures(*f) > 0)
            .map(|f| format!("{}={}", f.as_str(), self.failures(f)))
            .collect();
        if parts.is_empty() {
            "0".to_owned()
        } else {
            format!("{} ({})", self.failed(), parts.join(" "))
        }
    }

    /// One progress line covering the time since `previous` was taken.
    pub fn report_line(&self, elapsed: Duration, since: Duration, previous: &Snapshot) -> String {
        let now = self.snapshot();
        let secs = since.as_secs_f64().max(1e-9);
        let mib = |bytes: u64| bytes as f64 / (1024.0 * 1024.0) / secs;
        format!(
            "t={:>4}s open={} established={} (+{:.0}/s) failed={} closed_by_peer={} \
             up={:.1} MiB/s down={:.1} MiB/s requests={:.0}/s \
             handshake p50/p99={}/{} ms request p50/p99={}/{} ms",
            elapsed.as_secs(),
            self.open.load(Ordering::Relaxed),
            now.established,
            (now.established - previous.established) as f64 / secs,
            self.failure_breakdown(),
            self.closed_by_peer.load(Ordering::Relaxed),
            mib(now.bytes_up - previous.bytes_up),
            mib(now.bytes_down - previous.bytes_down),
            (now.requests - previous.requests) as f64 / secs,
            millis(self.handshake_time.percentile(0.5)),
            millis(self.handshake_time.percentile(0.99)),
            millis(self.request_time.percentile(0.5)),
            millis(self.request_time.percentile(0.99)),
        )
    }

    pub fn summary(&self, elapsed: Duration) -> String {
        let secs = elapsed.as_secs_f64().max(1e-9);
        format!(
            "summary: {:.1}s, attempted {}, established {}, failed {}, still open {}, \
             closed by peer {}, active errors {}\n\
             traffic: up {:.1} MiB, down {:.1} MiB, {} requests ({:.0}/s)\n\
             handshake ms: p50 {} p95 {} p99 {}\n\
             request ms:   p50 {} p95 {} p99 {}",
            secs,
            self.attempted.load(Ordering::Relaxed),
            self.established.load(Ordering::Relaxed),
            self.failure_breakdown(),
            self.open.load(Ordering::Relaxed),
            self.closed_by_peer.load(Ordering::Relaxed),
            self.active_errors.load(Ordering::Relaxed),
            self.bytes_up.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0),
            self.bytes_down.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0),
            self.requests.load(Ordering::Relaxed),
            self.requests.load(Ordering::Relaxed) as f64 / secs,
            millis(self.handshake_time.percentile(0.5)),
            millis(self.handshake_time.percentile(0.95)),
            millis(self.handshake_time.percentile(0.99)),
            millis(self.request_time.percentile(0.5)),
            millis(self.request_time.percentile(0.95)),
            millis(self.request_time.percentile(0.99)),
        )
    }
}

#[derive(Default)]
pub struct DcStats {
    pub accepted: AtomicU64,
    /// Connections that completed the upstream handshake and sent a header.
    pub sessions: AtomicU64,
    /// Connections whose upstream handshake could not be read or was wrong.
    pub bad_handshake: AtomicU64,
    /// Connections that did not start with a load generator header.
    pub not_loadgen: AtomicU64,
    /// Idle connections held open right now.
    pub parked: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}

impl DcStats {
    pub fn report_line(&self, elapsed: Duration) -> String {
        format!(
            "t={:>4}s accepted={} sessions={} parked_idle={} bad_handshake={} not_loadgen={} \
             in={:.1} MiB out={:.1} MiB",
            elapsed.as_secs(),
            self.accepted.load(Ordering::Relaxed),
            self.sessions.load(Ordering::Relaxed),
            self.parked.load(Ordering::Relaxed),
            self.bad_handshake.load(Ordering::Relaxed),
            self.not_loadgen.load(Ordering::Relaxed),
            self.bytes_in.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0),
            self.bytes_out.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_monotonic_and_bounded() {
        let mut last = 0;
        for micros in [0u64, 1, 2, 3, 4, 5, 6, 7, 8, 100, 1000, 1_000_000, u64::MAX] {
            let bucket = bucket_of(micros);
            assert!(bucket >= last, "{micros}");
            assert!(bucket < BUCKETS);
            last = bucket;
        }
    }

    #[test]
    fn bucket_value_is_close_to_what_was_recorded() {
        for micros in [2u64, 3, 10, 150, 999, 4096, 123_456, 9_999_999] {
            let value = bucket_value(bucket_of(micros));
            let ratio = value / micros as f64;
            assert!((0.8..=1.3).contains(&ratio), "{micros} -> {value}");
        }
    }

    #[test]
    fn percentiles_follow_the_distribution() {
        let histogram = Histogram::default();
        assert_eq!(histogram.percentile(0.5), None);
        // 90 fast samples and 10 slow ones.
        for _ in 0..90 {
            histogram.record(Duration::from_millis(2));
        }
        for _ in 0..10 {
            histogram.record(Duration::from_millis(200));
        }
        assert_eq!(histogram.count(), 100);
        let p50 = histogram.percentile(0.5).unwrap().as_secs_f64() * 1e3;
        let p99 = histogram.percentile(0.99).unwrap().as_secs_f64() * 1e3;
        assert!((1.5..3.0).contains(&p50), "{p50}");
        assert!((150.0..270.0).contains(&p99), "{p99}");
        // Exactly at the boundary: the 90th sample is still a fast one.
        let p90 = histogram.percentile(0.9).unwrap().as_secs_f64() * 1e3;
        assert!(p90 < 3.0, "{p90}");
    }

    #[test]
    fn failures_are_counted_per_kind() {
        let stats = ClientStats::default();
        stats.fail(Failure::Timeout);
        stats.fail(Failure::Timeout);
        stats.fail(Failure::NotLoadgenDc);
        assert_eq!(stats.failures(Failure::Timeout), 2);
        assert_eq!(stats.failed(), 3);
        assert_eq!(stats.failure_breakdown(), "3 (timeout=2 not_loadgen_dc=1)");
        assert_eq!(ClientStats::default().failure_breakdown(), "0");
    }

    #[test]
    fn report_line_shows_rates_since_the_previous_snapshot() {
        let stats = ClientStats::default();
        stats.established.store(100, Ordering::Relaxed);
        let previous = stats.snapshot();
        stats.established.store(600, Ordering::Relaxed);
        stats.bytes_down.store(10 * 1024 * 1024, Ordering::Relaxed);
        stats.open.store(600, Ordering::Relaxed);
        let line = stats.report_line(Duration::from_secs(7), Duration::from_secs(5), &previous);
        assert!(line.contains("open=600"), "{line}");
        assert!(line.contains("established=600 (+100/s)"), "{line}");
        assert!(line.contains("down=2.0 MiB/s"), "{line}");
        assert!(line.contains("failed=0"), "{line}");
    }
}
