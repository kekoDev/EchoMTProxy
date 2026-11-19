use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::limit::{Lane, Limits};

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

/// Label for SNIs outside the configured set. Not a valid hostname, so it
/// cannot collide with a real one.
pub const OTHER_LABEL: &str = "_other";

const MAX_SNI_LEN: usize = 253;
const METRICS_REQUEST_LIMIT: usize = 4096;
const METRICS_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeResult {
    Accepted,
    Malformed,
    BadDigest,
    BadTimestamp,
    Replay,
    BadInit,
    Timeout,
}

impl HandshakeResult {
    pub const ALL: [Self; 7] = [
        Self::Accepted,
        Self::Malformed,
        Self::BadDigest,
        Self::BadTimestamp,
        Self::Replay,
        Self::BadInit,
        Self::Timeout,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Malformed => "malformed",
            Self::BadDigest => "bad_digest",
            Self::BadTimestamp => "bad_timestamp",
            Self::Replay => "replay",
            Self::BadInit => "bad_init",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskResult {
    Forwarded,
    ConnectFailed,
    Limited,
}

impl MaskResult {
    pub const ALL: [Self; 3] = [Self::Forwarded, Self::ConnectFailed, Self::Limited];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::ConnectFailed => "connect_failed",
            Self::Limited => "limited",
        }
    }
}

#[derive(Default)]
struct LabelCounters {
    handshakes: [AtomicU64; HandshakeResult::ALL.len()],
    mask: [AtomicU64; MaskResult::ALL.len()],
    active: AtomicU64,
}

/// Process-wide counters.
///
/// Per-SNI series exist only for names known at startup (allowlisted mask
/// domains, the default mask host and the secrets' domains). Every other SNI
/// is folded into [`OTHER_LABEL`], so clients cannot grow the label set.
pub struct Stats {
    /// Handshakes rejected because the client clock was behind the proxy.
    pub skew_rejected_behind: SkewHistogram,
    /// Handshakes rejected because the client clock was ahead of the proxy.
    pub skew_rejected_ahead: SkewHistogram,
    labels: Vec<String>,
    lookup: HashMap<String, usize>,
    counters: Vec<LabelCounters>,
    connections_open: AtomicU64,
    connections_over_limit: AtomicU64,
    connections_accepted: AtomicU64,
    upstream_retries_ok: AtomicU64,
    upstream_retries_failed: AtomicU64,
    middle_connects_ok: AtomicU64,
    middle_connects_failed: AtomicU64,
    /// Lane byte counters, media limits and the congestion scale.
    pub limits: Limits,
}

/// Keeps a client connection counted as open until dropped.
pub struct OpenConnection {
    stats: Arc<Stats>,
}

impl Drop for OpenConnection {
    fn drop(&mut self) {
        self.stats.connections_open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Keeps a session counted as active until dropped.
pub struct ActiveSession {
    stats: Arc<Stats>,
    label: usize,
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.stats.counters[self.label]
            .active
            .fetch_sub(1, Ordering::Relaxed);
    }
}

fn normalize(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

impl Stats {
    pub fn new(names: impl IntoIterator<Item = String>) -> Self {
        Self::with_limits(names, Limits::unlimited())
    }

    pub fn with_limits(names: impl IntoIterator<Item = String>, limits: Limits) -> Self {
        let mut labels: Vec<String> = Vec::new();
        let mut lookup = HashMap::new();
        for name in names {
            let name = normalize(&name);
            if name != OTHER_LABEL && !lookup.contains_key(&name) {
                lookup.insert(name.clone(), labels.len());
                labels.push(name);
            }
        }
        labels.push(OTHER_LABEL.to_owned());
        let counters = labels.iter().map(|_| LabelCounters::default()).collect();
        Self {
            skew_rejected_behind: SkewHistogram::default(),
            skew_rejected_ahead: SkewHistogram::default(),
            labels,
            lookup,
            counters,
            connections_open: AtomicU64::new(0),
            connections_over_limit: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            upstream_retries_ok: AtomicU64::new(0),
            upstream_retries_failed: AtomicU64::new(0),
            middle_connects_ok: AtomicU64::new(0),
            middle_connects_failed: AtomicU64::new(0),
            limits,
        }
    }

    /// Counts a new client connection, unless `max` are already open. A
    /// refused connection is counted as over the limit instead.
    pub fn admit_connection(self: &Arc<Self>, max: u64) -> Option<OpenConnection> {
        self.connections_accepted.fetch_add(1, Ordering::Relaxed);
        if self.connections_open.fetch_add(1, Ordering::Relaxed) >= max {
            self.connections_open.fetch_sub(1, Ordering::Relaxed);
            self.connections_over_limit.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(OpenConnection {
            stats: self.clone(),
        })
    }

    pub fn connections_open(&self) -> u64 {
        self.connections_open.load(Ordering::Relaxed)
    }

    /// Every connection taken off a listener, admitted or not.
    pub fn connections_accepted(&self) -> u64 {
        self.connections_accepted.load(Ordering::Relaxed)
    }

    /// Counts one reconnect over the other address family after a DC reset
    /// the connection before answering.
    pub fn record_upstream_retry(&self, reconnected: bool) {
        let counter = if reconnected {
            &self.upstream_retries_ok
        } else {
            &self.upstream_retries_failed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts one attempt to connect and handshake with a middle proxy.
    pub fn record_middle_connect(&self, connected: bool) {
        let counter = if connected {
            &self.middle_connects_ok
        } else {
            &self.middle_connects_failed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// (connected, failed)
    pub fn middle_connects(&self) -> (u64, u64) {
        (
            self.middle_connects_ok.load(Ordering::Relaxed),
            self.middle_connects_failed.load(Ordering::Relaxed),
        )
    }

    /// (reconnected, failed to reconnect)
    pub fn upstream_retries(&self) -> (u64, u64) {
        (
            self.upstream_retries_ok.load(Ordering::Relaxed),
            self.upstream_retries_failed.load(Ordering::Relaxed),
        )
    }

    pub fn connections_over_limit(&self) -> u64 {
        self.connections_over_limit.load(Ordering::Relaxed)
    }

    /// Index of the series an SNI is counted under.
    pub fn label_index(&self, sni: Option<&str>) -> usize {
        sni.filter(|name| name.len() <= MAX_SNI_LEN)
            .and_then(|name| self.lookup.get(&normalize(name)).copied())
            .unwrap_or(self.labels.len() - 1)
    }

    pub fn label(&self, index: usize) -> &str {
        self.labels.get(index).map_or(OTHER_LABEL, String::as_str)
    }

    fn counters(&self, label: usize) -> &LabelCounters {
        &self.counters[label.min(self.counters.len() - 1)]
    }

    pub fn record_handshake(&self, label: usize, result: HandshakeResult) {
        self.counters(label).handshakes[result as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_mask(&self, label: usize, result: MaskResult) {
        self.counters(label).mask[result as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub fn session_started(self: &Arc<Self>, label: usize) -> ActiveSession {
        let label = label.min(self.counters.len() - 1);
        self.counters[label].active.fetch_add(1, Ordering::Relaxed);
        ActiveSession {
            stats: self.clone(),
            label,
        }
    }

    pub fn handshakes(&self, label: usize, result: HandshakeResult) -> u64 {
        self.counters(label).handshakes[result as usize].load(Ordering::Relaxed)
    }

    pub fn mask(&self, label: usize, result: MaskResult) -> u64 {
        self.counters(label).mask[result as usize].load(Ordering::Relaxed)
    }

    pub fn active_sessions(&self, label: usize) -> u64 {
        self.counters(label).active.load(Ordering::Relaxed)
    }

    /// `skew_secs` is client time minus proxy time: negative means behind.
    pub fn record_skew_rejection(&self, skew_secs: i64) {
        let histogram = if skew_secs < 0 {
            &self.skew_rejected_behind
        } else {
            &self.skew_rejected_ahead
        };
        histogram.record(skew_secs.unsigned_abs());
    }

    /// Prometheus text exposition of every counter.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);
        // Writing to a String cannot fail.
        let _ = self.render_into(&mut out);
        out
    }

    fn render_into(&self, out: &mut String) -> std::fmt::Result {
        writeln!(
            out,
            "# HELP echo_mtproxy_pool_buffers_in_use Relay buffers borrowed right now; \
             idle sessions hold none.\n\
             # TYPE echo_mtproxy_pool_buffers_in_use gauge\n\
             echo_mtproxy_pool_buffers_in_use {}",
            crate::pool::in_use()
        )?;
        writeln!(
            out,
            "# HELP echo_mtproxy_connections_open Client connections currently open, \
             including handshaking and masked ones.\n\
             # TYPE echo_mtproxy_connections_open gauge\n\
             echo_mtproxy_connections_open {}\n\
             # HELP echo_mtproxy_connections_accepted_total Connections taken off the \
             listeners, admitted or not.\n\
             # TYPE echo_mtproxy_connections_accepted_total counter\n\
             echo_mtproxy_connections_accepted_total {}\n\
             # HELP echo_mtproxy_connections_over_limit_total Connections refused because \
             max_connections were open.\n\
             # TYPE echo_mtproxy_connections_over_limit_total counter\n\
             echo_mtproxy_connections_over_limit_total {}",
            self.connections_open(),
            self.connections_accepted(),
            self.connections_over_limit()
        )?;
        let limits = &self.limits;
        writeln!(
            out,
            "# HELP echo_mtproxy_relay_bytes_total Bytes relayed, both directions, by lane.\n\
             # TYPE echo_mtproxy_relay_bytes_total counter\n\
             echo_mtproxy_relay_bytes_total{{lane=\"media\"}} {}\n\
             echo_mtproxy_relay_bytes_total{{lane=\"chat\"}} {}\n\
             # HELP echo_mtproxy_egress_bits_per_second Relay egress over the last \
             congestion-control tick (200 ms). An instantaneous sample: it reads 0 \
             between bursts, so average it over time or derive a rate from \
             echo_mtproxy_relay_bytes_total instead.\n\
             # TYPE echo_mtproxy_egress_bits_per_second gauge\n\
             echo_mtproxy_egress_bits_per_second {}\n\
             # HELP echo_mtproxy_congestion_scale Share of the configured media rate \
             currently allowed (1 = no congestion).\n\
             # TYPE echo_mtproxy_congestion_scale gauge\n\
             echo_mtproxy_congestion_scale {:.4}\n\
             # HELP echo_mtproxy_media_connections_throttled Media connections waiting on \
             their rate limit right now.\n\
             # TYPE echo_mtproxy_media_connections_throttled gauge\n\
             echo_mtproxy_media_connections_throttled {}",
            limits.bytes(Lane::Media),
            limits.bytes(Lane::Chat),
            limits.egress_bps(),
            limits.scale(),
            limits.throttled_now()
        )?;

        let (retried, retry_failed) = self.upstream_retries();
        writeln!(
            out,
            "# HELP echo_mtproxy_upstream_retries_total DC connections reset before the \
             DC's first byte and retried over the other address family.\n\
             # TYPE echo_mtproxy_upstream_retries_total counter\n\
             echo_mtproxy_upstream_retries_total{{result=\"reconnected\"}} {retried}\n\
             echo_mtproxy_upstream_retries_total{{result=\"failed\"}} {retry_failed}"
        )?;

        let (middle_ok, middle_failed) = self.middle_connects();
        writeln!(
            out,
            "# HELP echo_mtproxy_middle_connects_total Connection attempts to Telegram \
             middle proxies, including their handshake (upstream_mode = middle).\n\
             # TYPE echo_mtproxy_middle_connects_total counter\n\
             echo_mtproxy_middle_connects_total{{result=\"connected\"}} {middle_ok}\n\
             echo_mtproxy_middle_connects_total{{result=\"failed\"}} {middle_failed}"
        )?;

        out.push_str(
            "# HELP echo_mtproxy_handshakes_total Client handshakes by SNI and outcome.\n\
             # TYPE echo_mtproxy_handshakes_total counter\n",
        );
        for (index, label) in self.labels.iter().enumerate() {
            for result in HandshakeResult::ALL {
                writeln!(
                    out,
                    "echo_mtproxy_handshakes_total{{sni=\"{label}\",result=\"{}\"}} {}",
                    result.as_str(),
                    self.handshakes(index, result)
                )?;
            }
        }

        out.push_str(
            "# HELP echo_mtproxy_sessions_active Relayed sessions currently open, by SNI.\n\
             # TYPE echo_mtproxy_sessions_active gauge\n",
        );
        for (index, label) in self.labels.iter().enumerate() {
            writeln!(
                out,
                "echo_mtproxy_sessions_active{{sni=\"{label}\"}} {}",
                self.active_sessions(index)
            )?;
        }

        out.push_str(
            "# HELP echo_mtproxy_mask_connections_total Failed handshakes handed to a mask \
             target, by target and outcome.\n\
             # TYPE echo_mtproxy_mask_connections_total counter\n",
        );
        for (index, label) in self.labels.iter().enumerate() {
            if label == OTHER_LABEL {
                continue;
            }
            for result in MaskResult::ALL {
                writeln!(
                    out,
                    "echo_mtproxy_mask_connections_total{{target=\"{label}\",result=\"{}\"}} {}",
                    result.as_str(),
                    self.mask(index, result)
                )?;
            }
        }

        out.push_str(
            "# HELP echo_mtproxy_skew_rejected_seconds Clock offset of handshakes rejected \
             for clock skew.\n\
             # TYPE echo_mtproxy_skew_rejected_seconds histogram\n",
        );
        for (direction, histogram) in [
            ("behind", &self.skew_rejected_behind),
            ("ahead", &self.skew_rejected_ahead),
        ] {
            let snapshot = histogram.snapshot();
            let mut cumulative = 0;
            for (bound, count) in SKEW_BUCKETS_SECS.iter().zip(snapshot.buckets) {
                cumulative += count;
                writeln!(
                    out,
                    "echo_mtproxy_skew_rejected_seconds_bucket{{direction=\"{direction}\",le=\"{bound}\"}} {cumulative}"
                )?;
            }
            writeln!(
                out,
                "echo_mtproxy_skew_rejected_seconds_bucket{{direction=\"{direction}\",le=\"+Inf\"}} {}",
                snapshot.count
            )?;
            writeln!(
                out,
                "echo_mtproxy_skew_rejected_seconds_sum{{direction=\"{direction}\"}} {}",
                snapshot.sum_secs
            )?;
            writeln!(
                out,
                "echo_mtproxy_skew_rejected_seconds_count{{direction=\"{direction}\"}} {}",
                snapshot.count
            )?;
        }
        Ok(())
    }
}

async fn answer_metrics(mut stream: TcpStream, stats: &Stats) -> std::io::Result<()> {
    let mut request = Vec::with_capacity(512);
    let mut buf = [0u8; 512];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).await?;
        if n == 0 || request.len() + n > METRICS_REQUEST_LIMIT {
            return Ok(());
        }
        request.extend_from_slice(&buf[..n]);
    }
    let found = request.starts_with(b"GET /metrics ") || request.starts_with(b"GET /metrics?");
    let (status, body) = if found {
        ("200 OK", stats.render())
    } else {
        ("404 Not Found", "not found\n".to_owned())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

/// Serves `GET /metrics` in Prometheus text format, one request per connection.
pub async fn serve_metrics(listener: TcpListener, stats: Arc<Stats>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let stats = stats.clone();
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(
                        METRICS_REQUEST_TIMEOUT,
                        answer_metrics(stream, &stats),
                    )
                    .await;
                });
            }
            Err(err) => {
                tracing::warn!(error = %err, "metrics accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejections_are_split_by_direction() {
        let stats = Stats::new(Vec::new());
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
        let stats = Stats::new(Vec::new());
        for offset in [0, 60, 61, 86_400, 86_401, i64::MAX] {
            stats.record_skew_rejection(offset);
        }
        let ahead = stats.skew_rejected_ahead.snapshot();
        assert_eq!(ahead.buckets, [2, 1, 0, 0, 0, 0, 1, 2]);
        assert_eq!(ahead.count, 6);
    }

    #[test]
    fn extreme_offsets_do_not_panic() {
        let stats = Stats::new(Vec::new());
        stats.record_skew_rejection(i64::MIN);
        stats.record_skew_rejection(i64::MIN);
        let behind = stats.skew_rejected_behind.snapshot();
        assert_eq!(behind.count, 2);
        assert_eq!(behind.buckets[7], 2);
    }

    fn stats() -> Arc<Stats> {
        Arc::new(Stats::new(
            ["Google.com", "local.example", "google.com", "_other"].map(String::from),
        ))
    }

    #[test]
    fn labels_are_deduplicated_and_closed() {
        let stats = stats();
        assert_eq!(stats.label(0), "google.com");
        assert_eq!(stats.label(1), "local.example");
        assert_eq!(stats.label(2), OTHER_LABEL);
        assert_eq!(stats.label(99), OTHER_LABEL);

        assert_eq!(stats.label_index(Some("google.com")), 0);
        assert_eq!(stats.label_index(Some("GOOGLE.com.")), 0);
        assert_eq!(stats.label_index(Some("local.example")), 1);
        for unknown in [
            None,
            Some(""),
            Some("www.google.com"),
            Some("google.com.evil.example"),
            Some("_other"),
            Some("google.com.."),
        ] {
            assert_eq!(stats.label_index(unknown), 2, "{unknown:?}");
        }
        assert_eq!(stats.label_index(Some(&"a".repeat(100_000))), 2);
    }

    #[test]
    fn handshake_and_mask_counters_are_per_label() {
        let stats = stats();
        stats.record_handshake(0, HandshakeResult::Accepted);
        stats.record_handshake(0, HandshakeResult::Accepted);
        stats.record_handshake(1, HandshakeResult::BadDigest);
        stats.record_handshake(99, HandshakeResult::Replay);
        stats.record_mask(1, MaskResult::ConnectFailed);

        assert_eq!(stats.handshakes(0, HandshakeResult::Accepted), 2);
        assert_eq!(stats.handshakes(1, HandshakeResult::Accepted), 0);
        assert_eq!(stats.handshakes(1, HandshakeResult::BadDigest), 1);
        assert_eq!(stats.handshakes(2, HandshakeResult::Replay), 1);
        assert_eq!(stats.mask(1, MaskResult::ConnectFailed), 1);
        assert_eq!(stats.mask(0, MaskResult::ConnectFailed), 0);
    }

    #[test]
    fn active_sessions_follow_the_guard() {
        let stats = stats();
        let a = stats.session_started(0);
        let b = stats.session_started(0);
        let c = stats.session_started(42);
        assert_eq!(stats.active_sessions(0), 2);
        assert_eq!(stats.active_sessions(2), 1);
        drop(a);
        assert_eq!(stats.active_sessions(0), 1);
        drop((b, c));
        assert_eq!(stats.active_sessions(0), 0);
        assert_eq!(stats.active_sessions(2), 0);
    }

    #[test]
    fn connection_admission_respects_the_limit() {
        let stats = stats();
        let a = stats.admit_connection(2).unwrap();
        let b = stats.admit_connection(2).unwrap();
        assert!(stats.admit_connection(2).is_none());
        assert!(stats.admit_connection(2).is_none());
        assert_eq!(stats.connections_open(), 2);
        assert_eq!(stats.connections_over_limit(), 2);

        drop(a);
        assert_eq!(stats.connections_open(), 1);
        let c = stats.admit_connection(2).unwrap();
        assert!(stats.admit_connection(2).is_none());
        drop((b, c));
        assert_eq!(stats.connections_open(), 0);
        assert_eq!(stats.connections_over_limit(), 3);
        assert!(stats.admit_connection(0).is_none());

        let text = stats.render();
        assert!(text.contains("\necho_mtproxy_connections_open 0\n"));
        assert!(text.contains("\necho_mtproxy_connections_over_limit_total 4\n"));
        assert!(text.contains("\necho_mtproxy_connections_accepted_total 7\n"));
        assert_eq!(stats.connections_accepted(), 7);
    }

    #[test]
    fn concurrent_admission_never_exceeds_the_limit() {
        let stats = stats();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let stats = stats.clone();
                std::thread::spawn(move || {
                    let mut admitted = 0u64;
                    for _ in 0..20_000 {
                        if let Some(slot) = stats.admit_connection(3) {
                            assert!(stats.connections_open() <= 3 + 8);
                            admitted += 1;
                            drop(slot);
                        }
                    }
                    admitted
                })
            })
            .collect();
        let admitted: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(stats.connections_open(), 0);
        assert_eq!(admitted + stats.connections_over_limit(), 160_000);
    }

    #[test]
    fn traffic_and_congestion_metrics_are_rendered() {
        let stats = Arc::new(Stats::with_limits(
            ["a.example".to_owned()],
            // 1 Mbit/s link with the threshold at 80%.
            Limits::new(3_000_000, 0, 1_000_000, 0.8),
        ));
        let text = stats.render();
        for line in [
            "echo_mtproxy_relay_bytes_total{lane=\"media\"} 0",
            "echo_mtproxy_relay_bytes_total{lane=\"chat\"} 0",
            "# HELP echo_mtproxy_egress_bits_per_second Relay egress over the last \
             congestion-control tick (200 ms). An instantaneous sample: it reads 0 between \
             bursts, so average it over time or derive a rate from \
             echo_mtproxy_relay_bytes_total instead.",
            "echo_mtproxy_egress_bits_per_second 0",
            "echo_mtproxy_congestion_scale 1.0000",
            "echo_mtproxy_media_connections_throttled 0",
            "echo_mtproxy_upstream_retries_total{result=\"reconnected\"} 0",
            "echo_mtproxy_upstream_retries_total{result=\"failed\"} 0",
        ] {
            assert!(text.lines().any(|l| l == line), "missing: {line}\n{text}");
        }

        stats.record_upstream_retry(true);
        stats.record_upstream_retry(true);
        stats.record_upstream_retry(false);
        let text = stats.render();
        assert!(text.contains("echo_mtproxy_upstream_retries_total{result=\"reconnected\"} 2\n"));
        assert!(text.contains("echo_mtproxy_upstream_retries_total{result=\"failed\"} 1\n"));
    }

    #[test]
    fn render_is_valid_prometheus_text() {
        let stats = stats();
        stats.record_handshake(0, HandshakeResult::Accepted);
        stats.record_handshake(2, HandshakeResult::BadDigest);
        stats.record_mask(1, MaskResult::Forwarded);
        stats.record_skew_rejection(-700);
        stats.record_skew_rejection(-100_000);
        let _session = stats.session_started(0);
        let text = stats.render();

        for line in [
            "echo_mtproxy_handshakes_total{sni=\"google.com\",result=\"accepted\"} 1",
            "echo_mtproxy_handshakes_total{sni=\"google.com\",result=\"bad_digest\"} 0",
            "echo_mtproxy_handshakes_total{sni=\"_other\",result=\"bad_digest\"} 1",
            "echo_mtproxy_sessions_active{sni=\"google.com\"} 1",
            "echo_mtproxy_sessions_active{sni=\"local.example\"} 0",
            "echo_mtproxy_mask_connections_total{target=\"local.example\",result=\"forwarded\"} 1",
            "echo_mtproxy_skew_rejected_seconds_bucket{direction=\"behind\",le=\"300\"} 0",
            "echo_mtproxy_skew_rejected_seconds_bucket{direction=\"behind\",le=\"900\"} 1",
            "echo_mtproxy_skew_rejected_seconds_bucket{direction=\"behind\",le=\"86400\"} 1",
            "echo_mtproxy_skew_rejected_seconds_bucket{direction=\"behind\",le=\"+Inf\"} 2",
            "echo_mtproxy_skew_rejected_seconds_sum{direction=\"behind\"} 100700",
            "echo_mtproxy_skew_rejected_seconds_count{direction=\"behind\"} 2",
            "echo_mtproxy_skew_rejected_seconds_count{direction=\"ahead\"} 0",
        ] {
            assert!(text.lines().any(|l| l == line), "missing: {line}\n{text}");
        }
        assert!(!text.contains("target=\"_other\""));
        // Every line is a comment or `name{labels} value`.
        for line in text.lines() {
            assert!(
                line.starts_with("# ")
                    || (line.starts_with("echo_mtproxy_")
                        && line.rsplit(' ').next().unwrap().parse::<f64>().is_ok()),
                "{line}"
            );
        }
        // Every series has a TYPE line before its first sample.
        let mut typed = std::collections::HashSet::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                typed.insert(rest.split(' ').next().unwrap().to_owned());
            } else if !line.starts_with('#') {
                let name = line.split(['{', ' ']).next().unwrap();
                let family = name
                    .strip_suffix("_bucket")
                    .or_else(|| name.strip_suffix("_sum"))
                    .or_else(|| name.strip_suffix("_count"))
                    .unwrap_or(name);
                assert!(
                    typed.contains(family) || typed.contains(name),
                    "no TYPE for {name}"
                );
            }
        }
        assert!(text.ends_with('\n'));
    }

    async fn http(addr: std::net::SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        // The server may close, even with a reset, before taking the whole request.
        let _ = stream.write_all(request).await;
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response).await;
        response
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_only_metrics() {
        let stats = stats();
        stats.record_handshake(1, HandshakeResult::Replay);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_metrics(listener, stats));

        let ok = http(addr, b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
        let (headers, body) = ok.split_once("\r\n\r\n").unwrap();
        assert!(headers.contains(&format!("Content-Length: {}", body.len())));
        assert!(body
            .contains("echo_mtproxy_handshakes_total{sni=\"local.example\",result=\"replay\"} 1"));

        for request in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            b"GET /metricsx HTTP/1.1\r\n\r\n",
            b"POST /metrics HTTP/1.1\r\n\r\n",
        ] {
            assert!(http(addr, request).await.starts_with("HTTP/1.1 404 "));
        }

        // Oversized and incomplete requests are dropped without an answer.
        let mut huge = b"GET /metrics HTTP/1.1\r\nX: ".to_vec();
        huge.resize(10_000, b'a');
        assert_eq!(http(addr, &huge).await, "");
        let mut partial = TcpStream::connect(addr).await.unwrap();
        partial.write_all(b"GET /metrics HTT").await.unwrap();
        partial.shutdown().await.unwrap();
        let mut rest = String::new();
        partial.read_to_string(&mut rest).await.unwrap();
        assert_eq!(rest, "");
    }
}
