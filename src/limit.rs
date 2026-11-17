//! Media-lane rate limiting and traffic accounting.
//!
//! A session is on the media lane when its obfuscated2 init carries a negative
//! DC index, otherwise on the chat lane. Chat is never delayed. A media
//! session has a token bucket: it may send a burst at full speed, then a
//! sustained rate. Limiting is done by waiting before the next read, so the
//! peer is slowed by TCP backpressure and no byte is ever dropped.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use crate::sockopt;

const NANOS_PER_SEC: u128 = 1_000_000_000;
/// Fixed-point one for the congestion scale.
const SCALE_ONE: u32 = 1 << 16;
/// Media rates are never scaled below this share of the configured rate.
const MIN_SCALE: f64 = 0.05;
/// Recovery per controller tick once egress is back under the threshold.
const RECOVERY_FACTOR: f64 = 1.1;
/// Delays shorter than the timer resolution are carried as debt instead.
const MIN_SLEEP: Duration = Duration::from_millis(1);
/// One wait never exceeds this, so a rate change takes effect quickly.
const MAX_SLEEP: Duration = Duration::from_secs(1);
const COUNTER_SHARDS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Chat,
    Media,
}

impl Lane {
    /// Telegram clients mark media connections with a negative DC index.
    pub fn from_dc_idx(dc_idx: i16) -> Self {
        if dc_idx < 0 {
            Self::Media
        } else {
            Self::Chat
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Media => "media",
        }
    }
}

#[repr(align(64))]
#[derive(Default)]
struct Padded(AtomicU64);

/// A counter bumped from every worker on every read. Each thread adds to its
/// own cache line, so the hot path never contends; reading sums the shards.
pub struct ShardedCounter {
    shards: [Padded; COUNTER_SHARDS],
}

impl Default for ShardedCounter {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| Padded::default()),
        }
    }
}

fn shard_index() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static INDEX: usize = NEXT.fetch_add(1, Ordering::Relaxed) % COUNTER_SHARDS;
    }
    INDEX.try_with(|i| *i).unwrap_or(0)
}

impl ShardedCounter {
    #[inline]
    pub fn add(&self, n: u64) {
        self.shards[shard_index()].0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.shards
            .iter()
            .map(|s| s.0.load(Ordering::Relaxed))
            .sum()
    }
}

/// Process-wide limits and traffic counters.
pub struct Limits {
    /// Sustained media rate in bytes per second; 0 disables media limiting.
    media_rate: u64,
    media_burst: u64,
    /// Egress, in bits per second, above which media rates are scaled down.
    congestion_threshold_bps: f64,
    /// Current media scale as 16.16 fixed point.
    scale: AtomicU32,
    /// `media_rate` times the scale, in both forms, refreshed when the scale
    /// changes so the per-read path only loads them.
    effective_rate: AtomicU64,
    effective_rate_q32: AtomicU64,
    media_bytes: ShardedCounter,
    chat_bytes: ShardedCounter,
    throttled: AtomicU64,
    egress_bps: AtomicU64,
    last_total_bytes: AtomicU64,
}

/// Next congestion scale given the current one and the measured egress.
///
/// Above the threshold every media rate is cut by the same proportion the
/// link is over by. Below it the scale creeps back up, so a link that keeps
/// hovering at the threshold does not oscillate between extremes.
pub fn next_scale(current: f64, egress_bps: f64, threshold_bps: f64) -> f64 {
    let next = if threshold_bps > 0.0 && egress_bps > threshold_bps {
        current * threshold_bps / egress_bps
    } else {
        current * RECOVERY_FACTOR
    };
    next.clamp(MIN_SCALE, 1.0)
}

impl Limits {
    /// `media_rate_bps` and `link_capacity_bps` are in bits per second.
    pub fn new(
        media_rate_bps: u64,
        media_burst_bytes: u64,
        link_capacity_bps: u64,
        congestion_threshold: f64,
    ) -> Self {
        let rate = Rate::new(media_rate_bps / 8);
        Self {
            effective_rate: AtomicU64::new(rate.bytes_per_sec),
            effective_rate_q32: AtomicU64::new(rate.q32),
            media_rate: media_rate_bps / 8,
            media_burst: media_burst_bytes,
            congestion_threshold_bps: link_capacity_bps as f64 * congestion_threshold,
            scale: AtomicU32::new(SCALE_ONE),
            media_bytes: ShardedCounter::default(),
            chat_bytes: ShardedCounter::default(),
            throttled: AtomicU64::new(0),
            egress_bps: AtomicU64::new(0),
            last_total_bytes: AtomicU64::new(0),
        }
    }

    /// Accounting only: no media limit and no congestion control.
    pub fn unlimited() -> Self {
        Self::new(0, 0, 0, 0.0)
    }

    pub fn media_limited(&self) -> bool {
        self.media_rate > 0
    }

    /// Bytes relayed on a lane, both directions.
    pub fn bytes(&self, lane: Lane) -> u64 {
        match lane {
            Lane::Chat => self.chat_bytes.get(),
            Lane::Media => self.media_bytes.get(),
        }
    }

    /// Media sessions waiting on their bucket right now.
    pub fn throttled_now(&self) -> u64 {
        self.throttled.load(Ordering::Relaxed)
    }

    /// Relay egress measured by the last controller tick, in bits per second.
    pub fn egress_bps(&self) -> u64 {
        self.egress_bps.load(Ordering::Relaxed)
    }

    /// Share of the configured media rate currently allowed, 0.05 to 1.
    pub fn scale(&self) -> f64 {
        f64::from(self.scale.load(Ordering::Relaxed)) / f64::from(SCALE_ONE)
    }

    /// One step of congestion control: measures egress over `elapsed` and
    /// adjusts the media scale. Every relayed byte is written exactly once,
    /// so the lane counters are the proxy's relay egress.
    pub fn tick(&self, elapsed: Duration) {
        let total = self.media_bytes.get() + self.chat_bytes.get();
        let previous = self.last_total_bytes.swap(total, Ordering::Relaxed);
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 {
            return;
        }
        let egress = total.saturating_sub(previous) as f64 * 8.0 / secs;
        self.egress_bps.store(egress as u64, Ordering::Relaxed);
        let scale = next_scale(self.scale(), egress, self.congestion_threshold_bps);
        let fixed = (scale * f64::from(SCALE_ONE)).round() as u32;
        self.scale.store(fixed, Ordering::Relaxed);
        let rate = Rate::new((self.media_rate * u64::from(fixed)) >> 16);
        self.effective_rate
            .store(rate.bytes_per_sec, Ordering::Relaxed);
        self.effective_rate_q32.store(rate.q32, Ordering::Relaxed);
    }

    #[inline]
    fn effective_rate(&self) -> Rate {
        Rate {
            bytes_per_sec: self.effective_rate.load(Ordering::Relaxed),
            q32: self.effective_rate_q32.load(Ordering::Relaxed),
        }
    }

    #[cfg(test)]
    fn effective_media_rate(&self) -> u64 {
        self.effective_rate().bytes_per_sec
    }
}

/// A rate in the two forms the bucket needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rate {
    bytes_per_sec: u64,
    /// Bytes per nanosecond as 32.32 fixed point, so that crediting elapsed
    /// time is one multiplication and no division.
    q32: u64,
}

impl Rate {
    fn new(bytes_per_sec: u64) -> Self {
        let bytes_per_sec = bytes_per_sec.max(1);
        let q32 = (u128::from(bytes_per_sec) << 32) / NANOS_PER_SEC;
        Self {
            bytes_per_sec,
            q32: u64::try_from(q32).unwrap_or(u64::MAX).max(1),
        }
    }
}

/// Token bucket of one media session.
///
/// Both relay directions of a session run in the same task and never touch
/// the bucket concurrently; atomics are used only so the session stays `Send`.
struct Bucket {
    /// May go negative: a read is charged after it happened.
    tokens: AtomicI64,
    /// Time up to which refill has been credited, in ns since `epoch`.
    credited_ns: AtomicU64,
    /// Fraction of a byte earned but not yet credited, in 2^-32 bytes, so the
    /// remainder of each refill is carried instead of lost.
    fraction: AtomicU64,
    /// Bytes relayed since the last charge and not yet charged.
    pending: AtomicU64,
    /// How many bytes may stay pending before the next charge.
    slack: AtomicU64,
}

/// What charging a read did to the bucket.
#[derive(Debug, PartialEq, Eq)]
struct Charge {
    /// How long to wait so the debt is paid off at `rate`.
    wait: Duration,
    /// The bucket was completely full before this read.
    was_full: bool,
}

impl Bucket {
    fn new(burst: u64) -> Self {
        Self {
            tokens: AtomicI64::new(i64::try_from(burst).unwrap_or(i64::MAX)),
            credited_ns: AtomicU64::new(0),
            fraction: AtomicU64::new(0),
            pending: AtomicU64::new(0),
            slack: AtomicU64::new(burst / 2),
        }
    }

    /// Charges `bytes`, reading the clock only when the outcome can matter.
    ///
    /// A bucket holding T tokens cannot run dry before T more bytes pass,
    /// whatever the time. So after a charge leaves T tokens, up to T/2 bytes
    /// are only added up; the clock is read, and everything charged, once
    /// that much has accumulated. A session far from its limit pays an add
    /// and a compare per read. A session at its limit has no slack and is
    /// charged on every read, so throttling stays smooth.
    ///
    /// Charging late never grants more than charging on time would: refill is
    /// capped at the burst before the accumulated bytes are taken off.
    #[inline]
    fn charge_when_due(
        &self,
        bytes: u64,
        now_ns: impl FnOnce() -> u64,
        rate: Rate,
        burst: u64,
    ) -> Option<Charge> {
        let pending = self.pending.load(Ordering::Relaxed).saturating_add(bytes);
        if pending < self.slack.load(Ordering::Relaxed) {
            self.pending.store(pending, Ordering::Relaxed);
            return None;
        }
        let charge = self.charge(pending, now_ns(), rate, burst);
        self.pending.store(0, Ordering::Relaxed);
        let left = self.tokens.load(Ordering::Relaxed);
        self.slack
            .store(u64::try_from(left).unwrap_or(0) / 2, Ordering::Relaxed);
        Some(charge)
    }

    #[inline]
    fn charge(&self, bytes: u64, now_ns: u64, rate: Rate, burst: u64) -> Charge {
        let burst = i64::try_from(burst).unwrap_or(i64::MAX);
        let mut tokens = self.tokens.load(Ordering::Relaxed);

        let elapsed = now_ns.saturating_sub(self.credited_ns.load(Ordering::Relaxed));
        let earned_q32 = u128::from(elapsed) * u128::from(rate.q32)
            + u128::from(self.fraction.load(Ordering::Relaxed));
        let earned = i64::try_from(earned_q32 >> 32).unwrap_or(i64::MAX);
        self.credited_ns.store(now_ns, Ordering::Relaxed);
        if tokens.saturating_add(earned) >= burst {
            tokens = burst;
            self.fraction.store(0, Ordering::Relaxed);
        } else {
            tokens += earned;
            self.fraction
                .store(earned_q32 as u64 & u64::from(u32::MAX), Ordering::Relaxed);
        }
        let was_full = tokens >= burst;

        tokens = tokens.saturating_sub(i64::try_from(bytes).unwrap_or(i64::MAX));
        self.tokens.store(tokens, Ordering::Relaxed);
        if tokens >= 0 {
            return Charge {
                wait: Duration::ZERO,
                was_full,
            };
        }
        // Only a session in debt pays for a division.
        let nanos =
            u128::from(tokens.unsigned_abs()) * NANOS_PER_SEC / u128::from(rate.bytes_per_sec);
        Charge {
            wait: Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX)),
            was_full,
        }
    }
}

/// Traffic state of one session: its lane, byte counts and, on the media lane
/// with a limit configured, its bucket.
pub struct SessionTraffic<'a> {
    pub lane: Lane,
    limits: &'a Limits,
    client: &'a TcpStream,
    bucket: Option<Bucket>,
    epoch: Instant,
    /// Whether the kernel is currently pacing the client socket.
    paced: AtomicBool,
    /// Client→DC payload bytes.
    pub bytes_up: AtomicU64,
    /// DC→client bytes, including record headers.
    pub bytes_down: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Up,
    Down,
}

struct ThrottledGuard<'a>(&'a AtomicU64);

impl Drop for ThrottledGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl<'a> SessionTraffic<'a> {
    pub fn new(lane: Lane, limits: &'a Limits, client: &'a TcpStream) -> Self {
        let bucket = (lane == Lane::Media && limits.media_limited())
            .then(|| Bucket::new(limits.media_burst));
        Self {
            lane,
            limits,
            client,
            bucket,
            epoch: Instant::now(),
            paced: AtomicBool::new(false),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
        }
    }

    pub fn duration(&self) -> Duration {
        self.epoch.elapsed()
    }

    /// Counts `bytes` just relayed and returns how long the session must
    /// wait before reading again, if its bucket is in debt.
    #[inline]
    pub fn account(&self, direction: Direction, bytes: usize) -> Option<Duration> {
        let bytes = bytes as u64;
        match direction {
            Direction::Up => &self.bytes_up,
            Direction::Down => &self.bytes_down,
        }
        .fetch_add(bytes, Ordering::Relaxed);
        match self.lane {
            Lane::Chat => self.limits.chat_bytes.add(bytes),
            Lane::Media => self.limits.media_bytes.add(bytes),
        }

        let bucket = self.bucket.as_ref()?;
        let charge = bucket.charge_when_due(
            bytes,
            || u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX),
            self.limits.effective_rate(),
            self.limits.media_burst,
        )?;
        if charge.was_full && self.paced.load(Ordering::Relaxed) {
            // The session has been quiet long enough to earn its whole burst
            // back, so the kernel may send at full speed again.
            self.set_pacing(false);
        }
        (charge.wait >= MIN_SLEEP).then_some(charge.wait.min(MAX_SLEEP))
    }

    /// Waits out a delay returned by [`account`](Self::account).
    ///
    /// Kernel pacing starts with the first wait rather than with the session:
    /// pacing from the start would hold the burst to the sustained rate too.
    pub async fn throttle(&self, wait: Duration) {
        if !self.paced.load(Ordering::Relaxed) {
            self.set_pacing(true);
        }
        self.limits.throttled.fetch_add(1, Ordering::Relaxed);
        let _guard = ThrottledGuard(&self.limits.throttled);
        tokio::time::sleep(wait).await;
    }

    fn set_pacing(&self, on: bool) {
        let rate = on.then(|| u32::try_from(self.limits.media_rate).unwrap_or(u32::MAX));
        if let Err(err) = sockopt::set_max_pacing_rate(self.client, rate) {
            tracing::debug!(error = %err, "could not set the pacing rate");
        }
        self.paced.store(on, Ordering::Relaxed);
    }

    /// Whether `SO_MAX_PACING_RATE` is currently set on the client socket.
    pub fn is_paced(&self) -> bool {
        self.paced.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;
    const SEC: u64 = 1_000_000_000;
    /// 3 Mbit/s in bytes per second.
    const RATE: u64 = 375_000;
    const BURST: u64 = 10_000_000;

    #[test]
    fn lanes_follow_the_dc_index_sign() {
        for idx in [1, 2, 5, i16::MAX, 0] {
            assert_eq!(Lane::from_dc_idx(idx), Lane::Chat, "{idx}");
        }
        for idx in [-1, -2, -5, i16::MIN] {
            assert_eq!(Lane::from_dc_idx(idx), Lane::Media, "{idx}");
        }
    }

    #[test]
    fn burst_passes_without_any_wait() {
        let bucket = Bucket::new(BURST);
        let mut sent = 0;
        while sent + 16_384 <= BURST {
            let charge = bucket.charge(16_384, sent / 1000, Rate::new(RATE), BURST);
            assert_eq!(charge.wait, Duration::ZERO, "after {sent} bytes");
            sent += 16_384;
        }
        assert!(sent > BURST - 16_384);
    }

    #[test]
    fn debt_is_paid_at_the_sustained_rate() {
        let bucket = Bucket::new(BURST);
        bucket.charge(BURST, 0, Rate::new(RATE), BURST);
        // 375 000 bytes over the burst cost exactly one second at 3 Mbit/s.
        let charge = bucket.charge(RATE, 0, Rate::new(RATE), BURST);
        assert_eq!(charge.wait, Duration::from_secs(1));
        // After waiting it out, the next 16 KiB cost 16 384 / 375 000 s.
        let charge = bucket.charge(16_384, SEC, Rate::new(RATE), BURST);
        let expected = 16_384 * 1_000_000 / u128::from(RATE);
        assert!(
            charge.wait.as_micros().abs_diff(expected) < 10,
            "{:?}",
            charge.wait
        );
    }

    #[test]
    fn long_run_average_matches_the_rate() {
        let bucket = Bucket::new(BURST);
        let mut now = 0u64;
        let mut sent = 0u64;
        // A sender that always waits exactly as long as it is told.
        while now < 600 * SEC {
            let charge = bucket.charge(16_384, now, Rate::new(RATE), BURST);
            sent += 16_384;
            now += charge.wait.as_nanos() as u64 + 50_000;
        }
        let expected = BURST + RATE * 600;
        let error = (sent as f64 - expected as f64).abs() / expected as f64;
        assert!(error < 0.001, "sent {sent}, expected {expected}");
    }

    #[test]
    fn tiny_frequent_reads_do_not_lose_refill() {
        // 100 bytes every 100 µs asks for 1 MB/s against 375 kB/s. Each read
        // earns 37.5 bytes; dropping the half byte every time would under-fill.
        let bucket = Bucket::new(0);
        let mut now = 0u64;
        let mut waited = 0u128;
        for _ in 0..100_000 {
            let charge = bucket.charge(100, now, Rate::new(RATE), 0);
            waited = charge.wait.as_nanos();
            now += 100_000;
        }
        // 10 MB charged over 10 s, 3.75 MB earned: 6.25 MB of debt = 16.67 s.
        let debt_secs = waited as f64 / 1e9;
        assert!((debt_secs - 16.667).abs() < 0.01, "{debt_secs}");
    }

    #[test]
    fn idle_time_refills_up_to_the_burst_only() {
        let bucket = Bucket::new(BURST);
        bucket.charge(BURST, 0, Rate::new(RATE), BURST);
        // Ten seconds earn 3.75 MB: not full yet.
        let charge = bucket.charge(0, 10 * SEC, Rate::new(RATE), BURST);
        assert!(!charge.was_full);
        // Within the fixed-point rate's precision (under one part per million).
        assert!(bucket.tokens.load(Ordering::Relaxed).abs_diff(3_750_000) < 10);
        // A day later it is full, and no fuller than the burst.
        let charge = bucket.charge(0, 86_400 * SEC, Rate::new(RATE), BURST);
        assert!(charge.was_full);
        assert_eq!(bucket.tokens.load(Ordering::Relaxed), BURST as i64);
        let charge = bucket.charge(BURST + RATE, 86_400 * SEC, Rate::new(RATE), BURST);
        assert_eq!(charge.wait, Duration::from_secs(1));
    }

    #[test]
    fn rate_changes_apply_to_the_next_read() {
        let bucket = Bucket::new(0);
        assert_eq!(
            bucket.charge(RATE, 0, Rate::new(RATE), 0).wait,
            Duration::from_secs(1)
        );
        // Same debt, half the rate: twice the wait.
        assert_eq!(
            bucket.charge(0, 0, Rate::new(RATE / 2), 0).wait,
            Duration::from_secs(2)
        );
    }

    #[test]
    fn extreme_inputs_do_not_overflow() {
        let bucket = Bucket::new(u64::MAX);
        let charge = bucket.charge(u64::MAX, u64::MAX, Rate::new(u64::MAX), u64::MAX);
        assert!(charge.was_full);
        let bucket = Bucket::new(0);
        let charge = bucket.charge(u64::MAX, 0, Rate::new(0), 0);
        assert!(charge.wait > Duration::from_secs(1_000_000));
        bucket.charge(u64::MAX, 5 * MS, Rate::new(1), 0);
    }

    #[test]
    fn clock_is_not_read_while_plenty_of_burst_is_left() {
        let bucket = Bucket::new(BURST);
        let clock_reads = std::cell::Cell::new(0u32);
        let mut sent = 0u64;
        let mut charges = 0u32;
        // 4 MB of a 10 MB burst in 16 KiB reads.
        while sent < 4_000_000 {
            let charged = bucket.charge_when_due(
                16_384,
                || {
                    clock_reads.set(clock_reads.get() + 1);
                    sent / 1000
                },
                Rate::new(RATE),
                BURST,
            );
            assert!(charged.as_ref().is_none_or(|c| c.wait.is_zero()));
            charges += u32::from(charged.is_some());
            sent += 16_384;
        }
        assert_eq!(clock_reads.get(), 0, "clock read with 6 MB of burst left");
        assert_eq!(charges, 0);

        // The first charge happens at half the burst, and covers everything
        // sent until then.
        while clock_reads.get() == 0 {
            bucket.charge_when_due(
                16_384,
                || {
                    clock_reads.set(clock_reads.get() + 1);
                    0
                },
                Rate::new(RATE),
                BURST,
            );
            sent += 16_384;
        }
        assert!((5_000_000..5_020_000).contains(&sent), "{sent}");
        assert_eq!(
            bucket.tokens.load(Ordering::Relaxed),
            BURST as i64 - sent as i64
        );
        assert_eq!(bucket.pending.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_session_at_its_limit_is_charged_on_every_read() {
        let bucket = Bucket::new(BURST);
        // Spend the whole burst.
        let mut now = 0u64;
        let mut reads_until_empty = 0;
        while bucket.tokens.load(Ordering::Relaxed) > 0
            || bucket.pending.load(Ordering::Relaxed) > 0
        {
            bucket.charge_when_due(16_384, || now, Rate::new(RATE), BURST);
            reads_until_empty += 1;
            assert!(reads_until_empty < 10_000);
        }
        // From here on every read is charged and told how long to wait.
        for _ in 0..200 {
            let charge = bucket
                .charge_when_due(16_384, || now, Rate::new(RATE), BURST)
                .expect("a read at the limit was not charged");
            assert!(charge.wait > Duration::ZERO);
            now += charge.wait.as_nanos() as u64;
        }
    }

    #[test]
    fn deferred_charging_keeps_the_long_run_rate_and_never_overgrants() {
        // A sender that waits as told, with idle gaps, against an exact
        // bucket charged on every read with the same traffic.
        let lazy = Bucket::new(BURST);
        let exact = Bucket::new(BURST);
        let mut now = 0u64;
        let mut sent = 0u64;
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut idle_ns = 0u64;
        while now < 3600 * SEC {
            let bytes = 1 + next() % 16_384;
            let wait = lazy
                .charge_when_due(bytes, || now, Rate::new(RATE), BURST)
                .map_or(0, |c| c.wait.as_nanos() as u64);
            exact.charge(bytes, now, Rate::new(RATE), BURST);
            sent += bytes;
            // Whenever the lazy bucket is up to date it holds no more than
            // the exact one.
            if lazy.pending.load(Ordering::Relaxed) == 0 {
                assert!(
                    lazy.tokens.load(Ordering::Relaxed) <= exact.tokens.load(Ordering::Relaxed) + 1,
                    "over-granted at {now} ns"
                );
            }
            now += wait + 20_000;
            // Now and then the session goes quiet for up to a minute.
            if next() % 5000 == 0 {
                let gap = next() % (60 * SEC);
                idle_ns += gap;
                now += gap;
            }
        }
        // Never more than the burst plus what the rate allows over the hour.
        let allowed = BURST + RATE * 3600 + 16_384;
        assert!(sent <= allowed, "sent {sent}, allowed {allowed}");
        // And not much less: only refill lost to idle time above a full bucket.
        let floor = RATE * (3600 - idle_ns / SEC - 60);
        assert!(sent >= floor, "sent {sent}, floor {floor}");
    }

    #[test]
    fn scale_falls_in_proportion_and_recovers_gradually() {
        let threshold = 4.25e9;
        // 5 Gbit/s against a 4.25 Gbit/s threshold: cut to 85%.
        assert!((next_scale(1.0, 5.0e9, threshold) - 0.85).abs() < 1e-9);
        // Twice over: halve.
        assert!((next_scale(0.8, 8.5e9, threshold) - 0.4).abs() < 1e-9);
        // Never below the floor, never above one.
        assert_eq!(next_scale(0.06, 100e9, threshold), MIN_SCALE);
        assert_eq!(next_scale(1.0, 1.0e9, threshold), 1.0);
        // Recovery is 10% per tick.
        assert!((next_scale(0.5, 1.0e9, threshold) - 0.55).abs() < 1e-9);
        let mut scale = MIN_SCALE;
        let mut ticks = 0;
        while scale < 1.0 {
            scale = next_scale(scale, 0.0, threshold);
            ticks += 1;
        }
        assert_eq!(ticks, 32);
        // Exactly at the threshold counts as fine.
        assert!((next_scale(0.5, threshold, threshold) - 0.55).abs() < 1e-9);
        // No capacity configured: never scale down.
        assert_eq!(next_scale(1.0, 100e9, 0.0), 1.0);
    }

    #[test]
    fn tick_measures_egress_and_adjusts_the_scale() {
        // 1 Mbit/s link, threshold at 80%.
        let limits = Limits::new(3_000_000, 0, 1_000_000, 0.8);
        assert_eq!(limits.scale(), 1.0);

        limits.media_bytes.add(200_000);
        limits.chat_bytes.add(50_000);
        limits.tick(Duration::from_secs(1));
        // 250 kB in one second is 2 Mbit/s: 2.5 times the threshold.
        assert_eq!(limits.egress_bps(), 2_000_000);
        assert!((limits.scale() - 0.4).abs() < 0.001, "{}", limits.scale());
        // 375 kB/s scaled by 0.4, within fixed-point rounding.
        assert!(limits.effective_media_rate().abs_diff(150_000) < 10);

        // A quiet second: egress drops to zero and the scale starts back up.
        limits.tick(Duration::from_secs(1));
        assert_eq!(limits.egress_bps(), 0);
        assert!((limits.scale() - 0.44).abs() < 0.001, "{}", limits.scale());

        limits.tick(Duration::ZERO);
        assert!((limits.scale() - 0.44).abs() < 0.001);
        assert_eq!(limits.bytes(Lane::Media), 200_000);
        assert_eq!(limits.bytes(Lane::Chat), 50_000);
    }

    #[test]
    fn sharded_counter_sums_across_threads() {
        let counter = std::sync::Arc::new(ShardedCounter::default());
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let counter = counter.clone();
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        counter.add(3);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(counter.get(), 240_000);
    }

    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (near, far) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (near.unwrap(), far.unwrap().0)
    }

    #[tokio::test]
    async fn chat_sessions_are_counted_but_never_delayed() {
        let (client, _peer) = socket_pair().await;
        let limits = Limits::new(8, 0, 0, 0.0);
        let traffic = SessionTraffic::new(Lane::Chat, &limits, &client);
        for _ in 0..1000 {
            assert_eq!(traffic.account(Direction::Down, 16_384), None);
            assert_eq!(traffic.account(Direction::Up, 100), None);
        }
        assert_eq!(traffic.bytes_down.load(Ordering::Relaxed), 16_384_000);
        assert_eq!(traffic.bytes_up.load(Ordering::Relaxed), 100_000);
        assert_eq!(limits.bytes(Lane::Chat), 16_484_000);
        assert_eq!(limits.bytes(Lane::Media), 0);
        assert!(!traffic.is_paced());
    }

    #[tokio::test]
    async fn media_sessions_share_one_bucket_across_directions() {
        let (client, _peer) = socket_pair().await;
        // 8 Mbit/s = 1 MB/s, 1 MB burst.
        let limits = Limits::new(8_000_000, 1_000_000, 0, 0.0);
        let traffic = SessionTraffic::new(Lane::Media, &limits, &client);
        assert_eq!(traffic.account(Direction::Down, 600_000), None);
        assert_eq!(traffic.account(Direction::Up, 400_000), None);
        // The burst is spent by both directions together.
        let wait = traffic.account(Direction::Up, 500_000).unwrap();
        assert!(
            wait > Duration::from_millis(450) && wait <= Duration::from_millis(500),
            "{wait:?}"
        );
        assert_eq!(limits.bytes(Lane::Media), 1_500_000);
    }

    #[tokio::test]
    async fn media_is_unlimited_when_no_rate_is_configured() {
        let (client, _peer) = socket_pair().await;
        let limits = Limits::unlimited();
        let traffic = SessionTraffic::new(Lane::Media, &limits, &client);
        for _ in 0..1000 {
            assert_eq!(traffic.account(Direction::Down, 16_384), None);
        }
        assert_eq!(limits.bytes(Lane::Media), 16_384_000);
    }

    #[tokio::test]
    async fn waits_are_capped_and_short_debts_are_carried() {
        let (client, _peer) = socket_pair().await;
        let limits = Limits::new(8_000_000, 0, 0, 0.0);
        let traffic = SessionTraffic::new(Lane::Media, &limits, &client);
        // 500 bytes at 1 MB/s is half a millisecond: below the timer resolution.
        assert_eq!(traffic.account(Direction::Down, 500), None);
        // A huge read is told to wait the maximum, not minutes.
        assert_eq!(
            traffic.account(Direction::Down, 500_000_000),
            Some(MAX_SLEEP)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn throttled_sessions_are_counted_while_they_wait() {
        let (client, _peer) = socket_pair().await;
        let limits = Limits::new(8_000_000, 0, 0, 0.0);
        let traffic = SessionTraffic::new(Lane::Media, &limits, &client);
        assert_eq!(limits.throttled_now(), 0);
        {
            let wait = traffic.throttle(Duration::from_secs(1));
            tokio::pin!(wait);
            assert!(futures_poll_once(wait.as_mut()).await.is_none());
            assert_eq!(limits.throttled_now(), 1);
            assert!(traffic.is_paced());
            wait.await;
        }
        assert_eq!(limits.throttled_now(), 0);

        // A cancelled wait is uncounted too.
        {
            let wait = traffic.throttle(Duration::from_secs(1));
            tokio::pin!(wait);
            assert!(futures_poll_once(wait.as_mut()).await.is_none());
            assert_eq!(limits.throttled_now(), 1);
        }
        assert_eq!(limits.throttled_now(), 0);
    }

    /// Polls a future once without waiting for it.
    async fn futures_poll_once<F: std::future::Future + Unpin>(mut fut: F) -> Option<F::Output> {
        std::future::poll_fn(|cx| {
            std::task::Poll::Ready(match std::pin::Pin::new(&mut fut).poll(cx) {
                std::task::Poll::Ready(v) => Some(v),
                std::task::Poll::Pending => None,
            })
        })
        .await
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn pacing_starts_after_the_burst_and_stops_once_refilled() {
        use std::os::fd::AsRawFd;

        fn pacing_rate(socket: &TcpStream) -> u32 {
            let mut value: u32 = 0;
            let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
            // SAFETY: `value` and `len` are valid for writes and sized for a u32.
            let rc = unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MAX_PACING_RATE,
                    std::ptr::from_mut(&mut value).cast(),
                    &mut len,
                )
            };
            assert_eq!(rc, 0);
            value
        }

        let (client, _peer) = socket_pair().await;
        // 8 Mbit/s = 1 MB/s with a 100 kB burst.
        let limits = Limits::new(8_000_000, 100_000, 0, 0.0);
        let traffic = SessionTraffic::new(Lane::Media, &limits, &client);
        let unlimited = pacing_rate(&client);

        // Inside the burst: the socket is left alone.
        assert_eq!(traffic.account(Direction::Down, 90_000), None);
        assert_eq!(pacing_rate(&client), unlimited);

        // Past the burst: the first wait turns pacing on at the sustained rate.
        let wait = traffic.account(Direction::Down, 60_000).unwrap();
        traffic.throttle(wait).await;
        assert_eq!(pacing_rate(&client), 1_000_000);

        // Still paced while the bucket is in debt or only partly refilled.
        // (The paused test clock does not move the bucket's real clock, so
        // the debt is still there.)
        let _ = traffic.account(Direction::Down, 1);
        assert_eq!(pacing_rate(&client), 1_000_000);

        // Pacing is lifted by the first read after the bucket is full again.
        // The bucket runs on the real clock, so charge it directly as if a
        // long time had passed.
        let bucket = traffic.bucket.as_ref().unwrap();
        bucket.tokens.store(100_000, Ordering::Relaxed);
        assert_eq!(traffic.account(Direction::Down, 10), None);
        assert_eq!(pacing_rate(&client), u32::MAX);
        assert!(!traffic.is_paced());
    }
}
