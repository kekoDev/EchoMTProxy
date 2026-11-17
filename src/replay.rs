use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const KEY_LEN: usize = 32;

type Key = [u8; KEY_LEN];

const EMPTY: Key = [0; KEY_LEN];
/// Stands in for the all-zero key, which marks an empty slot.
const ZERO_KEY_ALIAS: Key = [0xff; KEY_LEN];

const MAX_SHARDS: usize = 64;
/// Below this many entries per shard, fewer shards are used.
const MIN_SHARD_ENTRIES: usize = 4096;
/// Slots per entry of capacity: a table never fills beyond 3/4.
const SLOTS_NUM: usize = 4;
const SLOTS_DEN: usize = 3;
const EARLY_ROTATION_LOG_INTERVAL_SECS: u64 = 60;

/// Fixed-size open-addressing set. Never grows and never rehashes.
struct Table {
    slots: Box<[Key]>,
    len: usize,
}

impl Table {
    fn new(slot_count: usize) -> Self {
        Self {
            // Zeroed allocation: untouched pages cost nothing until used.
            slots: vec![EMPTY; slot_count].into_boxed_slice(),
            len: 0,
        }
    }

    fn start(&self, hash: u64) -> usize {
        // Multiply-shift maps the hash onto any table size without a division.
        ((u128::from(hash) * self.slots.len() as u128) >> 64) as usize
    }

    fn contains(&self, key: &Key, hash: u64) -> bool {
        if self.len == 0 {
            return false;
        }
        let mut index = self.start(hash);
        loop {
            let slot = &self.slots[index];
            if slot == key {
                return true;
            }
            if *slot == EMPTY {
                return false;
            }
            index = (index + 1) % self.slots.len();
        }
    }

    /// The caller keeps `len` below the slot count, so an empty slot exists.
    fn insert(&mut self, key: &Key, hash: u64) {
        let mut index = self.start(hash);
        while self.slots[index] != EMPTY {
            index = (index + 1) % self.slots.len();
        }
        self.slots[index] = *key;
        self.len += 1;
    }

    fn clear(&mut self) {
        if self.len > 0 {
            self.slots.fill(EMPTY);
            self.len = 0;
        }
    }
}

struct Shard {
    current: Table,
    previous: Table,
    rotated_at: Instant,
}

impl Shard {
    fn rotate(&mut self, now: Instant) {
        std::mem::swap(&mut self.current, &mut self.previous);
        self.current.clear();
        self.rotated_at = now;
    }
}

/// Sharded, fixed-size anti-replay cache with two generations per shard.
///
/// A shard's generations rotate every `window`, so an entry is remembered for
/// at least `window` and at most twice that. `window` must cover the whole
/// period a handshake stays valid (the clock-skew window).
///
/// Memory is fixed at construction: 32-byte slots, 4/3 slots per entry, two
/// generations, i.e. 85.3 bytes per entry of `capacity` (42.7 per generation).
/// The tables are allocated zeroed, so pages are only resident once touched.
///
/// If a shard's current generation fills up before `window` has passed, that
/// shard rotates early. This forgets its previous generation and shortens the
/// guarantee for the keys in it, so it is counted and logged; raise the
/// capacity if it happens.
///
/// Keys are placed with a per-process random hash, so someone holding a valid
/// secret cannot aim keys at one shard or one probe run.
pub struct ReplayCache {
    shards: Box<[Mutex<Shard>]>,
    hasher: RandomState,
    window: Duration,
    shard_capacity: usize,
    early_rotations: AtomicU64,
    last_warning_secs: AtomicU64,
    created: Instant,
}

impl ReplayCache {
    /// `capacity` is the number of entries one generation holds across all shards.
    pub fn new(window: Duration, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let shard_count = (capacity / MIN_SHARD_ENTRIES)
            .clamp(1, MAX_SHARDS)
            .next_power_of_two()
            .min(MAX_SHARDS);
        let shard_capacity = capacity.div_ceil(shard_count);
        let slot_count = shard_capacity * SLOTS_NUM / SLOTS_DEN + 1;
        let now = Instant::now();
        let shards = (0..shard_count)
            .map(|_| {
                Mutex::new(Shard {
                    current: Table::new(slot_count),
                    previous: Table::new(slot_count),
                    rotated_at: now,
                })
            })
            .collect();
        Self {
            shards,
            hasher: RandomState::new(),
            window,
            shard_capacity,
            early_rotations: AtomicU64::new(0),
            last_warning_secs: AtomicU64::new(u64::MAX),
            created: now,
        }
    }

    /// Records `key` and returns `true` if it was not seen within the window.
    pub fn check_and_insert(&self, key: &[u8; KEY_LEN]) -> bool {
        self.check_and_insert_at(key, Instant::now())
    }

    pub fn early_rotations(&self) -> u64 {
        self.early_rotations.load(Ordering::Relaxed)
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Bytes of table memory, fixed for the lifetime of the cache.
    pub fn memory_bytes(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                let shard = shard.lock().unwrap_or_else(|e| e.into_inner());
                (shard.current.slots.len() + shard.previous.slots.len()) * KEY_LEN
            })
            .sum()
    }

    fn check_and_insert_at(&self, key: &[u8; KEY_LEN], now: Instant) -> bool {
        let key = if *key == EMPTY { &ZERO_KEY_ALIAS } else { key };
        let hash = self.hasher.hash_one(key);
        // High bits pick the shard; the multiply-shift in `Table::start` is
        // dominated by them too, so mix before reusing the hash for the slot.
        let shard_index = (hash >> 58) as usize & (self.shards.len() - 1);
        let slot_hash = hash.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29);

        let mut guard = self.shards[shard_index]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let shard = &mut *guard;

        let age = now.saturating_duration_since(shard.rotated_at);
        if age >= self.window {
            shard.rotate(now);
            if age >= self.window * 2 {
                // Nothing in the generation just moved to `previous` is still needed.
                shard.previous.clear();
            }
        }

        if shard.current.contains(key, slot_hash) || shard.previous.contains(key, slot_hash) {
            return false;
        }

        let early = shard.current.len >= self.shard_capacity;
        if early {
            shard.rotate(now);
        }
        shard.current.insert(key, slot_hash);
        drop(guard);
        if early {
            self.note_early_rotation(now);
        }
        true
    }

    fn note_early_rotation(&self, now: Instant) {
        let total = self.early_rotations.fetch_add(1, Ordering::Relaxed) + 1;
        let secs = now.saturating_duration_since(self.created).as_secs();
        let last = self.last_warning_secs.load(Ordering::Relaxed);
        let due = last == u64::MAX || secs >= last.saturating_add(EARLY_ROTATION_LOG_INTERVAL_SECS);
        if due
            && self
                .last_warning_secs
                .compare_exchange(last, secs, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                total,
                "replay cache shard filled before the skew window elapsed; raise replay_cache_entries"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    const WINDOW: Duration = Duration::from_secs(1800);

    fn key(n: u32) -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        k[..4].copy_from_slice(&n.to_le_bytes());
        k[8] = 1;
        k
    }

    #[test]
    fn detects_replays() {
        let cache = ReplayCache::new(WINDOW, 16);
        assert!(cache.check_and_insert(&key(1)));
        assert!(cache.check_and_insert(&key(2)));
        assert!(!cache.check_and_insert(&key(1)));
        assert!(!cache.check_and_insert(&key(2)));
        assert_eq!(cache.early_rotations(), 0);
    }

    #[test]
    fn all_zero_key_is_a_normal_key() {
        let cache = ReplayCache::new(WINDOW, 16);
        assert!(cache.check_and_insert(&[0; KEY_LEN]));
        assert!(!cache.check_and_insert(&[0; KEY_LEN]));
        assert!(cache.check_and_insert(&key(1)));
    }

    #[test]
    fn entries_live_for_at_least_the_window() {
        let cache = ReplayCache::new(WINDOW, 1024);
        let start = Instant::now();
        // Inserted right before a rotation: the worst case for retention.
        let inserted = start + WINDOW - Duration::from_secs(1);
        assert!(cache.check_and_insert_at(&key(1), inserted));

        let mut filler = 100;
        let mut t = inserted;
        while t < inserted + WINDOW {
            assert!(
                !cache.check_and_insert_at(&key(1), t),
                "forgotten too early"
            );
            assert!(cache.check_and_insert_at(&key(filler), t));
            filler += 1;
            t += Duration::from_secs(30);
        }
        assert!(!cache.check_and_insert_at(&key(1), inserted + WINDOW));
    }

    #[test]
    fn entries_expire_after_two_windows() {
        let cache = ReplayCache::new(WINDOW, 1024);
        let start = Instant::now();
        assert!(cache.check_and_insert_at(&key(1), start));
        assert!(cache.check_and_insert_at(&key(2), start + WINDOW));
        assert!(cache.check_and_insert_at(&key(1), start + WINDOW * 2));
    }

    #[test]
    fn long_idle_period_clears_both_generations() {
        let cache = ReplayCache::new(WINDOW, 1024);
        let start = Instant::now();
        assert!(cache.check_and_insert_at(&key(1), start));
        assert!(cache.check_and_insert_at(&key(1), start + WINDOW * 5));
        assert!(!cache.check_and_insert_at(&key(1), start + WINDOW * 5));
    }

    #[test]
    fn single_shard_stays_bounded_and_counts_early_rotations() {
        let capacity = 100;
        let cache = ReplayCache::new(WINDOW, capacity);
        assert_eq!(cache.shard_count(), 1);
        for n in 0..1000 {
            assert!(cache.check_and_insert(&key(n)));
            let shard = cache.shards[0].lock().unwrap();
            assert!(shard.current.len <= capacity);
            assert!(shard.previous.len <= capacity);
        }
        assert_eq!(cache.early_rotations(), 9);
        // The most recent `capacity` keys are always still known.
        for n in 900..1000 {
            assert!(!cache.check_and_insert(&key(n)));
        }
    }

    #[test]
    fn zero_capacity_is_treated_as_one() {
        let cache = ReplayCache::new(WINDOW, 0);
        assert!(cache.check_and_insert(&key(1)));
        assert!(!cache.check_and_insert(&key(1)));
    }

    #[test]
    fn shard_count_scales_with_capacity() {
        for (capacity, shards) in [
            (1, 1),
            (4095, 1),
            (8192, 2),
            (20_000, 4),
            (262_144, 64),
            (2_000_000, 64),
            (50_000_000, 64),
        ] {
            assert_eq!(
                ReplayCache::new(WINDOW, capacity).shard_count(),
                shards,
                "capacity {capacity}"
            );
        }
    }

    #[test]
    fn memory_is_fixed_and_matches_the_documented_cost() {
        let capacity = 2_000_000;
        let cache = ReplayCache::new(WINDOW, capacity);
        let bytes = cache.memory_bytes();
        // 32-byte slots * 4/3 * two generations = 85.33 bytes per entry.
        let per_entry = bytes as f64 / capacity as f64;
        assert!((85.3..85.4).contains(&per_entry), "{per_entry}");
        assert!(bytes < 171 * 1024 * 1024);

        for n in 0..50_000 {
            cache.check_and_insert(&key(n));
        }
        assert_eq!(cache.memory_bytes(), bytes);
    }

    #[test]
    fn full_capacity_fits_without_early_rotation_when_keys_spread_evenly() {
        // 64 shards; random keys spread with some imbalance, so fill to 90%.
        let capacity = 400_000;
        let cache = ReplayCache::new(WINDOW, capacity);
        assert_eq!(cache.shard_count(), 64);
        let fill = capacity as u32 * 9 / 10;
        for n in 0..fill {
            assert!(cache.check_and_insert(&key(n)));
        }
        assert_eq!(cache.early_rotations(), 0);
        for n in (0..fill).step_by(97) {
            assert!(!cache.check_and_insert(&key(n)));
        }
    }

    #[test]
    fn concurrent_inserts_admit_each_key_once() {
        let cache = Arc::new(ReplayCache::new(WINDOW, 100_000));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let cache = cache.clone();
                std::thread::spawn(move || {
                    (0..2000)
                        .filter(|n| cache.check_and_insert(&key(*n)))
                        .count()
                })
            })
            .collect();
        let admitted: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(admitted, 2000);
    }

    /// Time-driven rollover while eight threads insert: every key is admitted
    /// exactly once, replays inside the window are always caught across the
    /// rollover, and the tables never exceed their fixed size.
    #[test]
    fn generation_rollover_under_load() {
        const THREADS: u32 = 8;
        const STEPS: u32 = 240;
        const PER_STEP: u32 = 250;
        let step = WINDOW / 40;
        let cache = Arc::new(ReplayCache::new(WINDOW, 200_000));
        assert!(cache.shard_count() > 1);
        let memory = cache.memory_bytes();
        let start = Instant::now();
        let failed = Arc::new(AtomicBool::new(false));
        // All threads share one simulated clock: nobody starts step s + 1
        // before everyone has finished step s.
        let clock = Arc::new(std::sync::Barrier::new(THREADS as usize));

        let handles: Vec<_> = (0..THREADS)
            .map(|thread| {
                let cache = cache.clone();
                let failed = failed.clone();
                let clock = clock.clone();
                std::thread::spawn(move || {
                    for s in 0..STEPS {
                        // Six windows of simulated time in total.
                        let now = start + step * s;
                        for i in 0..PER_STEP {
                            let n = (thread << 24) | (s * PER_STEP + i);
                            let fresh = cache.check_and_insert_at(&key(n), now);
                            let replay_now = cache.check_and_insert_at(&key(n), now);
                            // Replay of a key from just under one window ago.
                            let replay_old = s < 39
                                || !cache.check_and_insert_at(
                                    &key((thread << 24) | ((s - 39) * PER_STEP + i)),
                                    now,
                                );
                            if !fresh || replay_now || !replay_old {
                                failed.store(true, Ordering::Relaxed);
                            }
                        }
                        clock.wait();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        assert!(!failed.load(Ordering::Relaxed));
        // 2000 keys per step * 40 steps = 80k per window, under the 200k capacity.
        assert_eq!(cache.early_rotations(), 0);
        assert_eq!(cache.memory_bytes(), memory);
        for shard in cache.shards.iter() {
            let shard = shard.lock().unwrap();
            assert!(shard.current.len <= cache.shard_capacity);
            assert!(shard.previous.len <= cache.shard_capacity);
        }
        // Keys from the first window were dropped by the rollovers: after two
        // more windows they are admitted again.
        let end = start + step * STEPS;
        assert!(cache.check_and_insert_at(&key(5), end));
    }

    /// Capacity-driven rollover with eight threads and far more keys than fit.
    /// The cache stays bounded, counts the early rotations and never rejects a
    /// key it has not seen.
    ///
    /// A replay sent right after the original is not asserted here: with the
    /// cache this overloaded, other threads can push a key out of both
    /// generations while its thread is descheduled. That recency bound is
    /// checked deterministically in `early_rollover_keeps_the_most_recent_keys`.
    #[test]
    fn early_rollover_under_load() {
        const THREADS: u32 = 8;
        const KEYS: u32 = 60_000;
        let cache = Arc::new(ReplayCache::new(WINDOW, 16_384));
        assert_eq!(cache.shard_count(), 4);
        let memory = cache.memory_bytes();

        let handles: Vec<_> = (0..THREADS)
            .map(|thread| {
                let cache = cache.clone();
                std::thread::spawn(move || {
                    let mut fresh_rejected = 0u32;
                    let mut replays_caught = 0u32;
                    for i in 0..KEYS {
                        let k = key((thread << 24) | i);
                        if !cache.check_and_insert(&k) {
                            fresh_rejected += 1;
                        }
                        if !cache.check_and_insert(&k) {
                            replays_caught += 1;
                        }
                    }
                    (fresh_rejected, replays_caught)
                })
            })
            .collect();
        let (fresh_rejected, replays_caught) = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));

        assert_eq!(fresh_rejected, 0);
        // Missing an immediate replay takes two rotations of a shard between
        // two consecutive calls of one thread, so it is rare even here.
        assert!(
            replays_caught >= THREADS * KEYS * 99 / 100,
            "{replays_caught}"
        );
        assert!(cache.early_rotations() >= u64::from(THREADS * KEYS / 16_384) - 4);
        assert_eq!(cache.memory_bytes(), memory);
        for shard in cache.shards.iter() {
            let shard = shard.lock().unwrap();
            assert!(shard.current.len <= cache.shard_capacity);
            assert!(shard.previous.len <= cache.shard_capacity);
        }
    }

    /// When shards rotate early, each still remembers at least its last
    /// `shard_capacity` keys, so the most recent keys overall are always known.
    #[test]
    fn early_rollover_keeps_the_most_recent_keys() {
        const KEYS: u32 = 200_000;
        let cache = ReplayCache::new(WINDOW, 16_384);
        let per_shard = cache.shard_capacity as u32;
        for n in 0..KEYS {
            assert!(cache.check_and_insert(&key(n)));
            assert!(!cache.check_and_insert(&key(n)), "immediate replay of {n}");
        }
        assert!(cache.early_rotations() > 20);
        // The last `per_shard` keys overall are within the last `per_shard`
        // keys of whichever shard they landed in.
        for n in KEYS - per_shard..KEYS {
            assert!(!cache.check_and_insert(&key(n)), "forgot recent key {n}");
        }
        // Keys from the start are long gone.
        let forgotten = (0..1000)
            .filter(|n| cache.check_and_insert(&key(*n)))
            .count();
        assert_eq!(forgotten, 1000);
    }
}
