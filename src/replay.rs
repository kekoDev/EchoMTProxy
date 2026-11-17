use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const KEY_LEN: usize = 32;

struct Generations {
    current: HashSet<[u8; KEY_LEN]>,
    previous: HashSet<[u8; KEY_LEN]>,
    rotated_at: Instant,
}

/// Bounded anti-replay cache with two generations.
///
/// Generations rotate every `window`, so an entry is remembered for at least
/// `window` and at most twice that. `window` must cover the whole period a
/// handshake stays valid (the clock-skew window).
///
/// Memory: a 32-byte key plus one control byte per hash-table slot, 38-75
/// bytes per live entry depending on table load, times two generations. The
/// tables grow on demand, so an idle proxy pays nothing.
///
/// If a generation reaches `capacity` before `window` has passed, it rotates
/// early. That drops the previous generation and shortens the guarantee, so it
/// is counted and logged; raise the capacity if it happens.
pub struct ReplayCache {
    generations: Mutex<Generations>,
    window: Duration,
    capacity: usize,
    early_rotations: AtomicU64,
}

impl ReplayCache {
    pub fn new(window: Duration, capacity: usize) -> Self {
        Self {
            generations: Mutex::new(Generations {
                current: HashSet::new(),
                previous: HashSet::new(),
                rotated_at: Instant::now(),
            }),
            window,
            capacity: capacity.max(1),
            early_rotations: AtomicU64::new(0),
        }
    }

    /// Records `key` and returns `true` if it was not seen within the window.
    pub fn check_and_insert(&self, key: &[u8; KEY_LEN]) -> bool {
        self.check_and_insert_at(key, Instant::now())
    }

    pub fn early_rotations(&self) -> u64 {
        self.early_rotations.load(Ordering::Relaxed)
    }

    fn check_and_insert_at(&self, key: &[u8; KEY_LEN], now: Instant) -> bool {
        let mut guard = self
            .generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let gens = &mut *guard;

        let age = now.saturating_duration_since(gens.rotated_at);
        if age >= self.window {
            // After two idle windows nothing in either generation is still needed.
            gens.previous = if age >= self.window * 2 {
                HashSet::new()
            } else {
                std::mem::take(&mut gens.current)
            };
            gens.current = HashSet::new();
            gens.rotated_at = now;
        }

        if gens.current.contains(key) || gens.previous.contains(key) {
            return false;
        }

        if gens.current.len() >= self.capacity {
            gens.previous = std::mem::take(&mut gens.current);
            gens.rotated_at = now;
            let total = self.early_rotations.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(
                total,
                capacity = self.capacity,
                "replay cache filled before the skew window elapsed; raise replay_cache_entries"
            );
        }
        gens.current.insert(*key);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(1800);

    fn key(n: u32) -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        k[..4].copy_from_slice(&n.to_le_bytes());
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
    fn stays_bounded_and_counts_early_rotations() {
        let capacity = 100;
        let cache = ReplayCache::new(WINDOW, capacity);
        for n in 0..1000 {
            assert!(cache.check_and_insert(&key(n)));
            let gens = cache.generations.lock().unwrap();
            assert!(gens.current.len() <= capacity);
            assert!(gens.previous.len() <= capacity);
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
    fn concurrent_inserts_admit_each_key_once() {
        let cache = std::sync::Arc::new(ReplayCache::new(WINDOW, 100_000));
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
}
