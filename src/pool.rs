//! Pool of relay buffers.
//!
//! A session borrows a buffer only between a socket becoming readable and the
//! matching write completing, so idle sessions hold none. Free buffers are kept
//! per thread: taking and returning one touches no lock and no shared cache
//! line.

use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::tls::{MAX_RECORD_PAYLOAD, RECORD_HEADER_LEN};

/// Room for one full TLS record: header plus 16 KiB of payload.
pub const BUF_LEN: usize = RECORD_HEADER_LEN + MAX_RECORD_PAYLOAD;
/// Free buffers a thread keeps (about 0.5 MiB); more are returned to the allocator.
const MAX_FREE_PER_THREAD: usize = 32;

struct Local {
    free: RefCell<Vec<Box<[u8]>>>,
    /// Buffers taken minus buffers returned on this thread. Negative when
    /// buffers taken elsewhere were returned here; only the sum is meaningful.
    balance: Arc<AtomicIsize>,
}

static BALANCES: Mutex<Vec<Arc<AtomicIsize>>> = Mutex::new(Vec::new());
/// Returns made while a thread's local state was already torn down.
static ORPHAN_RETURNS: AtomicIsize = AtomicIsize::new(0);

thread_local! {
    static LOCAL: Local = {
        let balance = Arc::new(AtomicIsize::new(0));
        BALANCES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(balance.clone());
        Local {
            free: RefCell::new(Vec::new()),
            balance,
        }
    };
}

pub struct PooledBuf(Option<Box<[u8]>>);

/// Borrows a `BUF_LEN` buffer. Its contents are unspecified.
pub fn take() -> PooledBuf {
    let buf = LOCAL.with(|local| {
        local.balance.fetch_add(1, Ordering::Relaxed);
        local.free.borrow_mut().pop()
    });
    PooledBuf(Some(
        buf.unwrap_or_else(|| vec![0u8; BUF_LEN].into_boxed_slice()),
    ))
}

/// Buffers currently borrowed, across all threads.
pub fn in_use() -> usize {
    let taken: isize = BALANCES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|b| b.load(Ordering::Relaxed))
        .sum();
    usize::try_from(taken - ORPHAN_RETURNS.load(Ordering::Relaxed)).unwrap_or(0)
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        let Some(buf) = self.0.take() else { return };
        let returned = LOCAL.try_with(|local| {
            local.balance.fetch_sub(1, Ordering::Relaxed);
            let mut free = local.free.borrow_mut();
            if free.len() < MAX_FREE_PER_THREAD {
                free.push(buf);
            }
        });
        if returned.is_err() {
            ORPHAN_RETURNS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Deref for PooledBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_deref().unwrap_or(&[])
    }
}

impl DerefMut for PooledBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.as_deref_mut().unwrap_or(&mut [])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `in_use` is process-wide and other tests borrow buffers concurrently,
    // so these tests check per-thread state and relative changes on threads
    // of their own.

    fn on_fresh_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::spawn(f).join().unwrap()
    }

    fn free_count() -> usize {
        LOCAL.with(|local| local.free.borrow().len())
    }

    fn balance() -> isize {
        LOCAL.with(|local| local.balance.load(Ordering::Relaxed))
    }

    #[test]
    fn buffers_have_room_for_a_full_record() {
        let mut buf = take();
        assert_eq!(buf.len(), 5 + 16384);
        buf[BUF_LEN - 1] = 7;
        assert_eq!(buf[BUF_LEN - 1], 7);
    }

    #[test]
    fn returned_buffers_are_reused() {
        on_fresh_thread(|| {
            let first = take();
            let address = first.as_ptr();
            assert_eq!((free_count(), balance()), (0, 1));
            drop(first);
            assert_eq!((free_count(), balance()), (1, 0));
            let second = take();
            assert_eq!(second.as_ptr(), address);
            assert_eq!((free_count(), balance()), (0, 1));
        });
    }

    #[test]
    fn free_list_is_bounded() {
        on_fresh_thread(|| {
            let burst: Vec<_> = (0..MAX_FREE_PER_THREAD + 50).map(|_| take()).collect();
            assert_eq!(balance() as usize, MAX_FREE_PER_THREAD + 50);
            drop(burst);
            assert_eq!(free_count(), MAX_FREE_PER_THREAD);
            assert_eq!(balance(), 0);
        });
    }

    #[test]
    fn buffers_may_be_returned_on_another_thread() {
        let (taken_on, buf) = on_fresh_thread(|| {
            let buf = take();
            (balance(), buf)
        });
        assert_eq!(taken_on, 1);
        on_fresh_thread(move || {
            drop(buf);
            assert_eq!(balance(), -1);
            assert_eq!(free_count(), 1);
        });
    }

    #[test]
    fn in_use_tracks_borrowed_buffers() {
        // Other tests may hold buffers, but never thousands at once.
        let before = in_use();
        let held: Vec<_> = (0..5000).map(|_| take()).collect();
        let during = in_use();
        assert!(during >= 5000, "{during}");
        drop(held);
        let after = in_use();
        assert!(after < before + 2500, "before {before}, after {after}");
    }
}
