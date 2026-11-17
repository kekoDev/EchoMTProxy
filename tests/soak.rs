//! Many concurrent sessions through one in-process proxy.
//!
//! Every session is established, held open while all the others are, used
//! again, and closed. `SOAK_CONNECTIONS` overrides the default of 10 000.
#![cfg(unix)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use echo_mtproxy::stats::{HandshakeResult, Stats};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

const DEFAULT_CONNECTIONS: usize = 10_000;
/// Descriptors per session in this process: client socket, the proxy's two
/// sockets and the fake DC's socket.
const FDS_PER_SESSION: u64 = 4;
const CONNECT_CONCURRENCY: usize = 256;
const DEADLINE: Duration = Duration::from_secs(300);

async fn wait_for(what: &str, deadline: Instant, mut done: impl FnMut() -> bool) {
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// An echo DC whose connections can all be closed from the DC side.
///
/// Whoever closes a TCP connection first keeps its port in TIME_WAIT. If the
/// clients closed first, the proxy would close its 10 000 DC connections
/// actively and their ephemeral ports would stay unusable for the next test
/// run on systems with a small port range.
async fn spawn_closable_dc(close: watch::Receiver<bool>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut close = close.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = echo_dc_session(stream, true) => {}
                    _ = close.wait_for(|now| *now) => {}
                }
            });
        }
    });
    addr
}

fn rejected(stats: &Stats, label: usize) -> u64 {
    HandshakeResult::ALL
        .into_iter()
        .filter(|r| *r != HandshakeResult::Accepted)
        .map(|r| stats.handshakes(label, r))
        .sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_sessions_soak() {
    let sessions: usize = std::env::var("SOAK_CONNECTIONS")
        .ok()
        .map(|v| v.parse().expect("SOAK_CONNECTIONS must be a number"))
        .unwrap_or(DEFAULT_CONNECTIONS);
    let needed = sessions as u64 * FDS_PER_SESSION + 512;
    let limit = raise_fd_limit(needed);
    assert!(
        limit >= needed,
        "{sessions} sessions need {needed} file descriptors but the limit is {limit}; \
         raise `ulimit -n` or set SOAK_CONNECTIONS lower"
    );

    let (close_dc, dc_closed) = watch::channel(false);
    let dc = spawn_closable_dc(dc_closed).await;
    let blackhole = spawn_blackhole().await;
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         mask_host = \"{blackhole}\"\n\
         metrics_listen = \"\"\n\
         [dc_override]\n\
         {DC} = \"{dc}\"\n"
    ))
    .await;
    let stats = handle.stats().clone();
    let label = stats.label_index(Some("www.example.com"));
    let other = stats.label_index(None);

    let started = Instant::now();
    let deadline = started + DEADLINE;
    let connecting = Arc::new(Semaphore::new(CONNECT_CONCURRENCY));
    let ready = Arc::new(AtomicUsize::new(0));
    let echoed_twice = Arc::new(AtomicUsize::new(0));
    let (release, released) = watch::channel(false);

    let mut tasks = JoinSet::new();
    for id in 0..sessions {
        let connecting = connecting.clone();
        let ready = ready.clone();
        let echoed_twice = echoed_twice.clone();
        let mut released = released.clone();
        tasks.spawn(async move {
            {
                let permit = connecting.acquire_owned().await.unwrap();
                let stream = connect_bulk(proxy).await;
                let mut client = Client::handshake(stream, DC, "www.example.com").await;
                let hello = format!("session {id} says hello");
                assert_eq!(client.echo(hello.as_bytes()).await, hello.as_bytes());
                drop(permit);

                // Stay open and silent until every other session is up.
                ready.fetch_add(1, Ordering::Relaxed);
                released.wait_for(|go| *go).await.unwrap();

                let mut again = random_bytes(1024);
                again[..8].copy_from_slice(&(id as u64).to_le_bytes());
                assert_eq!(client.echo(&again).await, again);
                echoed_twice.fetch_add(1, Ordering::Relaxed);

                // The DC hangs up first; the proxy must pass that on.
                let mut byte = [0u8; 1];
                let closed = tokio::time::timeout(DEADLINE, client.read.read(&mut byte)).await;
                assert!(
                    matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
                    "session {id} was not closed after the DC hung up"
                );
            }
        });
    }

    // No session finishes before the release, so one that does has failed.
    while ready.load(Ordering::Relaxed) < sessions {
        if let Some(early) = tasks.try_join_next() {
            early.expect("a session failed while connecting");
            panic!("a session ended before it was released");
        }
        assert!(Instant::now() < deadline, "timed out establishing sessions");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let established_in = started.elapsed();

    // Peak: every session is open at once and nothing was turned away.
    assert_eq!(stats.active_sessions(label), sessions as u64);
    assert_eq!(stats.connections_open(), sessions as u64);
    assert_eq!(
        stats.handshakes(label, HandshakeResult::Accepted),
        sessions as u64
    );
    assert_eq!(rejected(&stats, label) + rejected(&stats, other), 0);
    assert_eq!(stats.connections_over_limit(), 0);

    release.send(true).unwrap();
    // Sessions finish their second echo, then wait for the DC to hang up.
    wait_for("the second round of echoes", deadline, || {
        echoed_twice.load(Ordering::Relaxed) == sessions
    })
    .await;
    close_dc.send(true).unwrap();
    while let Some(finished) = tokio::time::timeout_at(deadline.into(), tasks.join_next())
        .await
        .expect("sessions did not finish")
    {
        finished.expect("a session failed");
    }

    // Nothing is left behind once the clients are gone.
    wait_for("the proxy to release every connection", deadline, || {
        stats.connections_open() == 0 && stats.active_sessions(label) == 0
    })
    .await;
    assert_eq!(
        stats.handshakes(label, HandshakeResult::Accepted),
        sessions as u64
    );
    println!(
        "soak: {sessions} concurrent sessions, established in {established_in:.1?}, total {:.1?}",
        started.elapsed()
    );
}
