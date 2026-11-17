//! Connection storm against the real binary: how many new connections per
//! second the proxy takes off its listeners, and how many full handshakes per
//! second it completes.
//!
//! The clients and fake DCs run in this process on the same machine and take
//! CPU of their own, so use the figures to compare builds and settings with
//! each other, not as the proxy's absolute capacity.
//!
//! ```sh
//! cargo test --release --test storm -- --ignored --nocapture
//! ```
//!
//! Environment: `STORM_SECS` per round (5), `STORM_ROUNDS` (3),
//! `STORM_CLIENTS` concurrent client tasks (64), `STORM_PROXY_WORKERS` (4),
//! `STORM_HARNESS_THREADS` threads for the clients and fake DCs (4),
//! `STORM_EXTRA_CONFIG` extra config lines, e.g. `upstream_mode = "obfuscated"`.
#![cfg(unix)]

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Loopback addresses the proxy listens on and the DCs live on. One address
/// pair only has about 28 000 ephemeral ports, which a storm exhausts.
const PROXY_ADDRS: [[u8; 4]; 4] = [
    [127, 0, 0, 1],
    [127, 0, 0, 2],
    [127, 0, 0, 3],
    [127, 0, 0, 4],
];
const DC_COUNT: usize = 5;

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .map(|v| v.parse().unwrap_or_else(|_| panic!("bad {name}")))
        .unwrap_or(default)
}

/// Closes with a reset so the local port is reusable at once instead of
/// sitting in TIME_WAIT.
fn close_now(stream: &TcpStream) {
    let _ = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

async fn metric(addr: SocketAddr, name: &str) -> u64 {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).await.unwrap();
    text.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("metric {name} not found"))
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.total_cmp(b));
    values[values.len() / 2]
}

/// Runs `clients` copies of `work` in a loop for `secs` and returns how many
/// iterations finished.
async fn hammer<F, Fut>(clients: usize, secs: u64, work: F) -> u64
where
    F: Fn(usize, u64) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = bool> + Send,
{
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicU64::new(0));
    let tasks: Vec<_> = (0..clients)
        .map(|client| {
            let (stop, done, work) = (stop.clone(), done.clone(), work.clone());
            tokio::spawn(async move {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    if work(client, n).await {
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                    n += 1;
                }
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_secs(secs)).await;
    stop.store(true, Ordering::Relaxed);
    let finished = done.load(Ordering::Relaxed);
    for task in tasks {
        let _ = task.await;
    }
    finished
}

#[test]
#[ignore = "benchmark: run explicitly with --ignored --nocapture"]
fn connection_storm() {
    if !cfg!(target_os = "linux") {
        eprintln!(
            "SKIPPED: the connection storm relies on Linux loopback addressing (this is {}).",
            std::env::consts::OS
        );
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(env_or("STORM_HARNESS_THREADS", 4))
        .enable_all()
        .build()
        .unwrap()
        .block_on(storm());
}

async fn storm() {
    let secs: u64 = env_or("STORM_SECS", 5);
    let rounds: usize = env_or("STORM_ROUNDS", 3);
    let clients: usize = env_or("STORM_CLIENTS", 64);
    let workers: usize = env_or("STORM_PROXY_WORKERS", 4);
    let extra = std::env::var("STORM_EXTRA_CONFIG").unwrap_or_default();
    raise_fd_limit(200_000);

    let mut dc_overrides = String::new();
    for dc in 1..=DC_COUNT {
        let addr = spawn_echo_dc_on([127, 0, 0, dc as u8]).await;
        dc_overrides.push_str(&format!("{dc} = \"{addr}\"\n"));
    }
    let mask = spawn_blackhole().await;
    let port = free_port();
    let listeners: Vec<SocketAddr> = PROXY_ADDRS
        .iter()
        .map(|ip| SocketAddr::from((*ip, port)))
        .collect();
    let listen = listeners
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let metrics = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let _proxy = start_proxy_process(
        "storm",
        &format!(
            "listen = [{listen}]\n\
             workers = {workers}\n\
             secrets = [\"{SECRET_HEX}\"]\n\
             mask_host = \"{mask}\"\n\
             metrics_listen = \"{metrics}\"\n\
             replay_cache_entries = 4000000\n\
             {extra}\n\
             [dc_override]\n\
             {dc_overrides}"
        ),
        listeners[0],
    )
    .await;
    let listeners = Arc::new(listeners);

    // Accept storm: connect and reset at once. The proxy's own counter of
    // accepted connections is the measure, not the clients' connect calls.
    let mut accept_rates = Vec::new();
    for _ in 0..rounds {
        let before = metric(metrics, "echo_mtproxy_connections_accepted_total").await;
        let started = Instant::now();
        let targets = listeners.clone();
        hammer(clients, secs, move |client, n| {
            let addr = targets[(client + n as usize) % targets.len()];
            async move {
                match TcpStream::connect(addr).await {
                    Ok(stream) => {
                        close_now(&stream);
                        true
                    }
                    Err(_) => false,
                }
            }
        })
        .await;
        let elapsed = started.elapsed().as_secs_f64();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let after = metric(metrics, "echo_mtproxy_connections_accepted_total").await;
        // The two metric fetches are connections themselves.
        accept_rates.push((after - before).saturating_sub(1) as f64 / elapsed);
    }

    // Handshake storm: full fake-tls and obfuscated2 handshake, one small
    // echo through the DC, close.
    let mut handshake_rates = Vec::new();
    for _ in 0..rounds {
        let started = Instant::now();
        let targets = listeners.clone();
        let completed = hammer(clients, secs, move |client, n| {
            let addr = targets[(client + n as usize) % targets.len()];
            let dc = ((client as u64 + n) % DC_COUNT as u64) as i16 + 1;
            async move {
                let Ok(stream) = TcpStream::connect(addr).await else {
                    return false;
                };
                let mut session = Client::handshake(stream, dc, "www.example.com").await;
                let ok = session.echo(b"storm").await == b"storm";
                close_now(session.read.as_ref());
                ok
            }
        })
        .await;
        handshake_rates.push(completed as f64 / started.elapsed().as_secs_f64());
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let show = |rates: &[f64]| {
        rates
            .iter()
            .map(|r| format!("{r:.0}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "storm ({clients} clients on {} harness threads, {workers} proxy workers, {secs} s x {rounds} rounds, extra config: {:?})",
        env_or("STORM_HARNESS_THREADS", 4usize),
        extra
    );
    println!(
        "  accepted connections/s: median {:.0}  [{}]",
        median(accept_rates.clone()),
        show(&accept_rates)
    );
    println!(
        "  full handshakes/s:      median {:.0}  [{}]",
        median(handshake_rates.clone()),
        show(&handshake_rates)
    );
}
