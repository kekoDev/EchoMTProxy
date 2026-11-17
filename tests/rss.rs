//! Resident memory the proxy keeps per idle session.
//!
//! Linux only: the figures come from `/proc`. The proxy runs as the real
//! binary in a child process, so its VmRSS excludes this test's own clients
//! and fake DCs. Heavy, so it is ignored by default:
//!
//! ```sh
//! cargo test --release --test rss -- --ignored --nocapture
//! ```
//!
//! `RSS_SESSIONS` (default 50000) and `RSS_BASELINE_SESSIONS` (default 1000)
//! change the two measurement points.
#![cfg(unix)]

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::*;
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_BASELINE_SESSIONS: usize = 1_000;
const DEFAULT_SESSIONS: usize = 50_000;
/// Traffic each session carries before it goes idle: more than one full relay
/// buffer in each direction, so both buffers have been used.
const TRAFFIC_BEFORE_IDLE: usize = 24 * 1024;
const SAMPLES: usize = 3;
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const SETTLE: Duration = Duration::from_secs(2);
const CONNECT_BATCH: usize = 200;

/// One loopback address can only be the target of about 28 000 connections
/// from another (the ephemeral port range), so both legs are spread over
/// several: clients over the proxy's listeners, the proxy over five DCs.
const PROXY_ADDRS: [[u8; 4]; 4] = [
    [127, 0, 0, 1],
    [127, 0, 0, 2],
    [127, 0, 0, 3],
    [127, 0, 0, 4],
];
const DC_COUNT: usize = 5;

/// Ceiling for resident bytes per idle session at full scale.
///
/// Measured over 1 000 -> 50 000 sessions in fast mode: 4.1 KiB on the target
/// server with mimalloc, 4.6 KiB there with glibc malloc. That is two 1 KiB
/// cipher states, a 1.4 KiB task, two socket registrations and allocator
/// overhead; idle sessions hold no relay buffer.
const BUDGET_BYTES_PER_IDLE_SESSION: u64 = 5 * 1024;

/// Ceiling when fewer than `FULL_SCALE_SESSIONS` are measured.
///
/// mimalloc commits memory in large steps, so over a few thousand sessions the
/// same build reads anywhere from 5.1 to 6.1 KiB per session. A small run can
/// only catch gross regressions.
const SMALL_SCALE_BUDGET_BYTES: u64 = 8 * 1024;
const FULL_SCALE_SESSIONS: u64 = 20_000;

struct ProxyProcess(Child);

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn env_count(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .map(|v| {
            v.parse()
                .unwrap_or_else(|_| panic!("{name} must be a number"))
        })
        .unwrap_or(default)
}

/// A `Name: value kB` field of a `/proc/<pid>/status` file, in bytes.
fn status_bytes(pid: &str, field: &str) -> u64 {
    let path = format!("/proc/{pid}/status");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    parse_status_kb(&text, field).unwrap_or_else(|| panic!("no {field} in {path}")) * 1024
}

fn parse_status_kb(status: &str, field: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kb| kb.parse().ok())
}

/// Pages of kernel memory held by all TCP sockets in this network namespace
/// (the `mem` field of the `TCP:` line in `/proc/net/sockstat`).
fn parse_sockstat_tcp_mem_pages(sockstat: &str) -> Option<u64> {
    let line = sockstat.lines().find(|l| l.starts_with("TCP:"))?;
    let mut fields = line.split_whitespace();
    fields.find(|f| *f == "mem")?;
    fields.next()?.parse().ok()
}

fn tcp_mem_pages() -> u64 {
    let text = std::fs::read_to_string("/proc/net/sockstat").expect("reading /proc/net/sockstat");
    parse_sockstat_tcp_mem_pages(&text).expect("no TCP mem field in /proc/net/sockstat")
}

fn page_size() -> u64 {
    // SAFETY: sysconf has no preconditions and only reads system configuration.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(size).ok().filter(|s| *s > 0).unwrap_or(4096)
}

fn median(mut values: [u64; SAMPLES]) -> u64 {
    values.sort_unstable();
    values[SAMPLES / 2]
}

struct Sample {
    proxy_rss: u64,
    harness_rss: u64,
    tcp_mem_pages: u64,
}

/// Median of three readings, taken after the system has settled.
async fn sample(proxy_pid: &str) -> Sample {
    tokio::time::sleep(SETTLE).await;
    let mut proxy = [0; SAMPLES];
    let mut harness = [0; SAMPLES];
    let mut tcp = [0; SAMPLES];
    for i in 0..SAMPLES {
        if i > 0 {
            tokio::time::sleep(SAMPLE_INTERVAL).await;
        }
        proxy[i] = status_bytes(proxy_pid, "VmRSS");
        harness[i] = status_bytes("self", "VmRSS");
        tcp[i] = tcp_mem_pages();
    }
    Sample {
        proxy_rss: median(proxy),
        harness_rss: median(harness),
        tcp_mem_pages: median(tcp),
    }
}

async fn spawn_dc_on(ip: [u8; 4]) -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from((ip, 0))).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = echo_dc_session(stream, true).await;
            });
        }
    });
    addr
}

async fn start_proxy(sessions: usize) -> (ProxyProcess, Vec<SocketAddr>) {
    let mut dc_overrides = String::new();
    for dc in 1..=DC_COUNT {
        let addr = spawn_dc_on([127, 0, 0, dc as u8]).await;
        dc_overrides.push_str(&format!("{dc} = \"{addr}\"\n"));
    }
    let mask = spawn_blackhole().await;

    // Reserve a free port, then hand it to the child.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let listeners: Vec<SocketAddr> = PROXY_ADDRS
        .iter()
        .map(|ip| SocketAddr::from((*ip, port)))
        .collect();
    let listen = listeners
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let config: PathBuf = [
        env!("CARGO_TARGET_TMPDIR"),
        &format!("rss-{}.toml", std::process::id()),
    ]
    .iter()
    .collect();
    // Each handshake stores two replay entries; size the cache so it never
    // rotates early during the run.
    let replay_entries = (sessions * 4).max(4096);
    std::fs::write(
        &config,
        format!(
            "listen = [{listen}]\n\
             secrets = [\"{SECRET_HEX}\"]\n\
             mask_host = \"{mask}\"\n\
             metrics_listen = \"\"\n\
             replay_cache_entries = {replay_entries}\n\
             [dc_override]\n\
             {dc_overrides}"
        ),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_echo-mtproxy"))
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("starting the proxy binary");
    let proxy = ProxyProcess(child);

    for _ in 0..200 {
        if TcpStream::connect(listeners[0]).await.is_ok() {
            let _ = std::fs::remove_file(&config);
            return (proxy, listeners);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the proxy did not start listening on {}", listeners[0]);
}

/// Opens sessions `from..to` that carry some traffic and then sit idle.
async fn open_idle_sessions(
    listeners: &[SocketAddr],
    sessions: &mut Vec<Client>,
    from: usize,
    to: usize,
) {
    let mut next = from;
    while next < to {
        let end = (next + CONNECT_BATCH).min(to);
        let mut tasks = tokio::task::JoinSet::new();
        for id in next..end {
            let proxy = listeners[id % listeners.len()];
            let dc = (id % DC_COUNT) as i16 + 1;
            tasks.spawn(async move {
                let stream = TcpStream::connect(proxy).await.unwrap();
                let mut client = Client::handshake(stream, dc, "www.example.com").await;
                let data = random_bytes(TRAFFIC_BEFORE_IDLE);
                assert_eq!(client.echo(&data).await, data);
                client
            });
        }
        while let Some(client) = tasks.join_next().await {
            sessions.push(client.expect("session failed"));
        }
        next = end;
    }
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "heavy: opens 50 000 sessions; run with --ignored on Linux"]
async fn idle_session_memory_stays_within_budget() {
    if !cfg!(target_os = "linux") {
        eprintln!(
            "SKIPPED: the idle-session memory test reads /proc and only runs on Linux \
             (this is {}). No measurement was made.",
            std::env::consts::OS
        );
        return;
    }

    let baseline = env_count("RSS_BASELINE_SESSIONS", DEFAULT_BASELINE_SESSIONS);
    let total = env_count("RSS_SESSIONS", DEFAULT_SESSIONS);
    assert!(
        total > baseline,
        "RSS_SESSIONS must exceed RSS_BASELINE_SESSIONS"
    );
    let measured = (total - baseline) as u64;

    // Two descriptors per session in the proxy (inherited limit) and two here.
    let needed = total as u64 * 2 + 1024;
    let limit = raise_fd_limit(needed);
    assert!(
        limit >= needed,
        "{total} sessions need {needed} file descriptors per process but the limit is {limit}; \
         raise `ulimit -n` or set RSS_SESSIONS lower"
    );

    let (proxy, listeners) = start_proxy(total).await;
    let pid = proxy.0.id().to_string();
    let mut sessions = Vec::with_capacity(total);

    // Warm-up: one-time costs (runtime, allocator arenas) are paid before the
    // first measurement and cancel out of the difference.
    open_idle_sessions(&listeners, &mut sessions, 0, baseline).await;
    let low = sample(&pid).await;
    open_idle_sessions(&listeners, &mut sessions, baseline, total).await;
    let high = sample(&pid).await;

    // The sessions being measured must really be alive.
    for client in sessions.iter_mut().step_by((total / 20).max(1)) {
        assert_eq!(client.echo(b"still open").await, b"still open");
    }

    let per_session = high.proxy_rss.saturating_sub(low.proxy_rss) / measured;
    let budget = if measured >= FULL_SCALE_SESSIONS {
        BUDGET_BYTES_PER_IDLE_SESSION
    } else {
        SMALL_SCALE_BUDGET_BYTES
    };
    let harness_per_session = high.harness_rss.saturating_sub(low.harness_rss) / measured;
    let tcp_pages = high.tcp_mem_pages.saturating_sub(low.tcp_mem_pages);
    let tcp_bytes = tcp_pages * page_size();

    println!("idle-session memory ({baseline} -> {total} sessions, median of {SAMPLES} samples)");
    println!(
        "  proxy VmRSS:        {:9.1} MiB -> {:9.1} MiB   {per_session} bytes/session (budget {budget})",
        mib(low.proxy_rss),
        mib(high.proxy_rss)
    );
    println!(
        "  kernel TCP memory:  {:9} pg  -> {:9} pg    {} bytes/session ({:.1} MiB more; all 4 sockets of a session, whole host)",
        low.tcp_mem_pages,
        high.tcp_mem_pages,
        tcp_bytes / measured,
        mib(tcp_bytes)
    );
    println!(
        "  test harness VmRSS: {:9.1} MiB -> {:9.1} MiB   {harness_per_session} bytes/session (clients and fake DCs, not the proxy)",
        mib(low.harness_rss),
        mib(high.harness_rss)
    );

    // A difference that rounds to zero is under budget, not a failure.
    assert!(
        per_session <= budget,
        "{per_session} resident bytes per idle session exceeds the budget of {budget}"
    );
    drop(sessions);
}

#[test]
fn proc_parsers() {
    let status = "Name:\techo-mtproxy\nVmPeak:\t  999 kB\nVmRSS:\t   12345 kB\nRssAnon:\t 1 kB\n";
    assert_eq!(parse_status_kb(status, "VmRSS"), Some(12345));
    assert_eq!(parse_status_kb(status, "VmPeak"), Some(999));
    assert_eq!(parse_status_kb(status, "VmSwap"), None);
    assert_eq!(parse_status_kb("VmRSS:\tlots kB\n", "VmRSS"), None);

    let sockstat =
        "sockets: used 310\nTCP: inuse 12 orphan 0 tw 3 alloc 20 mem 417\nUDP: inuse 2 mem 9\n";
    assert_eq!(parse_sockstat_tcp_mem_pages(sockstat), Some(417));
    assert_eq!(parse_sockstat_tcp_mem_pages("UDP: inuse 2 mem 9\n"), None);
    assert_eq!(
        parse_sockstat_tcp_mem_pages("TCP: inuse 12 alloc 20\n"),
        None
    );

    assert_eq!(median([3, 1, 2]), 2);
    assert_eq!(median([7, 7, 100]), 7);
}
