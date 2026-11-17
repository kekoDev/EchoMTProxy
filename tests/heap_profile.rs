//! Heap profile of idle sessions: which allocation sites still hold memory
//! once sessions have carried traffic and gone quiet.
//!
//! Proxy, clients and fake DC share this process; allocations are attributed
//! by their backtrace, and only the proxy's are reported. Needs symbols:
//!
//! ```sh
//! CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=1 \
//!     cargo test --release --test heap_profile -- --ignored --nocapture
//! ```
//!
//! `HEAP_SESSIONS` (default 10000) sets the number of sessions. dhat allows one
//! profiler per process, so run one test at a time by name, for example
//! `-- --ignored --nocapture masked_connection_heap_profile`.
#![cfg(unix)]

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use common::*;
use serde_json::Value;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const DEFAULT_SESSIONS: usize = 10_000;
const TRAFFIC_BEFORE_IDLE: usize = 24 * 1024;
const BATCH: usize = 200;

/// Modules whose presence in a backtrace marks an allocation as the proxy's.
const PROXY_MODULES: [&str; 6] = [
    "echo_mtproxy::server::",
    "echo_mtproxy::relay::",
    "echo_mtproxy::dc::",
    "echo_mtproxy::mask::",
    "echo_mtproxy::replay::",
    "echo_mtproxy::pool::",
];
const HARNESS_MARKERS: [&str; 2] = ["heap_profile::", "::common::"];

/// `0x1234: path::to::function (file.rs:1:2)` -> `path::to::function`.
fn function_name(frame: &str) -> &str {
    let name = frame.split_once(": ").map_or(frame, |(_, rest)| rest);
    name.split(" (").next().unwrap_or(name)
}

fn short(name: &str) -> String {
    // Drop the `::h0123456789abcdef` hash and closure noise.
    let name = name.rsplit_once("::h").map_or(name, |(head, tail)| {
        if tail.len() == 16 && tail.bytes().all(|b| b.is_ascii_hexdigit()) {
            head
        } else {
            name
        }
    });
    name.replace("::{{closure}}", "")
        .replace("echo_mtproxy::", "")
}

/// Label for an allocation site: the innermost proxy function, plus the
/// innermost non-allocator function it went through (what was allocated).
fn classify(frames: &[&str]) -> Option<String> {
    let names: Vec<&str> = frames.iter().map(|f| function_name(f)).collect();
    if names
        .iter()
        .any(|n| HARNESS_MARKERS.iter().any(|m| n.contains(m)))
    {
        return None;
    }
    let proxy = names
        .iter()
        .find(|n| PROXY_MODULES.iter().any(|m| n.contains(m)))?;
    let via = names
        .iter()
        .find(|n| {
            !n.contains("alloc::")
                && !n.contains("dhat::")
                && !n.contains("__rust")
                && !n.contains("__rg_")
                && !n.contains("core::ops::function")
                && !n.contains("hashbrown::raw")
        })
        .copied()
        .unwrap_or(proxy);
    let proxy = short(proxy);
    let via = short(via);
    Some(if via == proxy {
        proxy
    } else {
        format!("{proxy}  <-  {via}")
    })
}

fn report(what: &str, profile: &Value, sessions: usize) {
    let frames: Vec<&str> = profile["ftbl"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    let mut sites: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut harness = 0u64;
    for point in profile["pps"].as_array().unwrap() {
        let bytes = point["eb"].as_u64().unwrap_or(0);
        if bytes == 0 {
            continue;
        }
        let stack: Vec<&str> = point["fs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| frames[i.as_u64().unwrap() as usize])
            .collect();
        match classify(&stack) {
            Some(label) => {
                let entry = sites.entry(label).or_default();
                entry.0 += bytes;
                entry.1 += point["ebk"].as_u64().unwrap_or(0);
            }
            None => harness += bytes,
        }
    }

    let mut rows: Vec<_> = sites.into_iter().collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.1 .0));
    let total: u64 = rows.iter().map(|r| r.1 .0).sum();
    println!("live proxy heap with {sessions} {what}");
    println!("{:>12} {:>10} {:>10}  site", "bytes", "blocks", "B/session");
    for (label, (bytes, blocks)) in &rows {
        if bytes / sessions as u64 == 0 && *bytes < 64 * 1024 {
            continue;
        }
        println!(
            "{bytes:>12} {blocks:>10} {:>10}  {label}",
            bytes / sessions as u64
        );
    }
    println!(
        "{total:>12} {:>10} {:>10}  total proxy (requested bytes; allocator overhead not included)",
        "",
        total / sessions as u64
    );
    println!(
        "{harness:>12} {:>10} {:>10}  test harness (clients, fake DC), not counted",
        "", ""
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "heavy: profiles 10 000 sessions under dhat"]
async fn idle_session_heap_profile() {
    let sessions: usize = std::env::var("HEAP_SESSIONS")
        .ok()
        .map(|v| v.parse().expect("HEAP_SESSIONS must be a number"))
        .unwrap_or(DEFAULT_SESSIONS);
    let needed = sessions as u64 * 4 + 512;
    let limit = raise_fd_limit(needed);
    assert!(
        limit >= needed,
        "need {needed} file descriptors, limit is {limit}"
    );

    let output: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "dhat-idle-sessions.json"]
        .iter()
        .collect();
    let profiler = dhat::Profiler::builder().file_name(&output).build();

    let dc = spawn_echo_dc(true).await;
    let blackhole = spawn_blackhole().await;
    let (proxy, _handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         mask_host = \"{blackhole}\"\n\
         metrics_listen = \"\"\n\
         replay_cache_entries = 65536\n\
         [dc_override]\n\
         {DC} = \"{dc}\"\n"
    ))
    .await;

    let mut clients = Vec::with_capacity(sessions);
    while clients.len() < sessions {
        let mut batch = tokio::task::JoinSet::new();
        for _ in 0..BATCH.min(sessions - clients.len()) {
            batch.spawn(async move {
                let stream = connect_bulk(proxy).await;
                let mut client = Client::handshake(stream, DC, "www.example.com").await;
                let data = random_bytes(TRAFFIC_BEFORE_IDLE);
                assert_eq!(client.echo(&data).await, data);
                client
            });
        }
        while let Some(client) = batch.join_next().await {
            clients.push(client.expect("session failed"));
        }
    }
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Dropping the profiler writes the profile while every session is still open.
    drop(profiler);
    let text = std::fs::read_to_string(&output).expect("reading the dhat profile");
    report(
        "idle sessions",
        &serde_json::from_str(&text).expect("parsing the dhat profile"),
        sessions,
    );
    println!("full profile: {}", output.display());
    drop(clients);
}

/// Same measurement for connections that failed the handshake and are being
/// forwarded to a mask site that has gone quiet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "heavy: profiles masked connections under dhat"]
async fn masked_connection_heap_profile() {
    use echo_mtproxy::stats::HandshakeResult;
    use tokio::io::AsyncWriteExt;

    let connections: usize = std::env::var("HEAP_SESSIONS")
        .ok()
        .map(|v| v.parse().expect("HEAP_SESSIONS must be a number"))
        .unwrap_or(2_000);
    let needed = connections as u64 * 4 + 512;
    let limit = raise_fd_limit(needed);
    assert!(
        limit >= needed,
        "need {needed} file descriptors, limit is {limit}"
    );

    let output: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "dhat-masked.json"]
        .iter()
        .collect();
    let profiler = dhat::Profiler::builder().file_name(&output).build();

    // The mask site accepts, reads nothing and never answers.
    let site = spawn_blackhole().await;
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         mask_host = \"{site}\"\n\
         mask_max_connections = {}\n\
         mask_idle_timeout_secs = 3600\n\
         metrics_listen = \"\"\n",
        connections + 100
    ))
    .await;

    let hello = signed_hello(&[0x42; 16], unix_now());
    let mut held = Vec::with_capacity(connections);
    for _ in 0..connections {
        let mut stream = connect_bulk(proxy).await;
        stream.write_all(&hello).await.unwrap();
        held.push(stream);
    }
    let stats = handle.stats();
    let label = stats.label_index(Some("www.example.com"));
    for _ in 0..500 {
        if stats.handshakes(label, HandshakeResult::BadDigest) == connections as u64 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        stats.handshakes(label, HandshakeResult::BadDigest),
        connections as u64
    );
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    drop(profiler);
    let text = std::fs::read_to_string(&output).expect("reading the dhat profile");
    report(
        "masked connections",
        &serde_json::from_str(&text).expect("parsing the dhat profile"),
        connections,
    );
    drop(held);
}
