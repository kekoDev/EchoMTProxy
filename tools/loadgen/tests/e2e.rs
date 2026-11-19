//! The load generator against a real in-process proxy and its own fake DC.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use echo_loadgen::client::{self, ClientConfig, Mode};
use echo_loadgen::dc::{self, Dc};
use echo_loadgen::stats::{ClientStats, Failure};
use echo_mtproxy::cipher::{AesCtr, Ctr};
use echo_mtproxy::config::{Config, Secret};
use echo_mtproxy::server::{self, Proxy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

const SECRET_HEX: &str = "ee0f1e2d3c4b5a69788796a5b4c3d2e1f07777772e6578616d706c652e636f6d";

async fn spawn_fake_dc() -> (SocketAddr, Arc<Dc>) {
    let dc = Arc::new(Dc::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(dc::serve(listener, dc.clone()));
    (addr, dc)
}

/// A mask target that accepts and never answers.
async fn spawn_blackhole() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            held.push(listener.accept().await.unwrap().0);
        }
    });
    addr
}

/// A proxy whose five DCs all point at `upstream`.
async fn spawn_proxy(upstream: SocketAddr, mode: &str, extra: &str) -> (SocketAddr, Arc<Proxy>) {
    let mask = spawn_blackhole().await;
    let overrides: String = (1..=5)
        .map(|dc| format!("{dc} = \"{upstream}\"\n"))
        .collect();
    let config = Config::parse(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         upstream_mode = \"{mode}\"\n\
         mask_host = \"{mask}\"\n\
         metrics_listen = \"\"\n\
         {extra}\n\
         [dc_override]\n\
         {overrides}"
    ))
    .unwrap();
    let proxy = Arc::new(Proxy::from_config(&config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server::serve(listener, proxy.clone()));
    (addr, proxy)
}

fn config(proxy: SocketAddr, connections: usize, active: usize, mode: Mode) -> ClientConfig {
    let secret = Secret::parse(SECRET_HEX).unwrap();
    ClientConfig {
        targets: vec![proxy],
        bind: Vec::new(),
        sni: secret.domain.clone(),
        secret,
        connections,
        active,
        mode,
        payload: 20_000,
        interval: Duration::ZERO,
        rate: 0.0,
        concurrency: 64,
        media_share: 0.3,
        handshake_timeout: Duration::from_secs(10),
        hold: Duration::from_millis(1500),
        verify: true,
    }
}

async fn run(config: ClientConfig) -> (anyhow::Result<()>, Arc<ClientStats>) {
    let stats = Arc::new(ClientStats::default());
    let (_stop, stopped) = watch::channel(false);
    let result = client::run(config, stats.clone(), stopped).await;
    (result, stats)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_and_echo_sessions_through_every_upstream_mode() {
    for mode in ["fast", "obfuscated", "plain"] {
        let (dc_addr, dc) = spawn_fake_dc().await;
        // Media limiting off so media-lane sessions are not slowed here.
        let (proxy, handle) = spawn_proxy(dc_addr, mode, "media_rate_bps = 0").await;
        let (result, stats) = run(config(proxy, 300, 30, Mode::Echo)).await;
        result.unwrap_or_else(|e| panic!("{mode}: {e:#}"));

        assert_eq!(stats.established.load(Ordering::Relaxed), 300, "{mode}");
        assert_eq!(stats.failed(), 0, "{mode}");
        assert_eq!(stats.active_errors.load(Ordering::Relaxed), 0, "{mode}");
        assert_eq!(stats.closed_by_peer.load(Ordering::Relaxed), 0, "{mode}");
        assert_eq!(stats.open.load(Ordering::Relaxed), 300, "{mode}");
        let requests = stats.requests.load(Ordering::Relaxed);
        // How many fit in the run depends on the machine; that any did, verified,
        // is the point.
        assert!(requests > 0, "{mode}: no echo round trips");
        // Everything sent came back, except requests cut off when the run ended.
        let (up, down) = (
            stats.bytes_up.load(Ordering::Relaxed),
            stats.bytes_down.load(Ordering::Relaxed),
        );
        assert_eq!(down, requests * 20_000, "{mode}");
        assert!(
            up >= down && up - down <= 30 * 20_000,
            "{mode}: up {up}, down {down}"
        );
        assert!(stats.handshake_time.percentile(0.5).is_some());
        assert!(stats.request_time.percentile(0.99).is_some());

        // The fake DC saw every session and parked the idle ones.
        assert_eq!(dc.stats.sessions.load(Ordering::Relaxed), 300, "{mode}");
        assert_eq!(dc.stats.not_loadgen.load(Ordering::Relaxed), 0, "{mode}");
        assert_eq!(dc.stats.bad_handshake.load(Ordering::Relaxed), 0, "{mode}");
        // And the proxy counted them on both lanes.
        let limits = &handle.stats().limits;
        assert!(limits.bytes(echo_mtproxy::limit::Lane::Chat) > 0, "{mode}");
        assert!(limits.bytes(echo_mtproxy::limit::Lane::Media) > 0, "{mode}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn download_and_upload_modes_move_data_one_way() {
    let (dc_addr, dc) = spawn_fake_dc().await;
    let (proxy, _handle) = spawn_proxy(dc_addr, "fast", "media_rate_bps = 0").await;

    let (result, stats) = run(config(proxy, 20, 20, Mode::Download)).await;
    result.unwrap();
    let (up, down) = (
        stats.bytes_up.load(Ordering::Relaxed),
        stats.bytes_down.load(Ordering::Relaxed),
    );
    let requests = stats.requests.load(Ordering::Relaxed);
    assert!(requests > 0);
    assert_eq!(down, requests * 20_000);
    // Only 8-byte requests go up.
    assert!(up >= requests * 8 && up <= (requests + 20) * 8, "{up}");
    assert_eq!(stats.active_errors.load(Ordering::Relaxed), 0);

    let before = dc.stats.bytes_in.load(Ordering::Relaxed);
    let (result, stats) = run(config(proxy, 20, 20, Mode::Upload)).await;
    result.unwrap();
    let up = stats.bytes_up.load(Ordering::Relaxed);
    assert!(up > 20 * 20_000, "{up}");
    assert_eq!(stats.bytes_down.load(Ordering::Relaxed), 0);
    // What was sent keeps draining through socket buffers and the proxy
    // after the clients have gone; the DC ends up with nearly all of it.
    let mut swallowed = 0;
    for _ in 0..200 {
        swallowed = dc.stats.bytes_in.load(Ordering::Relaxed) - before;
        if swallowed * 10 >= up * 9 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(swallowed * 10 >= up * 9, "sent {up}, DC got {swallowed}");
    assert!(swallowed <= up);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_sessions_closed_by_the_proxy_are_noticed_on_both_sides() {
    let (dc_addr, dc) = spawn_fake_dc().await;
    // The proxy drops idle sessions after one second.
    let (proxy, _handle) = spawn_proxy(dc_addr, "fast", "idle_timeout_secs = 1").await;
    let mut cfg = config(proxy, 50, 0, Mode::Echo);
    cfg.hold = Duration::from_secs(3);
    let (result, stats) = run(cfg).await;
    result.unwrap();

    assert_eq!(stats.established.load(Ordering::Relaxed), 50);
    assert_eq!(stats.closed_by_peer.load(Ordering::Relaxed), 50);
    assert_eq!(stats.open.load(Ordering::Relaxed), 0);

    assert_eq!(dc.stats.parked.load(Ordering::Relaxed), 50);
    assert_eq!(dc.sweep(), 50);
    assert_eq!(dc.stats.parked.load(Ordering::Relaxed), 0);
}

/// A DC that speaks obfuscated2 correctly and echoes, but is not the load
/// generator's: what a real upstream looks like from the client's side.
async fn spawn_foreign_dc() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut init = [0u8; 64];
                if stream.read_exact(&mut init).await.is_err() {
                    return;
                }
                let mut key = [0u8; 32];
                let mut iv = [0u8; 16];
                key.copy_from_slice(&init[8..40]);
                iv.copy_from_slice(&init[40..56]);
                let mut dec = AesCtr::new(&key, &iv);
                let mut reversed = init[8..56].to_vec();
                reversed.reverse();
                key.copy_from_slice(&reversed[..32]);
                iv.copy_from_slice(&reversed[32..]);
                let mut enc = AesCtr::new(&key, &iv);
                dec.apply(&mut init);
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    dec.apply(&mut buf[..n]);
                    enc.apply(&mut buf[..n]);
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_stops_at_the_probe_when_the_far_end_is_not_the_fake_dc() {
    let foreign = spawn_foreign_dc().await;
    let (proxy, handle) = spawn_proxy(foreign, "fast", "").await;
    let (result, stats) = run(config(proxy, 500, 50, Mode::Echo)).await;

    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("probe session for DC 1"), "{error}");
    assert!(error.contains("not_loadgen_dc"), "{error}");
    assert!(error.contains("never left pointing at Telegram"), "{error}");
    // Exactly one session was attempted: no load was generated.
    assert_eq!(stats.attempted.load(Ordering::Relaxed), 1);
    assert_eq!(stats.failures(Failure::NotLoadgenDc), 1);
    assert_eq!(stats.established.load(Ordering::Relaxed), 0);
    assert_eq!(handle.stats().connections_accepted(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_dc_left_at_another_upstream_is_caught_before_any_load() {
    // DCs 1 to 4 point at the fake DC; DC 5 was forgotten and points
    // somewhere else (here a foreign DC standing in for Telegram).
    let (fake, dc) = spawn_fake_dc().await;
    let foreign = spawn_foreign_dc().await;
    let mask = spawn_blackhole().await;
    let config_text = format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         mask_host = \"{mask}\"\n\
         metrics_listen = \"\"\n\
         [dc_override]\n\
         1 = \"{fake}\"\n2 = \"{fake}\"\n3 = \"{fake}\"\n4 = \"{fake}\"\n5 = \"{foreign}\"\n"
    );
    let proxy = Arc::new(Proxy::from_config(&Config::parse(&config_text).unwrap()).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server::serve(listener, proxy.clone()));

    let (result, stats) = run(config(addr, 5000, 100, Mode::Echo)).await;
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("probe session for DC 5"), "{error}");
    assert!(error.contains("not_loadgen_dc"), "{error}");
    // Five probes, one per DC; the run never got to its 5000 sessions and
    // the foreign upstream saw exactly one connection.
    assert_eq!(stats.attempted.load(Ordering::Relaxed), 5);
    assert_eq!(stats.established.load(Ordering::Relaxed), 4);
    assert_eq!(dc.stats.sessions.load(Ordering::Relaxed), 4);
    assert_eq!(proxy.stats().connections_accepted(), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_reports_a_wrong_secret_and_an_unreachable_proxy() {
    let (dc_addr, _dc) = spawn_fake_dc().await;
    let (proxy, _handle) = spawn_proxy(dc_addr, "fast", "").await;

    // Wrong key: the proxy masks (here: to a silent host), so nothing comes back.
    let mut cfg = config(proxy, 100, 0, Mode::Echo);
    cfg.secret =
        Secret::parse("eeffffffffffffffffffffffffffffffff7777772e6578616d706c652e636f6d").unwrap();
    cfg.handshake_timeout = Duration::from_secs(1);
    let (result, stats) = run(cfg).await;
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("timeout"), "{error}");
    assert!(error.contains("wrong secret"), "{error}");
    assert_eq!(stats.attempted.load(Ordering::Relaxed), 1);

    // Nothing listening.
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let (result, stats) = run(config(dead, 100, 0, Mode::Echo)).await;
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("could not connect"), "{error}");
    assert_eq!(stats.failures(Failure::Connect), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limits_the_ramp_up_and_stop_ends_the_run_early() {
    let (dc_addr, _dc) = spawn_fake_dc().await;
    let (proxy, _handle) = spawn_proxy(dc_addr, "fast", "").await;

    // 200 sessions per second: 100 sessions take about half a second.
    let mut cfg = config(proxy, 100, 0, Mode::Echo);
    cfg.rate = 200.0;
    cfg.hold = Duration::ZERO;
    let started = std::time::Instant::now();
    let (result, stats) = run(cfg).await;
    result.unwrap();
    let took = started.elapsed();
    assert_eq!(stats.established.load(Ordering::Relaxed), 100);
    assert!(took >= Duration::from_millis(450), "{took:?}");

    // A stop signal cuts a long hold short.
    let mut cfg = config(proxy, 20, 0, Mode::Echo);
    cfg.hold = Duration::from_secs(600);
    let stats = Arc::new(ClientStats::default());
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(client::run(cfg, stats.clone(), stopped));
    while stats.established.load(Ordering::Relaxed) < 20 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("run ignored the stop signal")
        .unwrap()
        .unwrap();
}
