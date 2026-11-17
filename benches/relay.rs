//! Relay throughput per upstream mode over loopback TCP.
//!
//! The harness side (framing, unframing, the kernel's loopback path) is
//! included in the numbers, so compare modes, versions and machines with each
//! other rather than reading them as absolute proxy throughput.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use echo_mtproxy::cipher::AesCtr;
use echo_mtproxy::limit::{Direction, Lane, Limits, SessionTraffic};
use echo_mtproxy::relay::{relay, Ciphers};
use echo_mtproxy::tls::{self, RecordReader};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CHUNK: usize = 1 << 20;

fn cipher(seed: u8) -> Box<AesCtr> {
    Box::new(AesCtr::new(&[seed; 32], &[seed.wrapping_add(1); 16]))
}

fn ciphers(mode: &str) -> Ciphers {
    match mode {
        "fast" => Ciphers {
            client_dec: cipher(1),
            upstream_enc: Some(cipher(2)),
            upstream_dec: None,
            client_enc: None,
        },
        "obfuscated" => Ciphers {
            client_dec: cipher(1),
            upstream_enc: Some(cipher(2)),
            upstream_dec: Some(cipher(3)),
            client_enc: Some(cipher(4)),
        },
        _ => Ciphers {
            client_dec: cipher(1),
            upstream_enc: None,
            upstream_dec: None,
            client_enc: Some(cipher(4)),
        },
    }
}

async fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (near, far) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let (near, far) = (near.unwrap(), far.unwrap().0);
    near.set_nodelay(true).unwrap();
    far.set_nodelay(true).unwrap();
    (near, far)
}

/// How a benchmarked session is limited.
#[derive(Clone, Copy)]
enum Limiting {
    /// Chat lane: bytes are counted, nothing else.
    Chat,
    /// Media lane with `media_rate_bps = 0`: no bucket exists.
    MediaDisabled,
    /// Media lane with a bucket whose rate and burst are never reached, so
    /// every read pays for the bucket arithmetic but none ever waits.
    MediaUnlimited,
}

/// A running relay with the client and DC ends held by the benchmark.
fn start(runtime: &tokio::runtime::Runtime, mode: &str) -> (TcpStream, TcpStream) {
    start_with(runtime, mode, Limiting::Chat)
}

fn start_with(
    runtime: &tokio::runtime::Runtime,
    mode: &str,
    limiting: Limiting,
) -> (TcpStream, TcpStream) {
    let ((client, proxy_client), (upstream, proxy_upstream)) =
        runtime.block_on(async { (socket_pair().await, socket_pair().await) });
    let ciphers = ciphers(mode);
    runtime.spawn(async move {
        let (lane, limits) = match limiting {
            Limiting::Chat => (Lane::Chat, Limits::unlimited()),
            Limiting::MediaDisabled => (Lane::Media, Limits::unlimited()),
            // 100 Tbit/s with a 1 PB burst, and congestion control active
            // against a link that large.
            Limiting::MediaUnlimited => (
                Lane::Media,
                Limits::new(100_000_000_000_000, 1 << 50, 1_000_000_000_000_000, 0.85),
            ),
        };
        let traffic = SessionTraffic::new(lane, &limits, &proxy_client);
        relay(
            &proxy_client,
            &proxy_upstream,
            RecordReader::new(),
            ciphers,
            Some(Duration::from_secs(900)),
            &traffic,
        )
        .await
    });
    (client, upstream)
}

async fn download(client: &mut TcpStream, upstream: &mut TcpStream, data: &[u8]) {
    let mut records = RecordReader::new();
    let mut buf = vec![0u8; 64 * 1024];
    let read = async {
        let mut got = 0;
        while got < data.len() {
            let n = client.read(&mut buf).await.unwrap();
            got += records.unwrap_in_place(&mut buf, n).unwrap();
        }
    };
    let ((), written) = tokio::join!(read, upstream.write_all(data));
    written.unwrap();
}

async fn upload(client: &mut TcpStream, upstream: &mut TcpStream, framed: &[u8], len: usize) {
    let mut buf = vec![0u8; 64 * 1024];
    let read = async {
        let mut got = 0;
        while got < len {
            got += upstream.read(&mut buf).await.unwrap();
        }
    };
    let ((), written) = tokio::join!(read, client.write_all(framed));
    written.unwrap();
}

fn throughput(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let data = vec![0x5au8; CHUNK];
    let mut framed = Vec::new();
    tls::wrap_records(&data, &mut framed);

    let mut group = c.benchmark_group("relay");
    group.throughput(Throughput::Bytes(CHUNK as u64));
    for mode in ["fast", "obfuscated", "plain"] {
        let (mut client, mut upstream) = start(&runtime, mode);
        group.bench_function(BenchmarkId::new("download", mode), |b| {
            b.iter(|| runtime.block_on(download(&mut client, &mut upstream, &data)));
        });
        let (mut client, mut upstream) = start(&runtime, mode);
        group.bench_function(BenchmarkId::new("upload", mode), |b| {
            b.iter(|| runtime.block_on(upload(&mut client, &mut upstream, &framed, CHUNK)));
        });
    }
    group.finish();
}

/// Cost of media limiting on the relay: the same download with the limiter
/// off and with it on but never limiting. Fast mode does no AES on this path,
/// so any per-read overhead shows here more than anywhere else.
fn limiting_overhead(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let data = vec![0x5au8; CHUNK];
    let mut framed = Vec::new();
    tls::wrap_records(&data, &mut framed);

    let mut group = c.benchmark_group("relay_limiting");
    group.throughput(Throughput::Bytes(CHUNK as u64));
    for (name, limiting) in [
        ("chat", Limiting::Chat),
        ("media_disabled", Limiting::MediaDisabled),
        ("media_unlimited", Limiting::MediaUnlimited),
    ] {
        let (mut client, mut upstream) = start_with(&runtime, "fast", limiting);
        group.bench_function(BenchmarkId::new("download_fast", name), |b| {
            b.iter(|| runtime.block_on(download(&mut client, &mut upstream, &data)));
        });
        let (mut client, mut upstream) = start_with(&runtime, "fast", limiting);
        group.bench_function(BenchmarkId::new("upload_fast", name), |b| {
            b.iter(|| runtime.block_on(upload(&mut client, &mut upstream, &framed, CHUNK)));
        });
    }
    group.finish();
}

/// The limiter's own cost per read, without any I/O around it.
fn accounting(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (client, _peer) = runtime.block_on(socket_pair());
    let mut group = c.benchmark_group("account_per_read");
    for (name, limiting) in [
        ("chat", Limiting::Chat),
        ("media_disabled", Limiting::MediaDisabled),
        ("media_unlimited", Limiting::MediaUnlimited),
    ] {
        let (lane, limits) = match limiting {
            Limiting::Chat => (Lane::Chat, Limits::unlimited()),
            Limiting::MediaDisabled => (Lane::Media, Limits::unlimited()),
            Limiting::MediaUnlimited => (
                Lane::Media,
                Limits::new(100_000_000_000_000, 1 << 50, 1_000_000_000_000_000, 0.85),
            ),
        };
        let traffic = SessionTraffic::new(lane, &limits, &client);
        group.bench_function(name, |b| {
            b.iter(|| traffic.account(Direction::Down, std::hint::black_box(16_389)));
        });
    }
    group.finish();
}

criterion_group!(benches, throughput, limiting_overhead, accounting);
criterion_main!(benches);
