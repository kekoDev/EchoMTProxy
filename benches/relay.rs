//! Relay throughput per upstream mode over in-memory pipes.
//!
//! The harness side (framing, unframing, the pipes themselves) is included in
//! the numbers, so compare modes and machines with each other rather than
//! reading them as absolute proxy throughput.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use echo_mtproxy::cipher::AesCtr;
use echo_mtproxy::relay::{relay, Ciphers};
use echo_mtproxy::tls::{self, RecordReader};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const CHUNK: usize = 1 << 20;
const PIPE: usize = 256 * 1024;

fn cipher(seed: u8) -> AesCtr {
    AesCtr::new(&[seed; 32], &[seed.wrapping_add(1); 16])
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

/// A running relay with the client and DC ends held by the benchmark.
fn start(runtime: &tokio::runtime::Runtime, mode: &str) -> (DuplexStream, DuplexStream) {
    let (client, proxy_client) = tokio::io::duplex(PIPE);
    let (upstream, proxy_upstream) = tokio::io::duplex(PIPE);
    let (client_read, client_write) = tokio::io::split(proxy_client);
    let (upstream_read, upstream_write) = tokio::io::split(proxy_upstream);
    runtime.spawn(relay(
        client_read,
        client_write,
        upstream_read,
        upstream_write,
        RecordReader::new(),
        ciphers(mode),
        Some(Duration::from_secs(900)),
    ));
    (client, upstream)
}

async fn download(client: &mut DuplexStream, upstream: &mut DuplexStream, data: &[u8]) {
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

async fn upload(client: &mut DuplexStream, upstream: &mut DuplexStream, framed: &[u8], len: usize) {
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
        .enable_time()
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

criterion_group!(benches, throughput);
criterion_main!(benches);
