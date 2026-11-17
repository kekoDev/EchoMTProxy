//! Does media limiting slow the relay when it never actually limits?
//!
//! Loopback throughput drifts by tens of percent between runs, and one relay
//! instance can be a few percent faster than another identical one for its
//! whole life. Both are far larger than the effect being measured. So the two
//! variants are timed back to back in alternating order, over many freshly
//! created pairs of relays, and the median of all per-round ratios is
//! reported. A control comparison of two identical variants shows the noise
//! floor of the method.
//!
//! ```sh
//! cargo bench --bench limiting_ab
//! ```
//!
//! `AB_PAIRS` (default 60) sets the number of relay pairs per comparison and
//! `AB_ROUNDS` (default 40) the timed rounds per pair.

use std::time::{Duration, Instant};

use echo_mtproxy::cipher::AesCtr;
use echo_mtproxy::limit::{Lane, Limits, SessionTraffic};
use echo_mtproxy::relay::{relay, Ciphers};
use echo_mtproxy::tls::RecordReader;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CHUNK: usize = 1 << 20;

#[derive(Clone, Copy, PartialEq)]
enum Limiting {
    /// Media lane with `media_rate_bps = 0`: no bucket exists.
    Disabled,
    /// Media lane with a bucket whose rate and burst are never reached.
    Unlimited,
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

fn cipher(seed: u8) -> Box<AesCtr> {
    Box::new(AesCtr::new(&[seed; 32], &[seed.wrapping_add(1); 16]))
}

/// A running fast-mode relay; returns the client and DC ends.
async fn start(limiting: Limiting) -> (TcpStream, TcpStream) {
    let (client, proxy_client) = socket_pair().await;
    let (upstream, proxy_upstream) = socket_pair().await;
    tokio::spawn(async move {
        let limits = match limiting {
            Limiting::Disabled => Limits::unlimited(),
            Limiting::Unlimited => {
                Limits::new(100_000_000_000_000, 1 << 50, 1_000_000_000_000_000, 0.85)
            }
        };
        let traffic = SessionTraffic::new(Lane::Media, &limits, &proxy_client);
        relay(
            &proxy_client,
            &proxy_upstream,
            RecordReader::new(),
            Ciphers {
                client_dec: cipher(1),
                upstream_enc: Some(cipher(2)),
                upstream_dec: None,
                client_enc: None,
            },
            None,
            &traffic,
        )
        .await
    });
    (client, upstream)
}

async fn download(ends: &mut (TcpStream, TcpStream), data: &[u8]) -> Duration {
    let (client, upstream) = ends;
    let mut records = RecordReader::new();
    let mut buf = vec![0u8; 64 * 1024];
    let started = Instant::now();
    let read = async {
        let mut got = 0;
        while got < data.len() {
            let n = client.read(&mut buf).await.unwrap();
            got += records.unwrap_in_place(&mut buf, n).unwrap();
        }
    };
    let ((), written) = tokio::join!(read, upstream.write_all(data));
    written.unwrap();
    started.elapsed()
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

/// Times `a` and `b` back to back, swapping which goes first each round, on
/// `pairs` fresh pairs of relays, and returns the sorted ratios
/// time(b) / time(a).
async fn compare(a: Limiting, b: Limiting, pairs: usize, rounds: usize, data: &[u8]) -> Vec<f64> {
    let mut ratios = Vec::with_capacity(pairs * rounds);
    for pair in 0..pairs {
        // Alternate creation order too.
        let (mut first, mut second) = if pair % 2 == 0 {
            let first = start(a).await;
            (first, start(b).await)
        } else {
            let second = start(b).await;
            (start(a).await, second)
        };
        for _ in 0..10 {
            download(&mut first, data).await;
            download(&mut second, data).await;
        }
        for round in 0..rounds {
            let (ta, tb) = if round % 2 == 0 {
                let ta = download(&mut first, data).await;
                (ta, download(&mut second, data).await)
            } else {
                let tb = download(&mut second, data).await;
                (download(&mut first, data).await, tb)
            };
            ratios.push(tb.as_secs_f64() / ta.as_secs_f64());
        }
    }
    ratios.sort_by(|x, y| x.total_cmp(y));
    ratios
}

fn report(label: &str, ratios: &[f64]) {
    let median = percentile(ratios, 0.5);
    println!(
        "  {label:<44} median {:+.2}%   (quartiles {:+.2}% .. {:+.2}%)",
        (median - 1.0) * 100.0,
        (percentile(ratios, 0.25) - 1.0) * 100.0,
        (percentile(ratios, 0.75) - 1.0) * 100.0
    );
}

fn env_or(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let pairs = env_or("AB_PAIRS", 60);
    let rounds = env_or("AB_ROUNDS", 40);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let data = vec![0x5au8; CHUNK];

    runtime.block_on(async {
        println!(
            "relay download, fast mode, {} KiB per sample, {pairs} relay pairs x {rounds} rounds, \
             time relative to limiting disabled",
            CHUNK / 1024
        );
        let control = compare(Limiting::Disabled, Limiting::Disabled, pairs, rounds, &data).await;
        report("control: disabled vs disabled", &control);
        let effect = compare(
            Limiting::Disabled,
            Limiting::Unlimited,
            pairs,
            rounds,
            &data,
        )
        .await;
        report("limiting on but never limiting vs disabled", &effect);
    });
}
