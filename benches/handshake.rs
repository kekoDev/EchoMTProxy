//! CPU cost of accepting one client, without any I/O.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use echo_mtproxy::config::Secret;
use echo_mtproxy::obfs2;
use echo_mtproxy::replay::ReplayCache;
use echo_mtproxy::tls::{self, SkewPolicy};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

const NOW: u64 = 1_800_000_000;
const SKEW: SkewPolicy = SkewPolicy {
    behind_secs: 600,
    ahead_secs: 1200,
    accept_uptime: true,
};

fn secrets(count: usize) -> Vec<Secret> {
    (0..count)
        .map(|i| Secret {
            key: [i as u8 + 1; 16],
            domain: "www.example.com".to_owned(),
        })
        .collect()
}

fn signed_hello(secret: &Secret) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(1);
    let mut hello = tls::client_hello_template(&secret.domain, &mut rng).unwrap();
    tls::sign_client_hello(&mut hello, &secret.key, NOW as u32);
    hello
}

fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("client_hello_verify");
    for count in [1usize, 8, 64] {
        let all = secrets(count);
        // Worst case for a valid client: its secret is the last one tried.
        let hello = signed_hello(&all[count - 1]);
        group.bench_function(BenchmarkId::new("match_last_of", count), |b| {
            b.iter(|| tls::verify_client_hello(black_box(&hello), &all, NOW, &SKEW).unwrap());
        });
    }
    // What a prober costs: every secret is tried and none matches.
    let all = secrets(8);
    let stranger = signed_hello(&Secret {
        key: [0xee; 16],
        domain: "www.example.com".to_owned(),
    });
    group.bench_function("no_match_of/8", |b| {
        b.iter(|| tls::verify_client_hello(black_box(&stranger), &all, NOW, &SKEW).unwrap_err());
    });
    group.finish();
}

fn server_hello(c: &mut Criterion) {
    let secret = &secrets(1)[0];
    let hello = signed_hello(secret);
    let parsed =
        tls::verify_client_hello(&hello, std::slice::from_ref(secret), NOW, &SKEW).unwrap();
    let mut rng = StdRng::seed_from_u64(2);
    c.bench_function("server_hello_build/cert_2500", |b| {
        b.iter(|| {
            tls::build_server_hello(
                &secret.key,
                &parsed.client_random,
                parsed.session_id,
                2500,
                &mut rng,
            )
        });
    });
}

fn obfs2_init(c: &mut Criterion) {
    let secret = [7u8; 16];
    let mut seed = [0u8; 64];
    StdRng::seed_from_u64(3).fill_bytes(&mut seed);
    let wire = obfs2::client_init(seed, &secret, 2).wire;
    c.bench_function("obfs2/parse_client_init", |b| {
        b.iter(|| {
            obfs2::parse_client_init(black_box(&wire), &secret)
                .unwrap()
                .dc_idx
        });
    });
    let parsed = obfs2::parse_client_init(&wire, &secret).unwrap();
    c.bench_function("obfs2/upstream_init_fast", |b| {
        b.iter(|| {
            obfs2::upstream_init(
                black_box(seed),
                Some((&parsed.keys.enc_key, &parsed.keys.enc_iv)),
            )
            .wire
        });
    });
}

fn replay(c: &mut Criterion) {
    let cache = ReplayCache::new(std::time::Duration::from_secs(1800), 2_000_000);
    let mut rng = StdRng::seed_from_u64(4);
    let mut key = [0u8; 32];
    c.bench_function("replay/check_and_insert", |b| {
        b.iter(|| {
            rng.fill_bytes(&mut key);
            cache.check_and_insert(&key)
        });
    });
}

/// Everything the proxy computes for one accepted client in fast mode.
fn full(c: &mut Criterion) {
    let all = secrets(1);
    let hello = signed_hello(&all[0]);
    let mut seed = [0u8; 64];
    StdRng::seed_from_u64(5).fill_bytes(&mut seed);
    let wire = obfs2::client_init(seed, &all[0].key, 2).wire;
    let mut rng = StdRng::seed_from_u64(6);
    c.bench_function("handshake_cpu/fast_mode", |b| {
        b.iter(|| {
            let parsed = tls::verify_client_hello(black_box(&hello), &all, NOW, &SKEW).unwrap();
            let response = tls::build_server_hello(
                &all[0].key,
                &parsed.client_random,
                parsed.session_id,
                2500,
                &mut rng,
            );
            let init = obfs2::parse_client_init(black_box(&wire), &all[0].key).unwrap();
            let upstream =
                obfs2::upstream_init(seed, Some((&init.keys.enc_key, &init.keys.enc_iv)));
            (response.len(), upstream.wire[0])
        });
    });
}

criterion_group!(benches, verify, server_hello, obfs2_init, replay, full);
criterion_main!(benches);
