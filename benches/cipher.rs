//! AES-256-CTR cost: the dominant per-byte CPU cost of the proxy.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use echo_mtproxy::cipher::{AesCtr, Ctr};

const KEY: [u8; 32] = [0x42; 32];
const IV: [u8; 16] = [0x24; 16];

fn keystream(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes256_ctr/rustcrypto");
    // An obfs2 init, one MTU of payload, a small read and a full TLS record.
    for size in [64usize, 1420, 4096, 16384] {
        let mut buf = vec![0u8; size];
        let mut cipher = AesCtr::new(&KEY, &IV);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter(|| cipher.apply(black_box(&mut buf)));
        });
    }
    group.finish();
}

fn key_setup(c: &mut Criterion) {
    // Paid two to four times per connection.
    c.bench_function("aes256_ctr/rustcrypto/key_setup", |b| {
        b.iter(|| AesCtr::new(black_box(&KEY), black_box(&IV)));
    });
}

criterion_group!(benches, keystream, key_setup);
criterion_main!(benches);
