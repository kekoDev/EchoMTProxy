//! Middle-proxy framing cost per byte, both directions: CRC32, AES-256-CBC
//! and the copy that building frames needs.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use echo_mtproxy::middle::{build_frame, peer, CbcDec, CbcEnc, DownDecoder, UpEncoder, DOWN_SLACK};

const KEY: [u8; 32] = [0x42; 32];
const IV: [u8; 16] = [0x24; 16];
const READ: usize = 16 * 1024;

/// A stream of client messages of `msg_len` bytes, about `total` bytes long.
fn client_stream(msg_len: usize, total: usize) -> Vec<u8> {
    let mut stream = Vec::new();
    while stream.len() < total {
        stream.extend_from_slice(&(msg_len as u32).to_le_bytes());
        stream.extend(std::iter::repeat_n(0x5a, msg_len));
    }
    stream
}

fn encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("middle/encode");
    // A typical chat message and a media part.
    for msg_len in [256usize, 16 * 1024] {
        let stream = client_stream(msg_len, 1 << 20);
        let client = "192.0.2.1:1000".parse().unwrap();
        let ours = "192.0.2.2:2000".parse().unwrap();
        let mut up = UpEncoder::new(CbcEnc::new(&KEY, &IV), client, ours, Some(&[7; 16]));
        let mut out = vec![0u8; READ + 5];
        group.throughput(Throughput::Bytes(stream.len() as u64));
        group.bench_function(BenchmarkId::from_parameter(msg_len), |b| {
            b.iter(|| {
                for piece in stream.chunks(READ) {
                    let mut input = piece;
                    while !input.is_empty() {
                        let (used, ready) = up.encode(input, &mut out).unwrap();
                        black_box(&out[..ready]);
                        input = &input[used..];
                    }
                }
            });
        });
    }
    group.finish();
}

fn decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("middle/decode");
    for msg_len in [256usize, 16 * 1024] {
        // The decoder checks sequence numbers and the CBC chain, so each
        // iteration needs a fresh one; its setup is two key schedules.
        let conn = [1u8; 8];
        let mut wire = Vec::new();
        let mut seq = 0;
        while wire.len() < 1 << 20 {
            wire.extend_from_slice(&build_frame(
                seq,
                &peer::proxy_ans(&conn, &vec![0x5a; msg_len]),
            ));
            seq += 1;
        }
        CbcEnc::new(&KEY, &IV).apply(&mut wire);
        let mut buf = vec![0u8; DOWN_SLACK + 16 + READ];
        group.throughput(Throughput::Bytes(wire.len() as u64));
        group.bench_function(BenchmarkId::from_parameter(msg_len), |b| {
            b.iter(|| {
                let mut down = DownDecoder::new(CbcDec::new(&KEY, &IV));
                for piece in wire.chunks(READ) {
                    let offset = down.read_offset(&mut buf);
                    buf[offset..offset + piece.len()].copy_from_slice(piece);
                    let decoded = down.decode(&mut buf, offset + piece.len()).unwrap();
                    black_box(&buf[..decoded.len]);
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, encode, decode);
criterion_main!(benches);
