#![no_main]

use echo_mtproxy::middle::{
    build_frame, peer, CbcDec, CbcEnc, DownDecoder, FrameError, UpEncoder, DOWN_SLACK,
    MIN_ENCODE_BUF,
};
use libfuzzer_sys::fuzz_target;

const KEY: [u8; 32] = [0x31; 32];
const IV: [u8; 16] = [0x13; 16];

fn chunk_len(sizes: &[u8], turn: usize, rest: usize) -> usize {
    if sizes.is_empty() {
        rest
    } else {
        (usize::from(sizes[turn % sizes.len()]) + 1).min(rest)
    }
}

/// Encodes `stream` as client messages, in chunks and into an output buffer
/// whose sizes come from `sizes`.
fn encode(stream: &[u8], sizes: &[u8]) -> Result<Vec<u8>, FrameError> {
    let client = "192.0.2.1:1000".parse().unwrap();
    let ours = "[2001:db8::1]:2000".parse().unwrap();
    let mut up =
        UpEncoder::new(CbcEnc::new(&KEY, &IV), client, ours, Some(&[7; 16])).with_conn_id([1; 8]);
    let out_len = MIN_ENCODE_BUF + sizes.first().map_or(4096, |b| usize::from(*b) * 8);
    let mut out = vec![0u8; out_len];
    let mut wire = Vec::new();
    let (mut pos, mut turn) = (0, 0);
    while pos < stream.len() {
        let n = chunk_len(sizes, turn, stream.len() - pos);
        turn += 1;
        let mut input = &stream[pos..pos + n];
        while !input.is_empty() {
            let (used, ready) = up.encode(input, &mut out)?;
            assert!(used > 0 || ready > 0, "encoder made no progress");
            assert_eq!(ready % 16, 0);
            wire.extend_from_slice(&out[..ready]);
            input = &input[used..];
        }
        pos += n;
    }
    Ok(wire)
}

/// Feeds `input` to a decoder in chunks; `decrypt` selects between the
/// encrypted entry point and the plaintext parser. Returns the output length
/// and whether a close was seen.
fn decode(input: &[u8], sizes: &[u8], decrypt: bool) -> Result<(usize, bool), FrameError> {
    let mut down = DownDecoder::new(CbcDec::new(&KEY, &IV));
    let mut total = 0;
    let (mut pos, mut turn) = (0, 0);
    while pos < input.len() {
        let n = chunk_len(sizes, turn, input.len() - pos);
        turn += 1;
        let mut buf = vec![0u8; DOWN_SLACK + 16 + n];
        let decoded = if decrypt {
            let offset = down.read_offset(&mut buf);
            buf[offset..offset + n].copy_from_slice(&input[pos..pos + n]);
            down.decode(&mut buf, offset + n)?
        } else {
            buf[DOWN_SLACK..DOWN_SLACK + n].copy_from_slice(&input[pos..pos + n]);
            down.parse(&mut buf, DOWN_SLACK, DOWN_SLACK + n)?
        };
        // A frame never grows on its way to the client. One call may also
        // emit what up to 15 carried-over bytes of ciphertext completed.
        assert!(decoded.len <= n + 15 + 3, "output outgrew its input");
        total += decoded.len;
        if decoded.closed {
            return Ok((total, true));
        }
        pos += n;
    }
    Ok((total, false))
}

fuzz_target!(|data: &[u8]| {
    let split = data.len().min(8);
    let (sizes, stream) = data.split_at(split);

    // Arbitrary bytes as a client message stream: chunking and the output
    // buffer size must not change the ciphertext.
    let whole = encode(stream, &[]);
    let chunked = encode(stream, sizes);
    assert_eq!(whole.is_err(), chunked.is_err());
    if let (Ok(whole), Ok(chunked)) = (&whole, &chunked) {
        assert_eq!(whole, chunked);
    }

    // Arbitrary bytes as a decrypted frame stream, and as ciphertext: no
    // panic, and chunking does not change whether or how it fails.
    for decrypt in [false, true] {
        let whole = decode(stream, &[], decrypt);
        let chunked = decode(stream, sizes, decrypt);
        assert_eq!(whole.as_ref().err(), chunked.as_ref().err());
        assert_eq!(whole.map(|r| r.1).ok(), chunked.map(|r| r.1).ok());
    }

    // Well-formed answers built from the input always decode.
    let conn = [2u8; 8];
    let mut wire = Vec::new();
    let mut expected = 0;
    for (seq, piece) in stream.chunks(64).enumerate() {
        let data = &piece[..piece.len() - piece.len() % 4];
        wire.extend_from_slice(&build_frame(seq as i32, &peer::proxy_ans(&conn, data)));
        expected += 4 + data.len();
    }
    CbcEnc::new(&KEY, &IV).apply(&mut wire);
    let (len, closed) = decode(&wire, sizes, true).expect("valid frames rejected");
    assert!(!closed);
    // Each message gains its length word and up to 3 bytes of padding.
    assert!(len >= expected && len <= expected + 3 * stream.chunks(64).count());
});
