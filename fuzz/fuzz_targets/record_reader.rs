#![no_main]

use echo_mtproxy::tls::{self, RecordError, RecordReader};
use libfuzzer_sys::fuzz_target;

/// Unwraps `stream` in chunks whose sizes come from `sizes`. On error, returns
/// the payload produced before it.
fn unwrap_chunked(stream: &[u8], sizes: &[u8]) -> (Vec<u8>, Option<RecordError>) {
    let mut reader = RecordReader::new();
    let mut out = Vec::new();
    let mut pos = 0;
    let mut turn = 0;
    while pos < stream.len() {
        let want = if sizes.is_empty() {
            stream.len()
        } else {
            usize::from(sizes[turn % sizes.len()]) + 1
        };
        turn += 1;
        let n = want.min(stream.len() - pos);
        let mut buf = stream[pos..pos + n].to_vec();
        match reader.unwrap_in_place(&mut buf, n) {
            Ok(len) => {
                assert!(len <= n, "payload longer than its input");
                out.extend_from_slice(&buf[..len]);
            }
            Err(err) => return (out, Some(err)),
        }
        pos += n;
    }
    (out, None)
}

fuzz_target!(|data: &[u8]| {
    let split = data.len().min(8);
    let (sizes, stream) = data.split_at(split);

    // Arbitrary bytes as a record stream: chunking must not change the result.
    let (whole, whole_err) = unwrap_chunked(stream, &[]);
    let (chunked, chunked_err) = unwrap_chunked(stream, sizes);
    assert_eq!(whole_err, chunked_err);
    assert!(whole.len() <= stream.len());
    // Up to the failing header both have emitted the same payload prefix.
    let common = whole.len().min(chunked.len());
    assert_eq!(whole[..common], chunked[..common]);
    if whole_err.is_none() {
        assert_eq!(whole, chunked);
    }

    // Arbitrary bytes as payload: wrap then unwrap is the identity.
    let mut framed = Vec::new();
    tls::wrap_records(stream, &mut framed);
    let records = stream.len().div_ceil(tls::MAX_RECORD_PAYLOAD);
    assert_eq!(framed.len(), stream.len() + records * tls::RECORD_HEADER_LEN);
    let (round_trip, err) = unwrap_chunked(&framed, sizes);
    assert_eq!(err, None);
    assert_eq!(round_trip, stream);
});
