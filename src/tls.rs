use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use crate::config::Secret;

pub const RECORD_HEADER_LEN: usize = 5;
pub const MAX_RECORD_PAYLOAD: usize = 16384;
/// mtprotoproxy treats anything shorter as not fake-tls; real clients pad to 517 bytes.
pub const MIN_CLIENT_HELLO_PAYLOAD: usize = 512;
pub const RANDOM_LEN: usize = 32;

const RANDOM_POS: usize = 11;
const SESSION_ID_LEN_POS: usize = RANDOM_POS + RANDOM_LEN;
const SESSION_ID_POS: usize = SESSION_ID_LEN_POS + 1;
const MAX_SESSION_ID_LEN: usize = 32;
const DIGEST_PREFIX_LEN: usize = RANDOM_LEN - 4;
/// Timestamps below this are uptimes, not Unix times (mtprotoproxy: 1000 days).
const UPTIME_TIMESTAMP_LIMIT: u32 = 60 * 60 * 24 * 1000;

const TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
const TYPE_HANDSHAKE: u8 = 0x16;
const TYPE_APPLICATION_DATA: u8 = 0x17;
const VERSION_TLS12: [u8; 2] = [0x03, 0x03];
const CHANGE_CIPHER_SPEC_RECORD: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HelloError {
    #[error("not a fake-tls client hello")]
    Malformed,
    #[error("digest matches no secret")]
    BadDigest,
    /// `skew_secs` is the client's timestamp minus the proxy's clock:
    /// negative when the client clock is behind, positive when it is ahead.
    #[error("timestamp outside the allowed window (client clock {} s {})",
        .skew_secs.unsigned_abs(), skew_direction(*.skew_secs))]
    BadTimestamp { skew_secs: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("unexpected tls record type")]
    BadType,
    #[error("unexpected tls record version")]
    BadVersion,
}

/// "behind" or "ahead", for a client-minus-proxy clock difference.
pub fn skew_direction(skew_secs: i64) -> &'static str {
    if skew_secs < 0 {
        "behind"
    } else {
        "ahead"
    }
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // Zero-padding a short key to the block size is what HMAC does internally;
    // doing it here gives an infallible constructor.
    let mut block = [0u8; 64];
    block[..key.len().min(64)].copy_from_slice(&key[..key.len().min(64)]);
    let mut mac = <Hmac<Sha256> as Mac>::new(&block.into());
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Accepted difference between the proxy clock and the ClientHello timestamp.
#[derive(Debug, Clone, Copy)]
pub struct SkewPolicy {
    /// Client clock may lag the proxy by less than this.
    pub behind_secs: u64,
    /// Client clock may lead the proxy by less than this.
    pub ahead_secs: u64,
    /// Accept uptime-style timestamps from clients that fail to read Unix time.
    pub accept_uptime: bool,
}

impl SkewPolicy {
    pub fn allows(&self, now_unix: u64, timestamp: u32) -> bool {
        if self.accept_uptime && timestamp < UPTIME_TIMESTAMP_LIMIT {
            return true;
        }
        let delta = i128::from(now_unix) - i128::from(timestamp);
        -i128::from(self.ahead_secs) < delta && delta < i128::from(self.behind_secs)
    }

    /// How long a ClientHello stays valid, which is how long replay entries must live.
    pub fn window_secs(&self) -> u64 {
        self.behind_secs.saturating_add(self.ahead_secs)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsedHello<'a> {
    pub client_random: [u8; RANDOM_LEN],
    pub session_id: &'a [u8],
    pub sni: Option<&'a str>,
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<usize> {
        self.take(1).map(|b| usize::from(b[0]))
    }

    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
}

fn find_sni(after_session_id: &[u8]) -> Option<&str> {
    let mut body = Cursor(after_session_id);
    let suites = body.u16()?;
    body.take(suites)?;
    let compression = body.u8()?;
    body.take(compression)?;
    let extensions_len = body.u16()?;
    let mut extensions = Cursor(body.take(extensions_len)?);
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        let len = extensions.u16()?;
        let data = extensions.take(len)?;
        if kind != 0 {
            continue;
        }
        let mut names = Cursor(data);
        let list_len = names.u16()?;
        let mut list = Cursor(names.take(list_len)?);
        while !list.0.is_empty() {
            let name_type = list.u8()?;
            let name_len = list.u16()?;
            let name = list.take(name_len)?;
            if name_type == 0 {
                return std::str::from_utf8(name).ok();
            }
        }
        return None;
    }
    None
}

/// Structural parse of a full ClientHello record (header included).
/// The SNI is best effort: mtprotoproxy never reads it, so a hello without a
/// parseable SNI is still accepted.
pub fn parse_client_hello(record: &[u8]) -> Result<ParsedHello<'_>, HelloError> {
    if record.len() < RECORD_HEADER_LEN + MIN_CLIENT_HELLO_PAYLOAD
        || record[..3] != [TYPE_HANDSHAKE, 0x03, 0x01]
        || usize::from(u16::from_be_bytes([record[3], record[4]]))
            != record.len() - RECORD_HEADER_LEN
        || record[5] != 0x01
    {
        return Err(HelloError::Malformed);
    }
    let session_id_len = usize::from(record[SESSION_ID_LEN_POS]);
    if session_id_len > MAX_SESSION_ID_LEN {
        return Err(HelloError::Malformed);
    }
    let session_id = &record[SESSION_ID_POS..SESSION_ID_POS + session_id_len];
    let mut client_random = [0u8; RANDOM_LEN];
    client_random.copy_from_slice(&record[RANDOM_POS..SESSION_ID_LEN_POS]);
    Ok(ParsedHello {
        client_random,
        session_id,
        sni: find_sni(&record[SESSION_ID_POS + session_id_len..]),
    })
}

#[derive(Debug, PartialEq, Eq)]
pub struct ClientHello<'a> {
    /// Index into the secrets slice of the secret that signed this hello.
    pub secret_index: usize,
    pub client_random: [u8; RANDOM_LEN],
    pub session_id: &'a [u8],
    pub sni: Option<&'a str>,
    pub timestamp: u32,
}

fn client_hello_digest(key: &[u8], record: &[u8]) -> [u8; 32] {
    hmac_sha256(
        key,
        &[
            &record[..RANDOM_POS],
            &[0u8; RANDOM_LEN],
            &record[SESSION_ID_LEN_POS..],
        ],
    )
}

/// Checks the ClientHello digest against each secret and the embedded timestamp
/// against `skew`. Replay detection is the caller's job (see `replay`).
pub fn verify_client_hello<'a>(
    record: &'a [u8],
    secrets: &[Secret],
    now_unix: u64,
    skew: &SkewPolicy,
) -> Result<ClientHello<'a>, HelloError> {
    let parsed = parse_client_hello(record)?;
    let mut error = HelloError::BadDigest;
    for (secret_index, secret) in secrets.iter().enumerate() {
        let digest = client_hello_digest(&secret.key, record);
        if !ct_eq(
            &digest[..DIGEST_PREFIX_LEN],
            &parsed.client_random[..DIGEST_PREFIX_LEN],
        ) {
            continue;
        }
        let mut ts = [0u8; 4];
        for (i, b) in ts.iter_mut().enumerate() {
            *b = digest[DIGEST_PREFIX_LEN + i] ^ parsed.client_random[DIGEST_PREFIX_LEN + i];
        }
        let timestamp = u32::from_le_bytes(ts);
        if !skew.allows(now_unix, timestamp) {
            let now = i64::try_from(now_unix).unwrap_or(i64::MAX);
            error = HelloError::BadTimestamp {
                skew_secs: i64::from(timestamp).saturating_sub(now),
            };
            continue;
        }
        return Ok(ClientHello {
            secret_index,
            client_random: parsed.client_random,
            session_id: parsed.session_id,
            sni: parsed.sni,
            timestamp,
        });
    }
    Err(error)
}

/// `n² mod (2^255 - 19)`, little-endian. mtprotoproxy fills the key_share with
/// a quadratic residue instead of plain random bytes.
fn square_mod_p(n: &[u8; 32]) -> [u8; 32] {
    let mut a = [0u64; 4];
    for (i, limb) in a.iter_mut().enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&n[i * 8..i * 8 + 8]);
        *limb = u64::from_le_bytes(bytes);
    }

    let mut wide = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let cur = u128::from(wide[i + j]) + u128::from(a[i]) * u128::from(a[j]) + carry;
            wide[i + j] = cur as u64;
            carry = cur >> 64;
        }
        wide[i + 4] = carry as u64;
    }

    // 2^256 ≡ 38 (mod p): fold the high half into the low half.
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let cur = u128::from(wide[i]) + u128::from(wide[i + 4]) * 38 + carry;
        r[i] = cur as u64;
        carry = cur >> 64;
    }
    let mut extra = carry as u64 * 38;
    while extra != 0 {
        let mut c = u128::from(extra);
        for limb in r.iter_mut() {
            let cur = u128::from(*limb) + c;
            *limb = cur as u64;
            c = cur >> 64;
        }
        extra = c as u64 * 38;
    }

    // 2^255 ≡ 19 (mod p): fold bit 255. Two rounds bring r below 2^255.
    let add_small = |r: &mut [u64; 4], value: u64| {
        let mut c = u128::from(value);
        for limb in r.iter_mut() {
            let cur = u128::from(*limb) + c;
            *limb = cur as u64;
            c = cur >> 64;
        }
    };
    for _ in 0..2 {
        let top = r[3] >> 63;
        r[3] &= u64::MAX >> 1;
        add_small(&mut r, top * 19);
    }
    // r is in [0, 2^255); subtract p once if r >= p, i.e. if r + 19 reaches 2^255.
    let mut plus19 = r;
    add_small(&mut plus19, 19);
    if plus19[3] >> 63 == 1 {
        plus19[3] &= u64::MAX >> 1;
        r = plus19;
    }

    let mut out = [0u8; 32];
    for (i, limb) in r.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

fn fake_x25519_public(rng: &mut impl RngCore) -> [u8; 32] {
    let mut n = [0u8; 32];
    rng.fill_bytes(&mut n);
    square_mod_p(&n)
}

/// Builds the full fake-tls response: ServerHello, ChangeCipherSpec and one
/// application-data record of `cert_len` random bytes. Layout follows mtprotoproxy.
pub fn build_server_hello(
    key: &[u8],
    client_random: &[u8; RANDOM_LEN],
    session_id: &[u8],
    cert_len: usize,
    rng: &mut impl RngCore,
) -> Vec<u8> {
    let session_id = &session_id[..session_id.len().min(MAX_SESSION_ID_LEN)];
    let cert_len = cert_len.min(MAX_RECORD_PAYLOAD);

    let mut hello = Vec::with_capacity(96 + session_id.len());
    hello.extend_from_slice(&VERSION_TLS12);
    hello.extend_from_slice(&[0u8; RANDOM_LEN]);
    hello.push(session_id.len() as u8);
    hello.extend_from_slice(session_id);
    // TLS_AES_128_GCM_SHA256, no compression. Fixed: every client offers it.
    hello.extend_from_slice(&[0x13, 0x01, 0x00]);
    // Extensions (0x2e bytes): key_share x25519, then supported_versions = TLS 1.3.
    hello.extend_from_slice(&[0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    hello.extend_from_slice(&fake_x25519_public(rng));
    hello.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

    let mut out = Vec::with_capacity(hello.len() + 20 + cert_len);
    out.push(TYPE_HANDSHAKE);
    out.extend_from_slice(&VERSION_TLS12);
    out.extend_from_slice(&((hello.len() + 4) as u16).to_be_bytes());
    out.push(0x02);
    out.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&hello);
    out.extend_from_slice(&CHANGE_CIPHER_SPEC_RECORD);
    out.extend_from_slice(&record_header(cert_len));
    let cert_start = out.len();
    out.resize(cert_start + cert_len, 0);
    rng.fill_bytes(&mut out[cert_start..]);

    let digest = hmac_sha256(key, &[client_random, &out]);
    out[RANDOM_POS..RANDOM_POS + RANDOM_LEN].copy_from_slice(&digest);
    out
}

/// Client-side check of a fake-tls response. Used by tests and the load generator.
pub fn verify_server_hello(key: &[u8], client_random: &[u8; RANDOM_LEN], response: &[u8]) -> bool {
    if response.len() < RANDOM_POS + RANDOM_LEN {
        return false;
    }
    let digest = hmac_sha256(
        key,
        &[
            client_random,
            &response[..RANDOM_POS],
            &[0u8; RANDOM_LEN],
            &response[RANDOM_POS + RANDOM_LEN..],
        ],
    );
    ct_eq(&digest, &response[RANDOM_POS..RANDOM_POS + RANDOM_LEN])
}

/// A 517-byte Chrome-like ClientHello with a random `client_random`, following
/// mtprotoproxy's `gen_tls_client_hello_msg`. Returns `None` if the name is too
/// long to fit. Used by tests and the load generator; sign it with
/// [`sign_client_hello`].
pub fn client_hello_template(server_name: &str, rng: &mut impl RngCore) -> Option<Vec<u8>> {
    const TOTAL_LEN: usize = 517;
    let name = server_name.as_bytes();
    let mut random = [0u8; 32];
    let mut session_id = [0u8; 32];
    rng.fill_bytes(&mut random);
    rng.fill_bytes(&mut session_id);

    let mut msg = Vec::with_capacity(TOTAL_LEN);
    msg.extend_from_slice(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03");
    msg.extend_from_slice(&random);
    msg.push(0x20);
    msg.extend_from_slice(&session_id);
    msg.extend_from_slice(
        b"\x00\x22\x4a\x4a\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\
          \xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a\x01\x00\x01\x91\
          \xda\xda\x00\x00\x00\x00",
    );
    msg.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
    msg.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    msg.push(0x00);
    msg.extend_from_slice(&(name.len() as u16).to_be_bytes());
    msg.extend_from_slice(name);
    msg.extend_from_slice(
        b"\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0a\x00\x08\xaa\xaa\x00\x1d\x00\
          \x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10\x00\x0e\x00\x0c\x02\
          \x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00\
          \x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\
          \x06\x01\x02\x01\x00\x12\x00\x00\x00\x33\x00\x2b\x00\x29\xaa\xaa\x00\x01\x00\x00\
          \x1d\x00\x20",
    );
    msg.extend_from_slice(&fake_x25519_public(rng));
    msg.extend_from_slice(
        b"\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x0b\x0a\xba\xba\x03\x04\x03\x03\x03\x02\x03\
          \x01\x00\x1b\x00\x03\x02\x00\x02\x3a\x3a\x00\x01\x00\x00\x15",
    );
    let padding = TOTAL_LEN.checked_sub(msg.len() + 2)?;
    msg.extend_from_slice(&(padding as u16).to_be_bytes());
    msg.resize(TOTAL_LEN, 0);
    Some(msg)
}

/// Writes the fake-tls digest and timestamp into a ClientHello record's random.
pub fn sign_client_hello(record: &mut [u8], key: &[u8], timestamp: u32) {
    if record.len() < SESSION_ID_LEN_POS {
        return;
    }
    let mut digest = client_hello_digest(key, record);
    for (d, t) in digest[DIGEST_PREFIX_LEN..]
        .iter_mut()
        .zip(timestamp.to_le_bytes())
    {
        *d ^= t;
    }
    record[RANDOM_POS..SESSION_ID_LEN_POS].copy_from_slice(&digest);
}

/// Header of an application-data record. `len` must fit in a u16.
pub fn record_header(len: usize) -> [u8; RECORD_HEADER_LEN] {
    let len = (len as u16).to_be_bytes();
    [
        TYPE_APPLICATION_DATA,
        VERSION_TLS12[0],
        VERSION_TLS12[1],
        len[0],
        len[1],
    ]
}

/// Appends `payload` to `out` as application-data records of at most 16384 bytes.
pub fn wrap_records(payload: &[u8], out: &mut Vec<u8>) {
    for chunk in payload.chunks(MAX_RECORD_PAYLOAD) {
        out.extend_from_slice(&record_header(chunk.len()));
        out.extend_from_slice(chunk);
    }
}

/// Incremental unwrapping of the client's record stream. Holds only the
/// partial header and the bytes left in the current record, so the payload is
/// never buffered and records may be split across reads at any point.
#[derive(Debug, Default)]
pub struct RecordReader {
    header: [u8; RECORD_HEADER_LEN],
    header_len: u8,
    remaining: u16,
    skip: bool,
}

impl RecordReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Strips record framing from `buf[..len]` in place and returns the
    /// payload length; the payload ends up at the start of `buf`.
    /// ChangeCipherSpec records are dropped wherever they appear.
    pub fn unwrap_in_place(&mut self, buf: &mut [u8], len: usize) -> Result<usize, RecordError> {
        let mut read = 0;
        let mut written = 0;
        while read < len {
            if self.remaining == 0 {
                let want = RECORD_HEADER_LEN - usize::from(self.header_len);
                let take = want.min(len - read);
                let at = usize::from(self.header_len);
                self.header[at..at + take].copy_from_slice(&buf[read..read + take]);
                self.header_len += take as u8;
                read += take;
                if usize::from(self.header_len) < RECORD_HEADER_LEN {
                    break;
                }
                self.header_len = 0;
                self.skip = match self.header[0] {
                    TYPE_APPLICATION_DATA => false,
                    TYPE_CHANGE_CIPHER_SPEC => true,
                    _ => return Err(RecordError::BadType),
                };
                if self.header[1..3] != VERSION_TLS12 {
                    return Err(RecordError::BadVersion);
                }
                self.remaining = u16::from_be_bytes([self.header[3], self.header[4]]);
            } else {
                let take = usize::from(self.remaining).min(len - read);
                if !self.skip {
                    buf.copy_within(read..read + take, written);
                    written += take;
                }
                read += take;
                self.remaining -= take as u16;
            }
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const NOW: u64 = 1_800_000_000;
    const SKEW: SkewPolicy = SkewPolicy {
        behind_secs: 600,
        ahead_secs: 1200,
        accept_uptime: true,
    };

    fn rejected(skew_secs: i64) -> HelloError {
        HelloError::BadTimestamp { skew_secs }
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(7)
    }

    fn secret(key_byte: u8) -> Secret {
        Secret {
            key: [key_byte; 16],
            domain: "www.example.com".to_owned(),
        }
    }

    fn signed_hello(secret: &Secret, timestamp: u32) -> Vec<u8> {
        let mut record = client_hello_template(&secret.domain, &mut rng()).unwrap();
        sign_client_hello(&mut record, &secret.key, timestamp);
        record
    }

    #[test]
    fn template_is_a_well_formed_517_byte_hello() {
        let record = client_hello_template("www.example.com", &mut rng()).unwrap();
        assert_eq!(record.len(), 517);
        let parsed = parse_client_hello(&record).unwrap();
        assert_eq!(parsed.sni, Some("www.example.com"));
        assert_eq!(parsed.session_id.len(), 32);
        assert_eq!(parsed.client_random, record[11..43]);
        assert!(client_hello_template(&"a".repeat(300), &mut rng()).is_none());
    }

    #[test]
    fn valid_hello_is_accepted() {
        let secrets = [secret(1)];
        let record = signed_hello(&secrets[0], NOW as u32);
        let hello = verify_client_hello(&record, &secrets, NOW, &SKEW).unwrap();
        assert_eq!(hello.secret_index, 0);
        assert_eq!(hello.timestamp, NOW as u32);
        assert_eq!(hello.session_id, &record[44..76]);
        assert_eq!(hello.sni, Some("www.example.com"));
        assert_eq!(hello.client_random, record[11..43]);
    }

    #[test]
    fn matching_secret_is_found_among_several() {
        let secrets = [secret(1), secret(2), secret(3)];
        let record = signed_hello(&secrets[2], NOW as u32);
        let hello = verify_client_hello(&record, &secrets, NOW, &SKEW).unwrap();
        assert_eq!(hello.secret_index, 2);
    }

    #[test]
    fn bad_hmac_is_rejected() {
        let secrets = [secret(1)];
        let record = signed_hello(&secret(9), NOW as u32);
        assert_eq!(
            verify_client_hello(&record, &secrets, NOW, &SKEW),
            Err(HelloError::BadDigest)
        );
        assert_eq!(
            verify_client_hello(&record, &[], NOW, &SKEW),
            Err(HelloError::BadDigest)
        );
    }

    #[test]
    fn any_flipped_bit_breaks_the_digest() {
        let secrets = [secret(1)];
        let record = signed_hello(&secrets[0], NOW as u32);
        // Every position outside the 4 timestamp bytes and the framing checked by the parser.
        for pos in (5..39).chain(43..record.len()).step_by(3) {
            let mut tampered = record.clone();
            tampered[pos] ^= 0x01;
            assert!(
                verify_client_hello(&tampered, &secrets, NOW, &SKEW).is_err(),
                "byte {pos}"
            );
        }
    }

    #[test]
    fn timestamp_window_matches_the_reference() {
        let secrets = [secret(1)];
        let check = |timestamp: u64| {
            let record = signed_hello(&secrets[0], timestamp as u32);
            verify_client_hello(&record, &secrets, NOW, &SKEW).map(|h| h.timestamp)
        };
        // Client behind the proxy: allowed up to (not including) 600 s.
        assert!(check(NOW - 599).is_ok());
        assert_eq!(check(NOW - 600), Err(rejected(-600)));
        // Client ahead of the proxy: allowed up to (not including) 1200 s.
        assert!(check(NOW + 1199).is_ok());
        assert_eq!(check(NOW + 1200), Err(rejected(1200)));
        assert_eq!(check(NOW - 86_400), Err(rejected(-86_400)));
    }

    #[test]
    fn fifteen_minute_skew_is_asymmetric_like_the_reference() {
        // mtprotoproxy: -20 min < server_now - client_timestamp < 10 min. A client
        // clock 15 min behind gives +900 (rejected); 15 min ahead gives -900 (accepted).
        let secrets = [secret(1)];
        let behind = signed_hello(&secrets[0], (NOW - 900) as u32);
        assert_eq!(
            verify_client_hello(&behind, &secrets, NOW, &SKEW),
            Err(rejected(-900))
        );
        let ahead = signed_hello(&secrets[0], (NOW + 900) as u32);
        assert!(verify_client_hello(&ahead, &secrets, NOW, &SKEW).is_ok());
    }

    #[test]
    fn uptime_timestamps_follow_the_policy() {
        let secrets = [secret(1)];
        let strict = SkewPolicy {
            accept_uptime: false,
            ..SKEW
        };
        for timestamp in [0, 12_345, UPTIME_TIMESTAMP_LIMIT - 1] {
            let record = signed_hello(&secrets[0], timestamp);
            assert!(verify_client_hello(&record, &secrets, NOW, &SKEW).is_ok());
            assert_eq!(
                verify_client_hello(&record, &secrets, NOW, &strict),
                Err(rejected(i64::from(timestamp) - NOW as i64))
            );
        }
        let record = signed_hello(&secrets[0], UPTIME_TIMESTAMP_LIMIT);
        assert_eq!(
            verify_client_hello(&record, &secrets, NOW, &SKEW),
            Err(rejected(i64::from(UPTIME_TIMESTAMP_LIMIT) - NOW as i64))
        );
    }

    #[test]
    fn rejection_reports_the_offset_and_direction() {
        assert_eq!(
            rejected(-900).to_string(),
            "timestamp outside the allowed window (client clock 900 s behind)"
        );
        assert_eq!(
            rejected(1300).to_string(),
            "timestamp outside the allowed window (client clock 1300 s ahead)"
        );
        assert_eq!(skew_direction(i64::MIN), "behind");
        assert!(rejected(i64::MIN).to_string().contains("behind"));

        // A proxy clock beyond i64 range must not overflow the subtraction.
        let secrets = [secret(1)];
        let record = signed_hello(&secrets[0], u32::MAX);
        let strict = SkewPolicy {
            behind_secs: 1,
            ahead_secs: 1,
            accept_uptime: false,
        };
        assert!(matches!(
            verify_client_hello(&record, &secrets, u64::MAX, &strict),
            Err(HelloError::BadTimestamp { skew_secs }) if skew_secs < 0
        ));
    }

    #[test]
    fn skew_policy_handles_extreme_values() {
        let wide = SkewPolicy {
            behind_secs: u64::MAX,
            ahead_secs: u64::MAX,
            accept_uptime: false,
        };
        assert!(wide.allows(0, u32::MAX));
        assert!(wide.allows(u64::MAX - 1, 0));
        assert_eq!(wide.window_secs(), u64::MAX);
        let none = SkewPolicy {
            behind_secs: 0,
            ahead_secs: 0,
            accept_uptime: false,
        };
        assert!(!none.allows(NOW, NOW as u32));
        assert_eq!(SKEW.window_secs(), 1800);
    }

    #[test]
    fn replayed_hello_is_rejected_by_the_cache() {
        use crate::replay::ReplayCache;
        use std::time::Duration;

        let secrets = [secret(1)];
        let cache = ReplayCache::new(Duration::from_secs(SKEW.window_secs()), 1024);
        let record = signed_hello(&secrets[0], NOW as u32);

        let first = verify_client_hello(&record, &secrets, NOW, &SKEW).unwrap();
        assert!(cache.check_and_insert(&first.client_random));
        let second = verify_client_hello(&record, &secrets, NOW + 5, &SKEW).unwrap();
        assert!(!cache.check_and_insert(&second.client_random));
    }

    #[test]
    fn malformed_hellos_are_rejected() {
        let secrets = [secret(1)];
        let good = signed_hello(&secrets[0], NOW as u32);
        let reject = |record: &[u8]| {
            assert_eq!(
                verify_client_hello(record, &secrets, NOW, &SKEW),
                Err(HelloError::Malformed)
            );
        };

        reject(&[]);
        reject(&good[..5]);
        reject(&good[..43]);
        reject(&good[..good.len() - 1]);

        for (pos, value) in [(0, 0x17), (1, 0x02), (2, 0x03), (5, 0x02), (4, 0x01)] {
            let mut bad = good.clone();
            bad[pos] = value;
            reject(&bad);
        }

        let mut long_session = good.clone();
        long_session[43] = 33;
        reject(&long_session);

        // Below the 512-byte payload minimum, even with consistent framing.
        let mut short = good[..5 + 511].to_vec();
        short[3..5].copy_from_slice(&511u16.to_be_bytes());
        reject(&short);
    }

    #[test]
    fn sni_parsing_is_best_effort() {
        let secrets = [secret(1)];
        let mut record = client_hello_template("www.example.com", &mut rng()).unwrap();
        // Corrupt the extensions length; the hello still verifies, just without an SNI.
        let ext_len_pos = 76 + 2 + 0x22 + 2;
        assert_eq!(record[ext_len_pos..ext_len_pos + 2], [0x01, 0x91]);
        record[ext_len_pos] = 0xff;
        sign_client_hello(&mut record, &secrets[0].key, NOW as u32);
        let hello = verify_client_hello(&record, &secrets, NOW, &SKEW).unwrap();
        assert_eq!(hello.sni, None);

        assert_eq!(find_sni(&[]), None);
        assert_eq!(find_sni(&[0x00, 0x02, 0x13]), None);
        assert_eq!(find_sni(&[0x00, 0x00, 0x00, 0x00, 0x00]), None);
    }

    #[test]
    fn empty_session_id_is_supported() {
        let secrets = [secret(1)];
        let template = client_hello_template("www.example.com", &mut rng()).unwrap();
        let mut record = template[..43].to_vec();
        record.push(0);
        record.extend_from_slice(&template[76..]);
        record.resize(517, 0);
        sign_client_hello(&mut record, &secrets[0].key, NOW as u32);
        let hello = verify_client_hello(&record, &secrets, NOW, &SKEW).unwrap();
        assert!(hello.session_id.is_empty());
        assert_eq!(hello.sni, Some("www.example.com"));
    }

    #[test]
    fn server_hello_layout() {
        let key = [5u8; 16];
        let client_random = [0xabu8; 32];
        let session_id = [0x11u8; 32];
        let out = build_server_hello(&key, &client_random, &session_id, 2000, &mut rng());

        // ServerHello record: 5 header + 4 handshake header + 122 body.
        assert_eq!(out[..5], [0x16, 0x03, 0x03, 0x00, 0x7a]);
        assert_eq!(out[5..9], [0x02, 0x00, 0x00, 0x76]);
        assert_eq!(out[9..11], [0x03, 0x03]);
        assert_eq!(out[43], 32);
        assert_eq!(out[44..76], session_id);
        assert_eq!(out[76..79], [0x13, 0x01, 0x00]);
        assert_eq!(
            out[79..89],
            [0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]
        );
        assert_eq!(out[121..127], [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        assert_eq!(out[127..133], CHANGE_CIPHER_SPEC_RECORD);
        assert_eq!(out[133..138], [0x17, 0x03, 0x03, 0x07, 0xd0]);
        assert_eq!(out.len(), 138 + 2000);
    }

    #[test]
    fn server_hello_digest() {
        let key = [5u8; 16];
        let client_random = [0xabu8; 32];
        let out = build_server_hello(&key, &client_random, &[0x11; 32], 1500, &mut rng());

        let mut zeroed = out.clone();
        zeroed[11..43].fill(0);
        let mut message = client_random.to_vec();
        message.extend_from_slice(&zeroed);
        assert_eq!(out[11..43], hmac_sha256(&key, &[&message]));

        assert!(verify_server_hello(&key, &client_random, &out));
        assert!(!verify_server_hello(&[6u8; 16], &client_random, &out));
        assert!(!verify_server_hello(&key, &[0xac; 32], &out));
        let mut tampered = out.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(!verify_server_hello(&key, &client_random, &tampered));
        assert!(!verify_server_hello(&key, &client_random, &out[..20]));
    }

    #[test]
    fn server_hello_echoes_short_and_clamps_long_session_ids() {
        let key = [5u8; 16];
        let random = [1u8; 32];
        let empty = build_server_hello(&key, &random, &[], 1024, &mut rng());
        assert_eq!(empty[43], 0);
        assert_eq!(empty[44..47], [0x13, 0x01, 0x00]);
        assert!(verify_server_hello(&key, &random, &empty));

        let long = build_server_hello(&key, &random, &[7u8; 40], 1024, &mut rng());
        assert_eq!(long[43], 32);
        let huge_cert = build_server_hello(&key, &random, &[], 100_000, &mut rng());
        assert_eq!(huge_cert.len(), 106 + MAX_RECORD_PAYLOAD);
    }

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        assert_eq!(
            hex::encode(hmac_sha256(
                b"Jefe",
                &[b"what do ya want ", b"for nothing?"]
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn square_mod_p_edge_cases() {
        let le = |v: u128| {
            let mut out = [0u8; 32];
            out[..16].copy_from_slice(&v.to_le_bytes());
            out
        };
        assert_eq!(square_mod_p(&le(0)), le(0));
        assert_eq!(square_mod_p(&le(1)), le(1));
        assert_eq!(square_mod_p(&le(12345)), le(12345 * 12345));

        // p - 1 ≡ -1, p ≡ 0, p + 1 ≡ 1, 2^255 ≡ 19, 2^256 - 1 ≡ 37.
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        let mut p_minus_1 = p;
        p_minus_1[0] = 0xec;
        let mut p_plus_1 = p;
        p_plus_1[0] = 0xee;
        let mut two_255 = [0u8; 32];
        two_255[31] = 0x80;
        assert_eq!(square_mod_p(&p_minus_1), le(1));
        assert_eq!(square_mod_p(&p), le(0));
        assert_eq!(square_mod_p(&p_plus_1), le(1));
        assert_eq!(square_mod_p(&two_255), le(361));
        assert_eq!(square_mod_p(&[0xff; 32]), le(1369));
    }

    #[test]
    fn square_mod_p_matches_reference_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/mtprotoproxy.json")).unwrap();
        let cases = vectors["x25519_squares"].as_array().unwrap();
        assert!(cases.len() >= 20);
        for case in cases {
            let n: [u8; 32] = hex::decode(case["n"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                hex::encode(square_mod_p(&n)),
                case["square"].as_str().unwrap(),
                "n = {}",
                case["n"]
            );
        }
    }

    fn unwrap_all(stream: &[u8], chunk_sizes: &[usize]) -> Result<Vec<u8>, RecordError> {
        let mut reader = RecordReader::new();
        let mut out = Vec::new();
        let mut pos = 0;
        let mut sizes = chunk_sizes.iter().cycle();
        while pos < stream.len() {
            let n = (*sizes.next().unwrap()).clamp(1, stream.len() - pos);
            let mut buf = stream[pos..pos + n].to_vec();
            let m = reader.unwrap_in_place(&mut buf, n)?;
            out.extend_from_slice(&buf[..m]);
            pos += n;
        }
        Ok(out)
    }

    #[test]
    fn wrap_splits_at_the_record_limit() {
        let mut out = Vec::new();
        wrap_records(&[], &mut out);
        assert!(out.is_empty());

        wrap_records(&[9u8; MAX_RECORD_PAYLOAD], &mut out);
        assert_eq!(out.len(), 5 + MAX_RECORD_PAYLOAD);
        assert_eq!(out[..5], [0x17, 0x03, 0x03, 0x40, 0x00]);

        out.clear();
        wrap_records(&[9u8; MAX_RECORD_PAYLOAD + 1], &mut out);
        assert_eq!(out.len(), 10 + MAX_RECORD_PAYLOAD + 1);
        let second = 5 + MAX_RECORD_PAYLOAD;
        assert_eq!(out[second..second + 5], [0x17, 0x03, 0x03, 0x00, 0x01]);
    }

    #[test]
    fn reader_skips_change_cipher_spec_anywhere() {
        let mut stream = CHANGE_CIPHER_SPEC_RECORD.to_vec();
        wrap_records(b"hello ", &mut stream);
        stream.extend_from_slice(&CHANGE_CIPHER_SPEC_RECORD);
        stream.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x00]);
        wrap_records(b"world", &mut stream);
        for chunk in [1, 2, 3, 5, 7, 1000] {
            assert_eq!(unwrap_all(&stream, &[chunk]).unwrap(), b"hello world");
        }
    }

    #[test]
    fn reader_accepts_records_larger_than_it_writes() {
        let payload = vec![0x42u8; 65535];
        let mut stream = vec![0x17, 0x03, 0x03, 0xff, 0xff];
        stream.extend_from_slice(&payload);
        assert_eq!(unwrap_all(&stream, &[4096]).unwrap(), payload);
    }

    #[test]
    fn reader_rejects_bad_headers() {
        for header in [
            [0x16, 0x03, 0x03, 0x00, 0x01],
            [0x15, 0x03, 0x03, 0x00, 0x02],
            [0x00, 0x03, 0x03, 0x00, 0x01],
        ] {
            assert_eq!(unwrap_all(&header, &[5]), Err(RecordError::BadType));
            assert_eq!(unwrap_all(&header, &[1]), Err(RecordError::BadType));
        }
        for header in [
            [0x17, 0x03, 0x01, 0x00, 0x01],
            [0x17, 0x03, 0x04, 0x00, 0x01],
            [0x14, 0x02, 0x03, 0x00, 0x01],
        ] {
            assert_eq!(unwrap_all(&header, &[2]), Err(RecordError::BadVersion));
        }
        // A bad header after a good record is still caught.
        let mut stream = Vec::new();
        wrap_records(b"ok", &mut stream);
        stream.extend_from_slice(b"GET / HTTP/1.1\r\n");
        assert_eq!(unwrap_all(&stream, &[3]), Err(RecordError::BadType));
    }

    #[test]
    fn reader_keeps_state_for_truncated_input() {
        let mut stream = Vec::new();
        wrap_records(b"abcdef", &mut stream);
        let mut reader = RecordReader::new();
        let mut head = stream[..8].to_vec();
        assert_eq!(reader.unwrap_in_place(&mut head, 8).unwrap(), 3);
        assert_eq!(&head[..3], b"abc");
        let mut empty = [0u8; 0];
        assert_eq!(reader.unwrap_in_place(&mut empty, 0).unwrap(), 0);
        let mut tail = stream[8..].to_vec();
        assert_eq!(reader.unwrap_in_place(&mut tail, 3).unwrap(), 3);
        assert_eq!(&tail[..3], b"def");
    }

    proptest! {
        #[test]
        fn wrap_then_unwrap_round_trips(
            payload in proptest::collection::vec(any::<u8>(), 0..50_000),
            chunks in proptest::collection::vec(1usize..20_000, 1..8),
        ) {
            let mut stream = Vec::new();
            wrap_records(&payload, &mut stream);
            let records = payload.len().div_ceil(MAX_RECORD_PAYLOAD);
            prop_assert_eq!(stream.len(), payload.len() + records * RECORD_HEADER_LEN);
            prop_assert_eq!(unwrap_all(&stream, &chunks).unwrap(), payload);
        }

        #[test]
        fn unwrap_handles_arbitrary_record_sizes(
            records in proptest::collection::vec(
                (any::<bool>(), proptest::collection::vec(any::<u8>(), 0..3000)), 0..12),
            chunks in proptest::collection::vec(1usize..5000, 1..8),
        ) {
            let mut stream = Vec::new();
            let mut expected = Vec::new();
            for (is_ccs, data) in &records {
                stream.push(if *is_ccs { 0x14 } else { 0x17 });
                stream.extend_from_slice(&[0x03, 0x03]);
                stream.extend_from_slice(&(data.len() as u16).to_be_bytes());
                stream.extend_from_slice(data);
                if !is_ccs {
                    expected.extend_from_slice(data);
                }
            }
            prop_assert_eq!(unwrap_all(&stream, &chunks).unwrap(), expected);
        }

        #[test]
        fn parsers_never_panic_on_garbage(
            data in proptest::collection::vec(any::<u8>(), 0..2000),
            keep_prefix in any::<bool>(),
        ) {
            let mut record = data.clone();
            if keep_prefix && record.len() >= 6 {
                // Get past the framing checks so the body parser is exercised.
                record[..3].copy_from_slice(&[0x16, 0x03, 0x01]);
                let len = (record.len() - 5) as u16;
                record[3..5].copy_from_slice(&len.to_be_bytes());
                record[5] = 0x01;
            }
            let _ = verify_client_hello(&record, &[secret(1)], NOW, &SKEW);
            let _ = find_sni(&data);
            let mut buf = data.clone();
            let _ = RecordReader::new().unwrap_in_place(&mut buf, data.len());
        }

        #[test]
        fn signed_hello_verifies_for_any_key_and_time(
            key in any::<[u8; 16]>(),
            offset in -599i64..1200,
        ) {
            let secret = Secret { key, domain: "example.org".to_owned() };
            let timestamp = (NOW as i64 + offset) as u32;
            let record = signed_hello(&secret, timestamp);
            let hello = verify_client_hello(&record, &[secret], NOW, &SKEW).unwrap();
            prop_assert_eq!(hello.timestamp, timestamp);
        }
    }
}
