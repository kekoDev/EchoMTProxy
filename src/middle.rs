//! Middle-proxy upstream, as in mtprotoproxy: instead of a DC, the proxy talks
//! to one of Telegram's middle proxies, which is what makes the sponsored
//! channel (ad tag) possible.
//!
//! Unlike the direct modes this one has to see message boundaries. Each
//! client message (a padded-intermediate frame) becomes one `RPC_PROXY_REQ`
//! frame carrying the client's address and the ad tag; frames are numbered,
//! CRC32-checked, padded to the AES block size and sent through AES-256-CBC.
//! Message contents are still never looked at beyond their first 8 bytes,
//! which tell whether the message is unencrypted.
//!
//! Both directions are transformed as a stream: a message of any size passes
//! through fixed per-session state and pooled buffers.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::Aes256;
use cbc::cipher::inout::InOutBuf;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5::Md5;
use rand::seq::SliceRandom;
use rand::Rng;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const AD_TAG_LEN: usize = 16;
const BLOCK: usize = 16;
const NONCE_LEN: usize = 16;

const RPC_NONCE: [u8; 4] = [0xaa, 0x87, 0xcb, 0x7a];
const RPC_HANDSHAKE: [u8; 4] = [0xf5, 0xee, 0x82, 0x76];
const RPC_PROXY_REQ: [u8; 4] = [0xee, 0xf1, 0xce, 0x36];
const RPC_PROXY_ANS: [u8; 4] = [0x0d, 0xda, 0x03, 0x44];
const RPC_CLOSE_EXT: [u8; 4] = [0xa2, 0x34, 0xb6, 0x5e];
const RPC_SIMPLE_ACK: [u8; 4] = [0x9b, 0x40, 0xac, 0x3b];
const CRYPTO_AES: [u8; 4] = [1, 0, 0, 0];
const PROCESS_ID: &[u8; 12] = b"IPIPPRPDTIME";
/// A whole word of padding between frames; reads as a frame length of 4.
const PADDING_WORD: [u8; 4] = [4, 0, 0, 0];
const START_SEQ: i32 = -2;

const FLAG_NOT_ENCRYPTED: u32 = 0x2;
const FLAG_HAS_AD_TAG: u32 = 0x8;
const FLAG_MAGIC: u32 = 0x1000;
const FLAG_EXTMODE2: u32 = 0x2_0000;
const FLAG_PAD: u32 = 0x800_0000;
const FLAG_INTERMEDIATE: u32 = 0x2000_0000;
const FLAG_QUICKACK: u32 = 0x8000_0000;

/// Frame overhead: length, sequence number and CRC32.
const FRAME_OVERHEAD: usize = 12;
const MIN_FRAME_LEN: usize = FRAME_OVERHEAD;
const MAX_FRAME_LEN: usize = 1 << 24;
/// Largest client message accepted, so its frame stays within `MAX_FRAME_LEN`.
const MAX_CLIENT_MESSAGE: usize = MAX_FRAME_LEN - 256;

/// Telegram's middle-proxy secret (core.telegram.org/getProxySecret).
const DEFAULT_SECRET_HEX: &str = "c4f9faca9678e6bb48ad6c7e2ce5c0d24430645d554addeb55419e034da62721\
     d046eaab6e52ab14a95a443ecfb3463e79a05a66612adf9caeda8be9a80da698\
     6fb0a6ff387af84d88ef3a6413713e5c3377f6e1a3d47d99f5e0c56eece8f05c\
     54c490b079e31bef82ff0ee8f2b0a32756d249c5f21269816cb7061b265db212";

/// Used until `middle_proxy_config_files` is set. Telegram changes this list;
/// the files are the supported way to keep it current.
const DEFAULT_PROXIES: &str = "
proxy_for 1 149.154.175.50:8888;
proxy_for -1 149.154.175.50:8888;
proxy_for 2 149.154.161.144:8888;
proxy_for -2 149.154.161.184:8888;
proxy_for 3 149.154.175.100:8888;
proxy_for -3 149.154.175.100:8888;
proxy_for 4 91.108.4.136:8888;
proxy_for -4 149.154.165.109:8888;
proxy_for 5 91.108.56.107:8888;
proxy_for -5 91.108.56.107:8888;
proxy_for 1 [2001:b28:f23d:f001::d]:8888;
proxy_for -1 [2001:b28:f23d:f001::d]:8888;
proxy_for 2 [2001:67c:4e8:f002::d]:80;
proxy_for -2 [2001:67c:4e8:f002::d]:80;
proxy_for 3 [2001:b28:f23d:f003::d]:8888;
proxy_for -3 [2001:b28:f23d:f003::d]:8888;
proxy_for 4 [2001:67c:4e8:f004::d]:8888;
proxy_for -4 [2001:67c:4e8:f004::d]:8888;
proxy_for 5 [2001:b28:f23f:f005::d]:8888;
proxy_for -5 [2001:b28:f23f:f005::d]:8888;
";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame length {0} is out of range")]
    BadLength(u32),
    #[error("unexpected frame sequence number")]
    BadSequence,
    #[error("frame checksum mismatch")]
    BadChecksum,
    #[error("frame too short for its type")]
    Truncated,
}

impl From<FrameError> for io::Error {
    fn from(err: FrameError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }
}

/// AES-256-CBC over whole blocks, in place, keeping the chain between calls.
pub struct CbcEnc(cbc::Encryptor<Aes256>);
pub struct CbcDec(cbc::Decryptor<Aes256>);

impl CbcEnc {
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self(cbc::Encryptor::new(key.into(), iv.into()))
    }

    /// `buf` must be a whole number of blocks.
    pub fn apply(&mut self, buf: &mut [u8]) {
        debug_assert_eq!(buf.len() % BLOCK, 0);
        let (blocks, _) = InOutBuf::from(buf).into_chunks();
        self.0.encrypt_blocks_inout_mut(blocks);
    }
}

impl CbcDec {
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self(cbc::Decryptor::new(key.into(), iv.into()))
    }

    /// `buf` must be a whole number of blocks.
    pub fn apply(&mut self, buf: &mut [u8]) {
        debug_assert_eq!(buf.len() % BLOCK, 0);
        let (blocks, _) = InOutBuf::from(buf).into_chunks();
        self.0.decrypt_blocks_inout_mut(blocks);
    }
}

/// Inputs of the middle-proxy key derivation. `client` is the side that
/// connected (this proxy, by its public address), `server` the middle proxy.
pub struct KeyInput<'a> {
    pub nonce_server: [u8; NONCE_LEN],
    pub nonce_client: [u8; NONCE_LEN],
    pub client_timestamp: [u8; 4],
    pub server: SocketAddr,
    pub client: SocketAddr,
    pub secret: &'a [u8],
}

#[derive(Clone, Copy)]
pub enum Purpose {
    /// Key for what the connecting side sends.
    Client,
    /// Key for what the middle proxy sends.
    Server,
}

/// Key and IV for one direction, as in mtprotoproxy's
/// `get_middleproxy_aes_key_and_iv`.
pub fn derive_key(input: &KeyInput<'_>, purpose: Purpose) -> ([u8; 32], [u8; 16]) {
    let purpose: &[u8; 6] = match purpose {
        Purpose::Client => b"CLIENT",
        Purpose::Server => b"SERVER",
    };
    // IPv4 addresses go in reversed; over IPv6 those fields are zero and the
    // full addresses are appended instead.
    let (server_v4, client_v4, v6) = match (input.server.ip(), input.client.ip()) {
        (IpAddr::V4(server), IpAddr::V4(client)) => {
            let (mut s, mut c) = (server.octets(), client.octets());
            s.reverse();
            c.reverse();
            (s, c, None)
        }
        (server, client) => ([0; 4], [0; 4], Some((to_v6(client), to_v6(server)))),
    };

    let mut s = Vec::with_capacity(96 + input.secret.len());
    s.extend_from_slice(&input.nonce_server);
    s.extend_from_slice(&input.nonce_client);
    s.extend_from_slice(&input.client_timestamp);
    s.extend_from_slice(&server_v4);
    s.extend_from_slice(&input.client.port().to_le_bytes());
    s.extend_from_slice(purpose);
    s.extend_from_slice(&client_v4);
    s.extend_from_slice(&input.server.port().to_le_bytes());
    s.extend_from_slice(input.secret);
    s.extend_from_slice(&input.nonce_server);
    if let Some((client, server)) = v6 {
        s.extend_from_slice(&client);
        s.extend_from_slice(&server);
    }
    s.extend_from_slice(&input.nonce_client);

    let mut key = [0u8; 32];
    key[..12].copy_from_slice(&Md5::digest(&s[1..])[..12]);
    key[12..].copy_from_slice(&Sha1::digest(&s));
    let iv: [u8; 16] = Md5::digest(&s[2..]).into();
    (key, iv)
}

fn to_v6(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    }
}

/// Address and port as they appear in `RPC_PROXY_REQ`: an IPv6 (or
/// IPv4-mapped) address and a 4-byte port.
fn rpc_addr(addr: SocketAddr) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[..16].copy_from_slice(&to_v6(addr.ip()));
    out[16..].copy_from_slice(&u32::from(addr.port()).to_le_bytes());
    out
}

/// One frame: length, sequence number, message, CRC32, then padding words up
/// to the AES block size.
pub fn build_frame(seq: i32, msg: &[u8]) -> Vec<u8> {
    let len = msg.len() + FRAME_OVERHEAD;
    let mut out = Vec::with_capacity(len + BLOCK);
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(msg);
    let crc = crc32fast::hash(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    while !out.len().is_multiple_of(BLOCK) {
        out.extend_from_slice(&PADDING_WORD);
    }
    out
}

/// Takes one frame off the front of `buf` (plaintext), skipping padding
/// words. `Ok(None)` means more bytes are needed.
fn take_frame(buf: &mut Vec<u8>, seq: i32) -> Result<Option<Vec<u8>>, FrameError> {
    let mut skip = 0;
    while buf.len() >= skip + 4 && buf[skip..skip + 4] == PADDING_WORD {
        skip += 4;
    }
    if buf.len() < skip + 4 {
        return Ok(None);
    }
    let len_field = u32::from_le_bytes([buf[skip], buf[skip + 1], buf[skip + 2], buf[skip + 3]]);
    let len = len_field as usize;
    if !(MIN_FRAME_LEN..=MAX_FRAME_LEN).contains(&len) || !len.is_multiple_of(4) {
        return Err(FrameError::BadLength(len_field));
    }
    if buf.len() < skip + len {
        return Ok(None);
    }
    let frame = &buf[skip..skip + len];
    if frame[4..8] != seq.to_le_bytes() {
        return Err(FrameError::BadSequence);
    }
    let (body, crc) = frame.split_at(len - 4);
    if crc32fast::hash(body).to_le_bytes() != crc {
        return Err(FrameError::BadChecksum);
    }
    let msg = body[8..].to_vec();
    buf.drain(..skip + len);
    Ok(Some(msg))
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// A handshaken connection to a middle proxy, ready to carry one client.
pub struct Connected {
    pub enc: CbcEnc,
    pub dec: CbcDec,
    /// Decrypted bytes that arrived behind the handshake answer.
    pub pending: Vec<u8>,
    /// This proxy's address as the middle proxy knows it.
    pub our_addr: SocketAddr,
}

/// Runs the nonce and handshake exchange on a fresh connection.
///
/// `public_ip` is this host's address as Telegram sees it; the keys depend on
/// it, so behind NAT it must be configured. `None` uses the socket's own.
pub async fn handshake(
    stream: &mut TcpStream,
    secret: &[u8],
    public_ip: Option<IpAddr>,
) -> io::Result<Connected> {
    if secret.len() < 4 {
        return Err(bad("middle-proxy secret is too short"));
    }
    let server = stream.peer_addr()?;
    let local = stream.local_addr()?;
    let our_addr = SocketAddr::new(public_ip.unwrap_or_else(|| local.ip()), local.port());

    let nonce: [u8; NONCE_LEN] = rand::thread_rng().gen();
    let timestamp = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as u32)
        .to_le_bytes();
    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(&RPC_NONCE);
    msg.extend_from_slice(&secret[..4]);
    msg.extend_from_slice(&CRYPTO_AES);
    msg.extend_from_slice(&timestamp);
    msg.extend_from_slice(&nonce);
    // Sent padded although unencrypted, exactly as mtprotoproxy does.
    stream.write_all(&build_frame(START_SEQ, &msg)).await?;

    // Read byte-exact: whatever follows this frame is already encrypted.
    let mut word = [0u8; 4];
    stream.read_exact(&mut word).await?;
    while word == PADDING_WORD {
        stream.read_exact(&mut word).await?;
    }
    let len = u32::from_le_bytes(word);
    if len != 32 + FRAME_OVERHEAD as u32 {
        return Err(bad("unexpected middle-proxy nonce answer"));
    }
    let mut plain = vec![0u8; len as usize];
    plain[..4].copy_from_slice(&word);
    stream.read_exact(&mut plain[4..]).await?;
    let answer =
        take_frame(&mut plain, START_SEQ)?.ok_or_else(|| bad("short middle-proxy nonce answer"))?;
    if answer.len() != 32
        || answer[..4] != RPC_NONCE
        || answer[4..8] != secret[..4]
        || answer[8..12] != CRYPTO_AES
    {
        return Err(bad("unexpected middle-proxy nonce answer"));
    }
    let mut nonce_server = [0u8; NONCE_LEN];
    nonce_server.copy_from_slice(&answer[16..32]);

    let input = KeyInput {
        nonce_server,
        nonce_client: nonce,
        client_timestamp: timestamp,
        server,
        client: our_addr,
        secret,
    };
    let (enc_key, enc_iv) = derive_key(&input, Purpose::Client);
    let (dec_key, dec_iv) = derive_key(&input, Purpose::Server);
    let mut enc = CbcEnc::new(&enc_key, &enc_iv);
    let mut dec = CbcDec::new(&dec_key, &dec_iv);

    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(&RPC_HANDSHAKE);
    msg.extend_from_slice(&[0; 4]);
    msg.extend_from_slice(PROCESS_ID);
    msg.extend_from_slice(PROCESS_ID);
    let mut frame = build_frame(START_SEQ + 1, &msg);
    enc.apply(&mut frame);
    stream.write_all(&frame).await?;

    // With a wrong key (typically a wrong public address) the middle proxy
    // cannot read the frame above: it closes, or answers something that does
    // not decrypt here.
    let rejected = |detail: &dyn std::fmt::Display| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "middle proxy did not accept the handshake ({detail}); \
                 behind NAT, set public_ipv4/public_ipv6"
            ),
        )
    };
    let mut plain = Vec::with_capacity(64);
    let answer = loop {
        match take_frame(&mut plain, START_SEQ + 1) {
            Ok(Some(answer)) => break answer,
            Ok(None) => {}
            Err(err) => return Err(rejected(&err)),
        }
        let mut block = [0u8; BLOCK];
        stream
            .read_exact(&mut block)
            .await
            .map_err(|err| rejected(&err))?;
        dec.apply(&mut block);
        plain.extend_from_slice(&block);
    };
    if answer.len() != 32 || answer[..4] != RPC_HANDSHAKE || answer[20..32] != *PROCESS_ID {
        return Err(bad("unexpected middle-proxy handshake answer"));
    }

    Ok(Connected {
        enc,
        dec,
        pending: plain,
        our_addr,
    })
}

/// Room a frame's fixed part may take in the output: frame and request
/// headers, the ad tag block and the first bytes of the message.
const FRAME_START_ROOM: usize = 128;
/// CRC32 plus the most padding a frame can end with.
const FRAME_END_ROOM: usize = 4 + BLOCK - 4;
/// Smallest output buffer `UpEncoder::encode` makes progress with.
pub const MIN_ENCODE_BUF: usize = 2 * FRAME_START_ROOM;

/// Turns the client's message stream into encrypted `RPC_PROXY_REQ` frames.
pub struct UpEncoder {
    cbc: CbcEnc,
    seq: i32,
    /// Connection id, both addresses and the ad tag block: the same in every
    /// request of the session.
    fixed: [u8; 76],
    fixed_len: u8,
    flags: u32,
    /// The client's length word and up to 8 bytes of the message, gathered
    /// before the frame can be started.
    head: [u8; 12],
    head_len: u8,
    in_frame: bool,
    body_left: u32,
    /// Client-side padding to drop once the message is through.
    skip_left: u8,
    frame_len: u32,
    crc: crc32fast::Hasher,
    /// Plaintext waiting for the rest of its AES block.
    tail: [u8; BLOCK],
    tail_len: u8,
}

impl UpEncoder {
    pub fn new(
        cbc: CbcEnc,
        client: SocketAddr,
        our_addr: SocketAddr,
        ad_tag: Option<&[u8; AD_TAG_LEN]>,
    ) -> Self {
        let mut fixed = [0u8; 76];
        let conn_id: [u8; 8] = rand::thread_rng().gen();
        fixed[..8].copy_from_slice(&conn_id);
        fixed[8..28].copy_from_slice(&rpc_addr(client));
        fixed[28..48].copy_from_slice(&rpc_addr(our_addr));
        let mut fixed_len = 48;
        // Only `dd` clients are accepted, so every session is padded intermediate.
        let mut flags = FLAG_MAGIC | FLAG_EXTMODE2 | FLAG_INTERMEDIATE | FLAG_PAD;
        if let Some(tag) = ad_tag {
            // Extra block: its size, the TL id of the tag, then the tag as a
            // TL string (length byte, bytes, padding to a word).
            fixed[48..52].copy_from_slice(&[0x18, 0, 0, 0]);
            fixed[52..56].copy_from_slice(&[0xae, 0x26, 0x1e, 0xdb]);
            fixed[56] = AD_TAG_LEN as u8;
            fixed[57..73].copy_from_slice(tag);
            fixed_len = 76;
            flags |= FLAG_HAS_AD_TAG;
        }
        Self {
            cbc,
            seq: 0,
            fixed,
            fixed_len,
            flags,
            head: [0; 12],
            head_len: 0,
            in_frame: false,
            body_left: 0,
            skip_left: 0,
            frame_len: 0,
            crc: crc32fast::Hasher::new(),
            tail: [0; BLOCK],
            tail_len: 0,
        }
    }

    /// Replaces the random connection id, for reproducible output in tests.
    #[doc(hidden)]
    pub fn with_conn_id(mut self, conn_id: [u8; 8]) -> Self {
        self.fixed[..8].copy_from_slice(&conn_id);
        self
    }

    fn put(&mut self, out: &mut [u8], w: &mut usize, bytes: &[u8]) {
        out[*w..*w + bytes.len()].copy_from_slice(bytes);
        self.crc.update(bytes);
        *w += bytes.len();
    }

    /// Moves input into `head` until it holds `want` bytes.
    fn fill_head(&mut self, input: &[u8], r: &mut usize, want: usize) -> bool {
        let have = usize::from(self.head_len);
        let take = want.saturating_sub(have).min(input.len() - *r);
        self.head[have..have + take].copy_from_slice(&input[*r..*r + take]);
        self.head_len += take as u8;
        *r += take;
        usize::from(self.head_len) >= want
    }

    /// Encodes as much of `input` (decrypted client bytes) as fits in `out`
    /// (at least `MIN_ENCODE_BUF`). Returns the input bytes consumed and the
    /// length of the ciphertext now at the start of `out`, to be sent as is.
    /// Call again with the rest of the input until it is all consumed.
    pub fn encode(&mut self, input: &[u8], out: &mut [u8]) -> Result<(usize, usize), FrameError> {
        let mut w = usize::from(self.tail_len);
        out[..w].copy_from_slice(&self.tail[..w]);
        let mut r = 0;

        loop {
            if !self.in_frame {
                let skip = usize::from(self.skip_left).min(input.len() - r);
                r += skip;
                self.skip_left -= skip as u8;
                if self.skip_left > 0 || out.len() - w < FRAME_START_ROOM {
                    break;
                }
                if !self.fill_head(input, &mut r, 4) {
                    break;
                }
                let word =
                    u32::from_le_bytes([self.head[0], self.head[1], self.head[2], self.head[3]]);
                let quickack = word & 0x8000_0000 != 0;
                let len = (word & 0x7fff_ffff) as usize;
                if len > MAX_CLIENT_MESSAGE {
                    return Err(FrameError::BadLength(word));
                }
                // A padded-intermediate length that is not a multiple of 4
                // ends in padding, which is not part of the message.
                let msg_len = len - len % 4;
                let known = msg_len.min(8);
                if !self.fill_head(input, &mut r, 4 + known) {
                    break;
                }

                let mut flags = self.flags;
                if quickack {
                    flags |= FLAG_QUICKACK;
                }
                if known == 8 && self.head[4..12] == [0; 8] {
                    flags |= FLAG_NOT_ENCRYPTED;
                }
                let fixed_len = usize::from(self.fixed_len);
                self.frame_len = (FRAME_OVERHEAD + 8 + fixed_len + msg_len) as u32;
                self.crc = crc32fast::Hasher::new();
                let (frame_len, seq, fixed, head) =
                    (self.frame_len, self.seq, self.fixed, self.head);
                self.put(out, &mut w, &frame_len.to_le_bytes());
                self.put(out, &mut w, &seq.to_le_bytes());
                self.put(out, &mut w, &RPC_PROXY_REQ);
                self.put(out, &mut w, &flags.to_le_bytes());
                self.put(out, &mut w, &fixed[..fixed_len]);
                self.put(out, &mut w, &head[4..4 + known]);
                self.head_len = 0;
                self.in_frame = true;
                self.body_left = (msg_len - known) as u32;
                self.skip_left = (len % 4) as u8;
            }

            let room = (out.len() - w).saturating_sub(FRAME_END_ROOM);
            let take = (self.body_left as usize).min(input.len() - r).min(room);
            self.put(out, &mut w, &input[r..r + take]);
            r += take;
            self.body_left -= take as u32;
            if self.body_left > 0 {
                break;
            }

            let crc = self.crc.clone().finalize();
            out[w..w + 4].copy_from_slice(&crc.to_le_bytes());
            w += 4;
            let mut framed = self.frame_len as usize;
            while !framed.is_multiple_of(BLOCK) {
                out[w..w + 4].copy_from_slice(&PADDING_WORD);
                w += 4;
                framed += 4;
            }
            self.seq = self.seq.wrapping_add(1);
            self.in_frame = false;
        }

        let ready = w - w % BLOCK;
        self.cbc.apply(&mut out[..ready]);
        self.tail_len = (w - ready) as u8;
        self.tail[..w - ready].copy_from_slice(&out[ready..w]);
        Ok((r, ready))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DownState {
    /// Gathering the frame header: length, sequence number, type and, for the
    /// types that have them, flags and connection id.
    Head,
    /// Inside the frame body; `true` when it is forwarded to the client.
    Body(bool),
    Crc,
}

/// Turns the middle proxy's encrypted frame stream into the client's
/// padded-intermediate message stream.
pub struct DownDecoder {
    cbc: CbcDec,
    /// Ciphertext waiting for the rest of its AES block.
    carry: [u8; BLOCK],
    carry_len: u8,
    seq: i32,
    head: [u8; 24],
    head_len: u8,
    state: DownState,
    left: u32,
    /// Random padding to add behind the message being forwarded.
    pad: u8,
    pad_bytes: [u8; 3],
    crc: crc32fast::Hasher,
}

/// Bytes to leave free in front of the input given to `DownDecoder`.
pub const DOWN_SLACK: usize = 4;

/// Result of decoding one read.
pub struct Decoded {
    /// Length of the client-bound bytes now at the start of the buffer.
    pub len: usize,
    /// The middle proxy asked to close this connection.
    pub closed: bool,
}

impl DownDecoder {
    pub fn new(cbc: CbcDec) -> Self {
        Self {
            cbc,
            carry: [0; BLOCK],
            carry_len: 0,
            seq: 0,
            head: [0; 24],
            head_len: 0,
            state: DownState::Head,
            left: 0,
            pad: 0,
            pad_bytes: [0; 3],
            crc: crc32fast::Hasher::new(),
        }
    }

    /// Puts the ciphertext held over from the last read into `buf` and
    /// returns the offset at which the next read must be placed.
    pub fn read_offset(&self, buf: &mut [u8]) -> usize {
        let len = usize::from(self.carry_len);
        buf[DOWN_SLACK..DOWN_SLACK + len].copy_from_slice(&self.carry[..len]);
        DOWN_SLACK + len
    }

    /// Decrypts and decodes in place. `buf[DOWN_SLACK..end]` is the
    /// carried-over ciphertext followed by a fresh read; the client-bound
    /// bytes end up at the start of `buf`.
    pub fn decode(&mut self, buf: &mut [u8], end: usize) -> Result<Decoded, FrameError> {
        let len = end - DOWN_SLACK;
        let whole = DOWN_SLACK + len - len % BLOCK;
        self.carry_len = (end - whole) as u8;
        self.carry[..end - whole].copy_from_slice(&buf[whole..end]);
        self.cbc.apply(&mut buf[DOWN_SLACK..whole]);
        self.parse(buf, DOWN_SLACK, whole)
    }

    fn fill_head(&mut self, buf: &[u8], r: &mut usize, end: usize, want: usize) -> bool {
        let have = usize::from(self.head_len);
        let take = want.saturating_sub(have).min(end - *r);
        self.head[have..have + take].copy_from_slice(&buf[*r..*r + take]);
        self.head_len += take as u8;
        *r += take;
        usize::from(self.head_len) >= want
    }

    /// Decodes plaintext `buf[start..end]` to the start of `buf`; `start`
    /// must be at least `DOWN_SLACK`.
    ///
    /// The output may run ahead of the input by at most 3 bytes: a header
    /// begun in an earlier call can complete on its last byte and yield the
    /// 4-byte length, and a CRC likewise up to 3 bytes of padding, while a
    /// body is copied one to one. The slack keeps writes behind the reads.
    pub fn parse(
        &mut self,
        buf: &mut [u8],
        start: usize,
        end: usize,
    ) -> Result<Decoded, FrameError> {
        debug_assert!(start >= DOWN_SLACK);
        let (mut r, mut w) = (start, 0);
        while r < end {
            match self.state {
                DownState::Head => {
                    if !self.fill_head(buf, &mut r, end, 4) {
                        break;
                    }
                    let word = u32::from_le_bytes([
                        self.head[0],
                        self.head[1],
                        self.head[2],
                        self.head[3],
                    ]);
                    if self.head[..4] == PADDING_WORD {
                        self.head_len = 0;
                        continue;
                    }
                    let len = word as usize;
                    if !(MIN_FRAME_LEN + 4..=MAX_FRAME_LEN).contains(&len) || !len.is_multiple_of(4)
                    {
                        return Err(FrameError::BadLength(word));
                    }
                    if !self.fill_head(buf, &mut r, end, 12) {
                        break;
                    }
                    if self.head[4..8] != self.seq.to_le_bytes() {
                        return Err(FrameError::BadSequence);
                    }
                    let kind: [u8; 4] = [self.head[8], self.head[9], self.head[10], self.head[11]];
                    let body = len - FRAME_OVERHEAD;
                    match kind {
                        RPC_PROXY_ANS | RPC_SIMPLE_ACK => {
                            if body < 16 {
                                return Err(FrameError::Truncated);
                            }
                            if !self.fill_head(buf, &mut r, end, 24) {
                                break;
                            }
                            self.crc = crc32fast::Hasher::new();
                            self.crc.update(&self.head);
                            self.left = (body - 16) as u32;
                            if kind == RPC_PROXY_ANS {
                                let random: u32 = rand::random();
                                self.pad = (random & 3) as u8;
                                self.pad_bytes.copy_from_slice(&random.to_le_bytes()[1..]);
                                let total = self.left + u32::from(self.pad);
                                debug_assert!(w + 4 <= r);
                                buf[w..w + 4].copy_from_slice(&total.to_le_bytes());
                                self.state = DownState::Body(true);
                            } else {
                                // A quick-ack goes out bare: 4 bytes, no length.
                                let confirm =
                                    [self.head[20], self.head[21], self.head[22], self.head[23]];
                                debug_assert!(w + 4 <= r);
                                buf[w..w + 4].copy_from_slice(&confirm);
                                self.pad = 0;
                                self.state = DownState::Body(false);
                            }
                            w += 4;
                        }
                        RPC_CLOSE_EXT => {
                            return Ok(Decoded {
                                len: w,
                                closed: true,
                            })
                        }
                        _ => {
                            self.crc = crc32fast::Hasher::new();
                            self.crc.update(&self.head[..12]);
                            self.left = (body - 4) as u32;
                            self.pad = 0;
                            self.state = DownState::Body(false);
                        }
                    }
                    self.head_len = 0;
                    if self.left == 0 {
                        self.state = DownState::Crc;
                    }
                }
                DownState::Body(forward) => {
                    let take = (self.left as usize).min(end - r);
                    self.crc.update(&buf[r..r + take]);
                    if forward {
                        debug_assert!(w <= r);
                        buf.copy_within(r..r + take, w);
                        w += take;
                    }
                    r += take;
                    self.left -= take as u32;
                    if self.left == 0 {
                        self.state = DownState::Crc;
                    }
                }
                DownState::Crc => {
                    if !self.fill_head(buf, &mut r, end, 4) {
                        break;
                    }
                    if self.crc.clone().finalize().to_le_bytes() != self.head[..4] {
                        return Err(FrameError::BadChecksum);
                    }
                    let pad = usize::from(self.pad);
                    debug_assert!(w + pad <= r);
                    buf[w..w + pad].copy_from_slice(&self.pad_bytes[..pad]);
                    w += pad;
                    self.pad = 0;
                    self.head_len = 0;
                    self.seq = self.seq.wrapping_add(1);
                    self.state = DownState::Head;
                }
            }
        }
        Ok(Decoded {
            len: w,
            closed: false,
        })
    }
}

/// Middle-proxy addresses per DC index (negative indexes are media DCs and
/// have their own entries) and the secret shared with them.
#[derive(Debug, Clone)]
pub struct Table {
    v4: BTreeMap<i16, Vec<SocketAddr>>,
    v6: BTreeMap<i16, Vec<SocketAddr>>,
    secret: Vec<u8>,
}

/// Parses `proxy_for <dc> <address>:<port>;` lines, the format of
/// core.telegram.org/getProxyConfig. Other lines are ignored.
pub fn parse_proxy_config(text: &str) -> Vec<(i16, SocketAddr)> {
    let mut out = Vec::new();
    for statement in text.split([';', '\n']) {
        let mut words = statement.split_whitespace();
        if words.next() != Some("proxy_for") {
            continue;
        }
        let (Some(dc), Some(addr), None) = (words.next(), words.next(), words.next()) else {
            continue;
        };
        if let (Ok(dc), Ok(addr)) = (dc.parse::<i16>(), addr.parse::<SocketAddr>()) {
            out.push((dc, addr));
        }
    }
    out
}

impl Table {
    fn from_parts(entries: Vec<(i16, SocketAddr)>, secret: Vec<u8>) -> anyhow::Result<Self> {
        anyhow::ensure!(!entries.is_empty(), "no proxy_for entries");
        anyhow::ensure!(
            (32..=1024).contains(&secret.len()),
            "middle-proxy secret must be 32 to 1024 bytes, got {}",
            secret.len()
        );
        let mut table = Self {
            v4: BTreeMap::new(),
            v6: BTreeMap::new(),
            secret,
        };
        for (dc, addr) in entries {
            let family = if addr.is_ipv4() {
                &mut table.v4
            } else {
                &mut table.v6
            };
            family.entry(dc).or_default().push(addr);
        }
        Ok(table)
    }

    /// The list and secret built into the binary.
    pub fn builtin() -> Self {
        let secret = hex::decode(DEFAULT_SECRET_HEX).unwrap_or_default();
        Self::from_parts(parse_proxy_config(DEFAULT_PROXIES), secret).unwrap_or(Self {
            v4: BTreeMap::new(),
            v6: BTreeMap::new(),
            secret: Vec::new(),
        })
    }

    /// Addresses to try for a DC index, in order: the preferred family first,
    /// each family shuffled.
    pub fn candidates(&self, dc_idx: i16, prefer_v6: bool) -> Vec<SocketAddr> {
        let mut rng = rand::thread_rng();
        let mut pick = |family: &BTreeMap<i16, Vec<SocketAddr>>| {
            let mut addrs = family.get(&dc_idx).cloned().unwrap_or_default();
            addrs.shuffle(&mut rng);
            addrs
        };
        if prefer_v6 {
            let mut all = pick(&self.v6);
            all.extend(pick(&self.v4));
            all
        } else {
            pick(&self.v4)
        }
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

/// Where the table comes from and how it is kept current.
pub struct Middle {
    table: RwLock<Arc<Table>>,
    config_files: Vec<PathBuf>,
    secret_file: Option<PathBuf>,
    loaded: RwLock<Vec<Option<SystemTime>>>,
    pub ad_tag: Option<[u8; AD_TAG_LEN]>,
    pub public_v4: Option<IpAddr>,
    pub public_v6: Option<IpAddr>,
}

/// How often the files are checked for a newer version.
pub const RELOAD_PERIOD: Duration = Duration::from_secs(60);

impl Middle {
    /// With no files, the built-in list and secret are used.
    pub fn new(
        config_files: Vec<PathBuf>,
        secret_file: Option<PathBuf>,
        ad_tag: Option<[u8; AD_TAG_LEN]>,
        public_v4: Option<IpAddr>,
        public_v6: Option<IpAddr>,
    ) -> anyhow::Result<Self> {
        let middle = Self {
            table: RwLock::new(Arc::new(Table::builtin())),
            config_files,
            secret_file,
            loaded: RwLock::new(Vec::new()),
            ad_tag,
            public_v4,
            public_v6,
        };
        let table = middle.read_files()?;
        middle.store(table);
        if let Ok(mut loaded) = middle.loaded.write() {
            *loaded = middle.mtimes();
        }
        Ok(middle)
    }

    fn files(&self) -> impl Iterator<Item = &PathBuf> {
        self.config_files.iter().chain(self.secret_file.iter())
    }

    fn mtimes(&self) -> Vec<Option<SystemTime>> {
        self.files()
            .map(|path| std::fs::metadata(path).and_then(|m| m.modified()).ok())
            .collect()
    }

    fn read_files(&self) -> anyhow::Result<Table> {
        use anyhow::Context;
        let builtin = Table::builtin();
        let entries = if self.config_files.is_empty() {
            parse_proxy_config(DEFAULT_PROXIES)
        } else {
            let mut entries = Vec::new();
            for path in &self.config_files {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                entries.extend(parse_proxy_config(&text));
            }
            entries
        };
        let secret = match &self.secret_file {
            Some(path) => {
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?
            }
            None => builtin.secret,
        };
        Table::from_parts(entries, secret).context("middle-proxy files")
    }

    fn store(&self, table: Table) {
        if let Ok(mut current) = self.table.write() {
            *current = Arc::new(table);
        }
    }

    /// The current table. Taken once per new session, never while relaying.
    pub fn table(&self) -> Arc<Table> {
        match self.table.read() {
            Ok(table) => table.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Re-reads the files if any of them changed. A file that fails to load
    /// leaves the current table in place.
    pub fn reload_if_changed(&self) {
        let now = self.mtimes();
        let changed = self.loaded.read().map(|l| *l != now).unwrap_or(false);
        if !changed {
            return;
        }
        match self.read_files() {
            Ok(table) => {
                self.store(table);
                tracing::info!("middle-proxy list reloaded");
            }
            Err(err) => tracing::warn!(error = %err, "middle-proxy files not reloaded"),
        }
        if let Ok(mut loaded) = self.loaded.write() {
            *loaded = now;
        }
    }

    pub fn public_ip(&self, server: SocketAddr) -> Option<IpAddr> {
        if server.is_ipv4() {
            self.public_v4
        } else {
            self.public_v6
        }
    }
}

/// Checks the middle-proxy files for changes forever.
pub async fn run_reload(middle: Arc<Middle>) {
    if middle.files().next().is_none() {
        return;
    }
    let mut ticker = tokio::time::interval(RELOAD_PERIOD);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        middle.reload_if_changed();
    }
}

/// The middle proxy's side of the protocol, for the load generator and tests.
pub mod peer {
    use super::*;

    /// A connection accepted from a proxy, after the handshake.
    pub struct Peer {
        stream: TcpStream,
        enc: CbcEnc,
        dec: CbcDec,
        seq_in: i32,
        seq_out: i32,
        plain: Vec<u8>,
    }

    /// One `RPC_PROXY_REQ` as the proxy sent it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProxyReq {
        pub flags: u32,
        pub conn_id: [u8; 8],
        pub client: SocketAddr,
        pub proxy: SocketAddr,
        pub ad_tag: Option<[u8; AD_TAG_LEN]>,
        pub data: Vec<u8>,
    }

    fn addr_from(bytes: &[u8]) -> SocketAddr {
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&bytes[..16]);
        let ip = std::net::Ipv6Addr::from(ip);
        let port = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as u16;
        let ip = match ip.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(ip),
        };
        SocketAddr::new(ip, port)
    }

    /// Parses a frame's message as `RPC_PROXY_REQ`.
    pub fn parse_proxy_req(msg: &[u8]) -> Option<ProxyReq> {
        if msg.len() < 56 || msg[..4] != RPC_PROXY_REQ {
            return None;
        }
        let flags = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
        let mut conn_id = [0u8; 8];
        conn_id.copy_from_slice(&msg[8..16]);
        let mut rest = &msg[56..];
        let mut ad_tag = None;
        if flags & FLAG_HAS_AD_TAG != 0 {
            if rest.len() < 28 || rest[..9] != [0x18, 0, 0, 0, 0xae, 0x26, 0x1e, 0xdb, 16] {
                return None;
            }
            let mut tag = [0u8; AD_TAG_LEN];
            tag.copy_from_slice(&rest[9..25]);
            ad_tag = Some(tag);
            rest = &rest[28..];
        }
        Some(ProxyReq {
            flags,
            conn_id,
            client: addr_from(&msg[16..36]),
            proxy: addr_from(&msg[36..56]),
            ad_tag,
            data: rest.to_vec(),
        })
    }

    /// The message of an `RPC_PROXY_ANS` frame carrying `data` to the client.
    pub fn proxy_ans(conn_id: &[u8; 8], data: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(16 + data.len());
        msg.extend_from_slice(&RPC_PROXY_ANS);
        msg.extend_from_slice(&[0; 4]);
        msg.extend_from_slice(conn_id);
        msg.extend_from_slice(data);
        msg
    }

    /// The message of an `RPC_SIMPLE_ACK` frame.
    pub fn simple_ack(conn_id: &[u8; 8], confirm: [u8; 4]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(16);
        msg.extend_from_slice(&RPC_SIMPLE_ACK);
        msg.extend_from_slice(conn_id);
        msg.extend_from_slice(&confirm);
        msg
    }

    /// The message of an `RPC_CLOSE_EXT` frame.
    pub fn close_ext(conn_id: &[u8; 8]) -> Vec<u8> {
        let mut msg = RPC_CLOSE_EXT.to_vec();
        msg.extend_from_slice(conn_id);
        msg
    }

    pub const QUICKACK: u32 = FLAG_QUICKACK;
    pub const NOT_ENCRYPTED: u32 = FLAG_NOT_ENCRYPTED;

    /// Answers a proxy's nonce and handshake frames.
    pub async fn accept(mut stream: TcpStream, secret: &[u8]) -> io::Result<Peer> {
        let server = stream.local_addr()?;
        let client = stream.peer_addr()?;
        // The nonce frame arrives unencrypted but padded to a block.
        let mut first = vec![0u8; 48];
        stream.read_exact(&mut first).await?;
        let msg = take_frame(&mut first, START_SEQ)?.ok_or_else(|| bad("short nonce frame"))?;
        if msg.len() != 32 || msg[..4] != RPC_NONCE || msg[4..8] != secret[..4] {
            return Err(bad("unexpected nonce frame"));
        }
        let mut client_timestamp = [0u8; 4];
        client_timestamp.copy_from_slice(&msg[12..16]);
        let mut nonce_client = [0u8; NONCE_LEN];
        nonce_client.copy_from_slice(&msg[16..32]);
        let nonce_server: [u8; NONCE_LEN] = rand::thread_rng().gen();

        let mut answer = Vec::with_capacity(32);
        answer.extend_from_slice(&RPC_NONCE);
        answer.extend_from_slice(&secret[..4]);
        answer.extend_from_slice(&CRYPTO_AES);
        answer.extend_from_slice(&client_timestamp);
        answer.extend_from_slice(&nonce_server);
        // Unpadded: the proxy switches to decrypting right behind this frame.
        let mut frame = build_frame(START_SEQ, &answer);
        frame.truncate(answer.len() + FRAME_OVERHEAD);
        stream.write_all(&frame).await?;

        let input = KeyInput {
            nonce_server,
            nonce_client,
            client_timestamp,
            server,
            client,
            secret,
        };
        let (dec_key, dec_iv) = derive_key(&input, Purpose::Client);
        let (enc_key, enc_iv) = derive_key(&input, Purpose::Server);
        let mut peer = Peer {
            stream,
            enc: CbcEnc::new(&enc_key, &enc_iv),
            dec: CbcDec::new(&dec_key, &dec_iv),
            seq_in: START_SEQ + 1,
            seq_out: START_SEQ + 1,
            plain: Vec::new(),
        };
        let hello = peer
            .read_frame()
            .await?
            .ok_or_else(|| bad("closed before the handshake frame"))?;
        if hello.len() != 32 || hello[..4] != RPC_HANDSHAKE {
            return Err(bad("unexpected handshake frame"));
        }
        let mut answer = Vec::with_capacity(32);
        answer.extend_from_slice(&RPC_HANDSHAKE);
        answer.extend_from_slice(&[0; 4]);
        answer.extend_from_slice(PROCESS_ID);
        answer.extend_from_slice(&hello[8..20]);
        peer.write_frame(&answer).await?;
        Ok(peer)
    }

    impl Peer {
        /// The next frame's message, or `None` once the proxy has closed.
        pub async fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
            loop {
                if let Some(msg) = take_frame(&mut self.plain, self.seq_in)? {
                    self.seq_in += 1;
                    return Ok(Some(msg));
                }
                let mut block = [0u8; BLOCK];
                match self.stream.read_exact(&mut block).await {
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(err) => return Err(err),
                }
                self.dec.apply(&mut block);
                self.plain.extend_from_slice(&block);
            }
        }

        /// The next `RPC_PROXY_REQ`, or `None` once the proxy has closed.
        pub async fn read_request(&mut self) -> io::Result<Option<ProxyReq>> {
            match self.read_frame().await? {
                Some(msg) => parse_proxy_req(&msg)
                    .map(Some)
                    .ok_or_else(|| bad("not a proxy request")),
                None => Ok(None),
            }
        }

        pub async fn write_frame(&mut self, msg: &[u8]) -> io::Result<()> {
            let mut frame = build_frame(self.seq_out, msg);
            self.seq_out += 1;
            self.enc.apply(&mut frame);
            self.stream.write_all(&frame).await
        }

        pub fn stream(&self) -> &TcpStream {
            &self.stream
        }
    }
}

#[cfg(test)]
mod tests {
    use super::peer::{parse_proxy_req, proxy_ans, simple_ack, ProxyReq};
    use super::*;
    use proptest::prelude::*;
    use serde_json::Value;
    use tokio::net::TcpListener;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/vectors/middle.json")).unwrap()
    }

    fn bytes(value: &Value) -> Vec<u8> {
        hex::decode(value.as_str().unwrap()).unwrap()
    }

    fn array<const N: usize>(value: &Value) -> [u8; N] {
        bytes(value).try_into().unwrap()
    }

    fn addr(value: &Value) -> SocketAddr {
        value.as_str().unwrap().parse().unwrap()
    }

    #[test]
    fn builtin_secret_is_the_reference_one() {
        assert_eq!(Table::builtin().secret(), bytes(&vectors()["secret"]));
    }

    #[test]
    fn keys_match_the_reference_for_both_families() {
        let v = vectors();
        let secret = bytes(&v["secret"]);
        for case in v["keys"].as_array().unwrap() {
            let input = KeyInput {
                nonce_server: array(&case["nonce_server"]),
                nonce_client: array(&case["nonce_client"]),
                client_timestamp: array(&case["timestamp"]),
                server: addr(&case["server_addr"]),
                client: addr(&case["client_addr"]),
                secret: &secret,
            };
            for (purpose, name) in [(Purpose::Client, "client"), (Purpose::Server, "server")] {
                let (key, iv) = derive_key(&input, purpose);
                assert_eq!(key.to_vec(), bytes(&case[name]["key"]), "{name} key");
                assert_eq!(iv.to_vec(), bytes(&case[name]["iv"]), "{name} iv");
            }
        }
    }

    #[test]
    fn frames_match_the_reference() {
        for case in vectors()["frames"].as_array().unwrap() {
            let seq = case["seq"].as_i64().unwrap() as i32;
            let msg = bytes(&case["msg"]);
            let mut wire = build_frame(seq, &msg);
            assert_eq!(wire, bytes(&case["wire"]));
            assert_eq!(take_frame(&mut wire, seq).unwrap().unwrap(), msg);
            // Only padding is left behind a frame.
            assert!(wire.chunks(4).all(|w| w == PADDING_WORD));
        }
    }

    fn encoder(case: &Value) -> UpEncoder {
        let tag = bytes(&case["ad_tag"]);
        let tag: Option<[u8; AD_TAG_LEN]> = (!tag.is_empty()).then(|| tag.try_into().unwrap());
        let up = UpEncoder::new(
            CbcEnc::new(&array(&case["key"]), &array(&case["iv"])),
            addr(&case["client"]),
            addr(&case["proxy"]),
            tag.as_ref(),
        );
        up.with_conn_id(array(&case["conn_id"]))
    }

    /// Runs `stream` through an encoder in chunks of `chunk` bytes, with an
    /// output buffer of `out_len`.
    fn encode_all(up: &mut UpEncoder, stream: &[u8], chunk: usize, out_len: usize) -> Vec<u8> {
        let mut out = vec![0u8; out_len];
        let mut wire = Vec::new();
        for piece in stream.chunks(chunk.max(1)) {
            let mut input = piece;
            while !input.is_empty() {
                let (used, ready) = up.encode(input, &mut out).unwrap();
                wire.extend_from_slice(&out[..ready]);
                input = &input[used..];
            }
        }
        wire
    }

    #[test]
    fn requests_match_the_reference_for_any_chunking() {
        for case in vectors()["upstream"].as_array().unwrap() {
            let stream = bytes(&case["client_stream"]);
            let wire = bytes(&case["wire"]);
            for (chunk, out_len) in [
                (stream.len(), 16 * 1024),
                (1, 16 * 1024),
                (7, MIN_ENCODE_BUF),
                (1000, 300),
                (16 * 1024, 4096),
            ] {
                let got = encode_all(&mut encoder(case), &stream, chunk, out_len);
                assert!(got == wire, "chunk {chunk}, out {out_len}");
            }
        }
    }

    /// What a decoder's output is expected to be made of.
    #[derive(Debug, PartialEq, Eq, Clone)]
    enum Item {
        Message(Vec<u8>),
        Ack(Vec<u8>),
    }

    /// Splits decoder output into the messages and acks named by `kinds`
    /// (`true` = message), checking the padded-intermediate framing.
    fn split_client_stream(mut stream: &[u8], kinds: &[bool]) -> Vec<Item> {
        let mut items = Vec::new();
        for &message in kinds {
            if !message {
                items.push(Item::Ack(stream[..4].to_vec()));
                stream = &stream[4..];
                continue;
            }
            let total = u32::from_le_bytes(stream[..4].try_into().unwrap()) as usize;
            assert!(
                total % 4 < 4 && total <= stream.len() - 4,
                "bad length {total}"
            );
            let data = total - total % 4;
            items.push(Item::Message(stream[4..4 + data].to_vec()));
            stream = &stream[4 + total..];
        }
        assert!(stream.is_empty(), "{} stray bytes", stream.len());
        items
    }

    /// Feeds `wire` to a decoder in chunks, the way the relay does.
    fn decode_all(
        down: &mut DownDecoder,
        wire: &[u8],
        chunk: usize,
    ) -> Result<(Vec<u8>, bool), FrameError> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; DOWN_SLACK + BLOCK + chunk.max(1)];
        for piece in wire.chunks(chunk.max(1)) {
            let offset = down.read_offset(&mut buf);
            buf[offset..offset + piece.len()].copy_from_slice(piece);
            let decoded = down.decode(&mut buf, offset + piece.len())?;
            out.extend_from_slice(&buf[..decoded.len]);
            if decoded.closed {
                return Ok((out, true));
            }
        }
        Ok((out, false))
    }

    #[test]
    fn answers_written_by_the_reference_decode_for_any_chunking() {
        let v = vectors();
        let case = &v["downstream"];
        let wire = bytes(&case["wire"]);
        let expected: Vec<Item> = case["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| match item["kind"].as_str().unwrap() {
                "message" => Item::Message(bytes(&item["data"])),
                _ => Item::Ack(bytes(&item["data"])),
            })
            .collect();
        let kinds: Vec<bool> = expected
            .iter()
            .map(|i| matches!(i, Item::Message(_)))
            .collect();
        for chunk in [wire.len(), 1, 5, 16, 17, 1000] {
            let mut down = DownDecoder::new(CbcDec::new(&array(&case["key"]), &array(&case["iv"])));
            let (stream, closed) = decode_all(&mut down, &wire, chunk).unwrap();
            assert!(!closed);
            assert_eq!(
                split_client_stream(&stream, &kinds),
                expected,
                "chunk {chunk}"
            );
        }
    }

    const KEY: [u8; 32] = [7; 32];
    const IV: [u8; 16] = [9; 16];

    fn local(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// Decrypts a request stream and returns the requests in it.
    fn read_requests(wire: &[u8]) -> Vec<ProxyReq> {
        let mut plain = wire.to_vec();
        CbcDec::new(&KEY, &IV).apply(&mut plain);
        let mut requests = Vec::new();
        let mut seq = 0;
        while let Some(msg) = take_frame(&mut plain, seq).unwrap() {
            requests.push(parse_proxy_req(&msg).unwrap());
            seq += 1;
        }
        assert!(
            plain.chunks(4).all(|w| w == PADDING_WORD),
            "partial frame left"
        );
        requests
    }

    /// Encrypted frames, numbered from 0, as a middle proxy would send them.
    fn answer_wire(messages: &[Vec<u8>]) -> Vec<u8> {
        let mut wire = Vec::new();
        for (seq, msg) in messages.iter().enumerate() {
            wire.extend_from_slice(&build_frame(seq as i32, msg));
        }
        CbcEnc::new(&KEY, &IV).apply(&mut wire);
        wire
    }

    #[test]
    fn request_carries_addresses_tag_and_flags() {
        let tag = [0x5a; AD_TAG_LEN];
        let mut up = UpEncoder::new(
            CbcEnc::new(&KEY, &IV),
            local(1111),
            "[2001:db8::1]:2222".parse().unwrap(),
            Some(&tag),
        );
        let mut stream = Vec::new();
        // An unencrypted message (zero auth key id), then a quick-ack one.
        stream.extend_from_slice(&16u32.to_le_bytes());
        stream.extend_from_slice(&[0; 16]);
        stream.extend_from_slice(&(0x8000_0000u32 | 12).to_le_bytes());
        stream.extend_from_slice(&[3; 12]);
        let requests = read_requests(&encode_all(&mut up, &stream, 5, 4096));

        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].client, local(1111));
        assert_eq!(requests[0].proxy, "[2001:db8::1]:2222".parse().unwrap());
        assert_eq!(requests[0].ad_tag, Some(tag));
        assert_eq!(requests[0].conn_id, requests[1].conn_id);
        assert_ne!(requests[0].flags & peer::NOT_ENCRYPTED, 0);
        assert_eq!(requests[0].flags & peer::QUICKACK, 0);
        assert_eq!(requests[1].flags & peer::NOT_ENCRYPTED, 0);
        assert_ne!(requests[1].flags & peer::QUICKACK, 0);
        assert_eq!(requests[1].data, [3; 12]);
    }

    #[test]
    fn oversized_client_message_is_refused() {
        let mut up = UpEncoder::new(CbcEnc::new(&KEY, &IV), local(1), local(2), None);
        let word = (MAX_CLIENT_MESSAGE as u32 + 4).to_le_bytes();
        let mut out = vec![0u8; 4096];
        assert!(matches!(
            up.encode(&word, &mut out),
            Err(FrameError::BadLength(_))
        ));
    }

    #[test]
    fn decoder_rejects_bad_frames_and_honours_close() {
        let conn = [1u8; 8];
        let good = proxy_ans(&conn, &[5; 32]);
        let decode =
            |wire: &[u8]| decode_all(&mut DownDecoder::new(CbcDec::new(&KEY, &IV)), wire, 64);

        // Wrong sequence number.
        let mut wire = build_frame(3, &good);
        CbcEnc::new(&KEY, &IV).apply(&mut wire);
        assert_eq!(decode(&wire).unwrap_err(), FrameError::BadSequence);

        // Corrupted body: the checksum no longer matches.
        let mut plain = build_frame(0, &good);
        plain[30] ^= 1;
        CbcEnc::new(&KEY, &IV).apply(&mut plain);
        assert_eq!(decode(&plain).unwrap_err(), FrameError::BadChecksum);

        // Lengths outside the allowed range or not a multiple of 4.
        for len in [8u32, 12, 18, (MAX_FRAME_LEN + 4) as u32] {
            let mut plain = vec![0u8; 16];
            plain[..4].copy_from_slice(&len.to_le_bytes());
            CbcEnc::new(&KEY, &IV).apply(&mut plain);
            assert_eq!(decode(&plain).unwrap_err(), FrameError::BadLength(len));
        }

        // An answer too short to hold its connection id.
        let mut plain = build_frame(0, &RPC_PROXY_ANS);
        CbcEnc::new(&KEY, &IV).apply(&mut plain);
        assert_eq!(decode(&plain).unwrap_err(), FrameError::Truncated);

        // Data, then a close: the data is delivered and the session ends.
        let wire = answer_wire(&[good.clone(), peer::close_ext(&conn), good.clone()]);
        let (stream, closed) = decode(&wire).unwrap();
        assert!(closed);
        assert_eq!(
            split_client_stream(&stream, &[true]),
            [Item::Message(vec![5; 32])]
        );
    }

    #[test]
    fn padding_towards_the_client_varies() {
        let conn = [1u8; 8];
        let messages: Vec<Vec<u8>> = (0..64).map(|_| proxy_ans(&conn, &[8; 16])).collect();
        let (stream, _) = decode_all(
            &mut DownDecoder::new(CbcDec::new(&KEY, &IV)),
            &answer_wire(&messages),
            4096,
        )
        .unwrap();
        assert_eq!(split_client_stream(&stream, &[true; 64]).len(), 64);
        // 64 messages of 20 bytes each would be exactly 1280 without padding.
        assert!(stream.len() > 64 * 20, "no padding was added");
    }

    #[test]
    fn proxy_config_is_parsed() {
        let text = "# force_probability 10 10\ndefault 2;\nproxy_for 1 149.154.175.50:8888;\n\
                    proxy_for -4 [2001:67c:4e8:f004::d]:8888; proxy_for 4 91.108.4.1:80;\n\
                    proxy_for x 1.2.3.4:5;\nproxy_for 5 not-an-address;\nproxy_for 5;";
        assert_eq!(
            parse_proxy_config(text),
            [
                (1, "149.154.175.50:8888".parse().unwrap()),
                (-4, "[2001:67c:4e8:f004::d]:8888".parse().unwrap()),
                (4, "91.108.4.1:80".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn builtin_table_covers_every_dc_and_lane_in_both_families() {
        let table = Table::builtin();
        for dc in (1..=5).flat_map(|dc| [dc, -dc]) {
            let v4 = table.candidates(dc, false);
            assert!(
                !v4.is_empty() && v4.iter().all(SocketAddr::is_ipv4),
                "dc {dc}"
            );
            let both = table.candidates(dc, true);
            assert!(both[0].is_ipv6(), "dc {dc}: IPv6 is not tried first");
            assert!(both.iter().any(SocketAddr::is_ipv4), "dc {dc}: no fallback");
        }
        assert!(table.candidates(9, true).is_empty());
    }

    #[test]
    fn files_replace_the_builtin_table_and_are_reloaded() {
        let dir =
            std::env::temp_dir().join(format!("echo-mtproxy-middle-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let (list, secret) = (dir.join("proxy.conf"), dir.join("proxy-secret"));
        std::fs::write(&list, "proxy_for 2 127.0.0.1:7001;\n").unwrap();
        std::fs::write(&secret, [0x42u8; 64]).unwrap();

        let middle =
            Middle::new(vec![list.clone()], Some(secret.clone()), None, None, None).unwrap();
        let table = middle.table();
        assert_eq!(table.candidates(2, true), [local(7001)]);
        assert!(table.candidates(1, true).is_empty());
        assert_eq!(table.secret(), [0x42u8; 64]);

        // Unchanged files are not read again; a changed one is.
        middle.reload_if_changed();
        assert!(Arc::ptr_eq(&table, &middle.table()));
        std::fs::write(
            &list,
            "proxy_for 2 127.0.0.1:7002;\nproxy_for 2 127.0.0.1:7003;\n",
        )
        .unwrap();
        let later = SystemTime::now() + Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&list)
            .unwrap()
            .set_modified(later)
            .unwrap();
        middle.reload_if_changed();
        let mut addrs = middle.table().candidates(2, false);
        addrs.sort();
        assert_eq!(addrs, [local(7002), local(7003)]);

        // A broken file keeps the table that works.
        std::fs::write(&list, "nothing useful\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&list)
            .unwrap()
            .set_modified(later + Duration::from_secs(5))
            .unwrap();
        middle.reload_if_changed();
        assert_eq!(middle.table().candidates(2, false).len(), 2);

        assert!(Middle::new(vec![dir.join("missing")], None, None, None, None).is_err());
        std::fs::write(&secret, [1u8; 8]).unwrap();
        assert!(Middle::new(vec![], Some(secret), None, None, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn pair(v6: bool) -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(if v6 { "[::1]:0" } else { "127.0.0.1:0" })
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (near, far) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (near.unwrap(), far.unwrap().0)
    }

    #[tokio::test]
    async fn handshake_agrees_on_keys_over_both_families() {
        for v6 in [false, true] {
            let (mut near, far) = pair(v6).await;
            let secret = Table::builtin().secret().to_vec();
            let server_secret = secret.clone();
            let server =
                tokio::spawn(async move { peer::accept(far, &server_secret).await.unwrap() });
            let hello = handshake(&mut near, &secret, None).await.unwrap();
            let mut server = server.await.unwrap();
            assert_eq!(hello.our_addr, near.local_addr().unwrap());
            assert!(hello.pending.chunks(4).all(|w| w == PADDING_WORD));

            // A request written with the negotiated key is readable by the peer.
            let mut up = UpEncoder::new(hello.enc, local(5), hello.our_addr, None);
            let mut stream = 24u32.to_le_bytes().to_vec();
            stream.extend_from_slice(&[0xab; 24]);
            near.write_all(&encode_all(&mut up, &stream, 64, 4096))
                .await
                .unwrap();
            let request = server.read_request().await.unwrap().unwrap();
            assert_eq!(request.data, [0xab; 24]);

            // And an answer from the peer decodes on this side.
            server
                .write_frame(&proxy_ans(&request.conn_id, &[0xcd; 40]))
                .await
                .unwrap();
            server
                .write_frame(&simple_ack(&request.conn_id, [1, 2, 3, 4]))
                .await
                .unwrap();
            let mut down = DownDecoder::new(hello.dec);
            let mut pending = [0u8; DOWN_SLACK + 64];
            pending[DOWN_SLACK..DOWN_SLACK + hello.pending.len()].copy_from_slice(&hello.pending);
            let decoded = down
                .parse(&mut pending, DOWN_SLACK, DOWN_SLACK + hello.pending.len())
                .unwrap();
            assert_eq!(decoded.len, 0);
            let mut wire = [0u8; 80 + 32];
            near.read_exact(&mut wire).await.unwrap();
            let (stream, _) = decode_all(&mut down, &wire, 64).unwrap();
            assert_eq!(
                split_client_stream(&stream, &[true, false]),
                [Item::Message(vec![0xcd; 40]), Item::Ack(vec![1, 2, 3, 4])]
            );
        }
    }

    #[tokio::test]
    async fn handshake_fails_cleanly_on_a_wrong_secret_or_address() {
        let secret = Table::builtin().secret().to_vec();

        // A different secret: the key selector does not match.
        let (mut near, far) = pair(false).await;
        let other = vec![0x33u8; 64];
        let server = tokio::spawn(async move { peer::accept(far, &other).await.is_err() });
        assert!(handshake(&mut near, &secret, None).await.is_err());
        assert!(server.await.unwrap());

        // A wrong public address gives different keys; the error says where to look.
        let (mut near, far) = pair(false).await;
        let server_secret = secret.clone();
        let server = tokio::spawn(async move { peer::accept(far, &server_secret).await.is_err() });
        let err = handshake(&mut near, &secret, Some("203.0.113.1".parse().unwrap()))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("public_ipv4"), "{err}");
        drop(near);
        assert!(server.await.unwrap());
    }

    #[test]
    fn codec_state_sizes() {
        // Run with --nocapture to see them; both are boxed per session.
        println!("UpEncoder   {}", std::mem::size_of::<UpEncoder>());
        println!("DownDecoder {}", std::mem::size_of::<DownDecoder>());
        assert!(std::mem::size_of::<UpEncoder>() <= 2048);
        assert!(std::mem::size_of::<DownDecoder>() <= 2048);
    }

    fn client_stream(messages: &[(Vec<u8>, u8)]) -> Vec<u8> {
        let mut stream = Vec::new();
        for (msg, pad) in messages {
            stream.extend_from_slice(&((msg.len() + usize::from(*pad)) as u32).to_le_bytes());
            stream.extend_from_slice(msg);
            stream.extend_from_slice(&[0xee; 3][..usize::from(*pad)]);
        }
        stream
    }

    fn message() -> impl Strategy<Value = Vec<u8>> {
        // Message lengths are multiples of 4; a few are far larger than a buffer.
        prop_oneof![
            8 => (0usize..200).prop_map(|words| vec![0x61; words * 4]),
            1 => (4000usize..12_000).prop_map(|words| vec![0x62; words * 4]),
        ]
        .prop_flat_map(|msg| {
            let len = msg.len();
            proptest::collection::vec(any::<u8>(), len..=len)
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn requests_round_trip_for_any_messages_and_chunking(
            messages in proptest::collection::vec((message(), 0u8..4), 0..12),
            chunk in 1usize..20_000,
            out_len in MIN_ENCODE_BUF..20_000usize,
            tagged in any::<bool>(),
        ) {
            let tag = [0x77; AD_TAG_LEN];
            let mut up = UpEncoder::new(
                CbcEnc::new(&KEY, &IV),
                local(1),
                local(2),
                tagged.then_some(&tag),
            );
            let wire = encode_all(&mut up, &client_stream(&messages), chunk, out_len);
            prop_assert_eq!(wire.len() % BLOCK, 0);
            let requests = read_requests(&wire);
            prop_assert_eq!(requests.len(), messages.len());
            for (request, (msg, _)) in requests.iter().zip(&messages) {
                prop_assert_eq!(&request.data, msg);
                prop_assert_eq!(request.ad_tag, tagged.then_some(tag));
            }
        }

        #[test]
        fn answers_round_trip_for_any_messages_and_chunking(
            messages in proptest::collection::vec((message(), any::<bool>()), 0..12),
            chunk in 1usize..20_000,
        ) {
            let conn = [4u8; 8];
            let frames: Vec<Vec<u8>> = messages
                .iter()
                .flat_map(|(msg, with_ack)| {
                    let mut frames = vec![proxy_ans(&conn, msg)];
                    if *with_ack {
                        frames.push(simple_ack(&conn, [9, 8, 7, 6]));
                    }
                    frames
                })
                .collect();
            let mut down = DownDecoder::new(CbcDec::new(&KEY, &IV));
            let (stream, closed) = decode_all(&mut down, &answer_wire(&frames), chunk).unwrap();
            prop_assert!(!closed);
            let kinds: Vec<bool> = messages
                .iter()
                .flat_map(|(_, with_ack)| if *with_ack { vec![true, false] } else { vec![true] })
                .collect();
            let expected: Vec<Item> = messages
                .iter()
                .flat_map(|(msg, with_ack)| {
                    let mut items = vec![Item::Message(msg.clone())];
                    if *with_ack {
                        items.push(Item::Ack(vec![9, 8, 7, 6]));
                    }
                    items
                })
                .collect();
            prop_assert_eq!(split_client_stream(&stream, &kinds), expected);
        }
    }
}
