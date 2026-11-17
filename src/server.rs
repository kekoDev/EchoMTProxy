use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::cipher::{AesCtr, Ctr};
use crate::config::{Config, Secret, UpstreamMode};
use crate::dc::DcTable;
use crate::limit::{Direction, Lane, Limits, SessionTraffic};
use crate::mask::Masker;
use crate::obfs2::{self, ClientInit, InitError, INIT_LEN, TAG_SECURE};
use crate::pool;
use crate::relay::{relay, Ciphers, ClosedBy, Ended};
use crate::replay::ReplayCache;
use crate::stats::{HandshakeResult, MaskResult, Stats};
use crate::tls::{
    self, HelloError, RecordError, RecordReader, SkewPolicy, MAX_RECORD_PAYLOAD, RECORD_HEADER_LEN,
};

// Fake certificate size range used by mtprotoproxy before it learns the real one.
const FAKE_CERT_LEN: std::ops::Range<usize> = 1024..4096;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
// Over-limit connections are held silently so the refusal looks like a slow
// server rather than an instant close. Holding costs a descriptor each, so only
// this share of max_connections may be held; the rest are closed at once.
const OVERFLOW_SHARE: usize = 16;
const OVERFLOW_HELD_MIN: usize = 16;
const OVERFLOW_HELD_MAX: usize = 4096;

/// Everything a connection needs, shared by all of them.
pub struct Proxy {
    secrets: Vec<Secret>,
    skew: SkewPolicy,
    replay: ReplayCache,
    dc: DcTable,
    upstream_mode: UpstreamMode,
    handshake_timeout: Duration,
    /// `None` when `idle_timeout_secs` is 0.
    idle_timeout: Option<Duration>,
    max_connections: u64,
    overflow_slots: Arc<Semaphore>,
    masker: Masker,
    stats: Arc<Stats>,
}

impl Proxy {
    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let skew = SkewPolicy {
            behind_secs: config.time_skew_behind_secs,
            ahead_secs: config.time_skew_ahead_secs,
            accept_uptime: config.accept_uptime_timestamps,
        };
        let mut dc = DcTable::new(config.prefer_ipv6_upstream);
        for (index, addr) in config.parsed_dc_overrides()? {
            dc = dc.with_override(index, addr);
        }
        for (index, addr) in config.parsed_dc_overrides_v6()? {
            dc = dc.with_override_v6(index, addr);
        }
        let dc = dc.with_bind_addrs(&config.upstream_bind_addrs)?;
        let secrets = config.parsed_secrets()?;
        let masker = Masker::new(
            config.parsed_mask_domains()?,
            config.default_mask(&secrets)?,
            config.mask_max_connections,
            Duration::from_secs(config.mask_idle_timeout_secs),
            Duration::from_secs(config.mask_dns_ttl_secs),
        );
        let limits = Limits::new(
            config.media_rate_bps,
            config.media_burst_bytes,
            config.link_capacity_bps,
            config.congestion_threshold,
        );
        let stats = Stats::with_limits(
            masker
                .target_names()
                .map(str::to_owned)
                .chain(secrets.iter().map(|s| s.domain.clone())),
            limits,
        );
        Ok(Self {
            secrets,
            replay: ReplayCache::new(
                Duration::from_secs(skew.window_secs()),
                config.replay_cache_entries,
            ),
            skew,
            dc,
            upstream_mode: config.upstream_mode,
            handshake_timeout: Duration::from_secs(config.handshake_timeout_secs),
            idle_timeout: (config.idle_timeout_secs > 0)
                .then(|| Duration::from_secs(config.idle_timeout_secs)),
            max_connections: config.max_connections as u64,
            overflow_slots: Arc::new(Semaphore::new(
                (config.max_connections / OVERFLOW_SHARE)
                    .clamp(OVERFLOW_HELD_MIN, OVERFLOW_HELD_MAX),
            )),
            masker,
            stats: Arc::new(stats),
        })
    }
}

#[derive(Debug, thiserror::Error)]
enum Reject {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("client hello: {0}")]
    Hello(#[from] HelloError),
    #[error("tls record: {0}")]
    Record(#[from] RecordError),
    #[error("obfuscated2 init: {0}")]
    Init(#[from] InitError),
    #[error("replayed handshake")]
    Replay,
}

impl Reject {
    fn result(&self) -> HandshakeResult {
        match self {
            Self::Hello(HelloError::BadDigest) => HandshakeResult::BadDigest,
            Self::Hello(HelloError::BadTimestamp { .. }) => HandshakeResult::BadTimestamp,
            Self::Replay => HandshakeResult::Replay,
            Self::Init(_) => HandshakeResult::BadInit,
            Self::Hello(HelloError::Malformed) | Self::Record(_) | Self::Io(_) => {
                HandshakeResult::Malformed
            }
        }
    }
}

/// What the handshake learned about the client, kept outside its future so it
/// survives a rejection or a timeout.
#[derive(Default)]
struct Seen {
    /// Every byte read from the client before the proxy replied.
    bytes: Vec<u8>,
    /// Set once the fake ServerHello is on the wire. From then on the client
    /// has seen a proxy-specific answer and handing it to a mask site would
    /// only produce a broken TLS stream.
    replied: bool,
}

impl Seen {
    fn sni(&self) -> Option<&str> {
        tls::client_hello_sni(&self.bytes)
    }
}

struct Session {
    init: ClientInit,
    records: RecordReader,
    /// Client payload that arrived together with the init, still encrypted.
    leftover: Vec<u8>,
}

/// A session ready to relay.
struct Established {
    upstream: TcpStream,
    records: RecordReader,
    ciphers: Ciphers,
    label: usize,
    lane: Lane,
    /// What is needed to start over on the other address family, kept until
    /// the DC's first byte arrives.
    early: Box<Early>,
}

/// State for retrying the upstream connection. A DC connection can be reset
/// (by the DC or by something on the path) before the DC has answered at all;
/// nothing has reached the client yet at that point, so the upstream side can
/// be rebuilt from scratch on the other address family.
struct Early {
    dc_idx: i16,
    /// The DC address the current upstream connection uses.
    used: SocketAddr,
    /// The client's proxy→client key and IV, for the fast-mode upstream init.
    enc_key: [u8; 32],
    enc_iv: [u8; 16],
    /// Client payload sent upstream so far, decrypted, to be replayed.
    sent: Vec<u8>,
    /// Bytes of client payload sent upstream so far.
    sent_len: usize,
    /// The client has sent more than is kept; a retry is no longer possible.
    overflow: bool,
}

/// Client payload kept for a retry. A client's first flight is well under this.
const EARLY_DATA_LIMIT: usize = 16 * 1024;

impl Early {
    fn remember(&mut self, plain: &[u8]) {
        self.sent_len += plain.len();
        if self.overflow {
            return;
        }
        if self.sent.len() + plain.len() > EARLY_DATA_LIMIT {
            self.overflow = true;
            self.sent = Vec::new();
        } else {
            self.sent.extend_from_slice(plain);
        }
    }
}

/// What to do with a connection once everything before the relay is settled.
enum Next {
    Relay(Established),
    /// Hand the connection, with these already-read bytes, to a mask site.
    Mask(Vec<u8>),
    /// Stay silent until the client gives up or the handshake deadline passes.
    Drain,
    Close,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn handshake(
    stream: &mut TcpStream,
    proxy: &Proxy,
    seen: &mut Seen,
) -> Result<Session, Reject> {
    let mut header = [0u8; RECORD_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    seen.bytes.extend_from_slice(&header);
    let payload_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    // Any TLS handshake record is read in full, even one that cannot be
    // fake-tls, so its SNI can pick the mask target.
    if header[..2] != [0x16, 0x03] || payload_len > MAX_RECORD_PAYLOAD {
        return Err(HelloError::Malformed.into());
    }
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;
    seen.bytes.extend_from_slice(&payload);
    drop(payload);

    let hello = tls::verify_client_hello(&seen.bytes, &proxy.secrets, unix_now(), &proxy.skew)?;
    if !proxy.replay.check_and_insert(&hello.client_random) {
        return Err(Reject::Replay);
    }
    tracing::debug!(sni = ?hello.sni, secret = hello.secret_index, "client hello accepted");
    let secret = &proxy.secrets[hello.secret_index];

    let response = {
        let mut rng = rand::thread_rng();
        let cert_len = rng.gen_range(FAKE_CERT_LEN);
        tls::build_server_hello(
            &secret.key,
            &hello.client_random,
            hello.session_id,
            cert_len,
            &mut rng,
        )
    };
    seen.replied = true;
    stream.write_all(&response).await?;

    let mut records = RecordReader::new();
    let mut payload = Vec::with_capacity(INIT_LEN);
    let mut buf = [0u8; 2048];
    while payload.len() < INIT_LEN {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        let len = records.unwrap_in_place(&mut buf, n)?;
        payload.extend_from_slice(&buf[..len]);
    }

    let mut init_bytes = [0u8; INIT_LEN];
    init_bytes.copy_from_slice(&payload[..INIT_LEN]);
    // Only the secret that signed the ClientHello may be used for the init.
    let init = obfs2::parse_client_init(&init_bytes, &secret.key)?;
    if !proxy
        .replay
        .check_and_insert(&obfs2::replay_key(&init_bytes))
    {
        return Err(Reject::Replay);
    }

    Ok(Session {
        init,
        records,
        leftover: payload.split_off(INIT_LEN),
    })
}

/// Reads and discards until the peer closes: no reply, no reset. Used when a
/// failed handshake cannot be handed to a mask site.
async fn drain(stream: &mut TcpStream) {
    let mut buf = [0u8; 2048];
    while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
}

/// The bytes that open an upstream connection in the configured mode, with
/// the upstream-side ciphers that go with them.
fn upstream_handshake(
    mode: UpstreamMode,
    enc_key: &[u8; 32],
    enc_iv: &[u8; 16],
) -> (Vec<u8>, Option<Box<AesCtr>>, Option<Box<AesCtr>>) {
    match mode {
        UpstreamMode::Fast => {
            let up = obfs2::upstream_init(obfs2::random_init_seed(), Some((enc_key, enc_iv)));
            (up.wire.to_vec(), Some(Box::new(up.enc)), None)
        }
        UpstreamMode::Obfuscated => {
            let up = obfs2::upstream_init(obfs2::random_init_seed(), None);
            (
                up.wire.to_vec(),
                Some(Box::new(up.enc)),
                Some(Box::new(up.dec)),
            )
        }
        UpstreamMode::Plain => (TAG_SECURE.to_vec(), None, None),
    }
}

/// Connects to the DC and sends the upstream handshake together with any
/// client payload that arrived behind the init.
async fn connect_upstream(
    session: Session,
    proxy: &Proxy,
) -> io::Result<(TcpStream, RecordReader, Ciphers, Box<Early>)> {
    let Session {
        init,
        records,
        mut leftover,
    } = session;
    let ClientInit {
        dec: client_dec,
        enc: client_enc,
        dc_idx,
        keys,
    } = init;
    let mut client_dec = Box::new(client_dec);

    let (mut upstream, used) = proxy.dc.connect(dc_idx).await?;
    let (mut first, mut upstream_enc, upstream_dec) =
        upstream_handshake(proxy.upstream_mode, &keys.enc_key, &keys.enc_iv);
    // Fast mode leaves the DC's bytes untouched, so nothing encrypts for the client.
    let client_enc = (proxy.upstream_mode != UpstreamMode::Fast).then(|| Box::new(client_enc));

    client_dec.apply(&mut leftover);
    let mut early = Box::new(Early {
        dc_idx,
        used,
        enc_key: keys.enc_key,
        enc_iv: keys.enc_iv,
        sent: Vec::new(),
        sent_len: 0,
        overflow: false,
    });
    early.remember(&leftover);

    let header_len = first.len();
    first.extend_from_slice(&leftover);
    if let Some(enc) = upstream_enc.as_mut() {
        enc.apply(&mut first[header_len..]);
    }
    upstream.write_all(&first).await?;

    Ok((
        upstream,
        records,
        Ciphers {
            client_dec,
            upstream_enc,
            upstream_dec,
            client_enc,
        },
        early,
    ))
}

fn is_reset(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

/// Opens a fresh upstream connection on the other address family and replays
/// the handshake and the client's payload so far.
async fn reconnect_upstream(session: &mut Established, proxy: &Proxy) -> io::Result<()> {
    let early = &mut session.early;
    let (mut upstream, used) = proxy
        .dc
        .connect_other_family(early.dc_idx, early.used)
        .await?;
    let (mut first, mut upstream_enc, upstream_dec) =
        upstream_handshake(proxy.upstream_mode, &early.enc_key, &early.enc_iv);
    let header_len = first.len();
    first.extend_from_slice(&early.sent);
    if let Some(enc) = upstream_enc.as_mut() {
        enc.apply(&mut first[header_len..]);
    }
    upstream.write_all(&first).await?;

    early.used = used;
    session.ciphers.upstream_enc = upstream_enc;
    session.ciphers.upstream_dec = upstream_dec;
    session.upstream = upstream;
    Ok(())
}

/// What the DC side did while its first byte was awaited.
enum DcEvent {
    Data,
    Closed,
    Failed(io::Error),
}

async fn dc_event(upstream: &TcpStream) -> DcEvent {
    let mut probe = [0u8; 1];
    // Peeking leaves the byte for the relay to read.
    match upstream.peek(&mut probe).await {
        Ok(0) => DcEvent::Closed,
        Ok(_) => DcEvent::Data,
        Err(err) => DcEvent::Failed(err),
    }
}

/// Forwards one read from the client to the DC, remembering it for a retry.
/// Returns `Ok(false)` when the client has closed.
async fn forward_early(
    client: &TcpStream,
    session: &mut Established,
    traffic: &SessionTraffic<'_>,
) -> Result<bool, (ClosedBy, io::Error)> {
    let mut buf = pool::take();
    let n = match client.try_read(&mut buf) {
        Ok(0) => return Ok(false),
        Ok(n) => n,
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(true),
        Err(err) => return Err((ClosedBy::Client, err)),
    };
    let len = session.records.unwrap_in_place(&mut buf, n).map_err(|e| {
        (
            ClosedBy::Client,
            io::Error::new(io::ErrorKind::InvalidData, e),
        )
    })?;
    if len == 0 {
        return Ok(true);
    }
    let payload = &mut buf[..len];
    session.ciphers.client_dec.apply(payload);
    session.early.remember(payload);
    if let Some(enc) = session.ciphers.upstream_enc.as_mut() {
        enc.apply(payload);
    }
    let _ = traffic.account(Direction::Up, len);
    crate::relay::write_all(&session.upstream, payload)
        .await
        .map_err(|err| (ClosedBy::Dc, err))?;
    Ok(true)
}

/// Runs the session until the DC's first byte is waiting to be read.
///
/// Until then nothing from the DC has reached the client, so if the DC
/// connection is reset it is rebuilt once on the other address family.
/// Returns `Err` with how the session ended if it did not get that far.
async fn await_first_response(
    client: &TcpStream,
    session: &mut Established,
    proxy: &Proxy,
    traffic: &SessionTraffic<'_>,
) -> Result<(), Ended> {
    let mut retried = false;
    loop {
        let idle = async {
            match proxy.idle_timeout {
                Some(idle) => tokio::time::sleep(idle).await,
                None => std::future::pending().await,
            }
        };
        let failure = tokio::select! {
            event = dc_event(&session.upstream) => match event {
                DcEvent::Data => return Ok(()),
                DcEvent::Closed => return Err(Ended { by: ClosedBy::Dc, error: None }),
                DcEvent::Failed(err) => err,
            },
            ready = client.readable() => {
                if let Err(err) = ready {
                    return Err(Ended { by: ClosedBy::Client, error: Some(err) });
                }
                match forward_early(client, session, traffic).await {
                    Ok(true) => continue,
                    Ok(false) => return Err(Ended { by: ClosedBy::Client, error: None }),
                    Err((ClosedBy::Dc, err)) => err,
                    Err((by, err)) => return Err(Ended { by, error: Some(err) }),
                }
            }
            () = idle => return Err(Ended { by: ClosedBy::Idle, error: None }),
        };

        // The DC side failed before answering.
        let retryable = is_reset(&failure)
            && !retried
            && !session.early.overflow
            && proxy
                .dc
                .other_family(session.early.dc_idx, session.early.used)
                .is_some();
        if !retryable {
            return Err(Ended {
                by: ClosedBy::Dc,
                error: Some(failure),
            });
        }
        retried = true;
        match reconnect_upstream(session, proxy).await {
            Ok(()) => {
                proxy.stats.record_upstream_retry(true);
                tracing::debug!(
                    dc = session.early.dc_idx,
                    "upstream reset before answering; retried on the other address family"
                );
            }
            Err(err) => {
                proxy.stats.record_upstream_retry(false);
                return Err(Ended {
                    by: ClosedBy::Dc,
                    error: Some(err),
                });
            }
        }
    }
}

/// Everything up to the relay: handshake, accounting and the upstream connect.
async fn negotiate(stream: &mut TcpStream, proxy: &Proxy, deadline: Instant) -> Next {
    let stats = &proxy.stats;
    let mut seen = Seen::default();

    let outcome = tokio::time::timeout_at(deadline, handshake(stream, proxy, &mut seen)).await;
    let label = stats.label_index(seen.sni());
    let reason = match outcome {
        Ok(Ok(session)) => {
            stats.record_handshake(label, HandshakeResult::Accepted);
            drop(seen);
            let dc_idx = session.init.dc_idx;
            return match connect_upstream(session, proxy).await {
                Ok((upstream, records, ciphers, early)) => Next::Relay(Established {
                    upstream,
                    records,
                    ciphers,
                    label,
                    lane: Lane::from_dc_idx(dc_idx),
                    early,
                }),
                Err(err) => {
                    tracing::debug!(dc = dc_idx, error = %err, "upstream connect failed");
                    Next::Close
                }
            };
        }
        Ok(Err(Reject::Io(err))) => {
            tracing::debug!(error = %err, "handshake aborted");
            return Next::Close;
        }
        Ok(Err(reason)) => reason,
        Err(_) => {
            stats.record_handshake(label, HandshakeResult::Timeout);
            tracing::debug!("handshake timed out");
            return Next::Close;
        }
    };

    stats.record_handshake(label, reason.result());
    if let Reject::Hello(HelloError::BadTimestamp { skew_secs }) = reason {
        stats.record_skew_rejection(skew_secs);
        tracing::debug!(
            direction = tls::skew_direction(skew_secs),
            offset_secs = skew_secs.unsigned_abs(),
            "handshake rejected: client clock outside the skew window"
        );
    } else {
        tracing::debug!(%reason, "handshake rejected");
    }

    if seen.replied {
        Next::Drain
    } else {
        Next::Mask(seen.bytes)
    }
}

/// Runs one client connection.
///
/// The future of this function is the task that lives as long as the session,
/// so every idle client pays for its size. Each phase before the relay keeps
/// buffers and cipher states in its own state, so those phases run as boxed
/// futures that are freed when they finish; the relay itself is awaited inline
/// and holds only pointers.
pub async fn handle_client(mut stream: TcpStream, proxy: Arc<Proxy>) {
    let _ = stream.set_nodelay(true);
    let deadline = Instant::now() + proxy.handshake_timeout;

    let next = Box::pin(negotiate(&mut stream, &proxy, deadline)).await;
    match next {
        Next::Relay(mut session) => {
            let _active = proxy.stats.session_started(session.label);
            let traffic = SessionTraffic::new(session.lane, &proxy.stats.limits, &stream);
            // Counted and charged like any relayed bytes; too small to wait for.
            let _ = traffic.account(Direction::Up, session.early.sent_len);
            let first = Box::pin(await_first_response(
                &stream,
                &mut session,
                &proxy,
                &traffic,
            ))
            .await;
            // The retry state, with the client's first payload, is not needed
            // once the DC has answered.
            let Established {
                upstream,
                records,
                ciphers,
                early,
                ..
            } = session;
            drop(early);
            let ended = match first {
                Ok(()) => {
                    relay(
                        &stream,
                        &upstream,
                        records,
                        ciphers,
                        proxy.idle_timeout,
                        &traffic,
                    )
                    .await
                }
                Err(ended) => ended,
            };
            if let Some(err) = ended.error {
                tracing::debug!(error = %err, "session ended with error");
            }
        }
        Next::Mask(bytes) => {
            let (target, result) = Box::pin(proxy.masker.forward(&stream, bytes)).await;
            let stats = &proxy.stats;
            stats.record_mask(stats.label_index(Some(target)), result);
            if result == MaskResult::Limited {
                let _ = Box::pin(tokio::time::timeout_at(deadline, drain(&mut stream))).await;
            }
        }
        Next::Drain => {
            let _ = Box::pin(tokio::time::timeout_at(deadline, drain(&mut stream))).await;
        }
        Next::Close => {}
    }
}

/// How often egress is measured and the media scale adjusted.
pub const CONGESTION_TICK: Duration = Duration::from_millis(200);

/// Runs congestion control forever: measures relay egress every tick and
/// scales media rates down while it exceeds the configured share of the link.
pub async fn run_congestion_control(stats: Arc<Stats>) {
    let mut ticker = tokio::time::interval(CONGESTION_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last = Instant::now();
    loop {
        ticker.tick().await;
        let now = Instant::now();
        stats.limits.tick(now.duration_since(last));
        last = now;
    }
}

/// Accepts connections forever, one task per connection.
pub async fn serve(listener: TcpListener, proxy: Arc<Proxy>) {
    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let proxy = proxy.clone();
                if let Some(slot) = proxy.stats.admit_connection(proxy.max_connections) {
                    tokio::spawn(async move {
                        handle_client(stream, proxy).await;
                        drop(slot);
                    });
                } else if let Ok(held) = proxy.overflow_slots.clone().try_acquire_owned() {
                    tokio::spawn(async move {
                        let _ =
                            tokio::time::timeout(proxy.handshake_timeout, drain(&mut stream)).await;
                        drop(held);
                    });
                }
            }
            Err(err) => {
                // Typically EMFILE/ENFILE: back off instead of spinning.
                tracing::warn!(error = %err, "accept failed");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::AesCtr;

    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    fn proxy() -> Arc<Proxy> {
        let config = Config::parse(
            "secrets = [\"ee000102030405060708090a0b0c0d0e0f612e636f6d\"]\nmetrics_listen = \"\"",
        )
        .unwrap();
        Arc::new(Proxy::from_config(&config).unwrap())
    }

    /// The task spawned per connection lives as long as the session, so its
    /// size is paid by every idle client. Run with --nocapture to see it.
    #[tokio::test]
    async fn per_connection_state_sizes() {
        let (_client, accepted) = socket_pair().await;
        let (_client2, accepted2) = socket_pair().await;
        let proxy = proxy();

        let mut seen = Seen::default();
        let mut for_handshake = accepted2;
        let handshake_size =
            std::mem::size_of_val(&handshake(&mut for_handshake, &proxy, &mut seen));
        let task_size = std::mem::size_of_val(&handle_client(accepted, proxy.clone()));

        // Guards against buffers or cipher states creeping back into the
        // state that every idle session keeps.
        assert!(
            task_size <= 1536,
            "per-connection task is {task_size} bytes"
        );

        println!("per-connection state, bytes:");
        println!("  handle_client future (the spawned task)  {task_size}");
        println!("  handshake future                         {handshake_size}");
        println!(
            "  AesCtr                                   {}",
            std::mem::size_of::<AesCtr>()
        );
        println!(
            "  relay::Ciphers                           {}",
            std::mem::size_of::<Ciphers>()
        );
        println!(
            "  Session                                  {}",
            std::mem::size_of::<Session>()
        );
        println!(
            "  ClientInit                               {}",
            std::mem::size_of::<ClientInit>()
        );
        println!(
            "  RecordReader                             {}",
            std::mem::size_of::<RecordReader>()
        );
        println!(
            "  TcpStream                                {}",
            std::mem::size_of::<TcpStream>()
        );
    }
}
