use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::cipher::Ctr;
use crate::config::{Config, Secret, UpstreamMode};
use crate::dc::DcTable;
use crate::mask::Masker;
use crate::obfs2::{self, ClientInit, InitError, INIT_LEN, TAG_SECURE};
use crate::relay::{relay, Ciphers};
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
        let secrets = config.parsed_secrets()?;
        let masker = Masker::new(
            config.parsed_mask_domains()?,
            config.default_mask(&secrets)?,
            config.mask_max_connections,
            Duration::from_secs(config.mask_idle_timeout_secs),
            Duration::from_secs(config.mask_dns_ttl_secs),
        );
        let stats = Stats::new(
            masker
                .target_names()
                .map(str::to_owned)
                .chain(secrets.iter().map(|s| s.domain.clone())),
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

/// Connects to the DC and sends the upstream handshake together with any
/// client payload that arrived behind the init.
async fn connect_upstream(
    session: Session,
    proxy: &Proxy,
) -> io::Result<(TcpStream, RecordReader, Ciphers)> {
    let Session {
        init,
        records,
        leftover,
    } = session;
    let ClientInit {
        dec: client_dec,
        enc: client_enc,
        dc_idx,
        keys,
    } = init;
    let mut client_dec = Box::new(client_dec);

    let mut upstream = proxy.dc.connect(dc_idx).await?;

    let mut first = Vec::with_capacity(INIT_LEN + leftover.len());
    let (mut upstream_enc, upstream_dec, client_enc) = match proxy.upstream_mode {
        UpstreamMode::Fast => {
            let up = obfs2::upstream_init(
                obfs2::random_init_seed(),
                Some((&keys.enc_key, &keys.enc_iv)),
            );
            first.extend_from_slice(&up.wire);
            (Some(Box::new(up.enc)), None, None)
        }
        UpstreamMode::Obfuscated => {
            let up = obfs2::upstream_init(obfs2::random_init_seed(), None);
            first.extend_from_slice(&up.wire);
            (
                Some(Box::new(up.enc)),
                Some(Box::new(up.dec)),
                Some(Box::new(client_enc)),
            )
        }
        UpstreamMode::Plain => {
            first.extend_from_slice(&TAG_SECURE);
            (None, None, Some(Box::new(client_enc)))
        }
    };

    let header_len = first.len();
    first.extend_from_slice(&leftover);
    client_dec.apply(&mut first[header_len..]);
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
    ))
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
                Ok((upstream, records, ciphers)) => Next::Relay(Established {
                    upstream,
                    records,
                    ciphers,
                    label,
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
        Next::Relay(session) => {
            let _active = proxy.stats.session_started(session.label);
            let result = relay(
                &stream,
                &session.upstream,
                session.records,
                session.ciphers,
                proxy.idle_timeout,
            )
            .await;
            if let Err(err) = result {
                tracing::debug!(error = %err, "session ended with error");
            }
        }
        Next::Mask(bytes) => {
            let sni = tls::client_hello_sni(&bytes);
            let (target, result) = Box::pin(proxy.masker.forward(&mut stream, &bytes, sni)).await;
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
