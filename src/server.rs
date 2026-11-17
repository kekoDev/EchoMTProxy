use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

use crate::cipher::Ctr;
use crate::config::{Config, Secret, UpstreamMode};
use crate::dc::DcTable;
use crate::obfs2::{self, ClientInit, InitError, INIT_LEN, TAG_SECURE};
use crate::relay::{relay, Ciphers};
use crate::replay::ReplayCache;
use crate::stats::Stats;
use crate::tls::{
    self, HelloError, RecordError, RecordReader, SkewPolicy, MAX_RECORD_PAYLOAD,
    MIN_CLIENT_HELLO_PAYLOAD, RECORD_HEADER_LEN,
};

// Fake certificate size range used by mtprotoproxy before it learns the real one.
const FAKE_CERT_LEN: std::ops::Range<usize> = 1024..4096;
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Everything a connection needs, shared by all of them.
pub struct Proxy {
    secrets: Vec<Secret>,
    skew: SkewPolicy,
    replay: ReplayCache,
    dc: DcTable,
    upstream_mode: UpstreamMode,
    handshake_timeout: Duration,
    stats: Stats,
}

impl Proxy {
    pub fn stats(&self) -> &Stats {
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
        Ok(Self {
            secrets: config.parsed_secrets()?,
            replay: ReplayCache::new(
                Duration::from_secs(skew.window_secs()),
                config.replay_cache_entries,
            ),
            skew,
            dc,
            upstream_mode: config.upstream_mode,
            handshake_timeout: Duration::from_secs(config.handshake_timeout_secs),
            stats: Stats::default(),
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

struct Session {
    init: ClientInit,
    records: RecordReader,
    /// Client payload that arrived together with the init, still encrypted.
    leftover: Vec<u8>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn handshake(stream: &mut TcpStream, proxy: &Proxy) -> Result<Session, Reject> {
    let mut record = vec![0u8; RECORD_HEADER_LEN];
    stream.read_exact(&mut record).await?;
    let payload_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    if record[..3] != [0x16, 0x03, 0x01]
        || !(MIN_CLIENT_HELLO_PAYLOAD..=MAX_RECORD_PAYLOAD).contains(&payload_len)
    {
        return Err(HelloError::Malformed.into());
    }
    record.resize(RECORD_HEADER_LEN + payload_len, 0);
    stream.read_exact(&mut record[RECORD_HEADER_LEN..]).await?;

    let hello = tls::verify_client_hello(&record, &proxy.secrets, unix_now(), &proxy.skew)?;
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

/// Reads and discards until the peer closes. Without masking (phase 2) this is
/// the least distinguishable reaction to a bad handshake: no reply, no reset.
async fn drain(stream: &mut TcpStream) {
    let mut buf = [0u8; 2048];
    while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
}

async fn run_session(client: TcpStream, session: Session, proxy: &Proxy) -> io::Result<()> {
    let Session {
        init,
        records,
        leftover,
    } = session;
    let ClientInit {
        dec: mut client_dec,
        enc: client_enc,
        dc_idx,
        keys,
    } = init;

    let mut upstream = proxy.dc.connect(dc_idx).await?;

    let mut first = Vec::with_capacity(INIT_LEN + leftover.len());
    let (mut upstream_enc, upstream_dec, client_enc) = match proxy.upstream_mode {
        UpstreamMode::Fast => {
            let up = obfs2::upstream_init(
                obfs2::random_init_seed(),
                Some((&keys.enc_key, &keys.enc_iv)),
            );
            first.extend_from_slice(&up.wire);
            (Some(up.enc), None, None)
        }
        UpstreamMode::Obfuscated => {
            let up = obfs2::upstream_init(obfs2::random_init_seed(), None);
            first.extend_from_slice(&up.wire);
            (Some(up.enc), Some(up.dec), Some(client_enc))
        }
        UpstreamMode::Plain => {
            first.extend_from_slice(&TAG_SECURE);
            (None, None, Some(client_enc))
        }
    };

    let header_len = first.len();
    first.extend_from_slice(&leftover);
    drop(leftover);
    client_dec.apply(&mut first[header_len..]);
    if let Some(enc) = upstream_enc.as_mut() {
        enc.apply(&mut first[header_len..]);
    }
    upstream.write_all(&first).await?;
    drop(first);

    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();
    relay(
        client_read,
        client_write,
        upstream_read,
        upstream_write,
        records,
        Ciphers {
            client_dec,
            upstream_enc,
            upstream_dec,
            client_enc,
        },
    )
    .await
}

pub async fn handle_client(mut stream: TcpStream, proxy: Arc<Proxy>) {
    let _ = stream.set_nodelay(true);
    let deadline = Instant::now() + proxy.handshake_timeout;

    let session = match tokio::time::timeout_at(deadline, handshake(&mut stream, &proxy)).await {
        Ok(Ok(session)) => session,
        Ok(Err(Reject::Io(err))) => {
            tracing::debug!(error = %err, "handshake aborted");
            return;
        }
        Ok(Err(reason)) => {
            if let Reject::Hello(HelloError::BadTimestamp { skew_secs }) = reason {
                proxy.stats.record_skew_rejection(skew_secs);
                tracing::debug!(
                    direction = tls::skew_direction(skew_secs),
                    offset_secs = skew_secs.unsigned_abs(),
                    "handshake rejected: client clock outside the skew window"
                );
            } else {
                tracing::debug!(%reason, "handshake rejected");
            }
            let _ = tokio::time::timeout_at(deadline, drain(&mut stream)).await;
            return;
        }
        Err(_) => {
            tracing::debug!("handshake timed out");
            return;
        }
    };

    let dc_idx = session.init.dc_idx;
    if let Err(err) = run_session(stream, session, &proxy).await {
        tracing::debug!(dc = dc_idx, error = %err, "session ended with error");
    }
}

/// Accepts connections forever, one task per connection.
pub async fn serve(listener: TcpListener, proxy: Arc<Proxy>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle_client(stream, proxy.clone()));
            }
            Err(err) => {
                // Typically EMFILE/ENFILE: back off instead of spinning.
                tracing::warn!(error = %err, "accept failed");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
            }
        }
    }
}
