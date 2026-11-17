//! Fake Telegram clients: each opens a fake-tls session through the proxy to
//! the fake DC and then idles or moves data.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use echo_mtproxy::cipher::{AesCtr, Ctr};
use echo_mtproxy::config::Secret;
use echo_mtproxy::obfs2;
use echo_mtproxy::sockopt;
use echo_mtproxy::tls::{self, RecordReader};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{watch, Semaphore};

use crate::dc::is_closed;
use crate::proto::{self, Op, ACK};
use crate::stats::{ClientStats, Failure};

const CHANGE_CIPHER_SPEC: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
/// Largest TLS record a server may send.
const MAX_RECORD: usize = 16384 + 256;
const DC_COUNT: usize = 5;
/// Sessions one address pair takes before local ports get scarce with the
/// default Linux port range (see `port_pressure_warning`).
const COMFORTABLE_SESSIONS_PER_PAIR: usize = 14_000;
/// How often idle sessions are checked for having been closed by the proxy.
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Echo,
    Download,
    Upload,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Proxy addresses, used in rotation.
    pub targets: Vec<SocketAddr>,
    /// Local source addresses, used in rotation. Empty lets the kernel choose.
    pub bind: Vec<IpAddr>,
    pub secret: Secret,
    /// SNI to send; normally the secret's domain.
    pub sni: String,
    /// Total sessions to open.
    pub connections: usize,
    /// How many of them move data; the rest stay idle.
    pub active: usize,
    pub mode: Mode,
    /// Bytes per echo, per download request or per upload write.
    pub payload: usize,
    /// Pause between two requests of one active session.
    pub interval: Duration,
    /// New sessions per second; 0 means as fast as `concurrency` allows.
    pub rate: f64,
    /// Handshakes in flight at once.
    pub concurrency: usize,
    /// Share of sessions (0 to 1) opened on the media lane (negative DC index).
    pub media_share: f64,
    pub handshake_timeout: Duration,
    /// How long to hold the sessions after the ramp-up.
    pub hold: Duration,
    /// Compare echoed data byte for byte.
    pub verify: bool,
}

impl ClientConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.targets.is_empty(), "no target address");
        anyhow::ensure!(self.connections > 0, "connections must be at least 1");
        anyhow::ensure!(
            self.active <= self.connections,
            "active sessions exceed connections"
        );
        anyhow::ensure!(self.concurrency > 0, "concurrency must be at least 1");
        anyhow::ensure!(self.payload > 0, "payload must be at least 1 byte");
        anyhow::ensure!(
            (0.0..=1.0).contains(&self.media_share),
            "media share must be between 0 and 1"
        );
        anyhow::ensure!(
            tls::client_hello_template(&self.sni, &mut rand::thread_rng()).is_some(),
            "SNI {:?} is too long for a ClientHello",
            self.sni
        );
        for ip in &self.bind {
            anyhow::ensure!(
                self.targets.iter().any(|t| t.is_ipv4() == ip.is_ipv4()),
                "source address {ip} matches no target's address family"
            );
        }
        Ok(())
    }

    /// Number of distinct (source, target) pairs sessions are spread over.
    pub fn address_pairs(&self) -> usize {
        self.targets
            .iter()
            .map(|target| {
                self.bind
                    .iter()
                    .filter(|ip| ip.is_ipv4() == target.is_ipv4())
                    .count()
                    .max(1)
            })
            .sum()
    }

    /// A warning if so many sessions share one address pair that the kernel
    /// runs short of cheap local ports.
    ///
    /// Linux gives outgoing connections the even ports of the local range
    /// first, about 14 000 per pair with the default range. Beyond that every
    /// connect searches the odd ports and new sessions take a second or more.
    pub fn port_pressure_warning(&self) -> Option<String> {
        let per_pair = self.connections.div_ceil(self.address_pairs());
        (per_pair > COMFORTABLE_SESSIONS_PER_PAIR).then(|| {
            format!(
                "{per_pair} sessions per (source, target) address pair: above about                  {COMFORTABLE_SESSIONS_PER_PAIR} the ramp-up slows down sharply and handshakes                  take seconds. Add --target or --bind addresses, or widen                  net.ipv4.ip_local_port_range. The proxy's own connections to the fake DC                  have the same limit per (upstream_bind_addrs, DC address) pair."
            )
        })
    }

    /// The proxy address and source address for the `index`th session. Every
    /// (source, target) pair is its own pool of local ports, so sessions are
    /// spread over all pairs.
    fn tuple(&self, index: usize) -> (SocketAddr, Option<IpAddr>) {
        let target = self.targets[index % self.targets.len()];
        let sources: Vec<IpAddr> = self
            .bind
            .iter()
            .copied()
            .filter(|ip| ip.is_ipv4() == target.is_ipv4())
            .collect();
        if sources.is_empty() {
            return (target, None);
        }
        let source = sources[(index / self.targets.len()) % sources.len()];
        (target, Some(source))
    }

    /// What the `index`th session does: the first `active` ones move data.
    fn op(&self, index: usize) -> Op {
        if index >= self.active {
            return Op::Idle;
        }
        match self.mode {
            Mode::Echo => Op::Echo,
            Mode::Download => Op::Download,
            Mode::Upload => Op::Upload,
        }
    }

    /// DC index for the `index`th session: DCs in rotation, negative for the
    /// media lane.
    fn dc_idx(&self, index: usize) -> i16 {
        let dc = (index % DC_COUNT) as i16 + 1;
        // Spread media sessions evenly instead of putting them first.
        let media = ((index + 1) as f64 * self.media_share).floor()
            > (index as f64 * self.media_share).floor();
        if media {
            -dc
        } else {
            dc
        }
    }
}

/// An established session through the proxy to the fake DC.
struct Session {
    stream: TcpStream,
    enc: AesCtr,
    dec: AesCtr,
    records: RecordReader,
    /// Decrypted bytes received beyond what was asked for.
    pending: Vec<u8>,
}

fn classify(err: &io::Error) -> Failure {
    match err.kind() {
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted => Failure::Closed,
        _ => Failure::Io,
    }
}

async fn read_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut record = vec![0u8; 5];
    stream.read_exact(&mut record).await?;
    let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    if len > MAX_RECORD {
        return Err(io::ErrorKind::InvalidData.into());
    }
    record.resize(5 + len, 0);
    stream.read_exact(&mut record[5..]).await?;
    Ok(record)
}

impl Session {
    async fn send(
        &mut self,
        data: &[u8],
        scratch: &mut Vec<u8>,
        framed: &mut Vec<u8>,
    ) -> io::Result<()> {
        scratch.clear();
        scratch.extend_from_slice(data);
        self.enc.apply(scratch);
        framed.clear();
        tls::wrap_records(scratch, framed);
        self.stream.write_all(framed).await
    }

    /// Receives exactly `len` payload bytes into `out` (replacing its contents).
    async fn recv(&mut self, len: usize, out: &mut Vec<u8>, buf: &mut [u8]) -> io::Result<()> {
        out.clear();
        std::mem::swap(out, &mut self.pending);
        while out.len() < len {
            let n = self.stream.read(buf).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let m = self
                .records
                .unwrap_in_place(buf, n)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            self.dec.apply(&mut buf[..m]);
            out.extend_from_slice(&buf[..m]);
        }
        self.pending = out.split_off(len);
        Ok(())
    }
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

async fn connect(target: SocketAddr, source: Option<IpAddr>) -> io::Result<TcpStream> {
    let socket = if target.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(source) = source {
        // Leave the port open until connect so one source address is not
        // limited to one port range across all targets.
        let _ = sockopt::set_bind_address_no_port(&socket);
        socket.bind(SocketAddr::new(source, 0))?;
    }
    let stream = socket.connect(target).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Opens the `index`th session: TCP, fake-tls, obfuscated2, then the header
/// for `op` and the fake DC's acknowledgement.
async fn open_session(config: &ClientConfig, index: usize, op: Op) -> Result<Session, Failure> {
    let (target, source) = config.tuple(index);
    let mut stream = connect(target, source)
        .await
        .map_err(|_| Failure::Connect)?;

    let key = &config.secret.key;
    let mut hello =
        tls::client_hello_template(&config.sni, &mut rand::thread_rng()).ok_or(Failure::Io)?;
    tls::sign_client_hello(&mut hello, key, unix_now());
    stream.write_all(&hello).await.map_err(|e| classify(&e))?;

    // ServerHello, ChangeCipherSpec and one application-data record.
    let mut response = Vec::with_capacity(4096);
    for expected in [0x16u8, 0x14, 0x17] {
        let record = read_record(&mut stream).await.map_err(|e| classify(&e))?;
        if record[0] != expected {
            return Err(Failure::BadServerHello);
        }
        response.extend_from_slice(&record);
    }
    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&hello[11..43]);
    if !tls::verify_server_hello(key, &client_random, &response) {
        return Err(Failure::BadServerHello);
    }

    let mut seed = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut seed);
    let mut init = obfs2::client_init(seed, key, config.dc_idx(index));
    let mut payload = init.wire.to_vec();
    let mut header = proto::header(op);
    init.enc.apply(&mut header);
    payload.extend_from_slice(&header);
    let mut first = CHANGE_CIPHER_SPEC.to_vec();
    tls::wrap_records(&payload, &mut first);
    stream.write_all(&first).await.map_err(|e| classify(&e))?;

    let mut session = Session {
        stream,
        enc: init.enc,
        dec: init.dec,
        records: RecordReader::new(),
        pending: Vec::new(),
    };
    let mut ack = Vec::with_capacity(ACK.len());
    let mut buf = [0u8; 512];
    session
        .recv(ACK.len(), &mut ack, &mut buf)
        .await
        .map_err(|e| classify(&e))?;
    if ack != ACK {
        return Err(Failure::NotLoadgenDc);
    }
    Ok(session)
}

async fn open_session_timed(
    config: &ClientConfig,
    index: usize,
    op: Op,
    stats: &ClientStats,
) -> Result<Session, Failure> {
    stats.attempted.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let result = tokio::time::timeout(config.handshake_timeout, open_session(config, index, op))
        .await
        .unwrap_or(Err(Failure::Timeout));
    match &result {
        Ok(_) => {
            stats.handshake_time.record(started.elapsed());
            stats.established.fetch_add(1, Ordering::Relaxed);
            stats.open.fetch_add(1, Ordering::Relaxed);
        }
        Err(failure) => stats.fail(*failure),
    }
    result
}

/// Moves data on one session until told to stop.
async fn drive(mut session: Session, config: &ClientConfig, stats: &ClientStats) -> io::Result<()> {
    let mut payload = vec![0u8; config.payload];
    rand::thread_rng().fill_bytes(&mut payload);
    let mut scratch = Vec::with_capacity(config.payload);
    let mut framed = Vec::with_capacity(config.payload + config.payload / 16384 * 5 + 5);
    let mut received = Vec::with_capacity(config.payload);
    let mut buf = vec![0u8; 16 * 1024];
    let request = (config.payload as u64).to_le_bytes();
    loop {
        let started = Instant::now();
        match config.mode {
            Mode::Echo => {
                session.send(&payload, &mut scratch, &mut framed).await?;
                stats
                    .bytes_up
                    .fetch_add(config.payload as u64, Ordering::Relaxed);
                session
                    .recv(config.payload, &mut received, &mut buf)
                    .await?;
                stats
                    .bytes_down
                    .fetch_add(config.payload as u64, Ordering::Relaxed);
                if config.verify && received != payload {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "echoed data differs from what was sent",
                    ));
                }
                stats.request_time.record(started.elapsed());
                stats.requests.fetch_add(1, Ordering::Relaxed);
            }
            Mode::Download => {
                session.send(&request, &mut scratch, &mut framed).await?;
                stats
                    .bytes_up
                    .fetch_add(request.len() as u64, Ordering::Relaxed);
                session
                    .recv(config.payload, &mut received, &mut buf)
                    .await?;
                stats
                    .bytes_down
                    .fetch_add(config.payload as u64, Ordering::Relaxed);
                stats.request_time.record(started.elapsed());
                stats.requests.fetch_add(1, Ordering::Relaxed);
            }
            Mode::Upload => {
                session.send(&payload, &mut scratch, &mut framed).await?;
                stats
                    .bytes_up
                    .fetch_add(config.payload as u64, Ordering::Relaxed);
            }
        }
        if !config.interval.is_zero() {
            tokio::time::sleep(config.interval).await;
        }
    }
}

fn describe_probe_failure(failure: Failure) -> &'static str {
    match failure {
        Failure::Connect => "could not connect to the proxy",
        Failure::Timeout => {
            "no answer in time: wrong secret (the proxy stays silent or masks), \
             or the proxy cannot reach the fake DC"
        }
        Failure::Closed => {
            "the proxy closed the connection: check that its dc_override points at a running \
             `echo-loadgen dc`"
        }
        Failure::BadServerHello => {
            "the answer is not this proxy's fake-tls ServerHello: wrong secret, or the address \
             is not the proxy"
        }
        Failure::NotLoadgenDc => {
            "the far end is not the fake DC. Refusing to continue: the proxy's DCs must be \
             overridden to `echo-loadgen dc`, never left pointing at Telegram"
        }
        Failure::Io => "I/O error during the handshake",
    }
}

/// Opens the configured sessions, keeps them for `hold`, then closes them.
///
/// The first sessions are probes, one per DC index. If any of them does not
/// reach the fake DC the run ends there, before any load is generated.
pub async fn run(
    config: ClientConfig,
    stats: Arc<ClientStats>,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    config.validate()?;
    let config = Arc::new(config);
    let idle: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
    let aborted = Arc::new(AtomicBool::new(false));
    let mut active_tasks = tokio::task::JoinSet::new();
    // Active sessions start moving data only once every session is open, so
    // the ramp-up measures handshakes and the hold measures steady traffic,
    // and the two do not compete for this process's CPU.
    let (ramp_done, ramp_finished) = watch::channel(false);

    let place = |index: usize, session: Session, active_tasks: &mut tokio::task::JoinSet<()>| {
        if index < config.active {
            let (config, stats) = (config.clone(), stats.clone());
            let mut ramp_finished = ramp_finished.clone();
            active_tasks.spawn(async move {
                if ramp_finished.wait_for(|done| *done).await.is_err() {
                    return;
                }
                if drive(session, &config, &stats).await.is_err() {
                    stats.active_errors.fetch_add(1, Ordering::Relaxed);
                }
                stats.open.fetch_sub(1, Ordering::Relaxed);
            });
        } else {
            // An idle session needs no ciphers and no task: only its socket.
            idle.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(session.stream);
        }
    };

    // Probes: the first sessions go out one at a time and cover every DC
    // index the run will use. A proxy with even one DC left pointing at
    // Telegram is caught here, with one connection, not during the ramp-up.
    let probes = config.connections.min(DC_COUNT);
    for index in 0..probes {
        let probe = open_session_timed(&config, index, config.op(index), &stats)
            .await
            .map_err(|failure| {
                anyhow::anyhow!(
                    "probe session for DC {} failed ({}): {}",
                    config.dc_idx(index).abs(),
                    failure.as_str(),
                    describe_probe_failure(failure)
                )
            })?;
        place(index, probe, &mut active_tasks);
    }

    // Ramp-up.
    let permits = Arc::new(Semaphore::new(config.concurrency));
    let (opened_tx, mut opened_rx) = tokio::sync::mpsc::unbounded_channel::<(usize, Session)>();
    let pace = (config.rate > 0.0).then(|| Duration::from_secs_f64(1.0 / config.rate));
    let ramp_started = Instant::now();
    let ramp = {
        let (config, stats, aborted) = (config.clone(), stats.clone(), aborted.clone());
        let mut stop = stop.clone();
        tokio::spawn(async move {
            for index in probes..config.connections {
                if *stop.borrow() || aborted.load(Ordering::Relaxed) {
                    break;
                }
                if let Some(pace) = pace {
                    let due = ramp_started + pace.mul_f64((index - probes) as f64);
                    tokio::select! {
                        () = tokio::time::sleep_until(due.into()) => {}
                        _ = stop.changed() => break,
                    }
                }
                let Ok(permit) = permits.clone().acquire_owned().await else {
                    break;
                };
                let (config, stats, aborted, opened_tx) = (
                    config.clone(),
                    stats.clone(),
                    aborted.clone(),
                    opened_tx.clone(),
                );
                let op = config.op(index);
                tokio::spawn(async move {
                    match open_session_timed(&config, index, op, &stats).await {
                        Ok(session) => {
                            let _ = opened_tx.send((index, session));
                        }
                        // The far end stopped being the fake DC mid-run.
                        Err(Failure::NotLoadgenDc) => aborted.store(true, Ordering::Relaxed),
                        Err(_) => {}
                    }
                    drop(permit);
                });
            }
        })
    };

    while let Some((index, session)) = opened_rx.recv().await {
        place(index, session, &mut active_tasks);
    }
    ramp.await.context("ramp-up task")?;
    anyhow::ensure!(
        !aborted.load(Ordering::Relaxed),
        "a session reached something that is not the fake DC; stopped"
    );

    // Hold, checking idle sessions for closes by the proxy.
    let _ = ramp_done.send(true);
    let hold_until = Instant::now() + config.hold;
    loop {
        let wake = hold_until.min(Instant::now() + SWEEP_INTERVAL);
        tokio::select! {
            () = tokio::time::sleep_until(wake.into()) => {}
            _ = stop.changed() => break,
        }
        sweep_idle(&idle, &stats);
        if Instant::now() >= hold_until || *stop.borrow() {
            break;
        }
    }
    sweep_idle(&idle, &stats);

    active_tasks.abort_all();
    while active_tasks.join_next().await.is_some() {}
    Ok(())
}

fn sweep_idle(idle: &Mutex<Vec<TcpStream>>, stats: &ClientStats) {
    let mut idle = idle.lock().unwrap_or_else(|e| e.into_inner());
    let before = idle.len();
    idle.retain(|stream| !is_closed(stream));
    let closed = (before - idle.len()) as u64;
    stats.closed_by_peer.fetch_add(closed, Ordering::Relaxed);
    stats.open.fetch_sub(closed, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(targets: &[&str], bind: &[&str]) -> ClientConfig {
        ClientConfig {
            targets: targets.iter().map(|t| t.parse().unwrap()).collect(),
            bind: bind.iter().map(|b| b.parse().unwrap()).collect(),
            secret: Secret::parse("ee000102030405060708090a0b0c0d0e0f612e636f6d").unwrap(),
            sni: "a.com".to_owned(),
            connections: 10,
            active: 2,
            mode: Mode::Echo,
            payload: 100,
            interval: Duration::ZERO,
            rate: 0.0,
            concurrency: 4,
            media_share: 0.0,
            handshake_timeout: Duration::from_secs(5),
            hold: Duration::ZERO,
            verify: true,
        }
    }

    #[test]
    fn sessions_rotate_over_every_source_and_target_pair() {
        let config = config(
            &["10.0.0.1:443", "10.0.0.1:8443"],
            &["10.1.0.1", "10.1.0.2", "10.1.0.3"],
        );
        let pairs: std::collections::HashSet<_> = (0..6).map(|i| config.tuple(i)).collect();
        assert_eq!(pairs.len(), 6);
        // The seventh session starts over.
        assert_eq!(config.tuple(6), config.tuple(0));
    }

    #[test]
    fn source_addresses_match_the_target_family() {
        let config = config(
            &["10.0.0.1:443", "[2001:db8::1]:443"],
            &["10.1.0.1", "2001:db8::9"],
        );
        for index in 0..8 {
            let (target, source) = config.tuple(index);
            assert_eq!(target.is_ipv4(), source.unwrap().is_ipv4());
        }
        let no_bind = super::tests::config(&["10.0.0.1:443"], &[]);
        assert_eq!(no_bind.tuple(3).1, None);
    }

    #[test]
    fn media_share_is_spread_evenly() {
        let mut config = config(&["10.0.0.1:443"], &[]);
        for (share, expected) in [(0.0, 0), (0.25, 250), (0.5, 500), (1.0, 1000)] {
            config.media_share = share;
            let media = (0..1000).filter(|i| config.dc_idx(*i) < 0).count();
            assert_eq!(media, expected, "share {share}");
        }
        config.media_share = 0.25;
        // Not bunched at the start: every block of 40 has about 10.
        for block in 0..25 {
            let media = (block * 40..block * 40 + 40)
                .filter(|i| config.dc_idx(*i) < 0)
                .count();
            assert_eq!(media, 10, "block {block}");
        }
        // Every DC is used, on both lanes.
        let dcs: std::collections::HashSet<i16> = (0..1000).map(|i| config.dc_idx(i)).collect();
        assert_eq!(dcs.len(), 10);
    }

    #[test]
    fn port_pressure_is_reported_per_address_pair() {
        let mut one_pair = config(&["10.0.0.1:443"], &[]);
        one_pair.connections = 14_000;
        assert_eq!(one_pair.address_pairs(), 1);
        assert_eq!(one_pair.port_pressure_warning(), None);
        one_pair.connections = 14_001;
        let warning = one_pair.port_pressure_warning().unwrap();
        assert!(warning.contains("14001 sessions per"), "{warning}");

        // 2 targets x 3 sources = 6 pairs.
        let mut six_pairs = config(
            &["10.0.0.1:443", "10.0.0.1:8443"],
            &["10.1.0.1", "10.1.0.2", "10.1.0.3"],
        );
        assert_eq!(six_pairs.address_pairs(), 6);
        six_pairs.connections = 84_000;
        assert_eq!(six_pairs.port_pressure_warning(), None);
        six_pairs.connections = 100_000;
        assert!(six_pairs.port_pressure_warning().is_some());

        // Sources only count for targets of their own family.
        let mixed = config(
            &["10.0.0.1:443", "[2001:db8::1]:443"],
            &["10.1.0.1", "10.1.0.2"],
        );
        assert_eq!(mixed.address_pairs(), 3);
    }

    #[test]
    fn invalid_configs_are_rejected() {
        assert!(config(&["10.0.0.1:443"], &[]).validate().is_ok());
        assert!(config(&[], &[]).validate().is_err());
        assert!(config(&["10.0.0.1:443"], &["2001:db8::1"])
            .validate()
            .is_err());
        let mut bad = config(&["10.0.0.1:443"], &[]);
        bad.active = 11;
        assert!(bad.validate().is_err());
        let mut bad = config(&["10.0.0.1:443"], &[]);
        bad.media_share = 1.5;
        assert!(bad.validate().is_err());
        let mut bad = config(&["10.0.0.1:443"], &[]);
        bad.sni = "a".repeat(300);
        assert!(bad.validate().is_err());
        let mut bad = config(&["10.0.0.1:443"], &[]);
        bad.connections = 0;
        bad.active = 0;
        assert!(bad.validate().is_err());
    }
}
