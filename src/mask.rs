use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use socket2::SockRef;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::{MaskDomain, MaskTarget};
use crate::pool;
use crate::relay::write_all;
use crate::stats::MaskResult;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Forwards connections that failed the handshake to a real TLS site, so the
/// proxy answers probes the way that site would.
pub struct Masker {
    /// Allowlisted SNI (lowercase) to index into `targets`.
    allowed: HashMap<String, usize>,
    /// Allowlisted targets followed by the default one.
    targets: Vec<MaskDomain>,
    permits: Semaphore,
    /// A masked connection is dropped when either direction is silent this long.
    idle_timeout: Duration,
    dns_ttl: Duration,
    resolved: Mutex<HashMap<usize, (Vec<SocketAddr>, Instant)>>,
}

impl Masker {
    pub fn new(
        allowlist: Vec<MaskDomain>,
        default: MaskDomain,
        max_connections: usize,
        idle_timeout: Duration,
        dns_ttl: Duration,
    ) -> Self {
        let allowed = allowlist
            .iter()
            .enumerate()
            .map(|(index, entry)| (entry.domain.clone(), index))
            .collect();
        let mut targets = allowlist;
        targets.push(default);
        Self {
            allowed,
            targets,
            permits: Semaphore::new(max_connections),
            idle_timeout,
            dns_ttl,
            resolved: Mutex::new(HashMap::new()),
        }
    }

    /// Names every target is reported under, default last.
    pub fn target_names(&self) -> impl Iterator<Item = &str> {
        self.targets.iter().map(|t| t.domain.as_str())
    }

    /// The target for a failed handshake: the client's SNI when it is
    /// allowlisted (exact match, case-insensitive), otherwise the default.
    /// The SNI only ever selects among configured targets; it is never
    /// resolved or connected to itself.
    pub fn select(&self, sni: Option<&str>) -> &MaskDomain {
        &self.targets[self.select_index(sni)]
    }

    fn select_index(&self, sni: Option<&str>) -> usize {
        sni.filter(|name| name.len() <= 253)
            .map(|name| name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase())
            .and_then(|name| self.allowed.get(&name).copied())
            .unwrap_or(self.targets.len() - 1)
    }

    async fn resolve(&self, target: &MaskTarget, index: usize) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, target.port)]);
        }
        let cached = self
            .resolved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&index)
            .filter(|(_, at)| at.elapsed() < self.dns_ttl)
            .map(|(addrs, _)| addrs.clone());
        if let Some(addrs) = cached {
            return Ok(addrs);
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((target.host.as_str(), target.port))
            .await?
            .collect();
        if addrs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no addresses"));
        }
        self.resolved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(index, (addrs.clone(), Instant::now()));
        Ok(addrs)
    }

    async fn connect(&self, index: usize) -> io::Result<TcpStream> {
        let target = &self.targets[index];
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, async {
            let addrs = self.resolve(&target.target, index).await?;
            TcpStream::connect(&addrs[..]).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mask connect timed out"))??;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// Replays `seen` (everything read from the client so far) to the target
    /// its SNI selects and splices the two connections until both directions
    /// are done. Returns the target's name with the outcome.
    ///
    /// `seen` is taken by value and freed once it has been replayed, and the
    /// splice borrows pool buffers only while bytes are in flight, so a quiet
    /// masked connection holds neither.
    pub async fn forward(&self, client: &TcpStream, seen: Vec<u8>) -> (&str, MaskResult) {
        let index = self.select_index(crate::tls::client_hello_sni(&seen));
        let name = self.targets[index].domain.as_str();
        let Ok(_permit) = self.permits.try_acquire() else {
            return (name, MaskResult::Limited);
        };
        let mut server = match self.connect(index).await {
            Ok(server) => server,
            Err(err) => {
                tracing::debug!(mask = name, error = %err, "mask connect failed");
                return (name, MaskResult::ConnectFailed);
            }
        };
        if server.write_all(&seen).await.is_err() {
            return (name, MaskResult::ConnectFailed);
        }
        drop(seen);

        let result = tokio::try_join!(
            pipe(client, &server, self.idle_timeout),
            pipe(&server, client, self.idle_timeout)
        );
        if matches!(&result, Err(err) if err.kind() == io::ErrorKind::ConnectionReset) {
            // Pass a reset on as a reset rather than a clean close.
            let _ = SockRef::from(client).set_linger(Some(Duration::ZERO));
        }
        (name, MaskResult::Forwarded)
    }
}

fn idle_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "mask connection idle")
}

/// Copies one direction until EOF, which is passed on as a write shutdown.
/// Fails if the source stays silent, or the sink stays blocked, for `idle`.
async fn pipe(from: &TcpStream, to: &TcpStream, idle: Duration) -> io::Result<()> {
    loop {
        // Quiet connections wait here without a buffer.
        tokio::time::timeout(idle, from.readable())
            .await
            .map_err(|_| idle_error())??;
        let mut buf = pool::take();
        let n = match from.try_read(&mut buf) {
            Ok(0) => {
                let _ = SockRef::from(to).shutdown(std::net::Shutdown::Write);
                return Ok(());
            }
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        };
        tokio::time::timeout(idle, write_all(to, &buf[..n]))
            .await
            .map_err(|_| idle_error())??;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(name: &str, host: &str, port: u16) -> MaskDomain {
        MaskDomain {
            domain: name.to_owned(),
            target: MaskTarget {
                host: host.to_owned(),
                port,
            },
        }
    }

    fn masker() -> Masker {
        masker_with_ttl(Duration::from_secs(300))
    }

    fn masker_with_ttl(dns_ttl: Duration) -> Masker {
        Masker::new(
            vec![
                domain("google.com", "google.com", 443),
                domain("local.example", "127.0.0.1", 8443),
            ],
            domain("localhost.test", "localhost", 443),
            4,
            Duration::from_secs(120),
            dns_ttl,
        )
    }

    #[test]
    fn allowlisted_sni_selects_its_own_target() {
        let masker = masker();
        assert_eq!(masker.select(Some("google.com")).domain, "google.com");
        assert_eq!(masker.select(Some("GOOGLE.COM")).domain, "google.com");
        assert_eq!(masker.select(Some("google.com.")).domain, "google.com");
        let local = masker.select(Some("local.example"));
        assert_eq!(local.target.host, "127.0.0.1");
        assert_eq!(local.target.port, 8443);
    }

    #[test]
    fn everything_else_goes_to_the_default() {
        let masker = masker();
        for sni in [
            None,
            Some(""),
            Some("www.google.com"),
            Some("google.com.attacker.example"),
            Some("notgoogle.com"),
            Some("10.0.0.1"),
            Some("localhost"),
            Some("localhost.test"),
            Some("google.com\0"),
        ] {
            assert_eq!(masker.select(sni).domain, "localhost.test", "{sni:?}");
        }
        let long = "a".repeat(1_000_000);
        assert_eq!(masker.select(Some(&long)).domain, "localhost.test");
    }

    #[test]
    fn target_names_list_the_default_last() {
        let names: Vec<_> = masker().target_names().map(str::to_owned).collect();
        assert_eq!(names, ["google.com", "local.example", "localhost.test"]);
    }

    #[tokio::test]
    async fn ip_targets_skip_dns() {
        let masker = masker();
        let target = masker.select(Some("local.example")).clone();
        let addrs = masker.resolve(&target.target, 1).await.unwrap();
        assert_eq!(addrs, ["127.0.0.1:8443".parse().unwrap()]);
        assert!(masker.resolved.lock().unwrap().is_empty());
    }

    const DEFAULT: usize = 2;

    async fn resolve_default(masker: &Masker) -> Vec<SocketAddr> {
        let target = masker.select(None).target.clone();
        masker.resolve(&target, DEFAULT).await.unwrap()
    }

    /// Replaces the cached answer so a cache hit is distinguishable from a lookup.
    fn poison_cache(masker: &Masker) -> SocketAddr {
        let marker: SocketAddr = "192.0.2.77:443".parse().unwrap();
        let mut cache = masker.resolved.lock().unwrap();
        let entry = cache.get_mut(&DEFAULT).expect("lookup was not cached");
        entry.0 = vec![marker];
        marker
    }

    #[tokio::test]
    async fn resolved_hosts_are_reused_within_the_ttl() {
        let masker = masker_with_ttl(Duration::from_secs(300));
        let real = resolve_default(&masker).await;
        assert!(real.iter().all(|a| a.ip().is_loopback() && a.port() == 443));
        let marker = poison_cache(&masker);
        assert_eq!(resolve_default(&masker).await, [marker]);
    }

    #[tokio::test]
    async fn zero_ttl_resolves_every_time() {
        let masker = masker_with_ttl(Duration::ZERO);
        let real = resolve_default(&masker).await;
        let marker = poison_cache(&masker);
        let again = resolve_default(&masker).await;
        assert_eq!(again, real);
        assert!(!again.contains(&marker));
    }

    #[tokio::test]
    async fn expired_entries_are_resolved_again() {
        let masker = masker_with_ttl(Duration::from_millis(50));
        let real = resolve_default(&masker).await;
        let marker = poison_cache(&masker);
        assert_eq!(resolve_default(&masker).await, [marker]);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(resolve_default(&masker).await, real);
    }

    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (near, far) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (near.unwrap(), far.unwrap().0)
    }

    /// `source -> [from | pipe | to] -> sink`
    async fn piped(
        idle: Duration,
    ) -> (
        TcpStream,
        TcpStream,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let (source, from) = socket_pair().await;
        let (to, sink) = socket_pair().await;
        let task = tokio::spawn(async move { pipe(&from, &to, idle).await });
        (source, sink, task)
    }

    #[tokio::test]
    async fn pipe_times_out_only_when_idle() {
        use tokio::io::AsyncReadExt;
        const IDLE: Duration = Duration::from_millis(400);
        let (mut source, mut sink, task) = piped(IDLE).await;

        let mut byte = [0u8; 1];
        for _ in 0..5 {
            tokio::time::sleep(IDLE * 3 / 4).await;
            source.write_all(b"x").await.unwrap();
            sink.read_exact(&mut byte).await.unwrap();
            assert!(!task.is_finished());
        }
        let start = Instant::now();
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let quiet = start.elapsed();
        assert!(quiet >= IDLE * 9 / 10 && quiet < IDLE * 2, "{quiet:?}");
    }

    #[tokio::test]
    async fn pipe_forwards_eof_as_shutdown() {
        use tokio::io::AsyncReadExt;
        let (mut source, mut sink, task) = piped(Duration::from_secs(5)).await;
        source.write_all(b"bye").await.unwrap();
        source.shutdown().await.unwrap();
        let mut out = Vec::new();
        sink.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"bye");
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn pipe_carries_large_transfers_through_backpressure() {
        use tokio::io::AsyncReadExt;
        let (mut source, mut sink, task) = piped(Duration::from_secs(5)).await;
        let data: Vec<u8> = (0..4_000_000u32).map(|i| (i % 253) as u8).collect();
        let expected = data.clone();
        let writer = tokio::spawn(async move {
            source.write_all(&data).await.unwrap();
            source.shutdown().await.unwrap();
        });
        // Let the pipe fill the sink's socket buffer before anyone reads.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut out = Vec::with_capacity(expected.len());
        sink.read_to_end(&mut out).await.unwrap();
        assert!(out == expected);
        writer.await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn blocked_sink_counts_as_idle() {
        // The source keeps sending but the sink never reads: once the sink's
        // buffers are full the pipe is stuck in a write, and must give up.
        let (mut source, _sink, task) = piped(Duration::from_millis(300)).await;
        let feeder = tokio::spawn(async move {
            let chunk = vec![0u8; 64 * 1024];
            while source.write_all(&chunk).await.is_ok() {}
        });
        let err = tokio::time::timeout(Duration::from_secs(20), task)
            .await
            .expect("pipe never gave up on a blocked sink")
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        feeder.abort();
    }
}
