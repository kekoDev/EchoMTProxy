use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::{MaskDomain, MaskTarget};
use crate::stats::MaskResult;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// A masked connection with no traffic in one direction for this long is dropped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const DNS_TTL: Duration = Duration::from_secs(300);
const BUF_LEN: usize = 8192;

/// Forwards connections that failed the handshake to a real TLS site, so the
/// proxy answers probes the way that site would.
pub struct Masker {
    /// Allowlisted SNI (lowercase) to index into `targets`.
    allowed: HashMap<String, usize>,
    /// Allowlisted targets followed by the default one.
    targets: Vec<MaskDomain>,
    permits: Semaphore,
    resolved: Mutex<HashMap<usize, (Vec<SocketAddr>, Instant)>>,
}

impl Masker {
    pub fn new(allowlist: Vec<MaskDomain>, default: MaskDomain, max_connections: usize) -> Self {
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
            .filter(|(_, at)| at.elapsed() < DNS_TTL)
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
    /// chosen by `sni` and splices the two connections until both directions
    /// are done. Returns the target's name with the outcome.
    pub async fn forward(
        &self,
        client: &mut TcpStream,
        seen: &[u8],
        sni: Option<&str>,
    ) -> (&str, MaskResult) {
        let index = self.select_index(sni);
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
        if server.write_all(seen).await.is_err() {
            return (name, MaskResult::ConnectFailed);
        }

        let result = {
            let (client_read, client_write) = client.split();
            let (server_read, server_write) = server.split();
            tokio::try_join!(
                pipe(client_read, server_write),
                pipe(server_read, client_write)
            )
        };
        if matches!(&result, Err(err) if err.kind() == io::ErrorKind::ConnectionReset) {
            // Pass a reset on as a reset rather than a clean close.
            let _ = SockRef::from(&*client).set_linger(Some(Duration::ZERO));
        }
        (name, MaskResult::Forwarded)
    }
}

async fn pipe<R, W>(mut from: R, mut to: W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF_LEN];
    loop {
        let n = tokio::time::timeout(IDLE_TIMEOUT, from.read(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mask connection idle"))??;
        if n == 0 {
            let _ = to.shutdown().await;
            return Ok(());
        }
        to.write_all(&buf[..n]).await?;
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
        Masker::new(
            vec![
                domain("google.com", "google.com", 443),
                domain("local.example", "127.0.0.1", 8443),
            ],
            domain("default.example", "default.example", 443),
            4,
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
            Some("default.example"),
            Some("google.com\0"),
        ] {
            assert_eq!(masker.select(sni).domain, "default.example", "{sni:?}");
        }
        let long = "a".repeat(1_000_000);
        assert_eq!(masker.select(Some(&long)).domain, "default.example");
    }

    #[test]
    fn target_names_list_the_default_last() {
        let names: Vec<_> = masker().target_names().map(str::to_owned).collect();
        assert_eq!(names, ["google.com", "local.example", "default.example"]);
    }

    #[tokio::test]
    async fn ip_targets_skip_dns() {
        let masker = masker();
        let target = masker.select(Some("local.example")).clone();
        let addrs = masker.resolve(&target.target, 1).await.unwrap();
        assert_eq!(addrs, ["127.0.0.1:8443".parse().unwrap()]);
        assert!(masker.resolved.lock().unwrap().is_empty());
    }
}
