use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};

use crate::sockopt;

pub const DC_COUNT: usize = 5;
const DC_PORT: u16 = 443;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// DC 5 follows mtprotoproxy (149.154.171.5).
const DC_V4: [Ipv4Addr; DC_COUNT] = [
    Ipv4Addr::new(149, 154, 175, 50),
    Ipv4Addr::new(149, 154, 167, 51),
    Ipv4Addr::new(149, 154, 175, 100),
    Ipv4Addr::new(149, 154, 167, 91),
    Ipv4Addr::new(149, 154, 171, 5),
];

const DC_V6: [Ipv6Addr; DC_COUNT] = [
    Ipv6Addr::new(0x2001, 0xb28, 0xf23d, 0xf001, 0, 0, 0, 0xa),
    Ipv6Addr::new(0x2001, 0x67c, 0x4e8, 0xf002, 0, 0, 0, 0xa),
    Ipv6Addr::new(0x2001, 0xb28, 0xf23d, 0xf003, 0, 0, 0, 0xa),
    Ipv6Addr::new(0x2001, 0x67c, 0x4e8, 0xf004, 0, 0, 0, 0xa),
    Ipv6Addr::new(0x2001, 0xb28, 0xf23f, 0xf005, 0, 0, 0, 0xa),
];

#[derive(Debug)]
pub struct DcTable {
    v4: [SocketAddr; DC_COUNT],
    v6: [SocketAddr; DC_COUNT],
    overridden: [bool; DC_COUNT],
    prefer_v6: bool,
    /// Local source addresses for upstream connections, by family.
    bind_v4: Vec<IpAddr>,
    bind_v6: Vec<IpAddr>,
    next_v4: AtomicUsize,
    next_v6: AtomicUsize,
}

impl DcTable {
    pub fn new(prefer_v6: bool) -> Self {
        Self {
            v4: DC_V4.map(|ip| SocketAddr::new(IpAddr::V4(ip), DC_PORT)),
            v6: DC_V6.map(|ip| SocketAddr::new(IpAddr::V6(ip), DC_PORT)),
            overridden: [false; DC_COUNT],
            prefer_v6,
            bind_v4: Vec::new(),
            bind_v6: Vec::new(),
            next_v4: AtomicUsize::new(0),
            next_v6: AtomicUsize::new(0),
        }
    }

    /// Replaces both address families of a DC (zero-based index) with one address.
    pub fn with_override(mut self, index: usize, addr: SocketAddr) -> Self {
        if index < DC_COUNT {
            self.v4[index] = addr;
            self.v6[index] = addr;
            self.overridden[index] = true;
        }
        self
    }

    /// Source addresses to connect to DCs from, used in rotation per family.
    /// Spreading connections over several addresses multiplies the number of
    /// connections one DC address can receive from this host. Fails if an
    /// address is not assigned to this host.
    pub fn with_bind_addrs(mut self, addrs: &[IpAddr]) -> io::Result<Self> {
        for ip in addrs {
            let probe = socket2::Socket::new(
                socket2::Domain::for_address(SocketAddr::new(*ip, 0)),
                socket2::Type::STREAM,
                None,
            )?;
            probe.bind(&SocketAddr::new(*ip, 0).into()).map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!("upstream_bind_addrs: cannot bind {ip}: {err}"),
                )
            })?;
            if ip.is_ipv4() {
                self.bind_v4.push(*ip);
            } else {
                self.bind_v6.push(*ip);
            }
        }
        Ok(self)
    }

    /// Next source address for a connection to `target`, if any are configured
    /// for its family.
    fn next_source(&self, target: SocketAddr) -> Option<IpAddr> {
        let (addrs, next) = if target.is_ipv4() {
            (&self.bind_v4, &self.next_v4)
        } else {
            (&self.bind_v6, &self.next_v6)
        };
        if addrs.is_empty() {
            return None;
        }
        Some(addrs[next.fetch_add(1, Ordering::Relaxed) % addrs.len()])
    }

    /// Addresses to try, in order, for the DC index sent by the client.
    /// Negative indexes are media DCs; direct mode uses the same address.
    pub fn candidates(&self, dc_idx: i16) -> Option<(SocketAddr, Option<SocketAddr>)> {
        let index = usize::from(dc_idx.unsigned_abs()).checked_sub(1)?;
        if index >= DC_COUNT {
            return None;
        }
        if self.overridden[index] {
            Some((self.v4[index], None))
        } else if self.prefer_v6 {
            Some((self.v6[index], Some(self.v4[index])))
        } else {
            Some((self.v4[index], None))
        }
    }

    pub async fn connect(&self, dc_idx: i16) -> io::Result<TcpStream> {
        let (first, fallback) = self.candidates(dc_idx).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "unknown datacenter index")
        })?;
        match self.connect_one(first).await {
            Ok(stream) => Ok(stream),
            Err(err) => match fallback {
                Some(addr) => self.connect_one(addr).await,
                None => Err(err),
            },
        }
    }

    /// A socket for a connection to `addr`, bound to the next source address
    /// when any are configured.
    fn prepare_socket(&self, addr: SocketAddr) -> io::Result<TcpSocket> {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if let Some(source) = self.next_source(addr) {
            // Without this, binding reserves a port at once and each source
            // address is limited to one ephemeral port range in total rather
            // than per destination.
            if let Err(err) = sockopt::set_bind_address_no_port(&socket) {
                tracing::debug!(error = %err, "IP_BIND_ADDRESS_NO_PORT not set");
            }
            socket.bind(SocketAddr::new(source, 0))?;
        }
        Ok(socket)
    }

    async fn connect_one(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let socket = self.prepare_socket(addr)?;
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream connect timed out"))??;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_matches_the_reference() {
        let table = DcTable::new(false);
        let v4: Vec<String> = (1..=5)
            .map(|i| table.candidates(i).unwrap().0.to_string())
            .collect();
        assert_eq!(
            v4,
            [
                "149.154.175.50:443",
                "149.154.167.51:443",
                "149.154.175.100:443",
                "149.154.167.91:443",
                "149.154.171.5:443"
            ]
        );
        let table = DcTable::new(true);
        let v6: Vec<String> = (1..=5)
            .map(|i| table.candidates(i).unwrap().0.to_string())
            .collect();
        assert_eq!(
            v6,
            [
                "[2001:b28:f23d:f001::a]:443",
                "[2001:67c:4e8:f002::a]:443",
                "[2001:b28:f23d:f003::a]:443",
                "[2001:67c:4e8:f004::a]:443",
                "[2001:b28:f23f:f005::a]:443"
            ]
        );
    }

    #[test]
    fn media_dcs_use_the_absolute_index() {
        let table = DcTable::new(false);
        for i in 1..=5 {
            assert_eq!(table.candidates(-i), table.candidates(i));
        }
    }

    #[test]
    fn out_of_range_indexes_are_rejected() {
        let table = DcTable::new(true);
        for idx in [0, 6, -6, 203, i16::MAX, i16::MIN] {
            assert_eq!(table.candidates(idx), None, "{idx}");
        }
    }

    #[test]
    fn ipv6_preference_falls_back_to_ipv4() {
        let (first, fallback) = DcTable::new(true).candidates(2).unwrap();
        assert!(first.is_ipv6());
        assert_eq!(fallback, Some("149.154.167.51:443".parse().unwrap()));
        let (first, fallback) = DcTable::new(false).candidates(2).unwrap();
        assert!(first.is_ipv4());
        assert_eq!(fallback, None);
    }

    #[test]
    fn override_replaces_both_families() {
        let addr: SocketAddr = "127.0.0.1:1443".parse().unwrap();
        let table = DcTable::new(true)
            .with_override(1, addr)
            .with_override(9, addr);
        assert_eq!(table.candidates(2), Some((addr, None)));
        assert_eq!(table.candidates(-2), Some((addr, None)));
        assert!(table.candidates(1).unwrap().0.is_ipv6());
    }

    #[tokio::test]
    async fn connect_reports_unknown_dc_and_refused_connections() {
        let err = DcTable::new(false).connect(0).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let table = DcTable::new(false).with_override(0, addr);
        assert!(table.connect(1).await.is_err());
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn source_addresses_rotate_per_family() {
        let mut table = DcTable::new(true);
        table.bind_v4 = vec![ip("10.0.0.1"), ip("10.0.0.2")];
        table.bind_v6 = vec![ip("2001:db8::1"), ip("2001:db8::2"), ip("2001:db8::3")];
        let v4_target: SocketAddr = "149.154.167.51:443".parse().unwrap();
        let v6_target: SocketAddr = "[2001:67c:4e8:f002::a]:443".parse().unwrap();

        let v4: Vec<_> = (0..5)
            .map(|_| table.next_source(v4_target).unwrap())
            .collect();
        assert_eq!(
            v4,
            ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.2", "10.0.0.1"].map(ip)
        );
        // The v6 rotation is independent of how many v4 connections were made.
        let v6: Vec<_> = (0..4)
            .map(|_| table.next_source(v6_target).unwrap())
            .collect();
        assert_eq!(
            v6,
            ["2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::1"].map(ip)
        );
    }

    #[test]
    fn no_source_address_without_configuration_for_that_family() {
        let mut table = DcTable::new(true);
        let v4_target: SocketAddr = "149.154.167.51:443".parse().unwrap();
        let v6_target: SocketAddr = "[2001:67c:4e8:f002::a]:443".parse().unwrap();
        assert_eq!(table.next_source(v4_target), None);
        table.bind_v6 = vec![ip("2001:db8::1")];
        assert_eq!(table.next_source(v4_target), None);
        assert_eq!(table.next_source(v6_target), Some(ip("2001:db8::1")));
    }

    #[test]
    fn unassigned_bind_addresses_are_rejected_at_startup() {
        // TEST-NET-1 and the documentation prefix are never assigned to a host.
        for bad in ["192.0.2.77", "2001:db8::77"] {
            let err = DcTable::new(true).with_bind_addrs(&[ip(bad)]).unwrap_err();
            assert!(err.to_string().contains(bad), "{err}");
        }
        let table = DcTable::new(true)
            .with_bind_addrs(&[ip("127.0.0.1"), ip("::1")])
            .unwrap();
        assert_eq!(table.bind_v4, [ip("127.0.0.1")]);
        assert_eq!(table.bind_v6, [ip("::1")]);
    }

    async fn peer_ips(
        table: &DcTable,
        listener: &tokio::net::TcpListener,
        count: usize,
    ) -> Vec<IpAddr> {
        let mut seen = Vec::new();
        for _ in 0..count {
            let (stream, accepted) = tokio::join!(table.connect(1), listener.accept());
            stream.unwrap();
            seen.push(accepted.unwrap().1.ip());
        }
        seen
    }

    #[tokio::test]
    async fn connections_leave_from_the_configured_source() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let table = DcTable::new(false)
            .with_override(0, listener.local_addr().unwrap())
            .with_bind_addrs(&[ip("127.0.0.1")])
            .unwrap();
        assert_eq!(
            peer_ips(&table, &listener, 3).await,
            ["127.0.0.1"; 3].map(ip)
        );

        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let table = DcTable::new(true)
            .with_override(0, listener.local_addr().unwrap())
            .with_bind_addrs(&[ip("127.0.0.1"), ip("::1")])
            .unwrap();
        assert_eq!(peer_ips(&table, &listener, 2).await, ["::1"; 2].map(ip));
    }

    /// Linux answers on all of 127.0.0.0/8, so rotation is observable there.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_addresses_alternate_on_the_wire() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let table = DcTable::new(false)
            .with_override(0, listener.local_addr().unwrap())
            .with_bind_addrs(&[ip("127.0.0.2"), ip("127.0.0.3"), ip("127.0.0.4")])
            .unwrap();
        assert_eq!(
            peer_ips(&table, &listener, 7).await,
            [
                "127.0.0.2",
                "127.0.0.3",
                "127.0.0.4",
                "127.0.0.2",
                "127.0.0.3",
                "127.0.0.4",
                "127.0.0.2"
            ]
            .map(ip)
        );
    }

    /// Binding normally reserves a local port straight away, which caps one
    /// source address at one port range's worth of connections in total. With
    /// IP_BIND_ADDRESS_NO_PORT the port is left open until connect, where the
    /// kernel may reuse a port towards a different destination.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn binding_a_source_address_does_not_reserve_a_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let table = DcTable::new(false)
            .with_override(0, target)
            .with_bind_addrs(&[ip("127.0.0.9")])
            .unwrap();

        let socket = table.prepare_socket(target).unwrap();
        let bound = socket.local_addr().unwrap();
        assert_eq!(bound.ip(), ip("127.0.0.9"));
        assert_eq!(bound.port(), 0, "bind reserved a port");

        // For contrast: the same bind without the option picks a port at once.
        let plain = TcpSocket::new_v4().unwrap();
        plain.bind("127.0.0.9:0".parse().unwrap()).unwrap();
        assert_ne!(plain.local_addr().unwrap().port(), 0);

        // The port is assigned by connect.
        let (stream, accepted) = tokio::join!(socket.connect(target), listener.accept());
        let local = stream.unwrap().local_addr().unwrap();
        assert_ne!(local.port(), 0);
        assert_eq!(accepted.unwrap().1, local);
    }
}
