use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;

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

#[derive(Debug, Clone)]
pub struct DcTable {
    v4: [SocketAddr; DC_COUNT],
    v6: [SocketAddr; DC_COUNT],
    overridden: [bool; DC_COUNT],
    prefer_v6: bool,
}

impl DcTable {
    pub fn new(prefer_v6: bool) -> Self {
        Self {
            v4: DC_V4.map(|ip| SocketAddr::new(IpAddr::V4(ip), DC_PORT)),
            v6: DC_V6.map(|ip| SocketAddr::new(IpAddr::V6(ip), DC_PORT)),
            overridden: [false; DC_COUNT],
            prefer_v6,
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
        match connect_one(first).await {
            Ok(stream) => Ok(stream),
            Err(err) => match fallback {
                Some(addr) => connect_one(addr).await,
                None => Err(err),
            },
        }
    }
}

async fn connect_one(addr: SocketAddr) -> io::Result<TcpStream> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream connect timed out"))??;
    stream.set_nodelay(true)?;
    Ok(stream)
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
}
