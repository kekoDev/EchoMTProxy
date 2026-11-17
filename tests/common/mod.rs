//! Fake Telegram client, echo DC and proxy launchers shared by the test binaries.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use echo_mtproxy::cipher::{AesCtr, Ctr};
use echo_mtproxy::config::{Config, Secret};
use echo_mtproxy::obfs2;
use echo_mtproxy::server::{self, Proxy};
use echo_mtproxy::tls::{self, RecordReader};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

pub const SECRET_HEX: &str = "ee0f1e2d3c4b5a69788796a5b4c3d2e1f07777772e6578616d706c652e636f6d";
pub const DC: i16 = 2;
pub const STEP: Duration = Duration::from_secs(10);
/// How long to wait before concluding the proxy is staying silent.
pub const SILENCE: Duration = Duration::from_millis(300);

pub fn secret() -> Secret {
    Secret::parse(SECRET_HEX).unwrap()
}

pub fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

/// A DC that echoes every transport-level byte back.
pub async fn spawn_echo_dc(obfuscated: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = echo_dc_session(stream, obfuscated).await;
            });
        }
    });
    addr
}

pub async fn echo_dc_session(mut stream: TcpStream, obfuscated: bool) -> std::io::Result<()> {
    let mut ciphers = None;
    if obfuscated {
        let mut init = [0u8; 64];
        stream.read_exact(&mut init).await?;
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        key.copy_from_slice(&init[8..40]);
        iv.copy_from_slice(&init[40..56]);
        let mut dec = AesCtr::new(&key, &iv);
        let mut reversed: Vec<u8> = init[8..56].to_vec();
        reversed.reverse();
        key.copy_from_slice(&reversed[..32]);
        iv.copy_from_slice(&reversed[32..]);
        let enc = AesCtr::new(&key, &iv);
        dec.apply(&mut init);
        assert_eq!(init[56..60], [0xdd; 4], "DC got a bad obfuscated2 init");
        ciphers = Some((dec, enc));
    } else {
        let mut tag = [0u8; 4];
        stream.read_exact(&mut tag).await?;
        assert_eq!(tag, [0xdd; 4], "DC got a bad transport tag");
    }

    let mut buf = vec![0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        if let Some((dec, enc)) = ciphers.as_mut() {
            dec.apply(&mut buf[..n]);
            enc.apply(&mut buf[..n]);
        }
        stream.write_all(&buf[..n]).await?;
    }
}

pub async fn spawn_proxy(upstream_mode: &str, dc_addr: SocketAddr) -> SocketAddr {
    spawn_proxy_with(upstream_mode, dc_addr, "").await
}

/// A mask target that accepts connections and never answers, so tests of
/// rejected handshakes neither reach the internet nor get a reply.
pub async fn spawn_blackhole() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            held.push(listener.accept().await.unwrap().0);
        }
    });
    addr
}

pub async fn spawn_proxy_with(upstream_mode: &str, dc_addr: SocketAddr, extra: &str) -> SocketAddr {
    let blackhole = spawn_blackhole().await;
    spawn_proxy_from(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         upstream_mode = \"{upstream_mode}\"\n\
         mask_host = \"{blackhole}\"\n\
         metrics_listen = \"\"\n\
         {extra}\n\
         [dc_override]\n\
         {DC} = \"{dc_addr}\"\n"
    ))
    .await
}

pub async fn spawn_proxy_from(config: &str) -> SocketAddr {
    spawn_proxy_handle(config).await.0
}

/// Like `spawn_proxy_from`, but also returns the proxy for inspecting its stats.
pub async fn spawn_proxy_handle(config: &str) -> (SocketAddr, Arc<Proxy>) {
    let config = Config::parse(config).unwrap();
    let proxy = Arc::new(Proxy::from_config(&config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server::serve(listener, proxy.clone()));
    (addr, proxy)
}

pub fn signed_hello(key: &[u8], timestamp: u32) -> Vec<u8> {
    signed_hello_for("www.example.com", key, timestamp)
}

pub fn signed_hello_for(sni: &str, key: &[u8], timestamp: u32) -> Vec<u8> {
    let mut hello = tls::client_hello_template(sni, &mut rand::thread_rng()).unwrap();
    tls::sign_client_hello(&mut hello, key, timestamp);
    hello
}

/// Reads one TLS record and returns it with its header.
pub async fn read_record(stream: &mut TcpStream) -> Vec<u8> {
    let mut record = vec![0u8; 5];
    stream.read_exact(&mut record).await.unwrap();
    let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    record.resize(5 + len, 0);
    stream.read_exact(&mut record[5..]).await.unwrap();
    record
}

pub struct Client {
    pub read: OwnedReadHalf,
    pub write: OwnedWriteHalf,
    pub enc: AesCtr,
    pub dec: AesCtr,
    pub records: RecordReader,
    /// Decrypted bytes received beyond what the last `recv` asked for.
    pub pending: Vec<u8>,
}

pub async fn send_on(write: &mut OwnedWriteHalf, enc: &mut AesCtr, data: &[u8]) {
    let mut encrypted = data.to_vec();
    enc.apply(&mut encrypted);
    let mut framed = Vec::new();
    tls::wrap_records(&encrypted, &mut framed);
    write.write_all(&framed).await.unwrap();
}

pub async fn recv_on(
    read: &mut OwnedReadHalf,
    dec: &mut AesCtr,
    records: &mut RecordReader,
    pending: &mut Vec<u8>,
    len: usize,
) -> Vec<u8> {
    let mut out = std::mem::take(pending);
    let mut buf = vec![0u8; 16 * 1024];
    while out.len() < len {
        let n = timeout(STEP, read.read(&mut buf))
            .await
            .expect("timed out waiting for data from the proxy")
            .unwrap();
        assert_ne!(n, 0, "proxy closed the connection");
        let m = records.unwrap_in_place(&mut buf, n).unwrap();
        dec.apply(&mut buf[..m]);
        out.extend_from_slice(&buf[..m]);
    }
    *pending = out.split_off(len);
    out
}

impl Client {
    pub fn new(stream: TcpStream, init: obfs2::ClientSide) -> Self {
        let (read, write) = stream.into_split();
        Self {
            read,
            write,
            enc: init.enc,
            dec: init.dec,
            records: RecordReader::new(),
            pending: Vec::new(),
        }
    }

    /// Completes the fake-tls and obfuscated2 handshakes like a Telegram client.
    pub async fn connect(proxy: SocketAddr, dc_idx: i16) -> Self {
        Self::connect_with_sni(proxy, dc_idx, "www.example.com").await
    }

    pub async fn connect_with_sni(proxy: SocketAddr, dc_idx: i16, sni: &str) -> Self {
        let stream = TcpStream::connect(proxy).await.unwrap();
        Self::handshake(stream, dc_idx, sni).await
    }

    /// Runs the client side of both handshakes on an already connected socket.
    pub async fn handshake(mut stream: TcpStream, dc_idx: i16, sni: &str) -> Self {
        let secret = secret();
        let hello = signed_hello_for(sni, &secret.key, unix_now());
        stream.write_all(&hello).await.unwrap();

        let mut response = Vec::new();
        for expected_type in [0x16, 0x14, 0x17] {
            let record = timeout(STEP, read_record(&mut stream)).await.unwrap();
            assert_eq!(record[0], expected_type);
            response.extend_from_slice(&record);
        }
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&hello[11..43]);
        assert!(tls::verify_server_hello(
            &secret.key,
            &client_random,
            &response
        ));
        assert_eq!(response[44..76], hello[44..76], "session id not echoed");

        let mut seed = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut seed);
        let init = obfs2::client_init(seed, &secret.key, dc_idx);
        let mut first = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        tls::wrap_records(&init.wire, &mut first);
        stream.write_all(&first).await.unwrap();
        Self::new(stream, init)
    }

    pub async fn send(&mut self, data: &[u8]) {
        send_on(&mut self.write, &mut self.enc, data).await;
    }

    pub async fn recv(&mut self, len: usize) -> Vec<u8> {
        recv_on(
            &mut self.read,
            &mut self.dec,
            &mut self.records,
            &mut self.pending,
            len,
        )
        .await
    }

    /// Sends and receives at the same time, so large payloads cannot stall on
    /// full socket buffers.
    pub async fn echo(&mut self, data: &[u8]) -> Vec<u8> {
        let ((), echoed) = tokio::join!(
            send_on(&mut self.write, &mut self.enc, data),
            recv_on(
                &mut self.read,
                &mut self.dec,
                &mut self.records,
                &mut self.pending,
                data.len()
            ),
        );
        echoed
    }
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

/// True if the proxy sends nothing and keeps the connection open for `SILENCE`.
pub async fn stays_silent(stream: &mut TcpStream) -> bool {
    let mut buf = [0u8; 1];
    timeout(SILENCE, stream.read(&mut buf)).await.is_err()
}

/// Raises this process's open-file soft limit towards `needed` and returns the
/// limit now in effect. Child processes inherit it.
#[cfg(unix)]
// rlim_t is u64 on the platforms tested so far, but not everywhere.
#[allow(clippy::unnecessary_cast)]
pub fn raise_fd_limit(needed: u64) -> u64 {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable rlimit for the duration of the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return 0;
    }
    let current = limit.rlim_cur as u64;
    if current >= needed {
        return current;
    }
    // Some systems cap the soft limit below the reported hard limit, so fall
    // back to smaller requests instead of giving up.
    for target in [needed, needed.min(61_440), needed.min(10_240)] {
        let wanted = libc::rlimit {
            rlim_cur: target.min(limit.rlim_max as u64) as libc::rlim_t,
            rlim_max: limit.rlim_max,
        };
        // SAFETY: `wanted` is a valid rlimit; the call only changes this process's limit.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &wanted) } == 0 {
            return wanted.rlim_cur as u64;
        }
    }
    current
}

/// Connects from an explicitly chosen local port instead of an ephemeral one.
///
/// macOS serves every outgoing connection of the machine from one pool of
/// 16 384 ephemeral ports. A test that opens 10 000 client connections would
/// leave too few for the proxy's own 10 000 connections to the DC, so on macOS
/// the clients take their ports from below that pool.
pub async fn connect_from_fixed_port_range(addr: SocketAddr) -> TcpStream {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT_PORT: AtomicU16 = AtomicU16::new(18_000);
    loop {
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        assert!(
            port < 49_000,
            "ran out of local ports below the ephemeral range"
        );
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        // Lets a port still in TIME_WAIT from an earlier run be used again.
        socket.set_reuseaddr(true).unwrap();
        if socket
            .bind(SocketAddr::from(([127, 0, 0, 1], port)))
            .is_err()
        {
            continue;
        }
        match socket.connect(addr).await {
            Ok(stream) => return stream,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::AddrInUse | std::io::ErrorKind::AddrNotAvailable
                ) => {}
            Err(err) => panic!("connect from port {port} failed: {err}"),
        }
    }
}

/// A client socket for tests that open thousands of connections at once.
pub async fn connect_bulk(addr: SocketAddr) -> TcpStream {
    if cfg!(target_os = "macos") {
        connect_from_fixed_port_range(addr).await
    } else {
        TcpStream::connect(addr).await.unwrap()
    }
}
