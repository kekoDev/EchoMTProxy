//! In-process fake client ↔ proxy ↔ fake DC echo server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use echo_mtproxy::cipher::{AesCtr, Ctr};
use echo_mtproxy::config::{Config, Secret};
use echo_mtproxy::obfs2;
use echo_mtproxy::server::{self, Proxy};
use echo_mtproxy::stats::{self, HandshakeResult, MaskResult};
use echo_mtproxy::tls::{self, RecordReader};
use rand::{Rng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const SECRET_HEX: &str = "ee0f1e2d3c4b5a69788796a5b4c3d2e1f07777772e6578616d706c652e636f6d";
const DC: i16 = 2;
const STEP: Duration = Duration::from_secs(10);
/// How long to wait before concluding the proxy is staying silent.
const SILENCE: Duration = Duration::from_millis(300);

fn secret() -> Secret {
    Secret::parse(SECRET_HEX).unwrap()
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

/// A DC that echoes every transport-level byte back.
async fn spawn_echo_dc(obfuscated: bool) -> SocketAddr {
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

async fn echo_dc_session(mut stream: TcpStream, obfuscated: bool) -> std::io::Result<()> {
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

async fn spawn_proxy(upstream_mode: &str, dc_addr: SocketAddr) -> SocketAddr {
    spawn_proxy_with(upstream_mode, dc_addr, "").await
}

/// A mask target that accepts connections and never answers, so tests of
/// rejected handshakes neither reach the internet nor get a reply.
async fn spawn_blackhole() -> SocketAddr {
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

async fn spawn_proxy_with(upstream_mode: &str, dc_addr: SocketAddr, extra: &str) -> SocketAddr {
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

async fn spawn_proxy_from(config: &str) -> SocketAddr {
    spawn_proxy_handle(config).await.0
}

/// Like `spawn_proxy_from`, but also returns the proxy for inspecting its stats.
async fn spawn_proxy_handle(config: &str) -> (SocketAddr, Arc<Proxy>) {
    let config = Config::parse(config).unwrap();
    let proxy = Arc::new(Proxy::from_config(&config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server::serve(listener, proxy.clone()));
    (addr, proxy)
}

fn signed_hello(key: &[u8], timestamp: u32) -> Vec<u8> {
    signed_hello_for("www.example.com", key, timestamp)
}

fn signed_hello_for(sni: &str, key: &[u8], timestamp: u32) -> Vec<u8> {
    let mut hello = tls::client_hello_template(sni, &mut rand::thread_rng()).unwrap();
    tls::sign_client_hello(&mut hello, key, timestamp);
    hello
}

/// Reads one TLS record and returns it with its header.
async fn read_record(stream: &mut TcpStream) -> Vec<u8> {
    let mut record = vec![0u8; 5];
    stream.read_exact(&mut record).await.unwrap();
    let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    record.resize(5 + len, 0);
    stream.read_exact(&mut record[5..]).await.unwrap();
    record
}

struct Client {
    read: OwnedReadHalf,
    write: OwnedWriteHalf,
    enc: AesCtr,
    dec: AesCtr,
    records: RecordReader,
    /// Decrypted bytes received beyond what the last `recv` asked for.
    pending: Vec<u8>,
}

async fn send_on(write: &mut OwnedWriteHalf, enc: &mut AesCtr, data: &[u8]) {
    let mut encrypted = data.to_vec();
    enc.apply(&mut encrypted);
    let mut framed = Vec::new();
    tls::wrap_records(&encrypted, &mut framed);
    write.write_all(&framed).await.unwrap();
}

async fn recv_on(
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
    fn new(stream: TcpStream, init: obfs2::ClientSide) -> Self {
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
    async fn connect(proxy: SocketAddr, dc_idx: i16) -> Self {
        Self::connect_with_sni(proxy, dc_idx, "www.example.com").await
    }

    async fn connect_with_sni(proxy: SocketAddr, dc_idx: i16, sni: &str) -> Self {
        let secret = secret();
        let mut stream = TcpStream::connect(proxy).await.unwrap();
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

    async fn send(&mut self, data: &[u8]) {
        send_on(&mut self.write, &mut self.enc, data).await;
    }

    async fn recv(&mut self, len: usize) -> Vec<u8> {
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
    async fn echo(&mut self, data: &[u8]) -> Vec<u8> {
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

fn random_bytes(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

/// True if the proxy sends nothing and keeps the connection open for `SILENCE`.
async fn stays_silent(stream: &mut TcpStream) -> bool {
    let mut buf = [0u8; 1];
    timeout(SILENCE, stream.read(&mut buf)).await.is_err()
}

async fn echo_round_trip(upstream_mode: &str) {
    let dc = spawn_echo_dc(upstream_mode != "plain").await;
    let proxy = spawn_proxy(upstream_mode, dc).await;
    let mut client = Client::connect(proxy, DC).await;

    for len in [1, 64, 1000, 16384, 16385, 300_000] {
        let data = random_bytes(len);
        let echoed = client.echo(&data).await;
        assert_eq!(echoed, data, "{upstream_mode}: {len} bytes");
    }
}

#[tokio::test]
async fn echo_through_fast_upstream() {
    echo_round_trip("fast").await;
}

#[tokio::test]
async fn echo_through_obfuscated_upstream() {
    echo_round_trip("obfuscated").await;
}

#[tokio::test]
async fn echo_through_plain_upstream() {
    echo_round_trip("plain").await;
}

#[tokio::test]
async fn media_dc_index_reaches_the_same_dc() {
    let dc = spawn_echo_dc(true).await;
    let proxy = spawn_proxy("fast", dc).await;
    let mut client = Client::connect(proxy, -DC).await;
    client.send(b"media").await;
    assert_eq!(client.recv(5).await, b"media");
}

#[tokio::test]
async fn data_sent_with_the_init_is_not_lost() {
    for mode in ["fast", "obfuscated", "plain"] {
        let dc = spawn_echo_dc(mode != "plain").await;
        let proxy = spawn_proxy(mode, dc).await;
        let secret = secret();

        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let hello = signed_hello(&secret.key, unix_now());
        stream.write_all(&hello).await.unwrap();
        for _ in 0..3 {
            timeout(STEP, read_record(&mut stream)).await.unwrap();
        }

        let mut seed = [0x33u8; 64];
        rand::thread_rng().fill_bytes(&mut seed[8..]);
        let mut init = obfs2::client_init(seed, &secret.key, DC);
        let data = random_bytes(5000);
        let mut payload = data.clone();
        init.enc.apply(&mut payload);

        // Init and first payload share one record, split mid-header and mid-init on the wire.
        let mut body = init.wire.to_vec();
        body.extend_from_slice(&payload);
        let mut framed = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        tls::wrap_records(&body, &mut framed);
        for chunk in [&framed[..8], &framed[8..40], &framed[40..]] {
            stream.write_all(chunk).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let mut client = Client::new(stream, init);
        assert_eq!(client.recv(data.len()).await, data, "{mode}");
    }
}

#[tokio::test]
async fn many_clients_in_parallel() {
    let dc = spawn_echo_dc(true).await;
    let proxy = spawn_proxy("fast", dc).await;
    let tasks: Vec<_> = (0..64)
        .map(|_| {
            tokio::spawn(async move {
                let mut client = Client::connect(proxy, DC).await;
                let len = rand::thread_rng().gen_range(1..40_000);
                let data = random_bytes(len);
                assert_eq!(client.echo(&data).await, data);
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn wrong_secret_gets_no_response() {
    let dc = spawn_echo_dc(true).await;
    let proxy = spawn_proxy("fast", dc).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(&signed_hello(&[0x42; 16], unix_now()))
        .await
        .unwrap();
    assert!(stays_silent(&mut stream).await);
}

#[tokio::test]
async fn replayed_client_hello_gets_no_response() {
    let dc = spawn_echo_dc(true).await;
    let proxy = spawn_proxy("fast", dc).await;
    let hello = signed_hello(&secret().key, unix_now());

    let mut first = TcpStream::connect(proxy).await.unwrap();
    first.write_all(&hello).await.unwrap();
    assert_eq!(
        timeout(STEP, read_record(&mut first)).await.unwrap()[0],
        0x16
    );

    let mut second = TcpStream::connect(proxy).await.unwrap();
    second.write_all(&hello).await.unwrap();
    assert!(stays_silent(&mut second).await);
}

#[tokio::test]
async fn clock_skew_outside_the_window_gets_no_response() {
    let dc = spawn_echo_dc(true).await;
    let proxy = spawn_proxy("fast", dc).await;
    let key = secret().key;

    for offset in [-700i64, 1300] {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let timestamp = (i64::from(unix_now()) + offset) as u32;
        stream
            .write_all(&signed_hello(&key, timestamp))
            .await
            .unwrap();
        assert!(stays_silent(&mut stream).await, "offset {offset}");
    }

    for offset in [-500i64, 1100] {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let timestamp = (i64::from(unix_now()) + offset) as u32;
        stream
            .write_all(&signed_hello(&key, timestamp))
            .await
            .unwrap();
        let record = timeout(STEP, read_record(&mut stream)).await.unwrap();
        assert_eq!(record[0], 0x16, "offset {offset}");
    }
}

#[tokio::test]
async fn skew_rejections_are_counted_with_their_offset() {
    let blackhole = spawn_blackhole().await;
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\nmask_host = \"{blackhole}\"\n"
    ))
    .await;
    let key = secret().key;

    // 700 s and 900 s behind, 1300 s ahead: all outside the default window.
    for offset in [-700i64, -900, 1300] {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let timestamp = (i64::from(unix_now()) + offset) as u32;
        stream
            .write_all(&signed_hello(&key, timestamp))
            .await
            .unwrap();
        assert!(stays_silent(&mut stream).await, "offset {offset}");
    }
    // Accepted handshakes and non-skew rejections must not be counted.
    let mut ok = TcpStream::connect(proxy).await.unwrap();
    ok.write_all(&signed_hello(&key, unix_now())).await.unwrap();
    assert_eq!(timeout(STEP, read_record(&mut ok)).await.unwrap()[0], 0x16);
    let mut wrong = TcpStream::connect(proxy).await.unwrap();
    wrong
        .write_all(&signed_hello(&[0x42; 16], unix_now() - 5000))
        .await
        .unwrap();
    assert!(stays_silent(&mut wrong).await);

    let behind = handle.stats().skew_rejected_behind.snapshot();
    let ahead = handle.stats().skew_rejected_ahead.snapshot();
    assert_eq!(behind.count, 2);
    assert_eq!(ahead.count, 1);
    // The test's clock and the proxy's are read a moment apart.
    assert!((1598..=1604).contains(&behind.sum_secs), "{behind:?}");
    assert!((1296..=1300).contains(&ahead.sum_secs), "{ahead:?}");
    // Buckets: <=60, <=300, <=900, <=1800, ...
    assert_eq!(behind.buckets[2] + behind.buckets[3], 2);
    assert_eq!(ahead.buckets[3], 1);
}

#[tokio::test]
async fn uptime_timestamp_follows_config() {
    let dc = spawn_echo_dc(true).await;
    let key = secret().key;

    let lenient = spawn_proxy("fast", dc).await;
    let mut stream = TcpStream::connect(lenient).await.unwrap();
    stream.write_all(&signed_hello(&key, 4242)).await.unwrap();
    assert_eq!(
        timeout(STEP, read_record(&mut stream)).await.unwrap()[0],
        0x16
    );

    let strict = spawn_proxy_with("fast", dc, "accept_uptime_timestamps = false").await;
    let mut stream = TcpStream::connect(strict).await.unwrap();
    stream.write_all(&signed_hello(&key, 4242)).await.unwrap();
    assert!(stays_silent(&mut stream).await);
}

#[tokio::test]
async fn non_tls_and_short_hellos_get_no_response() {
    let dc = spawn_echo_dc(true).await;
    let proxy = spawn_proxy("fast", dc).await;

    let mut http = TcpStream::connect(proxy).await.unwrap();
    http.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    assert!(stays_silent(&mut http).await);

    let mut short = TcpStream::connect(proxy).await.unwrap();
    let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x64];
    record.extend_from_slice(&[0u8; 100]);
    short.write_all(&record).await.unwrap();
    assert!(stays_silent(&mut short).await);
}

#[tokio::test]
async fn bad_obfs2_init_gets_no_data_back() {
    let dc = spawn_echo_dc(true).await;
    let proxy = spawn_proxy("fast", dc).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(&signed_hello(&secret().key, unix_now()))
        .await
        .unwrap();
    for _ in 0..3 {
        timeout(STEP, read_record(&mut stream)).await.unwrap();
    }
    let mut framed = Vec::new();
    tls::wrap_records(&[0x55; 200], &mut framed);
    stream.write_all(&framed).await.unwrap();
    assert!(stays_silent(&mut stream).await);
}

#[tokio::test]
async fn handshake_timeout_closes_idle_connections() {
    let dc = spawn_echo_dc(true).await;
    let proxy = spawn_proxy_with("fast", dc, "handshake_timeout_secs = 1").await;

    let mut idle = TcpStream::connect(proxy).await.unwrap();
    let mut buf = [0u8; 1];
    let read = timeout(Duration::from_secs(5), idle.read(&mut buf)).await;
    assert_eq!(read.expect("proxy never closed").unwrap(), 0);

    // A client that stalls halfway through the ClientHello is cut off too.
    let mut stalled = TcpStream::connect(proxy).await.unwrap();
    let hello = signed_hello(&secret().key, unix_now());
    stalled.write_all(&hello[..200]).await.unwrap();
    let read = timeout(Duration::from_secs(5), stalled.read(&mut buf)).await;
    assert_eq!(read.expect("proxy never closed").unwrap(), 0);
}

#[tokio::test]
async fn client_disconnect_mid_handshake_does_not_break_the_proxy() {
    let dc = spawn_echo_dc(true).await;
    let proxy = spawn_proxy("fast", dc).await;
    let hello = signed_hello(&secret().key, unix_now());
    for cut in [0, 3, 5, 100, 516] {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(&hello[..cut]).await.unwrap();
        drop(stream);
    }
    let mut client = Client::connect(proxy, DC).await;
    client.send(b"still alive").await;
    assert_eq!(client.recv(11).await, b"still alive");
}

#[tokio::test]
async fn upstream_down_closes_the_client() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = listener.local_addr().unwrap();
    drop(listener);
    let proxy = spawn_proxy("fast", dead).await;

    let mut client = Client::connect(proxy, DC).await;
    let mut buf = [0u8; 16];
    let read = timeout(STEP, client.read.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
}

#[tokio::test]
async fn unknown_dc_index_closes_the_client() {
    let dc = spawn_echo_dc(true).await;
    let proxy = spawn_proxy("fast", dc).await;
    let mut client = Client::connect(proxy, 42).await;
    let mut buf = [0u8; 16];
    let read = timeout(STEP, client.read.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
}

#[tokio::test]
async fn dc_close_is_propagated_to_the_client() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dc = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut init = [0u8; 64];
            let _ = stream.read_exact(&mut init).await;
        }
    });
    let proxy = spawn_proxy("fast", dc).await;
    let mut client = Client::connect(proxy, DC).await;
    let mut buf = [0u8; 16];
    let read = timeout(STEP, client.read.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
}

/// Sends an unencrypted MTProto `req_pq_multi` through the proxy to a real
/// Telegram DC and expects `resPQ` with our nonce. This is the first message
/// of every new client, so it shows whether the DC accepts the upstream mode.
async fn real_dc_answers(upstream_mode: &str, prefer_ipv6: bool) {
    // RUST_LOG=debug with --nocapture shows why the proxy dropped a session.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let proxy = spawn_proxy_from(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         upstream_mode = \"{upstream_mode}\"\n\
         prefer_ipv6_upstream = {prefer_ipv6}\n"
    ))
    .await;

    for dc in 1..=5 {
        let mut client = Client::connect(proxy, dc).await;
        let nonce = random_bytes(16);
        let mut message = vec![0u8; 8];
        message.extend_from_slice(&((u64::from(unix_now()) << 32) | 4).to_le_bytes());
        message.extend_from_slice(&20u32.to_le_bytes());
        message.extend_from_slice(&0xbe7e8ef1u32.to_le_bytes());
        message.extend_from_slice(&nonce);
        let padding = random_bytes(3);
        let mut frame = ((message.len() + padding.len()) as u32)
            .to_le_bytes()
            .to_vec();
        frame.extend_from_slice(&message);
        frame.extend_from_slice(&padding);
        client.send(&frame).await;

        let head = client.recv(4).await;
        let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
        let body = client.recv(len).await;
        assert!(
            len >= 40,
            "{upstream_mode}: DC {dc} answered with transport error {:?}",
            body
        );
        assert_eq!(
            body[20..24],
            0x05162463u32.to_le_bytes(),
            "{upstream_mode}: DC {dc} did not answer with resPQ"
        );
        assert_eq!(
            body[24..40],
            nonce[..],
            "{upstream_mode}: DC {dc} nonce mismatch"
        );
    }
}

#[tokio::test]
#[ignore = "connects to real Telegram DCs"]
async fn real_dc_fast() {
    real_dc_answers("fast", false).await;
}

#[tokio::test]
#[ignore = "connects to real Telegram DCs"]
async fn real_dc_obfuscated() {
    real_dc_answers("obfuscated", false).await;
}

#[tokio::test]
#[ignore = "connects to real Telegram DCs"]
async fn real_dc_plain() {
    real_dc_answers("plain", false).await;
}

#[tokio::test]
#[ignore = "connects to real Telegram DCs over IPv6"]
async fn real_dc_fast_ipv6() {
    real_dc_answers("fast", true).await;
}

/// A stand-in for a real website: greets with `NAME:` and then echoes
/// everything it receives, so a test can see which site got which bytes.
async fn spawn_site(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let greeting = format!("{name}:");
                if stream.write_all(greeting.as_bytes()).await.is_err() {
                    return;
                }
                let mut buf = vec![0u8; 8192];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

struct MaskSetup {
    proxy: SocketAddr,
    handle: Arc<Proxy>,
}

/// Proxy with sites A and B allowlisted as a.example / b.example and site D
/// as the default mask host.
async fn spawn_masked_proxy(extra: &str) -> MaskSetup {
    let a = spawn_site("A").await;
    let b = spawn_site("B").await;
    let d = spawn_site("D").await;
    let dc = spawn_echo_dc(true).await;
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         mask_domains = [\"a.example={a}\", \"B.Example = {b}\"]\n\
         mask_host = \"{d}\"\n\
         metrics_listen = \"\"\n\
         {extra}\n\
         [dc_override]\n\
         {DC} = \"{dc}\"\n"
    ))
    .await;
    MaskSetup { proxy, handle }
}

/// Sends `bytes` and returns the open stream plus the name of the site that
/// answered, after checking that the site received exactly `bytes`.
async fn masked_by(proxy: SocketAddr, bytes: &[u8]) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(bytes).await.unwrap();
    let mut reply = vec![0u8; 2 + bytes.len()];
    timeout(STEP, stream.read_exact(&mut reply))
        .await
        .expect("no answer from a mask site")
        .unwrap();
    assert_eq!(reply[1], b':');
    assert_eq!(
        &reply[2..],
        bytes,
        "mask site did not get the client's bytes"
    );
    (stream, String::from_utf8_lossy(&reply[..1]).into_owned())
}

/// A small TLS 1.2 style ClientHello, far below the fake-tls minimum size.
fn short_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&random_bytes(32));
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    body.extend_from_slice(&((name.len() + 9) as u16).to_be_bytes());
    body.extend_from_slice(&[0x00, 0x00]);
    body.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
    body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    body.extend_from_slice(name);

    let mut record = vec![0x16, 0x03, 0x03];
    record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    record.push(0x01);
    record.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    record.extend_from_slice(&body);
    record
}

#[tokio::test]
async fn failed_handshake_is_masked_by_allowlisted_sni() {
    let setup = spawn_masked_proxy("").await;
    let wrong_key = [0x42u8; 16];

    for (sni, site) in [
        ("a.example", "A"),
        ("b.example", "B"),
        ("A.EXAMPLE", "A"),
        ("c.example", "D"),
        ("sub.a.example", "D"),
        ("a.example.evil.test", "D"),
        ("www.example.com", "D"),
    ] {
        let hello = signed_hello_for(sni, &wrong_key, unix_now());
        let (mut stream, answered) = masked_by(setup.proxy, &hello).await;
        assert_eq!(answered, site, "sni {sni}");

        // The splice keeps running in both directions after the replayed hello.
        let more = random_bytes(20_000);
        stream.write_all(&more).await.unwrap();
        let mut echoed = vec![0u8; more.len()];
        timeout(STEP, stream.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echoed, more, "sni {sni}");
    }
}

#[tokio::test]
async fn non_fake_tls_traffic_is_masked() {
    let setup = spawn_masked_proxy("").await;

    let (_s, site) = masked_by(setup.proxy, b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n").await;
    assert_eq!(site, "D", "plain HTTP has no SNI");

    let (_s, site) = masked_by(setup.proxy, &short_hello("a.example")).await;
    assert_eq!(site, "A", "short hello with allowlisted SNI");
    let (_s, site) = masked_by(setup.proxy, &short_hello("b.example")).await;
    assert_eq!(site, "B");
    let (_s, site) = masked_by(setup.proxy, &short_hello("nope.example")).await;
    assert_eq!(site, "D");

    // A TLS record that is not a ClientHello, and one with a broken body.
    let mut alert = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
    alert.extend_from_slice(b"padding so the proxy has five bytes and more");
    let (_s, site) = masked_by(setup.proxy, &alert).await;
    assert_eq!(site, "D");
    let mut broken = short_hello("a.example");
    broken[43] = 0xff;
    let (_s, site) = masked_by(setup.proxy, &broken).await;
    assert_eq!(site, "D");
}

#[tokio::test]
async fn replay_and_clock_skew_are_masked_by_sni() {
    let setup = spawn_masked_proxy("").await;
    let key = secret().key;

    let hello = signed_hello_for("b.example", &key, unix_now());
    let mut first = TcpStream::connect(setup.proxy).await.unwrap();
    first.write_all(&hello).await.unwrap();
    assert_eq!(
        timeout(STEP, read_record(&mut first)).await.unwrap()[0],
        0x16
    );
    let (_s, site) = masked_by(setup.proxy, &hello).await;
    assert_eq!(site, "B", "replayed hello");

    let late = signed_hello_for("a.example", &key, unix_now() - 5000);
    let (_s, site) = masked_by(setup.proxy, &late).await;
    assert_eq!(site, "A", "hello outside the skew window");

    let stats = setup.handle.stats();
    let a = stats.label_index(Some("a.example"));
    let b = stats.label_index(Some("b.example"));
    assert_eq!(stats.handshakes(b, HandshakeResult::Replay), 1);
    assert_eq!(stats.handshakes(a, HandshakeResult::BadTimestamp), 1);
    assert_eq!(
        stats.mask(a, MaskResult::Forwarded),
        0,
        "counted when the splice ends"
    );
}

#[tokio::test]
async fn masked_connection_supports_half_close() {
    let setup = spawn_masked_proxy("").await;
    let hello = signed_hello_for("a.example", &[0x42; 16], unix_now());
    let mut stream = TcpStream::connect(setup.proxy).await.unwrap();
    stream.write_all(&hello).await.unwrap();
    stream.shutdown().await.unwrap();

    let mut reply = Vec::new();
    timeout(STEP, stream.read_to_end(&mut reply))
        .await
        .expect("connection was not closed after the site finished")
        .unwrap();
    assert_eq!(&reply[..2], b"A:");
    assert_eq!(&reply[2..], &hello[..]);

    // Once the splice is over it is counted as forwarded.
    let stats = setup.handle.stats();
    let a = stats.label_index(Some("a.example"));
    for _ in 0..100 {
        if stats.mask(a, MaskResult::Forwarded) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(stats.mask(a, MaskResult::Forwarded), 1);
    assert_eq!(stats.handshakes(a, HandshakeResult::BadDigest), 1);
}

#[tokio::test]
async fn mask_connections_are_limited() {
    let setup = spawn_masked_proxy("mask_max_connections = 1").await;
    let hello = |sni| signed_hello_for(sni, &[0x42; 16], unix_now());

    let (held, site) = masked_by(setup.proxy, &hello("a.example")).await;
    assert_eq!(site, "A");

    let mut second = TcpStream::connect(setup.proxy).await.unwrap();
    second.write_all(&hello("b.example")).await.unwrap();
    assert!(stays_silent(&mut second).await);
    let stats = setup.handle.stats();
    let b = stats.label_index(Some("b.example"));
    assert_eq!(stats.mask(b, MaskResult::Limited), 1);

    // Real clients are unaffected by the mask limit.
    let mut client = Client::connect(setup.proxy, DC).await;
    assert_eq!(client.echo(b"still served").await, b"still served");

    // Releasing the held connection frees the slot.
    drop(held);
    let mut freed = None;
    for _ in 0..100 {
        let mut stream = TcpStream::connect(setup.proxy).await.unwrap();
        stream.write_all(&hello("b.example")).await.unwrap();
        let mut head = [0u8; 2];
        if let Ok(Ok(_)) = timeout(Duration::from_millis(100), stream.read_exact(&mut head)).await {
            freed = Some(head);
            break;
        }
    }
    assert_eq!(freed, Some(*b"B:"));
}

#[tokio::test]
async fn unreachable_mask_target_closes_the_client() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = listener.local_addr().unwrap();
    drop(listener);
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         mask_domains = [\"down.example={dead}\"]\n\
         mask_host = \"{dead}\"\n\
         metrics_listen = \"\"\n"
    ))
    .await;

    for sni in ["down.example", "other.example"] {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(&signed_hello_for(sni, &[0x42; 16], unix_now()))
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        let read = timeout(STEP, stream.read(&mut buf)).await.unwrap();
        assert!(matches!(read, Ok(0) | Err(_)), "sni {sni}");
    }
    let stats = handle.stats();
    let down = stats.label_index(Some("down.example"));
    let default = stats.label_index(Some("127.0.0.1"));
    assert_eq!(stats.mask(down, MaskResult::ConnectFailed), 1);
    assert_eq!(stats.mask(default, MaskResult::ConnectFailed), 1);
}

#[tokio::test]
async fn metrics_report_usage_and_failures_per_sni() {
    let setup = spawn_masked_proxy("").await;
    let stats = setup.handle.stats().clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics = listener.local_addr().unwrap();
    tokio::spawn(stats::serve_metrics(listener, stats.clone()));

    // Two good sessions on a.example (one still open), one on an unlisted SNI,
    // one failure on b.example.
    let mut open = Client::connect_with_sni(setup.proxy, DC, "a.example").await;
    assert_eq!(open.echo(b"ping").await, b"ping");
    let closed = Client::connect_with_sni(setup.proxy, DC, "A.Example").await;
    drop(closed);
    let mut unlisted = Client::connect_with_sni(setup.proxy, DC, "unlisted.example").await;
    assert_eq!(unlisted.echo(b"ping").await, b"ping");
    let (failed, site) = masked_by(
        setup.proxy,
        &signed_hello_for("b.example", &[0x42; 16], unix_now()),
    )
    .await;
    assert_eq!(site, "B");
    drop(failed);

    let a = stats.label_index(Some("a.example"));
    let b = stats.label_index(Some("b.example"));
    for _ in 0..200 {
        if stats.active_sessions(a) == 1 && stats.mask(b, MaskResult::Forwarded) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut http = TcpStream::connect(metrics).await.unwrap();
    http.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    timeout(STEP, http.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));

    for line in [
        "echo_mtproxy_handshakes_total{sni=\"a.example\",result=\"accepted\"} 2",
        "echo_mtproxy_handshakes_total{sni=\"b.example\",result=\"accepted\"} 0",
        "echo_mtproxy_handshakes_total{sni=\"b.example\",result=\"bad_digest\"} 1",
        "echo_mtproxy_handshakes_total{sni=\"_other\",result=\"accepted\"} 1",
        "echo_mtproxy_sessions_active{sni=\"a.example\"} 1",
        "echo_mtproxy_sessions_active{sni=\"_other\"} 1",
        "echo_mtproxy_mask_connections_total{target=\"b.example\",result=\"forwarded\"} 1",
        "echo_mtproxy_mask_connections_total{target=\"a.example\",result=\"forwarded\"} 0",
    ] {
        assert!(
            response.lines().any(|l| l == line),
            "missing {line}\n{response}"
        );
    }
    // Client-chosen names never become labels.
    assert!(!response.contains("unlisted.example"));
    drop((open, unlisted));
}

#[tokio::test]
async fn idle_session_is_closed_and_active_one_is_kept() {
    let dc = spawn_echo_dc(true).await;
    let proxy = spawn_proxy_with("fast", dc, "idle_timeout_secs = 1").await;

    // Traffic every 300 ms for 2.4 s: well past the timeout, never idle.
    let mut active = Client::connect(proxy, DC).await;
    let mut idle = Client::connect(proxy, DC).await;
    assert_eq!(idle.echo(b"once").await, b"once");
    let idle_since = std::time::Instant::now();
    for _ in 0..8 {
        assert_eq!(active.echo(b"keepalive").await, b"keepalive");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    let mut buf = [0u8; 8];
    let read = timeout(STEP, idle.read.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)), "idle session still open");
    assert!(idle_since.elapsed() >= Duration::from_secs(1));

    // The active session ends once it goes quiet too.
    let quiet_since = std::time::Instant::now();
    let read = timeout(STEP, active.read.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    let quiet = quiet_since.elapsed();
    assert!(
        quiet >= Duration::from_millis(600) && quiet < Duration::from_secs(3),
        "{quiet:?}"
    );
}

#[tokio::test]
async fn connections_over_the_limit_get_silence() {
    let dc = spawn_echo_dc(true).await;
    let blackhole = spawn_blackhole().await;
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         max_connections = 2\n\
         handshake_timeout_secs = 2\n\
         mask_host = \"{blackhole}\"\n\
         metrics_listen = \"\"\n\
         [dc_override]\n\
         {DC} = \"{dc}\"\n"
    ))
    .await;
    let stats = handle.stats();

    let mut first = Client::connect(proxy, DC).await;
    let mut second = Client::connect(proxy, DC).await;
    assert_eq!(first.echo(b"one").await, b"one");
    assert_eq!(second.echo(b"two").await, b"two");
    assert_eq!(stats.connections_open(), 2);

    // A third client with a perfectly valid hello gets nothing back, and the
    // connection is dropped once the handshake timeout passes.
    let mut third = TcpStream::connect(proxy).await.unwrap();
    third
        .write_all(&signed_hello(&secret().key, unix_now()))
        .await
        .unwrap();
    assert!(stays_silent(&mut third).await);
    assert_eq!(stats.connections_over_limit(), 1);
    assert_eq!(stats.connections_open(), 2);
    let mut buf = [0u8; 8];
    let read = timeout(Duration::from_secs(5), third.read(&mut buf)).await;
    assert!(matches!(
        read.expect("held past the handshake timeout"),
        Ok(0) | Err(_)
    ));

    // Existing sessions are untouched, and a freed slot is usable again.
    assert_eq!(first.echo(b"still here").await, b"still here");
    drop(second);
    for _ in 0..200 {
        if stats.connections_open() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(stats.connections_open(), 1);
    let mut replacement = Client::connect(proxy, DC).await;
    assert_eq!(replacement.echo(b"new").await, b"new");
    assert_eq!(stats.connections_over_limit(), 1);
}

#[tokio::test]
async fn held_over_limit_connections_are_bounded() {
    let blackhole = spawn_blackhole().await;
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         max_connections = 1\n\
         handshake_timeout_secs = 30\n\
         mask_host = \"{blackhole}\"\n\
         metrics_listen = \"\"\n"
    ))
    .await;

    // One admitted connection (idle in its handshake), then a flood.
    let _admitted = TcpStream::connect(proxy).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut flood = Vec::new();
    for _ in 0..80 {
        flood.push(TcpStream::connect(proxy).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // With max_connections = 1 the proxy holds at most 16; the rest are closed.
    let mut held = 0;
    let mut closed = 0;
    for stream in &mut flood {
        let mut buf = [0u8; 1];
        match timeout(Duration::from_millis(20), stream.read(&mut buf)).await {
            Err(_) => held += 1,
            Ok(Ok(0)) | Ok(Err(_)) => closed += 1,
            Ok(Ok(_)) => panic!("over-limit connection received data"),
        }
    }
    assert_eq!(held, 16);
    assert_eq!(closed, 64);
    assert_eq!(handle.stats().connections_over_limit(), 80);
    assert_eq!(handle.stats().connections_open(), 1);
}
