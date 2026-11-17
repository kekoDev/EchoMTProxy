//! In-process fake client ↔ proxy ↔ fake DC echo server.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use echo_mtproxy::cipher::Ctr;
use echo_mtproxy::obfs2;
use echo_mtproxy::server::{self, Proxy};
use echo_mtproxy::stats::{self, HandshakeResult, MaskResult};
use echo_mtproxy::tls;
use rand::{Rng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

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

#[tokio::test]
async fn masked_connection_is_dropped_after_mask_idle_timeout() {
    let setup = spawn_masked_proxy("mask_idle_timeout_secs = 1").await;
    let hello = signed_hello_for("a.example", &[0x42; 16], unix_now());
    let (mut stream, site) = masked_by(setup.proxy, &hello).await;
    assert_eq!(site, "A");

    let idle_since = std::time::Instant::now();
    let mut buf = [0u8; 8];
    let read = timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
    assert!(matches!(
        read.expect("idle masked connection stayed open"),
        Ok(0) | Err(_)
    ));
    let idle = idle_since.elapsed();
    assert!(
        idle >= Duration::from_millis(900) && idle < Duration::from_secs(3),
        "{idle:?}"
    );
}

/// A site that reads `expect` bytes and then ends the connection, either with
/// a TCP reset or with a normal close.
async fn spawn_closing_site(expect: usize, reset: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; expect];
                if stream.read_exact(&mut buf).await.is_err() {
                    return;
                }
                if reset {
                    // Zero linger turns the close into an RST.
                    socket2::SockRef::from(&stream)
                        .set_linger(Some(Duration::ZERO))
                        .unwrap();
                }
                drop(stream);
            });
        }
    });
    addr
}

#[tokio::test]
async fn mask_site_reset_reaches_the_client_as_a_reset() {
    let hello = signed_hello_for("reset.example", &[0x42; 16], unix_now());
    let resetting = spawn_closing_site(hello.len(), true).await;
    let closing = spawn_closing_site(hello.len(), false).await;
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         mask_domains = [\"reset.example={resetting}\", \"close.example={closing}\"]\n\
         mask_host = \"{closing}\"\n\
         metrics_listen = \"\"\n"
    ))
    .await;

    // Several rounds: the outcome must not depend on timing.
    for round in 0..10 {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(&hello).await.unwrap();
        let mut buf = [0u8; 8];
        let read = timeout(STEP, stream.read(&mut buf)).await.unwrap();
        let err = read.expect_err("site reset arrived as a clean close");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionReset,
            "round {round}"
        );
    }

    // A site that closes normally must reach the client as a normal close.
    let clean = signed_hello_for("close.example", &[0x42; 16], unix_now());
    for round in 0..10 {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(&clean).await.unwrap();
        let mut buf = [0u8; 8];
        let read = timeout(STEP, stream.read(&mut buf)).await.unwrap();
        assert_eq!(read.unwrap(), 0, "round {round}");
    }

    let stats = handle.stats();
    let reset = stats.label_index(Some("reset.example"));
    for _ in 0..200 {
        if stats.mask(reset, MaskResult::Forwarded) == 10 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(stats.mask(reset, MaskResult::Forwarded), 10);
}

#[tokio::test]
async fn chat_is_unaffected_while_media_is_throttled() {
    let dc = spawn_echo_dc(true).await;
    // 800 kbit/s (100 kB/s) per media connection after a 50 kB burst.
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         media_rate_bps = 800000\n\
         media_burst_bytes = 50000\n\
         metrics_listen = \"\"\n\
         [dc_override]\n\
         {DC} = \"{dc}\"\n"
    ))
    .await;
    let limits = &handle.stats().limits;

    // The same 200 kB echo on both lanes at the same time. Each byte crosses
    // the proxy twice, so the media session is charged 400 kB: 350 kB beyond
    // its burst, which takes 3.5 s at 100 kB/s.
    let payload = random_bytes(200_000);
    let media = Client::connect(proxy, -DC).await;
    let chat = Client::connect(proxy, DC).await;
    let timed = |mut client: Client, data: Vec<u8>| async move {
        let start = std::time::Instant::now();
        let echoed = client.echo(&data).await;
        assert!(echoed == data, "data changed in transit");
        (start.elapsed(), client)
    };
    let media_task = tokio::spawn(timed(media, payload.clone()));
    let (chat_took, mut chat) = timed(chat, payload.clone()).await;

    // The chat session can do a second round while media is still waiting.
    let start = std::time::Instant::now();
    assert!(chat.echo(&payload).await == payload);
    let chat_again = start.elapsed();
    assert!(
        !media_task.is_finished(),
        "media finished before two chat rounds: it was not throttled"
    );
    assert!(limits.throttled_now() >= 1, "no media session is waiting");

    let (media_took, media) = media_task.await.unwrap();
    assert!(
        media_took >= Duration::from_millis(2800) && media_took < Duration::from_secs(10),
        "media took {media_took:?}"
    );
    // Chat is bounded by this machine's speed only, far below media's time.
    assert!(
        chat_took * 3 < media_took && chat_again * 3 < media_took,
        "chat {chat_took:?} and {chat_again:?}, media {media_took:?}"
    );

    assert!(limits.bytes(echo_mtproxy::limit::Lane::Media) >= 400_000);
    assert!(limits.bytes(echo_mtproxy::limit::Lane::Chat) >= 800_000);
    drop((media, chat));
    for _ in 0..100 {
        if limits.throttled_now() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(limits.throttled_now(), 0);
}

#[tokio::test]
async fn media_is_not_limited_when_the_rate_is_zero() {
    let dc = spawn_echo_dc(true).await;
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         media_rate_bps = 0\n\
         media_burst_bytes = 0\n\
         metrics_listen = \"\"\n\
         [dc_override]\n\
         {DC} = \"{dc}\"\n"
    ))
    .await;
    assert!(!handle.stats().limits.media_limited());
    // With no burst, any limiting at all would stall this for minutes.
    let mut media = Client::connect(proxy, -DC).await;
    let payload = random_bytes(300_000);
    let echoed = timeout(Duration::from_secs(20), media.echo(&payload))
        .await
        .expect("media was throttled although the rate is 0");
    assert!(echoed == payload);
    assert_eq!(handle.stats().limits.throttled_now(), 0);
}

#[tokio::test]
async fn congestion_scales_media_down_and_recovers() {
    use echo_mtproxy::limit::Lane;

    let dc = spawn_echo_dc(true).await;
    // An 8 Mbit/s "link" with the threshold at half of it: 500 kB/s of relay
    // egress. Media connections get 80 kB/s with no burst.
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         link_capacity_bps = 8000000\n\
         congestion_threshold = 0.5\n\
         media_rate_bps = 640000\n\
         media_burst_bytes = 0\n\
         metrics_listen = \"\"\n\
         [dc_override]\n\
         {DC} = \"{dc}\"\n"
    ))
    .await;
    let stats = handle.stats().clone();
    tokio::spawn(server::run_congestion_control(stats.clone()));
    let limits = &stats.limits;
    assert_eq!(limits.scale(), 1.0);

    // Chat traffic far above the threshold for a while.
    let mut chat = Client::connect(proxy, DC).await;
    let chunk = random_bytes(200_000);
    let flood_until = std::time::Instant::now() + Duration::from_millis(1500);
    let mut lowest: f64 = 1.0;
    let mut peak_egress = 0;
    let mut rounds = 0u32;
    while std::time::Instant::now() < flood_until {
        assert!(chat.echo(&chunk).await == chunk);
        rounds += 1;
        lowest = lowest.min(limits.scale());
        peak_egress = peak_egress.max(limits.egress_bps());
    }
    // Chat itself was never slowed: it moved far more than the threshold allows.
    let chat_rate = f64::from(rounds) * 400_000.0 / 1.5;
    assert!(chat_rate > 1_000_000.0, "chat moved only {chat_rate} B/s");
    assert!(
        peak_egress > 4_000_000,
        "measured egress {peak_egress} bit/s"
    );
    assert!(lowest < 0.5, "media scale only fell to {lowest}");
    assert!(lowest >= 0.05);

    // While congested, a media connection is slower than its configured rate:
    // 20 kB echoed is 40 kB charged, 0.5 s at 80 kB/s, longer when scaled.
    let keep_flooding = tokio::spawn(async move {
        let until = std::time::Instant::now() + Duration::from_millis(1500);
        while std::time::Instant::now() < until {
            assert!(chat.echo(&chunk).await == chunk);
        }
        chat
    });
    let mut media = Client::connect(proxy, -DC).await;
    let small = random_bytes(20_000);
    let start = std::time::Instant::now();
    assert!(media.echo(&small).await == small);
    let congested = start.elapsed();
    assert!(
        congested > Duration::from_millis(700),
        "media took only {congested:?}"
    );
    let _chat = keep_flooding.await.unwrap();

    // With the link quiet the scale returns to 1 (10% per 200 ms tick).
    let recover_by = std::time::Instant::now() + Duration::from_secs(15);
    while limits.scale() < 1.0 {
        assert!(
            std::time::Instant::now() < recover_by,
            "scale stuck at {}",
            limits.scale()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(limits.egress_bps() < 4_000_000);
    assert!(limits.bytes(Lane::Chat) > limits.bytes(Lane::Media));
}

#[tokio::test]
async fn sessions_work_with_upstream_bind_addrs() {
    let dc = spawn_echo_dc(true).await;
    let proxy =
        spawn_proxy_with("fast", dc, "upstream_bind_addrs = [\"127.0.0.1\", \"::1\"]").await;
    for _ in 0..5 {
        let mut client = Client::connect(proxy, DC).await;
        assert_eq!(client.echo(b"bound upstream").await, b"bound upstream");
    }
}

#[tokio::test]
async fn unassigned_upstream_bind_addr_fails_at_startup() {
    let config = echo_mtproxy::config::Config::parse(&format!(
        "secrets = [\"{SECRET_HEX}\"]\nupstream_bind_addrs = [\"192.0.2.77\"]\n"
    ))
    .unwrap();
    let err = Proxy::from_config(&config)
        .err()
        .expect("startup should fail");
    assert!(format!("{err:#}").contains("192.0.2.77"), "{err:#}");
}

/// Length of the upstream handshake in the obfuscated modes.
const INIT: usize = 64;

/// A DC that reads `swallow` bytes, then resets the connection without ever
/// answering. Counts the connections it received.
async fn spawn_resetting_dc(
    bind: &str,
    swallow: usize,
) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind(bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tokio::spawn(async move {
                let mut buf = vec![0u8; swallow];
                let _ = stream.read_exact(&mut buf).await;
                socket2::SockRef::from(&stream)
                    .set_linger(Some(Duration::ZERO))
                    .unwrap();
                drop(stream);
            });
        }
    });
    (addr, hits)
}

async fn spawn_echo_dc_at(bind: &str) -> SocketAddr {
    let listener = TcpListener::bind(bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = echo_dc_session(stream, true).await;
            });
        }
    });
    addr
}

/// Proxy whose DC 2 is `v4` on the IPv4 side and `v6` on the IPv6 side.
async fn spawn_two_family_proxy(
    mode: &str,
    prefer_ipv6: bool,
    v4: SocketAddr,
    v6: SocketAddr,
) -> (SocketAddr, Arc<Proxy>) {
    let blackhole = spawn_blackhole().await;
    spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         upstream_mode = \"{mode}\"\n\
         prefer_ipv6_upstream = {prefer_ipv6}\n\
         mask_host = \"{blackhole}\"\n\
         metrics_listen = \"\"\n\
         [dc_override]\n\
         {DC} = \"{v4}\"\n\
         [dc_override_v6]\n\
         {DC} = \"{v6}\"\n"
    ))
    .await
}

#[tokio::test]
async fn dc_reset_before_first_byte_is_retried_on_the_other_family() {
    use std::sync::atomic::Ordering;
    for mode in ["fast", "obfuscated", "plain"] {
        // IPv4 side resets right after the upstream handshake (a 4-byte tag
        // in plain mode); IPv6 side works.
        let handshake = if mode == "plain" { 4 } else { INIT };
        let (bad, bad_hits) = spawn_resetting_dc("127.0.0.1:0", handshake).await;
        let good = if mode == "plain" {
            let listener = TcpListener::bind("[::1]:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    tokio::spawn(async move {
                        let _ = echo_dc_session(stream, false).await;
                    });
                }
            });
            addr
        } else {
            spawn_echo_dc_at("[::1]:0").await
        };
        let (proxy, handle) = spawn_two_family_proxy(mode, false, bad, good).await;

        let mut client = Client::connect(proxy, DC).await;
        let data = random_bytes(3000);
        assert!(client.echo(&data).await == data, "{mode}");
        // The session keeps working after the switch.
        let more = random_bytes(50_000);
        assert!(client.echo(&more).await == more, "{mode}");

        assert_eq!(bad_hits.load(Ordering::Relaxed), 1, "{mode}");
        assert_eq!(handle.stats().upstream_retries(), (1, 0), "{mode}");
    }
}

#[tokio::test]
async fn retry_replays_what_the_client_already_sent() {
    use std::sync::atomic::Ordering;
    // The IPv6 side (preferred here) swallows the init and the client's first
    // 2000 bytes before resetting, so those bytes must be sent again.
    let (bad, bad_hits) = spawn_resetting_dc("[::1]:0", INIT + 2000).await;
    let good = spawn_echo_dc_at("127.0.0.1:0").await;
    let (proxy, handle) = spawn_two_family_proxy("fast", true, good, bad).await;

    let mut client = Client::connect(proxy, DC).await;
    let data = random_bytes(2000);
    assert!(client.echo(&data).await == data);
    assert_eq!(bad_hits.load(Ordering::Relaxed), 1);
    assert_eq!(handle.stats().upstream_retries(), (1, 0));

    // Data sent in several pieces before the reset is replayed in order.
    let mut client = Client::connect(proxy, DC).await;
    let data = random_bytes(2000);
    for piece in data.chunks(500) {
        client.send(piece).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(client.recv(2000).await == data);
    assert_eq!(handle.stats().upstream_retries(), (2, 0));
}

#[tokio::test]
async fn only_one_retry_is_made() {
    use std::sync::atomic::Ordering;
    let (bad4, hits4) = spawn_resetting_dc("127.0.0.1:0", INIT).await;
    let (bad6, hits6) = spawn_resetting_dc("[::1]:0", INIT).await;
    let (proxy, handle) = spawn_two_family_proxy("fast", false, bad4, bad6).await;

    let mut client = Client::connect(proxy, DC).await;
    client.send(b"hello").await;
    let mut buf = [0u8; 8];
    let read = timeout(STEP, client.read.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)), "client was not closed");
    assert_eq!(hits4.load(Ordering::Relaxed), 1);
    assert_eq!(hits6.load(Ordering::Relaxed), 1);
    // The reconnect itself worked; the second reset is not retried.
    assert_eq!(handle.stats().upstream_retries(), (1, 0));
}

#[tokio::test]
async fn failed_reconnect_is_counted_and_closes_the_client() {
    let (bad4, _) = spawn_resetting_dc("127.0.0.1:0", INIT).await;
    let dead6 = {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let (proxy, handle) = spawn_two_family_proxy("fast", false, bad4, dead6).await;

    let mut client = Client::connect(proxy, DC).await;
    client.send(b"hello").await;
    let mut buf = [0u8; 8];
    let read = timeout(STEP, client.read.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    assert_eq!(handle.stats().upstream_retries(), (0, 1));
}

#[tokio::test]
async fn no_retry_without_another_family_or_after_too_much_data() {
    use std::sync::atomic::Ordering;
    // One address for both families: nowhere to retry.
    let (bad, hits) = spawn_resetting_dc("127.0.0.1:0", INIT).await;
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\nmetrics_listen = \"\"\n[dc_override]\n{DC} = \"{bad}\"\n"
    ))
    .await;
    let mut client = Client::connect(proxy, DC).await;
    client.send(b"hello").await;
    let mut buf = [0u8; 8];
    let read = timeout(STEP, client.read.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    assert_eq!(handle.stats().upstream_retries(), (0, 0));

    // More than 16 KiB sent before the reset: the proxy no longer has it all.
    let (bad, hits) = spawn_resetting_dc("127.0.0.1:0", INIT + 40_000).await;
    let good = spawn_echo_dc_at("[::1]:0").await;
    let (proxy, handle) = spawn_two_family_proxy("fast", false, bad, good).await;
    let mut client = Client::connect(proxy, DC).await;
    client.send(&random_bytes(40_000)).await;
    let read = timeout(STEP, client.read.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)), "session should have ended");
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    assert_eq!(handle.stats().upstream_retries(), (0, 0));
}

#[tokio::test]
async fn reset_after_the_dc_has_answered_is_not_retried() {
    use std::sync::atomic::Ordering;
    // Answers one echo, then resets.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let answering = listener.local_addr().unwrap();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let reset = socket2::SockRef::from(&stream).try_clone().unwrap();
                let _ = timeout(Duration::from_millis(400), echo_dc_session(stream, true)).await;
                let _ = reset.set_linger(Some(Duration::ZERO));
            });
        }
    });
    let good = spawn_echo_dc_at("[::1]:0").await;
    let (proxy, handle) = spawn_two_family_proxy("fast", false, answering, good).await;

    let mut client = Client::connect(proxy, DC).await;
    assert_eq!(client.echo(b"first").await, b"first");
    let mut buf = [0u8; 8];
    let read = timeout(STEP, client.read.read(&mut buf)).await.unwrap();
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "client should be closed by the DC reset"
    );
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    assert_eq!(handle.stats().upstream_retries(), (0, 0));
}

#[tokio::test]
async fn binary_serves_every_listen_address() {
    let dc = spawn_echo_dc(true).await;
    let mask = spawn_blackhole().await;
    let (first, second) = (free_port(), free_port());
    let listen: Vec<SocketAddr> = vec![
        format!("127.0.0.1:{first}").parse().unwrap(),
        format!("127.0.0.1:{second}").parse().unwrap(),
        format!("[::1]:{first}").parse().unwrap(),
    ];
    let listed = listen
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let metrics: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let _proxy = start_proxy_process(
        "ports",
        &format!(
            "listen = [{listed}]\n\
             secrets = [\"{SECRET_HEX}\"]\n\
             mask_host = \"{mask}\"\n\
             metrics_listen = \"{metrics}\"\n\
             [dc_override]\n\
             {DC} = \"{dc}\"\n"
        ),
        listen[0],
    )
    .await;

    // A full session on each address, all held open at the same time.
    let mut sessions = Vec::new();
    for addr in &listen {
        let mut client = Client::connect(*addr, DC).await;
        let data = format!("via {addr}");
        assert_eq!(client.echo(data.as_bytes()).await, data.as_bytes());
        sessions.push(client);
    }
    for client in &mut sessions {
        assert_eq!(client.echo(b"still open").await, b"still open");
    }

    // One process, one set of counters: all three sessions show up together.
    let mut http = TcpStream::connect(metrics).await.unwrap();
    http.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut text = String::new();
    http.read_to_string(&mut text).await.unwrap();
    assert!(
        text.lines()
            .any(|l| l
                == "echo_mtproxy_handshakes_total{sni=\"www.example.com\",result=\"accepted\"} 3"),
        "{text}"
    );
    assert!(text
        .lines()
        .any(|l| l == "echo_mtproxy_sessions_active{sni=\"www.example.com\"} 3"));
}

#[tokio::test]
async fn binary_refuses_to_start_when_a_listen_address_is_taken() {
    let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let busy = taken.local_addr().unwrap();
    let free = free_port();
    let config: std::path::PathBuf = [
        env!("CARGO_TARGET_TMPDIR"),
        &format!("busy-{}.toml", std::process::id()),
    ]
    .iter()
    .collect();
    std::fs::write(
        &config,
        format!(
            "listen = [\"127.0.0.1:{free}\", \"{busy}\"]\n\
             secrets = [\"{SECRET_HEX}\"]\nmetrics_listen = \"\"\n"
        ),
    )
    .unwrap();
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_echo-mtproxy"))
        .arg("--config")
        .arg(&config)
        .output();
    let output = timeout(STEP, output)
        .await
        .expect("the proxy kept running with a listen address it could not bind")
        .unwrap();
    let _ = std::fs::remove_file(&config);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&busy.to_string()), "{stderr}");
}

#[tokio::test]
async fn traffic_metrics_follow_real_sessions() {
    let dc = spawn_echo_dc(true).await;
    // An 8 Mbit/s link with the threshold at half; media at 100 kB/s, no burst.
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         link_capacity_bps = 8000000\n\
         congestion_threshold = 0.5\n\
         media_rate_bps = 800000\n\
         media_burst_bytes = 0\n\
         metrics_listen = \"\"\n\
         [dc_override]\n\
         {DC} = \"{dc}\"\n"
    ))
    .await;
    let stats = handle.stats().clone();
    tokio::spawn(server::run_congestion_control(stats.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics = listener.local_addr().unwrap();
    tokio::spawn(stats::serve_metrics(listener, stats.clone()));

    async fn scrape(addr: SocketAddr) -> String {
        let mut http = TcpStream::connect(addr).await.unwrap();
        http.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut text = String::new();
        http.read_to_string(&mut text).await.unwrap();
        text
    }
    fn value(text: &str, series: &str) -> f64 {
        text.lines()
            .find_map(|l| l.strip_prefix(series)?.strip_prefix(' '))
            .unwrap_or_else(|| panic!("no series {series}"))
            .parse()
            .unwrap()
    }

    // A media session that is being throttled, and chat traffic over the threshold.
    let mut media = Client::connect(proxy, -DC).await;
    let media_task = tokio::spawn(async move {
        let data = random_bytes(60_000);
        assert!(media.echo(&data).await == data);
        media
    });
    let mut chat = Client::connect(proxy, DC).await;
    let chunk = random_bytes(200_000);
    let mut seen_throttled = 0.0f64;
    let mut seen_egress = 0.0f64;
    let mut lowest_scale = 1.0f64;
    for _ in 0..6 {
        assert!(chat.echo(&chunk).await == chunk);
        let text = scrape(metrics).await;
        seen_throttled =
            seen_throttled.max(value(&text, "echo_mtproxy_media_connections_throttled"));
        seen_egress = seen_egress.max(value(&text, "echo_mtproxy_egress_bits_per_second"));
        lowest_scale = lowest_scale.min(value(&text, "echo_mtproxy_congestion_scale"));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        seen_throttled, 1.0,
        "the waiting media session was not reported"
    );
    assert!(seen_egress > 4_000_000.0, "egress {seen_egress}");
    assert!((0.05..1.0).contains(&lowest_scale), "scale {lowest_scale}");

    let _media = timeout(Duration::from_secs(30), media_task)
        .await
        .unwrap()
        .unwrap();
    let text = scrape(metrics).await;
    assert!(value(&text, "echo_mtproxy_relay_bytes_total{lane=\"chat\"}") >= 2_400_000.0);
    let media_bytes = value(&text, "echo_mtproxy_relay_bytes_total{lane=\"media\"}");
    assert!(
        (120_000.0..130_000.0).contains(&media_bytes),
        "{media_bytes}"
    );
    // The media session still owes a wait for its last bytes; once that has
    // passed nothing is throttled.
    let mut throttled = 1.0;
    for _ in 0..300 {
        throttled = value(
            &scrape(metrics).await,
            "echo_mtproxy_media_connections_throttled",
        );
        if throttled == 0.0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(throttled, 0.0);
}
