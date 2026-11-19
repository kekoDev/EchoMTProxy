//! In-process fake client ↔ proxy ↔ fake middle proxy.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use echo_mtproxy::config::Config;
use echo_mtproxy::middle::peer::{self, ProxyReq};
use echo_mtproxy::middle::Table;
use echo_mtproxy::server::Proxy;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

const AD_TAG: &str = "00112233445566778899aabbccddeeff";

/// What the fake middle proxy does with each request.
#[derive(Clone, Copy, PartialEq)]
enum Behaviour {
    /// Sends the message back as an answer.
    Echo,
    /// Sends a quick-ack, then the message back.
    AckThenEcho,
    /// Answers the first request, then asks to close the connection.
    CloseAfterFirst,
}

/// A fake middle proxy. Every request it receives is also reported on the
/// returned channel.
async fn spawn_middle(behaviour: Behaviour) -> (SocketAddr, mpsc::UnboundedReceiver<ProxyReq>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (seen, requests) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let secret = Table::builtin().secret().to_vec();
                let Ok(mut middle) = peer::accept(stream, &secret).await else {
                    return;
                };
                while let Ok(Some(request)) = middle.read_request().await {
                    let _ = seen.send(request.clone());
                    if behaviour == Behaviour::AckThenEcho {
                        let ack = peer::simple_ack(&request.conn_id, [0xa1, 0xa2, 0xa3, 0xa4]);
                        middle.write_frame(&ack).await.unwrap();
                    }
                    let answer = peer::proxy_ans(&request.conn_id, &request.data);
                    if middle.write_frame(&answer).await.is_err() {
                        return;
                    }
                    if behaviour == Behaviour::CloseAfterFirst {
                        let close = peer::close_ext(&request.conn_id);
                        let _ = middle.write_frame(&close).await;
                        // Stays open: the proxy has to act on the close itself.
                        tokio::time::sleep(STEP * 3).await;
                    }
                }
            });
        }
    });
    (addr, requests)
}

/// Writes a middle-proxy list file and returns its path.
fn proxy_list(lines: &[(i16, SocketAddr)]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("echo-mtproxy-list-{}", rand::random::<u64>()));
    let text: String = lines
        .iter()
        .map(|(dc, addr)| format!("proxy_for {dc} {addr};\n"))
        .collect();
    std::fs::write(&path, text).unwrap();
    path
}

async fn spawn_middle_proxy(list: &[(i16, SocketAddr)], extra: &str) -> (SocketAddr, Arc<Proxy>) {
    let blackhole = spawn_blackhole().await;
    let list = proxy_list(list);
    spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         upstream_mode = \"middle\"\n\
         middle_proxy_config_files = [{list:?}]\n\
         mask_host = \"{blackhole}\"\n\
         metrics_listen = \"\"\n\
         {extra}\n"
    ))
    .await
}

/// One client message as a padded-intermediate frame.
fn frame(msg: &[u8], pad: usize, quickack: bool) -> Vec<u8> {
    let mut word = (msg.len() + pad) as u32;
    if quickack {
        word |= 0x8000_0000;
    }
    let mut out = word.to_le_bytes().to_vec();
    out.extend_from_slice(msg);
    out.extend_from_slice(&[0x99; 3][..pad]);
    out
}

/// Reads one message from the proxy, dropping its padding.
async fn recv_message(client: &mut Client) -> Vec<u8> {
    let word = client.recv(4).await;
    let total = u32::from_le_bytes(word.try_into().unwrap()) as usize;
    let mut msg = client.recv(total).await;
    msg.truncate(total - total % 4);
    msg
}

#[tokio::test]
async fn messages_round_trip_with_the_ad_tag_and_client_address() {
    let (middle, mut requests) = spawn_middle(Behaviour::Echo).await;
    let (proxy, handle) =
        spawn_middle_proxy(&[(DC, middle)], &format!("ad_tag = \"{AD_TAG}\"")).await;
    let mut client = Client::connect(proxy, DC).await;
    let client_addr = client.write.local_addr().unwrap();

    // An unencrypted first message, as a real client's key exchange starts.
    let mut first = vec![0u8; 8];
    first.extend_from_slice(&random_bytes(32));
    for (index, len) in [40, 4, 1000, 16384, 16388, 300_000].into_iter().enumerate() {
        let msg = if index == 0 {
            first.clone()
        } else {
            random_bytes(len)
        };
        client.send(&frame(&msg, index % 4, false)).await;
        assert_eq!(recv_message(&mut client).await, msg, "message {index}");

        let request = requests.recv().await.unwrap();
        assert_eq!(request.data, msg);
        assert_eq!(request.client, client_addr);
        assert_eq!(request.proxy.ip(), middle.ip());
        assert_eq!(
            request.ad_tag.map(hex::encode).as_deref(),
            Some(AD_TAG),
            "message {index}"
        );
        assert_eq!(request.flags & peer::NOT_ENCRYPTED != 0, index == 0);
    }
    assert_eq!(handle.stats().middle_connects(), (1, 0));
}

#[tokio::test]
async fn several_messages_in_one_write_and_split_writes_arrive_intact() {
    let (middle, _requests) = spawn_middle(Behaviour::Echo).await;
    let (proxy, _) = spawn_middle_proxy(&[(DC, middle)], "").await;
    let mut client = Client::connect(proxy, DC).await;

    let messages: Vec<Vec<u8>> = (1..40).map(|n| random_bytes(n * 12)).collect();
    let mut stream = Vec::new();
    for (index, msg) in messages.iter().enumerate() {
        stream.extend_from_slice(&frame(msg, index % 4, false));
    }
    // Everything at once, then again in pieces that cut through headers.
    client.send(&stream).await;
    for msg in &messages {
        assert_eq!(&recv_message(&mut client).await, msg);
    }
    for piece in stream.chunks(7) {
        client.send(piece).await;
    }
    for msg in &messages {
        assert_eq!(&recv_message(&mut client).await, msg);
    }
}

#[tokio::test]
async fn no_tag_is_sent_when_none_is_configured() {
    let (middle, mut requests) = spawn_middle(Behaviour::Echo).await;
    let (proxy, _) = spawn_middle_proxy(&[(DC, middle)], "").await;
    let mut client = Client::connect(proxy, DC).await;
    let msg = random_bytes(64);
    client.send(&frame(&msg, 0, false)).await;
    assert_eq!(recv_message(&mut client).await, msg);
    assert_eq!(requests.recv().await.unwrap().ad_tag, None);
}

#[tokio::test]
async fn quick_ack_is_requested_and_delivered_bare() {
    let (middle, mut requests) = spawn_middle(Behaviour::AckThenEcho).await;
    let (proxy, _) = spawn_middle_proxy(&[(DC, middle)], "").await;
    let mut client = Client::connect(proxy, DC).await;
    let msg = random_bytes(48);
    client.send(&frame(&msg, 0, true)).await;
    assert_ne!(requests.recv().await.unwrap().flags & peer::QUICKACK, 0);
    // The ack is four bytes with no length in front of them.
    assert_eq!(client.recv(4).await, [0xa1, 0xa2, 0xa3, 0xa4]);
    assert_eq!(recv_message(&mut client).await, msg);
}

#[tokio::test]
async fn media_sessions_use_the_media_entry() {
    let (chat, mut chat_requests) = spawn_middle(Behaviour::Echo).await;
    let (media, mut media_requests) = spawn_middle(Behaviour::Echo).await;
    let (proxy, _) = spawn_middle_proxy(&[(DC, chat), (-DC, media)], "").await;

    for (dc_idx, requests) in [(DC, &mut chat_requests), (-DC, &mut media_requests)] {
        let mut client = Client::connect(proxy, dc_idx).await;
        let msg = random_bytes(128);
        client.send(&frame(&msg, 0, false)).await;
        assert_eq!(recv_message(&mut client).await, msg);
        assert_eq!(requests.recv().await.unwrap().data, msg);
    }
    assert!(chat_requests.try_recv().is_err());
    assert!(media_requests.try_recv().is_err());
}

async fn expect_closed(client: &mut Client) {
    let mut buf = [0u8; 16];
    let read = timeout(STEP, client.read.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
}

#[tokio::test]
async fn dc_without_a_middle_proxy_closes_the_client() {
    let (middle, _requests) = spawn_middle(Behaviour::Echo).await;
    let (proxy, handle) = spawn_middle_proxy(&[(DC, middle)], "").await;
    expect_closed(&mut Client::connect(proxy, 4).await).await;
    assert_eq!(handle.stats().middle_connects(), (0, 0));
}

#[tokio::test]
async fn dead_middle_proxy_is_skipped_for_a_live_one() {
    let (middle, _requests) = spawn_middle(Behaviour::Echo).await;
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let (proxy, handle) = spawn_middle_proxy(&[(DC, dead), (DC, middle)], "").await;

    // The order is random per session, so enough sessions hit the dead one.
    for _ in 0..12 {
        let mut client = Client::connect(proxy, DC).await;
        let msg = random_bytes(32);
        client.send(&frame(&msg, 0, false)).await;
        assert_eq!(recv_message(&mut client).await, msg);
    }
    let (connected, failed) = handle.stats().middle_connects();
    assert_eq!(connected, 12);
    assert!(failed > 0, "the dead address was never tried");
}

#[tokio::test]
async fn unreachable_middle_proxy_closes_the_client_and_is_counted() {
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let (proxy, handle) = spawn_middle_proxy(&[(DC, dead)], "").await;
    expect_closed(&mut Client::connect(proxy, DC).await).await;
    assert_eq!(handle.stats().middle_connects(), (0, 3));
}

#[tokio::test]
async fn wrong_public_address_fails_the_handshake() {
    let (middle, _requests) = spawn_middle(Behaviour::Echo).await;
    let (proxy, handle) =
        spawn_middle_proxy(&[(DC, middle)], "public_ipv4 = \"203.0.113.77\"").await;
    expect_closed(&mut Client::connect(proxy, DC).await).await;
    assert_eq!(handle.stats().middle_connects(), (0, 3));
}

#[tokio::test]
async fn close_from_the_middle_proxy_closes_the_client() {
    let (middle, _requests) = spawn_middle(Behaviour::CloseAfterFirst).await;
    let (proxy, _) = spawn_middle_proxy(&[(DC, middle)], "").await;
    let mut client = Client::connect(proxy, DC).await;
    let msg = random_bytes(32);
    client.send(&frame(&msg, 0, false)).await;
    assert_eq!(recv_message(&mut client).await, msg);
    expect_closed(&mut client).await;
}

#[tokio::test]
async fn garbage_instead_of_a_message_closes_the_client() {
    let (middle, _requests) = spawn_middle(Behaviour::Echo).await;
    let (proxy, _) = spawn_middle_proxy(&[(DC, middle)], "").await;
    let mut client = Client::connect(proxy, DC).await;
    // A length far beyond any message.
    client.send(&0x7fff_fff0u32.to_le_bytes()).await;
    expect_closed(&mut client).await;
}

#[tokio::test]
async fn idle_middle_session_is_timed_out() {
    let (middle, _requests) = spawn_middle(Behaviour::Echo).await;
    let (proxy, _) = spawn_middle_proxy(&[(DC, middle)], "idle_timeout_secs = 1").await;
    let mut client = Client::connect(proxy, DC).await;
    let msg = random_bytes(64);
    client.send(&frame(&msg, 0, false)).await;
    assert_eq!(recv_message(&mut client).await, msg);

    let start = std::time::Instant::now();
    expect_closed(&mut client).await;
    assert!(start.elapsed() >= Duration::from_millis(900));
}

#[tokio::test]
async fn media_limits_apply_through_a_middle_proxy() {
    let (middle, _requests) = spawn_middle(Behaviour::Echo).await;
    let (proxy, handle) = spawn_middle_proxy(
        &[(DC, middle), (-DC, middle)],
        "media_rate_bps = 800000\nmedia_burst_bytes = 20000",
    )
    .await;

    // 60 kB each way against a 20 kB burst and 100 kB/s: media has to wait.
    let msg = random_bytes(60_000);
    let mut media = Client::connect(proxy, -DC).await;
    let start = std::time::Instant::now();
    media.send(&frame(&msg, 0, false)).await;
    assert_eq!(recv_message(&mut media).await, msg);
    let media_took = start.elapsed();
    assert!(media_took >= Duration::from_millis(500), "{media_took:?}");

    let mut chat = Client::connect(proxy, DC).await;
    let start = std::time::Instant::now();
    chat.send(&frame(&msg, 0, false)).await;
    assert_eq!(recv_message(&mut chat).await, msg);
    assert!(start.elapsed() < media_took);

    let limits = &handle.stats().limits;
    assert!(limits.bytes(echo_mtproxy::limit::Lane::Media) >= 120_000);
    assert!(limits.bytes(echo_mtproxy::limit::Lane::Chat) >= 120_000);
}

#[test]
fn ad_tag_needs_middle_mode_and_32_hex_characters() {
    let config = |extra: &str| Config::parse(&format!("secrets = [\"{SECRET_HEX}\"]\n{extra}"));
    assert!(config(&format!("ad_tag = \"{AD_TAG}\"")).is_err());
    assert!(config(&format!(
        "upstream_mode = \"middle\"\nad_tag = \"{AD_TAG}\""
    ))
    .is_ok());
    assert!(config("upstream_mode = \"middle\"").is_ok());
    for bad in ["00", "zz112233445566778899aabbccddeeff", &AD_TAG[2..]] {
        assert!(
            config(&format!("upstream_mode = \"middle\"\nad_tag = \"{bad}\"")).is_err(),
            "{bad}"
        );
    }
    assert!(config("public_ipv4 = \"not an address\"").is_err());
    assert!(config("public_ipv6 = \"192.0.2.1\"").is_err());
    assert!(config("public_ipv4 = \"192.0.2.1\"\npublic_ipv6 = \"2001:db8::1\"").is_ok());
}

/// Sends an unencrypted MTProto `req_pq_multi` through the proxy and one of
/// Telegram's real middle proxies and expects `resPQ` with our nonce, for
/// every DC and both lanes. This is the first message of every new client.
///
/// Middle-proxy keys depend on this host's public address, so it has to be
/// given: `ECHO_PUBLIC_IPV4=... cargo test --test middle real_middle -- --ignored`.
async fn real_middle_proxy_answers(ad_tag: &str) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let public = std::env::var("ECHO_PUBLIC_IPV4").expect("set ECHO_PUBLIC_IPV4");
    let (proxy, handle) = spawn_proxy_handle(&format!(
        "secrets = [\"{SECRET_HEX}\"]\n\
         upstream_mode = \"middle\"\n\
         prefer_ipv6_upstream = false\n\
         public_ipv4 = \"{public}\"\n\
         ad_tag = \"{ad_tag}\"\n\
         metrics_listen = \"\"\n"
    ))
    .await;

    for dc in (1..=5).flat_map(|dc| [dc, -dc]) {
        // Behind a NAT that rewrites source ports the keys cannot match and
        // the middle proxy drops the handshake, so a session may need a few
        // tries from such a host. On a server with a public address the
        // first one works.
        let mut answer = None;
        let nonce = random_bytes(16);
        for _ in 0..8 {
            let mut client = Client::connect(proxy, dc).await;
            let mut message = vec![0u8; 8];
            message.extend_from_slice(&((u64::from(unix_now()) << 32) | 4).to_le_bytes());
            message.extend_from_slice(&20u32.to_le_bytes());
            message.extend_from_slice(&0xbe7e8ef1u32.to_le_bytes());
            message.extend_from_slice(&nonce);
            client.send(&frame(&message, 3, false)).await;

            let mut word = [0u8; 4];
            let mut got = Vec::new();
            let read = timeout(STEP, async {
                // The proxy closes without a byte when the middle proxy refused it.
                let first = client.read.read(&mut word[..0]).await;
                if first.is_err() {
                    return false;
                }
                match timeout(STEP, recv_message_or_close(&mut client)).await {
                    Ok(Some(msg)) => {
                        got = msg;
                        true
                    }
                    _ => false,
                }
            })
            .await;
            if read == Ok(true) {
                answer = Some(got);
                break;
            }
        }
        let answer = answer.unwrap_or_else(|| {
            panic!(
                "DC {dc}: no answer; middle connects (ok, failed) = {:?}",
                handle.stats().middle_connects()
            )
        });
        assert!(answer.len() >= 40, "DC {dc}: short answer {answer:?}");
        assert_eq!(
            answer[20..24],
            0x05162463u32.to_le_bytes(),
            "DC {dc} did not answer with resPQ"
        );
        assert_eq!(answer[24..40], nonce[..], "DC {dc} nonce mismatch");
    }
    let (connected, failed) = handle.stats().middle_connects();
    println!("middle-proxy handshakes: {connected} accepted, {failed} refused");
}

/// Like `recv_message`, but `None` if the proxy closes first.
async fn recv_message_or_close(client: &mut Client) -> Option<Vec<u8>> {
    use echo_mtproxy::cipher::Ctr;
    let mut plain = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        if plain.len() >= 4 {
            let total = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
            if plain.len() >= 4 + total {
                return Some(plain[4..4 + total - total % 4].to_vec());
            }
        }
        let n = client.read.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        let len = client.records.unwrap_in_place(&mut buf, n).ok()?;
        client.dec.apply(&mut buf[..len]);
        plain.extend_from_slice(&buf[..len]);
    }
}

#[tokio::test]
#[ignore = "connects to real Telegram middle proxies"]
async fn real_middle_proxy_without_a_tag() {
    real_middle_proxy_answers("").await;
}

#[tokio::test]
#[ignore = "connects to real Telegram middle proxies"]
async fn real_middle_proxy_with_a_tag() {
    // Not a registered tag: this only shows that tagged requests are accepted.
    real_middle_proxy_answers(AD_TAG).await;
}
