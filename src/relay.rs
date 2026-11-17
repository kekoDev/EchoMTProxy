use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::TcpStream;

use crate::cipher::{AesCtr, Ctr};
use crate::pool;
use crate::tls::{record_header, RecordReader, MAX_RECORD_PAYLOAD, RECORD_HEADER_LEN};

/// The idle watcher wakes this many times per idle period.
const IDLE_CHECKS: u32 = 4;

/// Per-direction ciphers. `None` means that step is skipped for the upstream
/// mode. Each state is about 1 KiB, so they are boxed: a session only pays for
/// the ones its mode uses, and the relay's own state stays small.
pub struct Ciphers {
    /// Removes the client's obfuscation.
    pub client_dec: Box<AesCtr>,
    /// Re-encrypts for the DC (obfuscated and fast modes).
    pub upstream_enc: Option<Box<AesCtr>>,
    /// Removes the DC's obfuscation (obfuscated mode).
    pub upstream_dec: Option<Box<AesCtr>>,
    /// Encrypts for the client (obfuscated and plain modes).
    pub client_enc: Option<Box<AesCtr>>,
}

/// Writes all of `data`, waiting for writability only when the socket is full.
pub(crate) async fn write_all(stream: &TcpStream, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        // Try first: the socket is usually writable and this saves a wake-up.
        match stream.try_write(data) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => data = &data[n..],
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => stream.writable().await?,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

async fn client_to_upstream(
    client: &TcpStream,
    upstream: &TcpStream,
    mut records: RecordReader,
    mut dec: Box<AesCtr>,
    mut enc: Option<Box<AesCtr>>,
    activity: &AtomicU64,
) -> io::Result<()> {
    loop {
        // No buffer is held while waiting here: this is where idle sessions sit.
        client.readable().await?;
        let mut buf = pool::take();
        let n = match client.try_read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        };
        activity.fetch_add(1, Ordering::Relaxed);
        let len = records
            .unwrap_in_place(&mut buf, n)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if len == 0 {
            continue;
        }
        let payload = &mut buf[..len];
        dec.apply(payload);
        if let Some(enc) = enc.as_mut() {
            enc.apply(payload);
        }
        write_all(upstream, payload).await?;
    }
}

async fn upstream_to_client(
    upstream: &TcpStream,
    client: &TcpStream,
    mut dec: Option<Box<AesCtr>>,
    mut enc: Option<Box<AesCtr>>,
    activity: &AtomicU64,
) -> io::Result<()> {
    loop {
        upstream.readable().await?;
        let mut buf = pool::take();
        // The payload is read behind room for the record header, so header and
        // payload leave in one write without copying the payload. One read
        // takes everything the kernel has, up to a full record, which is what
        // merges small upstream segments into large records under load.
        let n = match upstream.try_read(&mut buf[RECORD_HEADER_LEN..]) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        };
        activity.fetch_add(1, Ordering::Relaxed);
        let payload = &mut buf[RECORD_HEADER_LEN..RECORD_HEADER_LEN + n];
        if let Some(dec) = dec.as_mut() {
            dec.apply(payload);
        }
        if let Some(enc) = enc.as_mut() {
            enc.apply(payload);
        }
        buf[..RECORD_HEADER_LEN].copy_from_slice(&record_header(n));
        write_all(client, &buf[..RECORD_HEADER_LEN + n]).await?;
    }
}

/// Resolves once neither direction has read anything for `idle`.
///
/// Instead of re-arming a timer on every packet, the relay bumps a counter and
/// this wakes a few times per idle period to see whether it moved. The session
/// is therefore dropped between `idle` and `idle * 5/4` after its last byte.
async fn idle_watch(activity: &AtomicU64, idle: Option<Duration>) {
    let Some(idle) = idle else {
        return std::future::pending().await;
    };
    let tick = (idle / IDLE_CHECKS).max(Duration::from_millis(1));
    let mut last = activity.load(Ordering::Relaxed);
    let mut quiet = 0;
    while quiet < IDLE_CHECKS {
        tokio::time::sleep(tick).await;
        let now = activity.load(Ordering::Relaxed);
        if now == last {
            quiet += 1;
        } else {
            quiet = 0;
            last = now;
        }
    }
}

/// Relays until either side closes or fails, or until both directions have
/// been silent for `idle` (`None` disables that). `records` carries the
/// framing state left over from the handshake.
///
/// Buffers come from the pool and are held only from a successful read until
/// the write it feeds has finished.
pub async fn relay(
    client: &TcpStream,
    upstream: &TcpStream,
    records: RecordReader,
    ciphers: Ciphers,
    idle: Option<Duration>,
) -> io::Result<()> {
    const _: () = assert!(pool::BUF_LEN == RECORD_HEADER_LEN + MAX_RECORD_PAYLOAD);
    let activity = AtomicU64::new(0);
    tokio::select! {
        result = client_to_upstream(
            client,
            upstream,
            records,
            ciphers.client_dec,
            ciphers.upstream_enc,
            &activity,
        ) => result,
        result = upstream_to_client(
            upstream,
            client,
            ciphers.upstream_dec,
            ciphers.client_enc,
            &activity,
        ) => result,
        () = idle_watch(&activity, idle) => {
            Err(io::Error::new(io::ErrorKind::TimedOut, "session idle"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::wrap_records;
    use proptest::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn cipher(seed: u8) -> Box<AesCtr> {
        Box::new(AesCtr::new(&[seed; 32], &[seed.wrapping_mul(3); 16]))
    }

    fn no_ciphers() -> Ciphers {
        Ciphers {
            client_dec: cipher(1),
            upstream_enc: None,
            upstream_dec: None,
            client_enc: None,
        }
    }

    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (near, far) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (near.unwrap(), far.unwrap().0)
    }

    /// The test's client and DC ends, and the proxy's two sockets.
    struct Wiring {
        client: TcpStream,
        upstream: TcpStream,
        proxy_client: TcpStream,
        proxy_upstream: TcpStream,
    }

    async fn wiring() -> Wiring {
        let (client, proxy_client) = socket_pair().await;
        let (upstream, proxy_upstream) = socket_pair().await;
        Wiring {
            client,
            upstream,
            proxy_client,
            proxy_upstream,
        }
    }

    fn spawn_relay(
        proxy_client: TcpStream,
        proxy_upstream: TcpStream,
        ciphers: Ciphers,
        idle: Option<Duration>,
    ) -> tokio::task::JoinHandle<io::Result<()>> {
        tokio::spawn(async move {
            relay(
                &proxy_client,
                &proxy_upstream,
                RecordReader::new(),
                ciphers,
                idle,
            )
            .await
        })
    }

    /// Feeds `to_upstream` (client side, in the given chunk sizes) and
    /// `to_client` (upstream side) through a relay and returns what each end
    /// received, with the client's bytes unwrapped from their records.
    async fn run_relay(
        to_upstream: Vec<u8>,
        to_client: Vec<u8>,
        chunks: Vec<usize>,
        ciphers: Ciphers,
    ) -> (Vec<u8>, Vec<u8>) {
        let w = wiring().await;
        let relay_task = spawn_relay(w.proxy_client, w.proxy_upstream, ciphers, None);
        let (mut client_read, mut client_write) = w.client.into_split();
        let (mut upstream_read, mut upstream_write) = w.upstream.into_split();
        let expect_upstream = to_upstream.len();
        let expect_client = to_client.len();

        let client_writer = tokio::spawn(async move {
            let mut framed = Vec::new();
            wrap_records(&to_upstream, &mut framed);
            let mut sizes = chunks.iter().cycle();
            let mut pos = 0;
            while pos < framed.len() {
                let n = (*sizes.next().unwrap()).clamp(1, framed.len() - pos);
                client_write.write_all(&framed[pos..pos + n]).await.unwrap();
                tokio::task::yield_now().await;
                pos += n;
            }
            client_write
        });
        let upstream_writer = tokio::spawn(async move {
            upstream_write.write_all(&to_client).await.unwrap();
            upstream_write
        });

        let upstream_reader = tokio::spawn(async move {
            let mut got = vec![0u8; expect_upstream];
            upstream_read.read_exact(&mut got).await.unwrap();
            (got, upstream_read)
        });

        let mut got_client = Vec::new();
        let mut reader = RecordReader::new();
        let mut buf = vec![0u8; 8192];
        while got_client.len() < expect_client {
            let n = client_read.read(&mut buf).await.unwrap();
            assert_ne!(n, 0, "relay closed early");
            let m = reader.unwrap_in_place(&mut buf, n).unwrap();
            got_client.extend_from_slice(&buf[..m]);
        }
        let (got_upstream, upstream_read) = upstream_reader.await.unwrap();

        drop(client_writer.await.unwrap());
        drop(upstream_writer.await.unwrap());
        drop((client_read, upstream_read));
        let _ = relay_task.await.unwrap();
        (got_upstream, got_client)
    }

    #[tokio::test]
    async fn plain_mode_decrypts_up_and_encrypts_down() {
        let up_plain = b"request bytes".to_vec();
        let down_plain = b"response bytes".to_vec();
        let mut up_wire = up_plain.clone();
        cipher(1).apply(&mut up_wire);

        let (got_up, mut got_down) = run_relay(
            up_wire,
            down_plain.clone(),
            vec![3],
            Ciphers {
                client_dec: cipher(1),
                upstream_enc: None,
                upstream_dec: None,
                client_enc: Some(cipher(2)),
            },
        )
        .await;
        assert_eq!(got_up, up_plain);
        cipher(2).apply(&mut got_down);
        assert_eq!(got_down, down_plain);
    }

    #[tokio::test]
    async fn obfuscated_mode_recrypts_both_directions() {
        let up_plain = vec![0x11u8; 5000];
        let down_plain = vec![0x22u8; 40_000];
        let mut up_wire = up_plain.clone();
        cipher(1).apply(&mut up_wire);
        let mut down_wire = down_plain.clone();
        cipher(4).apply(&mut down_wire);

        let (mut got_up, mut got_down) = run_relay(
            up_wire,
            down_wire,
            vec![1000, 1],
            Ciphers {
                client_dec: cipher(1),
                upstream_enc: Some(cipher(3)),
                upstream_dec: Some(cipher(4)),
                client_enc: Some(cipher(2)),
            },
        )
        .await;
        cipher(3).apply(&mut got_up);
        assert_eq!(got_up, up_plain);
        cipher(2).apply(&mut got_down);
        assert_eq!(got_down, down_plain);
    }

    #[tokio::test]
    async fn fast_mode_passes_downstream_bytes_through() {
        let down_wire = vec![0x5au8; 20_000];
        let (_, got_down) = run_relay(
            Vec::new(),
            down_wire.clone(),
            vec![1],
            Ciphers {
                client_dec: cipher(1),
                upstream_enc: Some(cipher(3)),
                upstream_dec: None,
                client_enc: None,
            },
        )
        .await;
        assert_eq!(got_down, down_wire);
    }

    /// Reads one record from `client` and returns its payload length.
    async fn next_record_len(client: &mut TcpStream) -> usize {
        let mut header = [0u8; RECORD_HEADER_LEN];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[..3], [0x17, 0x03, 0x03]);
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut payload = vec![0u8; len];
        client.read_exact(&mut payload).await.unwrap();
        len
    }

    #[tokio::test]
    async fn queued_upstream_data_is_coalesced_into_full_records() {
        let mut w = wiring().await;
        // Three small segments are already waiting when the relay first looks.
        for chunk in [&b"aaaa"[..], b"bbbbbbbb", b"cc"] {
            w.upstream.write_all(chunk).await.unwrap();
            w.upstream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let task = spawn_relay(w.proxy_client, w.proxy_upstream, no_ciphers(), None);
        assert_eq!(next_record_len(&mut w.client).await, 14);

        // A backlog larger than a record leaves as full 16 KiB records.
        task.abort();
        let mut w = wiring().await;
        w.upstream.write_all(&vec![7u8; 40_000]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _task = spawn_relay(w.proxy_client, w.proxy_upstream, no_ciphers(), None);
        assert_eq!(next_record_len(&mut w.client).await, MAX_RECORD_PAYLOAD);
        assert_eq!(next_record_len(&mut w.client).await, MAX_RECORD_PAYLOAD);
        assert_eq!(
            next_record_len(&mut w.client).await,
            40_000 - 2 * MAX_RECORD_PAYLOAD
        );
    }

    #[tokio::test]
    async fn slow_reader_applies_backpressure_without_losing_data() {
        let mut w = wiring().await;
        let _task = spawn_relay(w.proxy_client, w.proxy_upstream, no_ciphers(), None);
        // Far more than the socket buffers hold, while the client reads nothing.
        let data: Vec<u8> = (0..8_000_000u32).map(|i| (i % 251) as u8).collect();
        let expected = data.clone();
        let mut upstream = w.upstream;
        let writer = tokio::spawn(async move {
            upstream.write_all(&data).await.unwrap();
            upstream
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!writer.is_finished(), "relay buffered without bound");

        let mut got = Vec::with_capacity(expected.len());
        let mut reader = RecordReader::new();
        let mut buf = vec![0u8; 64 * 1024];
        while got.len() < expected.len() {
            let n = w.client.read(&mut buf).await.unwrap();
            assert_ne!(n, 0);
            let m = reader.unwrap_in_place(&mut buf, n).unwrap();
            got.extend_from_slice(&buf[..m]);
        }
        assert!(got == expected);
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn bad_record_from_client_ends_the_relay() {
        let mut w = wiring().await;
        w.client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let result = relay(
            &w.proxy_client,
            &w.proxy_upstream,
            RecordReader::new(),
            no_ciphers(),
            None,
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn closing_either_side_ends_the_relay() {
        for close_client in [true, false] {
            let w = wiring().await;
            let (keep, close) = if close_client {
                (w.upstream, w.client)
            } else {
                (w.client, w.upstream)
            };
            drop(close);
            let result = relay(
                &w.proxy_client,
                &w.proxy_upstream,
                RecordReader::new(),
                no_ciphers(),
                None,
            )
            .await;
            assert!(result.is_ok());
            drop(keep);
        }
    }

    #[tokio::test]
    async fn idle_session_is_closed_within_the_documented_bound() {
        const IDLE: Duration = Duration::from_millis(400);
        let w = wiring().await;
        let start = std::time::Instant::now();
        let result = relay(
            &w.proxy_client,
            &w.proxy_upstream,
            RecordReader::new(),
            no_ciphers(),
            Some(IDLE),
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        let elapsed = start.elapsed();
        // Upper bound is 5/4 of the timeout plus scheduling slack.
        assert!(
            elapsed >= IDLE && elapsed <= IDLE * 5 / 4 + IDLE / 2,
            "{elapsed:?}"
        );
    }

    #[tokio::test]
    async fn traffic_in_either_direction_keeps_the_session_open() {
        const IDLE: Duration = Duration::from_millis(400);
        for from_client in [true, false] {
            let mut w = wiring().await;
            let start = std::time::Instant::now();
            let task = spawn_relay(w.proxy_client, w.proxy_upstream, no_ciphers(), Some(IDLE));

            // One direction stays silent for several idle periods while the
            // other sends a byte every 3/4 of a period.
            let mut sink = [0u8; 16];
            for _ in 0..6 {
                tokio::time::sleep(IDLE * 3 / 4).await;
                assert!(!task.is_finished(), "closed while active");
                if from_client {
                    let mut framed = Vec::new();
                    wrap_records(b"x", &mut framed);
                    w.client.write_all(&framed).await.unwrap();
                    w.upstream.read_exact(&mut sink[..1]).await.unwrap();
                } else {
                    w.upstream.write_all(b"x").await.unwrap();
                    w.client.read_exact(&mut sink[..6]).await.unwrap();
                }
            }
            let last_byte = std::time::Instant::now();
            let result = task.await.unwrap();
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            let quiet = last_byte.elapsed();
            assert!(
                quiet >= IDLE * 9 / 10 && quiet <= IDLE * 5 / 4 + IDLE / 2,
                "{quiet:?}"
            );
            assert!(start.elapsed() > IDLE * 4);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_watch_bounds_hold_exactly_in_virtual_time() {
        const IDLE: Duration = Duration::from_secs(900);
        let activity = AtomicU64::new(0);

        // Never active: fires exactly at the timeout.
        let start = tokio::time::Instant::now();
        idle_watch(&activity, Some(IDLE)).await;
        assert_eq!(start.elapsed(), IDLE);

        // Activity just after a check is noticed one check later, which is the
        // worst case: 5/4 of the timeout after that activity.
        let start = tokio::time::Instant::now();
        let bump = async {
            tokio::time::sleep(IDLE / 4 + Duration::from_secs(1)).await;
            activity.fetch_add(1, Ordering::Relaxed);
            tokio::time::Instant::now()
        };
        let (bumped_at, ()) = tokio::join!(bump, idle_watch(&activity, Some(IDLE)));
        let after_activity = start.elapsed() - (bumped_at - start);
        assert!(
            after_activity >= IDLE && after_activity <= IDLE * 5 / 4,
            "{after_activity:?}"
        );

        // Disabled: never fires.
        let never = tokio::time::timeout(
            Duration::from_secs(365 * 86_400),
            idle_watch(&activity, None),
        );
        assert!(never.await.is_err());
    }

    #[tokio::test]
    async fn relay_state_is_small() {
        let w = wiring().await;
        let fut = relay(
            &w.proxy_client,
            &w.proxy_upstream,
            RecordReader::new(),
            no_ciphers(),
            Some(Duration::from_secs(900)),
        );
        let size = std::mem::size_of_val(&fut);
        // No buffers and no cipher state inline: pointers, a timer and the
        // readiness waiters of both sockets (about 1 KiB today).
        assert!(size <= 1280, "relay future is {size} bytes");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn relay_preserves_bytes_for_random_chunk_splits(
            up in proptest::collection::vec(any::<u8>(), 0..40_000),
            down in proptest::collection::vec(any::<u8>(), 0..40_000),
            chunks in proptest::collection::vec(1usize..9000, 1..6),
        ) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let mut up_wire = up.clone();
            cipher(1).apply(&mut up_wire);
            let (mut got_up, mut got_down) = runtime.block_on(run_relay(
                up_wire,
                down.clone(),
                chunks,
                Ciphers {
                    client_dec: cipher(1),
                    upstream_enc: Some(cipher(3)),
                    upstream_dec: None,
                    client_enc: Some(cipher(2)),
                },
            ));
            cipher(3).apply(&mut got_up);
            cipher(2).apply(&mut got_down);
            prop_assert_eq!(got_up, up);
            prop_assert_eq!(got_down, down);
        }
    }
}
