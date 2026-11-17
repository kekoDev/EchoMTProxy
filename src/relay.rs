use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cipher::{AesCtr, Ctr};
use crate::tls::{record_header, RecordReader, MAX_RECORD_PAYLOAD, RECORD_HEADER_LEN};

const BUF_LEN: usize = 16 * 1024;

/// Per-direction ciphers. `None` means that step is skipped for the upstream mode.
pub struct Ciphers {
    /// Removes the client's obfuscation.
    pub client_dec: AesCtr,
    /// Re-encrypts for the DC (obfuscated and fast modes).
    pub upstream_enc: Option<AesCtr>,
    /// Removes the DC's obfuscation (obfuscated mode).
    pub upstream_dec: Option<AesCtr>,
    /// Encrypts for the client (obfuscated and plain modes).
    pub client_enc: Option<AesCtr>,
}

async fn client_to_upstream<R, W>(
    mut client: R,
    mut upstream: W,
    mut records: RecordReader,
    mut dec: AesCtr,
    mut enc: Option<AesCtr>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF_LEN];
    loop {
        let n = client.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
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
        upstream.write_all(payload).await?;
    }
}

async fn upstream_to_client<R, W>(
    mut upstream: R,
    mut client: W,
    mut dec: Option<AesCtr>,
    mut enc: Option<AesCtr>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // The record header is written in front of the data so each read goes out
    // as a single record with a single write.
    let mut buf = vec![0u8; RECORD_HEADER_LEN + MAX_RECORD_PAYLOAD];
    loop {
        let n = upstream.read(&mut buf[RECORD_HEADER_LEN..]).await?;
        if n == 0 {
            return Ok(());
        }
        let payload = &mut buf[RECORD_HEADER_LEN..RECORD_HEADER_LEN + n];
        if let Some(dec) = dec.as_mut() {
            dec.apply(payload);
        }
        if let Some(enc) = enc.as_mut() {
            enc.apply(payload);
        }
        buf[..RECORD_HEADER_LEN].copy_from_slice(&record_header(n));
        client.write_all(&buf[..RECORD_HEADER_LEN + n]).await?;
    }
}

/// Relays until either side closes or fails. `records` carries the framing
/// state left over from the handshake.
pub async fn relay<CR, CW, UR, UW>(
    client_read: CR,
    client_write: CW,
    upstream_read: UR,
    upstream_write: UW,
    records: RecordReader,
    ciphers: Ciphers,
) -> io::Result<()>
where
    CR: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
    UR: AsyncRead + Unpin,
    UW: AsyncWrite + Unpin,
{
    tokio::select! {
        result = client_to_upstream(
            client_read,
            upstream_write,
            records,
            ciphers.client_dec,
            ciphers.upstream_enc,
        ) => result,
        result = upstream_to_client(
            upstream_read,
            client_write,
            ciphers.upstream_dec,
            ciphers.client_enc,
        ) => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::wrap_records;
    use proptest::prelude::*;

    fn cipher(seed: u8) -> AesCtr {
        AesCtr::new(&[seed; 32], &[seed.wrapping_mul(3); 16])
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
        let (client, proxy_client) = tokio::io::duplex(64 * 1024);
        let (upstream, proxy_upstream) = tokio::io::duplex(64 * 1024);
        let (pc_read, pc_write) = tokio::io::split(proxy_client);
        let (pu_read, pu_write) = tokio::io::split(proxy_upstream);
        let relay_task = tokio::spawn(relay(
            pc_read,
            pc_write,
            pu_read,
            pu_write,
            RecordReader::new(),
            ciphers,
        ));

        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
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
                client_write.flush().await.unwrap();
                tokio::task::yield_now().await;
                pos += n;
            }
            client_write
        });
        let upstream_writer = tokio::spawn(async move {
            upstream_write.write_all(&to_client).await.unwrap();
            upstream_write
        });

        let mut got_upstream = vec![0u8; expect_upstream];
        upstream_read.read_exact(&mut got_upstream).await.unwrap();

        let mut got_client = Vec::new();
        let mut reader = RecordReader::new();
        let mut buf = vec![0u8; 8192];
        while got_client.len() < expect_client {
            let n = client_read.read(&mut buf).await.unwrap();
            assert_ne!(n, 0, "relay closed early");
            let m = reader.unwrap_in_place(&mut buf, n).unwrap();
            got_client.extend_from_slice(&buf[..m]);
        }

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

    #[tokio::test]
    async fn bad_record_from_client_ends_the_relay() {
        let (mut client, proxy_client) = tokio::io::duplex(1024);
        let (_upstream, proxy_upstream) = tokio::io::duplex(1024);
        let (pc_read, pc_write) = tokio::io::split(proxy_client);
        let (pu_read, pu_write) = tokio::io::split(proxy_upstream);
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let result = relay(
            pc_read,
            pc_write,
            pu_read,
            pu_write,
            RecordReader::new(),
            Ciphers {
                client_dec: cipher(1),
                upstream_enc: None,
                upstream_dec: None,
                client_enc: None,
            },
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn closing_either_side_ends_the_relay() {
        for close_client in [true, false] {
            let (client, proxy_client) = tokio::io::duplex(1024);
            let (upstream, proxy_upstream) = tokio::io::duplex(1024);
            let (pc_read, pc_write) = tokio::io::split(proxy_client);
            let (pu_read, pu_write) = tokio::io::split(proxy_upstream);
            let (keep, close) = if close_client {
                (upstream, client)
            } else {
                (client, upstream)
            };
            drop(close);
            let result = relay(
                pc_read,
                pc_write,
                pu_read,
                pu_write,
                RecordReader::new(),
                Ciphers {
                    client_dec: cipher(1),
                    upstream_enc: None,
                    upstream_dec: None,
                    client_enc: None,
                },
            )
            .await;
            assert!(result.is_ok());
            drop(keep);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn relay_preserves_bytes_for_random_chunk_splits(
            up in proptest::collection::vec(any::<u8>(), 0..40_000),
            down in proptest::collection::vec(any::<u8>(), 0..40_000),
            chunks in proptest::collection::vec(1usize..9000, 1..6),
        ) {
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
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
