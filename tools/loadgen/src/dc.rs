//! A stand-in for a Telegram DC. It speaks the upstream side of the proxy's
//! handshake (obfuscated2 or the plain transport tag) and then does what the
//! client's header asks: stay idle, echo, send data, or swallow data.

use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use echo_mtproxy::cipher::{AesCtr, Ctr};
use echo_mtproxy::pool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::proto::{self, Op, ACK, HEADER_LEN, REQUEST_LEN};
use crate::stats::DcStats;

const TAG_SECURE: [u8; 4] = [0xdd; 4];
const INIT_LEN: usize = 64;
/// How long a connection may take to send its handshake and header.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// How often idle connections are checked for having been closed.
const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// Shared by all listeners of one fake DC.
#[derive(Default)]
pub struct Dc {
    pub stats: DcStats,
    /// Idle connections. They need no task and no cipher state, only an open
    /// socket, so they are kept here and checked now and then.
    parked: Mutex<Vec<TcpStream>>,
}

/// Stream ciphers of one connection; `None` for the plain transport.
struct Ciphers(Option<(AesCtr, AesCtr)>);

impl Ciphers {
    fn decrypt(&mut self, buf: &mut [u8]) {
        if let Some((dec, _)) = self.0.as_mut() {
            dec.apply(buf);
        }
    }

    fn encrypt(&mut self, buf: &mut [u8]) {
        if let Some((_, enc)) = self.0.as_mut() {
            enc.apply(buf);
        }
    }
}

/// Reads what the proxy sends first and sets up the ciphers a real DC would
/// derive from it.
async fn upstream_handshake(stream: &mut TcpStream) -> io::Result<Option<Ciphers>> {
    let mut init = [0u8; INIT_LEN];
    stream.read_exact(&mut init[..4]).await?;
    if init[..4] == TAG_SECURE {
        return Ok(Some(Ciphers(None)));
    }
    stream.read_exact(&mut init[4..]).await?;
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&init[8..40]);
    iv.copy_from_slice(&init[40..56]);
    let mut dec = AesCtr::new(&key, &iv);
    let mut reversed = [0u8; 48];
    reversed.copy_from_slice(&init[8..56]);
    reversed.reverse();
    key.copy_from_slice(&reversed[..32]);
    iv.copy_from_slice(&reversed[32..]);
    let enc = AesCtr::new(&key, &iv);
    dec.apply(&mut init);
    if init[56..60] != TAG_SECURE {
        return Ok(None);
    }
    Ok(Some(Ciphers(Some((dec, enc)))))
}

async fn echo(mut stream: TcpStream, mut ciphers: Ciphers, dc: &Dc) -> io::Result<()> {
    loop {
        let mut buf = pool::take();
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        ciphers.decrypt(&mut buf[..n]);
        ciphers.encrypt(&mut buf[..n]);
        stream.write_all(&buf[..n]).await?;
        dc.stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
        dc.stats.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
    }
}

async fn download(mut stream: TcpStream, mut ciphers: Ciphers, dc: &Dc) -> io::Result<()> {
    loop {
        let mut request = [0u8; REQUEST_LEN];
        match stream.read_exact(&mut request).await {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        }
        ciphers.decrypt(&mut request);
        dc.stats
            .bytes_in
            .fetch_add(REQUEST_LEN as u64, Ordering::Relaxed);
        let mut left = u64::from_le_bytes(request);
        while left > 0 {
            let mut buf = pool::take();
            let n = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
            buf[..n].fill(0);
            ciphers.encrypt(&mut buf[..n]);
            stream.write_all(&buf[..n]).await?;
            dc.stats.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
            left -= n as u64;
        }
    }
}

async fn upload(mut stream: TcpStream, dc: &Dc) -> io::Result<()> {
    loop {
        let mut buf = pool::take();
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        dc.stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
    }
}

async fn session(mut stream: TcpStream, dc: Arc<Dc>) {
    let _ = stream.set_nodelay(true);
    let opening = async {
        let Some(mut ciphers) = upstream_handshake(&mut stream).await? else {
            return Ok(None);
        };
        let mut header = [0u8; HEADER_LEN];
        stream.read_exact(&mut header).await?;
        ciphers.decrypt(&mut header);
        io::Result::Ok(Some((ciphers, header)))
    };
    let (mut ciphers, header) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, opening).await {
        Ok(Ok(Some(opened))) => opened,
        _ => {
            dc.stats.bad_handshake.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let Some(op) = proto::parse_header(&header) else {
        // Not one of our clients. Say nothing and hang up.
        dc.stats.not_loadgen.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let mut ack = ACK;
    ciphers.encrypt(&mut ack);
    if stream.write_all(&ack).await.is_err() {
        return;
    }
    dc.stats.sessions.fetch_add(1, Ordering::Relaxed);

    let _ = match op {
        Op::Idle => {
            drop(ciphers);
            dc.stats.parked.fetch_add(1, Ordering::Relaxed);
            dc.parked
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(stream);
            Ok(())
        }
        Op::Echo => echo(stream, ciphers, &dc).await,
        Op::Download => download(stream, ciphers, &dc).await,
        Op::Upload => upload(stream, &dc).await,
    };
}

/// Accepts proxy connections forever.
pub async fn serve(listener: TcpListener, dc: Arc<Dc>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                dc.stats.accepted.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(session(stream, dc.clone()));
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

/// True if the peer has closed or reset the connection.
pub fn is_closed(stream: &TcpStream) -> bool {
    let mut probe = [0u8; 64];
    match stream.try_read(&mut probe) {
        Ok(0) => true,
        Ok(_) => false,
        Err(err) => err.kind() != io::ErrorKind::WouldBlock,
    }
}

impl Dc {
    /// Drops idle connections the proxy has closed. Returns how many.
    pub fn sweep(&self) -> usize {
        let mut parked = self.parked.lock().unwrap_or_else(|e| e.into_inner());
        let before = parked.len();
        parked.retain(|stream| !is_closed(stream));
        let closed = before - parked.len();
        self.stats
            .parked
            .fetch_sub(closed as u64, Ordering::Relaxed);
        closed
    }
}

/// Sweeps idle connections forever.
pub async fn sweep_forever(dc: Arc<Dc>) {
    loop {
        tokio::time::sleep(SWEEP_INTERVAL).await;
        dc.sweep();
    }
}
