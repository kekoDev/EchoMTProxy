//! The debug log line written when a session ends.
//!
//! Alone in its own test binary: log capture hooks into tracing's
//! process-wide callsite cache, which other tests running in parallel disturb.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use tokio::net::TcpListener;

/// Collects log output of the current thread.
#[derive(Clone, Default)]
struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogCapture {
    fn install(&self) -> tracing::subscriber::DefaultGuard {
        let writer = self.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::set_default(subscriber)
    }

    fn lines_with(&self, needle: &str) -> Vec<String> {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .lines()
            .filter(|l| l.contains(needle))
            .map(str::to_owned)
            .collect()
    }

    async fn wait_for(&self, needle: &str, count: usize) -> Vec<String> {
        for _ in 0..300 {
            let lines = self.lines_with(needle);
            if lines.len() >= count {
                return lines;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("log never showed {count} lines with {needle:?}");
    }
}

fn field(line: &str, name: &str) -> String {
    let start = line
        .find(&format!("{name}="))
        .unwrap_or_else(|| panic!("no {name} in {line}"))
        + name.len()
        + 1;
    line[start..]
        .split_whitespace()
        .next()
        .unwrap()
        .trim_matches('"')
        .to_owned()
}

// Current-thread runtime: the proxy's tasks log on this thread, where the
// capture is installed.
#[tokio::test]
async fn session_end_is_logged_with_closer_bytes_duration_and_lane() {
    let logs = LogCapture::default();
    let _guard = logs.install();

    // A DC that echoes and can be told to hang up.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dc = listener.local_addr().unwrap();
    let (hang_up, hang_up_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut hang_up = hang_up_rx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = echo_dc_session(stream, true) => {}
                    _ = hang_up.wait_for(|now| *now) => {}
                }
            });
        }
    });
    let proxy = spawn_proxy_with("fast", dc, "idle_timeout_secs = 1").await;

    // 1. Chat session closed by the client after 3000 bytes each way.
    let mut client = Client::connect(proxy, DC).await;
    let data = random_bytes(3000);
    assert!(client.echo(&data).await == data);
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(client);
    let line = logs.wait_for("session ended", 1).await.remove(0);
    assert_eq!(field(&line, "closed_by"), "client", "{line}");
    assert_eq!(field(&line, "lane"), "chat", "{line}");
    assert_eq!(field(&line, "bytes_up"), "3000", "{line}");
    // Downstream includes at least one 5-byte record header.
    let down: u64 = field(&line, "bytes_down").parse().unwrap();
    assert!((3005..3100).contains(&down), "{line}");
    let duration: u64 = field(&line, "duration_ms").parse().unwrap();
    assert!((40..5000).contains(&duration), "{line}");

    // 2. Media session that goes idle.
    let mut media = Client::connect(proxy, -DC).await;
    assert_eq!(media.echo(b"x").await, b"x");
    let line = logs.wait_for("session ended", 2).await.remove(1);
    assert_eq!(field(&line, "closed_by"), "idle", "{line}");
    assert_eq!(field(&line, "lane"), "media", "{line}");
    assert_eq!(field(&line, "bytes_up"), "1", "{line}");
    let duration: u64 = field(&line, "duration_ms").parse().unwrap();
    assert!(duration >= 1000, "{line}");

    // 3. Session closed by the DC.
    let mut client = Client::connect(proxy, DC).await;
    assert_eq!(client.echo(b"hello").await, b"hello");
    hang_up.send(true).unwrap();
    let line = logs.wait_for("session ended", 3).await.remove(2);
    assert_eq!(field(&line, "closed_by"), "dc", "{line}");
    assert_eq!(field(&line, "bytes_up"), "5", "{line}");

    // No client or server address appears in any of these lines.
    for line in logs.lines_with("session ended") {
        assert!(line.contains("DEBUG"), "{line}");
        assert!(!line.contains("127.0.0.1"), "{line}");
        assert!(!line.contains(&proxy.port().to_string()), "{line}");
    }
}
