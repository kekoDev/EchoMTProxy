use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use echo_loadgen::client::{self, ClientConfig, Mode};
use echo_loadgen::dc::{self, Dc};
use echo_loadgen::stats::ClientStats;
use echo_mtproxy::config::Secret;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// Load generator for echo-mtproxy.
///
/// Run `dc` where the proxy can reach it and point the proxy's [dc_override]
/// (all five DCs) at it. Then run `client` against the proxy. The client
/// stops at its first session if the far end is not the fake DC.
#[derive(Parser)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fake Telegram DC for the proxy's upstream side.
    Dc {
        /// Address to listen on; repeat for several.
        #[arg(long, required = true)]
        listen: Vec<SocketAddr>,
        /// Seconds between progress lines.
        #[arg(long, default_value_t = 5)]
        report_secs: u64,
    },
    /// Fake Telegram clients.
    Client(ClientArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    Echo,
    Download,
    Upload,
}

#[derive(Parser)]
struct ClientArgs {
    /// Proxy address; repeat to spread sessions over several addresses or ports.
    #[arg(long, required = true)]
    target: Vec<SocketAddr>,
    /// The proxy's ee secret.
    #[arg(long)]
    secret: String,
    /// SNI to send. Default: the domain in the secret.
    #[arg(long)]
    sni: Option<String>,
    /// Local source address; repeat for several. Each (source, target) pair
    /// has its own range of local ports.
    #[arg(long)]
    bind: Vec<IpAddr>,
    /// Sessions to open in total.
    #[arg(long, default_value_t = 1000)]
    connections: usize,
    /// How many of them move data; the rest stay idle.
    #[arg(long, default_value_t = 0)]
    active: usize,
    /// What active sessions do.
    #[arg(long, value_enum, default_value_t = ModeArg::Echo)]
    mode: ModeArg,
    /// Bytes per echo, download request or upload write.
    #[arg(long, default_value_t = 16384)]
    payload: usize,
    /// Milliseconds an active session waits between requests.
    #[arg(long, default_value_t = 0)]
    interval_ms: u64,
    /// New sessions per second; 0 = as fast as --concurrency allows.
    #[arg(long, default_value_t = 0.0)]
    rate: f64,
    /// Handshakes in flight at once.
    #[arg(long, default_value_t = 512)]
    concurrency: usize,
    /// Share of sessions (0 to 1) on the media lane.
    #[arg(long, default_value_t = 0.0)]
    media_share: f64,
    /// Seconds to keep the sessions after the ramp-up.
    #[arg(long, default_value_t = 60)]
    hold_secs: u64,
    /// Seconds allowed for one session's handshake.
    #[arg(long, default_value_t = 20)]
    handshake_timeout_secs: u64,
    /// Seconds between progress lines.
    #[arg(long, default_value_t = 5)]
    report_secs: u64,
    /// Skip the byte-for-byte check of echoed data.
    #[arg(long)]
    no_verify: bool,
}

/// Raises the open-file limit as far as the system allows and returns it.
fn raise_fd_limit() -> u64 {
    rlimit::increase_nofile_limit(u64::MAX).unwrap_or(0)
}

async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

async fn run_dc(listen: Vec<SocketAddr>, report_secs: u64) -> anyhow::Result<()> {
    let dc = Arc::new(Dc::default());
    for addr in &listen {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding {addr}"))?;
        tokio::spawn(dc::serve(listener, dc.clone()));
        println!("fake DC listening on {addr}");
    }
    tokio::spawn(dc::sweep_forever(dc.clone()));
    let started = Instant::now();
    let report = async {
        let mut ticker = tokio::time::interval(Duration::from_secs(report_secs.max(1)));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            println!("{}", dc.stats.report_line(started.elapsed()));
        }
    };
    tokio::select! {
        () = report => {}
        () = stop_signal() => {}
    }
    println!("{}", dc.stats.report_line(started.elapsed()));
    Ok(())
}

async fn run_client(args: ClientArgs, fd_limit: u64) -> anyhow::Result<()> {
    let secret = Secret::parse(&args.secret).context("--secret")?;
    let config = ClientConfig {
        sni: args.sni.unwrap_or_else(|| secret.domain.clone()),
        targets: args.target,
        bind: args.bind,
        secret,
        connections: args.connections,
        active: args.active,
        mode: match args.mode {
            ModeArg::Echo => Mode::Echo,
            ModeArg::Download => Mode::Download,
            ModeArg::Upload => Mode::Upload,
        },
        payload: args.payload,
        interval: Duration::from_millis(args.interval_ms),
        rate: args.rate,
        concurrency: args.concurrency,
        media_share: args.media_share,
        handshake_timeout: Duration::from_secs(args.handshake_timeout_secs),
        hold: Duration::from_secs(args.hold_secs),
        verify: !args.no_verify,
    };
    config.validate()?;
    let needed = config.connections as u64 + 256;
    anyhow::ensure!(
        fd_limit >= needed,
        "{} sessions need {needed} file descriptors but the limit is {fd_limit}; \
         raise `ulimit -n` (and fs.nr_open) or lower --connections",
        config.connections
    );
    if let Some(warning) = config.port_pressure_warning() {
        eprintln!("warning: {warning}");
    }
    println!(
        "{} sessions ({} active, {} idle) to {} target(s) from {} source address(es)",
        config.connections,
        config.active,
        config.connections - config.active,
        config.targets.len(),
        config.bind.len().max(1)
    );

    let stats = Arc::new(ClientStats::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let started = Instant::now();
    let report_every = Duration::from_secs(args.report_secs.max(1));
    let reporter = {
        let stats = stats.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(report_every);
            ticker.tick().await;
            let mut previous = stats.snapshot();
            loop {
                ticker.tick().await;
                println!(
                    "{}",
                    stats.report_line(started.elapsed(), report_every, &previous)
                );
                previous = stats.snapshot();
            }
        })
    };
    tokio::spawn(async move {
        stop_signal().await;
        let _ = stop_tx.send(true);
    });

    let result = client::run(config, stats.clone(), stop_rx).await;
    reporter.abort();
    println!("{}", stats.summary(started.elapsed()));
    result
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let fd_limit = raise_fd_limit();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the tokio runtime")?;
    runtime.block_on(async {
        match args.command {
            Command::Dc {
                listen,
                report_secs,
            } => run_dc(listen, report_secs).await,
            Command::Client(client) => run_client(client, fd_limit).await,
        }
    })
}
