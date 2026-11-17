use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};

use echo_mtproxy::config::{Config, Secret};
use echo_mtproxy::server::{self, Proxy};

const LISTEN_BACKLOG: i32 = 4096;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Print a new fake-tls secret for DOMAIN with its tg:// link, then exit.
    #[arg(long, value_name = "DOMAIN")]
    gen_secret: Option<String>,

    /// Server address to put in the generated link.
    #[arg(
        long,
        value_name = "HOST",
        default_value = "YOUR_SERVER",
        requires = "gen_secret"
    )]
    server: String,

    /// Port to put in the generated link.
    #[arg(long, default_value_t = 443, requires = "gen_secret")]
    port: u16,
}

fn bind(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        // Otherwise [::]:443 also claims IPv4 and 0.0.0.0:443 fails to bind.
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(LISTEN_BACKLOG)?;
    Ok(socket.into())
}

async fn shutdown_signal() {
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

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(domain) = args.gen_secret {
        let secret = Secret::generate(&domain)?;
        println!("secret: {}", secret.to_hex());
        println!("link:   {}", secret.tg_link(&args.server, args.port));
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::load(&args.config)?;
    let proxy = Arc::new(Proxy::from_config(&config)?);

    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.enable_all();
    if config.workers > 0 {
        runtime.worker_threads(config.workers);
    }
    let runtime = runtime.build().context("starting the tokio runtime")?;

    runtime.block_on(async {
        for addr in &config.listen {
            let listener = bind(*addr).with_context(|| format!("binding {addr}"))?;
            let listener = tokio::net::TcpListener::from_std(listener)
                .with_context(|| format!("registering {addr}"))?;
            tracing::info!(%addr, "listening");
            tokio::spawn(server::serve(listener, proxy.clone()));
        }
        tracing::info!(
            secrets = config.secrets.len(),
            upstream_mode = ?config.upstream_mode,
            "proxy started"
        );
        shutdown_signal().await;
        tracing::info!("shutting down");
        anyhow::Ok(())
    })
}
