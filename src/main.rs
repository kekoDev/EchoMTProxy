use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};

use echo_mtproxy::config::{links_for_domains, Config, Secret};
use echo_mtproxy::server::{self, Proxy};
use echo_mtproxy::stats;

const LISTEN_BACKLOG: i32 = 4096;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Print a new fake-tls secret with its tg:// link, then exit. With a
    /// DOMAIN, one link for that domain. Without one, one link per domain in
    /// the config's `mask_domains`, all sharing the new key.
    #[arg(long, value_name = "DOMAIN", num_args = 0..=1, default_missing_value = "")]
    gen_secret: Option<String>,

    /// Print tg:// links for the secrets already in the config, one per
    /// `mask_domains` entry, then exit.
    #[arg(long, conflicts_with = "gen_secret")]
    print_links: bool,

    /// Server address to put in generated links.
    #[arg(long, value_name = "HOST", default_value = "YOUR_SERVER")]
    server: String,

    /// Port to put in generated links.
    #[arg(long, default_value_t = 443)]
    port: u16,
}

fn print_links(links: &[(String, String)]) {
    let width = links.iter().map(|(d, _)| d.len()).max().unwrap_or(0);
    for (domain, link) in links {
        println!("{domain:width$}  {link}");
    }
}

fn allowlisted_domains(config: &Config) -> anyhow::Result<Vec<String>> {
    let domains: Vec<String> = config
        .parsed_mask_domains()?
        .into_iter()
        .map(|d| d.domain)
        .collect();
    anyhow::ensure!(
        !domains.is_empty(),
        "`mask_domains` is empty; list the domains in the config or pass --gen-secret DOMAIN"
    );
    Ok(domains)
}

fn generate(args: &Args, domain: &str) -> anyhow::Result<()> {
    if !domain.is_empty() {
        let secret = Secret::generate(domain)?;
        println!("secret: {}", secret.to_hex());
        println!("link:   {}", secret.tg_link(&args.server, args.port));
        return Ok(());
    }
    let config = Config::load(&args.config)?;
    let domains = allowlisted_domains(&config)?;
    let secret = Secret::generate(&domains[0])?;
    println!("secret: {}", secret.to_hex());
    print_links(&links_for_domains(
        &secret,
        domains.iter().map(String::as_str),
        &args.server,
        args.port,
    )?);
    Ok(())
}

fn print_existing(args: &Args) -> anyhow::Result<()> {
    let config = Config::load(&args.config)?;
    let domains = allowlisted_domains(&config)?;
    for (index, secret) in config.parsed_secrets()?.iter().enumerate() {
        println!("secrets[{index}]:");
        print_links(&links_for_domains(
            secret,
            domains.iter().map(String::as_str),
            &args.server,
            args.port,
        )?);
    }
    Ok(())
}

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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

    if let Some(domain) = &args.gen_secret {
        return generate(&args, domain);
    }
    if args.print_links {
        return print_existing(&args);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::load(&args.config)?;
    let proxy = Arc::new(Proxy::from_config(&config)?);

    let workers = if config.workers > 0 {
        config.workers
    } else {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    };
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    // Workers are not pinned to CPUs: pinning was measured on the target
    // server and did not help.
    runtime.enable_all().worker_threads(workers);
    let runtime = runtime.build().context("starting the tokio runtime")?;

    runtime.block_on(async {
        // One listener per address. Per-worker SO_REUSEPORT listeners were
        // measured on the target server and did not raise the accept rate.
        for addr in &config.listen {
            let listener = bind(*addr).with_context(|| format!("binding {addr}"))?;
            let listener = tokio::net::TcpListener::from_std(listener)
                .with_context(|| format!("registering {addr}"))?;
            tracing::info!(%addr, "listening");
            tokio::spawn(server::serve(listener, proxy.clone()));
        }
        tokio::spawn(server::run_congestion_control(proxy.stats().clone()));
        if let Some(middle) = proxy.middle() {
            tokio::spawn(echo_mtproxy::middle::run_reload(middle.clone()));
        }
        if let Some(addr) = config.metrics_addr() {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding metrics listener {addr}"))?;
            tracing::info!(%addr, "serving /metrics");
            tokio::spawn(stats::serve_metrics(listener, proxy.stats().clone()));
        }
        tracing::info!(
            secrets = config.secrets.len(),
            upstream_mode = ?config.upstream_mode,
            workers,
            "proxy started"
        );
        shutdown_signal().await;
        tracing::info!("shutting down");
        anyhow::Ok(())
    })
}
