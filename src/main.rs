use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
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

fn bind(addr: SocketAddr, reuse_port: bool) -> std::io::Result<std::net::TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if reuse_port {
        // Several sockets on one address: the kernel spreads new connections
        // over them, each with its own accept queue.
        #[cfg(unix)]
        socket.set_reuse_port(true)?;
    }
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

/// The CPU for the `index`th runtime thread, or `None` to leave it unpinned.
///
/// The runtime starts its `workers` worker threads first; threads started
/// later belong to the blocking pool (DNS lookups) and must stay free to run
/// anywhere.
fn cpu_for_thread(index: usize, workers: usize, cpus: usize) -> Option<usize> {
    (index < workers && cpus > 0).then(|| index % cpus)
}

fn pin_worker_threads(runtime: &mut tokio::runtime::Builder, workers: usize) {
    let Some(cpus) = core_affinity::get_core_ids().filter(|ids| !ids.is_empty()) else {
        tracing::warn!("pin_workers is set but the CPU list is unavailable; not pinning");
        return;
    };
    if workers > cpus.len() {
        tracing::warn!(
            workers,
            cpus = cpus.len(),
            "pin_workers: more workers than CPUs, some CPUs get several workers"
        );
    }
    let started = AtomicUsize::new(0);
    runtime.on_thread_start(move || {
        let index = started.fetch_add(1, Ordering::Relaxed);
        if let Some(slot) = cpu_for_thread(index, workers, cpus.len()) {
            let cpu = cpus[slot];
            if core_affinity::set_for_current(cpu) {
                tracing::debug!(worker = index, cpu = cpu.id, "worker pinned");
            } else {
                tracing::warn!(worker = index, cpu = cpu.id, "could not pin worker");
            }
        }
    });
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
    runtime.enable_all().worker_threads(workers);
    if config.pin_workers {
        pin_worker_threads(&mut runtime, workers);
    }
    let runtime = runtime.build().context("starting the tokio runtime")?;

    runtime.block_on(async {
        let sockets_per_address = if config.reuse_port { workers } else { 1 };
        for addr in &config.listen {
            for _ in 0..sockets_per_address {
                let listener =
                    bind(*addr, config.reuse_port).with_context(|| format!("binding {addr}"))?;
                let listener = tokio::net::TcpListener::from_std(listener)
                    .with_context(|| format!("registering {addr}"))?;
                tokio::spawn(server::serve(listener, proxy.clone()));
            }
            tracing::info!(%addr, sockets = sockets_per_address, "listening");
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
            pinned = config.pin_workers,
            "proxy started"
        );
        shutdown_signal().await;
        tracing::info!("shutting down");
        anyhow::Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::cpu_for_thread;

    #[test]
    fn workers_are_spread_over_cpus_in_order() {
        let plan: Vec<_> = (0..4).map(|i| cpu_for_thread(i, 4, 8)).collect();
        assert_eq!(plan, [Some(0), Some(1), Some(2), Some(3)]);
    }

    #[test]
    fn extra_workers_wrap_around() {
        let plan: Vec<_> = (0..5).map(|i| cpu_for_thread(i, 5, 2)).collect();
        assert_eq!(plan, [Some(0), Some(1), Some(0), Some(1), Some(0)]);
    }

    #[test]
    fn blocking_pool_threads_are_not_pinned() {
        assert_eq!(cpu_for_thread(4, 4, 8), None);
        assert_eq!(cpu_for_thread(100, 4, 8), None);
        assert_eq!(cpu_for_thread(0, 4, 0), None);
    }
}
