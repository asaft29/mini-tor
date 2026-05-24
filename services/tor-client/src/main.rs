use anyhow::{Context, Result};
use clap::Parser;
use common::crypto::TorNtorHandshaker;
use std::sync::Arc;
use tokio::sync::Mutex;
use tor_client::client::DirectoryClient;
use tor_client::core::circuit::{
    CircuitPool, spawn_circuit_keepalive, spawn_circuit_monitor, spawn_circuit_reader,
};
use tor_client::core::config::{MAX_HOPS, TorClientConfig};
use tor_client::core::metrics::ClientMetrics;
use tor_client::core::transport::TcpTlsTransport;
use tracing::{error, info};
use tracing_subscriber::fmt::writer::MakeWriterExt;

#[tokio::main]
async fn main() -> Result<()> {
    let mut config = TorClientConfig::parse();

    if config.tui {
        config = tor_client::wizard::run_wizard(&config)?;
    } else if config.hops == MAX_HOPS {
        eprintln!(
            "You requested a {MAX_HOPS}-hop circuit (the maximum).\n  \
             This requires {MAX_HOPS} relay nodes and adds significant latency.\n  \
             Proceed? [y/N]"
        );
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .context("Failed to read confirmation")?;
        let confirmed =
            input.trim().eq_ignore_ascii_case("y") || input.trim().eq_ignore_ascii_case("yes");
        if !confirmed {
            eprintln!("Aborted. Use --hops <3-9> for a smaller circuit.");
            std::process::exit(0);
        }
    }

    if config.tui {
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/tor-client.log")
            .context("Failed to open log file")?;
        tracing_subscriber::fmt()
            .with_writer(std::io::sink.and(log_file))
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "tor_client=info".into()),
            )
            .init();
    } else {
        tracing_subscriber::fmt::init();
    }

    info!(
        "Starting Tor client: socks_addr={}, directory_url={}, pool_size={}, hops={}",
        config.socks_addr, config.directory_url, config.pool_size, config.hops
    );

    let metrics = ClientMetrics::new();

    let directory_client = Arc::new(DirectoryClient::new(config.directory_url.clone()).await?);
    let transport = Arc::new(TcpTlsTransport);
    let handshaker = Arc::new(TorNtorHandshaker);
    let mut pool = CircuitPool::new(
        directory_client,
        transport,
        handshaker,
        config.pool_size,
        config.hops,
        config.max_rebuild_attempts,
    );
    pool.set_metrics(Arc::clone(&metrics));

    let built_circuits = match pool.initialize().await {
        Ok(circuits) => circuits,
        Err(e) => {
            error!(
                "Circuit pool initialization failed with --hops {}: {:#}\n\
                 Hint: ensure at least 1 entry, {} middle, and 1 exit relay are \
                 registered with the discovery service at {}",
                config.hops,
                e,
                config.hops.saturating_sub(2),
                config.directory_url,
            );
            return Err(e);
        }
    };

    for (circuit, read_half) in built_circuits {
        spawn_circuit_reader(circuit, read_half, Arc::clone(&metrics));
    }

    let pool = Arc::new(Mutex::new(pool));

    spawn_circuit_monitor(
        Arc::clone(&pool),
        Arc::clone(&metrics),
        std::time::Duration::from_secs(5),
    );
    spawn_circuit_keepalive(Arc::clone(&pool));

    let tui_handle = if config.tui {
        let tui_metrics = Arc::clone(&metrics);
        let tui_pool = Arc::clone(&pool);
        let tui_socks_addr = config.socks_addr.clone();
        Some(tokio::spawn(async move {
            tor_client::tui::run_tui(tui_metrics, tui_pool, tui_socks_addr).await
        }))
    } else {
        None
    };

    tor_client::client::socks_proxy::run(config.socks_addr.clone(), pool, metrics).await?;

    if let Some(handle) = tui_handle {
        let _ = handle.await;
    }

    info!("Tor client shut down");
    Ok(())
}
