use anyhow::{Context, Result};
use clap::Parser;
use dialoguer::{Confirm, theme::ColorfulTheme};
use simple_socks5::conn::reply::Rep;
use simple_socks5::conn::request::CMD;
use simple_socks5::parse::AddrPort;
use simple_socks5::{ATYP, Socks5};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tor_client::circuit::{
    CircuitPool, CircuitState, spawn_circuit_keepalive, spawn_circuit_monitor, spawn_circuit_reader,
};
use tor_client::config::{MAX_HOPS, TorClientConfig};
use tor_client::directory_client::DirectoryClient;
use tor_client::metrics::{ClientMetrics, EventKind};
use tor_client::stream::handle_stream;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    let config = TorClientConfig::parse();

    // Prompt for explicit confirmation before building a maximum-size circuit.
    // Do this before initializing logging so the prompt is always visible.
    if config.hops == MAX_HOPS {
        let confirmed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "You requested a {MAX_HOPS}-hop circuit (the maximum).\n  \
                 This requires {MAX_HOPS} relay nodes and adds significant latency.\n  \
                 A {MAX_HOPS}-node circuit will be built: 1 entry + {} middles + 1 exit.\n  \
                 Do you understand and want to proceed?",
                MAX_HOPS - 2
            ))
            .default(false)
            .interact()
            .context("Failed to read confirmation")?;

        if !confirmed {
            eprintln!("Aborted. Use --hops <3-9> for a smaller circuit.");
            std::process::exit(0);
        }
    }

    if config.tui {
        tracing_subscriber::fmt().with_writer(std::io::sink).init();
    } else {
        tracing_subscriber::fmt::init();
    }

    info!(
        "Starting Tor client: socks_addr={}, directory_url={}, pool_size={}, hops={}",
        config.socks_addr, config.directory_url, config.pool_size, config.hops
    );

    let metrics = ClientMetrics::new();

    let directory_client = DirectoryClient::new(config.directory_url.clone());
    let mut pool = CircuitPool::new(
        directory_client,
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

    let mut server = Socks5::bind(&config.socks_addr)
        .await
        .context("Failed to bind SOCKS5 server")?;
    server.allow_no_auth();
    let server = Arc::new(server);

    info!("SOCKS5 server listening on {}", config.socks_addr);

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

    loop {
        tokio::select! {
            result = server.accept() => {
                let (mut stream, addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Failed to accept SOCKS5 connection: {}", e);
                        metrics.push_event(EventKind::Error {
                            message: format!("Accept failed: {e}"),
                        });
                        continue;
                    }
                };

                info!("Accepted SOCKS5 connection from {}", addr);
                metrics
                    .connections_accepted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let server = Arc::clone(&server);
                let pool = Arc::clone(&pool);
                let metrics = Arc::clone(&metrics);

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(&server, &pool, &mut stream, addr, &metrics).await {
                        warn!("SOCKS5 connection from {} failed: {:#}", addr, e);
                        metrics.push_event(EventKind::Error {
                            message: format!("Connection from {addr} failed: {e:#}"),
                        });
                    }
                });
            }

            result = tokio::signal::ctrl_c() => {
                if let Err(e) = result {
                    error!("Failed to listen for Ctrl+C: {}", e);
                }
                info!("Received Ctrl+C, shutting down");
                break;
            }
        }
    }

    if let Some(handle) = tui_handle {
        let _ = handle.await;
    }

    info!("Tor client shut down");
    Ok(())
}

/// Handle a single SOCKS5 connection end-to-end.
async fn handle_connection(
    server: &Socks5,
    pool: &Arc<Mutex<CircuitPool>>,
    stream: &mut tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    metrics: &Arc<ClientMetrics>,
) -> Result<()> {
    server
        .authenticate(stream)
        .await
        .context("SOCKS5 authentication failed")?;

    let req = Socks5::read_conn_request(stream)
        .await
        .context("Failed to read SOCKS5 connection request")?;

    if req.cmd != CMD::Connect {
        warn!("Unsupported SOCKS5 command from {}: {:?}", addr, req.cmd);
        let _ = Socks5::send_conn_reply(
            stream,
            Rep::CommandNotSupported,
            ATYP::V4,
            AddrPort::V4(Ipv4Addr::UNSPECIFIED, 0),
        )
        .await;
        return Err(anyhow::anyhow!("Unsupported SOCKS5 command: {:?}", req.cmd));
    }

    let destination = req.dst.to_string();
    info!("SOCKS5 CONNECT from {} to {}", addr, destination);

    metrics.push_event(EventKind::Socks5Accept {
        addr,
        destination: destination.clone(),
    });

    let (circuit, maybe_read_half) = {
        let mut p = pool.lock().await;
        p.select_circuit()
            .await
            .context("Failed to select circuit")?
    };

    if let Some(read_half) = maybe_read_half {
        spawn_circuit_reader(Arc::clone(&circuit), read_half, Arc::clone(metrics));
    }

    let result = handle_stream(
        Arc::clone(&circuit),
        stream,
        destination,
        Arc::clone(metrics),
    )
    .await;

    if result.is_err() {
        let circuit_guard = circuit.lock().await;
        if circuit_guard.state == CircuitState::Closed {
            let failed_id = circuit_guard.circuit_id;
            drop(circuit_guard);

            warn!("Circuit {} is closed, scheduling replacement", failed_id);
            let mut p = pool.lock().await;
            match p.replace_circuit(failed_id).await {
                Ok((new_circuit, read_half)) => {
                    spawn_circuit_reader(new_circuit, read_half, Arc::clone(metrics));
                    info!("Successfully replaced failed circuit {}", failed_id);
                }
                Err(e) => {
                    error!("Failed to replace circuit {}: {}", failed_id, e);
                    metrics.push_event(EventKind::Error {
                        message: format!("Circuit replacement failed: {e}"),
                    });
                }
            }
        }
    }

    result
}
