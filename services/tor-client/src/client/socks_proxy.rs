use anyhow::{Context, Result};
use simple_socks5::conn::reply::Rep;
use simple_socks5::conn::request::CMD;
use simple_socks5::parse::AddrPort;
use simple_socks5::{ATYP, Socks5};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::core::circuit::{CircuitPool, CircuitState, spawn_circuit_reader};
use crate::core::metrics::{ClientMetrics, EventKind};
use crate::core::stream::handle_stream;

/// Run the SOCKS5 proxy server loop.
/// Accepts connections, performs SOCKS5 handshake, selects a circuit,
/// and spawns stream handling tasks.
pub async fn run(
    socks_addr: String,
    pool: Arc<Mutex<CircuitPool>>,
    metrics: Arc<ClientMetrics>,
) -> Result<()> {
    let mut server = Socks5::bind(&socks_addr)
        .await
        .context("Failed to bind SOCKS5 server")?;
    server.allow_no_auth();
    let server = Arc::new(server);

    info!("SOCKS5 server listening on {}", socks_addr);

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

    info!("SOCKS5 proxy shut down");
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
        destination.clone(),
        Arc::clone(metrics),
    )
    .await;

    if let Err(e) = &result {
        error!(
            "Stream processing for SOCKS5 connection from {} to {} failed: {:#}",
            addr, destination, e
        );
        metrics.push_event(EventKind::Error {
            message: format!("Stream processing failed: {e:#}"),
        });
    }

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
