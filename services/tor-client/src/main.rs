use anyhow::{Context, Result};
use clap::Parser;
use simple_socks5::conn::reply::Rep;
use simple_socks5::conn::request::CMD;
use simple_socks5::parse::AddrPort;
use simple_socks5::{ATYP, Socks5};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tor_client::circuit::{CircuitPool, CircuitState, spawn_circuit_reader};
use tor_client::config::TorClientConfig;
use tor_client::directory_client::DirectoryClient;
use tor_client::stream::handle_stream;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = TorClientConfig::parse();
    info!(
        "Starting Tor client: socks_addr={}, directory_url={}, pool_size={}",
        config.socks_addr, config.directory_url, config.pool_size
    );

    // Create directory client and circuit pool
    let directory_client = DirectoryClient::new(config.directory_url.clone());
    let mut pool = CircuitPool::new(directory_client, config.pool_size);
    let built_circuits = pool
        .initialize()
        .await
        .context("Failed to initialize circuit pool")?;

    // Spawn background readers for each pre-built circuit
    for (circuit, read_half) in built_circuits {
        spawn_circuit_reader(circuit, read_half);
    }

    let pool = Arc::new(Mutex::new(pool));

    // Start SOCKS5 server
    let mut server = Socks5::bind(&config.socks_addr)
        .await
        .context("Failed to bind SOCKS5 server")?;
    server.allow_no_auth();
    let server = Arc::new(server);

    info!("SOCKS5 server listening on {}", config.socks_addr);

    // Accept loop with graceful shutdown
    loop {
        tokio::select! {
            result = server.accept() => {
                let (mut stream, addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Failed to accept SOCKS5 connection: {}", e);
                        continue;
                    }
                };

                info!("Accepted SOCKS5 connection from {}", addr);

                let server = Arc::clone(&server);
                let pool = Arc::clone(&pool);

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(&server, &pool, &mut stream, addr).await {
                        warn!("SOCKS5 connection from {} failed: {:#}", addr, e);
                    }
                });
            }

            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down");
                break;
            }
        }
    }

    info!("Tor client shut down");
    Ok(())
}

/// Handle a single SOCKS5 connection end-to-end
///
/// Performs the SOCKS5 handshake (auth + CONNECT request), selects a circuit,
/// and hands off to `handle_stream` for bidirectional data relay.
///
/// # Errors
/// Returns an error if the SOCKS5 handshake, circuit selection, or stream handling fails
async fn handle_connection(
    server: &Socks5,
    pool: &Arc<Mutex<CircuitPool>>,
    stream: &mut tokio::net::TcpStream,
    addr: std::net::SocketAddr,
) -> Result<()> {
    // SOCKS5 authentication handshake (borrows stream)
    server
        .authenticate(stream)
        .await
        .context("SOCKS5 authentication failed")?;

    // Read connection request (borrows stream)
    let req = Socks5::read_conn_request(stream)
        .await
        .context("Failed to read SOCKS5 connection request")?;

    // Only support CONNECT command
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

    // Select least-loaded circuit (may build a new one if pool is exhausted)
    let (circuit, maybe_read_half) = {
        let mut p = pool.lock().await;
        p.select_circuit()
            .await
            .context("Failed to select circuit")?
    };

    // If a new circuit was built, spawn a reader for it (fixes Bug #3)
    if let Some(read_half) = maybe_read_half {
        spawn_circuit_reader(Arc::clone(&circuit), read_half);
    }

    // Route through onion circuit
    // handle_stream sends BEGIN, waits for CONNECTED, sends SOCKS5 reply,
    // and relays data bidirectionally
    let result = handle_stream(Arc::clone(&circuit), stream, destination).await;

    // If the stream failed, check if the circuit is dead and replace it
    if result.is_err() {
        let circuit_guard = circuit.lock().await;
        if circuit_guard.state == CircuitState::Closed {
            let failed_id = circuit_guard.circuit_id;
            drop(circuit_guard); // Release lock before replacing

            warn!("Circuit {} is closed, scheduling replacement", failed_id);
            let mut p = pool.lock().await;
            match p.replace_circuit(failed_id).await {
                Ok((new_circuit, read_half)) => {
                    spawn_circuit_reader(new_circuit, read_half);
                    info!("Successfully replaced failed circuit {}", failed_id);
                }
                Err(e) => {
                    error!("Failed to replace circuit {}: {}", failed_id, e);
                }
            }
        }
    }

    result
}
