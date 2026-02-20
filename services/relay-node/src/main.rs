mod circuit;
mod config;
mod keypair;

use anyhow::Result;
use circuit::{
    CircuitHandler, CircuitRegistry, EntryCircuitHandler, ExitCircuitHandler, MiddleCircuitHandler,
};
use clap::Parser;
use common::{NodeDescriptor, protocol::Message};
use config::RelayConfig;
use keypair::KeyPair;
use reqwest::Client;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncWriteExt, WriteHalf},
    net::TcpListener,
    signal,
    sync::Mutex,
    time::{Duration, interval},
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let config = RelayConfig::parse();

    info!("Starting relay node");
    info!("  Node type: {:?}", config.node_type);
    info!("  Bind address: {}:{}", config.host, config.port);
    info!("  Directory URL: {}", config.directory_url);
    info!("  Bandwidth: {} bytes/sec", config.bandwidth);

    let keypair = KeyPair::generate();
    info!(
        "  Public key: {:02x?}...",
        &keypair.public_key().bytes[0..8]
    );

    let bind_addr = config.bind_addr()?;

    let node_id = Uuid::new_v4().to_string();
    info!("  Node ID: {}", node_id);

    let descriptor = NodeDescriptor {
        node_id: node_id.clone(),
        node_type: config.node_type,
        address: bind_addr,
        public_key: keypair.public_key().clone(),
        bandwidth: config.bandwidth,
        exit_policy: config.exit_policy(),
    };

    let http_client = Client::new();

    register_with_directory(&http_client, &config.directory_url, &descriptor).await?;

    let circuit_registry = Arc::new(Mutex::new(CircuitRegistry::new()));

    let listener = TcpListener::bind(bind_addr).await?;
    info!("Listening on {}", bind_addr);

    let heartbeat_handle = tokio::spawn(heartbeat_loop(
        http_client.clone(),
        config.directory_url.clone(),
        node_id.clone(),
        config.heartbeat_interval,
    ));

    let connection_handle = tokio::spawn(accept_connections(
        listener,
        circuit_registry,
        keypair,
        config.node_type,
    ));

    info!("Relay node started successfully. Press Ctrl+C to stop.");

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
        result = heartbeat_handle => {
            error!("Heartbeat task terminated unexpectedly: {:?}", result);
        }
        result = connection_handle => {
            error!("Connection handler terminated unexpectedly: {:?}", result);
        }
    }

    info!("Unregistering from directory service...");
    if let Err(e) = unregister_from_directory(&http_client, &config.directory_url, &node_id).await {
        warn!("Failed to unregister: {}", e);
    }

    info!("Relay node stopped");
    Ok(())
}

/// Register this node with the directory service
async fn register_with_directory(
    client: &Client,
    directory_url: &str,
    descriptor: &NodeDescriptor,
) -> Result<()> {
    let url = format!("{}/api/nodes/register", directory_url);

    info!("Registering with directory service at {}", url);

    let response = client.post(&url).json(descriptor).send().await?;

    if response.status().is_success() {
        info!("Successfully registered with directory service");
        Ok(())
    } else {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_string());
        Err(anyhow::anyhow!(
            "Failed to register with directory: {} - {}",
            status,
            body
        ))
    }
}

/// Unregister this node from the directory service
async fn unregister_from_directory(
    client: &Client,
    directory_url: &str,
    node_id: &str,
) -> Result<()> {
    let url = format!("{}/api/nodes/{}", directory_url, node_id);

    let response = client.delete(&url).send().await?;

    if response.status().is_success() {
        info!("Successfully unregistered from directory service");
        Ok(())
    } else {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_string());
        Err(anyhow::anyhow!(
            "Failed to unregister from directory: {} - {}",
            status,
            body
        ))
    }
}

/// Periodically send heartbeats to the directory service
async fn heartbeat_loop(
    client: Client,
    directory_url: String,
    node_id: String,
    interval_secs: u64,
) {
    let mut ticker = interval(Duration::from_secs(interval_secs));

    loop {
        ticker.tick().await;

        let url = format!("{}/api/nodes/{}/heartbeat", directory_url, node_id);

        match client.post(&url).send().await {
            Ok(response) if response.status().is_success() => {
                info!("Heartbeat sent successfully");
            }
            Ok(response) => {
                warn!("Heartbeat failed with status: {}", response.status());
            }
            Err(e) => {
                error!("Failed to send heartbeat: {}", e);
            }
        }
    }
}

/// Accept incoming TCP connections
async fn accept_connections(
    listener: TcpListener,
    circuit_registry: Arc<Mutex<CircuitRegistry>>,
    keypair: KeyPair,
    node_type: common::NodeType,
) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("Accepted connection from {}", addr);

                let registry = circuit_registry.clone();
                let kp = keypair.clone();
                tokio::spawn(handle_connection(stream, addr, registry, kp, node_type));
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Handle a single TCP connection
///
/// The client-facing TcpStream is split into read and write halves using
/// `tokio::io::split()`. The read half is used directly in the main loop
/// (no mutex needed), while the write half is wrapped in `Arc<Mutex<...>>`
/// and shared with background tasks that send backward-direction messages.
/// This prevents the deadlock where the main read loop would hold a mutex
/// on the full stream while background writers wait to send responses.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    circuit_registry: Arc<Mutex<CircuitRegistry>>,
    keypair: KeyPair,
    node_type: common::NodeType,
) {
    info!("Handling connection from {}", addr);

    // Split the client-facing stream: read half for the main loop,
    // write half shared with background tasks for backward messages.
    let (mut read_half, write_half) = tokio::io::split(stream);
    let write_arc: Arc<Mutex<WriteHalf<tokio::net::TcpStream>>> = Arc::new(Mutex::new(write_half));

    loop {
        let msg_result = Message::from_stream(&mut read_half).await;

        match msg_result {
            Ok(Some(msg)) => {
                debug!(
                    "Received {:?} message for circuit {}",
                    msg.command, msg.circuit_id
                );
                let circuit_id = msg.circuit_id;
                let command = msg.command;

                match command {
                    common::protocol::MessageCommand::Create => {
                        let mut handler = match node_type {
                            common::NodeType::Entry => CircuitHandler::Entry(
                                EntryCircuitHandler::new(circuit_id, keypair.clone()),
                            ),
                            common::NodeType::Middle => CircuitHandler::Middle(
                                MiddleCircuitHandler::new(circuit_id, keypair.clone()),
                            ),
                            common::NodeType::Exit => CircuitHandler::Exit(
                                ExitCircuitHandler::new(circuit_id, keypair.clone()),
                            ),
                        };

                        match handler.handle_message(msg, Some(write_arc.clone())).await {
                            Ok(Some(response)) => {
                                let bytes = response.to_bytes();
                                let mut writer = write_arc.lock().await;
                                if let Err(e) = writer.write_all(&bytes).await {
                                    error!("Failed to send CREATED response: {}", e);
                                    break;
                                }
                                drop(writer);
                                info!("Sent CREATED response for circuit {}", circuit_id);

                                let mut registry = circuit_registry.lock().await;
                                registry.add_circuit(circuit_id, handler);
                            }
                            Ok(None) => {}
                            Err(e) => {
                                error!("Failed to handle CREATE: {}", e);
                                break;
                            }
                        }
                    }
                    _ => {
                        let mut registry = circuit_registry.lock().await;

                        let should_spawn_reader = matches!(
                            command,
                            common::protocol::MessageCommand::Extended
                                | common::protocol::MessageCommand::Extend
                        );

                        match registry.handle_message(msg, Some(write_arc.clone())).await {
                            Ok(Some(response)) => {
                                let bytes = response.to_bytes();
                                let mut writer = write_arc.lock().await;
                                if let Err(e) = writer.write_all(&bytes).await {
                                    error!("Failed to send response: {}", e);
                                    drop(writer);
                                    drop(registry);
                                    break;
                                }
                                drop(writer);

                                if should_spawn_reader
                                    && let Some(handler) = registry.get_circuit_mut(circuit_id)
                                    && let Some(task_handle) = handler.spawn_nexthop_reader(
                                        circuit_registry.clone(),
                                        write_arc.clone(),
                                    )
                                {
                                    info!("Spawned background reader for circuit {}", circuit_id);

                                    tokio::spawn(async move {
                                        if let Err(e) = task_handle.await {
                                            error!("Background reader task failed: {}", e);
                                        }
                                    });
                                }
                            }
                            Ok(None) => {
                                if should_spawn_reader
                                    && let Some(handler) = registry.get_circuit_mut(circuit_id)
                                    && let Some(task_handle) = handler.spawn_nexthop_reader(
                                        circuit_registry.clone(),
                                        write_arc.clone(),
                                    )
                                {
                                    info!("Spawned background reader for circuit {}", circuit_id);

                                    tokio::spawn(async move {
                                        if let Err(e) = task_handle.await {
                                            error!("Background reader task failed: {}", e);
                                        }
                                    });
                                }
                            }
                            Err(e) => {
                                error!("Failed to handle message: {}", e);
                                drop(registry);
                                break;
                            }
                        }
                        drop(registry);
                    }
                }
            }
            Ok(None) => {
                info!("Connection from {} closed", addr);
                break;
            }
            Err(e) => {
                error!("Error reading message from {}: {}", addr, e);
                break;
            }
        }
    }

    info!("Connection handler for {} terminated", addr);
}
