mod circuit;
mod core;
mod tui;
mod wizard;

use anyhow::{Context, Result};
use circuit::{
    CircuitHandler, CircuitRegistry, EntryCircuitHandler, ExitCircuitHandler, MiddleCircuitHandler,
};
use clap::Parser;
use common::{
    NodeDescriptor, NodeMetrics, RelayStream, RelayTlsConfig, RelayWriteHalf, protocol::Message,
};
use core::config::RelayConfig;
use core::keypair::KeyPair;
use core::metrics::{EventKind, RelayMetrics};
use proto::services::{HeartbeatRequest, RemoveNodeRequest, discovery_client::DiscoveryClient};
use proto::types::NodeDescriptor as ProtoNodeDescriptor;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::TcpListener,
    signal,
    sync::{Mutex, Semaphore},
    time::{Duration, interval},
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    let mut config = RelayConfig::parse();

    if config.tui && config.node_type.is_none() {
        config = wizard::run_wizard(&config)?;
    }

    let node_type = config.node_type.ok_or_else(|| {
        anyhow::anyhow!("--type is required (or use --tui for interactive setup)")
    })?;

    if config.tui {
        use tracing_subscriber::fmt::writer::MakeWriterExt;
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .with_writer(std::io::sink.with_max_level(tracing::Level::TRACE))
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .init();
    }

    info!("Starting relay node");
    info!("  Node type: {:?}", node_type);
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

    let tls_config = RelayTlsConfig::generate(&node_id, bind_addr)
        .context("Failed to generate TLS certificate")?;
    info!("  TLS fingerprint: {}", tls_config.fingerprint);

    let descriptor = NodeDescriptor {
        node_id: node_id.clone(),
        node_type,
        address: bind_addr,
        public_key: keypair.public_key().clone(),
        bandwidth: config.bandwidth,
        exit_policy: config.exit_policy(node_type),
        operator_id: config.operator_id.clone(),
        tls_cert_fingerprint: tls_config.fingerprint.clone(),
    };

    let channel = tonic::transport::Channel::from_shared(config.directory_url.clone())?
        .connect()
        .await
        .context("Failed to connect to discovery gRPC service")?;
    let mut grpc_client = DiscoveryClient::new(channel.clone());

    register_with_directory(&mut grpc_client, &descriptor).await?;

    let circuit_registry = Arc::new(Mutex::new(CircuitRegistry::new()));
    let relay_metrics = RelayMetrics::new();

    let listener = TcpListener::bind(bind_addr).await?;
    info!("Listening on {}", bind_addr);

    let heartbeat_handle = tokio::spawn(heartbeat_loop(
        channel.clone(),
        node_id.clone(),
        config.heartbeat_interval,
        circuit_registry.clone(),
        relay_metrics.clone(),
    ));

    let connection_handle = tokio::spawn(accept_connections(
        listener,
        circuit_registry.clone(),
        keypair,
        node_type,
        relay_metrics.clone(),
        tls_config.acceptor,
        500,
    ));

    info!("Relay node started successfully. Press Ctrl+C to stop.");

    if config.tui {
        let tui_metrics = relay_metrics.clone();
        let tui_registry = circuit_registry.clone();
        let tui_node_type = node_type;
        let tui_addr = bind_addr.to_string();

        let tui_handle = tokio::spawn(async move {
            tui::run_tui(tui_metrics, tui_registry, tui_node_type, tui_addr).await
        });

        tokio::select! {
            result = tui_handle => {
                match result {
                    Ok(Ok(true)) => {
                        info!("TUI quit requested");
                    }
                    Ok(Ok(false)) => {
                        info!("TUI exited");
                    }
                    Ok(Err(e)) => {
                        error!("TUI error: {}", e);
                    }
                    Err(e) => {
                        error!("TUI task panicked: {}", e);
                    }
                }
            }
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
    } else {
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
    }

    info!("Unregistering from directory service...");
    if let Err(e) = unregister_from_directory(&mut DiscoveryClient::new(channel), &node_id).await {
        warn!("Failed to unregister: {}", e);
    }

    info!("Relay node stopped");
    Ok(())
}

async fn register_with_directory(
    client: &mut DiscoveryClient<tonic::transport::Channel>,
    descriptor: &NodeDescriptor,
) -> Result<()> {
    let proto_desc = ProtoNodeDescriptor::from(descriptor.clone());
    let request = tonic::Request::new(proto_desc);

    info!("Registering with directory service via gRPC");
    let response = client.register_node(request).await?;
    info!(
        "Successfully registered with directory service: {}",
        response.into_inner().message
    );
    Ok(())
}

async fn unregister_from_directory(
    client: &mut DiscoveryClient<tonic::transport::Channel>,
    node_id: &str,
) -> Result<()> {
    let request = tonic::Request::new(RemoveNodeRequest {
        node_id: node_id.to_string(),
    });

    client.remove_node(request).await?;
    info!("Successfully unregistered from directory service");
    Ok(())
}

async fn build_metrics(
    metrics: &Arc<RelayMetrics>,
    circuit_registry: &Arc<Mutex<CircuitRegistry>>,
) -> NodeMetrics {
    NodeMetrics {
        connections_accepted: metrics.get_connections(),
        circuits_active: circuit_registry.lock().await.circuit_count() as u64,
        circuits_created: metrics.get_circuits_created(),
        circuits_destroyed: metrics.get_circuits_destroyed(),
        bytes_forwarded: metrics.get_bytes_forwarded(),
        bytes_received: metrics.get_bytes_received(),
        streams_opened: metrics.get_streams_opened(),
        uptime_secs: metrics.uptime().as_secs(),
        event_snapshot: metrics.event_snapshot(),
    }
}

async fn heartbeat_loop(
    channel: tonic::transport::Channel,
    node_id: String,
    interval_secs: u64,
    circuit_registry: Arc<Mutex<CircuitRegistry>>,
    metrics: Arc<RelayMetrics>,
) {
    let mut ticker = interval(Duration::from_secs(interval_secs));
    let mut client = DiscoveryClient::new(channel);

    loop {
        ticker.tick().await;

        let body = build_metrics(&metrics, &circuit_registry).await;

        let request = tonic::Request::new(HeartbeatRequest {
            node_id: node_id.clone(),
            metrics: Some(body.into()),
        });

        match client.update_heartbeat(request).await {
            Ok(_) => {
                debug!("Heartbeat sent successfully");
            }
            Err(e) => {
                warn!("Heartbeat failed: {e}");
            }
        }
    }
}

async fn accept_connections(
    listener: TcpListener,
    circuit_registry: Arc<Mutex<CircuitRegistry>>,
    keypair: KeyPair,
    node_type: common::NodeType,
    metrics: Arc<RelayMetrics>,
    tls_acceptor: Arc<dyn common::tls::StreamAcceptor>,
    max_concurrent: usize,
) {
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    loop {
        match listener.accept().await {
            Ok((tcp_stream, addr)) => {
                info!("Accepted TCP connection from {}", addr);

                metrics
                    .connections_accepted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                metrics.push_event(EventKind::ConnectionAccepted {
                    peer: addr.to_string(),
                });

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!(
                            "Connection from {} rejected: relay at max capacity ({})",
                            addr, max_concurrent
                        );
                        continue;
                    }
                };

                let registry = circuit_registry.clone();
                let kp = keypair.clone();
                let m = metrics.clone();
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match tls_acceptor.accept(tcp_stream).await {
                        Ok(stream) => {
                            handle_connection(stream, addr, registry, kp, node_type, m).await;
                        }
                        Err(e) => {
                            error!("TLS handshake failed for {}: {}", addr, e);
                        }
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Handle a single TLS connection.
///
/// Read half is used directly in the main loop; write half is shared with
/// background tasks via Arc<Mutex> to avoid deadlocks on bidirectional I/O.
async fn handle_connection(
    stream: RelayStream,
    addr: SocketAddr,
    circuit_registry: Arc<Mutex<CircuitRegistry>>,
    keypair: KeyPair,
    node_type: common::NodeType,
    metrics: Arc<RelayMetrics>,
) {
    info!("Handling connection from {}", addr);

    let (mut read_half, write_half) = tokio::io::split(stream);
    let write_arc: Arc<Mutex<RelayWriteHalf>> = Arc::new(Mutex::new(write_half));

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
                            common::NodeType::Entry => {
                                let mut entry_handler =
                                    EntryCircuitHandler::new(circuit_id, keypair.clone());
                                entry_handler.set_metrics(metrics.clone());
                                CircuitHandler::Entry(entry_handler)
                            }
                            common::NodeType::Middle => {
                                let mut middle_handler =
                                    MiddleCircuitHandler::new(circuit_id, keypair.clone());
                                middle_handler.set_metrics(metrics.clone());
                                CircuitHandler::Middle(middle_handler)
                            }
                            common::NodeType::Exit => {
                                let mut exit_handler =
                                    ExitCircuitHandler::new(circuit_id, keypair.clone());
                                exit_handler.set_metrics(metrics.clone());
                                CircuitHandler::Exit(exit_handler)
                            }
                        };

                        match handler.handle_message(msg, Some(write_arc.clone())).await {
                            Ok(Some(response)) => {
                                let mut writer = write_arc.lock().await;
                                if let Err(e) = response.write_to_stream(&mut *writer).await {
                                    error!("Failed to send CREATED response: {}", e);
                                    break;
                                }
                                drop(writer);
                                info!("Sent CREATED response for circuit {}", circuit_id);

                                metrics
                                    .circuits_created
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                metrics.push_event(EventKind::CircuitCreated { circuit_id });

                                let mut registry = circuit_registry.lock().await;
                                registry.add_circuit(circuit_id, handler);
                            }
                            Ok(None) => {}
                            Err(e) => {
                                error!("Failed to handle CREATE: {}", e);
                                metrics.push_event(EventKind::Error {
                                    message: format!("CREATE failed cid={circuit_id}: {e}"),
                                });
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
                                let resp_bytes = response.data.len();
                                let mut writer = write_arc.lock().await;
                                if let Err(e) = response.write_to_stream(&mut *writer).await {
                                    error!("Failed to send response: {}", e);
                                    drop(writer);
                                    drop(registry);
                                    break;
                                }
                                drop(writer);

                                if !matches!(
                                    command,
                                    common::protocol::MessageCommand::Extended
                                        | common::protocol::MessageCommand::Extend
                                        | common::protocol::MessageCommand::Destroy
                                ) {
                                    metrics.bytes_forwarded.fetch_add(
                                        resp_bytes as u64,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                    metrics.push_event(EventKind::RelayForward {
                                        circuit_id,
                                        command,
                                        bytes: resp_bytes,
                                    });
                                }

                                if matches!(command, common::protocol::MessageCommand::Destroy) {
                                    metrics
                                        .circuits_destroyed
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    metrics.push_event(EventKind::CircuitDestroyed { circuit_id });
                                }

                                if should_spawn_reader
                                    && let Some(handler) = registry.get_circuit_mut(circuit_id)
                                    && let Some(task_handle) = handler.spawn_nexthop_reader(
                                        crate::circuit::handler::CircuitIoContext {
                                            circuit_registry: circuit_registry.clone(),
                                            prev_hop_write: write_arc.clone(),
                                            metrics: metrics.clone(),
                                        },
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
                                if matches!(command, common::protocol::MessageCommand::Destroy) {
                                    metrics
                                        .circuits_destroyed
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    metrics.push_event(EventKind::CircuitDestroyed { circuit_id });
                                }

                                if should_spawn_reader
                                    && let Some(handler) = registry.get_circuit_mut(circuit_id)
                                    && let Some(task_handle) = handler.spawn_nexthop_reader(
                                        crate::circuit::handler::CircuitIoContext {
                                            circuit_registry: circuit_registry.clone(),
                                            prev_hop_write: write_arc.clone(),
                                            metrics: metrics.clone(),
                                        },
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
                                metrics.push_event(EventKind::Error {
                                    message: format!("{command} failed cid={circuit_id}: {e}"),
                                });
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
                metrics.push_event(EventKind::ConnectionClosed {
                    peer: addr.to_string(),
                });
                break;
            }
            Err(e) => {
                error!("Error reading message from {}: {}", addr, e);
                metrics.push_event(EventKind::ConnectionClosed {
                    peer: addr.to_string(),
                });
                break;
            }
        }
    }

    info!("Connection handler for {} terminated", addr);
}
