use clap::Parser;
use discovery::config::DiscoveryConfig;
use discovery::grpc::DiscoveryServiceImpl;
use discovery::metrics::{DiscoveryMetrics, EventKind};
use discovery::registry::{AppState, NodeRegistry};
use discovery::routes;
use proto::services::discovery_server::DiscoveryServer;
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = DiscoveryConfig::parse();

    if config.tui {
        use tracing_subscriber::fmt::writer::MakeWriterExt;
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "discovery=info,tower_http=info".into()),
            )
            .with_writer(std::io::sink.with_max_level(tracing::Level::TRACE))
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "discovery=info,tower_http=info".into()),
            )
            .init();
    }

    tracing::info!("Starting Tor Discovery Service...");

    let registry = Arc::new(RwLock::new(NodeRegistry::new(config.allow_same_ip)));
    let metrics = Some(DiscoveryMetrics::new());

    let state = AppState {
        registry: registry.clone(),
        metrics: metrics.clone(),
    };

    spawn_background_tasks(registry.clone(), config.stale_timeout_secs, metrics.clone());

    let bind_addr = config.bind_addr();
    let web_bind_addr = config.web_bind_addr();

    let grpc_svc = DiscoveryServiceImpl::new(state.clone());

    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::services::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<DiscoveryServer<DiscoveryServiceImpl>>()
        .await;

    let grpc_listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    let web_listener = tokio::net::TcpListener::bind(&web_bind_addr).await?;

    tracing::info!("gRPC service listening on http://{}", bind_addr);
    tracing::info!("Web UI available at http://{}", web_bind_addr);

    if !config.tui {
        println!("gRPC endpoints on http://{}", bind_addr);
        println!("  HealthCheck, RegisterNode, RemoveNode, UpdateHeartbeat");
        println!("  GetAllNodes, GetRandomPath, GetStats");
        println!("  gRPC reflection enabled (use grpcurl for exploration)");
        println!();
    }

    let web_router = routes::build_web_router(state.clone());

    let grpc_server = tonic::transport::Server::builder()
        .accept_http1(true)
        .add_service(health_service)
        .add_service(reflection_service)
        .add_service(DiscoveryServer::new(grpc_svc))
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(grpc_listener),
            shutdown_signal(),
        );

    let web_server = axum::serve(web_listener, web_router);

    if config.tui {
        let tui_metrics = metrics
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Metrics must be present when TUI is enabled"))?;
        let tui_registry = registry.clone();
        let tui_addr = bind_addr.clone();

        let grpc_handle = tokio::spawn(grpc_server);
        let web_handle = tokio::spawn(async move { web_server.await });

        let tui_handle = tokio::spawn(async move {
            discovery::tui::run_tui(tui_metrics, tui_registry, tui_addr).await
        });

        tokio::select! {
            result = tui_handle => {
                match result {
                    Ok(Ok(true)) => {
                        tracing::info!("TUI quit requested");
                    }
                    Ok(Ok(false)) => {
                        tracing::info!("TUI exited");
                    }
                    Ok(Err(e)) => {
                        tracing::error!("TUI error: {}", e);
                    }
                    Err(e) => {
                        tracing::error!("TUI task panicked: {}", e);
                    }
                }
            }
            result = grpc_handle => {
                match result {
                    Ok(Ok(())) => tracing::info!("gRPC server exited"),
                    Ok(Err(e)) => tracing::error!("gRPC server error: {}", e),
                    Err(e) => tracing::error!("gRPC task panicked: {}", e),
                }
            }
            result = web_handle => {
                match result {
                    Ok(Ok(())) => tracing::info!("Web server exited"),
                    Ok(Err(e)) => tracing::error!("Web server error: {}", e),
                    Err(e) => tracing::error!("Web task panicked: {}", e),
                }
            }
        }
    } else {
        tokio::select! {
            result = grpc_server => {
                if let Err(e) = result {
                    tracing::error!("gRPC server error: {}", e);
                }
            }
            result = web_server => {
                if let Err(e) = result {
                    tracing::error!("Web server error: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Spawn background tasks for periodic maintenance
fn spawn_background_tasks(
    registry: Arc<RwLock<NodeRegistry>>,
    stale_timeout_secs: u64,
    metrics: Option<Arc<DiscoveryMetrics>>,
) {
    let registry_cleanup = registry.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let mut registry = registry_cleanup.write().await;
            let removed = registry.cleanup_stale_nodes(Duration::from_secs(stale_timeout_secs));
            if removed > 0 {
                tracing::info!("Cleaned up {} stale nodes", removed);
                if let Some(m) = &metrics {
                    m.stale_cleaned
                        .fetch_add(removed as u64, std::sync::atomic::Ordering::Relaxed);
                    m.push_event(EventKind::StaleCleanup { removed });
                }
            }
        }
    });
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.ok();
    tracing::info!("Received shutdown signal");
}
