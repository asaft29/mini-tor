use clap::Parser;
use discovery::config::DiscoveryConfig;
use discovery::metrics::{DiscoveryMetrics, EventKind};
use discovery::registry::{AppState, NodeRegistry};
use discovery::routes;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = DiscoveryConfig::parse();

    // Set up tracing: when TUI is active, send logs to sink to avoid corrupting display
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

    tracing::info!("Starting Tor Directory Service...");

    let consensus_path = PathBuf::from(&config.consensus_path);

    if let Some(parent) = consensus_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut registry = NodeRegistry::new(consensus_path);

    if let Err(e) = registry.load().await {
        tracing::warn!("Failed to load consensus: {}", e);
    }

    let registry = Arc::new(RwLock::new(registry));

    // Create metrics only when TUI is enabled
    let metrics = if config.tui {
        Some(DiscoveryMetrics::new())
    } else {
        None
    };

    let state = AppState {
        registry: registry.clone(),
        metrics: metrics.clone(),
    };

    spawn_background_tasks(registry.clone(), config.stale_timeout_secs, metrics.clone());

    let app = routes::build_router(state);

    let bind_addr = config.bind_addr();
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    tracing::info!("Directory service listening on http://{}", bind_addr);

    if !config.tui {
        print_api_endpoints();
    }

    if config.tui {
        let tui_metrics = metrics
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Metrics must be present when TUI is enabled"))?;
        let tui_registry = registry.clone();
        let tui_addr = bind_addr.clone();

        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .map_err(anyhow::Error::from)
        });

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
            result = server_handle => {
                match result {
                    Ok(Ok(())) => tracing::info!("Server exited"),
                    Ok(Err(e)) => tracing::error!("Server error: {}", e),
                    Err(e) => tracing::error!("Server task panicked: {}", e),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received shutdown signal");
            }
        }
    } else {
        axum::serve(listener, app).await?;
    }

    Ok(())
}

/// Spawn background tasks for periodic maintenance
fn spawn_background_tasks(
    registry: Arc<RwLock<NodeRegistry>>,
    stale_timeout_secs: u64,
    metrics: Option<Arc<DiscoveryMetrics>>,
) {
    let registry_save = registry.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let registry = registry_save.read().await;
            if let Err(e) = registry.save().await {
                tracing::error!("Failed to save consensus: {}", e);
            }
        }
    });

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

/// Print available API endpoints
fn print_api_endpoints() {
    tracing::info!("API endpoints:");
    tracing::info!("  GET    /health                     - Health check (always 200)");
    tracing::info!(
        "  GET    /ready                      - Readiness check (503 if insufficient nodes)"
    );
    tracing::info!("  POST   /api/nodes/register         - Register a relay node");
    tracing::info!("  GET    /api/nodes                  - List all nodes");
    tracing::info!("  GET    /api/nodes/random           - Get random path (3 nodes)");
    tracing::info!("  POST   /api/nodes/{{id}}/heartbeat   - Update heartbeat");
    tracing::info!("  DELETE /api/nodes/{{id}}             - Remove node");
    tracing::info!("  GET    /api/stats                  - Get statistics");
    tracing::info!("  GET    /swagger-ui                 - OpenAPI documentation UI");
    tracing::info!("  GET    /api-docs/openapi.json      - OpenAPI specification");
}
