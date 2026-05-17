use axum::{
    Json,
    extract::{Path, Query, State},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use common::{NodeDescriptor, NodeMetrics};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use utoipa::ToSchema;

use crate::error::Result;
use crate::metrics::EventKind;
use crate::registry::{AppState, RegistryStats};

/// Response for list nodes endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct NodesResponse {
    pub nodes: Vec<NodeDescriptor>,
    pub count: usize,
}

/// Register a new node.
#[utoipa::path(
    post,
    path = "/api/nodes/register",
    request_body = NodeDescriptor,
    responses(
        (status = 201, description = "Node registered successfully"),
        (status = 400, description = "Invalid node data"),
        (status = 422, description = "Validation failed")
    ),
    tag = "nodes"
)]
pub async fn register_node(
    State(state): State<AppState>,
    Json(descriptor): Json<NodeDescriptor>,
) -> Result<impl IntoResponse> {
    if descriptor.node_id.is_empty() {
        return Err(crate::error::AppError::validation(
            "Node ID cannot be empty",
        ));
    }
    if descriptor.bandwidth == 0 {
        return Err(crate::error::AppError::validation(
            "Bandwidth must be greater than 0",
        ));
    }

    let node_id = descriptor.node_id.clone();
    let node_type = format!("{}", descriptor.node_type);
    let address = descriptor.address.to_string();

    let mut registry = state.registry.write().await;
    registry.register_node(descriptor);

    if let Some(m) = &state.metrics {
        m.registrations.fetch_add(1, Ordering::Relaxed);
        m.push_event(EventKind::NodeRegistered {
            node_id,
            node_type,
            address,
        });
    }

    Ok((StatusCode::CREATED, "Node registered successfully"))
}

/// Get all nodes.
#[utoipa::path(
    get,
    path = "/api/nodes",
    responses(
        (status = 200, description = "List of all registered nodes", body = NodesResponse)
    ),
    tag = "nodes"
)]
pub async fn get_all_nodes(State(state): State<AppState>) -> Result<Json<NodesResponse>> {
    let registry = state.registry.read().await;
    let nodes = registry.get_all_nodes();
    let count = nodes.len();

    Ok(Json(NodesResponse { nodes, count }))
}

/// Query parameters for the random path endpoint.
#[derive(Deserialize)]
pub struct RandomPathQuery {
    #[serde(default = "default_hop_count")]
    pub count: usize,
}

fn default_hop_count() -> usize {
    3
}

/// Get random path for circuit. Returns `count` nodes: 1 entry + (count-2) middles + 1 exit.
/// `count` defaults to 3 and is clamped to a minimum of 3.
#[utoipa::path(
    get,
    path = "/api/nodes/random",
    params(
        ("count" = Option<usize>, Query, description = "Number of hops (default 3, minimum 3)")
    ),
    responses(
        (status = 200, description = "Random path with N nodes (entry, middles, exit)", body = Vec<NodeDescriptor>),
        (status = 503, description = "Insufficient nodes available")
    ),
    tag = "nodes"
)]
pub async fn get_random_path(
    State(state): State<AppState>,
    Query(params): Query<RandomPathQuery>,
) -> Result<Json<Vec<NodeDescriptor>>> {
    let count = params.count.max(3);
    let registry = state.registry.read().await;
    let path = registry.get_random_path(count)?;

    if let Some(m) = &state.metrics {
        m.path_requests.fetch_add(1, Ordering::Relaxed);
        m.push_event(EventKind::PathRequested);
    }

    Ok(Json(path))
}

/// Update node heartbeat.
#[utoipa::path(
    post,
    path = "/api/nodes/{id}/heartbeat",
    params(
        ("id" = String, Path, description = "Node ID")
    ),
    request_body = NodeMetrics,
    responses(
        (status = 200, description = "Heartbeat updated successfully"),
        (status = 404, description = "Node not found")
    ),
    tag = "nodes"
)]
pub async fn update_heartbeat(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    Json(metrics): Json<NodeMetrics>,
) -> Result<impl IntoResponse> {
    let mut registry = state.registry.write().await;
    registry.update_heartbeat_with_metrics(&node_id, metrics)?;

    if let Some(m) = &state.metrics {
        m.heartbeats.fetch_add(1, Ordering::Relaxed);
        m.push_event(EventKind::Heartbeat {
            node_id: node_id.clone(),
        });
    }

    Ok(StatusCode::OK)
}

/// Remove a node.
#[utoipa::path(
    delete,
    path = "/api/nodes/{id}",
    params(
        ("id" = String, Path, description = "Node ID")
    ),
    responses(
        (status = 204, description = "Node removed successfully"),
        (status = 404, description = "Node not found")
    ),
    tag = "nodes"
)]
pub async fn remove_node(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<impl IntoResponse> {
    let mut registry = state.registry.write().await;
    registry.remove_node(&node_id)?;

    if let Some(m) = &state.metrics {
        m.removals.fetch_add(1, Ordering::Relaxed);
        m.push_event(EventKind::NodeRemoved {
            node_id: node_id.clone(),
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Get registry statistics.
#[utoipa::path(
    get,
    path = "/api/stats",
    responses(
        (status = 200, description = "Registry statistics", body = RegistryStats)
    ),
    tag = "stats"
)]
pub async fn get_stats(State(state): State<AppState>) -> Result<Json<RegistryStats>> {
    let registry = state.registry.read().await;
    let stats = registry.get_stats();

    if let Some(m) = &state.metrics {
        m.push_event(EventKind::StatsQueried);
    }

    Ok(Json(stats))
}

/// Health check response.
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub ready: bool,
    pub message: Option<String>,
}

/// Health check endpoint.
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service health status", body = HealthResponse)
    ),
    tag = "health"
)]
pub async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let registry = state.registry.read().await;
    let ready = registry.is_ready();

    if let Some(m) = &state.metrics {
        m.push_event(EventKind::HealthCheck { ready });
    }

    let response = HealthResponse {
        status: "ok".to_string(),
        ready,
        message: if ready {
            None
        } else {
            Some("Insufficient nodes to build circuits. Need at least 1 entry, 1 middle, and 1 exit node.".to_string())
        },
    };

    Json(response)
}

/// Readiness check — returns 200 if ready, 503 if not.
#[utoipa::path(
    get,
    path = "/ready",
    responses(
        (status = 200, description = "Service is ready"),
        (status = 503, description = "Service is not ready - insufficient nodes")
    ),
    tag = "health"
)]
pub async fn readiness_check(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let registry = state.registry.read().await;

    if registry.is_ready() {
        Ok((StatusCode::OK, "Ready"))
    } else {
        Err(crate::error::AppError::ServiceUnavailable(
            "Insufficient nodes to build circuits. Need at least 1 entry, 1 middle, and 1 exit node.".to_string()
        ))
    }
}

// ── Web UI ────────────────────────────────────────────────────────────────────

/// Metrics snapshot for the web dashboard.
#[derive(Debug, Serialize)]
pub struct MetricsSummary {
    pub registrations: u64,
    pub removals: u64,
    pub heartbeats: u64,
    pub path_requests: u64,
    pub stale_cleaned: u64,
    pub uptime_secs: u64,
}

/// A single pre-formatted activity log entry for the web dashboard.
#[derive(Debug, Serialize)]
pub struct EventEntry {
    /// Seconds since service start when the event was recorded.
    pub elapsed_secs: f64,
    /// CSS class suffix: "register" | "remove" | "heartbeat" | "path" | "cleanup" | "stats" | "health" | "error"
    pub event_type: String,
    /// Display label matching the TUI (e.g. "+ REGISTER", "♥ HEARTBEAT").
    pub label: String,
    /// Human-readable detail string.
    pub detail: String,
}

/// A node descriptor combined with live metrics for the web dashboard.
#[derive(Debug, Serialize)]
pub struct NodeWithMetrics {
    #[serde(flatten)]
    pub descriptor: NodeDescriptor,
    pub metrics: Option<NodeMetrics>,
}

/// Combined response for the web dashboard — nodes, stats, metrics, and activity log.
#[derive(Debug, Serialize)]
pub struct DashboardResponse {
    pub nodes: Vec<NodeWithMetrics>,
    pub stats: RegistryStats,
    pub metrics: MetricsSummary,
    pub ready: bool,
    /// Last 50 events, newest first.
    pub events: Vec<EventEntry>,
}

fn event_to_entry(e: &common::metrics::TuiEvent<EventKind>) -> EventEntry {
    let elapsed_secs = e.elapsed.as_secs_f64();
    let (event_type, label, detail) = match &e.kind {
        EventKind::NodeRegistered {
            node_id,
            node_type,
            address,
        } => (
            "register",
            "+ REGISTER",
            format!("{node_type} {node_id} @ {address}"),
        ),
        EventKind::NodeRemoved { node_id } => ("remove", "- REMOVE", node_id.clone()),
        EventKind::Heartbeat { node_id } => ("heartbeat", "♥ HEARTBEAT", node_id.clone()),
        EventKind::PathRequested => ("path", "→ PATH", "random 3-hop path requested".to_string()),
        EventKind::StaleCleanup { removed } => (
            "cleanup",
            "✗ CLEANUP",
            format!("{removed} stale node(s) removed"),
        ),
        EventKind::StatsQueried => ("stats", "ℹ STATS", "stats queried".to_string()),
        EventKind::HealthCheck { ready } => (
            "health",
            "ℹ HEALTH",
            if *ready {
                "check: ready".to_string()
            } else {
                "check: NOT ready".to_string()
            },
        ),
        EventKind::Error { message } => ("error", "✗ ERROR", message.clone()),
    };
    EventEntry {
        elapsed_secs,
        event_type: event_type.to_string(),
        label: label.to_string(),
        detail,
    }
}

/// Single endpoint for the web dashboard UI (polled every 3 s).
pub async fn dashboard_handler(State(state): State<AppState>) -> Json<DashboardResponse> {
    let registry = state.registry.read().await;
    let nodes: Vec<NodeWithMetrics> = registry
        .get_all_entries()
        .into_iter()
        .map(|e| NodeWithMetrics {
            descriptor: e.descriptor.clone(),
            metrics: e.metrics.clone(),
        })
        .collect();
    let stats = registry.get_stats();
    let ready = registry.is_ready();
    drop(registry);

    let (metrics, events) = match &state.metrics {
        Some(m) => {
            let summary = MetricsSummary {
                registrations: m.get_registrations(),
                removals: m.get_removals(),
                heartbeats: m.get_heartbeats(),
                path_requests: m.get_path_requests(),
                stale_cleaned: m.get_stale_cleaned(),
                uptime_secs: m.uptime().as_secs(),
            };
            let mut evts = m.events.snapshot(event_to_entry);
            evts.reverse(); // newest first
            evts.truncate(50);
            (summary, evts)
        }
        None => (
            MetricsSummary {
                registrations: 0,
                removals: 0,
                heartbeats: 0,
                path_requests: 0,
                stale_cleaned: 0,
                uptime_secs: 0,
            },
            Vec::new(),
        ),
    };

    Json(DashboardResponse {
        nodes,
        stats,
        metrics,
        ready,
        events,
    })
}

fn mime_for_path(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript",
        Some("wasm") => "application/wasm",
        Some("css") => "text/css",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("svg") => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

/// Serve embedded web UI assets. Maps `/` → `index.html`; all other paths are
/// looked up directly in the embedded `web-dist/` bundle.
pub async fn serve_asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match crate::assets::Asset::get(path) {
        Some(content) => {
            let mime = mime_for_path(path);
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime)],
                content.data.into_owned(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
