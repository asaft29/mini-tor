use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use common::metrics::TuiEvent;
use serde::Serialize;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::core::metrics::EventKind;
use crate::core::registry::AppState;

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
    /// Display label matching the TUI (e.g. "+ REGISTER", "heart HEARTBEAT").
    pub label: String,
    /// Human-readable detail string.
    pub detail: String,
}

/// A node descriptor combined with live metrics for the web dashboard.
#[derive(Debug, Serialize)]
pub struct NodeWithMetrics {
    #[serde(flatten)]
    pub descriptor: common::NodeDescriptor,
    pub metrics: Option<common::NodeMetrics>,
}

/// Combined response for the web dashboard — nodes, stats, metrics, and activity log.
#[derive(Debug, Serialize)]
pub struct DashboardResponse {
    pub nodes: Vec<NodeWithMetrics>,
    pub stats: crate::core::registry::RegistryStats,
    pub metrics: MetricsSummary,
    pub ready: bool,
    pub events: Vec<EventEntry>,
}

fn event_to_entry(e: &TuiEvent<EventKind>) -> EventEntry {
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
        EventKind::Heartbeat { node_id } => ("heartbeat", "heart HEARTBEAT", node_id.clone()),
        EventKind::PathRequested => ("path", "-> PATH", "random 3-hop path requested".to_string()),
        EventKind::StaleCleanup { removed } => (
            "cleanup",
            "x CLEANUP",
            format!("{removed} stale node(s) removed"),
        ),
        EventKind::StatsQueried => ("stats", "i STATS", "stats queried".to_string()),
        EventKind::HealthCheck { ready } => (
            "health",
            "i HEALTH",
            if *ready {
                "check: ready".to_string()
            } else {
                "check: NOT ready".to_string()
            },
        ),
        EventKind::Error { message } => ("error", "x ERROR", message.clone()),
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
    let entries = state.registry.get_all_entries().await;
    let nodes: Vec<NodeWithMetrics> = entries
        .into_iter()
        .map(|e| NodeWithMetrics {
            descriptor: e.descriptor,
            metrics: e.metrics,
        })
        .collect();
    let stats = state.registry.get_stats().await;
    let ready = state.registry.is_ready().await;

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
            evts.reverse();
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

/// Serve embedded web UI assets. Maps `/` -> `index.html`; all other paths are
/// looked up directly in the embedded `web-dist/` bundle.
pub async fn serve_asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match crate::core::assets::Asset::get(path) {
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

/// Build the Axum router for the web UI (REST dashboard + static assets).
pub fn build_web_router(state: AppState) -> Router {
    Router::new()
        .route("/api/dashboard", get(dashboard_handler))
        .with_state(state)
        .fallback(serve_asset)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}
