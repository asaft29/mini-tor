//! Integration tests for the Discovery service REST API.
//!
//! These tests exercise the full HTTP layer (handlers, routing, error mapping)
//! via `tower::ServiceExt::oneshot()` — no TCP listener required.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use axum::body::Body;
use common::{NodeDescriptor, NodeMetrics, NodeType, PublicKey};
use discovery::registry::{AppState, NodeRegistry};
use discovery::routes::build_router;
use http::Request;
use http_body_util::BodyExt;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;

/// Build a fresh `AppState` (empty registry, no persistence).
fn fresh_state() -> AppState {
    AppState {
        registry: Arc::new(RwLock::new(NodeRegistry::new(false))),
        metrics: None,
    }
}

/// Create a minimal `NodeDescriptor` for testing.
/// Each (id) gets a unique port to avoid address-based dedup in the registry.
fn make_node(id: &str, node_type: NodeType, bandwidth: u64) -> NodeDescriptor {
    let port: u16 = 9000 + id.bytes().map(|b| b as u16).sum::<u16>() % 1000;
    NodeDescriptor::new(
        id.to_string(),
        node_type,
        format!("127.0.0.1:{}", port).parse().unwrap(),
        PublicKey::new([0u8; 32]),
        bandwidth,
        None,
    )
}

/// Serialize a `NodeDescriptor` to a JSON `Body`.
fn json_body(node: &NodeDescriptor) -> Body {
    Body::from(serde_json::to_string(node).unwrap())
}

/// Read the entire response body as a `String`.
async fn body_string(body: Body) -> String {
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Helper: register a node via POST and return the status code.
async fn register(state: &AppState, node: &NodeDescriptor) -> http::StatusCode {
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/nodes/register")
        .header("content-type", "application/json")
        .body(json_body(node))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    resp.status()
}

/// Helper: register the standard 3-node set (entry, middle, exit).
async fn register_three_nodes(state: &AppState) {
    register(state, &make_node("entry-1", NodeType::Entry, 1_000_000)).await;
    register(state, &make_node("middle-1", NodeType::Middle, 2_000_000)).await;
    register(state, &make_node("exit-1", NodeType::Exit, 3_000_000)).await;
}

#[tokio::test]
async fn test_register_node_success() {
    let state = fresh_state();
    let node = make_node("node-1", NodeType::Entry, 1_000_000);

    let status = register(&state, &node).await;
    assert_eq!(status, http::StatusCode::CREATED);
}

#[tokio::test]
async fn test_register_node_empty_id_returns_422() {
    let state = fresh_state();
    let node = make_node("", NodeType::Entry, 1_000_000);

    let status = register(&state, &node).await;
    assert_eq!(status, http::StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_register_node_zero_bandwidth_returns_422() {
    let state = fresh_state();
    let node = make_node("node-1", NodeType::Entry, 0);

    let status = register(&state, &node).await;
    assert_eq!(status, http::StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_get_all_nodes_empty() {
    let state = fresh_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/nodes")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["count"], 0);
    assert!(json["nodes"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_get_all_nodes_after_registration() {
    let state = fresh_state();
    register_three_nodes(&state).await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .uri("/api/nodes")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["count"], 3);
    assert_eq!(json["nodes"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_get_random_path_success() {
    let state = fresh_state();
    register_three_nodes(&state).await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .uri("/api/nodes/random")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = body_string(resp.into_body()).await;
    let path: Vec<NodeDescriptor> = serde_json::from_str(&body).unwrap();
    assert_eq!(path.len(), 3);
    assert_eq!(path[0].node_type, NodeType::Entry);
    assert_eq!(path[1].node_type, NodeType::Middle);
    assert_eq!(path[2].node_type, NodeType::Exit);
}

#[tokio::test]
async fn test_get_random_path_insufficient_nodes_returns_503() {
    let state = fresh_state();
    // Only register an entry — missing middle and exit
    register(&state, &make_node("entry-1", NodeType::Entry, 1_000_000)).await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .uri("/api/nodes/random")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_heartbeat_success() {
    let state = fresh_state();
    register(&state, &make_node("node-1", NodeType::Entry, 1_000_000)).await;

    let metrics = NodeMetrics::default();
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/nodes/node-1/heartbeat")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&metrics).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
}

#[tokio::test]
async fn test_heartbeat_not_found() {
    let state = fresh_state();

    let metrics = NodeMetrics::default();
    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/api/nodes/nonexistent/heartbeat")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&metrics).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_remove_node_success() {
    let state = fresh_state();
    register(&state, &make_node("node-1", NodeType::Entry, 1_000_000)).await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/nodes/node-1")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);

    // Verify the node is gone
    let app = build_router(state.clone());
    let req = Request::builder()
        .uri("/api/nodes")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["count"], 0);
}

#[tokio::test]
async fn test_remove_node_not_found() {
    let state = fresh_state();

    let app = build_router(state);
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/nodes/nonexistent")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_stats() {
    let state = fresh_state();
    register_three_nodes(&state).await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .uri("/api/stats")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["total_nodes"], 3);
    assert_eq!(json["entry_count"], 1);
    assert_eq!(json["middle_count"], 1);
    assert_eq!(json["exit_count"], 1);
}

#[tokio::test]
async fn test_health_check_not_ready() {
    let state = fresh_state();

    let app = build_router(state);
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["ready"], false);
    assert!(json["message"].as_str().unwrap().contains("Insufficient"));
}

#[tokio::test]
async fn test_health_check_ready() {
    let state = fresh_state();
    register_three_nodes(&state).await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = body_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["ready"], true);
    assert!(json["message"].is_null());
}

#[tokio::test]
async fn test_readiness_check_not_ready() {
    let state = fresh_state();

    let app = build_router(state);
    let req = Request::builder()
        .uri("/ready")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_readiness_check_ready() {
    let state = fresh_state();
    register_three_nodes(&state).await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .uri("/ready")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
}

/// Full workflow: register 3 nodes → ready → random path → remove 1 → not ready
#[tokio::test]
async fn test_full_workflow() {
    let state = fresh_state();

    // 1. Not ready initially
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::SERVICE_UNAVAILABLE);

    // 2. Register 3 nodes
    register_three_nodes(&state).await;

    // 3. Now ready
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);

    // 4. Random path works
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/nodes/random")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body = body_string(resp.into_body()).await;
    let path: Vec<NodeDescriptor> = serde_json::from_str(&body).unwrap();
    assert_eq!(path.len(), 3);

    // 5. Remove the exit node
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/nodes/exit-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);

    // 6. No longer ready (missing exit)
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::SERVICE_UNAVAILABLE);

    // 7. Random path fails
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/nodes/random")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::SERVICE_UNAVAILABLE);
}
