//! Integration tests for the Discovery service gRPC API.
//!
//! These tests exercise the full gRPC layer via tonic's in-process transport.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use common::{NodeDescriptor, NodeMetrics, NodeType, PublicKey};
use discovery::api::grpc::DiscoveryServiceImpl;
use discovery::core::registry::{AppState, NodeRegistry};
use proto::services::{
    GetAllNodesResponse, GetRandomPathRequest, HeartbeatRequest, RemoveNodeRequest,
    discovery_client::DiscoveryClient, discovery_server::DiscoveryServer,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::{Channel, Server};

/// Build a fresh `AppState` (empty registry, no persistence).
fn fresh_state() -> AppState {
    AppState {
        registry: Arc::new(RwLock::new(NodeRegistry::new(false))),
        metrics: None,
    }
}

/// Create a minimal `NodeDescriptor` for testing.
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

/// Start an in-process gRPC server on a random port and return a connected client.
async fn start_test_server(state: AppState) -> DiscoveryClient<Channel> {
    let svc = DiscoveryServiceImpl::new(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        Server::builder()
            .add_service(DiscoveryServer::new(svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();

    DiscoveryClient::new(channel)
}

/// Helper: register the standard 3-node set (entry, middle, exit).
async fn register_three_nodes(client: &mut DiscoveryClient<Channel>) {
    let nodes = [
        make_node("entry-1", NodeType::Entry, 1_000_000),
        make_node("middle-1", NodeType::Middle, 2_000_000),
        make_node("exit-1", NodeType::Exit, 3_000_000),
    ];
    for node in &nodes {
        let proto_node: proto::types::NodeDescriptor = node.clone().into();
        client
            .register_node(tonic::Request::new(proto_node))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn test_register_node_success() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    let node = make_node("node-1", NodeType::Entry, 1_000_000);
    let proto_node: proto::types::NodeDescriptor = node.into();
    let response = client.register_node(tonic::Request::new(proto_node)).await;
    assert!(response.is_ok());
}

#[tokio::test]
async fn test_register_node_empty_id_returns_error() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    let node = make_node("", NodeType::Entry, 1_000_000);
    let proto_node: proto::types::NodeDescriptor = node.into();
    let response = client.register_node(tonic::Request::new(proto_node)).await;
    assert!(response.is_err());
    let status = response.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_register_node_zero_bandwidth_returns_error() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    let node = make_node("node-1", NodeType::Entry, 0);
    let proto_node: proto::types::NodeDescriptor = node.into();
    let response = client.register_node(tonic::Request::new(proto_node)).await;
    assert!(response.is_err());
    let status = response.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_get_all_nodes_empty() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    let response = client.get_all_nodes(tonic::Request::new(())).await.unwrap();
    let body: GetAllNodesResponse = response.into_inner();
    assert_eq!(body.count, 0);
    assert!(body.nodes.is_empty());
}

#[tokio::test]
async fn test_get_all_nodes_after_registration() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    register_three_nodes(&mut client).await;

    let response = client.get_all_nodes(tonic::Request::new(())).await.unwrap();
    let body: GetAllNodesResponse = response.into_inner();
    assert_eq!(body.count, 3);
    assert_eq!(body.nodes.len(), 3);
}

#[tokio::test]
async fn test_get_random_path_success() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    register_three_nodes(&mut client).await;

    let request = tonic::Request::new(GetRandomPathRequest { count: 3 });
    let response = client.get_random_path(request).await.unwrap();
    let path = response.into_inner().nodes;
    assert_eq!(path.len(), 3);
    assert_eq!(path[0].node_type(), proto::types::NodeType::Entry);
    assert_eq!(path[1].node_type(), proto::types::NodeType::Middle);
    assert_eq!(path[2].node_type(), proto::types::NodeType::Exit);
}

#[tokio::test]
async fn test_get_random_path_insufficient_nodes_returns_error() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    let node = make_node("entry-1", NodeType::Entry, 1_000_000);
    let proto_node: proto::types::NodeDescriptor = node.into();
    client
        .register_node(tonic::Request::new(proto_node))
        .await
        .unwrap();

    let request = tonic::Request::new(GetRandomPathRequest { count: 3 });
    let response = client.get_random_path(request).await;
    assert!(response.is_err());
    let status = response.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
}

#[tokio::test]
async fn test_heartbeat_success() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    let node = make_node("node-1", NodeType::Entry, 1_000_000);
    let proto_node: proto::types::NodeDescriptor = node.into();
    client
        .register_node(tonic::Request::new(proto_node))
        .await
        .unwrap();

    let metrics: proto::types::NodeMetrics = NodeMetrics::default().into();
    let request = tonic::Request::new(HeartbeatRequest {
        node_id: "node-1".to_string(),
        metrics: Some(metrics),
    });
    let response = client.update_heartbeat(request).await;
    assert!(response.is_ok());
}

#[tokio::test]
async fn test_heartbeat_not_found() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    let metrics: proto::types::NodeMetrics = NodeMetrics::default().into();
    let request = tonic::Request::new(HeartbeatRequest {
        node_id: "nonexistent".to_string(),
        metrics: Some(metrics),
    });
    let response = client.update_heartbeat(request).await;
    assert!(response.is_err());
    let status = response.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_remove_node_success() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    let node = make_node("node-1", NodeType::Entry, 1_000_000);
    let proto_node: proto::types::NodeDescriptor = node.into();
    client
        .register_node(tonic::Request::new(proto_node))
        .await
        .unwrap();

    let request = tonic::Request::new(RemoveNodeRequest {
        node_id: "node-1".to_string(),
    });
    client.remove_node(request).await.unwrap();

    let response = client.get_all_nodes(tonic::Request::new(())).await.unwrap();
    assert_eq!(response.into_inner().count, 0);
}

#[tokio::test]
async fn test_remove_node_not_found() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    let request = tonic::Request::new(RemoveNodeRequest {
        node_id: "nonexistent".to_string(),
    });
    let response = client.remove_node(request).await;
    assert!(response.is_err());
    let status = response.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_get_stats() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    register_three_nodes(&mut client).await;

    let response = client.get_stats(tonic::Request::new(())).await.unwrap();
    let stats = response.into_inner();
    assert_eq!(stats.total_nodes, 3);
    assert_eq!(stats.entry_count, 1);
    assert_eq!(stats.middle_count, 1);
    assert_eq!(stats.exit_count, 1);
}

#[tokio::test]
async fn test_health_check_not_ready() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    let response = client.health_check(tonic::Request::new(())).await.unwrap();
    let health = response.into_inner();
    assert_eq!(health.status, "ok");
    assert!(!health.ready);
    assert!(health.message.unwrap().contains("Insufficient"));
}

#[tokio::test]
async fn test_health_check_ready() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    register_three_nodes(&mut client).await;

    let response = client.health_check(tonic::Request::new(())).await.unwrap();
    let health = response.into_inner();
    assert_eq!(health.status, "ok");
    assert!(health.ready);
    assert!(health.message.is_none());
}

#[tokio::test]
async fn test_readiness_check_not_ready() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    let response = client.readiness_check(tonic::Request::new(())).await;
    assert!(response.is_err());
    let status = response.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
}

#[tokio::test]
async fn test_readiness_check_ready() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    register_three_nodes(&mut client).await;

    let response = client.readiness_check(tonic::Request::new(())).await;
    assert!(response.is_ok());
}

/// Full workflow: register 3 nodes → ready → random path → remove 1 → not ready
#[tokio::test]
async fn test_full_workflow() {
    let state = fresh_state();
    let mut client = start_test_server(state).await;

    // 1. Not ready initially
    let response = client.readiness_check(tonic::Request::new(())).await;
    assert!(response.is_err());

    // 2. Register 3 nodes
    register_three_nodes(&mut client).await;

    // 3. Now ready
    let response = client.readiness_check(tonic::Request::new(())).await;
    assert!(response.is_ok());

    // 4. Random path works
    let request = tonic::Request::new(GetRandomPathRequest { count: 3 });
    let response = client.get_random_path(request).await.unwrap();
    assert_eq!(response.into_inner().nodes.len(), 3);

    // 5. Remove the exit node
    let request = tonic::Request::new(RemoveNodeRequest {
        node_id: "exit-1".to_string(),
    });
    client.remove_node(request).await.unwrap();

    // 6. No longer ready (missing exit)
    let response = client.readiness_check(tonic::Request::new(())).await;
    assert!(response.is_err());

    // 7. Random path fails
    let request = tonic::Request::new(GetRandomPathRequest { count: 3 });
    let response = client.get_random_path(request).await;
    assert!(response.is_err());
}
