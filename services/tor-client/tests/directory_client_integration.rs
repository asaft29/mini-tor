//! Integration tests for the `DirectoryClient` using `wiremock` mock HTTP server.
//!
//! These tests verify that `DirectoryClient` correctly calls the discovery
//! service endpoints, parses responses, handles errors, and manages caching.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use common::{NodeDescriptor, NodeType, PublicKey};
use tor_client::directory_client::DirectoryClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Create a minimal `NodeDescriptor` for mock responses.
fn make_node(id: &str, node_type: NodeType) -> NodeDescriptor {
    NodeDescriptor::new(
        id.to_string(),
        node_type,
        "127.0.0.1:9001".parse().unwrap(),
        PublicKey::new([0u8; 32]),
        1_000_000,
        None,
    )
}

#[tokio::test]
async fn test_get_random_path_success() {
    let mock_server = MockServer::start().await;

    let nodes = vec![
        make_node("entry-1", NodeType::Entry),
        make_node("middle-1", NodeType::Middle),
        make_node("exit-1", NodeType::Exit),
    ];

    Mock::given(method("GET"))
        .and(path("/api/nodes/random"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&nodes))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = DirectoryClient::new(mock_server.uri());
    let result = client.get_random_path(3).await.unwrap();

    assert_eq!(result.len(), 3);
    assert_eq!(result[0].node_id, "entry-1");
    assert_eq!(result[0].node_type, NodeType::Entry);
    assert_eq!(result[1].node_id, "middle-1");
    assert_eq!(result[1].node_type, NodeType::Middle);
    assert_eq!(result[2].node_id, "exit-1");
    assert_eq!(result[2].node_type, NodeType::Exit);
}

#[tokio::test]
async fn test_get_random_path_server_error_503() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/nodes/random"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Insufficient nodes"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = DirectoryClient::new(mock_server.uri());
    let result = client.get_random_path(3).await;

    assert!(result.is_err());
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("error"),
        "Error message should indicate server error: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_get_random_path_wrong_count() {
    let mock_server = MockServer::start().await;

    // Return only 2 nodes instead of 3
    let nodes = vec![
        make_node("entry-1", NodeType::Entry),
        make_node("middle-1", NodeType::Middle),
    ];

    Mock::given(method("GET"))
        .and(path("/api/nodes/random"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&nodes))
        .expect(1)
        .mount(&mock_server)
        .await;

    let client = DirectoryClient::new(mock_server.uri());
    let result = client.get_random_path(3).await;

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("Expected 3 nodes"),
        "Should report wrong count: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_get_all_nodes_success() {
    let mock_server = MockServer::start().await;

    let nodes = vec![
        make_node("entry-1", NodeType::Entry),
        make_node("middle-1", NodeType::Middle),
        make_node("exit-1", NodeType::Exit),
    ];

    let body = serde_json::json!({
        "nodes": nodes,
        "count": 3,
    });

    Mock::given(method("GET"))
        .and(path("/api/nodes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut client = DirectoryClient::new(mock_server.uri());
    let result = client.get_all_nodes().await.unwrap();

    assert_eq!(result.len(), 3);
    assert_eq!(result[0].node_id, "entry-1");
}

#[tokio::test]
async fn test_get_all_nodes_caching() {
    let mock_server = MockServer::start().await;

    let nodes = vec![make_node("entry-1", NodeType::Entry)];
    let body = serde_json::json!({
        "nodes": nodes,
        "count": 1,
    });

    // Server should only be hit once — second call uses cache
    Mock::given(method("GET"))
        .and(path("/api/nodes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut client = DirectoryClient::new(mock_server.uri());

    // First call — hits server
    let result1 = client.get_all_nodes().await.unwrap();
    assert_eq!(result1.len(), 1);
    assert!(client.is_cache_valid());

    // Second call — returns cached
    let result2 = client.get_all_nodes().await.unwrap();
    assert_eq!(result2.len(), 1);

    // wiremock `expect(1)` validates the server was only hit once
}

#[tokio::test]
async fn test_get_all_nodes_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/nodes"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut client = DirectoryClient::new(mock_server.uri());
    let result = client.get_all_nodes().await;

    assert!(result.is_err());
    assert!(
        !client.is_cache_valid(),
        "Cache should remain invalid after error"
    );
}
