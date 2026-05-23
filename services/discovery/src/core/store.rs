use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::api::error::RegistryError;
use crate::core::registry::{NodeEntry, NodeRegistry, RegistryStats};
use common::{NodeDescriptor, NodeMetrics};

/// Abstraction over the node registry storage.
/// Enables unit-testing gRPC handlers and swapping persistence backends
/// without changing any call sites.
#[async_trait]
pub trait NodeStore: Send + Sync {
    async fn get_all_nodes(&self) -> Vec<NodeDescriptor>;
    async fn get_all_entries(&self) -> Vec<NodeEntry>;
    async fn get_random_path(&self, count: usize) -> Result<Vec<NodeDescriptor>, RegistryError>;
    async fn get_stats(&self) -> RegistryStats;
    async fn is_ready(&self) -> bool;
    async fn register_node(&self, descriptor: NodeDescriptor);
    async fn update_heartbeat_with_metrics(
        &self,
        node_id: &str,
        metrics: NodeMetrics,
    ) -> Result<(), RegistryError>;
    async fn remove_node(&self, node_id: &str) -> Result<(), RegistryError>;
    async fn cleanup_stale_nodes(&self, timeout: Duration) -> usize;
}

/// Wraps the in-memory `NodeRegistry` behind an `Arc<RwLock<>>`,
/// implementing the `NodeStore` trait with internal locking.
pub struct NodeRegistryStore {
    inner: Arc<RwLock<NodeRegistry>>,
}

impl NodeRegistryStore {
    pub fn new(inner: Arc<RwLock<NodeRegistry>>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl NodeStore for NodeRegistryStore {
    async fn get_all_nodes(&self) -> Vec<NodeDescriptor> {
        self.inner.read().await.get_all_nodes()
    }

    async fn get_all_entries(&self) -> Vec<NodeEntry> {
        self.inner
            .read()
            .await
            .get_all_entries()
            .into_iter()
            .cloned()
            .collect()
    }

    async fn get_random_path(&self, count: usize) -> Result<Vec<NodeDescriptor>, RegistryError> {
        self.inner.read().await.get_random_path(count)
    }

    async fn get_stats(&self) -> RegistryStats {
        self.inner.read().await.get_stats()
    }

    async fn is_ready(&self) -> bool {
        self.inner.read().await.is_ready()
    }

    async fn register_node(&self, descriptor: NodeDescriptor) {
        self.inner.write().await.register_node(descriptor);
    }

    async fn update_heartbeat_with_metrics(
        &self,
        node_id: &str,
        metrics: NodeMetrics,
    ) -> Result<(), RegistryError> {
        self.inner
            .write()
            .await
            .update_heartbeat_with_metrics(node_id, metrics)
    }

    async fn remove_node(&self, node_id: &str) -> Result<(), RegistryError> {
        self.inner.write().await.remove_node(node_id)
    }

    async fn cleanup_stale_nodes(&self, timeout: Duration) -> usize {
        self.inner.write().await.cleanup_stale_nodes(timeout)
    }
}
