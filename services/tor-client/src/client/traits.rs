use anyhow::Result;
use async_trait::async_trait;
use common::NodeDescriptor;

/// Abstraction over the directory service for path selection.
/// Enables mocking in tests and swapping the transport layer without
/// changing circuit-building logic.
#[async_trait]
pub trait NodeDirectory: Send + Sync {
    async fn get_random_path(&self, hop_count: usize) -> Result<Vec<NodeDescriptor>>;
}
