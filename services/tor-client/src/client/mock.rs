use anyhow::Result;
use async_trait::async_trait;
use common::NodeDescriptor;
use tokio::sync::Mutex;

use super::traits::NodeDirectory;

/// A mock directory that returns pre-configured paths for testing.
/// Paths are consumed from the queue in FIFO order.
pub struct MockDirectory {
    paths: Mutex<Vec<Vec<NodeDescriptor>>>,
}

impl MockDirectory {
    #[allow(dead_code)]
    pub fn new(paths: Vec<Vec<NodeDescriptor>>) -> Self {
        Self {
            paths: Mutex::new(paths),
        }
    }
}

#[async_trait]
impl NodeDirectory for MockDirectory {
    async fn get_random_path(&self, hop_count: usize) -> Result<Vec<NodeDescriptor>> {
        let path = self
            .paths
            .lock()
            .await
            .pop()
            .ok_or_else(|| anyhow::anyhow!("MockDirectory: no paths remaining"))?;
        if path.len() != hop_count {
            return Err(anyhow::anyhow!(
                "MockDirectory: expected {} nodes, got {}",
                hop_count,
                path.len()
            ));
        }
        Ok(path)
    }
}
