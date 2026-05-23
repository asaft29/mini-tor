use anyhow::{Context, Result};
use common::NodeDescriptor;
use proto::discovery::{GetRandomPathRequest, discovery_client::DiscoveryClient};
use std::time::{Duration, Instant};
use tonic::transport::Channel;
use tracing::{debug, info};

/// gRPC client for the discovery service.
pub struct DirectoryClient {
    grpc_client: DiscoveryClient<Channel>,
    #[allow(dead_code)]
    cached_nodes: Vec<NodeDescriptor>,
    #[allow(dead_code)]
    cache_expiry: Option<Instant>,
    #[allow(dead_code)]
    cache_ttl: Duration,
}

impl DirectoryClient {
    pub async fn new(directory_url: String) -> Result<Self> {
        let channel = Channel::from_shared(directory_url)?
            .connect()
            .await
            .context("Failed to connect to discovery gRPC service")?;
        Ok(Self {
            grpc_client: DiscoveryClient::new(channel),
            cached_nodes: Vec::new(),
            cache_expiry: None,
            cache_ttl: Duration::from_secs(300),
        })
    }

    pub fn from_channel(channel: Channel) -> Self {
        Self {
            grpc_client: DiscoveryClient::new(channel),
            cached_nodes: Vec::new(),
            cache_expiry: None,
            cache_ttl: Duration::from_secs(300),
        }
    }

    /// Fetch a random N-hop path from the directory (1 entry + (hop_count-2) middles + 1 exit).
    pub async fn get_random_path(&self, hop_count: usize) -> Result<Vec<NodeDescriptor>> {
        debug!("Fetching {}-hop random path via gRPC", hop_count);

        let request = tonic::Request::new(GetRandomPathRequest {
            count: hop_count as u32,
        });

        let response = self
            .grpc_client
            .clone()
            .get_random_path(request)
            .await
            .context("Failed to get random path from discovery service")?;

        let nodes: Vec<NodeDescriptor> = response
            .into_inner()
            .nodes
            .iter()
            .map(NodeDescriptor::try_from)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse node descriptors")?;

        if nodes.len() != hop_count {
            return Err(anyhow::anyhow!(
                "Expected {} nodes from directory, got {}",
                hop_count,
                nodes.len()
            ));
        }

        info!(
            "Got {}-hop random path: {}",
            nodes.len(),
            nodes
                .iter()
                .map(|n| n.address.to_string())
                .collect::<Vec<_>>()
                .join(" -> ")
        );

        Ok(nodes)
    }

    /// Fetch all registered nodes (cached for 5 minutes).
    #[allow(dead_code)]
    pub async fn get_all_nodes(&mut self) -> Result<Vec<NodeDescriptor>> {
        if let Some(expiry) = self.cache_expiry
            && Instant::now() < expiry
        {
            debug!(
                "Returning cached node list ({} nodes)",
                self.cached_nodes.len()
            );
            return Ok(self.cached_nodes.clone());
        }

        debug!("Fetching all nodes via gRPC");

        let response = self
            .grpc_client
            .clone()
            .get_all_nodes(tonic::Request::new(()))
            .await
            .context("Failed to get all nodes from discovery service")?;

        let nodes: Vec<NodeDescriptor> = response
            .into_inner()
            .nodes
            .iter()
            .map(NodeDescriptor::try_from)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse node descriptors")?;

        self.cached_nodes = nodes.clone();
        self.cache_expiry = Some(Instant::now() + self.cache_ttl);

        info!("Fetched {} nodes from directory", nodes.len());

        Ok(nodes)
    }

    #[allow(dead_code)]
    pub fn is_cache_valid(&self) -> bool {
        self.cache_expiry
            .map(|expiry| Instant::now() < expiry)
            .unwrap_or(false)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_initially_invalid() {
        // Test via from_channel without connecting
        let client = DirectoryClient::from_channel(
            Channel::from_static("http://localhost:8080").connect_lazy(),
        );
        assert!(!client.is_cache_valid());
    }
}
