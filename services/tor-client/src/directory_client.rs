use anyhow::{Context, Result};
use common::NodeDescriptor;
use reqwest::Client;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// HTTP client for the discovery service API.
pub struct DirectoryClient {
    http_client: Client,
    directory_url: String,
    #[allow(dead_code)]
    cached_nodes: Vec<NodeDescriptor>,
    #[allow(dead_code)]
    cache_expiry: Option<Instant>,
    #[allow(dead_code)]
    cache_ttl: Duration,
}

impl DirectoryClient {
    pub fn new(directory_url: String) -> Self {
        Self {
            http_client: Client::new(),
            directory_url,
            cached_nodes: Vec::new(),
            cache_expiry: None,
            cache_ttl: Duration::from_secs(300),
        }
    }

    /// Fetch a random N-hop path from the directory (1 entry + (hop_count-2) middles + 1 exit).
    pub async fn get_random_path(&self, hop_count: usize) -> Result<Vec<NodeDescriptor>> {
        let url = format!(
            "{}/api/nodes/random?count={}",
            self.directory_url, hop_count
        );
        debug!("Fetching {}-hop random path from {}", hop_count, url);

        let nodes = self
            .http_client
            .get(&url)
            .send()
            .await
            .context("Failed to send request to directory service")?
            .error_for_status()
            .context("Directory service returned error")?
            .json::<Vec<NodeDescriptor>>()
            .await
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

        let url = format!("{}/api/nodes", self.directory_url);
        debug!("Fetching all nodes from {}", url);

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .context("Failed to send request to directory service")?
            .error_for_status()
            .context("Directory service returned error")?
            .json::<NodesResponse>()
            .await
            .context("Failed to parse nodes response")?;

        self.cached_nodes = response.nodes.clone();
        self.cache_expiry = Some(Instant::now() + self.cache_ttl);

        info!("Fetched {} nodes from directory", response.nodes.len());

        Ok(response.nodes)
    }

    #[allow(dead_code)]
    pub fn is_cache_valid(&self) -> bool {
        self.cache_expiry
            .map(|expiry| Instant::now() < expiry)
            .unwrap_or(false)
    }
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct NodesResponse {
    nodes: Vec<NodeDescriptor>,
    #[allow(dead_code)]
    count: usize,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_new_client_defaults() {
        let client = DirectoryClient::new("http://localhost:8080".to_string());
        assert!(client.cached_nodes.is_empty());
        assert!(client.cache_expiry.is_none());
        assert_eq!(client.cache_ttl, Duration::from_secs(300));
    }

    #[test]
    fn test_cache_initially_invalid() {
        let client = DirectoryClient::new("http://localhost:8080".to_string());
        assert!(!client.is_cache_valid());
    }

    #[test]
    fn test_cache_valid_after_set() {
        let mut client = DirectoryClient::new("http://localhost:8080".to_string());
        client.cache_expiry = Some(Instant::now() + Duration::from_secs(60));
        assert!(client.is_cache_valid());
    }

    #[test]
    fn test_cache_expired() {
        let mut client = DirectoryClient::new("http://localhost:8080".to_string());
        client.cache_expiry = Some(Instant::now() - Duration::from_secs(1));
        assert!(!client.is_cache_valid());
    }
}
