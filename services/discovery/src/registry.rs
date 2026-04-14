use crate::error::RegistryError;
use crate::metrics::DiscoveryMetrics;
use common::{NodeDescriptor, NodeType};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;

/// Shared application state for Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<tokio::sync::RwLock<NodeRegistry>>,
    pub metrics: Option<Arc<DiscoveryMetrics>>,
}

/// Entry in the node registry.
#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub descriptor: NodeDescriptor,
    pub registered_at: Instant,
    pub last_heartbeat: Instant,
}

impl NodeEntry {
    fn new(d: NodeDescriptor, reg: Instant, last: Instant) -> Self {
        Self {
            descriptor: d,
            registered_at: reg,
            last_heartbeat: last,
        }
    }
}

/// Consensus document for disk persistence.
#[derive(Debug, Serialize, Deserialize)]
struct Consensus {
    generated_at: chrono::DateTime<chrono::Utc>,
    nodes: Vec<NodeDescriptor>,
}

impl Consensus {
    fn new(gen_at: chrono::DateTime<chrono::Utc>, nodes: Vec<NodeDescriptor>) -> Self {
        Self {
            generated_at: gen_at,
            nodes,
        }
    }
}

/// Registry statistics snapshot.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RegistryStats {
    pub total_nodes: usize,
    pub entry_count: usize,
    pub middle_count: usize,
    pub exit_count: usize,
    pub oldest_node_age_secs: Option<u64>,
    pub newest_node_age_secs: Option<u64>,
}

impl RegistryStats {
    fn new(
        total: usize,
        entry_c: usize,
        middle_c: usize,
        exit_c: usize,
        oldest: Option<u64>,
        newest: Option<u64>,
    ) -> Self {
        Self {
            total_nodes: total,
            entry_count: entry_c,
            middle_count: middle_c,
            exit_count: exit_c,
            oldest_node_age_secs: oldest,
            newest_node_age_secs: newest,
        }
    }
}

/// Node registry storing all registered relay nodes.
pub struct NodeRegistry {
    nodes: HashMap<String, NodeEntry>,
    consensus_path: PathBuf,
}

impl NodeRegistry {
    pub fn new(consensus_path: PathBuf) -> Self {
        Self {
            nodes: HashMap::new(),
            consensus_path,
        }
    }

    pub async fn load(&mut self) -> anyhow::Result<()> {
        if !self.consensus_path.exists() {
            tracing::info!("No consensus file found, starting fresh");
            return Ok(());
        }

        let data = fs::read_to_string(&self.consensus_path).await?;
        let consensus: Consensus = serde_json::from_str(&data)?;

        let now = Instant::now();
        for node in consensus.nodes.into_iter() {
            let node_id = node.node_id.clone();
            let entry = NodeEntry::new(node, now, now);
            self.nodes.insert(node_id, entry);
        }

        tracing::info!("Loaded {} nodes from consensus", self.nodes.len());
        Ok(())
    }

    pub async fn save(&self) -> anyhow::Result<()> {
        let consensus = Consensus::new(chrono::Utc::now(), self.get_all_nodes());

        let json = serde_json::to_string_pretty(&consensus)?;
        fs::write(&self.consensus_path, json).await?;

        tracing::debug!("Saved consensus with {} nodes", self.nodes.len());
        Ok(())
    }

    pub fn register_node(&mut self, descriptor: NodeDescriptor) {
        let node_id = descriptor.node_id.clone();
        let addr = descriptor.address;
        let now = Instant::now();

        self.nodes
            .retain(|id, entry| id == &node_id || entry.descriptor.address != addr);

        match self.nodes.contains_key(&node_id) {
            false => {
                let entry = NodeEntry::new(descriptor, now, now);
                self.nodes.insert(node_id.clone(), entry);
                tracing::info!("Registered new node: {}", node_id);
            }
            true => {
                if let Some(entry) = self.nodes.get_mut(&node_id) {
                    entry.descriptor = descriptor;
                    entry.last_heartbeat = now;
                    tracing::info!("Updated node: {}", node_id);
                }
            }
        }
    }

    pub fn get_all_nodes(&self) -> Vec<NodeDescriptor> {
        self.nodes
            .values()
            .map(|entry| entry.descriptor.clone())
            .collect()
    }

    pub(crate) fn get_nodes_by_type(&self, node_type: NodeType) -> Vec<NodeDescriptor> {
        self.nodes
            .values()
            .filter(|entry| entry.descriptor.node_type.eq(&node_type))
            .map(|entry| entry.descriptor.clone())
            .collect()
    }

    /// Get a random N-hop path: 1 entry + (count-2) middles + 1 exit.
    /// `count` must be >= 3.
    pub fn get_random_path(&self, count: usize) -> Result<Vec<NodeDescriptor>, RegistryError> {
        if count < 3 {
            return Err(RegistryError::InsufficientNodes(format!(
                "hop count must be >= 3, got {count}"
            )));
        }

        let entry_nodes = self.get_nodes_by_type(NodeType::Entry);
        let middle_nodes = self.get_nodes_by_type(NodeType::Middle);
        let exit_nodes = self.get_nodes_by_type(NodeType::Exit);

        if entry_nodes.is_empty() {
            return Err(RegistryError::InsufficientNodes(
                "No entry nodes available".to_string(),
            ));
        }
        let middle_count = count - 2;

        if middle_nodes.is_empty() {
            return Err(RegistryError::InsufficientNodes(
                "No middle nodes available".to_string(),
            ));
        }
        if middle_nodes.len() < middle_count {
            return Err(RegistryError::InsufficientNodes(format!(
                "Need {middle_count} unique middle nodes for a {count}-hop circuit, \
                 only {} registered",
                middle_nodes.len()
            )));
        }
        if exit_nodes.is_empty() {
            return Err(RegistryError::InsufficientNodes(
                "No exit nodes available".to_string(),
            ));
        }

        let mut rng = rand::rng();

        // Select middle nodes WITHOUT replacement so the same relay cannot appear
        // twice in the same circuit (duplicate hops corrupt per-hop cipher state).
        let mut available_middles = middle_nodes;
        let mut path = Vec::with_capacity(count);
        path.push(Self::select_weighted_node(&entry_nodes, &mut rng)?);
        for _ in 0..middle_count {
            let idx = Self::select_weighted_index(&available_middles, &mut rng)?;
            let node = available_middles.remove(idx);
            path.push(node);
        }
        path.push(Self::select_weighted_node(&exit_nodes, &mut rng)?);

        Ok(path)
    }

    fn select_weighted_node<R: Rng>(
        nodes: &[NodeDescriptor],
        rng: &mut R,
    ) -> Result<NodeDescriptor, RegistryError> {
        let idx = Self::select_weighted_index(nodes, rng)?;
        nodes
            .get(idx)
            .cloned()
            .ok_or_else(|| RegistryError::InsufficientNodes("Empty node list".to_string()))
    }

    /// Return the index of a bandwidth-weighted random node from `nodes`.
    fn select_weighted_index<R: Rng>(
        nodes: &[NodeDescriptor],
        rng: &mut R,
    ) -> Result<usize, RegistryError> {
        if nodes.is_empty() {
            return Err(RegistryError::InsufficientNodes("Empty node list".to_string()));
        }

        let total_bandwidth: u64 = nodes.iter().map(|n| n.bandwidth).sum();

        if total_bandwidth == 0 {
            return Ok(rng.random_range(0..nodes.len()));
        }

        let mut random_weight = rng.random_range(0..total_bandwidth);

        for (i, node) in nodes.iter().enumerate() {
            if random_weight < node.bandwidth {
                return Ok(i);
            }
            random_weight -= node.bandwidth;
        }

        Ok(nodes.len() - 1)
    }

    pub fn update_heartbeat(&mut self, node_id: &str) -> Result<(), RegistryError> {
        let entry = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| RegistryError::NodeNotFound(node_id.to_string()))?;

        entry.last_heartbeat = Instant::now();
        tracing::debug!("Updated heartbeat for node: {}", node_id);
        Ok(())
    }

    pub fn remove_node(&mut self, node_id: &str) -> Result<(), RegistryError> {
        self.nodes
            .remove(node_id)
            .ok_or_else(|| RegistryError::NodeNotFound(node_id.to_string()))?;

        tracing::info!("Removed node: {}", node_id);
        Ok(())
    }

    pub fn cleanup_stale_nodes(&mut self, timeout: Duration) -> usize {
        let now = Instant::now();
        let before_count = self.nodes.len();

        self.nodes.retain(|node_id, entry| {
            let is_stale = now.duration_since(entry.last_heartbeat) > timeout;
            if is_stale {
                tracing::warn!("Removing stale node: {}", node_id);
            }
            !is_stale
        });

        let removed = before_count - self.nodes.len();
        if removed > 0 {
            tracing::info!("Cleaned up {} stale nodes", removed);
        }
        removed
    }

    pub fn is_ready(&self) -> bool {
        !self.get_nodes_by_type(NodeType::Entry).is_empty()
            && !self.get_nodes_by_type(NodeType::Middle).is_empty()
            && !self.get_nodes_by_type(NodeType::Exit).is_empty()
    }

    pub fn get_stats(&self) -> RegistryStats {
        let mut entry_count = 0;
        let mut middle_count = 0;
        let mut exit_count = 0;
        let mut oldest_registration: Option<Instant> = None;
        let mut newest_registration: Option<Instant> = None;

        for entry in self.nodes.values() {
            match entry.descriptor.node_type {
                NodeType::Entry => entry_count += 1,
                NodeType::Middle => middle_count += 1,
                NodeType::Exit => exit_count += 1,
            }

            match oldest_registration {
                None => oldest_registration = Some(entry.registered_at),
                Some(oldest) if entry.registered_at < oldest => {
                    oldest_registration = Some(entry.registered_at)
                }
                _ => {}
            }

            match newest_registration {
                None => newest_registration = Some(entry.registered_at),
                Some(newest) if entry.registered_at > newest => {
                    newest_registration = Some(entry.registered_at)
                }
                _ => {}
            }
        }

        let now = Instant::now();
        let oldest_node_age_secs = oldest_registration.map(|t| now.duration_since(t).as_secs());
        let newest_node_age_secs = newest_registration.map(|t| now.duration_since(t).as_secs());

        RegistryStats::new(
            self.nodes.len(),
            entry_count,
            middle_count,
            exit_count,
            oldest_node_age_secs,
            newest_node_age_secs,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use common::PublicKey;

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

    fn make_registry() -> NodeRegistry {
        NodeRegistry::new(PathBuf::from("/tmp/test-consensus.json"))
    }

    #[test]
    fn test_register_and_get_all() {
        let mut reg = make_registry();
        reg.register_node(make_node("node-1", NodeType::Entry, 1_000_000));

        let nodes = reg.get_all_nodes();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "node-1");
        assert_eq!(nodes[0].node_type, NodeType::Entry);
    }

    #[test]
    fn test_register_multiple() {
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("middle-1", NodeType::Middle, 2_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 3_000_000));

        let nodes = reg.get_all_nodes();
        assert_eq!(nodes.len(), 3);
    }

    #[test]
    fn test_register_duplicate_updates() {
        let mut reg = make_registry();
        reg.register_node(make_node("node-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("node-1", NodeType::Entry, 5_000_000));

        let nodes = reg.get_all_nodes();
        assert_eq!(nodes.len(), 1, "duplicate should update, not add");
        assert_eq!(nodes[0].bandwidth, 5_000_000, "bandwidth should be updated");
    }

    #[test]
    fn test_get_nodes_by_type() {
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("entry-2", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));

        assert_eq!(reg.get_nodes_by_type(NodeType::Entry).len(), 2);
        assert_eq!(reg.get_nodes_by_type(NodeType::Middle).len(), 1);
        assert_eq!(reg.get_nodes_by_type(NodeType::Exit).len(), 1);
    }

    #[test]
    fn test_get_random_path_success() {
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));

        let path = reg.get_random_path(3).unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[0].node_type, NodeType::Entry);
        assert_eq!(path[1].node_type, NodeType::Middle);
        assert_eq!(path[2].node_type, NodeType::Exit);
    }

    #[test]
    fn test_get_random_path_no_entry() {
        let mut reg = make_registry();
        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));

        let err = reg.get_random_path(3).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientNodes(_)));
    }

    #[test]
    fn test_get_random_path_no_middle() {
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));

        let err = reg.get_random_path(3).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientNodes(_)));
    }

    #[test]
    fn test_get_random_path_no_exit() {
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));

        let err = reg.get_random_path(3).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientNodes(_)));
    }

    #[test]
    fn test_get_random_path_empty() {
        let reg = make_registry();

        let err = reg.get_random_path(3).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientNodes(_)));
    }

    #[test]
    fn test_update_heartbeat_existing() {
        let mut reg = make_registry();
        reg.register_node(make_node("node-1", NodeType::Entry, 1_000_000));

        assert!(reg.update_heartbeat("node-1").is_ok());
    }

    #[test]
    fn test_update_heartbeat_missing() {
        let mut reg = make_registry();

        let err = reg.update_heartbeat("nonexistent").unwrap_err();
        assert!(matches!(err, RegistryError::NodeNotFound(_)));
    }

    #[test]
    fn test_remove_node_existing() {
        let mut reg = make_registry();
        reg.register_node(make_node("node-1", NodeType::Entry, 1_000_000));

        assert!(reg.remove_node("node-1").is_ok());
        assert!(reg.get_all_nodes().is_empty());
    }

    #[test]
    fn test_remove_node_missing() {
        let mut reg = make_registry();

        let err = reg.remove_node("nonexistent").unwrap_err();
        assert!(matches!(err, RegistryError::NodeNotFound(_)));
    }

    #[test]
    fn test_cleanup_stale_nodes() {
        let mut reg = make_registry();
        reg.register_node(make_node("node-1", NodeType::Entry, 1_000_000));

        std::thread::sleep(Duration::from_millis(50));

        let removed = reg.cleanup_stale_nodes(Duration::from_millis(10));
        assert_eq!(removed, 1);
        assert!(reg.get_all_nodes().is_empty());
    }

    #[test]
    fn test_is_ready() {
        let mut reg = make_registry();

        assert!(!reg.is_ready());

        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        assert!(!reg.is_ready());

        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));
        assert!(!reg.is_ready());

        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));
        assert!(reg.is_ready());
    }

    #[test]
    fn test_get_stats() {
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("entry-2", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));

        let stats = reg.get_stats();
        assert_eq!(stats.total_nodes, 4);
        assert_eq!(stats.entry_count, 2);
        assert_eq!(stats.middle_count, 1);
        assert_eq!(stats.exit_count, 1);
        assert!(stats.oldest_node_age_secs.is_some());
        assert!(stats.newest_node_age_secs.is_some());
    }

    #[test]
    fn test_get_stats_empty() {
        let reg = make_registry();

        let stats = reg.get_stats();
        assert_eq!(stats.total_nodes, 0);
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.middle_count, 0);
        assert_eq!(stats.exit_count, 0);
        assert!(stats.oldest_node_age_secs.is_none());
        assert!(stats.newest_node_age_secs.is_none());
    }

    #[test]
    fn test_get_random_path_4_hops() {
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("middle-2", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));

        let path = reg.get_random_path(4).unwrap();
        assert_eq!(path.len(), 4);
        assert_eq!(path[0].node_type, NodeType::Entry);
        assert_eq!(path[1].node_type, NodeType::Middle);
        assert_eq!(path[2].node_type, NodeType::Middle);
        assert_eq!(path[3].node_type, NodeType::Exit);
    }

    #[test]
    fn test_get_random_path_5_hops() {
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("middle-2", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("middle-3", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));

        let path = reg.get_random_path(5).unwrap();
        assert_eq!(path.len(), 5);
        assert_eq!(path[0].node_type, NodeType::Entry);
        assert_eq!(path[1].node_type, NodeType::Middle);
        assert_eq!(path[2].node_type, NodeType::Middle);
        assert_eq!(path[3].node_type, NodeType::Middle);
        assert_eq!(path[4].node_type, NodeType::Exit);
    }

    #[test]
    fn test_get_random_path_insufficient_middles() {
        // Only 1 middle node available — 5-hop path needs 3 unique middles, must fail.
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));

        let err = reg.get_random_path(5).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientNodes(_)));
    }

    #[test]
    fn test_get_random_path_middles_unique() {
        // 2 middles, 4-hop path needs 2 unique middles — should succeed with distinct nodes.
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("middle-2", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));

        let path = reg.get_random_path(4).unwrap();
        assert_eq!(path.len(), 4);
        // The two middle hops must be different nodes.
        assert_ne!(path[1].node_id, path[2].node_id);
    }

    #[test]
    fn test_get_random_path_count_below_minimum() {
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));

        let err = reg.get_random_path(2).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientNodes(_)));
    }

    #[test]
    fn test_get_random_path_count_1_rejected() {
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));

        let err = reg.get_random_path(1).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientNodes(_)));
    }
}
