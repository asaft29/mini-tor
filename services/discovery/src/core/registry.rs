use crate::api::error::RegistryError;
use crate::core::metrics::DiscoveryMetrics;
use common::{NodeDescriptor, NodeMetrics, NodeType};
use rand::Rng;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    pub metrics: Option<NodeMetrics>,
}

impl NodeEntry {
    fn new(d: NodeDescriptor, reg: Instant, last: Instant) -> Self {
        Self {
            descriptor: d,
            registered_at: reg,
            last_heartbeat: last,
            metrics: None,
        }
    }
}

/// Registry statistics snapshot.
#[derive(Debug, Serialize)]
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
    allow_same_ip: bool,
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self::new(false)
    }
}

impl NodeRegistry {
    pub fn new(allow_same_ip: bool) -> Self {
        Self {
            nodes: HashMap::new(),
            allow_same_ip,
        }
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

    pub fn get_all_entries(&self) -> Vec<&NodeEntry> {
        self.nodes.values().collect()
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

        // Running exclusion sets for IPs and operator families already committed
        // to the circuit. Loopback IPs are exempt so localhost demos still work.
        // When --allow-same-ip is set, IP exclusion is skipped entirely.
        let mut excluded_ips = std::collections::HashSet::<std::net::IpAddr>::new();
        let mut excluded_ops = std::collections::HashSet::<String>::new();

        // Pick exit first — it has the most constraints (exit policy).
        let exit_node = Self::select_weighted_node(&exit_nodes, &mut rng)?;
        if !self.allow_same_ip && !exit_node.address.ip().is_loopback() {
            excluded_ips.insert(exit_node.address.ip());
        }
        if let Some(op) = exit_node.operator_id.as_deref() {
            excluded_ops.insert(op.to_owned());
        }

        // Pick entry — reject if it shares an IP or operator_id with exit.
        let entry_node = Self::select_weighted_node(&entry_nodes, &mut rng)?;
        if !self.allow_same_ip
            && !entry_node.address.ip().is_loopback()
            && excluded_ips.contains(&entry_node.address.ip())
        {
            return Err(RegistryError::InsufficientNodes(
                "entry and exit share the same IP address".into(),
            ));
        }
        if let Some(op) = entry_node.operator_id.as_deref() {
            if excluded_ops.contains(op) {
                return Err(RegistryError::InsufficientNodes(
                    "entry and exit share the same operator_id".into(),
                ));
            }
            excluded_ops.insert(op.to_owned());
        }
        if !self.allow_same_ip && !entry_node.address.ip().is_loopback() {
            excluded_ips.insert(entry_node.address.ip());
        }

        // Pick each middle in turn; exclusion sets grow after every pick so
        // middle-vs-middle IP and operator conflicts are caught too.
        let mut path = Vec::with_capacity(count);
        path.push(entry_node);

        let mut available_middles = middle_nodes;
        for slot in 0..middle_count {
            available_middles.retain(|n| {
                let ip_ok = self.allow_same_ip
                    || n.address.ip().is_loopback()
                    || !excluded_ips.contains(&n.address.ip());
                let op_ok = n
                    .operator_id
                    .as_deref()
                    .is_none_or(|op| !excluded_ops.contains(op));
                ip_ok && op_ok
            });
            let remaining_slots = middle_count - slot;
            if available_middles.len() < remaining_slots {
                return Err(RegistryError::InsufficientNodes(format!(
                    "Not enough unique-IP/operator middle nodes: need {remaining_slots} more, {} remain",
                    available_middles.len()
                )));
            }
            let idx = Self::select_weighted_index(&available_middles, &mut rng)?;
            let node = available_middles.remove(idx);
            if !self.allow_same_ip && !node.address.ip().is_loopback() {
                excluded_ips.insert(node.address.ip());
            }
            if let Some(op) = node.operator_id.as_deref() {
                excluded_ops.insert(op.to_owned());
            }
            path.push(node);
        }

        path.push(exit_node);
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
            return Err(RegistryError::InsufficientNodes(
                "Empty node list".to_string(),
            ));
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

    pub fn update_heartbeat_with_metrics(
        &mut self,
        node_id: &str,
        metrics: NodeMetrics,
    ) -> Result<(), RegistryError> {
        let entry = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| RegistryError::NodeNotFound(node_id.to_string()))?;

        entry.last_heartbeat = Instant::now();
        entry.metrics = Some(metrics);
        tracing::debug!("Updated heartbeat (with metrics) for node: {}", node_id);
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
        NodeRegistry::new(false)
    }

    fn make_registry_allow_same_ip() -> NodeRegistry {
        NodeRegistry::new(true)
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

    // ---- IP exclusion tests (Phase A) ----

    fn make_node_with_ip(id: &str, node_type: NodeType, ip: &str, bw: u64) -> NodeDescriptor {
        // Derive a unique port from the id so nodes with the same IP but different
        // ids get distinct SocketAddrs (registry.register_node evicts on address match).
        let port: u16 = 9000 + id.bytes().map(|b| b as u16).sum::<u16>() % 1000;
        let addr: std::net::SocketAddr = format!("{ip}:{port}").parse().unwrap();
        NodeDescriptor::new(
            id.to_string(),
            node_type,
            addr,
            PublicKey::new([0u8; 32]),
            bw,
            None,
        )
    }

    #[test]
    fn test_ip_exclusion_loopback_exempt() {
        // All nodes on 127.0.0.1 — the loopback exemption must keep the demo working.
        let mut reg = make_registry();
        reg.register_node(make_node("entry-1", NodeType::Entry, 1_000_000));
        reg.register_node(make_node("middle-1", NodeType::Middle, 1_000_000));
        reg.register_node(make_node("exit-1", NodeType::Exit, 1_000_000));

        let path = reg.get_random_path(3).unwrap();
        assert_eq!(path.len(), 3);
    }

    #[test]
    fn test_ip_exclusion_different_ips_succeeds() {
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip(
            "entry-1",
            NodeType::Entry,
            "1.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "middle-1",
            NodeType::Middle,
            "2.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "exit-1",
            NodeType::Exit,
            "3.0.0.1",
            1_000_000,
        ));

        let path = reg.get_random_path(3).unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[0].node_type, NodeType::Entry);
        assert_eq!(path[1].node_type, NodeType::Middle);
        assert_eq!(path[2].node_type, NodeType::Exit);
    }

    #[test]
    fn test_ip_exclusion_entry_exit_same_ip() {
        // Entry and exit on the same non-loopback IP — must be rejected.
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip(
            "entry-1",
            NodeType::Entry,
            "1.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "middle-1",
            NodeType::Middle,
            "2.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "exit-1",
            NodeType::Exit,
            "1.0.0.1",
            1_000_000,
        ));

        let err = reg.get_random_path(3).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientNodes(_)));
    }

    #[test]
    fn test_ip_exclusion_middle_shares_entry_ip() {
        // middle-1 shares IP with entry — only middle-2 is valid.
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip(
            "entry-1",
            NodeType::Entry,
            "1.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "middle-1",
            NodeType::Middle,
            "1.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "middle-2",
            NodeType::Middle,
            "2.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "exit-1",
            NodeType::Exit,
            "3.0.0.1",
            1_000_000,
        ));

        let path = reg.get_random_path(3).unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[1].node_id, "middle-2");
    }

    #[test]
    fn test_ip_exclusion_middle_shares_exit_ip() {
        // middle-1 shares IP with exit — only middle-2 is valid.
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip(
            "entry-1",
            NodeType::Entry,
            "1.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "middle-1",
            NodeType::Middle,
            "3.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "middle-2",
            NodeType::Middle,
            "2.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "exit-1",
            NodeType::Exit,
            "3.0.0.1",
            1_000_000,
        ));

        let path = reg.get_random_path(3).unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[1].node_id, "middle-2");
    }

    #[test]
    fn test_ip_exclusion_two_middles_same_ip() {
        // 4-hop circuit: middle-1 and middle-2 share an IP — only one can be picked.
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip(
            "entry-1",
            NodeType::Entry,
            "1.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "middle-1",
            NodeType::Middle,
            "2.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "middle-2",
            NodeType::Middle,
            "2.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "middle-3",
            NodeType::Middle,
            "4.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "exit-1",
            NodeType::Exit,
            "3.0.0.1",
            1_000_000,
        ));

        let path = reg.get_random_path(4).unwrap();
        assert_eq!(path.len(), 4);
        // The two middles must have different IPs.
        assert_ne!(path[1].address.ip(), path[2].address.ip());
    }

    #[test]
    fn test_ip_exclusion_not_enough_after_filter() {
        // All middles share the entry IP — no valid middle remains.
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip(
            "entry-1",
            NodeType::Entry,
            "1.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "middle-1",
            NodeType::Middle,
            "1.0.0.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "exit-1",
            NodeType::Exit,
            "3.0.0.1",
            1_000_000,
        ));

        let err = reg.get_random_path(3).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientNodes(_)));
    }

    // ---- operator_id exclusion tests (Phase B) ----

    fn make_node_with_ip_and_op(
        id: &str,
        node_type: NodeType,
        ip: &str,
        op: Option<&str>,
        bw: u64,
    ) -> NodeDescriptor {
        let port: u16 = 9000 + id.bytes().map(|b| b as u16).sum::<u16>() % 1000;
        let addr: std::net::SocketAddr = format!("{ip}:{port}").parse().unwrap();
        let mut n = NodeDescriptor::new(
            id.to_string(),
            node_type,
            addr,
            PublicKey::new([0u8; 32]),
            bw,
            None,
        );
        n.operator_id = op.map(str::to_owned);
        n
    }

    #[test]
    fn test_operator_id_entry_exit_same() {
        // Entry and exit tagged with same operator_id — must be rejected even on different IPs.
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip_and_op(
            "entry-1",
            NodeType::Entry,
            "1.0.0.1",
            Some("alice"),
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "middle-1",
            NodeType::Middle,
            "2.0.0.1",
            None,
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "exit-1",
            NodeType::Exit,
            "3.0.0.1",
            Some("alice"),
            1_000_000,
        ));

        let err = reg.get_random_path(3).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientNodes(_)));
    }

    #[test]
    fn test_operator_id_middle_excluded() {
        // middle-1 shares operator_id with entry — only middle-2 (untagged) is valid.
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip_and_op(
            "entry-1",
            NodeType::Entry,
            "1.0.0.1",
            Some("alice"),
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "middle-1",
            NodeType::Middle,
            "2.0.0.1",
            Some("alice"),
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "middle-2",
            NodeType::Middle,
            "3.0.0.1",
            None,
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "exit-1",
            NodeType::Exit,
            "4.0.0.1",
            None,
            1_000_000,
        ));

        let path = reg.get_random_path(3).unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[1].node_id, "middle-2");
    }

    #[test]
    fn test_operator_id_none_never_excluded() {
        // All nodes have operator_id: None — path selection must succeed normally.
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip_and_op(
            "entry-1",
            NodeType::Entry,
            "1.0.0.1",
            None,
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "middle-1",
            NodeType::Middle,
            "2.0.0.1",
            None,
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "exit-1",
            NodeType::Exit,
            "3.0.0.1",
            None,
            1_000_000,
        ));

        let path = reg.get_random_path(3).unwrap();
        assert_eq!(path.len(), 3);
    }

    #[test]
    fn test_operator_id_mixed() {
        // entry tagged "alice", middle-1 also "alice", middle-2 untagged → middle-2 selected.
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip_and_op(
            "entry-1",
            NodeType::Entry,
            "1.0.0.1",
            Some("alice"),
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "middle-1",
            NodeType::Middle,
            "2.0.0.1",
            Some("alice"),
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "middle-2",
            NodeType::Middle,
            "3.0.0.1",
            None,
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "exit-1",
            NodeType::Exit,
            "4.0.0.1",
            Some("bob"),
            1_000_000,
        ));

        let path = reg.get_random_path(3).unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[1].node_id, "middle-2");
    }

    #[test]
    fn test_operator_id_8hop_fails_when_not_enough_untagged_middles() {
        // 8 hops = 1 entry + 6 middles + 1 exit.
        // entry + 2 middles share "alice" → only 5 middles remain after filtering → should fail.
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip_and_op(
            "entry-1",
            NodeType::Entry,
            "1.0.0.1",
            Some("alice"),
            1_000_000,
        ));
        // 2 middles tagged "alice" — both will be excluded
        reg.register_node(make_node_with_ip_and_op(
            "middle-alice-1",
            NodeType::Middle,
            "2.0.0.1",
            Some("alice"),
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "middle-alice-2",
            NodeType::Middle,
            "3.0.0.1",
            Some("alice"),
            1_000_000,
        ));
        // 5 untagged middles — need 6, only 5 available after filtering
        for i in 0..5_u8 {
            reg.register_node(make_node_with_ip_and_op(
                &format!("middle-{i}"),
                NodeType::Middle,
                &format!("10.0.{i}.1"),
                None,
                1_000_000,
            ));
        }
        reg.register_node(make_node_with_ip_and_op(
            "exit-1",
            NodeType::Exit,
            "20.0.0.1",
            None,
            1_000_000,
        ));

        let err = reg.get_random_path(8).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientNodes(_)));
    }

    #[test]
    fn test_operator_id_8hop_succeeds_with_enough_untagged_middles() {
        // 8 hops = 1 entry + 6 middles + 1 exit.
        // entry + 1 middle share "alice" → 6 untagged middles remain → should succeed.
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip_and_op(
            "entry-1",
            NodeType::Entry,
            "1.0.0.1",
            Some("alice"),
            1_000_000,
        ));
        // 1 middle tagged "alice" — excluded
        reg.register_node(make_node_with_ip_and_op(
            "middle-alice-1",
            NodeType::Middle,
            "2.0.0.1",
            Some("alice"),
            1_000_000,
        ));
        // 6 untagged middles — exactly enough
        for i in 0..6_u8 {
            reg.register_node(make_node_with_ip_and_op(
                &format!("middle-{i}"),
                NodeType::Middle,
                &format!("10.0.{i}.1"),
                None,
                1_000_000,
            ));
        }
        reg.register_node(make_node_with_ip_and_op(
            "exit-1",
            NodeType::Exit,
            "20.0.0.1",
            None,
            1_000_000,
        ));

        let path = reg.get_random_path(8).unwrap();
        assert_eq!(path.len(), 8);
        // No node in the path should have operator_id "alice" except entry
        for hop in path.iter().skip(1) {
            assert_ne!(hop.operator_id.as_deref(), Some("alice"));
        }
    }

    // ---- allow_same_ip tests ----

    #[test]
    fn test_allow_same_ip_non_loopback_succeeds() {
        let mut reg = make_registry_allow_same_ip();
        reg.register_node(make_node_with_ip(
            "entry-1",
            NodeType::Entry,
            "5.5.5.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "middle-1",
            NodeType::Middle,
            "5.5.5.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "exit-1",
            NodeType::Exit,
            "5.5.5.1",
            1_000_000,
        ));

        let path = reg.get_random_path(3).unwrap();
        assert_eq!(path.len(), 3);
    }

    #[test]
    fn test_allow_same_ip_operator_exclusion_still_works() {
        let mut reg = make_registry_allow_same_ip();
        reg.register_node(make_node_with_ip_and_op(
            "entry-1",
            NodeType::Entry,
            "5.5.5.1",
            Some("alice"),
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "middle-alice",
            NodeType::Middle,
            "5.5.5.1",
            Some("alice"),
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "middle-bob",
            NodeType::Middle,
            "5.5.5.1",
            None,
            1_000_000,
        ));
        reg.register_node(make_node_with_ip_and_op(
            "exit-1",
            NodeType::Exit,
            "5.5.5.1",
            None,
            1_000_000,
        ));

        let path = reg.get_random_path(3).unwrap();
        assert_eq!(path.len(), 3);
        for hop in path.iter().skip(1) {
            assert_ne!(hop.operator_id.as_deref(), Some("alice"));
        }
    }

    #[test]
    fn test_allow_same_ip_disabled_same_ip_fails() {
        let mut reg = make_registry();
        reg.register_node(make_node_with_ip(
            "entry-1",
            NodeType::Entry,
            "5.5.5.1",
            1_000_000,
        ));
        reg.register_node(make_node_with_ip(
            "exit-1",
            NodeType::Exit,
            "5.5.5.1",
            1_000_000,
        ));

        let err = reg.get_random_path(3).unwrap_err();
        assert!(matches!(err, RegistryError::InsufficientNodes(_)));
    }
}
