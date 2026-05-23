use crate::error::RegistryError;
use crate::metrics::EventKind;
use crate::registry::AppState;
use proto::services::{
    GetAllNodesResponse, GetRandomPathRequest, GetRandomPathResponse, HealthCheckResponse,
    HeartbeatRequest, RegisterResponse, RemoveNodeRequest, discovery_server::Discovery,
};
use proto::types::{NodeDescriptor as ProtoNodeDescriptor, RegistryStats as ProtoRegistryStats};
use std::sync::atomic::Ordering;
use tonic::{Request, Response, Status};

pub struct DiscoveryServiceImpl {
    state: AppState,
}

impl DiscoveryServiceImpl {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl Discovery for DiscoveryServiceImpl {
    // ── Health & Readiness ───────────────────────────────────────────────────

    async fn health_check(
        &self,
        _request: Request<()>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let registry = self.state.registry.read().await;
        let ready = registry.is_ready();

        if let Some(m) = &self.state.metrics {
            m.push_event(EventKind::HealthCheck { ready });
        }

        let response = HealthCheckResponse {
            status: "ok".to_string(),
            ready,
            message: if ready {
                None
            } else {
                Some("Insufficient nodes to build circuits. Need at least 1 entry, 1 middle, and 1 exit node.".to_string())
            },
        };
        Ok(Response::new(response))
    }

    async fn readiness_check(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        let registry = self.state.registry.read().await;

        if registry.is_ready() {
            Ok(Response::new(()))
        } else {
            Err(Status::unavailable(
                "Insufficient nodes to build circuits. Need at least 1 entry, 1 middle, and 1 exit node.",
            ))
        }
    }

    // ── Node Management ──────────────────────────────────────────────────────

    async fn register_node(
        &self,
        request: Request<ProtoNodeDescriptor>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let proto_desc = request.into_inner();
        let descriptor = common::NodeDescriptor::try_from(&proto_desc)?;

        if descriptor.node_id.is_empty() {
            return Err(Status::invalid_argument("Node ID cannot be empty"));
        }
        if descriptor.bandwidth == 0 {
            return Err(Status::invalid_argument("Bandwidth must be greater than 0"));
        }

        let node_id = descriptor.node_id.clone();
        let node_type = descriptor.node_type.to_string();
        let address = descriptor.address.to_string();

        let mut registry = self.state.registry.write().await;
        registry.register_node(descriptor);

        if let Some(m) = &self.state.metrics {
            m.registrations.fetch_add(1, Ordering::Relaxed);
            m.push_event(EventKind::NodeRegistered {
                node_id,
                node_type,
                address,
            });
        }

        Ok(Response::new(RegisterResponse {
            message: "Node registered successfully".to_string(),
        }))
    }

    async fn remove_node(
        &self,
        request: Request<RemoveNodeRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let node_id = req.node_id;

        let mut registry = self.state.registry.write().await;
        registry.remove_node(&node_id).map_err(|e| match e {
            RegistryError::NodeNotFound(_) => Status::not_found(e.to_string()),
            other => Status::internal(other.to_string()),
        })?;

        if let Some(m) = &self.state.metrics {
            m.removals.fetch_add(1, Ordering::Relaxed);
            m.push_event(EventKind::NodeRemoved {
                node_id: node_id.clone(),
            });
        }

        Ok(Response::new(()))
    }

    // ── Heartbeat ────────────────────────────────────────────────────────────

    async fn update_heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let node_id = req.node_id;
        let metrics = req
            .metrics
            .ok_or_else(|| Status::invalid_argument("Metrics are required"))?;
        let metrics: common::NodeMetrics = (&metrics).into();

        let mut registry = self.state.registry.write().await;
        registry
            .update_heartbeat_with_metrics(&node_id, metrics)
            .map_err(|e| match e {
                RegistryError::NodeNotFound(_) => Status::not_found(e.to_string()),
                other => Status::internal(other.to_string()),
            })?;

        if let Some(m) = &self.state.metrics {
            m.heartbeats.fetch_add(1, Ordering::Relaxed);
            m.push_event(EventKind::Heartbeat {
                node_id: node_id.clone(),
            });
        }

        Ok(Response::new(()))
    }

    // ── Query ────────────────────────────────────────────────────────────────

    async fn get_all_nodes(
        &self,
        _request: Request<()>,
    ) -> Result<Response<GetAllNodesResponse>, Status> {
        let registry = self.state.registry.read().await;
        let nodes = registry.get_all_nodes();
        let count = nodes.len() as u64;
        let nodes: Vec<ProtoNodeDescriptor> =
            nodes.into_iter().map(ProtoNodeDescriptor::from).collect();

        Ok(Response::new(GetAllNodesResponse { nodes, count }))
    }

    async fn get_random_path(
        &self,
        request: Request<GetRandomPathRequest>,
    ) -> Result<Response<GetRandomPathResponse>, Status> {
        let req = request.into_inner();
        let count = (req.count as usize).max(3);

        let registry = self.state.registry.read().await;
        let path = registry.get_random_path(count).map_err(|e| match e {
            RegistryError::InsufficientNodes(_) => Status::unavailable(e.to_string()),
            other => Status::internal(other.to_string()),
        })?;

        if let Some(m) = &self.state.metrics {
            m.path_requests.fetch_add(1, Ordering::Relaxed);
            m.push_event(EventKind::PathRequested);
        }

        let nodes: Vec<ProtoNodeDescriptor> =
            path.into_iter().map(ProtoNodeDescriptor::from).collect();

        Ok(Response::new(GetRandomPathResponse { nodes }))
    }

    async fn get_stats(
        &self,
        _request: Request<()>,
    ) -> Result<Response<ProtoRegistryStats>, Status> {
        let registry = self.state.registry.read().await;
        let stats = registry.get_stats();

        if let Some(m) = &self.state.metrics {
            m.push_event(EventKind::StatsQueried);
        }

        Ok(Response::new(ProtoRegistryStats {
            total_nodes: stats.total_nodes as u64,
            entry_count: stats.entry_count as u64,
            middle_count: stats.middle_count as u64,
            exit_count: stats.exit_count as u64,
            oldest_node_age_secs: stats.oldest_node_age_secs,
            newest_node_age_secs: stats.newest_node_age_secs,
        }))
    }
}
