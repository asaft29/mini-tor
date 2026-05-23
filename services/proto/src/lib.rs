use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub mod discovery {
    tonic::include_proto!("discovery");

    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("discovery_descriptor");
}

// ── NodeType ────────────────────────────────────────────────────────────────

impl From<common::NodeType> for discovery::NodeType {
    fn from(t: common::NodeType) -> Self {
        match t {
            common::NodeType::Entry => discovery::NodeType::Entry,
            common::NodeType::Middle => discovery::NodeType::Middle,
            common::NodeType::Exit => discovery::NodeType::Exit,
        }
    }
}

impl TryFrom<discovery::NodeType> for common::NodeType {
    type Error = tonic::Status;

    fn try_from(t: discovery::NodeType) -> Result<Self, Self::Error> {
        match t {
            discovery::NodeType::Entry => Ok(common::NodeType::Entry),
            discovery::NodeType::Middle => Ok(common::NodeType::Middle),
            discovery::NodeType::Exit => Ok(common::NodeType::Exit),
            discovery::NodeType::Unspecified => {
                Err(tonic::Status::invalid_argument("NodeType unspecified"))
            }
        }
    }
}

// ── PublicKey ───────────────────────────────────────────────────────────────

impl From<common::PublicKey> for discovery::PublicKey {
    fn from(pk: common::PublicKey) -> Self {
        discovery::PublicKey {
            bytes: pk.bytes.to_vec(),
        }
    }
}

impl TryFrom<&discovery::PublicKey> for common::PublicKey {
    type Error = tonic::Status;

    fn try_from(pk: &discovery::PublicKey) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = pk
            .bytes
            .get(..)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| tonic::Status::invalid_argument("PublicKey must be exactly 32 bytes"))?;
        Ok(common::PublicKey::new(bytes))
    }
}

// ── ExitPolicy ──────────────────────────────────────────────────────────────

impl From<common::ExitPolicy> for discovery::ExitPolicy {
    fn from(policy: common::ExitPolicy) -> Self {
        discovery::ExitPolicy {
            allowed_ports: policy.allowed_ports.iter().map(|&p| p as u32).collect(),
            blocked_ports: policy.blocked_ports.iter().map(|&p| p as u32).collect(),
            allowed_ips: policy.allowed_ips.iter().map(ip_to_bytes).collect(),
            blocked_ips: policy.blocked_ips.iter().map(ip_to_bytes).collect(),
        }
    }
}

impl TryFrom<&discovery::ExitPolicy> for common::ExitPolicy {
    type Error = tonic::Status;

    fn try_from(policy: &discovery::ExitPolicy) -> Result<Self, Self::Error> {
        let allowed_ips = policy
            .allowed_ips
            .iter()
            .map(|b| ip_from_bytes(b))
            .collect::<Result<Vec<_>, _>>()?;
        let blocked_ips = policy
            .blocked_ips
            .iter()
            .map(|b| ip_from_bytes(b))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(common::ExitPolicy {
            allowed_ports: policy.allowed_ports.iter().map(|&p| p as u16).collect(),
            blocked_ports: policy.blocked_ports.iter().map(|&p| p as u16).collect(),
            allowed_ips,
            blocked_ips,
        })
    }
}

fn ip_to_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

#[allow(clippy::result_large_err)]
fn ip_from_bytes(bytes: &[u8]) -> Result<IpAddr, tonic::Status> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes
                .try_into()
                .map_err(|_| tonic::Status::invalid_argument("Invalid IPv4 bytes"))?;
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        16 => {
            let octets: [u8; 16] = bytes
                .try_into()
                .map_err(|_| tonic::Status::invalid_argument("Invalid IPv6 bytes"))?;
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(tonic::Status::invalid_argument(format!(
            "Invalid IP byte length: {}",
            bytes.len()
        ))),
    }
}

// ── NodeDescriptor ──────────────────────────────────────────────────────────

impl From<common::NodeDescriptor> for discovery::NodeDescriptor {
    fn from(d: common::NodeDescriptor) -> Self {
        discovery::NodeDescriptor {
            node_id: d.node_id,
            node_type: discovery::NodeType::from(d.node_type) as i32,
            address: d.address.to_string(),
            public_key: Some(discovery::PublicKey::from(d.public_key)),
            bandwidth: d.bandwidth,
            exit_policy: d.exit_policy.map(discovery::ExitPolicy::from),
            operator_id: d.operator_id,
            tls_cert_fingerprint: d.tls_cert_fingerprint,
        }
    }
}

impl TryFrom<&discovery::NodeDescriptor> for common::NodeDescriptor {
    type Error = tonic::Status;

    fn try_from(d: &discovery::NodeDescriptor) -> Result<Self, Self::Error> {
        let node_type = discovery::NodeType::try_from(d.node_type)
            .map_err(|e| tonic::Status::invalid_argument(format!("Invalid node type: {}", e)))?;
        let node_type = common::NodeType::try_from(node_type)?;
        let address: SocketAddr = d
            .address
            .parse()
            .map_err(|e| tonic::Status::invalid_argument(format!("Invalid address: {}", e)))?;
        let public_key = match &d.public_key {
            Some(pk) => common::PublicKey::try_from(pk)?,
            None => {
                return Err(tonic::Status::invalid_argument("PublicKey is required"));
            }
        };
        let exit_policy = match &d.exit_policy {
            Some(ep) => Some(common::ExitPolicy::try_from(ep)?),
            None => None,
        };
        Ok(common::NodeDescriptor {
            node_id: d.node_id.clone(),
            node_type,
            address,
            public_key,
            bandwidth: d.bandwidth,
            exit_policy,
            operator_id: d.operator_id.clone(),
            tls_cert_fingerprint: d.tls_cert_fingerprint.clone(),
        })
    }
}

// ── NodeMetrics ─────────────────────────────────────────────────────────────

impl From<common::NodeMetrics> for discovery::NodeMetrics {
    fn from(m: common::NodeMetrics) -> Self {
        discovery::NodeMetrics {
            connections_accepted: m.connections_accepted,
            circuits_active: m.circuits_active,
            circuits_created: m.circuits_created,
            circuits_destroyed: m.circuits_destroyed,
            bytes_forwarded: m.bytes_forwarded,
            bytes_received: m.bytes_received,
            streams_opened: m.streams_opened,
            uptime_secs: m.uptime_secs,
        }
    }
}

impl From<&discovery::NodeMetrics> for common::NodeMetrics {
    fn from(m: &discovery::NodeMetrics) -> Self {
        common::NodeMetrics {
            connections_accepted: m.connections_accepted,
            circuits_active: m.circuits_active,
            circuits_created: m.circuits_created,
            circuits_destroyed: m.circuits_destroyed,
            bytes_forwarded: m.bytes_forwarded,
            bytes_received: m.bytes_received,
            streams_opened: m.streams_opened,
            uptime_secs: m.uptime_secs,
        }
    }
}

// ── RegistryStats ───────────────────────────────────────────────────────────

/// Conversion from proto `RegistryStats` to a raw struct with typed fields.
/// The discovery crate's `RegistryStats` uses this conversion in its gRPC handler.
pub struct RegistryStatsConverted {
    pub total_nodes: usize,
    pub entry_count: usize,
    pub middle_count: usize,
    pub exit_count: usize,
    pub oldest_node_age_secs: Option<u64>,
    pub newest_node_age_secs: Option<u64>,
}

impl From<discovery::RegistryStats> for RegistryStatsConverted {
    fn from(s: discovery::RegistryStats) -> Self {
        RegistryStatsConverted {
            total_nodes: s.total_nodes as usize,
            entry_count: s.entry_count as usize,
            middle_count: s.middle_count as usize,
            exit_count: s.exit_count as usize,
            oldest_node_age_secs: s.oldest_node_age_secs,
            newest_node_age_secs: s.newest_node_age_secs,
        }
    }
}
