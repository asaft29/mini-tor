use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

/// Trait that combines AsyncRead + AsyncWrite for boxed relay streams.
pub trait RelayStreamTrait: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> RelayStreamTrait for T {}

/// A boxed stream that implements AsyncRead + AsyncWrite + Unpin + Send.
/// Used to abstract over TLS and plain TCP streams in relay-to-relay connections.
pub type RelayStream = Box<dyn RelayStreamTrait>;

/// Read half of a RelayStream.
pub type RelayReadHalf = ReadHalf<RelayStream>;

/// Write half of a RelayStream.
pub type RelayWriteHalf = WriteHalf<RelayStream>;

/// Node type in the Tor network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeType {
    Entry,
    Middle,
    Exit,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeType::Entry => write!(f, "entry"),
            NodeType::Middle => write!(f, "middle"),
            NodeType::Exit => write!(f, "exit"),
        }
    }
}

impl std::str::FromStr for NodeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "entry" => Ok(NodeType::Entry),
            "middle" => Ok(NodeType::Middle),
            "exit" => Ok(NodeType::Exit),
            _ => Err(format!("Invalid node type: {}", s)),
        }
    }
}

/// X25519 public key for a relay node (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey {
    pub bytes: [u8; 32],
}

impl PublicKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Create from a 64-character hex string.
    ///
    /// # Errors
    /// Returns an error string if `hex` is not exactly 64 characters or contains non-hex digits.
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        if hex.len() != 64 {
            return Err("Hex string must be 64 characters (32 bytes)".to_string());
        }

        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let hex_slice = hex
                .get(i * 2..i * 2 + 2)
                .ok_or_else(|| format!("Invalid hex slice at position {}", i))?;
            *byte = u8::from_str_radix(hex_slice, 16).map_err(|e| format!("Invalid hex: {}", e))?;
        }

        Ok(Self { bytes })
    }

    pub fn to_hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.to_hex()[..16])
    }
}

/// Exit policy for exit nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitPolicy {
    pub allowed_ports: Vec<u16>,
    pub blocked_ports: Vec<u16>,
    pub allowed_ips: Vec<IpAddr>,
    pub blocked_ips: Vec<IpAddr>,
}

impl ExitPolicy {
    /// Default policy: allow common web ports.
    pub fn default_policy() -> Self {
        Self {
            allowed_ports: vec![80, 443, 8080, 8443],
            blocked_ports: vec![25, 587, 465],
            allowed_ips: vec![],
            blocked_ips: vec![],
        }
    }

    /// Allow all ports (permissive policy).
    pub fn allow_all() -> Self {
        Self {
            allowed_ports: vec![],
            blocked_ports: vec![],
            allowed_ips: vec![],
            blocked_ips: vec![],
        }
    }

    /// Check if connection to destination is allowed.
    pub fn allows(&self, addr: &SocketAddr) -> bool {
        let port = addr.port();
        let ip = addr.ip();

        if self.blocked_ips.contains(&ip) {
            return false;
        }

        if !self.allowed_ips.is_empty() && !self.allowed_ips.contains(&ip) {
            return false;
        }

        if self.blocked_ports.contains(&port) {
            return false;
        }

        if self.allowed_ports.is_empty() {
            true
        } else {
            self.allowed_ports.contains(&port)
        }
    }
}

/// Node descriptor containing all information about a relay node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub node_id: String,
    pub node_type: NodeType,

    pub address: SocketAddr,
    pub public_key: PublicKey,

    pub bandwidth: u64,
    pub exit_policy: Option<ExitPolicy>,

    /// Optional operator family tag. When set, path selection refuses to place
    /// two nodes with the same `operator_id` in the same circuit, even if they
    /// are on different IP addresses. Purely opt-in — `None` means no grouping.
    #[serde(default)]
    pub operator_id: Option<String>,

    /// SHA-256 hex fingerprint of this relay's self-signed TLS certificate.
    /// Used by peers to verify the relay's identity during TLS handshake.
    #[serde(default)]
    pub tls_cert_fingerprint: String,
}

/// Live metrics snapshot sent by a relay node during heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeMetrics {
    pub connections_accepted: u64,
    pub circuits_active: u64,
    pub circuits_created: u64,
    pub circuits_destroyed: u64,
    pub bytes_forwarded: u64,
    pub bytes_received: u64,
    pub streams_opened: u64,
    pub uptime_secs: u64,
    pub event_snapshot: Vec<String>,
}

impl NodeDescriptor {
    pub fn new(
        node_id: String,
        node_type: NodeType,
        address: SocketAddr,
        public_key: PublicKey,
        bandwidth: u64,
        exit_policy: Option<ExitPolicy>,
    ) -> Self {
        Self {
            node_id,
            node_type,
            address,
            public_key,
            bandwidth,
            exit_policy,
            operator_id: None,
            tls_cert_fingerprint: String::new(),
        }
    }

    /// Serialize to JSON.
    ///
    /// # Errors
    /// Returns a serde error if serialization fails (should not happen for this type).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    /// Returns a serde error if `json` is malformed or missing required fields.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_node_type_display() {
        assert_eq!(NodeType::Entry.to_string(), "entry");
        assert_eq!(NodeType::Middle.to_string(), "middle");
        assert_eq!(NodeType::Exit.to_string(), "exit");
    }

    #[test]
    fn test_node_type_from_str() {
        use std::str::FromStr;
        assert_eq!(NodeType::from_str("entry").unwrap(), NodeType::Entry);
        assert_eq!(NodeType::from_str("MIDDLE").unwrap(), NodeType::Middle);
        assert!(NodeType::from_str("invalid").is_err());
    }

    #[test]
    fn test_exit_policy_allows() {
        let policy = ExitPolicy::default_policy();

        let http_addr = "93.184.216.34:80".parse().unwrap();
        assert!(policy.allows(&http_addr));

        let https_addr = "93.184.216.34:443".parse().unwrap();
        assert!(policy.allows(&https_addr));

        let smtp_addr = "93.184.216.34:25".parse().unwrap();
        assert!(!policy.allows(&smtp_addr));
    }

    #[test]
    fn test_exit_policy_ip_filtering() {
        let mut policy = ExitPolicy::default_policy();
        let blocked_ip: IpAddr = "192.168.1.1".parse().unwrap();
        policy.blocked_ips.push(blocked_ip);

        let blocked_addr = "192.168.1.1:80".parse().unwrap();
        assert!(!policy.allows(&blocked_addr));

        let allowed_addr = "93.184.216.34:80".parse().unwrap();
        assert!(policy.allows(&allowed_addr));
    }

    #[test]
    fn test_exit_policy_allowed_ips() {
        let mut policy = ExitPolicy::default_policy();
        let allowed_ip: IpAddr = "1.1.1.1".parse().unwrap();
        policy.allowed_ips.push(allowed_ip);

        let allowed_addr = "1.1.1.1:443".parse().unwrap();
        assert!(policy.allows(&allowed_addr));

        let disallowed_addr = "8.8.8.8:443".parse().unwrap();
        assert!(!policy.allows(&disallowed_addr));
    }

    #[test]
    fn test_public_key_hex() {
        let bytes = [1u8; 32];
        let pk = PublicKey::new(bytes);
        let hex = pk.to_hex();
        assert_eq!(hex.len(), 64);

        let pk2 = PublicKey::from_hex(&hex).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_node_descriptor_json() {
        let pubkey = PublicKey::new([0u8; 32]);
        let addr = "127.0.0.1:9001".parse().unwrap();

        let node = NodeDescriptor::new(
            "node-1".to_string(),
            NodeType::Entry,
            addr,
            pubkey,
            1_000_000,
            None,
        );

        let json = node.to_json().unwrap();
        let node2 = NodeDescriptor::from_json(&json).unwrap();

        assert_eq!(node.node_id, node2.node_id);
        assert_eq!(node.node_type, node2.node_type);
    }
}
