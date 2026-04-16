use clap::Parser;
use common::{ExitPolicy, NodeType};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Configuration for a relay node.
#[derive(Debug, Clone, Parser)]
#[command(name = "relay-node")]
#[command(about = "Tor-like relay node", long_about = None)]
pub struct RelayConfig {
    #[arg(long, value_parser = parse_node_type)]
    pub node_type: NodeType,

    #[arg(long, default_value = "9001")]
    pub port: u16,

    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    #[arg(long, default_value = "http://localhost:8080")]
    pub directory_url: String,

    #[arg(long, default_value = "1048576")]
    pub bandwidth: u64,

    #[arg(long, default_value = "60")]
    pub heartbeat_interval: u64,

    #[arg(long, default_value = "false")]
    pub exit_allow_all: bool,

    #[arg(long, default_value = "false")]
    pub tui: bool,

    /// Optional operator family tag. Nodes sharing the same operator_id are
    /// never placed in the same circuit by the discovery service.
    #[arg(long)]
    pub operator_id: Option<String>,
}

impl RelayConfig {
    pub fn bind_addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        let ip: IpAddr = self.host.parse()?;
        Ok(SocketAddr::new(ip, self.port))
    }

    pub fn exit_policy(&self) -> Option<ExitPolicy> {
        if self.node_type == NodeType::Exit {
            Some(if self.exit_allow_all {
                ExitPolicy {
                    allowed_ports: vec![],
                    blocked_ports: vec![],
                    allowed_ips: vec![],
                    blocked_ips: vec![],
                }
            } else {
                ExitPolicy {
                    allowed_ports: vec![80, 443, 8080, 8443],
                    blocked_ports: vec![25, 465, 587],
                    allowed_ips: vec![],
                    blocked_ips: vec![
                        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
                        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
                    ],
                }
            })
        } else {
            None
        }
    }
}

fn parse_node_type(s: &str) -> Result<NodeType, String> {
    match s.to_lowercase().as_str() {
        "entry" => Ok(NodeType::Entry),
        "middle" => Ok(NodeType::Middle),
        "exit" => Ok(NodeType::Exit),
        _ => Err(format!(
            "Invalid node type: '{}'. Must be 'entry', 'middle', or 'exit'",
            s
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_node_type() {
        assert_eq!(parse_node_type("entry").ok(), Some(NodeType::Entry));
        assert_eq!(parse_node_type("middle").ok(), Some(NodeType::Middle));
        assert_eq!(parse_node_type("exit").ok(), Some(NodeType::Exit));
        assert_eq!(parse_node_type("ENTRY").ok(), Some(NodeType::Entry));
        assert!(parse_node_type("invalid").is_err());
    }

    #[test]
    fn test_bind_addr() {
        let config = RelayConfig {
            node_type: NodeType::Entry,
            port: 9001,
            host: "127.0.0.1".to_string(),
            directory_url: "http://localhost:8080".to_string(),
            bandwidth: 1048576,
            heartbeat_interval: 60,
            exit_allow_all: false,
            tui: false,
            operator_id: None,
        };

        let addr = config.bind_addr().ok();
        assert_eq!(
            addr,
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                9001
            ))
        );
    }

    #[test]
    fn test_exit_policy_for_exit_node() {
        let config = RelayConfig {
            node_type: NodeType::Exit,
            port: 9001,
            host: "127.0.0.1".to_string(),
            directory_url: "http://localhost:8080".to_string(),
            bandwidth: 1048576,
            heartbeat_interval: 60,
            exit_allow_all: false,
            tui: false,
            operator_id: None,
        };

        let policy = config.exit_policy();
        assert!(policy.is_some());
        let policy = policy.ok_or("no policy").ok();
        assert!(policy.is_some());
    }

    #[test]
    fn test_no_exit_policy_for_non_exit() {
        let config = RelayConfig {
            node_type: NodeType::Middle,
            port: 9001,
            host: "127.0.0.1".to_string(),
            directory_url: "http://localhost:8080".to_string(),
            bandwidth: 1048576,
            heartbeat_interval: 60,
            exit_allow_all: false,
            tui: false,
            operator_id: None,
        };

        assert!(config.exit_policy().is_none());
    }
}
