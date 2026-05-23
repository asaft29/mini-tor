//! Discovery service CLI configuration.

use clap::Parser;

/// Tor Directory / Discovery Service.
#[derive(Debug, Clone, Parser)]
#[command(name = "discovery", about = "Tor-like onion routing discovery service")]
pub struct DiscoveryConfig {
    #[arg(long, default_value = "8080")]
    pub port: u16,

    #[arg(long, default_value = "8081")]
    pub web_port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    #[arg(long, default_value_t = false)]
    pub tui: bool,

    #[arg(long, default_value = "120")]
    pub stale_timeout_secs: u64,

    #[arg(long, default_value_t = false)]
    pub allow_same_ip: bool,
}

impl DiscoveryConfig {
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn web_bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.web_port)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DiscoveryConfig::parse_from(["discovery"]);
        assert_eq!(config.port, 8080);
        assert_eq!(config.web_port, 8081);
        assert_eq!(config.host, "0.0.0.0");
        assert!(!config.tui);
        assert_eq!(config.stale_timeout_secs, 120);
        assert!(!config.allow_same_ip);
    }

    #[test]
    fn test_allow_same_ip_flag() {
        let config = DiscoveryConfig::parse_from(["discovery", "--allow-same-ip"]);
        assert!(config.allow_same_ip);
    }

    #[test]
    fn test_custom_port_and_tui() {
        let config = DiscoveryConfig::parse_from(["discovery", "--port", "9090", "--tui"]);
        assert_eq!(config.port, 9090);
        assert!(config.tui);
    }

    #[test]
    fn test_bind_addr() {
        let config =
            DiscoveryConfig::parse_from(["discovery", "--host", "127.0.0.1", "--port", "3000"]);
        assert_eq!(config.bind_addr(), "127.0.0.1:3000");
    }
}
