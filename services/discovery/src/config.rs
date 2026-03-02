//! Discovery service CLI configuration
//!
//! Uses Clap derive macros for argument parsing. Previously the service
//! relied solely on environment variables; this module adds CLI flags
//! while keeping backwards-compatible defaults.

use clap::Parser;

/// Tor Directory / Discovery Service
#[derive(Debug, Clone, Parser)]
#[command(name = "discovery", about = "Tor-like onion routing discovery service")]
pub struct DiscoveryConfig {
    /// Port to listen on
    #[arg(long, default_value = "8080")]
    pub port: u16,

    /// Host/IP to bind to
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    /// Path to the consensus persistence file
    #[arg(
        long,
        env = "CONSENSUS_PATH",
        default_value = "services/discovery/data/consensus.json"
    )]
    pub consensus_path: String,

    /// Enable the TUI dashboard (disables stdout logging)
    #[arg(long, default_value_t = false)]
    pub tui: bool,

    /// Heartbeat staleness timeout in seconds
    #[arg(long, default_value = "120")]
    pub stale_timeout_secs: u64,
}

impl DiscoveryConfig {
    /// Build the bind address string
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
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
        assert_eq!(config.host, "0.0.0.0");
        assert!(!config.tui);
        assert_eq!(config.stale_timeout_secs, 120);
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
