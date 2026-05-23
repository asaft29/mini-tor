use clap::Parser;

/// Maximum number of hops allowed in a single circuit.
pub const MAX_HOPS: usize = 10;

/// Configuration for the Tor client SOCKS5 proxy
#[derive(Debug, Clone, Parser)]
#[command(name = "tor-client")]
#[command(about = "Tor-like onion routing SOCKS5 proxy client", long_about = None)]
pub struct TorClientConfig {
    /// SOCKS5 listen address (host:port)
    #[arg(long, default_value = "127.0.0.1:1080")]
    pub socks_addr: String,

    /// Discovery service URL
    #[arg(long, default_value = "http://localhost:8080")]
    pub directory_url: String,

    /// Number of circuits to maintain in the pool
    #[arg(long, default_value = "3")]
    pub pool_size: usize,

    /// Number of relay hops per circuit (minimum 3: 1 entry + N-2 middles + 1 exit)
    #[arg(long, default_value = "3", value_parser = parse_hop_count)]
    pub hops: usize,

    /// Enable TUI dashboard (disables stdout logging)
    #[arg(long)]
    pub tui: bool,

    /// Max consecutive rebuild failures per circuit slot before giving up on that slot (min 1)
    #[arg(long, default_value = "3", value_parser = parse_rebuild_attempts)]
    pub max_rebuild_attempts: usize,
}

fn parse_rebuild_attempts(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid integer"))?;
    if n < 1 {
        return Err(format!("max-rebuild-attempts must be >= 1, got {n}"));
    }
    Ok(n)
}

fn parse_hop_count(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid integer"))?;
    if n < 3 {
        return Err(format!(
            "hops must be >= 3 (1 entry + N-2 middles + 1 exit), got {n}"
        ));
    }
    if n > MAX_HOPS {
        return Err(format!(
            "hops must be <= {MAX_HOPS} (maximum circuit size), got {n}"
        ));
    }
    Ok(n)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_default_socks_addr() {
        let config = TorClientConfig::parse_from(["tor-client"]);
        assert_eq!(config.socks_addr, "127.0.0.1:1080");
    }

    #[test]
    fn test_default_directory_url() {
        let config = TorClientConfig::parse_from(["tor-client"]);
        assert_eq!(config.directory_url, "http://localhost:8080");
    }

    #[test]
    fn test_default_pool_size() {
        let config = TorClientConfig::parse_from(["tor-client"]);
        assert_eq!(config.pool_size, 3);
    }

    #[test]
    fn test_custom_pool_size() {
        let config = TorClientConfig::parse_from(["tor-client", "--pool-size", "5"]);
        assert_eq!(config.pool_size, 5);
    }

    #[test]
    fn test_custom_socks_addr() {
        let config = TorClientConfig::parse_from(["tor-client", "--socks-addr", "0.0.0.0:9050"]);
        assert_eq!(config.socks_addr, "0.0.0.0:9050");
    }

    #[test]
    fn test_custom_directory_url() {
        let config = TorClientConfig::parse_from([
            "tor-client",
            "--directory-url",
            "http://192.168.1.100:8080",
        ]);
        assert_eq!(config.directory_url, "http://192.168.1.100:8080");
    }

    #[test]
    fn test_default_hops() {
        let config = TorClientConfig::parse_from(["tor-client"]);
        assert_eq!(config.hops, 3);
    }

    #[test]
    fn test_custom_hops() {
        let config = TorClientConfig::parse_from(["tor-client", "--hops", "5"]);
        assert_eq!(config.hops, 5);
    }

    #[test]
    fn test_hops_below_minimum_rejected() {
        let result = TorClientConfig::try_parse_from(["tor-client", "--hops", "2"]);
        assert!(result.is_err(), "hops=2 should be rejected");
    }

    #[test]
    fn test_hops_1_rejected() {
        let result = TorClientConfig::try_parse_from(["tor-client", "--hops", "1"]);
        assert!(result.is_err(), "hops=1 should be rejected");
    }

    #[test]
    fn test_hops_0_rejected() {
        let result = TorClientConfig::try_parse_from(["tor-client", "--hops", "0"]);
        assert!(result.is_err(), "hops=0 should be rejected");
    }

    #[test]
    fn test_hops_max_accepted() {
        let config = TorClientConfig::parse_from(["tor-client", "--hops", "10"]);
        assert_eq!(config.hops, 10);
    }

    #[test]
    fn test_hops_above_max_rejected() {
        let result = TorClientConfig::try_parse_from(["tor-client", "--hops", "11"]);
        assert!(result.is_err(), "hops=11 should be rejected (max is 10)");
    }

    #[test]
    fn test_default_max_rebuild_attempts() {
        let config = TorClientConfig::parse_from(["tor-client"]);
        assert_eq!(config.max_rebuild_attempts, 3);
    }

    #[test]
    fn test_custom_max_rebuild_attempts() {
        let config = TorClientConfig::parse_from(["tor-client", "--max-rebuild-attempts", "5"]);
        assert_eq!(config.max_rebuild_attempts, 5);
    }

    #[test]
    fn test_max_rebuild_attempts_zero_rejected() {
        let result = TorClientConfig::try_parse_from(["tor-client", "--max-rebuild-attempts", "0"]);
        assert!(result.is_err(), "max-rebuild-attempts=0 should be rejected");
    }
}
