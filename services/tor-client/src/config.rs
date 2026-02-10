use clap::Parser;

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
}
