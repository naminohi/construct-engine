//! P2P configuration options.

use crate::p2p::{DEFAULT_STUN_SERVERS, P2P_PORT, P2P_TIMEOUT_SECS};

/// P2P configuration.
#[derive(Debug, Clone)]
pub struct P2PConfig {
    /// Enable P2P mode (default: true)
    pub enable_p2p: bool,

    /// Enable local network mDNS discovery (default: true)
    pub enable_lan_discovery: bool,

    /// STUN servers for NAT traversal
    pub stun_servers: Vec<String>,

    /// Minimum server latency before trying P2P (ms)
    /// If server latency < this, P2P may not be worth it
    pub min_server_latency_ms: u64,

    /// P2P connection timeout (seconds)
    pub p2p_timeout_secs: u64,

    /// Auto-retry interval after P2P failure (seconds)
    pub retry_interval_secs: u64,

    /// Enable multi-path bonding (P2P + relay simultaneously)
    pub enable_bonding: bool,

    /// Maximum acceptable P2P latency (ms)
    /// If P2P latency > this, fallback to relay
    pub max_p2p_latency_ms: u64,

    /// P2P listening port
    pub p2p_port: u16,

    /// Prefer P2P for desktop-to-desktop connections
    pub prefer_p2p_desktop: bool,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            enable_p2p: true,
            enable_lan_discovery: true,
            stun_servers: DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
            min_server_latency_ms: 50,
            p2p_timeout_secs: P2P_TIMEOUT_SECS,
            retry_interval_secs: 300, // 5 minutes
            enable_bonding: false,    // Phase 4 feature
            max_p2p_latency_ms: 200,
            p2p_port: P2P_PORT,
            prefer_p2p_desktop: true,
        }
    }
}

impl P2PConfig {
    /// Create a new P2PConfig with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if P2P is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enable_p2p
    }

    /// Check if LAN discovery is enabled.
    pub fn is_lan_discovery_enabled(&self) -> bool {
        self.enable_lan_discovery && self.enable_p2p
    }

    /// Check if bonding is enabled.
    pub fn is_bonding_enabled(&self) -> bool {
        self.enable_bonding && self.enable_p2p
    }
}
