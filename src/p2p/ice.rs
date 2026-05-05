//! ICE candidate types for P2P connection.
//!
//! ICE (Interactive Connectivity Establishment) candidates describe
//! network endpoints where a peer can be reached.

use serde::{Deserialize, Serialize};

/// ICE candidate for P2P connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ICECandidate {
    /// Candidate type
    pub candidate_type: CandidateType,

    /// IP address and port (e.g., "192.168.1.100:8765")
    pub address: String,

    /// Priority (lower = higher priority)
    pub priority: u32,

    /// Foundation for ICE pairing (opaque string)
    pub foundation: Option<String>,

    /// Network interface name (e.g., "en0", "eth0")
    pub interface_name: Option<String>,

    /// Transport protocol (always "udp" for QUIC)
    pub transport: String,

    /// Generation (for ICE restarts, typically 0)
    pub generation: u32,
}

impl ICECandidate {
    /// Create a new ICE candidate.
    pub fn new(candidate_type: CandidateType, address: String, priority: u32) -> Self {
        Self {
            candidate_type,
            address,
            priority,
            foundation: None,
            interface_name: None,
            transport: "udp".to_string(),
            generation: 0,
        }
    }

    /// Create a LAN candidate.
    pub fn lan(address: String, interface_name: Option<String>) -> Self {
        Self {
            candidate_type: CandidateType::LocalLan,
            address,
            priority: 100,
            foundation: None,
            interface_name,
            transport: "udp".to_string(),
            generation: 0,
        }
    }

    /// Create a public IP candidate (from STUN).
    pub fn public_ip(address: String) -> Self {
        Self {
            candidate_type: CandidateType::PublicIp,
            address,
            priority: 50,
            foundation: None,
            interface_name: None,
            transport: "udp".to_string(),
            generation: 0,
        }
    }

    /// Check if this is a LAN candidate.
    pub fn is_lan(&self) -> bool {
        matches!(
            self.candidate_type,
            CandidateType::LocalLan | CandidateType::Ipv6LinkLocal
        )
    }

    /// Check if this is a relay candidate.
    pub fn is_relay(&self) -> bool {
        self.candidate_type == CandidateType::Relay
    }
}

/// ICE candidate type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateType {
    /// Local LAN address (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    /// Highest priority (fastest, no NAT traversal needed)
    LocalLan,

    /// Public IP address (obtained via STUN)
    /// Medium priority (may require NAT hole punching)
    PublicIp,

    /// Relay address (via TURN-like relay node)
    /// Lowest priority (fallback when direct connection fails)
    Relay,

    /// IPv6 link-local address (fe80::/10)
    /// High priority on IPv6 networks
    Ipv6LinkLocal,

    /// IPv6 global unicast address
    /// Medium priority (depends on IPv6 connectivity)
    Ipv6Global,
}

impl CandidateType {
    /// Get the default priority for this candidate type.
    pub fn default_priority(self) -> u32 {
        match self {
            CandidateType::LocalLan => 100,
            CandidateType::Ipv6LinkLocal => 90,
            CandidateType::PublicIp => 50,
            CandidateType::Ipv6Global => 45,
            CandidateType::Relay => 10,
        }
    }
}

impl From<i32> for CandidateType {
    fn from(value: i32) -> Self {
        match value {
            0 => CandidateType::LocalLan,
            1 => CandidateType::PublicIp,
            2 => CandidateType::Relay,
            3 => CandidateType::Ipv6LinkLocal,
            4 => CandidateType::Ipv6Global,
            _ => CandidateType::PublicIp, // Default fallback
        }
    }
}

impl From<CandidateType> for i32 {
    fn from(value: CandidateType) -> Self {
        match value {
            CandidateType::LocalLan => 0,
            CandidateType::PublicIp => 1,
            CandidateType::Relay => 2,
            CandidateType::Ipv6LinkLocal => 3,
            CandidateType::Ipv6Global => 4,
        }
    }
}
