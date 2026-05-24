//! P2P (Peer-to-Peer) transport module for Construct Messenger.
//!
//! **Status**: Phase 2 - P2PManager implementation (ROADMAP.md)
//!
//! # Architecture (Three-Tier Network)
//!
//! ```text
//! Tier 1 — Federated Servers    (full feature set)
//!     ↓ fallback
//! Tier 2 — Community Relay Nodes (store-and-forward only)
//!     ↓ fallback
//! Tier 3 — Full P2P              (direct QUIC/ICE connection)
//! ```

pub mod config;
pub mod ice;
pub mod manager;
pub mod quic_p2p;
pub mod stun;

pub use config::P2PConfig;
pub use ice::{CandidateType, ICECandidate};
pub use manager::{P2PManager, PeerInfo, PeerStatus, P2PStats};
pub use quic_p2p::{ConnectionState, P2PConnection, P2PConnectionBuilder};
pub use stun::{StunClient, query_stun_servers};

/// P2P connection port (default QUIC port)
pub const P2P_PORT: u16 = 8765;

/// Maximum P2P connection timeout (seconds)
pub const P2P_TIMEOUT_SECS: u64 = 10;

/// Default STUN servers for NAT traversal
pub const DEFAULT_STUN_SERVERS: &[&str] =
    &["stun.l.google.com:19302", "stun.stunprotocol.org:3478"];
