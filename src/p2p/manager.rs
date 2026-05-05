//! P2P connection manager.
//!
//! Handles peer discovery, connection establishment, and lifecycle management.

use super::{config::P2PConfig, ice::ICECandidate, P2P_PORT};
use crate::events::UiEvent;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

/// P2P peer information.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer user ID
    pub user_id: String,

    /// Peer device ID
    pub device_id: String,

    /// Last known ICE candidates
    pub candidates: Vec<ICECandidate>,

    /// Connection status
    pub status: PeerStatus,

    /// Last latency measurement (ms)
    pub latency_ms: Option<u64>,
}

/// P2P connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    /// Not connected
    Disconnected,

    /// Handoff in progress (exchanging candidates via server)
    Handshaking,

    /// Connecting (attempting direct connection)
    Connecting,

    /// Connected (direct P2P link established)
    Connected,

    /// Failed (connection attempt failed, will retry)
    Failed,

    /// Fallback to relay (P2P not possible, using relay node)
    RelayFallback,
}

/// P2P connection statistics.
#[derive(Debug, Clone, Default)]
pub struct P2PStats {
    /// Total P2P connections established
    pub connections_established: u64,

    /// Total handoff attempts
    pub handoff_attempts: u64,

    /// Successful handoffs
    pub handoffs_successful: u64,

    /// Fallbacks to relay
    pub fallbacks_to_relay: u64,

    /// Average P2P latency (ms)
    pub avg_latency_ms: Option<f64>,

    /// Total bytes sent via P2P
    pub bytes_sent: u64,

    /// Total bytes received via P2P
    pub bytes_received: u64,
}

/// P2P connection manager.
///
/// Manages peer-to-peer connections with server-assisted handoff.
///
/// # Architecture
///
/// ```text
/// 1. Server detects both peers online → sends P2PHandoffInitiate
/// 2. Peers exchange ICE candidates via MessageStream
/// 3. Direct QUIC connection established
/// 4. Server exits relay path (optional, for bandwidth saving)
/// ```
pub struct P2PManager {
    /// P2P configuration
    config: P2PConfig,

    /// Known peers and their status
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,

    /// P2P statistics
    stats: Arc<Mutex<P2PStats>>,

    /// Local ICE candidates
    local_candidates: Arc<Mutex<Vec<ICECandidate>>>,

    /// Event sender for P2P events
    event_tx: mpsc::UnboundedSender<UiEvent>,
}

impl P2PManager {
    /// Create a new P2PManager.
    pub fn new(config: P2PConfig, event_tx: mpsc::UnboundedSender<UiEvent>) -> Self {
        Self {
            config,
            peers: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(P2PStats::default())),
            local_candidates: Arc::new(Mutex::new(Vec::new())),
            event_tx,
        }
    }

    /// Get P2P configuration.
    pub fn config(&self) -> &P2PConfig {
        &self.config
    }

    /// Get P2P statistics.
    pub async fn stats(&self) -> P2PStats {
        self.stats.lock().await.clone()
    }

    /// Gather local ICE candidates (LAN + STUN).
    ///
    /// This collects all available network interfaces and queries STUN servers
    /// to discover the public IP address.
    pub async fn gather_local_candidates(&self) -> Vec<ICECandidate> {
        debug!("Gathering local ICE candidates...");

        let mut candidates = Vec::new();

        // Gather LAN candidates from network interfaces
        match get_if_addrs::get_if_addrs() {
            Ok(interfaces) => {
                for iface in interfaces {
                    if !iface.is_loopback() {
                        let addr = match iface.addr {
                            get_if_addrs::IfAddr::V4(v4) => {
                                format!("{}:{}", v4.ip, P2P_PORT)
                            }
                            get_if_addrs::IfAddr::V6(v6) => {
                                format!("[{}]:{}", v6.ip, P2P_PORT)
                            }
                        };

                        debug!("Found LAN candidate: {} ({})", addr, iface.name);

                        let candidate = ICECandidate::lan(
                            addr,
                            Some(iface.name.clone()),
                        );

                        candidates.push(candidate);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to get network interfaces: {}", e);
            }
        }

        // Query STUN servers for public IP
        for stun_server in &self.config.stun_servers {
            match self.query_stun(stun_server).await {
                Ok(public_addr) => {
                    debug!("Found public IP candidate via {}: {}", stun_server, public_addr);
                    let candidate = ICECandidate::public_ip(public_addr);
                    candidates.push(candidate);
                    break; // Use first successful STUN response
                }
                Err(e) => {
                    warn!("STUN query failed for {}: {}", stun_server, e);
                }
            }
        }

        // Cache candidates locally
        *self.local_candidates.lock().await = candidates.clone();

        info!("Gathered {} local ICE candidates", candidates.len());
        candidates
    }

    /// Query STUN server for public IP address.
    async fn query_stun(&self, server: &str) -> Result<String, String> {
        // Phase 2: Implement actual STUN query using stun-client crate
        // For now, return placeholder
        debug!("STUN query to {} (stub - will be implemented in Phase 2)", server);
        Err("STUN not yet implemented".to_string())
    }

    /// Initiate P2P handoff with a peer.
    ///
    /// Called when server detects both peers online and suggests P2P connection.
    pub async fn initiate_handoff(&self, peer_user_id: &str, peer_device_id: &str) {
        info!("Initiating P2P handoff with {} ({})", peer_user_id, peer_device_id);

        let peer_key = format!("{}:{}", peer_user_id, peer_device_id);

        // Update peer status
        {
            let mut peers = self.peers.lock().await;
            peers.entry(peer_key.clone()).and_modify(|peer| {
                peer.status = PeerStatus::Handshaking;
            }).or_insert_with(|| PeerInfo {
                user_id: peer_user_id.to_string(),
                device_id: peer_device_id.to_string(),
                candidates: Vec::new(),
                status: PeerStatus::Handshaking,
                latency_ms: None,
            });
        }

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.handoff_attempts += 1;
        }

        // Gather our candidates
        let local_candidates = self.gather_local_candidates().await;

        // Send handoff initiate event to platform
        // Platform will forward candidates to peer via server
        let _ = self.event_tx.send(UiEvent::P2PHandoffInitiate {
            peer_id: peer_user_id.to_string(),
            candidates: local_candidates,
        });

        info!("P2P handoff initiated for {}", peer_key);
    }

    /// Handle incoming P2P handoff from peer.
    ///
    /// Called when we receive peer's ICE candidates via server.
    pub async fn handle_handoff_initiate(
        &self,
        peer_user_id: &str,
        peer_device_id: &str,
        candidates: Vec<ICECandidate>,
    ) {
        info!(
            "Received P2P handoff from {} ({}): {} candidates",
            peer_user_id,
            peer_device_id,
            candidates.len()
        );

        let peer_key = format!("{}:{}", peer_user_id, peer_device_id);

        // Store peer's candidates
        {
            let mut peers = self.peers.lock().await;
            peers.entry(peer_key.clone()).and_modify(|peer| {
                peer.candidates = candidates.clone();
                peer.status = PeerStatus::Handshaking;
            }).or_insert_with(|| PeerInfo {
                user_id: peer_user_id.to_string(),
                device_id: peer_device_id.to_string(),
                candidates,
                status: PeerStatus::Handshaking,
                latency_ms: None,
            });
        }

        // Gather our candidates and send ack
        let local_candidates = self.gather_local_candidates().await;

        let _ = self.event_tx.send(UiEvent::P2PHandoffAck {
            session_id: format!("{}:{}", peer_user_id, peer_device_id),
            success: true,
            candidates: local_candidates,
            measured_latency_ms: None,
        });

        // Start connection attempt
        self.attempt_connection(peer_user_id, peer_device_id).await;
    }

    /// Handle P2P handoff acknowledgment.
    pub async fn handle_handoff_ack(
        &self,
        peer_user_id: &str,
        peer_device_id: &str,
        candidates: Vec<ICECandidate>,
    ) {
        info!(
            "Received P2P handoff ack from {} ({}): {} candidates",
            peer_user_id,
            peer_device_id,
            candidates.len()
        );

        // Store peer's candidates
        let peer_key = format!("{}:{}", peer_user_id, peer_device_id);
        {
            let mut peers = self.peers.lock().await;
            peers.entry(peer_key).and_modify(|peer| {
                peer.candidates = candidates.clone();
            });
        }

        // Start connection attempt
        self.attempt_connection(peer_user_id, peer_device_id).await;
    }

    /// Attempt to establish direct P2P connection.
    async fn attempt_connection(&self, peer_user_id: &str, peer_device_id: &str) {
        let peer_key = format!("{}:{}", peer_user_id, peer_device_id);

        // Update status
        {
            let mut peers = self.peers.lock().await;
            if let Some(peer) = peers.get_mut(&peer_key) {
                peer.status = PeerStatus::Connecting;
            }
        }

        info!("Attempting P2P connection to {}", peer_key);

        // Phase 2: Implement actual QUIC connection logic
        // For now, simulate connection attempt
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Simulate connection failure (will be replaced with real logic)
        warn!("P2P connection to {} failed (stub - Phase 2)", peer_key);

        // Update status to failed
        {
            let mut peers = self.peers.lock().await;
            if let Some(peer) = peers.get_mut(&peer_key) {
                peer.status = PeerStatus::Failed;
            }
        }

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.fallbacks_to_relay += 1;
        }

        // Schedule retry
        self.schedule_retry(peer_user_id, peer_device_id).await;
    }

    /// Schedule a retry attempt after failure.
    async fn schedule_retry(&self, peer_user_id: &str, peer_device_id: &str) {
        let retry_interval = self.config.retry_interval_secs;
        let peer_key = format!("{}:{}", peer_user_id, peer_device_id);

        info!("Scheduling P2P retry for {} in {}s", peer_key, retry_interval);

        // Phase 2: Implement actual retry logic with backoff
        debug!("Retry logic stub (will be implemented in Phase 2)");
    }

    /// Get peer status.
    pub async fn get_peer_status(&self, user_id: &str, device_id: &str) -> Option<PeerStatus> {
        let peer_key = format!("{}:{}", user_id, device_id);
        self.peers.lock().await.get(&peer_key).map(|p| p.status)
    }

    /// Get all known peers.
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        self.peers.lock().await.values().cloned().collect()
    }

    /// Remove a peer from tracking.
    pub async fn remove_peer(&self, user_id: &str, device_id: &str) {
        let peer_key = format!("{}:{}", user_id, device_id);
        self.peers.lock().await.remove(&peer_key);
        debug!("Removed peer: {}", peer_key);
    }

    /// Check if P2P is preferable for given peer.
    ///
    /// Returns true if:
    /// - P2P is enabled
    /// - Peer is desktop (not mobile burst mode)
    /// - Server latency is high enough to justify P2P
    pub fn should_use_p2p(&self, server_latency_ms: u64, is_peer_mobile: bool) -> bool {
        if !self.config.enable_p2p {
            return false;
        }

        // Mobile peers use burst mode only
        if is_peer_mobile {
            return false;
        }

        // Check if server latency justifies P2P
        server_latency_ms >= self.config.min_server_latency_ms
    }

    /// Update peer latency measurement.
    pub async fn update_peer_latency(&self, user_id: &str, device_id: &str, latency_ms: u64) {
        let peer_key = format!("{}:{}", user_id, device_id);

        let mut peers = self.peers.lock().await;
        if let Some(peer) = peers.get_mut(&peer_key) {
            peer.latency_ms = Some(latency_ms);

            // Check if latency is acceptable
            if latency_ms > self.config.max_p2p_latency_ms {
                warn!("P2P latency too high ({}ms) for {}, considering relay fallback", latency_ms, peer_key);
            }
        }

        // Update average latency in stats
        let mut stats = self.stats.lock().await;
        let current_avg = stats.avg_latency_ms.unwrap_or(0.0);
        let count = stats.connections_established.max(1);
        stats.avg_latency_ms = Some((current_avg * (count - 1) as f64 + latency_ms as f64) / count as f64);
    }

    /// Record bytes sent via P2P.
    pub async fn record_bytes_sent(&self, bytes: u64) {
        self.stats.lock().await.bytes_sent += bytes;
    }

    /// Record bytes received via P2P.
    pub async fn record_bytes_received(&self, bytes: u64) {
        self.stats.lock().await.bytes_received += bytes;
    }

    /// Record successful connection.
    pub async fn record_connection_success(&self) {
        let mut stats = self.stats.lock().await;
        stats.connections_established += 1;
        stats.handoffs_successful += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn test_p2p_config_default() {
        let config = P2PConfig::default();
        assert!(config.enable_p2p);
        assert!(config.enable_lan_discovery);
        assert_eq!(config.p2p_port, P2P_PORT);
        assert_eq!(config.stun_servers.len(), 2);
    }

    #[test]
    fn test_candidate_type_conversion() {
        use super::super::ice::CandidateType;

        assert_eq!(CandidateType::LocalLan as i32, 0);
        assert_eq!(CandidateType::PublicIp as i32, 1);
        assert_eq!(CandidateType::Relay as i32, 2);

        assert_eq!(CandidateType::from(0), CandidateType::LocalLan);
        assert_eq!(CandidateType::from(1), CandidateType::PublicIp);
        assert_eq!(CandidateType::from(2), CandidateType::Relay);
    }

    #[tokio::test]
    async fn test_p2p_manager_creation() {
        let (tx, _rx) = mpsc::unbounded_channel::<UiEvent>();
        let manager = P2PManager::new(P2PConfig::default(), tx);

        assert!(manager.config().enable_p2p);
        assert_eq!(manager.stats().await.connections_established, 0);
    }

    #[tokio::test]
    async fn test_peer_status_tracking() {
        let (tx, _rx) = mpsc::unbounded_channel::<UiEvent>();
        let manager = P2PManager::new(P2PConfig::default(), tx);

        // Initially no peer
        assert!(manager.get_peer_status("user1", "device1").await.is_none());

        // Initiate handoff creates peer entry
        manager.initiate_handoff("user1", "device1").await;
        let status = manager.get_peer_status("user1", "device1").await;
        assert_eq!(status, Some(PeerStatus::Handshaking));
    }

    #[test]
    fn test_should_use_p2p() {
        let config = P2PConfig {
            enable_p2p: true,
            min_server_latency_ms: 50,
            ..Default::default()
        };

        let (tx, _rx) = mpsc::unbounded_channel::<UiEvent>();
        let manager = P2PManager::new(config, tx);

        // Desktop peer with high latency → use P2P
        assert!(manager.should_use_p2p(100, false));

        // Desktop peer with low latency → don't use P2P
        assert!(!manager.should_use_p2p(30, false));

        // Mobile peer → don't use P2P (burst mode only)
        assert!(!manager.should_use_p2p(100, true));
    }
}
