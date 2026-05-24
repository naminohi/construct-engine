//! QUIC P2P connection handler.
//!
//! Manages direct QUIC connections between peers after ICE handoff.

use super::ice::ICECandidate;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

/// P2P connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,

    /// Connecting (handshake in progress)
    Connecting,

    /// Connected (QUIC handshake complete)
    Connected,

    /// Reconnecting (connection lost, attempting recovery)
    Reconnecting,

    /// Closed (gracefully shut down)
    Closed,

    /// Failed (connection attempt failed)
    Failed,
}

/// QUIC P2P connection.
pub struct P2PConnection {
    /// Peer user ID
    pub peer_user_id: String,

    /// Peer device ID
    pub peer_device_id: String,

    /// Connection state
    state: Arc<RwLock<ConnectionState>>,

    /// Remote address (if known)
    remote_addr: Arc<RwLock<Option<SocketAddr>>>,

    /// Connection timeout
    timeout: Duration,

    /// Bytes sent
    bytes_sent: Arc<Mutex<u64>>,

    /// Bytes received
    bytes_received: Arc<Mutex<u64>>,

    /// Last RTT measurement (ms)
    last_rtt_ms: Arc<RwLock<Option<u64>>>,
}

impl P2PConnection {
    /// Create a new P2P connection (not yet connected).
    pub fn new(peer_user_id: &str, peer_device_id: &str, timeout: Duration) -> Self {
        Self {
            peer_user_id: peer_user_id.to_string(),
            peer_device_id: peer_device_id.to_string(),
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            remote_addr: Arc::new(RwLock::new(None)),
            timeout,
            bytes_sent: Arc::new(Mutex::new(0)),
            bytes_received: Arc::new(Mutex::new(0)),
            last_rtt_ms: Arc::new(RwLock::new(None)),
        }
    }

    /// Get connection state.
    pub async fn state(&self) -> ConnectionState {
        *self.state.read().await
    }

    /// Check if connected.
    pub async fn is_connected(&self) -> bool {
        *self.state.read().await == ConnectionState::Connected
    }

    /// Attempt to establish connection using ICE candidates.
    ///
    /// Tries each candidate in priority order until connection succeeds.
    pub async fn connect(&self, candidates: &[ICECandidate]) -> Result<(), String> {
        info!(
            "Attempting P2P connection to {} ({})",
            self.peer_user_id, self.peer_device_id
        );

        // Update state
        *self.state.write().await = ConnectionState::Connecting;

        // Sort candidates by priority (lower = higher priority)
        let mut sorted_candidates: Vec<&ICECandidate> = candidates.iter().collect();
        sorted_candidates.sort_by_key(|c| c.priority);

        // Try each candidate
        for candidate in sorted_candidates {
            debug!(
                "Trying candidate: {} (type: {:?}, priority: {})",
                candidate.address, candidate.candidate_type, candidate.priority
            );

            match self.try_connect_to_candidate(candidate).await {
                Ok(()) => {
                    info!(
                        "P2P connection established to {} via {}",
                        self.peer_user_id, candidate.address
                    );

                    *self.state.write().await = ConnectionState::Connected;
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "Failed to connect to {}: {} (trying next candidate)",
                        candidate.address, e
                    );
                }
            }
        }

        // All candidates failed
        *self.state.write().await = ConnectionState::Failed;
        Err("All ICE candidates failed".to_string())
    }

    /// Try to connect to a single ICE candidate.
    async fn try_connect_to_candidate(&self, candidate: &ICECandidate) -> Result<(), String> {
        use std::net::UdpSocket;

        // Parse candidate address
        let addr: SocketAddr = candidate
            .address
            .parse()
            .map_err(|e| format!("Invalid candidate address: {}", e))?;

        // Bind local UDP socket (blocking, but quick)
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        // Set timeout
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set socket timeout: {}", e))?;

        socket
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        // Phase 3: Implement actual QUIC handshake using quinn crate
        // For now, simulate connection with a simple UDP ping

        // Send connection probe
        let probe = b"P2P_CONNECT_PROBE";
        socket
            .send_to(probe, addr)
            .map_err(|e| format!("Failed to send probe: {}", e))?;

        // Wait for response (use tokio spawn_blocking for non-blocking wait)
        let socket = Arc::new(socket);
        let socket_clone = socket.clone();

        match tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 1500];
            socket_clone.recv_from(&mut buf)
        })
        .await
        {
            Ok(Ok((len, from))) => {
                debug!("Received {} bytes from {}", len, from);

                // Check if it's a valid response
                if len > 0 {
                    *self.remote_addr.write().await = Some(addr);
                    return Ok(());
                }
            }
            Ok(Err(e)) => {
                return Err(format!("Recv error: {}", e));
            }
            Err(e) => {
                return Err(format!("Task join error: {}", e));
            }
        }

        Err("No response from peer".to_string())
    }

    /// Send data over P2P connection.
    pub async fn send(&self, data: &[u8]) -> Result<usize, String> {
        use std::net::UdpSocket;

        let remote_addr = *self.remote_addr.read().await;
        let addr = remote_addr.ok_or_else(|| "Remote address unknown".to_string())?;

        // Create temporary socket for sending
        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind socket: {}", e))?;

        match socket.send_to(data, addr) {
            Ok(len) => {
                *self.bytes_sent.lock().await += len as u64;
                debug!("Sent {} bytes via P2P", len);
                Ok(len)
            }
            Err(e) => Err(format!("Send failed: {}", e)),
        }
    }

    /// Receive data from P2P connection.
    pub async fn receive(&self, buf: &mut [u8]) -> Result<usize, String> {
        use std::net::UdpSocket;

        let remote_addr = *self.remote_addr.read().await;
        let _addr = remote_addr.ok_or_else(|| "Remote address unknown".to_string())?;

        // Create temporary socket for receiving (bind to any port)
        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind socket: {}", e))?;

        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        let socket = Arc::new(socket);
        let socket_clone = socket.clone();
        let buf_vec = buf.to_vec();

        match tokio::task::spawn_blocking(move || {
            let mut recv_buf = vec![0u8; buf_vec.len()];
            socket_clone
                .recv_from(&mut recv_buf)
                .map(|(len, _)| (len, recv_buf))
        })
        .await
        {
            Ok(Ok((len, recv_buf))) => {
                buf[..len].copy_from_slice(&recv_buf[..len]);
                *self.bytes_received.lock().await += len as u64;
                debug!("Received {} bytes via P2P", len);
                Ok(len)
            }
            Ok(Err(e)) => Err(format!("Recv failed: {}", e)),
            Err(e) => Err(format!("Task join error: {}", e)),
        }
    }

    /// Measure RTT to peer.
    pub async fn measure_rtt(&self) -> Option<u64> {
        if !self.is_connected().await {
            return None;
        }

        let start = std::time::Instant::now();

        // Send ping
        let ping = b"PING";
        if self.send(ping).await.is_err() {
            return None;
        }

        // Wait for pong
        let mut buf = vec![0u8; 64];
        match tokio::time::timeout(Duration::from_secs(2), self.receive(&mut buf)).await {
            Ok(Ok(len)) if &buf[..len] == b"PONG" => {
                let rtt = start.elapsed().as_millis() as u64;
                *self.last_rtt_ms.write().await = Some(rtt);
                debug!("P2P RTT: {}ms", rtt);
                Some(rtt)
            }
            _ => None,
        }
    }

    /// Send keepalive ping.
    pub async fn send_keepalive(&self) -> Result<(), String> {
        self.send(b"PONG").await.map(|_| ())
    }

    /// Get bytes sent.
    pub async fn bytes_sent(&self) -> u64 {
        *self.bytes_sent.lock().await
    }

    /// Get bytes received.
    pub async fn bytes_received(&self) -> u64 {
        *self.bytes_received.lock().await
    }

    /// Get last RTT measurement.
    pub async fn last_rtt(&self) -> Option<u64> {
        *self.last_rtt_ms.read().await
    }

    /// Close the connection.
    pub async fn close(&self) {
        *self.state.write().await = ConnectionState::Closed;
        *self.remote_addr.write().await = None;
        info!("P2P connection closed");
    }

    /// Gracefully shutdown and attempt reconnection.
    pub async fn reconnect(&self, candidates: &[ICECandidate]) -> Result<(), String> {
        info!("Reconnecting P2P connection...");

        // Close current connection
        self.close().await;

        // Wait a bit before reconnecting
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Try to reconnect
        *self.state.write().await = ConnectionState::Reconnecting;
        self.connect(candidates).await
    }
}

/// P2P connection builder.
pub struct P2PConnectionBuilder {
    peer_user_id: String,
    peer_device_id: String,
    timeout: Duration,
}

impl P2PConnectionBuilder {
    /// Create a new builder.
    pub fn new(peer_user_id: &str, peer_device_id: &str) -> Self {
        Self {
            peer_user_id: peer_user_id.to_string(),
            peer_device_id: peer_device_id.to_string(),
            timeout: Duration::from_secs(10),
        }
    }

    /// Set connection timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build the connection.
    pub fn build(self) -> P2PConnection {
        P2PConnection::new(&self.peer_user_id, &self.peer_device_id, self.timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_creation() {
        let conn = P2PConnection::new("user1", "device1", Duration::from_secs(5));

        assert_eq!(conn.peer_user_id, "user1");
        assert_eq!(conn.peer_device_id, "device1");
        assert_eq!(conn.state().await, ConnectionState::Disconnected);
        assert!(!conn.is_connected().await);
    }

    #[tokio::test]
    async fn test_connection_state_transitions() {
        let conn = P2PConnection::new("user1", "device1", Duration::from_secs(5));

        // Initial state
        assert_eq!(conn.state().await, ConnectionState::Disconnected);

        // Simulate connection attempt (will fail without real peer)
        let candidates = vec![];
        let result = conn.connect(&candidates).await;
        assert!(result.is_err());

        // State should be Failed
        assert_eq!(conn.state().await, ConnectionState::Failed);
    }

    #[test]
    fn test_builder() {
        let conn = P2PConnectionBuilder::new("user1", "device1")
            .timeout(Duration::from_secs(30))
            .build();

        assert_eq!(conn.peer_user_id, "user1");
        assert_eq!(conn.peer_device_id, "device1");
    }
}
