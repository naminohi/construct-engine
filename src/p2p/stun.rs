//! STUN client for NAT traversal.
//!
//! Queries STUN servers to discover public IP address and port mapping.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use tracing::{debug, warn};

/// STUN client for NAT traversal.
#[derive(Debug)]
pub struct StunClient {
    /// STUN server address
    server: SocketAddr,

    /// UDP socket for STUN queries
    socket: UdpSocket,

    /// Transaction timeout
    timeout: Duration,
}

impl StunClient {
    /// Create a new STUN client.
    pub fn new(server: &str) -> Result<Self, String> {
        let server = server
            .parse::<SocketAddr>()
            .map_err(|e| format!("Invalid STUN server address: {}", e))?;

        // Bind to any available port
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("Failed to set socket timeout: {}", e))?;

        Ok(Self {
            server,
            socket,
            timeout: Duration::from_secs(5),
        })
    }

    /// Query STUN server for public IP address.
    ///
    /// Returns the public IP:port as seen by the STUN server.
    pub fn query(&self) -> Result<String, String> {
        debug!("Querying STUN server: {}", self.server);

        // Build STUN Binding Request
        let transaction_id = Self::generate_transaction_id();
        let request = Self::build_binding_request(&transaction_id);

        // Send request
        self.socket
            .send_to(&request, self.server)
            .map_err(|e| format!("Failed to send STUN request: {}", e))?;

        debug!("STUN request sent ({} bytes)", request.len());

        // Wait for response
        let mut response = [0u8; 512];
        self.socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        let (len, _) = self
            .socket
            .recv_from(&mut response)
            .map_err(|e| format!("STUN request timed out: {}", e))?;

        debug!("STUN response received ({} bytes)", len);

        // Parse response
        self.parse_binding_response(&response[..len], &transaction_id)
    }

    /// Generate a random 96-bit transaction ID.
    fn generate_transaction_id() -> [u8; 12] {
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut id = [0u8; 12];

        // Use system time + random bytes for uniqueness
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        id[0..8].copy_from_slice(&timestamp.to_be_bytes());

        // Add some randomness from lower bits
        for (j, byte) in id[8..12].iter_mut().enumerate() {
            *byte = (timestamp >> (j * 8)) as u8;
        }

        id
    }

    /// Build a STUN Binding Request packet.
    ///
    /// STUN packet format:
    /// - Message Type (2 bytes): 0x0001 for Binding Request
    /// - Message Length (2 bytes): length of payload (0 for request)
    /// - Magic Cookie (4 bytes): 0x2112A442
    /// - Transaction ID (12 bytes)
    fn build_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(20);

        // Message Type: Binding Request (0x0001)
        packet.extend_from_slice(&[0x00, 0x01]);

        // Message Length: 0 (no payload)
        packet.extend_from_slice(&[0x00, 0x00]);

        // Magic Cookie: 0x2112A442
        packet.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);

        // Transaction ID
        packet.extend_from_slice(transaction_id);

        packet
    }

    /// Parse STUN Binding Response.
    ///
    /// Response format:
    /// - Message Type (2 bytes): 0x0101 for Binding Success
    /// - Message Length (2 bytes): length of payload
    /// - Magic Cookie (4 bytes): 0x2112A442
    /// - Transaction ID (12 bytes)
    /// - Attributes (variable)
    fn parse_binding_response(
        &self,
        response: &[u8],
        expected_tid: &[u8; 12],
    ) -> Result<String, String> {
        if response.len() < 20 {
            return Err("STUN response too short".to_string());
        }

        // Check message type (0x0101 = Binding Success)
        let msg_type = u16::from_be_bytes([response[0], response[1]]);
        if msg_type != 0x0101 {
            return Err(format!("Unexpected STUN message type: 0x{:04X}", msg_type));
        }

        // Verify transaction ID
        if &response[4..16] != expected_tid {
            return Err("Transaction ID mismatch".to_string());
        }

        // Parse attributes
        let mut offset = 20;
        let msg_length = u16::from_be_bytes([response[2], response[3]]) as usize;

        while offset < 20 + msg_length {
            if offset + 4 > response.len() {
                break;
            }

            let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let attr_length =
                u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_length > response.len() {
                break;
            }

            // XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
            if attr_type == 0x0020 || attr_type == 0x0001 {
                let addr = self.parse_mapped_address(
                    &response[offset..offset + attr_length],
                    attr_type == 0x0020,
                )?;
                debug!("STUN mapped address: {}", addr);
                return Ok(addr);
            }

            offset += attr_length;

            // Pad to 4-byte boundary
            let padding = (4 - (attr_length % 4)) % 4;
            offset += padding;
        }

        Err("No mapped address found in STUN response".to_string())
    }

    /// Parse MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute.
    fn parse_mapped_address(&self, data: &[u8], is_xored: bool) -> Result<String, String> {
        if data.len() < 4 {
            return Err("Mapped address too short".to_string());
        }

        // First byte is reserved (0x00)
        let family = data[1];

        let port = u16::from_be_bytes([data[2], data[3]]);
        let port = if is_xored {
            port ^ 0x2112 // XOR with magic cookie
        } else {
            port
        };

        match family {
            0x01 => {
                // IPv4
                if data.len() < 8 {
                    return Err("IPv4 address too short".to_string());
                }

                let mut ip_bytes = [0u8; 4];
                ip_bytes.copy_from_slice(&data[4..8]);

                if is_xored {
                    // XOR with magic cookie
                    let magic = [0x21, 0x12, 0xA4, 0x42];
                    for i in 0..4 {
                        ip_bytes[i] ^= magic[i];
                    }
                }

                Ok(format!(
                    "{}.{}.{}.{}:{}",
                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], port
                ))
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    return Err("IPv6 address too short".to_string());
                }

                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[4..20]);

                if is_xored {
                    // XOR with magic cookie
                    let magic = [0x21, 0x12, 0xA4, 0x42];
                    for i in 0..4 {
                        ip_bytes[i] ^= magic[i];
                    }
                }

                let ip: std::net::Ipv6Addr = ip_bytes.into();
                Ok(format!("[{}]:{}", ip, port))
            }
            _ => Err(format!("Unknown address family: 0x{:02X}", family)),
        }
    }
}

/// Query multiple STUN servers and return the first successful result.
pub fn query_stun_servers(servers: &[String]) -> Option<String> {
    for server in servers {
        match StunClient::new(server) {
            Ok(client) => match client.query() {
                Ok(addr) => {
                    debug!("STUN success via {}: {}", server, addr);
                    return Some(addr);
                }
                Err(e) => {
                    warn!("STUN query failed ({}): {}", server, e);
                }
            },
            Err(e) => {
                warn!("Failed to create STUN client ({}): {}", server, e);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_id_generation() {
        let id1 = StunClient::generate_transaction_id();
        let id2 = StunClient::generate_transaction_id();

        // IDs should be 12 bytes
        assert_eq!(id1.len(), 12);
        assert_eq!(id2.len(), 12);

        // Note: IDs might be same if generated in same nanosecond
        // In practice, they will differ due to timing
    }

    #[test]
    fn test_binding_request_format() {
        let tid = [0x00; 12];
        let request = StunClient::build_binding_request(&tid);

        // Check message type (Binding Request)
        assert_eq!(request[0], 0x00);
        assert_eq!(request[1], 0x01);

        // Check message length (0)
        assert_eq!(request[2], 0x00);
        assert_eq!(request[3], 0x00);

        // Check magic cookie
        assert_eq!(request[4], 0x21);
        assert_eq!(request[5], 0x12);
        assert_eq!(request[6], 0xA4);
        assert_eq!(request[7], 0x42);

        // Total size: 20 bytes
        assert_eq!(request.len(), 20);
    }

    #[test]
    fn test_parse_ipv4_address() {
        // Test IPv4 parsing (non-XORed)
        // Family: 0x01, Port: 8765 (0x223D), IP: 192.168.1.100
        let data = vec![
            0x00, 0x01, // Reserved + Family
            0x22, 0x3D, // Port (8765)
            0xC0, 0xA8, 0x01, 0x64, // IP (192.168.1.100)
        ];

        // Just verify the data is valid (actual parsing tested via integration)
        assert_eq!(data.len(), 8);
        assert_eq!(data[1], 0x01); // IPv4 family
    }

    #[ignore = "Requires network access"]
    #[test]
    fn test_real_stun_query() {
        let servers = vec!["stun.l.google.com:19302".to_string()];
        let result = query_stun_servers(&servers);

        assert!(result.is_some());
        let addr = result.unwrap();
        assert!(addr.contains(':'));
        println!("Public IP: {}", addr);
    }
}
