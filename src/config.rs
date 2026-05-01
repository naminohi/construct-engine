/// Engine configuration passed from Swift at startup.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Construct server hostname (e.g. "api.konstruct.cc")
    pub server_host: String,

    /// QUIC/HTTP3 port (default: 443)
    pub server_port: u16,

    /// The authenticated user's device ID (UUID string).
    /// Set after first successful auth; empty string before first auth.
    pub my_device_id: String,

    /// Access token from Keychain — passed at startup if the user was
    /// previously authenticated.  May be None for fresh installs.
    pub auth_token: Option<String>,

    /// Whether to verify TLS certificates (false only in dev)
    pub verify_certs: bool,

    /// Enable MASQUE CONNECT-UDP tunnelling for censorship evasion.
    /// When true, QUIC is tunnelled through an HTTP/3 MASQUE proxy.
    pub use_masque: bool,

    /// MASQUE proxy host (required when use_masque = true)
    pub masque_host: Option<String>,

    /// MASQUE proxy port (default: 443)
    pub masque_port: Option<u16>,

    /// Event channel buffer depth (default: 1024)
    pub event_buffer: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            server_host: "api.konstruct.cc".to_string(),
            server_port: 443,
            my_device_id: String::new(),
            auth_token: None,
            verify_certs: true,
            use_masque: false,
            masque_host: None,
            masque_port: None,
            event_buffer: 1024,
        }
    }
}

impl EngineConfig {
    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.server_host, self.server_port)
    }
}
