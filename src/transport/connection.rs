use std::sync::Arc;

use quinn::{ClientConfig, Endpoint};
use rustls::RootCertStore;
use tracing::{debug, info};

use crate::{config::EngineConfig, error::EngineError};

/// QUIC connection manager.
///
/// Phase 0: creates a quinn `Endpoint` with proper TLS roots.
///          Connection is opened lazily on first use.
/// Phase 1: implements `open_bidi_stream()` and `open_unary_stream()`.
/// Phase 4: swaps TLS backend to aws-lc-rs for X25519Kyber768Draft00.
pub struct QuicConnection {
    pub endpoint: Endpoint,
    pub server_name: String,
    pub server_addr: std::net::SocketAddr,
}

impl QuicConnection {
    pub async fn new(config: Arc<EngineConfig>) -> Result<Self, EngineError> {
        let tls = build_tls_config(&config)?;

        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                .map_err(|e| EngineError::tls(format!("QuicClientConfig: {e}")))?,
        ));

        // Bind to an ephemeral local port (0.0.0.0:0)
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| EngineError::transport(format!("endpoint bind: {e}")))?;
        endpoint.set_default_client_config(client_config);

        let server_addr = resolve_addr(&config).await?;

        info!(
            host = %config.server_host,
            addr = %server_addr,
            "QuicConnection ready"
        );

        Ok(Self {
            endpoint,
            server_name: config.server_host.clone(),
            server_addr,
        })
    }

    /// Open a new QUIC connection to the server.
    /// Each call returns a fresh `quinn::Connection` (0-RTT on subsequent calls).
    pub async fn connect(&self) -> Result<quinn::Connection, EngineError> {
        debug!(addr = %self.server_addr, "opening QUIC connection");
        let conn = self
            .endpoint
            .connect(self.server_addr, &self.server_name)
            .map_err(|e| EngineError::transport(format!("connect: {e}")))?
            .await
            .map_err(|e| EngineError::transport(format!("handshake: {e}")))?;
        info!(
            rtt = ?conn.rtt(),
            "QUIC handshake complete"
        );
        Ok(conn)
    }
}

fn build_tls_config(config: &EngineConfig) -> Result<rustls::ClientConfig, EngineError> {
    let mut root_store = RootCertStore::empty();

    if config.verify_certs {
        // Load system certificate roots (macOS Keychain / Linux trust store)
        let native_certs = rustls_native_certs::load_native_certs()
            .map_err(|e| EngineError::tls(format!("native certs: {e}")))?;
        for cert in native_certs {
            root_store
                .add(cert)
                .map_err(|e| EngineError::tls(format!("add cert: {e}")))?;
        }

        // Also add well-known roots for environments without full system trust
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    } else {
        // Dev/testing: accept any certificate
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // HTTP/3 ALPN — required for QUIC/H3
    tls.alpn_protocols = vec![b"h3".to_vec()];

    Ok(tls)
}

async fn resolve_addr(config: &EngineConfig) -> Result<std::net::SocketAddr, EngineError> {
    use tokio::net::lookup_host;
    let host_port = format!("{}:{}", config.server_host, config.server_port);
    let addr = lookup_host(&host_port)
        .await
        .map_err(|e| EngineError::transport(format!("DNS resolve '{host_port}': {e}")))?
        .next()
        .ok_or_else(|| EngineError::transport(format!("no addresses for '{host_port}'")))?;
    Ok(addr)
}
