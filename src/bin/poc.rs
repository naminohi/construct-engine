//! Phase 0 PoC — QUIC + HTTP/3 connectivity test
//!
//! Opens a QUIC connection to a known HTTP/3 endpoint and makes a GET request.
//! Validates the full quinn + h3 stack before we build real gRPC calls.
//!
//! Usage:
//!   cargo run --bin poc -- [host] [path]
//!   cargo run --bin poc -- quic.tech /
//!   cargo run --bin poc -- cloudflare.com /cdn-cgi/trace

use std::sync::Arc;

use bytes::Buf;
use http::{Request, Uri};
use quinn::{ClientConfig, Endpoint};
use rustls::RootCertStore;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("poc=info".parse()?))
        .init();

    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).map(|s| s.as_str()).unwrap_or("cloudflare.com");
    let path = args.get(2).map(|s| s.as_str()).unwrap_or("/cdn-cgi/trace");
    let port: u16 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(443);

    info!(%host, %path, %port, "construct-engine Phase 0 PoC");

    // Explicitly select ring as TLS backend (construct-core pulls in aws-lc-rs too)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let result = run(host, path, port).await;
    match &result {
        Ok(body) => {
            info!("SUCCESS — response body ({} bytes):", body.len());
            println!("{}", String::from_utf8_lossy(body));
        }
        Err(e) => {
            error!("FAILED: {e:#}");
        }
    }

    result.map(|_| ())
}

async fn run(host: &str, path: &str, port: u16) -> anyhow::Result<Vec<u8>> {
    // ── Build TLS config ────────────────────────────────────────────────────
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Also try native roots (macOS Keychain)
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            let mut added = 0usize;
            for cert in certs {
                if root_store.add(cert).is_ok() {
                    added += 1;
                }
            }
            info!("loaded {added} native CA certs");
        }
        Err(e) => {
            tracing::warn!("native certs unavailable: {e}");
        }
    }

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // HTTP/3 ALPN — required for QUIC/H3 connections
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));

    // ── Bind QUIC endpoint ──────────────────────────────────────────────────
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // ── DNS resolve ─────────────────────────────────────────────────────────
    let addr = tokio::net::lookup_host(format!("{host}:{port}"))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("DNS resolve failed for {host}"))?;

    info!(%addr, "connecting");

    // ── QUIC handshake ──────────────────────────────────────────────────────
    let conn = endpoint.connect(addr, host)?.await?;
    info!(rtt=?conn.rtt(), "QUIC handshake complete — ALPN={:?}",
        conn.handshake_data()
            .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|d| d.protocol.clone())
            .map(|p| String::from_utf8_lossy(&p).into_owned())
            .unwrap_or_else(|| "?".to_string())
    );

    // ── HTTP/3 client ───────────────────────────────────────────────────────
    let quinn_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(quinn_conn).await?;

    // Drive the H3 connection in the background
    let drive_handle = tokio::spawn(async move {
        let err = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        error!("H3 driver closed: {err}");
    });

    // ── Send GET request ────────────────────────────────────────────────────
    let uri: Uri = format!("https://{host}{path}").parse()?;
    let req = Request::builder()
        .method("GET")
        .uri(&uri)
        .header("user-agent", "construct-engine/0.1.0")
        .body(())?;

    info!(%uri, "sending GET");
    let mut stream = send_request.send_request(req).await?;
    stream.finish().await?;

    // ── Read response ────────────────────────────────────────────────────────
    let resp = stream.recv_response().await?;
    info!(status = %resp.status(), "response received");

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }

    // Cleanly close the send side, then wait for driver
    drop(stream);
    drop(send_request);
    drive_handle.abort();

    Ok(body)
}
