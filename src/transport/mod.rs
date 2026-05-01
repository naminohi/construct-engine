pub mod connection;
pub mod grpc;
pub mod stream;

use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use http::Request;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::{config::EngineConfig, error::EngineError};
pub use connection::QuicConnection;
pub use stream::BiDiStreamHandle;

use self::grpc::{GrpcStatus, decode_grpc_frame, encode_grpc_frame};

// ── gRPC service paths ───────────────────────────────────────────────────────

pub const AUTH_AUTHENTICATE: &str = "/shared.proto.services.v1.AuthService/AuthenticateDevice";
pub const AUTH_REFRESH: &str = "/shared.proto.services.v1.AuthService/RefreshToken";
pub const AUTH_LOGOUT: &str = "/shared.proto.services.v1.AuthService/Logout";
pub const KEY_GET_BUNDLE: &str = "/shared.proto.services.v1.KeyService/GetPreKeyBundle";
pub const KEY_UPLOAD: &str = "/shared.proto.services.v1.KeyService/UploadPreKeys";
pub const KEY_COUNT: &str = "/shared.proto.services.v1.KeyService/GetPreKeyCount";
pub const KEY_ROTATE_SPK: &str = "/shared.proto.services.v1.KeyService/RotateSignedPreKey";
pub const MESSAGING_STREAM: &str = "/shared.proto.services.v1.MessagingService/MessageStream";
pub const MESSAGING_GET_PENDING: &str =
    "/shared.proto.services.v1.MessagingService/GetPendingMessages";
pub const USER_FIND: &str = "/shared.proto.services.v1.UserService/FindUser";
pub const NOTIFICATION_REGISTER: &str =
    "/shared.proto.services.v1.NotificationService/RegisterDeviceToken";

// ── H3 state ─────────────────────────────────────────────────────────────────

type H3SendReq = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

struct H3State {
    send_request: H3SendReq,
    /// Keeps the H3 connection driver alive. Dropped when the state is replaced.
    _driver: tokio::task::JoinHandle<()>,
}

// ── Transport ─────────────────────────────────────────────────────────────────

/// Top-level transport handle used by the engine event loop.
///
/// Phase 1: maintains a persistent H3 connection; provides `unary_call()` and
///          `open_message_stream()` for all gRPC interactions.
/// Phase 3: MASQUE CONNECT-UDP proxy mode.
pub struct Transport {
    pub config: Arc<EngineConfig>,
    pub quic: Arc<QuicConnection>,
    /// Live H3 connection (None until first use / after reconnect).
    h3: RwLock<Option<H3State>>,
    /// Current bearer token — set after successful auth.
    pub token: RwLock<Option<String>>,
}

impl Transport {
    pub async fn new(config: Arc<EngineConfig>) -> Result<Self, EngineError> {
        let quic = QuicConnection::new(Arc::clone(&config)).await?;
        let initial_token = config.auth_token.clone();
        Ok(Self {
            config,
            quic: Arc::new(quic),
            h3: RwLock::new(None),
            token: RwLock::new(initial_token),
        })
    }

    /// Establish (or re-establish) the H3 connection to the server.
    pub async fn connect_h3(&self) -> Result<(), EngineError> {
        let quic_conn = self.quic.connect().await?;
        let h3_quinn_conn = h3_quinn::Connection::new(quic_conn);

        let (mut h3_driver, send_request) = h3::client::new(h3_quinn_conn)
            .await
            .map_err(|e| EngineError::transport(format!("h3 client init: {e}")))?;

        let driver_handle = tokio::spawn(async move {
            let _closed = std::future::poll_fn(|cx| h3_driver.poll_close(cx)).await;
            error!("H3 driver closed");
        });

        *self.h3.write().await = Some(H3State {
            send_request,
            _driver: driver_handle,
        });

        info!("H3 connection established");
        Ok(())
    }

    /// Ensure a live H3 connection exists; connect if not.
    async fn ensure_h3(&self) -> Result<(), EngineError> {
        if self.h3.read().await.is_none() {
            self.connect_h3().await?;
        }
        Ok(())
    }

    /// Clone the SendRequest handle (cheap — wraps an Arc internally).
    async fn send_request(&self) -> Result<H3SendReq, EngineError> {
        let guard = self.h3.read().await;
        guard
            .as_ref()
            .map(|s| s.send_request.clone())
            .ok_or_else(|| EngineError::transport("H3 not connected"))
    }

    /// Make a single gRPC unary call over H3.
    ///
    /// `service_path` — e.g. `"/shared.proto.services.v1.AuthService/AuthenticateDevice"`
    /// `request_bytes` — prost-encoded request proto
    ///
    /// Returns the prost-encoded response proto bytes.
    pub async fn unary_call(
        &self,
        service_path: &str,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, EngineError> {
        self.ensure_h3().await?;

        let mut send_req = self.send_request().await?;
        let token = self.token.read().await.clone();
        let authority = self.config.server_addr();

        let result = do_unary_call(
            &mut send_req,
            service_path,
            &authority,
            request_bytes,
            token.as_deref(),
        )
        .await;

        // On transport failure: drop the H3 state so the next call reconnects.
        if let Err(EngineError::Transport { .. }) = &result {
            *self.h3.write().await = None;
            debug!("H3 connection dropped after transport error");
        }

        result
    }

    /// Open the persistent gRPC bidirectional MessageStream.
    ///
    /// Returns a `BiDiStreamHandle` that the engine uses to send frames and
    /// route incoming messages. The handle drives a background pump task that
    /// reads incoming frames and forwards them via `on_frame`.
    pub async fn open_message_stream<F>(
        &self,
        conversation_ids: Vec<String>,
        since_cursor: Option<String>,
        on_frame: F,
    ) -> Result<BiDiStreamHandle, EngineError>
    where
        F: Fn(Bytes) + Send + 'static,
    {
        self.ensure_h3().await?;

        let mut send_req = self.send_request().await?;
        let token = self.token.read().await.clone();
        let authority = self.config.server_addr();

        stream::open_message_stream(
            &mut send_req,
            MESSAGING_STREAM,
            &authority,
            conversation_ids,
            since_cursor,
            token.as_deref(),
            on_frame,
        )
        .await
    }
}

// ── Unary call implementation ────────────────────────────────────────────────

async fn do_unary_call(
    send_req: &mut H3SendReq,
    service_path: &str,
    authority: &str,
    request_bytes: &[u8],
    token: Option<&str>,
) -> Result<Vec<u8>, EngineError> {
    let uri = format!("https://{authority}{service_path}");
    let mut req_builder = Request::builder()
        .method("POST")
        .uri(&uri)
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        .header("grpc-encoding", "identity")
        .header("user-agent", "construct-engine/0.1.0");

    if let Some(t) = token {
        req_builder = req_builder.header("authorization", format!("Bearer {t}"));
    }

    let req = req_builder
        .body(())
        .map_err(|e| EngineError::transport(format!("build request: {e}")))?;

    let mut stream = send_req
        .send_request(req)
        .await
        .map_err(|e| EngineError::transport(format!("send_request '{service_path}': {e}")))?;

    // Send the gRPC frame and half-close the client send side.
    stream
        .send_data(encode_grpc_frame(request_bytes))
        .await
        .map_err(|e| EngineError::transport(format!("send_data: {e}")))?;
    stream
        .finish()
        .await
        .map_err(|e| EngineError::transport(format!("finish: {e}")))?;

    // Read HTTP response status.
    let response = stream
        .recv_response()
        .await
        .map_err(|e| EngineError::transport(format!("recv_response: {e}")))?;

    if response.status() != http::StatusCode::OK {
        return Err(EngineError::transport(format!(
            "HTTP {} from '{service_path}'",
            response.status()
        )));
    }

    // Collect the response body.
    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| EngineError::transport(format!("recv_data: {e}")))?
    {
        let b = chunk.copy_to_bytes(chunk.remaining());
        body.extend_from_slice(&b);
    }

    // Parse gRPC trailers.
    if let Some(trailers) = stream
        .recv_trailers()
        .await
        .map_err(|e| EngineError::transport(format!("recv_trailers: {e}")))?
    {
        let grpc_status = trailers
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(2);
        let grpc_msg = trailers
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let status = GrpcStatus::from_code(grpc_status);
        if !status.is_ok() {
            if status.is_unauthenticated() {
                return Err(EngineError::unauthenticated(grpc_msg));
            }
            return Err(EngineError::grpc(grpc_status, grpc_msg));
        }
    }

    // Decode the gRPC length-prefix frame.
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let (msg, _) = decode_grpc_frame(body.freeze())?;
    Ok(msg.to_vec())
}
