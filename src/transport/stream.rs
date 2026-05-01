//! Bidirectional gRPC MessageStream over a single H3 request stream.
//!
//! `open_message_stream()` opens an HTTP/3 POST to `MessagingService/MessageStream`,
//! sends an initial `SubscribeRequest`, and drives a background pump task that:
//!
//!   1. Drains the outgoing channel and writes gRPC frames to the server.
//!   2. Polls for incoming frames (with a short timeout between send checks).
//!   3. Calls `on_frame(raw_bytes)` for each incoming gRPC frame.
//!
//! The pump uses a polling strategy (50 ms timeout on recv) because the h3
//! `RequestStream` cannot be split into independent send/recv halves — both
//! operations require `&mut self`.  For Phase 2+, this may be replaced with a
//! raw QUIC stream + manual QPACK headers to achieve true concurrency.

use std::time::Duration;

use bytes::{Buf, Bytes};
use http::Request;
use prost::Message;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
    error::EngineError,
    proto::services::v1::{MessageStreamRequest, SubscribeRequest, message_stream_request},
    transport::grpc::encode_grpc_frame,
};

type H3SendReq = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// How long the pump waits for an incoming frame before checking the send queue.
const RECV_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Channel depth for the outgoing frame queue.
const OUTGOING_CHANNEL_DEPTH: usize = 256;

fn uuid_v4_hex() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Lightweight UUID-like hex — no dep needed, just needs to be unique per request.
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{t:032x}")
}

// ── Public handle ─────────────────────────────────────────────────────────────

/// Handle to the live MessageStream bidi gRPC call.
///
/// Drop it (or call `close()`) to gracefully half-close the client side.
pub struct BiDiStreamHandle {
    /// Send gRPC frames (already length-prefixed) to the server.
    frame_tx: mpsc::Sender<Bytes>,
    /// Background pump task handle — aborted on drop.
    task: tokio::task::JoinHandle<()>,
}

impl BiDiStreamHandle {
    /// Enqueue a gRPC frame for sending.  Non-blocking; returns an error if
    /// the underlying pump task has exited (stream closed by server).
    pub async fn send_frame(&self, frame: Bytes) -> Result<(), EngineError> {
        self.frame_tx
            .send(frame)
            .await
            .map_err(|_| EngineError::transport("MessageStream send channel closed"))
    }

    /// Close the client send side gracefully.
    pub fn close(self) {
        drop(self);
    }
}

impl Drop for BiDiStreamHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ── Stream open ───────────────────────────────────────────────────────────────

/// Open the persistent `MessagingService/MessageStream` bidi call.
///
/// * `on_frame` — called for every incoming gRPC frame (raw 5-byte-prefixed bytes)
///               on the pump task's thread.  Keep it fast (channel forward only).
pub async fn open_message_stream<F>(
    send_req: &mut H3SendReq,
    service_path: &str,
    authority: &str,
    conversation_ids: Vec<String>,
    since_cursor: Option<String>,
    token: Option<&str>,
    on_frame: F,
) -> Result<BiDiStreamHandle, EngineError>
where
    F: Fn(Bytes) + Send + 'static,
{
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
        .map_err(|e| EngineError::transport(format!("build stream request: {e}")))?;

    let mut stream = send_req
        .send_request(req)
        .await
        .map_err(|e| EngineError::transport(format!("open MessageStream: {e}")))?;

    // The server immediately responds with 200 before any data frames.
    let response = stream
        .recv_response()
        .await
        .map_err(|e| EngineError::transport(format!("MessageStream recv_response: {e}")))?;

    if response.status() != http::StatusCode::OK {
        return Err(EngineError::transport(format!(
            "MessageStream HTTP {}",
            response.status()
        )));
    }
    info!(
        "MessageStream open — subscribing to {} conversation(s)",
        conversation_ids.len()
    );

    // Send the initial SubscribeRequest so the server starts delivering messages.
    let subscribe = MessageStreamRequest {
        request: Some(message_stream_request::Request::Subscribe(
            SubscribeRequest {
                conversation_ids,
                since_cursor,
                include_presence: false,
            },
        )),
        request_id: uuid_v4_hex(),
        attempt_id: None,
    };
    let subscribe_bytes = subscribe.encode_to_vec();
    stream
        .send_data(encode_grpc_frame(&subscribe_bytes))
        .await
        .map_err(|e| EngineError::transport(format!("SubscribeRequest send: {e}")))?;

    // Spawn the pump task.
    let (frame_tx, frame_rx) = mpsc::channel::<Bytes>(OUTGOING_CHANNEL_DEPTH);
    let task = tokio::spawn(pump_task(stream, frame_rx, on_frame));

    Ok(BiDiStreamHandle { frame_tx, task })
}

// ── Pump task ─────────────────────────────────────────────────────────────────

/// Drives the H3 bidi stream.
///
/// Uses a polling strategy: wait up to `RECV_POLL_INTERVAL` for incoming data,
/// then drain the outgoing queue before polling again.  This avoids a two-borrow
/// conflict (`&mut self` on both `send_data` and `recv_data`) without unsafe code.
async fn pump_task<F>(
    mut stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut outgoing_rx: mpsc::Receiver<Bytes>,
    on_frame: F,
) where
    F: Fn(Bytes),
{
    debug!("MessageStream pump started");
    let mut recv_buf = bytes::BytesMut::new();

    loop {
        // ── Phase 1: drain any pending outgoing frames ────────────────────────
        loop {
            match outgoing_rx.try_recv() {
                Ok(frame) => {
                    if let Err(e) = stream.send_data(frame).await {
                        warn!("MessageStream send_data failed: {e}");
                        let _ = stream.finish().await;
                        return;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // Handle dropped — half-close client send side and drain incoming.
                    info!("MessageStream outgoing channel closed — half-closing");
                    let _ = stream.finish().await;
                    return;
                }
            }
        }

        // ── Phase 2: poll for incoming data (bounded by RECV_POLL_INTERVAL) ──
        match tokio::time::timeout(RECV_POLL_INTERVAL, stream.recv_data()).await {
            Ok(Ok(Some(mut chunk))) => {
                let data: Bytes = chunk.copy_to_bytes(chunk.remaining());
                recv_buf.extend_from_slice(&data);

                // Drain all complete gRPC frames from the buffer.
                loop {
                    if recv_buf.len() < 5 {
                        break;
                    }
                    let msg_len =
                        u32::from_be_bytes([recv_buf[1], recv_buf[2], recv_buf[3], recv_buf[4]])
                            as usize;
                    if recv_buf.len() < 5 + msg_len {
                        break; // wait for more data
                    }
                    // Extract the full frame (header + body).
                    let frame = recv_buf.split_to(5 + msg_len).freeze();
                    on_frame(frame);
                }
            }
            Ok(Ok(None)) => {
                // Server cleanly closed the send side (half-close).
                info!("MessageStream: server closed send side");
                return;
            }
            Ok(Err(e)) => {
                error!("MessageStream recv_data error: {e}");
                return;
            }
            Err(_timeout) => {
                // Nothing received in RECV_POLL_INTERVAL — loop back to check sends.
            }
        }
    }
}
