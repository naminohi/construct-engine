//! gRPC-over-HTTP/3 framing helpers.
//!
//! gRPC wire format (identical over H2 and H3):
//!   1 byte  — compression flag (0 = uncompressed)
//!   4 bytes — message length (big-endian u32)
//!   N bytes — protobuf-encoded message body
//!
//! HTTP/3 headers required by gRPC:
//!   :method  = POST
//!   :path    = /package.ServiceName/MethodName
//!   :scheme  = https
//!   content-type = application/grpc+proto
//!   te = trailers
//!   authorization = Bearer <token>

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::EngineError;

/// Encode a protobuf message into a gRPC length-prefix frame.
pub fn encode_grpc_frame(proto_bytes: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(5 + proto_bytes.len());
    buf.put_u8(0); // compression flag: 0 = uncompressed
    buf.put_u32(proto_bytes.len() as u32);
    buf.put_slice(proto_bytes);
    buf.freeze()
}

/// Decode a gRPC length-prefix frame from raw bytes.
/// Returns `(message_bytes, remaining_bytes)`.
pub fn decode_grpc_frame(mut data: Bytes) -> Result<(Bytes, Bytes), EngineError> {
    if data.len() < 5 {
        return Err(EngineError::transport(format!(
            "gRPC frame too short: {} bytes",
            data.len()
        )));
    }

    let compressed = data.get_u8();
    if compressed != 0 {
        return Err(EngineError::transport(
            "compressed gRPC frames not supported",
        ));
    }

    let msg_len = data.get_u32() as usize;
    if data.len() < msg_len {
        return Err(EngineError::transport(format!(
            "gRPC frame incomplete: need {msg_len} bytes, have {}",
            data.len()
        )));
    }

    let msg = data.split_to(msg_len);
    Ok((msg, data))
}

/// gRPC status codes (subset — full list at grpc.io/docs/guides/status-codes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GrpcStatus {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl GrpcStatus {
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::Cancelled,
            3 => Self::InvalidArgument,
            4 => Self::DeadlineExceeded,
            5 => Self::NotFound,
            7 => Self::PermissionDenied,
            8 => Self::ResourceExhausted,
            12 => Self::Unimplemented,
            13 => Self::Internal,
            14 => Self::Unavailable,
            16 => Self::Unauthenticated,
            _ => Self::Unknown,
        }
    }

    pub fn is_ok(self) -> bool {
        self == Self::Ok
    }

    pub fn is_unauthenticated(self) -> bool {
        self == Self::Unauthenticated
    }

    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Unavailable | Self::DeadlineExceeded | Self::ResourceExhausted
        )
    }
}

/// Build the HTTP/3 pseudo-headers and gRPC headers for a request.
pub fn grpc_request_headers(service_path: &str, auth_token: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        (":method".to_string(), "POST".to_string()),
        (":path".to_string(), service_path.to_string()),
        (":scheme".to_string(), "https".to_string()),
        (
            "content-type".to_string(),
            "application/grpc+proto".to_string(),
        ),
        ("te".to_string(), "trailers".to_string()),
        ("grpc-encoding".to_string(), "identity".to_string()),
        (
            "user-agent".to_string(),
            "construct-engine/0.1.0".to_string(),
        ),
    ];

    if let Some(token) = auth_token {
        headers.push(("authorization".to_string(), format!("Bearer {token}")));
    }

    headers
}

/// Parse gRPC trailers to extract status code and message.
/// Returns `(status_code, status_message)`.
pub fn parse_grpc_trailers(trailers: &[(String, String)]) -> (u32, String) {
    let code = trailers
        .iter()
        .find(|(k, _)| k == "grpc-status")
        .and_then(|(_, v)| v.parse::<u32>().ok())
        .unwrap_or(2); // Unknown

    let message = trailers
        .iter()
        .find(|(k, _)| k == "grpc-message")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    (code, message)
}
