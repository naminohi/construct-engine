use thiserror::Error;

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("Transport error: {message}")]
    Transport { message: String },

    #[error("TLS error: {message}")]
    Tls { message: String },

    #[error("gRPC error: code={code}, message={message}")]
    Grpc { code: u32, message: String },

    #[error("Crypto error: {message}")]
    Crypto { message: String },

    #[error("Config error: {message}")]
    Config { message: String },

    #[error("Engine is already running")]
    AlreadyRunning,

    #[error("Engine is not running")]
    NotRunning,

    #[error("Operation timed out")]
    Timeout,

    #[error("Unauthenticated: {message}")]
    Unauthenticated { message: String },

    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl EngineError {
    pub fn transport(msg: impl ToString) -> Self {
        Self::Transport {
            message: msg.to_string(),
        }
    }
    pub fn tls(msg: impl ToString) -> Self {
        Self::Tls {
            message: msg.to_string(),
        }
    }
    pub fn grpc(code: u32, msg: impl ToString) -> Self {
        Self::Grpc {
            code,
            message: msg.to_string(),
        }
    }
    pub fn crypto(msg: impl ToString) -> Self {
        Self::Crypto {
            message: msg.to_string(),
        }
    }
    pub fn config(msg: impl ToString) -> Self {
        Self::Config {
            message: msg.to_string(),
        }
    }
    pub fn unauthenticated(msg: impl ToString) -> Self {
        Self::Unauthenticated {
            message: msg.to_string(),
        }
    }
    pub fn internal(msg: impl ToString) -> Self {
        Self::Internal {
            message: msg.to_string(),
        }
    }
}
