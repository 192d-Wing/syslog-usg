//! Transport error types.

use thiserror::Error;

/// Errors that can occur in the transport layer.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("frame too large: {size} bytes exceeds maximum {max}")]
    FrameTooLarge { size: usize, max: usize },

    #[error("invalid frame: {0}")]
    InvalidFrame(String),

    #[error("connection closed")]
    ConnectionClosed,
}
