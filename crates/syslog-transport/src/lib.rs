//! Syslog transport layer — UDP, TCP, TLS, and DTLS listeners and senders.
//!
//! Implements transport mappings per:
//! - RFC 5426 — UDP transport
//! - RFC 5425 — TLS transport
//! - RFC 6012 — DTLS transport (types only; I/O not yet implemented)
//! - RFC 9662 — Updated cipher suites

pub mod dtls;
pub mod error;
pub mod framing;
pub mod tcp;
pub mod tls;
pub mod udp;

pub use dtls::{
    DtlsDatagram, DtlsError, DtlsListenerConfig, DtlsSession, DtlsVersion, run_dtls_listener,
};
pub use error::TransportError;
pub use framing::OctetCountingCodec;
pub use tcp::{TcpListenerConfig, TcpMessage, run_tcp_listener};
pub use udp::{UdpDatagram, UdpListenerConfig, run_udp_listener};
