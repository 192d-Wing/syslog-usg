//! Syslog transport layer — UDP, TCP, and TLS listeners and senders.
//!
//! Implements transport mappings per:
//! - RFC 5426 — UDP transport
//! - RFC 5425 — TLS transport
//! - RFC 9662 — Updated cipher suites

pub mod error;
pub mod framing;
pub mod tcp;
pub mod tls;
pub mod udp;

pub use error::TransportError;
pub use framing::OctetCountingCodec;
pub use tcp::{TcpListenerConfig, TcpMessage, run_tcp_listener};
pub use udp::{UdpDatagram, UdpListenerConfig, run_udp_listener};
