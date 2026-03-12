//! RFC 6012 DTLS transport types.
//!
//! Phase A: Configuration types and session tracking structures.
//! Actual DTLS I/O is not yet implemented (no pure-Rust DTLS library available).

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use thiserror::Error;

// ---------------------------------------------------------------------------
// DTLS version
// ---------------------------------------------------------------------------

/// DTLS protocol version.
///
/// RFC 6012 specifies DTLS as the security mechanism for syslog over UDP.
/// DTLS 1.2 (RFC 6347) and DTLS 1.3 (RFC 9147) are the supported versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DtlsVersion {
    /// DTLS 1.2 (RFC 6347).
    Dtls12,
    /// DTLS 1.3 (RFC 9147).
    Dtls13,
}

impl DtlsVersion {
    /// Returns the version as a human-readable string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dtls12 => "DTLS 1.2",
            Self::Dtls13 => "DTLS 1.3",
        }
    }
}

impl fmt::Display for DtlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Listener configuration
// ---------------------------------------------------------------------------

/// Configuration for a DTLS syslog listener.
///
/// RFC 6012 §4: A DTLS transport sender or collector listens on a UDP port
/// and negotiates a DTLS session for each peer.
#[derive(Debug, Clone)]
pub struct DtlsListenerConfig {
    /// The socket address to bind to.
    pub bind_addr: SocketAddr,
    /// Path to PEM certificate file.
    pub cert_path: PathBuf,
    /// Path to PEM private-key file.
    pub key_path: PathBuf,
    /// Minimum DTLS version to accept.
    pub min_version: DtlsVersion,
    /// Maximum idle time before a session is considered expired.
    pub max_idle_timeout: Duration,
}

impl DtlsListenerConfig {
    /// Default idle timeout: 30 seconds.
    const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;

    /// Creates a new configuration with sensible defaults for the version
    /// and idle timeout.
    #[must_use]
    pub fn new(bind_addr: SocketAddr, cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            bind_addr,
            cert_path,
            key_path,
            min_version: DtlsVersion::Dtls12,
            max_idle_timeout: Duration::from_secs(Self::DEFAULT_IDLE_TIMEOUT_SECS),
        }
    }

    /// Validate the configuration, returning an error if it is invalid.
    pub fn validate(&self) -> Result<(), DtlsError> {
        if self.bind_addr.port() == 0 {
            return Err(DtlsError::InvalidConfig(
                "bind address must have a non-zero port".to_owned(),
            ));
        }
        if self.cert_path.as_os_str().is_empty() {
            return Err(DtlsError::InvalidConfig(
                "cert_path must not be empty".to_owned(),
            ));
        }
        if self.key_path.as_os_str().is_empty() {
            return Err(DtlsError::InvalidConfig(
                "key_path must not be empty".to_owned(),
            ));
        }
        if self.max_idle_timeout.is_zero() {
            return Err(DtlsError::InvalidConfig(
                "max_idle_timeout must be > 0".to_owned(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Datagram
// ---------------------------------------------------------------------------

/// A decrypted DTLS datagram received from a peer.
///
/// In a full implementation this would be produced after DTLS decryption.
/// For now it serves as the type contract for the pipeline.
#[derive(Debug, Clone)]
pub struct DtlsDatagram {
    /// The peer address that sent the datagram.
    pub peer: SocketAddr,
    /// The decrypted payload bytes.
    pub payload: Vec<u8>,
    /// The instant the datagram was received.
    pub received_at: Instant,
}

// ---------------------------------------------------------------------------
// Session tracking
// ---------------------------------------------------------------------------

/// Tracks an active DTLS session with a remote peer.
///
/// RFC 6012 §4: The collector maintains session state per peer for the
/// lifetime of the DTLS association.
#[derive(Debug, Clone)]
pub struct DtlsSession {
    /// The peer's socket address.
    pub peer: SocketAddr,
    /// When the session was established.
    pub established_at: Instant,
    /// Last activity timestamp, updated on each received datagram.
    pub last_activity: Instant,
    /// Number of datagrams received in this session.
    pub datagrams_received: u64,
}

impl DtlsSession {
    /// Create a new session for the given peer, established "now".
    #[must_use]
    pub fn new(peer: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            peer,
            established_at: now,
            last_activity: now,
            datagrams_received: 0,
        }
    }

    /// Returns `true` if the session has been idle longer than `timeout`.
    #[must_use]
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Record a received datagram, updating the last-activity timestamp.
    pub fn record_datagram(&mut self) {
        self.last_activity = Instant::now();
        self.datagrams_received = self.datagrams_received.saturating_add(1);
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors specific to the DTLS transport.
#[derive(Debug, Error)]
pub enum DtlsError {
    /// DTLS transport is not yet implemented (no pure-Rust DTLS library).
    #[error("DTLS transport is not yet implemented")]
    NotAvailable,

    /// A DTLS session has expired due to inactivity.
    #[error("DTLS session expired for peer {peer}")]
    SessionExpired {
        /// The peer whose session expired.
        peer: SocketAddr,
    },

    /// The DTLS configuration is invalid.
    #[error("invalid DTLS configuration: {0}")]
    InvalidConfig(String),
}

// ---------------------------------------------------------------------------
// Listener stub
// ---------------------------------------------------------------------------

/// Run a DTLS syslog listener.
///
/// **Not yet implemented.** This always returns [`DtlsError::NotAvailable`]
/// because no pure-Rust DTLS library is available. Once one is, this function
/// will accept datagrams, negotiate DTLS sessions, and forward decrypted
/// payloads into the pipeline.
///
/// # Errors
///
/// Always returns `Err(DtlsError::NotAvailable)` in this phase.
pub async fn run_dtls_listener(_config: &DtlsListenerConfig) -> Result<(), DtlsError> {
    Err(DtlsError::NotAvailable)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn dtls_version_as_str() {
        assert_eq!(DtlsVersion::Dtls12.as_str(), "DTLS 1.2");
        assert_eq!(DtlsVersion::Dtls13.as_str(), "DTLS 1.3");
    }

    #[test]
    fn dtls_version_display() {
        let v12 = format!("{}", DtlsVersion::Dtls12);
        let v13 = format!("{}", DtlsVersion::Dtls13);
        assert_eq!(v12, "DTLS 1.2");
        assert_eq!(v13, "DTLS 1.3");
    }

    #[test]
    fn dtls_version_equality() {
        assert_eq!(DtlsVersion::Dtls12, DtlsVersion::Dtls12);
        assert_ne!(DtlsVersion::Dtls12, DtlsVersion::Dtls13);
    }

    #[test]
    fn dtls_listener_config_new_defaults() {
        let addr = localhost(6514);
        let cfg = DtlsListenerConfig::new(
            addr,
            PathBuf::from("/etc/ssl/cert.pem"),
            PathBuf::from("/etc/ssl/key.pem"),
        );
        assert_eq!(cfg.bind_addr, addr);
        assert_eq!(cfg.min_version, DtlsVersion::Dtls12);
        assert_eq!(cfg.max_idle_timeout, Duration::from_secs(30));
    }

    #[test]
    fn dtls_listener_config_validate_ok() {
        let cfg = DtlsListenerConfig::new(
            localhost(6514),
            PathBuf::from("/cert.pem"),
            PathBuf::from("/key.pem"),
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn dtls_listener_config_validate_zero_port() {
        let cfg = DtlsListenerConfig::new(
            localhost(0),
            PathBuf::from("/cert.pem"),
            PathBuf::from("/key.pem"),
        );
        let err = cfg.validate();
        assert!(
            matches!(err, Err(DtlsError::InvalidConfig(ref msg)) if msg.contains("non-zero port")),
            "expected InvalidConfig with non-zero port message"
        );
    }

    #[test]
    fn dtls_listener_config_validate_empty_cert() {
        let cfg = DtlsListenerConfig::new(
            localhost(6514),
            PathBuf::from(""),
            PathBuf::from("/key.pem"),
        );
        let result = cfg.validate();
        assert!(
            matches!(result, Err(DtlsError::InvalidConfig(ref msg)) if msg.contains("cert_path")),
            "expected InvalidConfig for empty cert_path"
        );
    }

    #[test]
    fn dtls_listener_config_validate_empty_key() {
        let cfg = DtlsListenerConfig::new(
            localhost(6514),
            PathBuf::from("/cert.pem"),
            PathBuf::from(""),
        );
        let result = cfg.validate();
        assert!(
            matches!(result, Err(DtlsError::InvalidConfig(ref msg)) if msg.contains("key_path")),
            "expected InvalidConfig for empty key_path"
        );
    }

    #[test]
    fn dtls_listener_config_validate_zero_timeout() {
        let mut cfg = DtlsListenerConfig::new(
            localhost(6514),
            PathBuf::from("/cert.pem"),
            PathBuf::from("/key.pem"),
        );
        cfg.max_idle_timeout = Duration::ZERO;
        let result = cfg.validate();
        assert!(
            matches!(result, Err(DtlsError::InvalidConfig(ref msg)) if msg.contains("max_idle_timeout")),
            "expected InvalidConfig for zero timeout"
        );
    }

    #[test]
    fn dtls_datagram_construction() {
        let now = Instant::now();
        let dg = DtlsDatagram {
            peer: localhost(12345),
            payload: vec![1, 2, 3],
            received_at: now,
        };
        assert_eq!(dg.peer.port(), 12345);
        assert_eq!(dg.payload, vec![1, 2, 3]);
        // received_at should be <= now (practically equal)
        assert!(dg.received_at <= Instant::now());
    }

    #[test]
    fn dtls_session_new_and_fields() {
        let peer = localhost(9999);
        let session = DtlsSession::new(peer);
        assert_eq!(session.peer, peer);
        assert_eq!(session.datagrams_received, 0);
        assert!(session.established_at <= session.last_activity);
    }

    #[test]
    fn dtls_session_record_datagram() {
        let mut session = DtlsSession::new(localhost(9999));
        assert_eq!(session.datagrams_received, 0);
        session.record_datagram();
        assert_eq!(session.datagrams_received, 1);
        session.record_datagram();
        assert_eq!(session.datagrams_received, 2);
    }

    #[test]
    fn dtls_session_is_expired() {
        let session = DtlsSession::new(localhost(9999));
        // With a very long timeout, should not be expired.
        assert!(!session.is_expired(Duration::from_secs(3600)));
        // With zero timeout, should be expired (any elapsed time > 0).
        // Note: Instant::now() - last_activity may be 0, so we allow either.
        // This is a best-effort check.
        let zero_check = session.is_expired(Duration::ZERO);
        // Either outcome is valid for Duration::ZERO since elapsed may be 0ns.
        let _ = zero_check;
    }

    #[tokio::test]
    async fn run_dtls_listener_returns_not_available() {
        let cfg = DtlsListenerConfig::new(
            localhost(6514),
            PathBuf::from("/cert.pem"),
            PathBuf::from("/key.pem"),
        );
        let result = run_dtls_listener(&cfg).await;
        assert!(
            matches!(result, Err(DtlsError::NotAvailable)),
            "expected DtlsError::NotAvailable"
        );
    }

    #[test]
    fn dtls_error_display_not_available() {
        let err = DtlsError::NotAvailable;
        let msg = format!("{err}");
        assert_eq!(msg, "DTLS transport is not yet implemented");
    }

    #[test]
    fn dtls_error_display_session_expired() {
        let err = DtlsError::SessionExpired {
            peer: localhost(1234),
        };
        let msg = format!("{err}");
        assert!(msg.contains("127.0.0.1:1234"));
        assert!(msg.contains("expired"));
    }

    #[test]
    fn dtls_error_display_invalid_config() {
        let err = DtlsError::InvalidConfig("bad value".to_owned());
        let msg = format!("{err}");
        assert!(msg.contains("bad value"));
    }
}
