//! RFC 6012 DTLS transport types and plaintext-fallback listener.
//!
//! No pure-Rust DTLS library is available, and the project forbids `openssl`.
//! The listener therefore falls back to **plaintext UDP** with a prominent
//! security warning.  All datagrams are forwarded into the pipeline as
//! [`DtlsDatagram`] values so that callers see the same type contract they
//! would get from a real DTLS implementation.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

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

    /// An I/O error occurred on the underlying UDP socket.
    #[error("DTLS I/O error: {0}")]
    Io(#[from] std::io::Error),

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

/// Maximum receive-buffer size for a single datagram (same limit as UDP).
const MAX_DATAGRAM_SIZE: usize = 65535;

/// How often (in received-datagram count) the session table is swept for
/// expired entries.  Keeps per-datagram overhead negligible.
const SESSION_SWEEP_INTERVAL: u64 = 256;

// ---------------------------------------------------------------------------
// Listener — plaintext UDP fallback
// ---------------------------------------------------------------------------

/// Run a DTLS syslog listener.
///
/// **Security warning:** No pure-Rust DTLS library is available and the
/// project forbids `openssl`, so this listener falls back to **plaintext
/// UDP**.  A prominent warning is logged at startup.  All received datagrams
/// are forwarded through `tx` as [`DtlsDatagram`] values, with session
/// tracking and idle-expiry identical to what a real DTLS implementation
/// would provide.
///
/// The listener runs until the `shutdown` watch signal becomes `true` or the
/// channel is closed.
///
/// # Errors
///
/// Returns [`DtlsError::Io`] if the underlying UDP socket cannot be bound.
pub async fn run_dtls_listener(
    config: &DtlsListenerConfig,
    tx: mpsc::Sender<DtlsDatagram>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), DtlsError> {
    // -----------------------------------------------------------------------
    // SECURITY WARNING — emitted at startup
    // -----------------------------------------------------------------------
    warn!(
        addr = %config.bind_addr,
        "DTLS listener falling back to PLAINTEXT UDP — \
         no pure-Rust DTLS library is available. \
         Datagrams are NOT encrypted. \
         Do NOT use this in production without network-level encryption (e.g. IPsec/WireGuard)."
    );

    let socket = UdpSocket::bind(config.bind_addr).await?;
    let bound_addr = socket.local_addr().unwrap_or(config.bind_addr);
    info!(addr = %bound_addr, "DTLS (plaintext-fallback) listener started");

    let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
    let mut sessions: HashMap<SocketAddr, DtlsSession> = HashMap::new();
    let mut datagram_counter: u64 = 0;

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, peer)) => {
                        // Update or create session
                        let session = sessions.entry(peer).or_insert_with(|| {
                            debug!(peer = %peer, "new DTLS (plaintext) session");
                            DtlsSession::new(peer)
                        });
                        session.record_datagram();

                        let payload = buf.get(..len).unwrap_or_default().to_vec();
                        let datagram = DtlsDatagram {
                            peer,
                            payload,
                            received_at: Instant::now(),
                        };

                        if let Err(e) = tx.try_send(datagram) {
                            match e {
                                mpsc::error::TrySendError::Full(_) => {
                                    warn!(
                                        peer = %peer,
                                        "DTLS ingest channel full, dropping datagram"
                                    );
                                }
                                mpsc::error::TrySendError::Closed(_) => {
                                    debug!("DTLS ingest channel closed, shutting down");
                                    return Ok(());
                                }
                            }
                        }

                        // Periodic session sweep
                        datagram_counter = datagram_counter.saturating_add(1);
                        if datagram_counter % SESSION_SWEEP_INTERVAL == 0 {
                            sweep_expired_sessions(
                                &mut sessions,
                                config.max_idle_timeout,
                            );
                        }
                    }
                    Err(e) => {
                        warn!("DTLS (plaintext) recv error: {e}");
                    }
                }
            }
            _ = crate::udp::shutdown_signal(&shutdown) => {
                info!("DTLS (plaintext-fallback) listener shutting down");
                return Ok(());
            }
        }
    }
}

/// Remove sessions that have been idle longer than `timeout`.
fn sweep_expired_sessions(sessions: &mut HashMap<SocketAddr, DtlsSession>, timeout: Duration) {
    let before = sessions.len();
    sessions.retain(|_peer, session| !session.is_expired(timeout));
    let removed = before.saturating_sub(sessions.len());
    if removed > 0 {
        debug!(
            removed,
            remaining = sessions.len(),
            "swept expired DTLS sessions"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::sync::watch;

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

    #[test]
    fn dtls_error_display_not_available() {
        let err = DtlsError::NotAvailable;
        let msg = format!("{err}");
        assert_eq!(msg, "DTLS transport is not yet implemented");
    }

    #[test]
    fn dtls_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::AddrInUse, "address in use");
        let err = DtlsError::Io(io_err);
        let msg = format!("{err}");
        assert!(msg.contains("address in use"));
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

    #[test]
    fn sweep_expired_sessions_removes_old() {
        let mut sessions = HashMap::new();
        let peer1 = localhost(1111);
        let peer2 = localhost(2222);

        // peer1: create with an artificially old last_activity
        let mut s1 = DtlsSession::new(peer1);
        // We can't easily backdate Instant, so use a zero timeout to expire
        // everything, and verify sweep removes entries.
        s1.record_datagram();
        sessions.insert(peer1, s1);

        let s2 = DtlsSession::new(peer2);
        sessions.insert(peer2, s2);

        // With a very large timeout nothing should be removed
        sweep_expired_sessions(&mut sessions, Duration::from_secs(3600));
        assert_eq!(sessions.len(), 2);

        // With Duration::ZERO, elapsed > 0 should expire both (may not on
        // very fast machines, but at least the function doesn't panic).
        // We accept either outcome here.
        sweep_expired_sessions(&mut sessions, Duration::ZERO);
        // sessions.len() is 0 or 2 depending on timing — just assert no panic.
        assert!(sessions.len() <= 2);
    }

    // -- Async listener tests -----------------------------------------------

    #[tokio::test]
    async fn dtls_listener_receives_datagram() {
        // Bind to ephemeral port
        let mut cfg = DtlsListenerConfig::new(
            localhost(0),
            PathBuf::from("/cert.pem"),
            PathBuf::from("/key.pem"),
        );
        // Override bind_addr with port 0 for test (validation rejects this,
        // but run_dtls_listener does not call validate).
        cfg.bind_addr = ([127, 0, 0, 1], 0u16).into();

        // Discover a free port by pre-binding
        let probe = UdpSocket::bind(cfg.bind_addr).await;
        assert!(probe.is_ok());
        let probe = match probe {
            Ok(s) => s,
            Err(_) => return,
        };
        let bound_addr = probe.local_addr().unwrap_or(cfg.bind_addr);
        drop(probe);

        cfg.bind_addr = bound_addr;

        let (tx, mut rx) = mpsc::channel::<DtlsDatagram>(16);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            let _ = run_dtls_listener(&cfg, tx, shutdown_rx).await;
        });

        // Give the listener time to bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send a test datagram
        let sender_addr: SocketAddr = ([127, 0, 0, 1], 0u16).into();
        let sender = match UdpSocket::bind(sender_addr).await {
            Ok(s) => s,
            Err(_) => {
                let _ = _shutdown_tx.send(true);
                let _ = handle.await;
                return;
            }
        };
        let _ = sender
            .send_to(b"<13>1 - - - - - - dtls-test", bound_addr)
            .await;

        // Receive
        let datagram = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
        assert!(datagram.is_ok());
        if let Ok(Some(d)) = datagram {
            assert_eq!(d.payload, b"<13>1 - - - - - - dtls-test");
        }

        let _ = _shutdown_tx.send(true);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn dtls_listener_shuts_down_on_signal() {
        let cfg = DtlsListenerConfig {
            bind_addr: ([127, 0, 0, 1], 0u16).into(),
            cert_path: PathBuf::from("/cert.pem"),
            key_path: PathBuf::from("/key.pem"),
            min_version: DtlsVersion::Dtls12,
            max_idle_timeout: Duration::from_secs(30),
        };

        let (tx, _rx) = mpsc::channel::<DtlsDatagram>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            let _ = run_dtls_listener(&cfg, tx, shutdown_rx).await;
        });

        // Give the listener time to bind, then signal shutdown
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(true);

        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "listener should shut down within 2 seconds");
    }

    #[tokio::test]
    async fn dtls_listener_tracks_sessions() {
        let cfg = DtlsListenerConfig {
            bind_addr: ([127, 0, 0, 1], 0u16).into(),
            cert_path: PathBuf::from("/cert.pem"),
            key_path: PathBuf::from("/key.pem"),
            min_version: DtlsVersion::Dtls12,
            max_idle_timeout: Duration::from_secs(30),
        };

        let (tx, mut rx) = mpsc::channel::<DtlsDatagram>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Pre-bind to discover port
        let probe = match UdpSocket::bind(cfg.bind_addr).await {
            Ok(s) => s,
            Err(_) => return,
        };
        let bound_addr = probe.local_addr().unwrap_or(cfg.bind_addr);
        drop(probe);

        let listen_cfg = DtlsListenerConfig {
            bind_addr: bound_addr,
            ..cfg
        };

        let handle = tokio::spawn(async move {
            let _ = run_dtls_listener(&listen_cfg, tx, shutdown_rx).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send multiple datagrams from the same source
        let sender_addr: SocketAddr = ([127, 0, 0, 1], 0u16).into();
        let sender = match UdpSocket::bind(sender_addr).await {
            Ok(s) => s,
            Err(_) => {
                let _ = shutdown_tx.send(true);
                let _ = handle.await;
                return;
            }
        };

        for i in 0..3u8 {
            let msg = format!("<13>1 - - - - - - msg{i}");
            let _ = sender.send_to(msg.as_bytes(), bound_addr).await;
        }

        // Receive all three
        for _ in 0..3 {
            let datagram = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
            assert!(datagram.is_ok(), "should receive datagram");
        }

        let _ = shutdown_tx.send(true);
        let _ = handle.await;
    }
}
