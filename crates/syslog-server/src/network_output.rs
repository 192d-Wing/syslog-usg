//! Network output — forwards syslog messages to a remote server over TCP or TLS.
//!
//! Uses RFC 5424 serialization and RFC 5425 octet-counting framing.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use syslog_proto::SyslogMessage;
use syslog_relay::RelayError;
use syslog_relay::output::Output;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Minimum reconnection backoff.
const MIN_BACKOFF: Duration = Duration::from_millis(100);
/// Maximum reconnection backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// A network output that sends syslog messages over TCP or TLS
/// using octet-counting framing (RFC 5425 §4.3).
#[derive(Clone)]
pub struct NetworkOutput {
    name: String,
    addr: SocketAddr,
    tls_connector: Option<Arc<tokio_rustls::TlsConnector>>,
    tls_server_name: String,
    conn: Arc<Mutex<Option<Connection>>>,
    /// Backoff state for reconnection attempts.
    backoff: Arc<Mutex<BackoffState>>,
}

/// Tracks exponential backoff between reconnection attempts.
struct BackoffState {
    /// When the last connection attempt started (if any).
    last_attempt: Option<Instant>,
    /// Current backoff duration (doubles on each failure, capped at MAX_BACKOFF).
    current: Duration,
}

impl Default for BackoffState {
    fn default() -> Self {
        Self {
            last_attempt: None,
            current: MIN_BACKOFF,
        }
    }
}

/// An active connection — either plain TCP or TLS.
enum Connection {
    Tcp(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl Connection {
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(data).await,
            Self::Tls(stream) => stream.write_all(data).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush().await,
            Self::Tls(stream) => stream.flush().await,
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown().await,
            Self::Tls(stream) => stream.shutdown().await,
        }
    }
}

impl fmt::Debug for NetworkOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkOutput")
            .field("name", &self.name)
            .field("addr", &self.addr)
            .field("tls", &self.tls_connector.is_some())
            .finish()
    }
}

impl NetworkOutput {
    /// Create a new TCP network output.
    #[must_use]
    pub fn tcp(name: impl Into<String>, addr: SocketAddr) -> Self {
        Self {
            name: name.into(),
            addr,
            tls_connector: None,
            tls_server_name: String::new(),
            conn: Arc::new(Mutex::new(None)),
            backoff: Arc::new(Mutex::new(BackoffState::default())),
        }
    }

    /// Create a new TLS network output.
    #[must_use]
    pub fn tls(
        name: impl Into<String>,
        addr: SocketAddr,
        connector: Arc<tokio_rustls::TlsConnector>,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            addr,
            tls_connector: Some(connector),
            tls_server_name: server_name.into(),
            conn: Arc::new(Mutex::new(None)),
            backoff: Arc::new(Mutex::new(BackoffState::default())),
        }
    }

    /// Add jitter to a duration (0-25% based on system clock nanoseconds).
    fn jittered(d: Duration) -> Duration {
        // Use sub-second nanoseconds from the system clock as a cheap
        // pseudo-random source. Unlike Instant::now().elapsed() (which is
        // always ~0), SystemTime provides varying nanoseconds.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let jitter_pct = (nanos % 26) as u64; // 0-25%
        let jitter = d.as_millis() as u64 * jitter_pct / 100;
        d + Duration::from_millis(jitter)
    }

    /// Establish a connection if not already connected, respecting backoff.
    async fn ensure_connected(&self) -> Result<(), RelayError> {
        let mut guard = self.conn.lock().await;
        if guard.is_some() {
            return Ok(());
        }

        // Check backoff window
        {
            let backoff = self.backoff.lock().await;
            if let Some(last) = backoff.last_attempt {
                let elapsed = last.elapsed();
                if elapsed < backoff.current {
                    return Err(RelayError::OutputSendFailed {
                        output: self.name.clone(),
                        reason: format!(
                            "backoff: retry in {}ms",
                            backoff.current.saturating_sub(elapsed).as_millis()
                        ),
                    });
                }
            }
        }

        // Record attempt time
        {
            let mut backoff = self.backoff.lock().await;
            backoff.last_attempt = Some(Instant::now());
        }

        let tcp_result = tokio::net::TcpStream::connect(self.addr).await;

        let tcp_stream = match tcp_result {
            Ok(s) => s,
            Err(e) => {
                // Increase backoff on failure
                let mut backoff = self.backoff.lock().await;
                backoff.current = Self::jittered(backoff.current.min(MAX_BACKOFF));
                let next = backoff.current.saturating_mul(2).min(MAX_BACKOFF);
                backoff.current = next;
                warn!(
                    output = %self.name,
                    backoff_ms = next.as_millis() as u64,
                    "connection failed, backing off: {e}"
                );
                return Err(RelayError::OutputSendFailed {
                    output: self.name.clone(),
                    reason: format!("connect to {}: {e}", self.addr),
                });
            }
        };

        let conn = if let Some(ref connector) = self.tls_connector {
            let server_name = rustls::pki_types::ServerName::try_from(self.tls_server_name.clone())
                .map_err(|e| RelayError::OutputSendFailed {
                    output: self.name.clone(),
                    reason: format!("invalid server name '{}': {e}", self.tls_server_name),
                })?;

            let tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| {
                    // Increase backoff on TLS failure too
                    warn!(
                        output = %self.name,
                        "TLS handshake failed, will back off: {e}"
                    );
                    RelayError::OutputSendFailed {
                        output: self.name.clone(),
                        reason: format!("TLS handshake to {}: {e}", self.addr),
                    }
                })?;

            Connection::Tls(Box::new(tls_stream))
        } else {
            Connection::Tcp(tcp_stream)
        };

        // Reset backoff on success
        {
            let mut backoff = self.backoff.lock().await;
            backoff.current = MIN_BACKOFF;
            backoff.last_attempt = None;
        }

        debug!(
            output = %self.name,
            addr = %self.addr,
            tls = self.tls_connector.is_some(),
            "connected to remote syslog server"
        );

        *guard = Some(conn);
        Ok(())
    }

    /// Send an octet-counted frame: `{len} {data}`.
    async fn send_framed(&self, data: &[u8]) -> Result<(), RelayError> {
        let mut guard = self.conn.lock().await;
        let conn = guard.as_mut().ok_or_else(|| RelayError::OutputSendFailed {
            output: self.name.clone(),
            reason: "not connected".to_owned(),
        })?;

        // RFC 5425 §4.3: SYSLOG-FRAME = MSG-LEN SP SYSLOG-MSG
        let header = format!("{} ", data.len());

        let result = async {
            conn.write_all(header.as_bytes()).await?;
            conn.write_all(data).await?;
            conn.flush().await
        }
        .await;

        if let Err(e) = result {
            // Drop the broken connection so next send reconnects
            warn!(output = %self.name, "write failed, dropping connection: {e}");
            if let Some(mut c) = guard.take() {
                let _ = c.shutdown().await;
            }
            return Err(RelayError::OutputSendFailed {
                output: self.name.clone(),
                reason: format!("write to {}: {e}", self.addr),
            });
        }

        Ok(())
    }
}

impl Output for NetworkOutput {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, message: SyslogMessage) -> Result<(), RelayError> {
        // Ensure we have a connection (lazy connect / reconnect)
        self.ensure_connected().await?;

        // Serialize to RFC 5424 wire format
        let wire = syslog_parse::rfc5424::serializer::serialize(&message);

        // Send with octet-counting framing
        self.send_framed(&wire).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_state_defaults() {
        let state = BackoffState::default();
        assert_eq!(state.current, MIN_BACKOFF);
        assert!(state.last_attempt.is_none());
    }

    #[tokio::test]
    async fn backoff_increases_on_failure() {
        // Connect to a port that won't accept connections
        let output = NetworkOutput::tcp(
            "test",
            "127.0.0.1:1"
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 1))),
        );

        // First attempt should fail
        let r1 = output.ensure_connected().await;
        assert!(r1.is_err());

        // Check backoff increased
        let backoff = output.backoff.lock().await;
        assert!(
            backoff.current > MIN_BACKOFF,
            "backoff should increase after failure"
        );
        assert!(backoff.last_attempt.is_some());
    }

    #[test]
    fn jittered_duration_is_at_least_original() {
        let d = Duration::from_millis(100);
        let j = NetworkOutput::jittered(d);
        assert!(j >= d, "jittered duration should be >= original");
    }
}
