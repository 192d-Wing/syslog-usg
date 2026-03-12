//! Network output — forwards syslog messages to a remote server over TCP or TLS.
//!
//! Uses RFC 5424 serialization and RFC 5425 octet-counting framing.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use syslog_proto::SyslogMessage;
use syslog_relay::RelayError;
use syslog_relay::output::Output;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// A network output that sends syslog messages over TCP or TLS
/// using octet-counting framing (RFC 5425 §4.3).
#[derive(Clone)]
pub struct NetworkOutput {
    name: String,
    addr: SocketAddr,
    tls_connector: Option<Arc<tokio_rustls::TlsConnector>>,
    tls_server_name: String,
    conn: Arc<Mutex<Option<Connection>>>,
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
        }
    }

    /// Establish a connection if not already connected.
    async fn ensure_connected(&self) -> Result<(), RelayError> {
        let mut guard = self.conn.lock().await;
        if guard.is_some() {
            return Ok(());
        }

        let tcp_stream = tokio::net::TcpStream::connect(self.addr)
            .await
            .map_err(|e| RelayError::OutputSendFailed {
                output: self.name.clone(),
                reason: format!("connect to {}: {e}", self.addr),
            })?;

        let conn = if let Some(ref connector) = self.tls_connector {
            let server_name = rustls::pki_types::ServerName::try_from(self.tls_server_name.clone())
                .map_err(|e| RelayError::OutputSendFailed {
                    output: self.name.clone(),
                    reason: format!("invalid server name '{}': {e}", self.tls_server_name),
                })?;

            let tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| RelayError::OutputSendFailed {
                    output: self.name.clone(),
                    reason: format!("TLS handshake to {}: {e}", self.addr),
                })?;

            Connection::Tls(Box::new(tls_stream))
        } else {
            Connection::Tcp(tcp_stream)
        };

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
