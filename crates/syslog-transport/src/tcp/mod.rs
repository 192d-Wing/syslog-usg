//! TCP transport with octet-counting framing.
//!
//! Provides a TCP listener that accepts connections and frames incoming
//! syslog messages using the octet-counting codec (RFC 5425 §4.3).
//! Can also upgrade connections to TLS.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use tracing::{debug, error, info, warn};

use crate::framing::OctetCountingCodec;

/// A framed syslog message received over TCP/TLS.
#[derive(Debug, Clone)]
pub struct TcpMessage {
    /// The raw message bytes.
    pub data: Bytes,
    /// The remote peer's address.
    pub peer: SocketAddr,
    /// Whether this connection uses TLS.
    pub tls: bool,
}

/// Configuration for a TCP/TLS syslog listener.
#[derive(Clone)]
pub struct TcpListenerConfig {
    /// The socket address to bind to.
    pub bind_addr: SocketAddr,
    /// Maximum message frame size.
    pub max_frame_size: usize,
    /// Optional TLS acceptor for TLS-enabled listeners.
    pub tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
}

impl Default for TcpListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: ([0, 0, 0, 0], 6514).into(),
            max_frame_size: 64 * 1024,
            tls_acceptor: None,
        }
    }
}

/// Run a TCP (or TLS) syslog listener, sending received messages to the channel.
///
/// # Errors
/// Returns an error if the TCP socket cannot be bound.
pub async fn run_tcp_listener(
    config: TcpListenerConfig,
    tx: mpsc::Sender<TcpMessage>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), crate::error::TransportError> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    let tls_acceptor = config.tls_acceptor.clone();
    let max_frame_size = config.max_frame_size;
    let is_tls = tls_acceptor.is_some();

    info!(
        addr = %config.bind_addr,
        tls = is_tls,
        "TCP syslog listener started"
    );

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        let tx = tx.clone();
                        let tls_acceptor = tls_acceptor.clone();

                        tokio::spawn(async move {
                            if let Some(acceptor) = tls_acceptor {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        handle_tls_connection(tls_stream, peer, max_frame_size, tx).await;
                                    }
                                    Err(e) => {
                                        warn!(peer = %peer, "TLS handshake failed: {e}");
                                    }
                                }
                            } else {
                                handle_tcp_connection(stream, peer, max_frame_size, tx).await;
                            }
                        });
                    }
                    Err(e) => {
                        error!("TCP accept error: {e}");
                    }
                }
            }
            _ = wait_for_shutdown(&shutdown) => {
                info!("TCP listener shutting down");
                return Ok(());
            }
        }
    }
}

/// Handle a plain TCP connection.
async fn handle_tcp_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    max_frame_size: usize,
    tx: mpsc::Sender<TcpMessage>,
) {
    debug!(peer = %peer, "TCP connection accepted");
    let codec = OctetCountingCodec::with_max_frame_size(max_frame_size);
    let mut framed = FramedRead::new(stream, codec);

    while let Some(result) = framed.next().await {
        match result {
            Ok(frame) => {
                let msg = TcpMessage {
                    data: Bytes::from(frame),
                    peer,
                    tls: false,
                };
                if tx.send(msg).await.is_err() {
                    debug!(peer = %peer, "channel closed, dropping TCP connection");
                    return;
                }
            }
            Err(e) => {
                warn!(peer = %peer, "TCP frame error: {e}");
                return;
            }
        }
    }
    debug!(peer = %peer, "TCP connection closed");
}

/// Handle a TLS connection.
async fn handle_tls_connection(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer: SocketAddr,
    max_frame_size: usize,
    tx: mpsc::Sender<TcpMessage>,
) {
    debug!(peer = %peer, "TLS connection accepted");
    let codec = OctetCountingCodec::with_max_frame_size(max_frame_size);
    let mut framed = FramedRead::new(stream, codec);

    while let Some(result) = framed.next().await {
        match result {
            Ok(frame) => {
                let msg = TcpMessage {
                    data: Bytes::from(frame),
                    peer,
                    tls: true,
                };
                if tx.send(msg).await.is_err() {
                    debug!(peer = %peer, "channel closed, dropping TLS connection");
                    return;
                }
            }
            Err(e) => {
                warn!(peer = %peer, "TLS frame error: {e}");
                return;
            }
        }
    }
    debug!(peer = %peer, "TLS connection closed");
}

/// Wait for the shutdown signal (watch value becomes `true`).
async fn wait_for_shutdown(shutdown: &tokio::sync::watch::Receiver<bool>) {
    let mut rx = shutdown.clone();
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}
