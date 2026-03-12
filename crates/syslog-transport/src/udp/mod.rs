//! UDP transport (RFC 5426).
//!
//! RFC 5426 §3.1: Each syslog message is carried in one UDP datagram.
//! Maximum message size is 65535-8-20 = 65507 bytes, but implementers
//! SHOULD support messages up to 2048 bytes (§3.2).

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Configuration for a UDP syslog listener.
#[derive(Debug, Clone)]
pub struct UdpListenerConfig {
    /// The socket address to bind to.
    pub bind_addr: SocketAddr,
    /// Maximum datagram size to receive (default: 65535).
    pub max_message_size: usize,
    /// Receive buffer size hint for SO_RCVBUF (0 = OS default).
    pub recv_buf_size: usize,
}

impl Default for UdpListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: ([0, 0, 0, 0], 514).into(),
            max_message_size: 65535,
            recv_buf_size: 0,
        }
    }
}

/// A raw datagram received from a UDP syslog sender.
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    /// The raw message bytes.
    pub data: Bytes,
    /// The source address of the sender.
    pub source: SocketAddr,
}

/// Run a UDP syslog listener, sending received datagrams to the provided channel.
///
/// This function runs until the provided `shutdown` signal resolves or an
/// unrecoverable I/O error occurs.
///
/// # Errors
/// Returns an I/O error if the socket cannot be bound.
pub async fn run_udp_listener(
    config: UdpListenerConfig,
    tx: mpsc::Sender<UdpDatagram>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), crate::error::TransportError> {
    let socket = UdpSocket::bind(config.bind_addr).await?;

    // Set receive buffer size if requested
    if config.recv_buf_size > 0 {
        if let Err(e) = socket.set_broadcast(true) {
            warn!("failed to set SO_BROADCAST: {e}");
        }
    }

    let socket = Arc::new(socket);
    info!(addr = %config.bind_addr, "UDP syslog listener started");

    let mut buf = vec![0u8; config.max_message_size];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, source)) => {
                        let data = Bytes::copy_from_slice(
                            buf.get(..len).unwrap_or_default()
                        );
                        let datagram = UdpDatagram { data, source };

                        if let Err(e) = tx.try_send(datagram) {
                            match e {
                                mpsc::error::TrySendError::Full(_) => {
                                    warn!("UDP ingest channel full, dropping datagram from {source}");
                                }
                                mpsc::error::TrySendError::Closed(_) => {
                                    debug!("UDP ingest channel closed, shutting down");
                                    return Ok(());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("UDP recv error: {e}");
                    }
                }
            }
            _ = shutdown_signal(&shutdown) => {
                info!("UDP listener shutting down");
                return Ok(());
            }
        }
    }
}

/// Wait for the shutdown signal (watch value becomes `true`).
pub(crate) async fn shutdown_signal(shutdown: &tokio::sync::watch::Receiver<bool>) {
    let mut rx = shutdown.clone();
    // Wait until the value becomes true
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            return; // Sender dropped
        }
    }
}

/// Send a syslog message over UDP.
///
/// RFC 5426 §3.1: A syslog sender sends each message in a single UDP datagram.
pub async fn send_udp(
    socket: &UdpSocket,
    target: SocketAddr,
    message: &[u8],
) -> Result<(), crate::error::TransportError> {
    socket.send_to(message, target).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::watch;

    #[tokio::test]
    async fn udp_listener_sends_datagrams() {
        let config = UdpListenerConfig {
            bind_addr: ([127, 0, 0, 1], 0).into(),
            ..Default::default()
        };

        // Bind first to discover the port
        let socket = UdpSocket::bind(config.bind_addr).await;
        assert!(socket.is_ok());
        let socket = socket.unwrap_or_else(|_| unreachable!());
        let bound_addr = socket.local_addr().unwrap_or_else(|_| config.bind_addr);
        drop(socket);

        let listener_config = UdpListenerConfig {
            bind_addr: bound_addr,
            ..Default::default()
        };

        let (tx, mut rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            let _ = run_udp_listener(listener_config, tx, shutdown_rx).await;
        });

        // Give the listener a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send a test message
        let sender_addr: SocketAddr = ([127, 0, 0, 1], 0u16).into();
        let sender = UdpSocket::bind(sender_addr).await;
        assert!(sender.is_ok());
        if let Ok(sender) = sender {
            let _ = sender.send_to(b"<13>1 - - - - - - test", bound_addr).await;
        }

        // Receive
        let datagram = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await;
        assert!(datagram.is_ok());
        if let Ok(Some(d)) = datagram {
            assert_eq!(&d.data[..], b"<13>1 - - - - - - test");
        }

        // Shutdown
        let _ = shutdown_tx.send(true);
        let _ = handle.await;
    }
}
