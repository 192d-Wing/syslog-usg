//! UDP transport (RFC 5426).
//!
//! RFC 5426 §3.1: Each syslog message is carried in one UDP datagram.
//! Maximum message size is 65535-8-20 = 65507 bytes, but implementers
//! SHOULD support messages up to 2048 bytes (§3.2).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Default SO_RCVBUF size: 2 MiB.
const DEFAULT_RECV_BUF_SIZE: usize = 2 * 1024 * 1024;

/// Maximum number of unique source IPs tracked for rate limiting.
/// Prevents unbounded HashMap growth from spoofed source addresses.
const MAX_TRACKED_SOURCES: usize = 100_000;

/// Configuration for a UDP syslog listener.
#[derive(Debug, Clone)]
pub struct UdpListenerConfig {
    /// The socket address to bind to.
    pub bind_addr: SocketAddr,
    /// Maximum datagram size to receive (default: 65535).
    pub max_message_size: usize,
    /// Receive buffer size hint for SO_RCVBUF (0 = use default of 2 MiB).
    pub recv_buf_size: usize,
    /// Maximum datagrams per source IP per rate-limit window (0 = unlimited).
    pub max_per_source: u32,
    /// Optional set of allowed source IPs. If non-empty, datagrams from other IPs are dropped.
    /// RFC 5426 §3.5 MAY: source IP filtering.
    pub allowed_sources: std::collections::HashSet<std::net::IpAddr>,
}

impl Default for UdpListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: ([0, 0, 0, 0], 514).into(),
            max_message_size: 65535,
            recv_buf_size: 0,
            max_per_source: 0,
            allowed_sources: std::collections::HashSet::new(),
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

/// Build a UDP socket with SO_RCVBUF set via `socket2`, then convert to
/// a `tokio::net::UdpSocket`.
fn build_udp_socket(config: &UdpListenerConfig) -> Result<UdpSocket, crate::error::TransportError> {
    let domain = if config.bind_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // RFC 5426 §3.6: receivers SHOULD be able to handle bursts of messages.
    // Set SO_RCVBUF to reduce packet loss under load.
    let buf_size = if config.recv_buf_size > 0 {
        config.recv_buf_size
    } else {
        DEFAULT_RECV_BUF_SIZE
    };
    if let Err(e) = socket.set_recv_buffer_size(buf_size) {
        warn!(requested = buf_size, "failed to set SO_RCVBUF: {e}");
    }

    // Allow address reuse for quick restarts.
    socket.set_reuse_address(true)?;
    // Must set non-blocking before converting to tokio socket.
    socket.set_nonblocking(true)?;

    let addr: socket2::SockAddr = config.bind_addr.into();
    socket.bind(&addr)?;

    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket = UdpSocket::from_std(std_socket)?;
    Ok(tokio_socket)
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
    let socket = build_udp_socket(&config)?;

    let socket = Arc::new(socket);
    info!(addr = %config.bind_addr, "UDP syslog listener started");

    let mut buf = vec![0u8; config.max_message_size];
    let rate_limit = config.max_per_source;

    // Simple per-source-IP rate limiter: count datagrams in the current window.
    // The window resets every RATE_WINDOW_SECS seconds.
    const RATE_WINDOW_SECS: u64 = 10;
    let mut source_counts: HashMap<IpAddr, u32> = HashMap::new();
    let mut window_start = std::time::Instant::now();

    loop {
        // Reset rate-limit window periodically
        if rate_limit > 0 && window_start.elapsed().as_secs() >= RATE_WINDOW_SECS {
            source_counts.clear();
            window_start = std::time::Instant::now();
        }

        // Cap source tracking table to prevent OOM from spoofed source IPs
        if rate_limit > 0 && source_counts.len() >= MAX_TRACKED_SOURCES {
            warn!(
                max = MAX_TRACKED_SOURCES,
                "per-source rate-limit table full, resetting (possible spoofed-IP flood)"
            );
            source_counts.clear();
            window_start = std::time::Instant::now();
        }

        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, source)) => {
                        // RFC 5426 §3.5 MAY: source IP filtering
                        if !config.allowed_sources.is_empty() && !config.allowed_sources.contains(&source.ip()) {
                            debug!(source = %source, "dropping datagram from non-allowed source IP");
                            continue;
                        }

                        // Per-source rate limiting
                        if rate_limit > 0 {
                            let count = source_counts.entry(source.ip()).or_insert(0);
                            *count = count.saturating_add(1);
                            if *count > rate_limit {
                                if *count == rate_limit.saturating_add(1) {
                                    warn!(
                                        source = %source.ip(),
                                        limit = rate_limit,
                                        window_secs = RATE_WINDOW_SECS,
                                        "per-source rate limit exceeded, dropping datagrams"
                                    );
                                }
                                continue;
                            }
                        }

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

/// Maximum UDP syslog payload: 65535 − 8 byte UDP header = 65527.
///
/// RFC 5426 §3.2 MUST NOT: "a syslog sender MUST NOT send a UDP datagram
/// with a SYSLOG-MSG longer than 65535-8 octets."
const MAX_UDP_PAYLOAD: usize = 65527;

/// Send a syslog message over UDP.
///
/// RFC 5426 §3.1: A syslog sender sends each message in a single UDP datagram.
///
/// # Errors
/// Returns [`TransportError::FrameTooLarge`] if the message exceeds
/// the RFC 5426 §3.2 maximum of 65527 bytes.
pub async fn send_udp(
    socket: &UdpSocket,
    target: SocketAddr,
    message: &[u8],
) -> Result<(), crate::error::TransportError> {
    // RFC 5426 §3.2 MUST NOT: message must fit in a single UDP datagram
    if message.len() > MAX_UDP_PAYLOAD {
        return Err(crate::error::TransportError::FrameTooLarge {
            size: message.len(),
            max: MAX_UDP_PAYLOAD,
        });
    }
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
        let bound_addr = socket.local_addr().unwrap_or(config.bind_addr);
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

    #[tokio::test]
    async fn udp_listener_with_custom_recv_buf_size() {
        // Discover a free port by binding to port 0, then release it.
        let any_addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let probe = UdpSocket::bind(any_addr).await;
        assert!(probe.is_ok());
        let probe = probe.unwrap_or_else(|_| unreachable!());
        let bound_addr = probe.local_addr().unwrap_or(any_addr);
        drop(probe);

        // Use a custom recv_buf_size of 4 MiB
        let listener_config = UdpListenerConfig {
            bind_addr: bound_addr,
            recv_buf_size: 4 * 1024 * 1024,
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
        let sender_addr: SocketAddr = ([127, 0, 0, 1], 0).into();
        let sender = match UdpSocket::bind(sender_addr).await {
            Ok(s) => s,
            Err(_) => {
                let _ = shutdown_tx.send(true);
                let _ = handle.await;
                return;
            }
        };
        let _ = sender
            .send_to(b"<14>1 - - - - - - buf-test", bound_addr)
            .await;

        // Receive the datagram
        let datagram = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await;
        assert!(datagram.is_ok());
        if let Ok(Some(d)) = datagram {
            assert_eq!(&d.data[..], b"<14>1 - - - - - - buf-test");
        }

        let _ = shutdown_tx.send(true);
        let _ = handle.await;
    }

    #[tokio::test]
    async fn send_udp_oversized_rejected() {
        // RFC 5426 §3.2: MUST NOT send > 65527 bytes
        let socket = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(s) => s,
            Err(_) => return,
        };
        let target: SocketAddr = match "127.0.0.1:9999".parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        let oversized = vec![0u8; MAX_UDP_PAYLOAD + 1];
        let result = send_udp(&socket, target, &oversized).await;
        assert!(result.is_err(), "messages > 65527 bytes must be rejected");
    }

    #[tokio::test]
    async fn send_udp_max_size_accepted() {
        // Exactly 65527 bytes should be accepted (may fail at OS level, but not our check)
        let socket = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(s) => s,
            Err(_) => return,
        };
        let target: SocketAddr = match "127.0.0.1:9999".parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        let max_msg = vec![0u8; MAX_UDP_PAYLOAD];
        let result = send_udp(&socket, target, &max_msg).await;
        // Should not be a FrameTooLarge error (may be an IO error from OS)
        assert!(
            !matches!(result, Err(crate::error::TransportError::FrameTooLarge { .. })),
            "exactly 65527 bytes should pass size validation"
        );
    }
}
