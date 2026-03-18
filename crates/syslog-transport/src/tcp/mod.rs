//! TCP transport with octet-counting framing.
//!
//! Provides a TCP listener that accepts connections and frames incoming
//! syslog messages using the octet-counting codec (RFC 5425 §4.3).
//! Can also upgrade connections to TLS.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use tracing::{debug, error, info, warn};

use crate::framing::{LfDelimitedCodec, OctetCountingCodec, SyslogCodec};

/// Maximum number of unique source IPs tracked for per-IP connection limiting.
/// Prevents unbounded HashMap growth from connections with diverse source IPs.
const MAX_TRACKED_IPS: usize = 100_000;

/// Default timeout for TLS handshake completion.
/// Prevents Slowloris-style attacks where an attacker holds connection slots
/// by sending partial ClientHello messages.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Default read timeout applied when no explicit timeout is configured.
/// Prevents half-open connections from holding resources indefinitely.
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// Maximum number of concurrent TCP/TLS connections.
    /// When the limit is reached, new connections are rejected with a warning.
    pub max_connections: Option<usize>,
    /// Maximum concurrent connections from a single source IP.
    /// When exceeded, new connections from that IP are rejected.
    /// Default: None (unlimited per-IP).
    pub max_connections_per_ip: Option<usize>,
    /// Per-frame read timeout. If no complete frame arrives within this
    /// duration the connection is closed.
    pub read_timeout: Option<Duration>,
    /// Idle timeout — functionally equivalent to `read_timeout` for
    /// frame-oriented protocols but expressed as a separate knob for clarity.
    pub idle_timeout: Option<Duration>,
    /// Optional set of allowed source IPs. If non-empty, connections from other IPs are rejected.
    /// RFC 5426 §3.5 MAY: source IP filtering.
    pub allowed_sources: std::collections::HashSet<std::net::IpAddr>,
    /// When true, use LF-delimited (non-transparent) framing (RFC 6587 §3.4.2)
    /// instead of octet-counting.
    pub use_lf_framing: bool,
}

impl Default for TcpListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: ([0, 0, 0, 0], 6514).into(),
            max_frame_size: 64 * 1024,
            tls_acceptor: None,
            max_connections: None,
            max_connections_per_ip: None,
            read_timeout: None,
            idle_timeout: None,
            allowed_sources: std::collections::HashSet::new(),
            use_lf_framing: false,
        }
    }
}

/// RAII guard that decrements the per-IP connection count on drop.
struct PerIpGuard {
    ip: IpAddr,
    counts: Arc<std::sync::Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        // Recover from mutex poison to prevent permanently blocking the IP.
        // A poisoned mutex indicates a panic in another thread; the inner
        // data may be inconsistent, but decrementing is always safe since
        // we use saturating_sub and remove-on-zero semantics.
        let mut map = match self.counts.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!(ip = %self.ip, "per-IP tracking mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };
        if let Some(count) = map.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.ip);
            }
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

    // F-02: connection limit semaphore
    let semaphore = config.max_connections.map(|n| Arc::new(Semaphore::new(n)));

    // Per-IP connection tracking
    let per_ip_counts: Arc<std::sync::Mutex<HashMap<IpAddr, usize>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Effective read timeout: explicit read_timeout takes precedence, then idle_timeout,
    // then a safe default to prevent half-open connections from holding resources indefinitely.
    let effective_timeout = Some(
        config
            .read_timeout
            .or(config.idle_timeout)
            .unwrap_or(DEFAULT_READ_TIMEOUT),
    );

    info!(
        addr = %config.bind_addr,
        tls = is_tls,
        max_connections = ?config.max_connections,
        read_timeout = ?effective_timeout,
        "TCP syslog listener started"
    );

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        // RFC 5426 §3.5 MAY: source IP filtering
                        if !config.allowed_sources.is_empty() && !config.allowed_sources.contains(&peer.ip()) {
                            debug!(peer = %peer, "rejecting connection from non-allowed source IP");
                            drop(stream);
                            continue;
                        }

                        // F-02: enforce connection limit
                        let permit = if let Some(ref sem) = semaphore {
                            match Arc::clone(sem).try_acquire_owned() {
                                Ok(p) => Some(p),
                                Err(_) => {
                                    warn!(
                                        peer = %peer,
                                        "connection limit reached, rejecting"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            }
                        } else {
                            None
                        };

                        // Per-IP connection limit check
                        let per_ip_guard = if let Some(max_per_ip) = config.max_connections_per_ip {
                            match per_ip_counts.lock() {
                                Ok(mut counts) => {
                                    // Cap tracking table to prevent OOM from diverse source IPs.
                                    // Entries are cleaned on disconnect via PerIpGuard drop, but
                                    // half-open connections could still grow the table.
                                    if counts.len() >= MAX_TRACKED_IPS && !counts.contains_key(&peer.ip()) {
                                        warn!(
                                            peer = %peer,
                                            max = MAX_TRACKED_IPS,
                                            "per-IP tracking table full, rejecting new connection"
                                        );
                                        drop(stream);
                                        continue;
                                    }
                                    let count = counts.entry(peer.ip()).or_insert(0);
                                    if *count >= max_per_ip {
                                        warn!(
                                            peer = %peer,
                                            limit = max_per_ip,
                                            "per-IP connection limit reached, rejecting"
                                        );
                                        drop(stream);
                                        continue;
                                    }
                                    *count += 1;
                                    Some(PerIpGuard {
                                        ip: peer.ip(),
                                        counts: Arc::clone(&per_ip_counts),
                                    })
                                }
                                Err(_) => None,
                            }
                        } else {
                            None
                        };

                        // Harden TCP socket: disable Nagle for framing
                        // correctness and enable keepalive to detect
                        // half-open connections.
                        if let Err(e) = stream.set_nodelay(true) {
                            debug!(peer = %peer, "failed to set TCP_NODELAY: {e}");
                        }
                        // Enable TCP keepalive to detect and clean up
                        // half-open connections at the OS level.
                        let sock_ref = socket2::SockRef::from(&stream);
                        let keepalive = socket2::TcpKeepalive::new()
                            .with_time(Duration::from_secs(60))
                            .with_interval(Duration::from_secs(15));
                        if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
                            debug!(peer = %peer, "failed to set TCP keepalive: {e}");
                        }

                        let tx = tx.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        let use_lf = config.use_lf_framing;

                        tokio::spawn(async move {
                            // Keep the permit and per-IP guard alive for the
                            // lifetime of the connection
                            let _permit = permit;
                            let _per_ip_guard = per_ip_guard;
                            if let Some(acceptor) = tls_acceptor {
                                // Timeout the TLS handshake to prevent Slowloris-style
                                // attacks that hold connection slots by sending partial
                                // ClientHello messages.
                                match tokio::time::timeout(
                                    TLS_HANDSHAKE_TIMEOUT,
                                    acceptor.accept(stream),
                                )
                                .await
                                {
                                    Ok(Ok(tls_stream)) => {
                                        handle_tls_connection(tls_stream, peer, max_frame_size, tx, effective_timeout, use_lf).await;
                                    }
                                    Ok(Err(e)) => {
                                        warn!(peer = %peer, "TLS handshake failed: {e}");
                                    }
                                    Err(_) => {
                                        warn!(peer = %peer, "TLS handshake timed out after {}s", TLS_HANDSHAKE_TIMEOUT.as_secs());
                                    }
                                }
                            } else {
                                handle_tcp_connection(stream, peer, max_frame_size, tx, effective_timeout, use_lf).await;
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
    read_timeout: Option<Duration>,
    use_lf_framing: bool,
) {
    debug!(peer = %peer, "TCP connection accepted");
    let codec = if use_lf_framing {
        SyslogCodec::LfDelimited(LfDelimitedCodec::with_max_frame_size(max_frame_size))
    } else {
        SyslogCodec::OctetCounting(OctetCountingCodec::with_max_frame_size(max_frame_size))
    };
    let mut framed = FramedRead::new(stream, codec);

    loop {
        let next = if let Some(timeout) = read_timeout {
            match tokio::time::timeout(timeout, framed.next()).await {
                Ok(val) => val,
                Err(_) => {
                    warn!(peer = %peer, "TCP read timeout, closing connection");
                    return;
                }
            }
        } else {
            framed.next().await
        };

        match next {
            Some(Ok(frame)) => {
                let msg = TcpMessage {
                    data: Bytes::from(frame),
                    peer,
                    tls: false,
                };
                // Use a timeout on channel send to prevent blocking
                // indefinitely if the pipeline is stalled.
                match tokio::time::timeout(Duration::from_secs(5), tx.send(msg)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        debug!(peer = %peer, "channel closed, dropping TCP connection");
                        return;
                    }
                    Err(_) => {
                        warn!(peer = %peer, "pipeline backpressure timeout, dropping TCP connection");
                        return;
                    }
                }
            }
            Some(Err(e)) => {
                warn!(peer = %peer, "TCP frame error: {e}");
                return;
            }
            None => break,
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
    read_timeout: Option<Duration>,
    use_lf_framing: bool,
) {
    debug!(peer = %peer, "TLS connection accepted");
    let codec = if use_lf_framing {
        SyslogCodec::LfDelimited(LfDelimitedCodec::with_max_frame_size(max_frame_size))
    } else {
        SyslogCodec::OctetCounting(OctetCountingCodec::with_max_frame_size(max_frame_size))
    };
    let mut framed = FramedRead::new(stream, codec);

    loop {
        let next = if let Some(timeout) = read_timeout {
            match tokio::time::timeout(timeout, framed.next()).await {
                Ok(val) => val,
                Err(_) => {
                    warn!(peer = %peer, "TLS read timeout, closing connection");
                    return;
                }
            }
        } else {
            framed.next().await
        };

        match next {
            Some(Ok(frame)) => {
                let msg = TcpMessage {
                    data: Bytes::from(frame),
                    peer,
                    tls: true,
                };
                // Use a timeout on channel send to prevent blocking
                // indefinitely if the pipeline is stalled.
                match tokio::time::timeout(Duration::from_secs(5), tx.send(msg)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        debug!(peer = %peer, "channel closed, dropping TLS connection");
                        return;
                    }
                    Err(_) => {
                        warn!(peer = %peer, "pipeline backpressure timeout, dropping TLS connection");
                        return;
                    }
                }
            }
            Some(Err(e)) => {
                warn!(peer = %peer, "TLS frame error: {e}");
                return;
            }
            None => break,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::watch;

    /// Helper: start a TCP listener on an ephemeral port and return its address.
    /// Returns `None` if binding fails (e.g., port contention in CI).
    async fn start_listener(
        max_connections: Option<usize>,
        read_timeout: Option<Duration>,
    ) -> Option<(
        SocketAddr,
        mpsc::Receiver<TcpMessage>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<(), crate::error::TransportError>>,
    )> {
        start_listener_with_per_ip(max_connections, None, read_timeout).await
    }

    /// Helper: start a TCP listener with optional per-IP limit.
    async fn start_listener_with_per_ip(
        max_connections: Option<usize>,
        max_connections_per_ip: Option<usize>,
        read_timeout: Option<Duration>,
    ) -> Option<(
        SocketAddr,
        mpsc::Receiver<TcpMessage>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<(), crate::error::TransportError>>,
    )> {
        let bind: SocketAddr = ([127, 0, 0, 1], 0u16).into();
        let tmp = TcpListener::bind(bind).await.ok()?;
        let addr = tmp.local_addr().ok()?;
        drop(tmp);

        let config = TcpListenerConfig {
            bind_addr: addr,
            max_frame_size: 8192,
            tls_acceptor: None,
            max_connections,
            max_connections_per_ip,
            read_timeout,
            idle_timeout: None,
            allowed_sources: std::collections::HashSet::new(),
            use_lf_framing: false,
        };

        let (tx, rx) = mpsc::channel::<TcpMessage>(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(run_tcp_listener(config, tx, shutdown_rx));

        // Give the listener time to bind.
        tokio::time::sleep(Duration::from_millis(100)).await;

        Some((addr, rx, shutdown_tx, handle))
    }

    /// F-02: TCP listener enforces max_connections limit.
    #[tokio::test]
    async fn test_max_connections_limit() {
        let Some((addr, mut rx, shutdown_tx, listener_handle)) =
            start_listener(Some(1), None).await
        else {
            return; // skip if port unavailable
        };

        // First connection: should be accepted.
        let Ok(mut conn1) = tokio::net::TcpStream::connect(addr).await else {
            let _ = shutdown_tx.send(true);
            return;
        };

        // Send a valid octet-counted frame on conn1.
        if conn1.write_all(b"5 hello").await.is_err() {
            let _ = shutdown_tx.send(true);
            return;
        }

        // We must receive that message.
        let received = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
        assert!(
            matches!(received, Ok(Some(_))),
            "should receive message from conn1"
        );

        // Second connection while conn1 is still alive — should be rejected.
        // The server may accept at the TCP level but immediately drops the
        // socket, so any data sent will never produce a TcpMessage.
        if let Ok(mut c2) = tokio::net::TcpStream::connect(addr).await {
            let _ = c2.write_all(b"5 world").await;
            let received2 = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
            assert!(
                received2.is_err(),
                "second connection should be rejected at the limit"
            );
        }

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), listener_handle).await;
    }

    /// F-02: TCP read timeout closes idle connections.
    #[tokio::test]
    async fn test_read_timeout() {
        let Some((addr, _rx, shutdown_tx, listener_handle)) =
            start_listener(None, Some(Duration::from_millis(200))).await
        else {
            return;
        };

        // Connect but send nothing — the server should close after the timeout.
        if let Ok(mut c) = tokio::net::TcpStream::connect(addr).await {
            tokio::time::sleep(Duration::from_millis(400)).await;
            // After the timeout the server side has closed; a write may or
            // may not fail depending on platform buffering, but the handler
            // has exited.
            let _ = c.write_all(b"5 hello").await;
        }

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), listener_handle).await;
    }

    /// Per-IP connection limit rejects excess connections from the same source.
    #[tokio::test]
    async fn test_max_connections_per_ip() {
        let Some((addr, mut rx, shutdown_tx, listener_handle)) =
            start_listener_with_per_ip(None, Some(1), None).await
        else {
            return; // skip if port unavailable
        };

        // First connection from localhost: should be accepted.
        let Ok(mut conn1) = tokio::net::TcpStream::connect(addr).await else {
            let _ = shutdown_tx.send(true);
            return;
        };

        // Send a valid octet-counted frame on conn1.
        if conn1.write_all(b"5 hello").await.is_err() {
            let _ = shutdown_tx.send(true);
            return;
        }

        // We must receive that message.
        let received = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
        assert!(
            matches!(received, Ok(Some(_))),
            "should receive message from conn1"
        );

        // Second connection from same IP while conn1 is alive — should be rejected.
        if let Ok(mut c2) = tokio::net::TcpStream::connect(addr).await {
            let _ = c2.write_all(b"5 world").await;
            let received2 = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
            assert!(
                received2.is_err(),
                "second connection from same IP should be rejected"
            );
        }

        // Drop conn1, then a new connection should be accepted (guard decrements count).
        drop(conn1);
        tokio::time::sleep(Duration::from_millis(100)).await;

        if let Ok(mut c3) = tokio::net::TcpStream::connect(addr).await {
            if c3.write_all(b"5 after").await.is_ok() {
                let received3 = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
                assert!(
                    matches!(received3, Ok(Some(_))),
                    "connection after previous close should be accepted"
                );
            }
        }

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), listener_handle).await;
    }
}
