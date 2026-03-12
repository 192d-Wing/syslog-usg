# Phase 05: Transport Layer and Security Design

**Document Version:** 1.0
**Date:** 2026-03-11
**Status:** Draft
**Scope:** Transport support for UDP, TCP/TLS, and (future) DTLS, including all security considerations for syslog-usg.

**Governing RFCs:** RFC 5425 (TLS), RFC 5426 (UDP), RFC 9662 (Cipher Suites), RFC 6012 (DTLS, future)

---

## Table of Contents

1. [Transport Support Strategy](#1-transport-support-strategy)
2. [UDP Listener Architecture](#2-udp-listener-architecture)
3. [TLS Listener/Acceptor Architecture](#3-tls-listeneracceptor-architecture)
4. [TLS Sender Architecture](#4-tls-sender-architecture)
5. [UDP Sender](#5-udp-sender)
6. [Octet-Counting Framing](#6-octet-counting-framing)
7. [TLS/DTLS Security Design](#7-tlsdtls-security-design)
8. [Secure Defaults](#8-secure-defaults)
9. [Transport-Specific Risks](#9-transport-specific-risks)
10. [Required Security Controls](#10-required-security-controls)

---

## 1. Transport Support Strategy

### 1.1 Design Philosophy

syslog-usg treats transports as pluggable components behind a unified trait interface. Every transport — whether receiving or sending — produces or consumes the same internal `SyslogMessage` type. The pipeline never knows which transport originated a message or which transport will deliver it. This separation enables protocol translation (UDP-in to TLS-out) without coupling.

### 1.2 Trait Abstractions

#### Transport Listener Trait

```rust
/// A transport listener accepts inbound syslog messages from network sources.
/// Each listener runs as an independent Tokio task and pushes parsed messages
/// into the pipeline via a bounded channel sender.
#[async_trait]
pub trait TransportListener: Send + Sync + 'static {
    /// Human-readable name for metrics labels and logging (e.g., "udp://0.0.0.0:514").
    fn name(&self) -> &str;

    /// The transport protocol this listener handles.
    fn transport_type(&self) -> TransportType;

    /// Start the listener. This method runs until the shutdown signal fires.
    /// It reads from the network, frames/parses as needed, and sends
    /// RawMessage values into `output`.
    ///
    /// Returns Ok(()) on clean shutdown, Err on fatal bind/init failure.
    async fn run(
        self,
        output: mpsc::Sender<RawMessage>,
        shutdown: CancellationToken,
    ) -> Result<(), TransportError>;
}
```

#### Transport Sender Trait

```rust
/// A transport sender delivers syslog messages to a downstream destination.
/// Each sender runs as an independent Tokio task and pulls messages from a
/// bounded channel receiver.
#[async_trait]
pub trait TransportSender: Send + Sync + 'static {
    /// Human-readable name for metrics and logging (e.g., "tls://collector.example.com:6514").
    fn name(&self) -> &str;

    /// The transport protocol this sender uses.
    fn transport_type(&self) -> TransportType;

    /// Start the sender. Reads from `input`, serializes/frames messages,
    /// and writes to the network. Handles reconnection internally.
    ///
    /// Returns Ok(()) on clean shutdown, Err on unrecoverable failure.
    async fn run(
        self,
        input: mpsc::Receiver<Arc<SyslogMessage>>,
        shutdown: CancellationToken,
    ) -> Result<(), TransportError>;
}
```

#### Transport Type Enumeration

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    Udp,
    Tcp,       // Plain TCP (warned at startup)
    Tls,
    Dtls,      // Future
}
```

#### RawMessage — The Listener Output

```rust
/// A raw message as received from the network, before parsing.
/// Carries transport metadata for routing, rate-limiting, and diagnostics.
pub struct RawMessage {
    /// The raw bytes of the syslog message (excluding framing).
    pub payload: Bytes,
    /// Source address of the sender.
    pub source: SocketAddr,
    /// Which listener received this message.
    pub listener_id: ListenerId,
    /// Transport protocol used.
    pub transport: TransportType,
    /// Timestamp of receipt (monotonic clock for latency, wall clock for logging).
    pub received_at: Instant,
    /// For TLS: authenticated client identity (CN or SAN from client certificate).
    pub peer_identity: Option<Arc<PeerIdentity>>,
}
```

### 1.3 Listener and Sender Unification

All listeners and senders are managed by a `TransportManager` that:

1. Instantiates listeners and senders from configuration.
2. Spawns each as a named Tokio task with the shared `CancellationToken`.
3. Collects `JoinHandle`s for orderly shutdown (listeners stop accepting first, senders drain).
4. Registers per-transport metrics via a shared metrics registry.

```
                  +--------------+
  UDP:514  ----> | UdpListener  |---+
                  +--------------+   |     +----------+     +----------+
                                     +---> | Pipeline | --> | TlsSender| ---> TLS:6514
                  +--------------+   |     +----------+     +----------+
  TLS:6514 ----> | TlsListener  |---+
                  +--------------+         (bounded mpsc channels at each arrow)
```

### 1.4 Module Layout

```
src/
  transport/
    mod.rs              // TransportListener, TransportSender traits, TransportType
    raw_message.rs      // RawMessage, PeerIdentity
    manager.rs          // TransportManager: lifecycle, spawn, shutdown
    udp/
      mod.rs
      listener.rs       // UdpListener
      sender.rs         // UdpSender
    tls/
      mod.rs
      listener.rs       // TlsListener, TlsAcceptor loop
      sender.rs         // TlsSender, connection pool
      config.rs         // ServerConfig/ClientConfig builders
      cert.rs           // Certificate loading, validation, fingerprinting
      framing.rs        // OctetCountingCodec (encoder + decoder)
    tcp/
      mod.rs
      listener.rs       // PlainTcpListener (warns at startup)
    dtls/               // Future: DTLS support
      mod.rs
```

---

## 2. UDP Listener Architecture

### 2.1 Overview

The UDP listener is the highest-throughput receive path. It must sustain 100k+ messages/sec on commodity hardware. The design leverages multiple sockets, per-core affinity, and minimal allocation on the hot path.

**RFC 5426 compliance summary:**
- One syslog message per datagram (MUST, S3.1)
- Accept messages up to 480 octets IPv4 / 1180 octets IPv6 (MUST, S3.2)
- Accept messages up to 2048 octets (SHOULD, S3.2)
- Listen on port 514 (MUST, S3.3)
- UDP checksums enabled (MUST, S3.6)

### 2.2 Socket Configuration

#### SO_REUSEPORT for Multi-Core Scaling

On Linux, `SO_REUSEPORT` allows multiple sockets to bind to the same address:port. The kernel distributes incoming datagrams across sockets using a hash of the source address, providing:

- Automatic load distribution across CPU cores
- Elimination of lock contention on a single socket
- Near-linear throughput scaling

```rust
pub struct UdpListenerConfig {
    /// Bind address and port (default: 0.0.0.0:514).
    pub bind_addr: SocketAddr,
    /// Number of sockets to create. Default: number of available CPU cores.
    /// Each socket gets its own recv task.
    pub socket_count: usize,
    /// Receive buffer size per socket. Default: 4 MiB.
    /// Set via SO_RCVBUF. Larger buffers absorb burst traffic.
    pub recv_buf_size: usize,
    /// Maximum message size to accept. Default: 8192 octets.
    /// Datagrams larger than this are logged and dropped.
    pub max_message_size: usize,
}
```

#### Socket Creation

```rust
fn create_udp_socket(config: &UdpListenerConfig) -> io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        if config.bind_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;

    // Enable address reuse for multi-socket binding.
    socket.set_reuse_address(true)?;

    // SO_REUSEPORT: kernel distributes datagrams across sockets.
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;

    // Set receive buffer size. The kernel may cap this at sysctl net.core.rmem_max.
    socket.set_recv_buffer_size(config.recv_buf_size)?;

    // Bind.
    socket.bind(&config.bind_addr.into())?;

    // Set non-blocking for Tokio.
    socket.set_nonblocking(true)?;

    Ok(socket.into())
}
```

**Note on SO_RCVBUF:** The default Linux `rmem_max` is often 212992 bytes (208 KiB). For 100k msg/sec at 512 bytes average, the socket must buffer ~50 MB/sec. The operational documentation must advise setting `net.core.rmem_max` to at least 8388608 (8 MiB). The `set_recv_buffer_size` call will silently cap to `rmem_max`; the listener logs a warning if the actual buffer is smaller than requested.

### 2.3 IPv4/IPv6 Dual-Stack

Two strategies, chosen by configuration:

1. **Dual-stack socket (default on Linux):** Bind a single IPv6 socket with `IPV6_V6ONLY=false`. Accepts both IPv4-mapped (::ffff:x.x.x.x) and native IPv6 sources. Source addresses are normalized to canonical form for metrics and rate-limiting.

2. **Separate sockets:** Bind one IPv4 and one IPv6 socket. Required on platforms that do not support dual-stack (some BSDs). The listener spawns recv tasks for both sets.

```rust
pub enum DualStackMode {
    /// Single IPv6 socket accepts both v4 and v6 (IPV6_V6ONLY=false).
    DualStack,
    /// Separate sockets for IPv4 and IPv6.
    Separate,
}
```

### 2.4 Receive Loop Design

Each socket gets a dedicated Tokio task. The task performs a tight `recv_from` loop with zero-copy where possible.

```rust
async fn recv_loop(
    socket: UdpSocket,
    output: mpsc::Sender<RawMessage>,
    metrics: Arc<UdpMetrics>,
    config: Arc<UdpListenerConfig>,
    shutdown: CancellationToken,
) {
    // Pre-allocate receive buffer at max_message_size.
    let mut buf = vec![0u8; config.max_message_size];

    loop {
        tokio::select! {
            biased;  // Check shutdown first for responsiveness.

            _ = shutdown.cancelled() => break,

            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, source)) => {
                        metrics.datagrams_received.increment(1);

                        // Validate minimum size: a valid RFC 5424 message is at
                        // least "<0>1 - - - - - -" = ~20 bytes. Drop obviously
                        // invalid datagrams.
                        if len < 10 {
                            metrics.invalid_datagrams.increment(1);
                            continue;
                        }

                        // Copy payload into Bytes for pipeline ownership.
                        let payload = Bytes::copy_from_slice(&buf[..len]);

                        let raw = RawMessage {
                            payload,
                            source,
                            listener_id: config.listener_id,
                            transport: TransportType::Udp,
                            received_at: Instant::now(),
                            peer_identity: None,  // No auth on UDP
                        };

                        // If the channel is full, drop the message (never block UDP recv).
                        if output.try_send(raw).is_err() {
                            metrics.channel_drops.increment(1);
                        }
                    }
                    Err(e) => {
                        // ENOBUFS, ENOMEM: transient. Log and continue.
                        // EINTR: spurious. Continue.
                        metrics.recv_errors.increment(1);
                        tracing::warn!(error = %e, "UDP recv_from error");
                    }
                }
            }
        }
    }
}
```

**Key design decisions:**

- **`try_send` not `send.await`:** UDP reception must never block waiting for pipeline capacity. If the channel is full, the datagram is dropped and counted. This is explicit in the syslog model: UDP has no backpressure.
- **Pre-allocated buffer:** A single buffer is reused per recv call. Data is copied into `Bytes` for pipeline ownership. The cost of one copy is acceptable versus the complexity of buffer pools.
- **`biased` select:** Shutdown is checked before recv to ensure clean exit even under high load.

### 2.5 Batch Reception (Linux recvmmsg, future)

For sustained throughput above 100k msg/sec, the `recvmmsg` system call receives multiple datagrams in a single kernel transition. This is a future optimization gated behind a `linux-perf` feature flag:

```rust
// Future: recvmmsg via io_uring or direct syscall.
// Expected throughput improvement: 2-3x over per-datagram recv_from.
// Implementation approach: use tokio-uring crate or raw syscall via nix.
```

The initial implementation uses single-datagram `recv_from` which benchmarks show is sufficient for 100k msg/sec with 4 SO_REUSEPORT sockets on modern hardware.

### 2.6 Message Boundary Handling

RFC 5426 S3.1 mandates one syslog message per datagram. The implementation enforces this:

- The entire datagram payload is treated as a single syslog message.
- No scanning for newlines or other delimiters within the datagram.
- If a sender violates this by packing multiple messages into one datagram, the entire datagram is parsed as one message. This will likely fail RFC 5424 parsing and be handled by the lenient parser or rejected in strict mode.

### 2.7 Source IP Extraction

The source IP is captured from `recv_from` and stored in `RawMessage::source`. It serves several purposes:

- **Rate limiting key:** Per-source rate limiting uses the source IP.
- **Routing decisions:** Configuration can route messages based on source network (CIDR matching).
- **Metrics cardinality:** Source IP is NOT used as a high-cardinality metric label. Instead, metrics aggregate by source subnet or listener.

Per RFC 5426 S3.4, the source IP SHOULD NOT be interpreted as the message originator. The `HOSTNAME` field in the parsed syslog message is the canonical origin identifier.

### 2.8 Error Handling

| Error Condition | Behavior | Metric |
|----------------|----------|--------|
| Datagram too large (exceeds `max_message_size`) | Truncated by kernel; logged and dropped | `udp_truncated_datagrams_total` |
| Datagram too small (< 10 bytes) | Dropped silently | `udp_invalid_datagrams_total` |
| `recv_from` returns ENOBUFS | Log warning, continue | `udp_recv_errors_total` |
| `recv_from` returns ENOMEM | Log error, continue | `udp_recv_errors_total` |
| Pipeline channel full | Drop message, do not block | `udp_channel_drops_total` |
| UDP checksum failure | Handled by kernel; datagram never delivered to application | N/A (invisible) |
| IP fragmentation loss | Fragment loss causes entire datagram loss; invisible to application | N/A (invisible) |

### 2.9 Metrics

```
syslog_udp_datagrams_received_total{listener="..."}
syslog_udp_datagrams_invalid_total{listener="...", reason="too_small|too_large"}
syslog_udp_recv_errors_total{listener="..."}
syslog_udp_channel_drops_total{listener="..."}
syslog_udp_bytes_received_total{listener="..."}
```

---

## 3. TLS Listener/Acceptor Architecture

### 3.1 Overview

The TLS listener handles inbound TLS connections on port 6514, performing handshake, optional mutual authentication, and octet-counting frame decoding. It must support 10k concurrent connections at 50k aggregate msg/sec.

**RFC 5425 compliance summary:**
- TLS 1.2 minimum (MUST, S4.2)
- Certificate-based authentication (MUST, S4.2.1)
- Octet-counting framing (MUST, S4.3)
- Process messages up to 2048 octets (MUST, S4.3), up to 8192 (SHOULD)
- `close_notify` on shutdown (MUST, S4.4)

### 3.2 rustls ServerConfig Setup

```rust
pub fn build_server_config(tls_config: &TlsListenerConfig) -> Result<Arc<ServerConfig>, TlsConfigError> {
    let cert_chain = load_certificate_chain(&tls_config.cert_path)?;
    let private_key = load_private_key(&tls_config.key_path)?;

    let mut config = ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    // Configure cipher suites per RFC 9662.
    // TLS 1.3 suites are always AEAD; TLS 1.2 suites are explicitly listed.
    .with_cipher_suites(&rfc9662_server_cipher_suites())
    .with_safe_default_kx_groups()
    .with_client_cert_verifier(build_client_verifier(tls_config)?)
    .with_single_cert(cert_chain, private_key)?;

    // MUST NOT enable 0-RTT (RFC 9662).
    config.max_early_data_size = 0;

    // Session resumption: allowed but parameters are re-validated.
    // rustls handles this correctly by default with its internal session cache.
    config.session_storage = ServerSessionMemoryCache::new(
        tls_config.session_cache_size.unwrap_or(1024),
    );

    // ALPN: not required for syslog but could be used for protocol identification.
    // Left empty per current RFC requirements.

    Ok(Arc::new(config))
}
```

### 3.3 Certificate Loading and Validation

```rust
fn load_certificate_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    let file = File::open(path)
        .map_err(|e| TlsConfigError::CertificateLoad { path: path.into(), source: e })?;
    let mut reader = BufReader::new(file);

    // Support both PEM and DER formats.
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsConfigError::CertificateParse { path: path.into(), source: e })?;

    if certs.is_empty() {
        return Err(TlsConfigError::NoCertificatesFound { path: path.into() });
    }

    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsConfigError> {
    // Validate file permissions: warn if world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        if meta.mode() & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                "TLS private key file has group/world permissions; consider chmod 600"
            );
        }
    }

    let file = File::open(path)
        .map_err(|e| TlsConfigError::KeyLoad { path: path.into(), source: e })?;
    let mut reader = BufReader::new(file);

    // Try PKCS#8 first, then RSA, then EC.
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TlsConfigError::KeyParse { path: path.into(), source: e })?
        .ok_or_else(|| TlsConfigError::NoKeyFound { path: path.into() })
}
```

### 3.4 Mutual TLS Configuration

Mutual TLS is controlled by configuration. Three modes:

```rust
pub enum ClientAuthMode {
    /// No client certificate required. Connections are authenticated server-side only.
    None,
    /// Client certificate requested but not required. If presented, it is validated.
    Optional,
    /// Client certificate required. Connections without a valid client cert are rejected.
    Required,
}
```

The client verifier is constructed accordingly:

```rust
fn build_client_verifier(
    config: &TlsListenerConfig,
) -> Result<Arc<dyn ClientCertVerifier>, TlsConfigError> {
    match config.client_auth {
        ClientAuthMode::None => {
            Ok(WebPkiClientVerifier::no_client_auth())
        }
        ClientAuthMode::Optional | ClientAuthMode::Required => {
            let mut root_store = RootCertStore::empty();

            // Load CA certificates for client cert validation.
            let ca_certs = load_certificate_chain(&config.client_ca_path
                .as_ref()
                .ok_or(TlsConfigError::ClientCaRequired)?)?;
            for cert in ca_certs {
                root_store.add(cert)?;
            }

            let builder = WebPkiClientVerifier::builder(Arc::new(root_store));
            let verifier = if config.client_auth == ClientAuthMode::Optional {
                builder.allow_unauthenticated().build()?
            } else {
                builder.build()?
            };

            Ok(verifier)
        }
    }
}
```

### 3.5 Connection Accept Loop

The TLS listener runs a TCP accept loop. Each accepted connection is handed to a per-connection task after TLS handshake.

```rust
async fn tls_accept_loop(
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    output: mpsc::Sender<RawMessage>,
    limits: Arc<ConnectionLimits>,
    metrics: Arc<TlsMetrics>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,

            result = tcp_listener.accept() => {
                let (tcp_stream, peer_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        // Accept errors: EMFILE, ENFILE, ENOMEM.
                        // Back off briefly to avoid busy-loop.
                        metrics.accept_errors.increment(1);
                        tracing::error!(error = %e, "TCP accept error");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };

                // Connection limit enforcement.
                if limits.active_connections.load(Ordering::Relaxed) >= limits.max_connections {
                    metrics.rejected_connections.increment(1);
                    tracing::warn!(peer = %peer_addr, "Connection rejected: limit reached");
                    drop(tcp_stream);  // RST
                    continue;
                }

                limits.active_connections.fetch_add(1, Ordering::Relaxed);
                metrics.connections_accepted.increment(1);

                // Spawn per-connection task.
                let acceptor = tls_acceptor.clone();
                let output = output.clone();
                let metrics = metrics.clone();
                let limits = limits.clone();
                let shutdown = shutdown.clone();

                tokio::spawn(async move {
                    let _guard = ConnectionGuard::new(&limits);

                    // TLS handshake with timeout.
                    let tls_stream = match tokio::time::timeout(
                        Duration::from_secs(10),
                        acceptor.accept(tcp_stream),
                    ).await {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(e)) => {
                            metrics.handshake_errors.increment(1);
                            tracing::debug!(peer = %peer_addr, error = %e, "TLS handshake failed");
                            return;
                        }
                        Err(_) => {
                            metrics.handshake_timeouts.increment(1);
                            tracing::debug!(peer = %peer_addr, "TLS handshake timed out");
                            return;
                        }
                    };

                    // Extract peer identity from client certificate (if mutual TLS).
                    let peer_identity = extract_peer_identity(&tls_stream);

                    // Run the message reader for this connection.
                    handle_tls_connection(tls_stream, peer_addr, peer_identity, output, metrics, shutdown).await;
                });
            }
        }
    }
}
```

### 3.6 Per-Connection Task and Frame Decoding

Each TLS connection is processed by a dedicated task that reads octet-counted frames and pushes `RawMessage` values into the pipeline.

```rust
async fn handle_tls_connection(
    tls_stream: TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    peer_identity: Option<Arc<PeerIdentity>>,
    output: mpsc::Sender<RawMessage>,
    metrics: Arc<TlsMetrics>,
    shutdown: CancellationToken,
) {
    let framed = FramedRead::new(tls_stream, OctetCountingDecoder::new(MAX_FRAME_SIZE));

    tokio::pin!(framed);

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                // Graceful shutdown: send close_notify (handled by drop of TlsStream).
                break;
            }

            frame = framed.next() => {
                match frame {
                    Some(Ok(payload)) => {
                        metrics.messages_received.increment(1);

                        let raw = RawMessage {
                            payload,
                            source: peer_addr,
                            listener_id: /* ... */,
                            transport: TransportType::Tls,
                            received_at: Instant::now(),
                            peer_identity: peer_identity.clone(),
                        };

                        // Backpressure: if channel is full, await (TCP/TLS has
                        // backpressure via flow control — blocking the read
                        // propagates naturally).
                        if output.send(raw).await.is_err() {
                            // Pipeline shut down; exit.
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        metrics.frame_errors.increment(1);
                        tracing::debug!(peer = %peer_addr, error = %e, "Frame decode error");
                        // On framing error: close the connection. The stream
                        // state is unrecoverable because we have lost byte
                        // alignment in the octet-counting protocol.
                        break;
                    }
                    None => {
                        // Clean EOF from peer.
                        break;
                    }
                }
            }
        }
    }

    metrics.connections_closed.increment(1);
}
```

### 3.7 Backpressure from Pipeline to Connection Read

Unlike UDP, TLS connections support backpressure. When the pipeline's bounded channel is full:

1. `output.send(raw).await` blocks the per-connection task.
2. The task stops reading from the `FramedRead`.
3. The TLS read buffer fills.
4. TCP flow control (window size) kicks in, signaling the sender to slow down.

This is the correct behavior: TCP/TLS senders can handle backpressure. The sender will buffer or slow its transmission rate. No messages are silently dropped on TLS connections.

**Backpressure safety valve:** A per-connection read timeout prevents a stalled pipeline from holding connections indefinitely. If no message is read for `idle_timeout` (default: 300 seconds), the connection is closed with `close_notify`.

### 3.8 Connection Draining on Shutdown

When `CancellationToken` fires:

1. The accept loop stops accepting new connections.
2. Each per-connection task's `select!` branch detects cancellation.
3. The connection task exits its read loop.
4. When the `TlsStream` is dropped, rustls sends `close_notify` (RFC 5425 S4.4 MUST).
5. A drain timeout (configurable, default 5 seconds) is applied. After this timeout, remaining connections are forcibly closed.

```rust
async fn drain_connections(
    active_connections: &AtomicUsize,
    drain_timeout: Duration,
) {
    let deadline = tokio::time::sleep(drain_timeout);
    tokio::pin!(deadline);

    loop {
        if active_connections.load(Ordering::Relaxed) == 0 {
            tracing::info!("All TLS connections drained");
            return;
        }
        tokio::select! {
            _ = &mut deadline => {
                let remaining = active_connections.load(Ordering::Relaxed);
                tracing::warn!(remaining, "Drain timeout reached; closing remaining connections");
                return;
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Poll active count.
            }
        }
    }
}
```

### 3.9 Session Resumption

rustls supports TLS 1.2 session tickets and TLS 1.3 session tickets by default via `ServerSessionMemoryCache`. This is allowed by RFC 5425 S4.2 with the caveat that security parameters SHOULD be checked on resumption. rustls handles this correctly: resumed sessions inherit the original negotiated parameters and the server config's current certificate/cipher requirements.

Session resumption significantly reduces handshake latency for reconnecting clients, which matters for the relay use case where connections are long-lived but may be interrupted.

The session cache size is configurable (default: 1024 entries). Each entry consumes approximately 200-500 bytes.

### 3.10 TLS Listener Metrics

```
syslog_tls_connections_accepted_total{listener="..."}
syslog_tls_connections_rejected_total{listener="...", reason="limit|handshake|timeout"}
syslog_tls_connections_active{listener="..."}
syslog_tls_handshake_errors_total{listener="...", error_type="..."}
syslog_tls_handshake_duration_seconds{listener="..."}  (histogram)
syslog_tls_messages_received_total{listener="..."}
syslog_tls_frame_errors_total{listener="..."}
syslog_tls_bytes_received_total{listener="..."}
syslog_tls_close_notify_sent_total{listener="..."}
syslog_tls_cert_expiry_seconds{listener="..."}  (gauge, seconds until expiry)
```

---

## 4. TLS Sender Architecture

### 4.1 Overview

The TLS sender delivers syslog messages to downstream collectors or relays over TLS. It manages connection pooling, reconnection, octet-counting framing, and write batching for throughput.

### 4.2 Connection Pooling and Management

For most syslog deployments, the sender maintains a single persistent connection per configured destination. Connection pooling (multiple connections to the same destination) is available for high-throughput scenarios:

```rust
pub struct TlsSenderConfig {
    /// Destination address and port (default port: 6514).
    pub destination: SocketAddr,
    /// Hostname for TLS SNI and certificate validation.
    pub server_name: ServerName<'static>,
    /// Number of connections to maintain. Default: 1.
    /// Multiple connections can increase throughput by parallelizing TLS writes.
    pub pool_size: usize,
    /// Maximum time to wait for a connection to become available. Default: 5s.
    pub connect_timeout: Duration,
    /// Idle connection timeout. Close connections idle longer than this. Default: 300s.
    pub idle_timeout: Duration,
    /// Write batch size. Accumulate up to this many messages before flushing. Default: 64.
    pub batch_size: usize,
    /// Maximum time to hold a partial batch before flushing. Default: 10ms.
    pub batch_timeout: Duration,
}
```

#### Connection State Machine

```
            connect_timeout
  Idle -----> Connecting -----> Connected -----> Draining -----> Closed
   ^             |                  |                              |
   |             v                  v                              |
   +------- Backoff <------- Disconnected <------------------------+
```

Each connection cycles through these states. The sender task selects an available connection from the pool using round-robin. If all connections are in `Backoff` or `Connecting`, messages are buffered in the sender's input channel (bounded; backpressure propagates upstream).

### 4.3 Reconnection with Exponential Backoff

```rust
pub struct ReconnectPolicy {
    /// Initial delay after first failure. Default: 100ms.
    pub initial_delay: Duration,
    /// Maximum delay between attempts. Default: 60s.
    pub max_delay: Duration,
    /// Multiplier per failed attempt. Default: 2.0.
    pub multiplier: f64,
    /// Random jitter factor (0.0 to 1.0). Default: 0.1.
    pub jitter: f64,
}
```

The reconnection sequence:

1. Connection drops or handshake fails.
2. Enter `Backoff` state; schedule retry after `delay`.
3. On next failure: `delay = min(delay * multiplier, max_delay)` with jitter.
4. On success: reset `delay` to `initial_delay`.
5. Log each reconnection attempt with attempt count and delay.

The backoff timer uses jitter to prevent thundering herd when multiple senders reconnect simultaneously (e.g., after a collector restart).

### 4.4 Octet-Counting Frame Encoder

Messages are encoded using the `OctetCountingEncoder` (see Section 6). The encoder prepends the message length and a space character.

### 4.5 Write Batching for Throughput

To amortize system call overhead, the sender batches multiple framed messages into a single `write_all`:

```rust
async fn write_batch(
    writer: &mut TlsStream<TcpStream>,
    batch: &[Arc<SyslogMessage>],
    encoder: &OctetCountingEncoder,
    write_buf: &mut BytesMut,
) -> io::Result<()> {
    write_buf.clear();

    for msg in batch {
        let serialized = msg.serialize();
        encoder.encode(&serialized, write_buf);
    }

    writer.write_all(&write_buf).await?;
    writer.flush().await?;

    Ok(())
}
```

The batch loop accumulates messages until either `batch_size` messages are collected or `batch_timeout` elapses, whichever comes first:

```rust
async fn sender_loop(
    input: &mut mpsc::Receiver<Arc<SyslogMessage>>,
    writer: &mut TlsStream<TcpStream>,
    config: &TlsSenderConfig,
) -> Result<(), SenderError> {
    let mut batch = Vec::with_capacity(config.batch_size);
    let mut write_buf = BytesMut::with_capacity(config.batch_size * 1024);
    let encoder = OctetCountingEncoder;

    loop {
        // Fill the batch.
        let deadline = tokio::time::sleep(config.batch_timeout);
        tokio::pin!(deadline);

        loop {
            if batch.len() >= config.batch_size {
                break;
            }

            tokio::select! {
                biased;
                msg = input.recv() => {
                    match msg {
                        Some(msg) => batch.push(msg),
                        None => {
                            // Channel closed — flush remaining and exit.
                            if !batch.is_empty() {
                                write_batch(writer, &batch, &encoder, &mut write_buf).await?;
                            }
                            return Ok(());
                        }
                    }
                }
                _ = &mut deadline => break,
            }
        }

        if !batch.is_empty() {
            write_batch(writer, &batch, &encoder, &mut write_buf).await?;
            batch.clear();
        }
    }
}
```

### 4.6 Health Checking and Keepalive

Connection health is maintained through:

1. **TCP keepalive:** Enabled on the underlying TCP socket with configurable interval (default: 60 seconds). Detects half-open connections.

2. **Application-level health:** A connection is considered unhealthy if a write fails. Failed writes trigger immediate reconnection and re-queue of the failed batch.

3. **Certificate expiry monitoring:** The sender periodically checks the server's certificate expiry date and emits a gauge metric `syslog_tls_sender_peer_cert_expiry_seconds`. Warnings are logged at 30, 7, and 1 days before expiry.

### 4.7 rustls ClientConfig Setup

```rust
pub fn build_client_config(tls_config: &TlsSenderTlsConfig) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let mut root_store = RootCertStore::empty();

    // Load CA certificates for server validation.
    if let Some(ca_path) = &tls_config.ca_cert_path {
        let ca_certs = load_certificate_chain(ca_path)?;
        for cert in ca_certs {
            root_store.add(cert)?;
        }
    } else {
        // Use webpki-roots as default CA bundle.
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let builder = ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_cipher_suites(&rfc9662_client_cipher_suites())
    .with_safe_default_kx_groups()
    .with_root_certificates(root_store);

    let mut config = if let (Some(cert_path), Some(key_path)) =
        (&tls_config.client_cert_path, &tls_config.client_key_path)
    {
        // Mutual TLS: present client certificate.
        let cert_chain = load_certificate_chain(cert_path)?;
        let key = load_private_key(key_path)?;
        builder.with_client_auth_cert(cert_chain, key)?
    } else {
        builder.with_no_client_auth()
    };

    // MUST NOT enable 0-RTT.
    config.enable_early_data = false;

    Ok(Arc::new(config))
}
```

### 4.8 TLS Sender Metrics

```
syslog_tls_sender_messages_sent_total{destination="..."}
syslog_tls_sender_bytes_sent_total{destination="..."}
syslog_tls_sender_batches_sent_total{destination="..."}
syslog_tls_sender_batch_size{destination="..."}  (histogram)
syslog_tls_sender_write_errors_total{destination="..."}
syslog_tls_sender_reconnections_total{destination="..."}
syslog_tls_sender_connection_state{destination="...", state="connected|backoff|connecting"}
syslog_tls_sender_peer_cert_expiry_seconds{destination="..."}
```

---

## 5. UDP Sender

### 5.1 Overview

The UDP sender transmits syslog messages as individual datagrams to a configured destination. It is the simplest output transport — no framing, no connection state, no reliability.

### 5.2 Socket Management

```rust
pub struct UdpSender {
    socket: UdpSocket,
    destination: SocketAddr,
    max_message_size: usize,  // Default: 2048 (SHOULD per RFC 5426 S3.2)
    metrics: Arc<UdpSenderMetrics>,
}

impl UdpSender {
    pub async fn new(config: &UdpSenderConfig) -> Result<Self, TransportError> {
        // Bind to ephemeral port (0.0.0.0:0 or [::]:0).
        let bind_addr: SocketAddr = if config.destination.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(bind_addr).await?;

        // Connect to destination for slightly faster sends (avoids per-send
        // destination lookup in kernel).
        socket.connect(config.destination).await?;

        Ok(Self {
            socket,
            destination: config.destination,
            max_message_size: config.max_message_size.unwrap_or(2048),
            metrics: Arc::new(UdpSenderMetrics::new(&config.destination.to_string())),
        })
    }
}
```

### 5.3 Message Size Validation

Before sending, the serialized message size is checked:

```rust
async fn send_message(&self, msg: &SyslogMessage) -> Result<(), SenderError> {
    let serialized = msg.serialize();
    let len = serialized.len();

    if len > self.max_message_size {
        self.metrics.oversized_messages.increment(1);
        tracing::warn!(
            size = len,
            max = self.max_message_size,
            "Message exceeds UDP max size; dropping"
        );
        return Err(SenderError::MessageTooLarge { size: len, max: self.max_message_size });
    }

    // Enforce RFC minimum: we should not send messages that receivers
    // might not be able to accept.
    if len > 480 {
        // Not an error, but note that IPv4 receivers are only required to
        // accept 480 octets. Messages between 480 and 2048 are in the
        // SHOULD range and are generally safe.
    }

    self.socket.send(&serialized).await?;
    self.metrics.messages_sent.increment(1);
    self.metrics.bytes_sent.increment(len as u64);

    Ok(())
}
```

### 5.4 Send Error Handling

| Error | Behavior |
|-------|----------|
| `send` returns EMSGSIZE | Message too large for socket; drop and count |
| `send` returns ENETUNREACH / EHOSTUNREACH | Destination unreachable; log, count, continue |
| `send` returns ENOBUFS | Kernel send buffer full; log, count, continue (transient) |
| Serialization produces empty message | Skip silently (should not occur) |

UDP sends are fire-and-forget. The sender does not retry failed sends because UDP provides no delivery guarantee anyway.

### 5.5 Metrics

```
syslog_udp_sender_messages_sent_total{destination="..."}
syslog_udp_sender_bytes_sent_total{destination="..."}
syslog_udp_sender_errors_total{destination="...", error_type="..."}
syslog_udp_sender_oversized_dropped_total{destination="..."}
```

---

## 6. Octet-Counting Framing

### 6.1 Frame Format

Per RFC 5425 S4.3:

```
SYSLOG-FRAME = MSG-LEN SP SYSLOG-MSG
MSG-LEN      = NONZERO-DIGIT *DIGIT
SP            = %d32
SYSLOG-MSG   = (per RFC 5424)
```

Example: A 30-byte syslog message is framed as:

```
30 <30 bytes of syslog message>
```

`MSG-LEN` is the decimal count of octets in `SYSLOG-MSG`, with no leading zeros.

### 6.2 Codec Implementation

The codec is implemented as a `tokio_util::codec::Decoder` and `tokio_util::codec::Encoder`, suitable for use with `FramedRead` and `FramedWrite`.

#### Decoder

```rust
pub struct OctetCountingDecoder {
    /// Maximum allowed frame size. MUST be at least 2048 (RFC 5425 S4.3).
    /// SHOULD be at least 8192. Default: 65536.
    max_frame_size: usize,
    /// Current decoder state.
    state: DecoderState,
}

enum DecoderState {
    /// Reading the MSG-LEN digits and SP.
    ReadingLength {
        /// Accumulated length value.
        len_value: usize,
        /// Number of digits read so far.
        digits_read: usize,
    },
    /// Reading the SYSLOG-MSG body.
    ReadingBody {
        /// Expected body length.
        expected_len: usize,
    },
}

impl Decoder for OctetCountingDecoder {
    type Item = Bytes;
    type Error = FrameError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Bytes>, FrameError> {
        loop {
            match &mut self.state {
                DecoderState::ReadingLength { len_value, digits_read } => {
                    if src.is_empty() {
                        return Ok(None);  // Need more data.
                    }

                    // Scan for digits and SP.
                    while !src.is_empty() {
                        let byte = src[0];

                        if byte == b' ' {
                            // SP found — transition to ReadingBody.
                            if *digits_read == 0 {
                                return Err(FrameError::EmptyLength);
                            }
                            let expected_len = *len_value;
                            if expected_len > self.max_frame_size {
                                return Err(FrameError::FrameTooLarge {
                                    size: expected_len,
                                    max: self.max_frame_size,
                                });
                            }
                            src.advance(1);  // Consume SP.
                            self.state = DecoderState::ReadingBody { expected_len };
                            break;
                        } else if byte.is_ascii_digit() {
                            // Leading zero check.
                            if *digits_read == 0 && byte == b'0' {
                                return Err(FrameError::LeadingZero);
                            }
                            *len_value = len_value
                                .checked_mul(10)
                                .and_then(|v| v.checked_add((byte - b'0') as usize))
                                .ok_or(FrameError::LengthOverflow)?;
                            *digits_read += 1;
                            src.advance(1);

                            // Safety: MSG-LEN should not exceed ~6 digits for
                            // any reasonable frame size.
                            if *digits_read > 7 {
                                return Err(FrameError::LengthOverflow);
                            }
                        } else {
                            return Err(FrameError::InvalidLengthByte { byte });
                        }
                    }

                    // If we consumed all bytes without finding SP, need more data.
                    if matches!(self.state, DecoderState::ReadingLength { .. }) {
                        return Ok(None);
                    }
                }

                DecoderState::ReadingBody { expected_len } => {
                    if src.len() < *expected_len {
                        // Reserve capacity to avoid repeated reallocations.
                        src.reserve(*expected_len - src.len());
                        return Ok(None);  // Need more data.
                    }

                    let body = src.split_to(*expected_len).freeze();
                    self.state = DecoderState::ReadingLength {
                        len_value: 0,
                        digits_read: 0,
                    };
                    return Ok(Some(body));
                }
            }
        }
    }
}
```

#### Encoder

```rust
pub struct OctetCountingEncoder;

impl Encoder<&[u8]> for OctetCountingEncoder {
    type Error = io::Error;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), io::Error> {
        let len = item.len();
        // Write MSG-LEN as ASCII decimal.
        // Use itoa for fast integer-to-string conversion.
        let mut len_buf = itoa::Buffer::new();
        let len_str = len_buf.format(len);

        dst.reserve(len_str.len() + 1 + len);
        dst.put_slice(len_str.as_bytes());
        dst.put_u8(b' ');
        dst.put_slice(item);

        Ok(())
    }
}
```

### 6.3 Max Frame Size Enforcement

The decoder enforces a configurable maximum frame size (default: 65536 octets). This prevents a malicious or buggy sender from causing unbounded memory allocation by sending a large `MSG-LEN` value.

| Configuration | Value | Rationale |
|--------------|-------|-----------|
| Minimum allowed `max_frame_size` | 2048 | RFC 5425 S4.3 MUST |
| Recommended `max_frame_size` | 8192 | RFC 5425 S4.3 SHOULD |
| Default `max_frame_size` | 65536 | Handles large structured data messages |
| Hard ceiling | 1048576 (1 MiB) | Prevents misconfiguration causing OOM |

### 6.4 Partial Read Handling

TCP delivers a byte stream, not message boundaries. The decoder handles partial reads naturally:

- **Partial length:** The `ReadingLength` state accumulates digits across multiple `decode` calls. If the buffer ends mid-digit, the decoder returns `Ok(None)` and resumes when more data arrives.
- **Partial body:** The `ReadingBody` state checks `src.len() < expected_len`. If insufficient data is available, the decoder reserves the needed capacity and returns `Ok(None)`.

This is inherent in the `tokio_util::codec::Decoder` contract and requires no special handling beyond correct state management.

### 6.5 Error Recovery on Malformed Frames

Octet-counting is not self-synchronizing. If the decoder encounters a malformed frame (non-digit in length position, leading zero, overflow), recovery is not possible because the byte stream is now out of alignment. The decoder returns `Err(FrameError)`, and the connection task closes the connection.

This is the correct behavior per RFC 5425: the protocol offers no resynchronization mechanism. A malformed frame indicates either a buggy sender or data corruption, and the connection must be torn down.

```rust
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("empty MSG-LEN")]
    EmptyLength,
    #[error("leading zero in MSG-LEN")]
    LeadingZero,
    #[error("MSG-LEN overflow")]
    LengthOverflow,
    #[error("invalid byte 0x{byte:02x} in MSG-LEN")]
    InvalidLengthByte { byte: u8 },
    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}
```

---

## 7. TLS/DTLS Security Design

### 7.1 Cipher Suite Configuration for RFC 9662

#### TLS 1.2 Cipher Suites

RFC 9662 mandates two cipher suites and establishes a preference order:

| Cipher Suite | IANA Value | Status | rustls Constant |
|-------------|-----------|--------|-----------------|
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 0xC02F | MUST, SHOULD prefer | `rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` |
| `TLS_RSA_WITH_AES_128_CBC_SHA` | 0x002F | MUST implement, MAY use | Not available in default rustls (no static RSA key exchange) |

**Important rustls limitation:** rustls does not support static RSA key exchange (`TLS_RSA_WITH_AES_128_CBC_SHA`) because it lacks forward secrecy. This is a deliberate design decision by the rustls maintainers. Since RFC 9662 marks this suite as legacy/migration-only, and the ECDHE suite is the SHOULD-prefer suite, this limitation is acceptable for production deployments. For environments that require the legacy suite, an optional `openssl` feature gate can be provided.

The default cipher suite list for TLS 1.2:

```rust
fn rfc9662_tls12_cipher_suites() -> Vec<SupportedCipherSuite> {
    vec![
        // MUST implement, SHOULD prefer (RFC 9662 S5).
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        // Additional AEAD suites supported by rustls for interoperability.
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        // ECDSA variants for deployments using EC keys.
        rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ]
}
```

#### TLS 1.3 Cipher Suites

TLS 1.3 mandates AEAD-only cipher suites. RFC 9662 S5 states: "For TLS 1.3, the mandatory-to-implement cipher suites are defined by [RFC 8446]." rustls supports all standard TLS 1.3 suites:

```rust
fn rfc9662_tls13_cipher_suites() -> Vec<SupportedCipherSuite> {
    vec![
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ]
}
```

#### Combined Suite List

```rust
fn rfc9662_server_cipher_suites() -> Vec<SupportedCipherSuite> {
    let mut suites = rfc9662_tls13_cipher_suites();  // TLS 1.3 preferred.
    suites.extend(rfc9662_tls12_cipher_suites());
    suites
}

fn rfc9662_client_cipher_suites() -> Vec<SupportedCipherSuite> {
    // Same suites for client; preference order is server-driven.
    rfc9662_server_cipher_suites()
}
```

### 7.2 Certificate Chain Loading

Certificates are loaded from PEM files. The chain must include the end-entity certificate followed by intermediate CA certificates in order. The root CA certificate should NOT be included in the chain (it must be in the peer's trust store).

```rust
/// Validates the loaded certificate chain:
/// 1. At least one certificate (the end-entity).
/// 2. End-entity certificate is not expired.
/// 3. Chain order is correct (each cert signs the next).
fn validate_certificate_chain(
    certs: &[CertificateDer<'_>],
) -> Result<CertificateInfo, TlsConfigError> {
    if certs.is_empty() {
        return Err(TlsConfigError::EmptyChain);
    }

    // Parse end-entity certificate for metadata.
    let end_entity = X509Certificate::from_der(&certs[0])
        .map_err(|e| TlsConfigError::CertificateParse { source: e.into() })?;

    let not_after = end_entity.validity().not_after.to_datetime();
    let subject = end_entity.subject().to_string();

    // Extract SANs for logging.
    let sans: Vec<String> = end_entity
        .subject_alternative_name()
        .map(|ext| ext.value.general_names.iter()
            .filter_map(|gn| match gn {
                GeneralName::DnsName(dns) => Some(dns.to_string()),
                _ => None,
            })
            .collect())
        .unwrap_or_default();

    Ok(CertificateInfo {
        subject,
        sans,
        not_after,
        fingerprint_sha256: sha256_fingerprint(&certs[0]),
    })
}
```

### 7.3 CA Bundle Management

Trust anchor configuration supports three modes:

1. **Explicit CA file:** A PEM file containing one or more CA certificates. Used for private PKI.
2. **System trust store:** Uses the platform's native certificate store via `rustls-native-certs`. Suitable when communicating with public-CA-signed endpoints.
3. **WebPKI roots:** Bundled Mozilla root certificates via `webpki-roots`. Deterministic across platforms but requires crate updates for root changes.

```toml
# Configuration examples:

# Explicit CA for private PKI
[tls]
ca_cert = "/etc/syslog-usg/ca-chain.pem"

# System trust store
[tls]
ca_cert = "system"

# Bundled WebPKI roots (default for sender)
[tls]
ca_cert = "webpki"
```

### 7.4 CRL and OCSP Considerations (Future)

Certificate revocation checking is not implemented in the MVP but the design accommodates it:

- **CRL (Certificate Revocation List):** rustls supports CRL checking via `WebPkiClientVerifier::builder().with_crls()`. The CRL file path will be a configuration option. CRL refresh will run on a configurable timer (default: 1 hour).
- **OCSP Stapling:** rustls supports OCSP stapling on the server side. The server can be configured with a pre-fetched OCSP response. An OCSP fetcher task will periodically request fresh responses.
- **OCSP Must-Staple:** If the server certificate has the OCSP Must-Staple extension, the server must provide a valid OCSP response or connections will fail.

These features are deferred to post-MVP because many syslog deployments use private PKI without CRL/OCSP infrastructure.

### 7.5 Private Key Protection

Private keys require the following protections:

1. **File permissions:** Warn at startup if the key file is readable by group or others (mode & 0o077 != 0 on Unix). Documented best practice is `chmod 600`.
2. **No logging:** Private key material is never logged, even at trace level. The key path may be logged; the key content must not.
3. **No metrics exposure:** Key material is never included in metrics labels, health endpoints, or error messages.
4. **Memory handling:** rustls uses `Zeroize` for key material in memory. syslog-usg does not perform additional key memory management beyond what rustls provides.
5. **Encrypted keys (future):** Support for PKCS#8 encrypted private keys with passphrase provided via environment variable (`SYSLOG_TLS_KEY_PASSPHRASE`). Not in MVP because rustls does not natively support encrypted PEM keys; integration would require the `rsa` or `p256` crates for decryption.

### 7.6 0-RTT Prevention

RFC 9662 S5 explicitly states: "Implementations MUST NOT use early data."

The rationale is that syslog messages have no application-layer replay protection. If 0-RTT were allowed, a network attacker could replay captured early data to inject duplicate syslog messages.

Prevention in syslog-usg:

- **Server:** `ServerConfig::max_early_data_size` is set to `0`. This causes the server to reject any client attempting to send early data.
- **Client:** `ClientConfig::enable_early_data` is set to `false`. The client will never attempt 0-RTT.
- **Configuration:** There is no configuration knob to enable 0-RTT. The prohibition is hardcoded and cannot be overridden.

### 7.7 Minimum TLS Version Enforcement

RFC 5425 S4.2 requires TLS 1.2 as the minimum version. RFC 9662 recommends TLS 1.3.

```rust
// Protocol version configuration.
// TLS 1.0 and 1.1 are never offered. rustls does not support them at all,
// which provides defense-in-depth: even a configuration error cannot
// enable deprecated versions.
let versions = &[
    &rustls::version::TLS13,  // Preferred.
    &rustls::version::TLS12,  // Mandatory minimum.
];
```

rustls enforces this structurally: it does not implement TLS 1.0 or 1.1. This means syslog-usg inherently cannot negotiate a version below TLS 1.2, satisfying the RFC requirement without additional configuration.

### 7.8 Certificate Fingerprint Matching

RFC 5425 S4.2.1 requires support for end-entity certificate matching via fingerprints. This is an alternative to full PKI path validation, useful when certificates are self-signed or the CA infrastructure is not available.

```rust
/// Fingerprint algorithms supported for certificate matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FingerprintAlgorithm {
    /// SHA-1: MUST support per RFC 5425 S4.2.2 (label: "sha-1").
    Sha1,
    /// SHA-256: recommended for new deployments.
    Sha256,
}

/// A certificate fingerprint in colon-separated hex format.
/// Example: "E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D"
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertificateFingerprint {
    pub algorithm: FingerprintAlgorithm,
    pub bytes: Vec<u8>,
}

impl CertificateFingerprint {
    pub fn from_der(cert_der: &[u8], algorithm: FingerprintAlgorithm) -> Self {
        let bytes = match algorithm {
            FingerprintAlgorithm::Sha1 => {
                use sha1::Digest;
                sha1::Sha1::digest(cert_der).to_vec()
            }
            FingerprintAlgorithm::Sha256 => {
                use sha2::Digest;
                sha2::Sha256::digest(cert_der).to_vec()
            }
        };
        Self { algorithm, bytes }
    }

    /// Format as colon-separated hex string.
    pub fn to_hex_string(&self) -> String {
        self.bytes.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Parse from "algorithm:hex" format.
    /// Example: "sha-256:E1:2D:53:..."
    pub fn parse(s: &str) -> Result<Self, FingerprintParseError> {
        let (alg_label, hex_part) = s.split_once(':')
            .ok_or(FingerprintParseError::MissingAlgorithm)?;

        let algorithm = match alg_label {
            "sha-1" => FingerprintAlgorithm::Sha1,
            "sha-256" => FingerprintAlgorithm::Sha256,
            _ => return Err(FingerprintParseError::UnknownAlgorithm(alg_label.to_string())),
        };

        let bytes: Result<Vec<u8>, _> = hex_part
            .split(':')
            .map(|h| u8::from_str_radix(h, 16))
            .collect();

        Ok(Self {
            algorithm,
            bytes: bytes.map_err(|_| FingerprintParseError::InvalidHex)?,
        })
    }
}
```

Fingerprint matching is configured per-listener or per-sender:

```toml
[tls.listener.allowed_fingerprints]
# Accept connections from clients with these certificate fingerprints.
# When set, PKI path validation is bypassed for matching certificates.
sha-256 = [
    "E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D:...",
    "A3:4F:...",
]
```

A custom `ClientCertVerifier` implementation checks fingerprints:

```rust
struct FingerprintVerifier {
    allowed: HashSet<CertificateFingerprint>,
    /// Fallback to PKI validation if fingerprint does not match.
    fallback_verifier: Option<Arc<dyn ClientCertVerifier>>,
}

impl ClientCertVerifier for FingerprintVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let fp_sha256 = CertificateFingerprint::from_der(
            end_entity.as_ref(),
            FingerprintAlgorithm::Sha256,
        );

        if self.allowed.contains(&fp_sha256) {
            return Ok(ClientCertVerified::assertion());
        }

        // Try SHA-1 for backward compatibility.
        let fp_sha1 = CertificateFingerprint::from_der(
            end_entity.as_ref(),
            FingerprintAlgorithm::Sha1,
        );

        if self.allowed.contains(&fp_sha1) {
            return Ok(ClientCertVerified::assertion());
        }

        // Optionally fall back to PKI validation.
        if let Some(fallback) = &self.fallback_verifier {
            return fallback.verify_client_cert(end_entity, _intermediates, _now);
        }

        Err(rustls::Error::General("certificate fingerprint not in allowed list".into()))
    }
}
```

---

## 8. Secure Defaults

### 8.1 Default TLS Configuration

The following defaults apply when a TLS listener or sender is configured without explicit cipher/version overrides:

| Setting | Default Value | Rationale |
|---------|--------------|-----------|
| Minimum TLS version | 1.2 | RFC 5425 MUST |
| Preferred TLS version | 1.3 | RFC 9662 SHOULD |
| Cipher suites (TLS 1.2) | ECDHE+AEAD only | Forward secrecy, RFC 9662 preference |
| Cipher suites (TLS 1.3) | All standard (AES-128-GCM, AES-256-GCM, ChaCha20) | RFC 8446 mandatory |
| 0-RTT / early data | Disabled, not configurable | RFC 9662 MUST NOT |
| Session resumption | Enabled (ticket-based) | Performance; parameters re-validated |
| Client authentication | Optional (listener), none (sender) | SHOULD per RFC 5425 |
| Certificate validation | Full PKI path validation | MUST per RFC 5425 S5.2 |
| Key exchange groups | X25519, P-256, P-384 | rustls safe defaults |

### 8.2 Default Mutual TLS Behavior

- **Listeners:** Client certificate is requested but not required (`ClientAuthMode::Optional`). If a client presents a certificate, it is validated against the configured CA. If no client CA is configured, client certificates are not requested (`ClientAuthMode::None`).
- **Senders:** Client certificate is presented only if both `client_cert` and `client_key` are configured. Mutual TLS is encouraged in documentation but not forced.

### 8.3 Self-Signed Certificate Policy

Self-signed certificates are supported but require explicit opt-in:

```toml
[tls.listener]
cert = "/etc/syslog-usg/server.pem"
key = "/etc/syslog-usg/server.key"
# To accept self-signed client certs, use fingerprint matching:
client_auth = "required"
allowed_fingerprints = ["sha-256:..."]

[tls.sender]
# To connect to a server with a self-signed cert:
ca_cert = "/etc/syslog-usg/server-self-signed.pem"
# Or use fingerprint pinning:
server_fingerprint = "sha-256:..."
```

Without explicit fingerprint or CA configuration, connections to self-signed servers will fail certificate validation. This is the secure default.

### 8.4 Plain-Text TCP Warning

When a plain-text TCP listener is configured (no TLS), a prominent warning is emitted at startup:

```
WARN [transport::tcp] Plain-text TCP listener enabled on 0.0.0.0:514.
     Messages are transmitted without encryption or authentication.
     This configuration is NOT RECOMMENDED for production use.
     Consider using TLS (port 6514) per RFC 5425.
```

This warning is also exposed as a metrics gauge:

```
syslog_insecure_listeners_active{listener="tcp://0.0.0.0:514"} 1
```

### 8.5 Default Configuration Summary

```toml
# Secure defaults — what ships in the example configuration.

[listener.udp]
bind = "0.0.0.0:514"
max_message_size = 8192

[listener.tls]
bind = "0.0.0.0:6514"
cert = "/etc/syslog-usg/server.pem"
key = "/etc/syslog-usg/server.key"
client_auth = "optional"
# client_ca = "/etc/syslog-usg/client-ca.pem"  # Uncomment for mutual TLS
min_tls_version = "1.2"
max_frame_size = 65536
idle_timeout = "300s"

[output.tls]
destination = "collector.example.com:6514"
# ca_cert = "webpki"  # Default: use bundled WebPKI roots
# client_cert = "/etc/syslog-usg/client.pem"
# client_key = "/etc/syslog-usg/client.key"
```

---

## 9. Transport-Specific Risks

### 9.1 UDP Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Message loss under load** | High | Medium | Monitor `udp_channel_drops_total`. Size SO_RCVBUF appropriately. Use SO_REUSEPORT with multiple sockets. Accept that UDP loss is inherent and documented. |
| **Message truncation** | Medium | Medium | Set `max_message_size` >= 2048. Log truncated datagrams. Advise senders to stay within MTU. |
| **Source IP spoofing** | Medium | High | Never use source IP as an authentication mechanism. Rate-limit per source to contain amplification. For authenticated transport, use TLS. |
| **Amplification attacks** | Low | High | syslog-usg is a receiver (not a reflector), so amplification risk is limited. Rate limiting on inbound prevents resource exhaustion. |
| **IP fragmentation** | Medium | Low | Fragmented datagrams reassembled by kernel. Fragment loss causes silent message loss. Advise senders to avoid fragmentation. |
| **Duplicate delivery** | Low | Low | UDP can deliver duplicates (rare). The pipeline treats each datagram independently. Deduplication is not performed (not required by RFC). |
| **Out-of-order delivery** | High | Low | RFC 5426 S4.4: arrival order SHOULD NOT be treated as authoritative. Timestamp-based ordering in the pipeline. |

### 9.2 TLS Risks

| Risk | Likelihood | Impact | Impact Detail | Mitigation |
|------|-----------|--------|---------------|------------|
| **Handshake failure** | Medium | Low | Single connection fails | Log handshake errors with peer address and error type. Monitor `tls_handshake_errors_total`. Common causes: cipher mismatch, expired cert, untrusted CA. |
| **Certificate expiry** | High | High | All connections fail | Monitor `tls_cert_expiry_seconds` gauge. Alert at 30/7/1 days. Log warnings on startup if cert expires within 30 days. |
| **Connection storms** | Medium | High | Resource exhaustion | Enforce `max_connections` limit. Rate-limit new connections per source IP. Handshake timeout prevents slow-loris attacks. |
| **Slow-loris / slow-read** | Medium | Medium | Connection slot exhaustion | Per-connection idle timeout. Handshake timeout (10s). Read timeout on inactive connections (300s). |
| **Memory exhaustion from connections** | Low | High | Process crash | Each TLS connection consumes ~50-100 KiB. At 10k connections: ~500 MiB - 1 GiB. Set `max_connections` relative to available memory. |
| **Session resumption replay** | Low | Medium | Duplicate messages | rustls validates resumed session parameters. 0-RTT is disabled, eliminating the primary replay vector. |
| **Key compromise** | Low | Critical | All connections compromised | Use ECDHE for forward secrecy (default). Compromised key cannot decrypt past traffic. Rotate keys and re-deploy. |
| **Downgrade attack** | Low | High | Weak cipher negotiated | rustls does not implement TLS 1.0/1.1. Only AEAD suites are configured by default. No downgrade path exists. |

### 9.3 DTLS Risks (Future)

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Message reordering** | High | Low | DTLS delivers records in order within an epoch, but UDP reordering can cause out-of-epoch delivery. Sequence numbers in DTLS records handle this. |
| **Replay attacks** | Medium | Medium | DTLS includes anti-replay via sequence number window. RFC 9662 prohibits 0-RTT, closing the main replay vector. |
| **PMTU issues** | Medium | Medium | DTLS record size limited by path MTU. Large syslog messages may not fit. DTLS handles fragmentation at the record layer, but performance degrades. |
| **Cookie exchange overhead** | High | Low | Adds one round-trip to initial handshake. Acceptable for DoS protection. Cache cookies for reconnecting clients. |
| **Handshake retransmission** | Medium | Low | DTLS handshake uses retransmission timers since UDP is unreliable. Handshake may take longer than TLS. Configure appropriate timeouts. |

---

## 10. Required Security Controls

### 10.1 Rate Limiting

#### Per-Source IP Rate Limiting

Protects against single-source flood attacks on UDP and connection storms on TLS.

```rust
pub struct RateLimitConfig {
    /// Maximum sustained message rate per source IP. Default: 10,000 msg/sec.
    pub messages_per_second: u64,
    /// Burst allowance above sustained rate. Default: 1,000 messages.
    pub burst_size: u64,
    /// Rate limit algorithm.
    pub algorithm: RateLimitAlgorithm,
    /// Maximum number of tracked source IPs. Default: 100,000.
    /// Prevents memory exhaustion from many unique sources.
    pub max_tracked_sources: usize,
    /// Eviction policy when max_tracked_sources is reached.
    pub eviction: EvictionPolicy,
}

#[derive(Debug, Clone)]
pub enum RateLimitAlgorithm {
    /// Token bucket: smooth rate with burst tolerance.
    TokenBucket,
    /// Sliding window: precise rate counting over a time window.
    SlidingWindow { window: Duration },
}
```

Implementation uses a token bucket per source IP, stored in a concurrent hash map (`dashmap`). Stale entries are evicted by a background sweep task.

Rate limit events are counted:

```
syslog_rate_limited_messages_total{listener="...", source_subnet="..."}
syslog_rate_limit_active_sources{listener="..."}
```

#### Per-Output Rate Limiting

Prevents a high-volume input from overwhelming a downstream destination:

```rust
pub struct OutputRateLimitConfig {
    /// Maximum sustained message rate to this output. Default: unlimited.
    pub messages_per_second: Option<u64>,
    /// What to do when rate limit is hit.
    pub overflow_action: OverflowAction,
}

pub enum OverflowAction {
    /// Drop excess messages (counted in metrics).
    Drop,
    /// Apply backpressure to the pipeline (may affect other outputs sharing the queue).
    Backpressure,
}
```

### 10.2 Connection Limits

```rust
pub struct ConnectionLimits {
    /// Maximum concurrent TLS connections per listener. Default: 10,000.
    pub max_connections: usize,
    /// Maximum new connections per second per source IP. Default: 100.
    pub max_connections_per_source_per_second: u64,
    /// Maximum concurrent connections from a single source IP. Default: 100.
    pub max_connections_per_source: usize,
    /// Handshake timeout. Default: 10 seconds.
    pub handshake_timeout: Duration,
    /// Idle connection timeout. Default: 300 seconds.
    pub idle_timeout: Duration,
    /// Active connection counter (atomic for lock-free checking).
    pub active_connections: AtomicUsize,
}
```

The `max_connections_per_source_per_second` limit uses a per-IP token bucket (shared with the message rate limiter infrastructure). This prevents SYN flood and TLS handshake exhaustion attacks.

### 10.3 Input Size Limits

| Limit | Default | Configurable | Rationale |
|-------|---------|-------------|-----------|
| UDP max datagram size | 8192 bytes | Yes | Beyond RFC SHOULD (2048), accommodates large structured data |
| TLS max frame size | 65536 bytes | Yes | Prevents OOM from malicious MSG-LEN |
| TLS max frame size hard ceiling | 1 MiB | No | Prevents misconfiguration |
| Maximum syslog message size (parsed) | 65536 bytes | Yes | Limits memory per message in pipeline |
| Maximum STRUCTURED-DATA size | 32768 bytes | Yes | Prevents pathological SD parsing |
| Maximum SD-ELEMENT count | 128 | Yes | Prevents deep-nesting attacks |
| Maximum PARAM-VALUE length | 16384 bytes | Yes | Individual parameter value limit |

### 10.4 Flood Protection

#### SYN Flood Protection

TCP SYN flood is mitigated at the OS level via SYN cookies. syslog-usg's contribution is:

- Limiting the TCP accept backlog to a reasonable size (default: 1024).
- Enforcing `max_connections` to prevent resource exhaustion from completed connections.
- Fast handshake timeout (10s) to reclaim slots from stalled connections.

Documentation advises enabling OS-level SYN cookies:

```
sysctl -w net.ipv4.tcp_syncookies=1
```

#### UDP Flood Protection

UDP has no connection state, so flood protection relies entirely on rate limiting:

1. **Per-source rate limit** (token bucket) drops excess datagrams from any single source.
2. **Global rate limit** (optional) caps total ingest rate across all sources.
3. **Pipeline backpressure** is handled via `try_send` dropping messages when the channel is full.

#### Slowloris Protection

The per-connection idle timeout and handshake timeout prevent slowloris-style attacks:

- A connection that completes the TLS handshake but sends no messages is closed after `idle_timeout`.
- A connection that does not complete the TLS handshake is closed after `handshake_timeout`.
- A connection that sends data very slowly will naturally occupy one connection slot, bounded by `max_connections`.

### 10.5 Privilege Dropping

After binding privileged ports (514 for UDP, 6514 for TLS), the process drops privileges to a configured unprivileged user/group:

```rust
pub struct PrivilegeConfig {
    /// User to switch to after binding. Example: "syslog-usg".
    pub user: Option<String>,
    /// Group to switch to after binding. Example: "syslog-usg".
    pub group: Option<String>,
}
```

The privilege drop sequence:

1. Parse configuration and validate.
2. Bind all listener sockets (requires root for port 514).
3. Load TLS certificates and private keys (may require root for file access).
4. Drop supplementary groups (`setgroups([])`).
5. Set GID (`setgid(target_gid)`).
6. Set UID (`setuid(target_uid)`).
7. Verify privileges were dropped (`getuid() != 0`).
8. Start the async runtime and begin accepting connections.

This sequence ensures that the async runtime and all message processing run without root privileges. If privilege dropping fails, the process exits with an error rather than running as root.

```rust
#[cfg(unix)]
fn drop_privileges(config: &PrivilegeConfig) -> Result<(), PrivilegeError> {
    use nix::unistd::{setuid, setgid, setgroups, Uid, Gid, User, Group};

    if let Some(group_name) = &config.group {
        let group = Group::from_name(group_name)?
            .ok_or(PrivilegeError::GroupNotFound(group_name.clone()))?;
        setgroups(&[])?;
        setgid(group.gid)?;
    }

    if let Some(user_name) = &config.user {
        let user = User::from_name(user_name)?
            .ok_or(PrivilegeError::UserNotFound(user_name.clone()))?;
        setuid(user.uid)?;
    }

    // Verify we are no longer root.
    if Uid::current().is_root() {
        return Err(PrivilegeError::StillRoot);
    }

    tracing::info!("Privileges dropped successfully");
    Ok(())
}
```

### 10.6 Security Control Summary Matrix

| Control | UDP Listener | TLS Listener | TLS Sender | UDP Sender |
|---------|-------------|-------------|-----------|-----------|
| Per-source rate limiting | Yes | Yes (per IP) | N/A | N/A |
| Connection limit | N/A | Yes (max_connections) | N/A (pool_size) | N/A |
| Input size limit | max_message_size | max_frame_size | N/A | max_message_size |
| Handshake timeout | N/A | 10 seconds | connect_timeout | N/A |
| Idle timeout | N/A | 300 seconds | idle_timeout | N/A |
| Authentication | None | Mutual TLS (optional) | Server cert validation | None |
| Encryption | None | TLS 1.2+ | TLS 1.2+ | None |
| Privilege dropping | Yes | Yes | Yes | Yes |
| 0-RTT prevention | N/A | Hardcoded off | Hardcoded off | N/A |

---

## Appendix A: DTLS Future Design Notes

When DTLS support is added (Phase 2), the following design points apply:

1. **Crate selection:** No mature DTLS crate exists in the Rust ecosystem as of 2026. Options include `openssl` (via `tokio-openssl`) with DTLS support, or a future `rustls` DTLS implementation. The `openssl` path would be gated behind a `dtls-openssl` feature flag.

2. **Port sharing:** DTLS and TLS both use port 6514 but on different transport protocols (UDP vs TCP). The `TransportManager` binds both a TCP and UDP socket on 6514 when both TLS and DTLS listeners are configured.

3. **Framing difference:** Unlike TLS where octet-counting is required, DTLS uses the DTLS record boundary as the message delimiter. Each DTLS record contains exactly one syslog message. No octet-counting framing is applied over DTLS.

4. **Cookie exchange:** DTLS cookie exchange (HelloVerifyRequest) is mandatory per RFC 6012 S5.3 and provides DoS mitigation analogous to TCP SYN cookies.

5. **DTLS 1.0 prohibition:** RFC 9662 explicitly bans DTLS 1.0. The implementation must reject DTLS 1.0 negotiation attempts.

## Appendix B: Traceability to RFC Requirements

| RFC | Section | Requirement Level | This Document Section |
|-----|---------|------------------|-----------------------|
| RFC 5426 | S3.1 | MUST: one message per datagram | 2.6 |
| RFC 5426 | S3.2 | MUST: accept 480/1180 octets | 2.2, 2.8 |
| RFC 5426 | S3.2 | SHOULD: accept 2048 octets | 2.2 |
| RFC 5426 | S3.3 | MUST: port 514 | 2.2 |
| RFC 5426 | S3.6 | MUST: UDP checksums | 2.2 (kernel-enforced) |
| RFC 5425 | S4.2 | MUST: TLS 1.2 | 3.2, 7.7 |
| RFC 5425 | S4.2.1 | MUST: certificate authentication | 3.3, 3.4 |
| RFC 5425 | S4.2.1 | MUST: fingerprint matching | 7.8 |
| RFC 5425 | S4.3 | MUST: octet-counting framing | 6.1-6.5 |
| RFC 5425 | S4.3 | MUST: 2048 octet messages | 6.3 |
| RFC 5425 | S4.4 | MUST: close_notify | 3.8 |
| RFC 5425 | S5.2 | MUST: PKI path validation | 7.2 |
| RFC 9662 | S5 | MUST: ECDHE_RSA_AES_128_GCM_SHA256 | 7.1 |
| RFC 9662 | S5 | MUST NOT: 0-RTT | 7.6 |
| RFC 9662 | S5 | SHOULD: TLS 1.3 | 7.7, 8.1 |
| RFC 6012 | S5.3 | MUST: DTLS 1.2 (future) | Appendix A |
| RFC 6012 | S5.3 | MUST NOT: DTLS 1.0 (future) | Appendix A |
| RFC 6012 | S5.3 | MUST: cookie exchange (future) | Appendix A |

