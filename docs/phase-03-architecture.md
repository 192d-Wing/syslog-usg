# Phase 03 — System Architecture

## syslog-usg: A Production-Grade Syslog Server/Relay in Rust

**Version:** 1.0.0-draft
**Date:** 2026-03-11
**Status:** Draft
**Prerequisite:** [Phase 01 — Requirements and Scope](phase-01-requirements.md)

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Component Diagram](#2-component-diagram)
3. [Data Flow](#3-data-flow)
4. [Trust Boundaries](#4-trust-boundaries)
5. [Concurrency Model](#5-concurrency-model)
6. [Performance-Critical Paths](#6-performance-critical-paths)
7. [Failure Domains](#7-failure-domains)
8. [Internal Message Representation](#8-internal-message-representation)
9. [Recommended Implementation Phases](#9-recommended-implementation-phases)

---

## 1. Architecture Overview

syslog-usg is structured as a multi-stage relay pipeline running on the Tokio async runtime. The system decomposes into five major subsystems:

**Ingress** receives syslog messages from the network via UDP and TLS listeners. Each transport has its own acceptance strategy (datagram-per-message for UDP, connection-per-task for TLS) but all converge onto a shared internal message representation.

**Pipeline** is the processing core. It receives parsed messages from ingress, applies filter rules, evaluates routing decisions, and dispatches messages to one or more output queues. The pipeline is a directed acyclic graph of processing stages connected by bounded async channels.

**Egress** drains per-output queues and delivers messages to downstream destinations over TLS, UDP, file, or stdout. Each output runs as an independent task with its own retry logic, connection management, and backpressure signaling.

**Control Plane** manages configuration loading, graceful lifecycle (startup, shutdown, reload), signal handling, and the admin HTTP server (health, readiness, liveness, and Prometheus metrics endpoints).

**Observability** is a cross-cutting concern. Atomic counters and histograms are updated inline on the hot path. A dedicated HTTP server exposes metrics on demand. The system's own operational logs are emitted as structured JSON via `tracing`.

The workspace crate boundaries enforce these subsystem separations:

| Crate | Subsystem | Responsibility |
|-------|-----------|----------------|
| `syslog-proto` | Core | RFC 5424 types, internal message representation |
| `syslog-parse` | Pipeline | Parser and serializer for RFC 5424 and RFC 3164 |
| `syslog-transport` | Ingress / Egress | UDP, TLS listeners and senders |
| `syslog-relay` | Pipeline | Filter, route, enrich stages and fan-out |
| `syslog-config` | Control Plane | TOML loading, validation, env var substitution |
| `syslog-observe` | Observability | Metrics registry, health endpoints |
| `syslog-server` | Binary | Entrypoint, lifecycle orchestration, signal handling |

---

## 2. Component Diagram

```
                          +--------------------------+
                          |     Signal Handler       |
                          |  (SIGTERM/SIGINT/SIGHUP) |
                          +------------+-------------+
                                       |
                                       v
+------------------+          +--------+---------+          +------------------+
|  Config Loader   |--------->|   Lifecycle      |<-------->|  Admin HTTP      |
|  (TOML + env)    |          |   Manager        |          |  Server          |
+------------------+          +--------+---------+          +--+----+----+-----+
                                       |                       |    |    |
                       +---------------+---------------+       |    |    |
                       |                               |    /health |  /metrics
                       v                               v       |  /ready |
         +-------------+--------+     +--------+------+--+     |  /live  |
         |     UDP Listener(s)  |     |   TLS Listener(s) |    +----+----+
         |  (port 514, v4/v6)   |     |  (port 6514)      |         |
         |  +----------------+  |     |  +--------------+  |         |
         |  | recv_buf pool  |  |     |  | TLS Acceptor |  |    +----+--------+
         |  +-------+--------+  |     |  | (rustls)     |  |    |  Metrics    |
         +----------|----------+     |  +------+-------+  |    |  Collector  |
                    |                 |         |          |    |  (atomics)  |
                    |                 |  +------+-------+  |    +-------------+
                    |                 |  | Conn Manager |  |
                    |                 |  | (per-conn    |  |
                    |                 |  |  task spawn) |  |
                    |                 |  +------+-------+  |
                    |                 +---------|----------+
                    |                           |
                    v                           v
              +-----+---------------------------+------+
              |            Parser Stage                |
              |  (RFC 5424 / RFC 3164 auto-detect)     |
              |  Zero-copy where possible              |
              +-------------------+--------------------+
                                  |
                          bounded channel
                                  |
                                  v
              +-------------------+--------------------+
              |           Filter Stage                 |
              |  (facility, severity, hostname,        |
              |   app-name, SD-ID match rules)         |
              +-------------------+--------------------+
                                  |
                                  v
              +-------------------+--------------------+
              |           Route Stage                  |
              |  (evaluate routing table, fan-out      |
              |   to matching output queues)           |
              +---+---------------+----------------+---+
                  |               |                |
          bounded queue    bounded queue    bounded queue
                  |               |                |
                  v               v                v
          +-------+---+   +------+----+   +-------+---+
          | TLS Sender |   | UDP Sender|   | File/     |
          | (RFC 5425) |   | (RFC 5426)|   | Stdout    |
          | - conn pool|   |           |   | Writer    |
          | - batching |   |           |   |           |
          +------------+   +-----------+   +-----------+
```

### Component Responsibilities

**UDP Listener(s):** Bind to configured UDP sockets. Receive datagrams, one syslog message per datagram (RFC 5426). Apply receive-buffer tuning (`SO_RCVBUF`). On Linux, future optimization path via `recvmmsg` / `io_uring` for batch receive.

**TLS Listener(s) / Acceptor:** Bind to configured TCP sockets. Accept connections, perform TLS handshake via rustls. Enforce mutual authentication, cipher suite policy (RFC 9662), and 0-RTT prohibition. Hand off established connections to the Connection Manager.

**Connection Manager:** Spawns one Tokio task per accepted TLS connection. Manages octet-counting frame decoding (RFC 5425). Enforces per-connection read timeouts. Tracks active connections for graceful shutdown draining.

**Parser (RFC 5424/3164):** Auto-detects message format by inspecting the version field after PRI. Parses into the internal `SyslogMessage` representation. Operates in strict or lenient mode per configuration. Updates parse metrics (count, errors, latency histogram).

**Filter Stage:** Evaluates configured include/exclude rules against parsed message fields. Rules are evaluated in order; first match wins. Filtered messages are counted in `messages_dropped_total{reason="filtered"}`.

**Route Stage:** Evaluates the routing table to determine which output(s) a message should be delivered to. Supports fan-out (one message to multiple outputs). Clones the message `Arc` for each target output queue.

**Per-Output Bounded Queues:** Each output destination has its own bounded async queue (bounded by both message count and aggregate byte size). The queue enforces the configured backpressure policy (`drop-oldest`, `drop-newest`, or `block`). Overflow events increment `messages_dropped_total{reason="queue_full"}`.

**Output Senders:** Each output has a dedicated sender task that drains its queue. TLS senders maintain a connection pool to downstream servers, batch writes, and handle reconnection with exponential backoff. UDP senders transmit one message per datagram. File writers handle rotation. Stdout writers serialize to JSON lines.

**Config Loader:** Reads TOML configuration from disk, applies `${VAR}` and `${VAR:-default}` environment variable substitution, validates the schema, and produces a typed configuration struct. Supports a `validate-config` subcommand that exits after validation.

**Metrics Collector:** A registry of atomic counters, gauges, and histograms. Updated inline on the hot path (no locks, no channel sends). Rendered to Prometheus exposition format on demand when the admin HTTP server handles a `/metrics` request.

**Admin HTTP Server:** A lightweight HTTP server (using `hyper` or `axum`) serving `/health`, `/ready`, `/live`, and `/metrics` endpoints. Runs on a separate port from syslog traffic.

**Signal Handler / Lifecycle Manager:** Listens for OS signals. `SIGTERM`/`SIGINT` trigger graceful shutdown: stop accepting new connections, close listeners, drain queues with a configurable timeout, then exit. `SIGHUP` triggers configuration reload.

---

## 3. Data Flow

This section traces a single syslog message from network arrival to output delivery.

### 3.1 UDP Path

```
Network → kernel recv buffer → UDP socket read → stack-allocated staging buffer
→ parse (borrow from staging buffer) → allocate SyslogMessage (owned)
→ send into pipeline channel → filter → route → clone Arc per output
→ enqueue in output queue → dequeue by sender → serialize to wire format
→ transmit via TLS/UDP/file
```

**Step-by-step:**

1. **Socket Read.** The UDP listener task calls `recv_from` on the bound `UdpSocket`. The datagram lands in a stack-allocated (or reusable) buffer of `max_message_size` bytes (configurable, default 8192). Ownership: the buffer is owned by the listener task and reused across receives.

2. **Parse.** The parser borrows the buffer slice `&[u8]` and produces a `ParsedMessage<'_>` with borrowed references into the buffer for string fields (hostname, app-name, message body). This is the zero-copy stage. If parsing succeeds, the borrowed fields are copied into an owned `SyslogMessage` (allocated once). If parsing fails, the raw bytes are wrapped in a `SyslogMessage` with parse-error metadata for drop logging.

3. **Receive Metadata.** Before sending into the pipeline, the listener stamps the `SyslogMessage` with receive metadata: kernel receive timestamp (via `SO_TIMESTAMP` if available, otherwise `Instant::now()`), source socket address, listener ID, and an internally generated trace ID (`u64`, monotonically increasing atomic).

4. **Channel Send.** The `SyslogMessage` is wrapped in `Arc<SyslogMessage>` and sent into a bounded `tokio::sync::mpsc` channel connecting ingress to the pipeline. If the channel is full, backpressure behavior depends on configuration: the listener may drop the message (incrementing the drop counter) or yield until space is available.

5. **Filter.** The pipeline filter task receives from the channel, evaluates the message against filter rules, and either passes it through or drops it (with metric increment).

6. **Route.** The router evaluates the routing table. For each matching output, it clones the `Arc<SyslogMessage>` (cheap reference count increment) and sends it into the corresponding output queue.

7. **Queue.** The message `Arc` sits in the per-output bounded queue until the sender task dequeues it.

8. **Serialize and Send.** The sender task dequeues the message. For TLS output, it serializes the message to RFC 5424 wire format with octet-counting framing and writes to the TLS stream. For UDP output, it serializes and sends a single datagram. For file/stdout, it serializes to the configured format (RFC 5424 text or JSON). Serialization can use the raw bytes from `SyslogMessage.raw` if the message is being forwarded without modification (passthrough optimization).

### 3.2 TLS Path

```
Network → kernel TCP buffer → TLS decrypt (rustls) → octet-counting frame decode
→ parse → same pipeline as UDP from step 3 onward
```

The TLS path differs only in steps 1-2:

1. **Connection Accept.** The TLS listener accepts a TCP connection and performs the TLS handshake (rustls). On success, the Connection Manager spawns a dedicated Tokio task for this connection.

2. **Frame Decode.** The per-connection task reads from the `TlsStream`, applying octet-counting framing (RFC 5425): read the `MSG-LEN` decimal digits, read the space separator, then read exactly `MSG-LEN` bytes as the syslog message. Each decoded frame yields a byte buffer that is passed to the parser. The buffer is allocated per-frame (or drawn from a pool for high-throughput connections).

3. **Parse onward.** Identical to UDP path from step 2 onward.

### 3.3 Buffer Ownership Summary

| Stage | Buffer Type | Ownership | Lifetime |
|-------|------------|-----------|----------|
| UDP recv | `[u8; MAX_MSG_SIZE]` on stack or reusable `Vec` | Listener task | One recv cycle |
| TLS frame | `Vec<u8>` per frame (or pooled) | Connection task | Until parse completes |
| Parse (zero-copy) | `ParsedMessage<'buf>` borrowing recv buffer | Parser | Transient; fields copied to owned |
| Owned message | `SyslogMessage` (owned `String`/`Bytes` fields) | `Arc` wrapper | Until last `Arc` clone dropped |
| Pipeline channel | `Arc<SyslogMessage>` | Channel | Until receiver takes |
| Output queue | `Arc<SyslogMessage>` | Queue | Until sender dequeues |
| Serialization | Temporary write buffer per sender | Sender task | One write cycle |

---

## 4. Trust Boundaries

```
+================================================================+
|                    UNTRUSTED NETWORK                            |
|  (arbitrary UDP datagrams, TCP connections, TLS clients)       |
+======+========================+================================+
       |                        |
       | UDP (port 514)         | TCP (port 6514)
       |                        |
- - - -|- - - - TRUST BOUNDARY 1: Network Input - - - - - - - - -
       |                        |
       v                        v
  +---------+            +-------------+
  | UDP     |            | TLS         |
  | Recv    |            | Termination |--- TRUST BOUNDARY 2:
  +---------+            +-------------+    TLS handshake +
       |                        |           certificate validation
       |                        |
- - - -|- - - TRUST BOUNDARY 3: Input Validation (Parser) - - - -
       |                        |
       v                        v
  +-----------------------------------------+
  |         Validated Message Pipeline       |
  |  (filter, route, enqueue)               |
  +-----------------------------------------+
       |
- - - -|- - - TRUST BOUNDARY 4: Output Serialization - - - - - -
       |
       v
  +-------------------+
  | Output Senders    |--- outbound TLS: trust boundary with
  +-------------------+    downstream receivers
```

### Trust Boundary 1: Network Input

All bytes arriving on UDP port 514 and TCP port 6514 are untrusted. Threats include:

- **Oversized messages** designed to exhaust memory. Mitigation: hard `max_message_size` limit enforced at the recv/frame-decode layer. Bytes beyond the limit are discarded and counted.
- **Malformed UTF-8** and binary payloads. Mitigation: parser treats input as `&[u8]`, validates UTF-8 only where the RFC requires it, and uses lossy conversion otherwise.
- **Connection floods** (TCP/TLS). Mitigation: configurable `max_connections` limit per listener. Excess connections receive TCP RST.
- **UDP source spoofing.** Mitigation: UDP is inherently spoofable; the system does not authenticate UDP sources. Rate limiting per source IP mitigates amplification.

### Trust Boundary 2: TLS Termination

TLS handshake and certificate validation occur here. After this boundary, the identity of the remote peer is established (for mutual TLS). Key enforcement:

- **Cipher suites:** Only RFC 9662-compliant suites are offered. Weak/legacy suites are disabled unless explicitly configured.
- **0-RTT prohibition:** TLS 1.3 early data is disabled (RFC 9662 requirement). rustls is configured with `max_early_data_size = 0`.
- **Certificate validation:** Full PKIX path validation or fingerprint pinning, per configuration. Failed handshakes are logged with peer address and error type, counted in `tls_handshake_errors_total`.
- **Client authentication metadata** (CN, SAN, certificate fingerprint) is attached to the connection context and available to downstream pipeline stages for per-source routing or access control.

### Trust Boundary 3: Input Validation (Parser)

The parser is the primary defense against malformed input. Every field is validated against the RFC 5424 ABNF or the lenient RFC 3164 heuristics. Specific hardening:

- **PRI bounds:** Facility 0-23, severity 0-7. Out-of-range values are rejected (strict) or clamped (lenient).
- **Field length limits:** HOSTNAME <= 255, APP-NAME <= 48, PROCID <= 128, MSGID <= 32 (RFC 5424 Section 6). Violations are rejected or truncated.
- **Structured data depth:** Maximum SD-ELEMENT count and SD-PARAM count per element are configurable to prevent CPU exhaustion on deeply nested inputs.
- **Timestamp validation:** RFC 3339 format with bounds checking on date/time components.
- **No panics:** The parser returns `Result<ParsedMessage, ParseError>` for all inputs. Fuzz testing ensures no panicking paths exist.

### Trust Boundary 4: Output Serialization

Messages leaving the system must be correctly framed to avoid injection attacks on downstream systems:

- **Octet-counting framing** (RFC 5425) prevents message injection in the TLS output stream. The `MSG-LEN` is computed from the actual serialized bytes, not from any untrusted field.
- **Outbound TLS** establishes a separate trust relationship with the downstream receiver. Certificate validation is applied to outbound connections per configuration.

### Privileged Operations

- **Port binding:** UDP 514 and TCP 6514 require `CAP_NET_BIND_SERVICE` or root on Linux. After binding, the process drops privileges to the configured unprivileged user/group.
- **File permissions:** TLS private keys should be mode 0600. The config loader warns if key files are world-readable.
- **PID file:** Written to a configured path, requires write permission to that directory.

---

## 5. Concurrency Model

syslog-usg runs on the Tokio multi-threaded runtime with work-stealing. The default thread count equals the number of available CPU cores (configurable via `TOKIO_WORKER_THREADS`). All I/O is non-blocking async.

### 5.1 Task Topology

```
Tokio Runtime (N worker threads, work-stealing)
|
+-- [1] Signal Handler Task
|     Listens for SIGTERM, SIGINT, SIGHUP.
|     Sends shutdown/reload commands to Lifecycle Manager via oneshot channels.
|
+-- [1] Lifecycle Manager Task
|     Owns the CancellationToken tree.
|     Coordinates startup, shutdown, and reload sequences.
|
+-- [1 per UDP listener] UDP Listener Task
|     Loop: recv_from → parse → channel_send.
|     CPU-bound parsing is done inline (not spawned); parsing is < 10us and
|     does not warrant a spawn overhead.
|     On Linux, future: batch recv via recvmmsg using spawn_blocking or io_uring.
|
+-- [1] TLS Acceptor Task (per TLS listener)
|     Loop: accept → TLS handshake → spawn connection task.
|     Handshake is done in the acceptor task (amortized cost).
|     Alternatively, handshake can be moved to the spawned connection task
|     to avoid head-of-line blocking on slow handshakes.
|
+-- [1 per TLS connection] TLS Connection Task
|     Loop: read_frame → parse → channel_send.
|     Task is dropped on connection close or shutdown signal.
|     Tracked in a JoinSet for graceful drain.
|
+-- [1] Pipeline Dispatcher Task
|     Receives from the ingress channel.
|     Runs filter and route logic inline.
|     Sends to per-output queue channels.
|     This is the fan-out point.
|     NOTE: If routing logic becomes CPU-heavy, this can be sharded into
|     N dispatcher tasks reading from the same ingress channel.
|
+-- [1 per output] Output Sender Task
|     Loop: dequeue → serialize → send.
|     Manages its own connection(s) to the downstream destination.
|     Handles reconnection, backoff, and batching.
|
+-- [1] Admin HTTP Server Task
|     Runs an axum/hyper server on the admin port.
|     Handles /health, /ready, /live, /metrics.
|     Metrics rendering reads atomic counters; no lock contention.
|
+-- [0] Metrics Collection Task (not needed as a separate task)
      Metrics are updated inline via atomic operations.
      Rendering is on-demand in the HTTP handler.
```

### 5.2 Channel Topology

```
UDP Listener 1 --\
UDP Listener 2 ---+--> [ingress_tx] ==bounded mpsc==> [ingress_rx] --> Pipeline
TLS Conn 1 ------/                                                    Dispatcher
TLS Conn 2 -----/                                                        |
TLS Conn N ---/                                                     fan-out
                                                               /      |       \
                                                [out_q_1]  [out_q_2]  [out_q_3]
                                                    |          |          |
                                              Sender 1    Sender 2    Sender 3
```

**Ingress channel:** A single bounded `tokio::sync::mpsc` channel (capacity configurable, default 10,000 messages). Multiple producers (listener and connection tasks) send into `ingress_tx`. A single consumer (pipeline dispatcher) reads from `ingress_rx`. The `mpsc` channel is chosen over `broadcast` because the dispatcher is the sole consumer.

**Output queues:** Each output has a dedicated bounded `tokio::sync::mpsc` channel. The pipeline dispatcher clones the `Arc<SyslogMessage>` and sends to each matching output's channel. If a queue is full, the dispatcher applies the configured backpressure policy inline.

### 5.3 Cancellation

Graceful shutdown is coordinated via `tokio_util::sync::CancellationToken`:

```
root_token
  +-- ingress_token (listeners and connections)
  +-- pipeline_token (dispatcher)
  +-- egress_token (output senders)
  +-- admin_token (HTTP server)
```

Shutdown sequence:
1. Signal handler receives SIGTERM. Signals the lifecycle manager.
2. Lifecycle manager cancels `ingress_token`. Listeners stop accepting; connection tasks begin draining.
3. After ingress tasks complete, cancel `pipeline_token`. Dispatcher drains its channel.
4. After pipeline drains, cancel `egress_token`. Senders drain their queues.
5. After egress tasks complete (or drain timeout expires), cancel `admin_token`.
6. Process exits.

### 5.4 Thread and CPU Affinity

The Tokio multi-threaded runtime's work-stealing scheduler distributes tasks across worker threads automatically. No manual CPU pinning is done at MVP. For extreme performance tuning (post-MVP), the following knobs are available:

- **`SO_REUSEPORT` with multiple UDP sockets:** Spawn N UDP listener tasks, each bound to the same port with `SO_REUSEPORT`. The kernel distributes datagrams across sockets. This parallelizes the recv-parse hot path.
- **Dedicated current-thread runtime** for the admin HTTP server, isolating metrics rendering from the data plane.

---

## 6. Performance-Critical Paths

### 6.1 Hot Path: UDP Recv -> Parse -> Channel Send

This is the highest-throughput path and must sustain 100k msg/sec.

**Design decisions:**

- **Reusable recv buffer.** A single `[u8; 8192]` buffer is stack-allocated in the listener task loop and reused across iterations. No heap allocation per recv.
- **Inline parsing.** The parser is invoked synchronously in the listener task. Spawning a separate task per message would add ~1-2us of overhead per message (Tokio spawn + wake), which is comparable to the parse time itself. Inline parsing avoids this.
- **Owned message allocation.** After zero-copy parsing, an owned `SyslogMessage` is allocated. This is one allocation per message (unavoidable, since the recv buffer must be reused). Field strings are stored as `CompactString` or `Bytes` to minimize small-string allocations.
- **`Arc` wrapping.** The owned message is wrapped in `Arc` before channel send. This enables zero-copy fan-out in the routing stage (clone the `Arc`, not the message).
- **Channel send.** `tokio::sync::mpsc::Sender::send` is the channel boundary. The bounded channel applies backpressure when full.

**Allocation budget per message (target):**
- 1x `SyslogMessage` struct (~256 bytes inline + variable-length fields)
- 1x `Arc` header (16 bytes)
- Total: ~300-500 bytes per message depending on field sizes

**Metrics on hot path:**
- All metrics are `AtomicU64` counters incremented with `Relaxed` ordering. No `Mutex`, no channel send, no allocation.
- Histogram updates (parse latency) use a lock-free bucket array or are sampled (e.g., every 100th message) to avoid overhead.

### 6.2 Hot Path: Queue Drain -> TLS Write

This path must sustain 50k msg/sec per output.

**Design decisions:**

- **Batch dequeue.** The sender task dequeues up to N messages (configurable, default 64) per iteration using `recv_many` or a drain loop. This amortizes the channel receive overhead.
- **Vectored writes.** For TLS output, multiple messages are serialized into a contiguous write buffer and written in a single `write_all` call. This reduces TLS record overhead and syscall count.
- **Passthrough optimization.** If a message was received and is being forwarded without modification (no enrichment, no field changes), the sender uses `SyslogMessage.raw` bytes directly, skipping re-serialization entirely.
- **Connection pooling.** For TLS outputs with multiple downstream servers, a pool of persistent connections is maintained. Connections are reused across write batches.
- **Write buffer reuse.** The sender task maintains a reusable `Vec<u8>` write buffer that is cleared (not deallocated) between batches.

### 6.3 Metrics Update Path

- **Counter increments:** `AtomicU64::fetch_add(1, Relaxed)`. Single instruction on x86. No contention unless multiple cores increment the same counter simultaneously (which is expected; `Relaxed` ordering is sufficient since exact count is not required at any instant).
- **Gauge updates (queue depth):** Updated by the sender task on dequeue and the dispatcher on enqueue. Two separate atomics: `enqueued_total` and `dequeued_total`. Current depth = `enqueued - dequeued` (computed at render time).
- **Histogram (parse latency):** Use a fixed-bucket histogram (e.g., [0.5us, 1us, 2us, 5us, 10us, 25us, 50us, 100us]) with atomic bucket counters. Or sample: only measure every Nth message to reduce `Instant::now()` calls.

### 6.4 Allocation-Free Zones

The following operations MUST NOT allocate on the heap in steady state:

| Operation | Strategy |
|-----------|----------|
| UDP recv | Stack buffer or pre-allocated `Vec` |
| Metric increment | Atomic |
| Channel send (when not full) | Moves existing `Arc` pointer |
| Queue backpressure drop | Drop `Arc`, decrement refcount |
| Passthrough serialization | Borrow `raw` bytes, no new allocation |

---

## 7. Failure Domains

### 7.1 Downstream Output Unreachable

**Scope:** Single output sender task.

**Behavior:**
1. The sender task detects a connection failure (TLS write error, connection refused, timeout).
2. The sender enters a reconnection loop with exponential backoff (initial 100ms, max 30s, jitter).
3. While disconnected, the per-output queue continues to accept messages from the pipeline dispatcher up to its capacity limit.
4. If the queue fills, the configured backpressure policy applies:
   - `drop-newest`: New messages for this output are silently dropped (counted in metrics).
   - `drop-oldest`: The oldest message in the queue is evicted to make room (counted in metrics).
   - `block`: The pipeline dispatcher blocks on this queue's send, which propagates backpressure to all outputs (NOT recommended in most configurations; use only for critical outputs).
5. On reconnection, the sender resumes draining the queue. No messages are retransmitted; the queue provides the buffering.

**Isolation:** One output's failure does NOT affect other outputs (unless `block` policy is used). The pipeline dispatcher sends to each output queue independently.

### 7.2 Queue Full

**Scope:** Single output queue.

**Behavior:** See backpressure policies above. Additional detail:
- `drop-oldest` requires a data structure that supports efficient eviction from the front. Use a `VecDeque`-backed bounded buffer behind a `Mutex` (taken only briefly) or a custom lock-free ring buffer. Alternative: use `tokio::sync::mpsc` with `try_send`; on `Full`, the dispatcher applies the drop policy by receiving from the queue's consumer end (requires careful synchronization) or simply drops the incoming message (`drop-newest`).
- For MVP, `drop-newest` (the dispatcher calls `try_send` and drops on failure) is the simplest and lowest-risk implementation.
- Queue depth metrics are updated atomically. A separate `queue_overflow_total` counter tracks drops per queue.

### 7.3 Malformed Input

**Scope:** Single message.

**Behavior:**
1. The parser returns `Err(ParseError)` with a descriptive error variant (e.g., `InvalidPri`, `InvalidTimestamp`, `OversizedField`, `InvalidUtf8`).
2. In strict mode: the message is discarded. `parse_errors_total{error_type="..."}` is incremented.
3. In lenient mode: a `SyslogMessage` is constructed with as many fields as could be parsed. Unparseable fields are set to `None` or default values. A `parse_warnings` annotation is attached. The message continues through the pipeline.
4. In both modes, the raw bytes are preserved in the `SyslogMessage` for potential debugging output or drop logging.

**No cascading failure:** A parse error affects exactly one message. The listener task continues processing the next datagram/frame.

### 7.4 TLS Handshake Failure

**Scope:** Single incoming connection.

**Behavior:**
1. The TLS acceptor detects the handshake failure (e.g., certificate validation failure, unsupported cipher, protocol version mismatch).
2. `tls_handshake_errors_total{error_type="..."}` is incremented.
3. The TCP connection is closed. No connection task is spawned.
4. A structured log entry is emitted at WARN level with: peer address, error description, and certificate subject (if available).

**No cascading failure:** The acceptor task continues accepting new connections. A flood of failing handshakes may consume CPU; the `max_connections` limit and connection rate limiting mitigate this.

### 7.5 Configuration Reload Error

**Scope:** Control plane.

**Behavior (on SIGHUP reload):**
1. The config loader reads and parses the new configuration file.
2. Schema validation is applied.
3. If validation fails: a structured error log is emitted with the specific validation errors. The current running configuration is unchanged. No pipeline disruption.
4. If validation succeeds: the lifecycle manager applies the new configuration. New listeners are started, removed listeners are drained, filter/route rules are swapped atomically (via `Arc::swap` or similar), and output configurations are updated.
5. Existing TLS connections are NOT dropped on reload. They continue under the previous TLS settings until they close naturally. New connections use the new settings.

### 7.6 SIGTERM Received

**Scope:** Entire process.

**Behavior (graceful shutdown):**
1. Signal handler notifies the lifecycle manager.
2. Lifecycle manager cancels the ingress token:
   - UDP listeners stop receiving.
   - TLS acceptor stops accepting new connections.
   - Existing TLS connection tasks are notified to finish their current message and close.
3. Lifecycle manager waits for ingress tasks to complete (with timeout).
4. Pipeline dispatcher drains its input channel to completion, forwarding all remaining messages to output queues.
5. Output senders drain their queues (with configurable drain timeout, default 5 seconds).
6. After drain completes or timeout expires, all remaining messages are counted as `messages_dropped_total{reason="shutdown"}`.
7. Admin HTTP server is shut down.
8. Process exits with code 0.

### 7.7 Panic in a Task

**Scope:** Single Tokio task.

**Behavior:**
- All task spawns use `JoinSet` or `tokio::spawn` with the `JoinHandle` monitored by the lifecycle manager.
- If a task panics, the `JoinHandle` returns `Err(JoinError)`.
- The lifecycle manager logs the panic at ERROR level with the task identity.
- For listener and sender tasks: the lifecycle manager attempts to respawn the task.
- For connection tasks: the connection is lost; the client will reconnect.
- The process does NOT crash. `#[cfg(panic = "abort")]` is NOT used; panics are caught at task boundaries by the Tokio runtime.
- `std::panic::set_hook` installs a custom panic handler that logs structured JSON before the default behavior.

---

## 8. Internal Message Representation

The `SyslogMessage` struct is the currency of the pipeline. It flows from ingress through filter, route, queue, and output stages.

### 8.1 Design Principles

- **Owned fields.** After parsing, all fields are owned (not borrowed). This allows the message to outlive the receive buffer and cross task/channel boundaries without lifetime complexity.
- **`Arc`-wrapped for fan-out.** Messages are wrapped in `Arc<SyslogMessage>` before entering the pipeline. Routing to multiple outputs clones the `Arc` (refcount increment), not the message data.
- **Raw bytes preserved.** The original wire-format bytes are kept alongside parsed fields. This enables passthrough forwarding without re-serialization and debugging/drop-logging of malformed messages.
- **Compact representation.** Use `CompactString` (from the `compact_str` crate) for short string fields to avoid heap allocation for strings under 24 bytes. Use `Bytes` (from the `bytes` crate) for the raw message and MSG body to enable zero-copy slicing.

### 8.2 Struct Definition (Conceptual)

```rust
/// The internal representation of a syslog message flowing through the pipeline.
/// All fields are owned. Wrapped in Arc<SyslogMessage> for zero-copy fan-out.
pub struct SyslogMessage {
    // ── Receive metadata ──────────────────────────────────────────
    /// Monotonically increasing internal trace ID for pipeline correlation.
    /// Generated by the ingress task via AtomicU64::fetch_add.
    pub trace_id: u64,

    /// Timestamp when the message was received by the listener.
    /// Uses std::time::SystemTime for wall-clock time.
    pub received_at: SystemTime,

    /// Source address of the sender (IP:port for UDP, peer addr for TLS).
    pub source_addr: SocketAddr,

    /// Identifier of the listener that received this message.
    /// Corresponds to the listener name in the configuration.
    pub listener_id: CompactString,

    /// Transport protocol used for ingestion.
    pub transport: Transport,

    /// TLS peer identity, if applicable (certificate subject CN or SAN).
    pub peer_identity: Option<CompactString>,

    // ── Raw bytes ─────────────────────────────────────────────────
    /// The original wire-format bytes of the message, exactly as received.
    /// Used for passthrough forwarding and drop logging.
    pub raw: Bytes,

    // ── Parsed RFC 5424 fields ────────────────────────────────────
    /// Facility (0-23). Extracted from PRI.
    pub facility: Facility,

    /// Severity (0-7). Extracted from PRI.
    pub severity: Severity,

    /// RFC 5424 version (always 1 for RFC 5424; None for RFC 3164 legacy).
    pub version: Option<u8>,

    /// Message timestamp from the HEADER.
    /// None if NILVALUE ("-") in RFC 5424 or unparseable in RFC 3164.
    pub timestamp: Option<SyslogTimestamp>,

    /// Hostname from the HEADER.
    pub hostname: Option<CompactString>,

    /// Application name from the HEADER.
    pub app_name: Option<CompactString>,

    /// Process ID from the HEADER.
    pub proc_id: Option<CompactString>,

    /// Message ID from the HEADER.
    pub msg_id: Option<CompactString>,

    /// Structured data elements.
    /// Empty vec if NILVALUE or RFC 3164 legacy.
    pub structured_data: Vec<SdElement>,

    /// Message body (the MSG part after STRUCTURED-DATA).
    /// Stored as Bytes for zero-copy slicing from raw.
    pub message: Option<Bytes>,

    // ── Parse metadata ────────────────────────────────────────────
    /// Which format was detected (RFC 5424 or RFC 3164 legacy).
    pub format: MessageFormat,

    /// Parse warnings (lenient mode only). Empty in strict mode.
    pub parse_warnings: Vec<ParseWarning>,
}

/// RFC 5424 structured data element.
pub struct SdElement {
    /// SD-ID: either IANA-registered name or "name@enterprise-number".
    pub id: CompactString,

    /// SD-PARAMs: key-value pairs within this element.
    /// SmallVec avoids heap allocation for elements with few params (common case).
    pub params: SmallVec<[(CompactString, String); 4]>,
}

/// High-precision timestamp preserving the original RFC 5424 representation.
pub struct SyslogTimestamp {
    /// Parsed timestamp as a chrono DateTime or equivalent.
    /// Preserves nanosecond precision and timezone offset.
    pub datetime: DateTime<FixedOffset>,
}

/// Transport protocol enum.
pub enum Transport {
    Udp,
    Tcp,
    Tls,
}

/// Detected message format.
pub enum MessageFormat {
    Rfc5424,
    Rfc3164Legacy,
}

/// Facility codes (RFC 5424 Section 6.2.1).
/// Represented as a newtype around u8 with named constants.
pub struct Facility(u8);

/// Severity levels (RFC 5424 Section 6.2.1).
/// Represented as a newtype around u8 with named constants.
pub struct Severity(u8);
```

### 8.3 Size Budget

Target: each `SyslogMessage` should fit within a single cache line pair (128 bytes) for the fixed-size header fields, with variable-length data (structured data, message body) behind pointers. Approximate layout:

| Field(s) | Size (bytes) |
|-----------|-------------|
| `trace_id` | 8 |
| `received_at` | 16 |
| `source_addr` | 28 (v6) |
| `listener_id` | 24 (CompactString inline) |
| `transport` | 1 + padding |
| `peer_identity` | 24 (Option<CompactString>) |
| `raw` | 32 (Bytes: ptr + len + Arc) |
| `facility` + `severity` | 2 |
| `version` | 2 (Option<u8>) |
| `timestamp` | 16 (Option<DateTime>) |
| `hostname` .. `msg_id` | 4 x 24 = 96 (Option<CompactString>) |
| `structured_data` | 24 (Vec header) |
| `message` | 32 (Option<Bytes>) |
| `format` | 1 |
| `parse_warnings` | 24 (Vec header) |
| **Total (approx)** | **~330 bytes** |

With `Arc` overhead (16 bytes): ~346 bytes per message in the pipeline. Under the 256 MB budget, this allows ~740k messages in flight simultaneously, well above the 10k-message queue depth target.

---

## 9. Recommended Implementation Phases

### Phase A: Core Types + Parser

**Crates:** `syslog-proto`, `syslog-parse`

**Deliverables:**
1. `SyslogMessage`, `SdElement`, `SyslogTimestamp`, `Facility`, `Severity`, `Transport`, `MessageFormat` types in `syslog-proto`.
2. RFC 5424 parser: `parse_rfc5424(input: &[u8]) -> Result<ParsedMessage<'_>, ParseError>`.
3. RFC 3164 legacy parser: `parse_rfc3164(input: &[u8]) -> Result<ParsedMessage<'_>, ParseError>`.
4. Auto-detection function: `parse_syslog(input: &[u8]) -> Result<ParsedMessage<'_>, ParseError>`.
5. Conversion from `ParsedMessage<'_>` (borrowed) to `SyslogMessage` (owned).
6. RFC 5424 serializer: `serialize_rfc5424(msg: &SyslogMessage) -> Vec<u8>`.
7. Unit tests: valid and invalid RFC 5424 messages, RFC 3164 legacy messages, edge cases (NILVALUE, BOM, max-length fields, empty structured data, deeply nested SD-ELEMENTs).
8. Criterion benchmarks: parse latency for typical and worst-case messages.
9. Fuzz harness: `cargo-fuzz` target for the parser.

**Exit criteria:** Parser passes all unit tests, p99 parse latency < 10us on benchmark, fuzz harness runs for 1 hour without panics.

### Phase B: UDP Listener + Basic Pipeline

**Crates:** `syslog-transport` (UDP listener), `syslog-relay` (minimal pipeline), `syslog-server` (binary skeleton)

**Deliverables:**
1. UDP listener: bind, recv, parse, wrap in `Arc<SyslogMessage>`, send to ingress channel.
2. Minimal pipeline dispatcher: receive from ingress channel, forward to a single output queue (no filter/route logic yet).
3. Stdout output sender: dequeue, serialize to RFC 5424 text, write to stdout.
4. Binary entrypoint: hard-coded configuration (no TOML yet), start listener + pipeline + stdout output.
5. Integration test: send UDP datagrams to the listener, verify they appear on stdout.
6. Basic `CancellationToken` wiring for Ctrl+C shutdown.

**Exit criteria:** End-to-end UDP-in to stdout-out works. 100k msg/sec sustained on a benchmark host with the stdout output replaced by a `/dev/null` sink.

### Phase C: TLS Listener and Sender

**Crates:** `syslog-transport` (TLS listener, TLS sender)

**Deliverables:**
1. TLS listener: TCP accept, rustls handshake, octet-counting frame decode, parse, send to ingress channel.
2. Connection manager: per-connection task spawning, `JoinSet` tracking, connection limit enforcement.
3. TLS sender output: connection establishment, octet-counting frame encoding, write batching.
4. rustls configuration: cipher suite enforcement (RFC 9662), mutual TLS, 0-RTT disabled, certificate validation.
5. Integration tests: TLS-in to TLS-out relay, mutual TLS authentication, handshake failure handling.
6. UDP sender output (for completeness).

**Exit criteria:** TLS-in to TLS-out relay works with mutual authentication. 50k msg/sec sustained with persistent TLS connections. Handshake failures are gracefully handled and logged.

### Phase D: Configuration + Filter/Route

**Crates:** `syslog-config`, `syslog-relay` (filter and route stages)

**Deliverables:**
1. TOML configuration schema: listeners, outputs, routes, filters, TLS settings, queue settings.
2. Config loader: file read, environment variable substitution, schema validation.
3. `validate-config` subcommand.
4. Filter stage: include/exclude rules by facility, severity, hostname, app-name, SD-ID.
5. Route stage: routing table evaluation, fan-out to multiple output queues.
6. Per-output bounded queues with configurable capacity and backpressure policy.
7. Example configuration file.
8. Integration tests: filter drops, route fan-out, backpressure behavior.

**Exit criteria:** Full relay pipeline works with TOML configuration. Messages are filtered and routed correctly per configuration. Backpressure policies function as designed.

### Phase E: Metrics + Health

**Crates:** `syslog-observe`

**Deliverables:**
1. Metrics registry: atomic counters and histograms for all metrics defined in the requirements (Section 3.1.8 of Phase 01).
2. Prometheus exposition format renderer.
3. Admin HTTP server (axum): `/metrics`, `/health`, `/ready`, `/live` endpoints.
4. Structured JSON operational logging via `tracing` + `tracing-subscriber` with JSON formatter.
5. Integration of metric updates into all pipeline stages (listener recv count, parse errors, queue depth, forward count, drop count, TLS handshake errors).
6. Integration tests: verify metric values after sending known message counts.

**Exit criteria:** All required metrics are exposed and accurate. Health endpoints return correct status. Operational logs are structured JSON.

### Phase F: Graceful Lifecycle

**Crates:** `syslog-server` (lifecycle manager), updates across all crates

**Deliverables:**
1. Full `CancellationToken` tree with ordered shutdown sequence.
2. SIGTERM/SIGINT handling with configurable drain timeout.
3. SIGHUP configuration reload (validate-then-swap).
4. Startup validation: bind-check listeners, validate TLS certs, test output connectivity.
5. PID file write/cleanup.
6. Connection draining: existing TLS connections finish current message before closing.
7. Panic handler: structured logging, task restart for critical tasks.
8. Integration tests: graceful shutdown under load (no message loss beyond queue capacity), config reload without connection drops, panic recovery.

**Exit criteria:** Process shuts down gracefully within the configured drain timeout. Config reload works without dropping existing connections. No unaccounted message loss (every message is forwarded, drop-logged, or counted in metrics).

---

## Appendix A: Key Crate Dependencies

| Dependency | Purpose | Crate(s) |
|------------|---------|----------|
| `tokio` | Async runtime, channels, timers, signals | All |
| `tokio-rustls` | Async TLS streams | `syslog-transport` |
| `rustls` | TLS implementation | `syslog-transport` |
| `rustls-pemfile` | PEM certificate/key loading | `syslog-transport` |
| `webpki-roots` or custom CA | Root certificate store | `syslog-transport` |
| `bytes` | Zero-copy byte buffers (`Bytes`) | `syslog-proto`, `syslog-parse` |
| `compact_str` | Inline small strings (avoids heap alloc) | `syslog-proto` |
| `smallvec` | Inline small vectors (SD-PARAMs) | `syslog-proto` |
| `chrono` | Timestamp parsing with timezone support | `syslog-parse` |
| `toml` | TOML deserialization | `syslog-config` |
| `serde` | Serialization framework | `syslog-config`, `syslog-proto` |
| `axum` or `hyper` | Admin HTTP server | `syslog-observe` |
| `tracing` + `tracing-subscriber` | Structured logging | All |
| `thiserror` | Error type derivation | All library crates |
| `anyhow` | Error handling in binary | `syslog-server` |
| `criterion` | Benchmarks | `benches/` |
| `cargo-fuzz` / `libfuzzer-sys` | Fuzz testing | `syslog-parse` |
| `tokio-util` | `CancellationToken`, codec utilities | `syslog-transport`, `syslog-server` |

## Appendix B: Configuration Schema Outline

```toml
# syslog-usg.toml — Example configuration structure

[server]
drain_timeout_seconds = 5
pid_file = "/var/run/syslog-usg.pid"

[admin]
listen = "127.0.0.1:9090"

[[listeners]]
name = "udp-default"
transport = "udp"
listen = "0.0.0.0:514"
max_message_size = 8192
recv_buffer_size = 4194304  # 4 MB SO_RCVBUF
parse_mode = "lenient"      # "strict" | "lenient"

[[listeners]]
name = "tls-default"
transport = "tls"
listen = "0.0.0.0:6514"
max_connections = 10000
parse_mode = "strict"

[listeners.tls]
cert = "${SYSLOG_TLS_CERT:-/etc/syslog-usg/server.crt}"
key = "${SYSLOG_TLS_KEY:-/etc/syslog-usg/server.key}"
ca = "/etc/syslog-usg/ca.crt"
mutual = true
min_version = "1.2"

[[outputs]]
name = "upstream-tls"
transport = "tls"
target = "collector.example.com:6514"
queue_capacity = 10000
queue_byte_limit = "64MB"
backpressure = "drop-newest"  # "drop-oldest" | "drop-newest" | "block"

[outputs.tls]
cert = "/etc/syslog-usg/client.crt"
key = "/etc/syslog-usg/client.key"
ca = "/etc/syslog-usg/upstream-ca.crt"

[[outputs]]
name = "local-file"
transport = "file"
path = "/var/log/syslog-usg/messages.log"
format = "rfc5424"            # "rfc5424" | "json"
queue_capacity = 5000
backpressure = "drop-oldest"

[[filters]]
name = "drop-debug"
action = "exclude"
severity = ["debug"]

[[routes]]
name = "default"
match_all = true
outputs = ["upstream-tls", "local-file"]

[[routes]]
name = "security-only"
facility = ["auth", "authpriv"]
severity = ["emerg", "alert", "crit", "err", "warning"]
outputs = ["upstream-tls"]

[logging]
level = "info"
format = "json"               # syslog-usg's own operational logs

[metrics]
enabled = true
# Exposed via [admin] listen address at /metrics
```

