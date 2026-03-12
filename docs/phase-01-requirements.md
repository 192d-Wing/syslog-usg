# Phase 01 — Requirements and Scope

## syslog-usg: A Production-Grade Syslog Server/Relay in Rust

**Version:** 1.0.0-draft
**Date:** 2026-03-11
**Status:** Draft

---

## Table of Contents

1. [Product Goals](#1-product-goals)
2. [Use Cases and Deployment Modes](#2-use-cases-and-deployment-modes)
3. [MVP Scope](#3-mvp-scope)
4. [Future Feature Roadmap](#4-future-feature-roadmap)
5. [Non-Functional Requirements](#5-non-functional-requirements)
6. [RFC Compliance Scope Summary](#6-rfc-compliance-scope-summary)
7. [Key Assumptions](#7-key-assumptions)
8. [Major Risks](#8-major-risks)

---

## 1. Product Goals

### 1.1 What This System Does

syslog-usg is a high-performance, RFC-compliant syslog server and relay implemented in Rust. It receives, parses, validates, routes, queues, and forwards syslog messages across network boundaries. It is not merely a parser library; it is a complete server process with transport listeners, a relay pipeline, bounded internal queueing, and configurable output destinations.

### 1.2 Who It Is For

| Persona | Description |
|---------|-------------|
| **Infrastructure Engineer** | Operates centralized logging infrastructure at scale; needs high throughput, reliability, and operational observability. |
| **Security Engineer** | Requires tamper-evident, encrypted log transport with mutual authentication; enforces compliance and audit trails. |
| **Network Operator** | Manages heterogeneous network equipment emitting syslog over UDP; needs a reliable aggregation point with protocol translation. |
| **Platform Team / SRE** | Deploys syslog collection in Kubernetes or edge environments; needs lightweight footprint, structured output, and metrics integration. |
| **Compliance Officer** | Requires demonstrable RFC conformance, message integrity guarantees, and retention-grade log pipelines. |

### 1.3 What Problem It Solves

Existing syslog implementations suffer from one or more of the following:

- **Incomplete RFC compliance** — Most servers implement only fragments of the syslog RFC family, particularly lacking RFC 5424 structured data, RFC 5425 TLS transport, and RFC 9662 updated cipher suites.
- **Memory safety vulnerabilities** — C-based implementations (rsyslog, syslog-ng) have a long history of buffer overflows, use-after-free, and format string vulnerabilities in a component that processes untrusted network input.
- **Performance ceilings** — Single-threaded architectures or GC-paused runtimes cannot sustain the throughput required by modern infrastructure (100k+ msg/sec per node).
- **Operational opacity** — Legacy servers lack structured metrics, health endpoints, and integration with modern observability stacks.
- **Configuration complexity** — Existing tools use bespoke DSLs that are error-prone and hard to validate programmatically.

syslog-usg addresses all five by combining Rust's memory safety and performance with first-class RFC compliance and modern operational practices.

---

## 2. Use Cases and Deployment Modes

### 2.1 Centralized Collector

**Primary Persona:** Infrastructure Engineer

**Description:** A single syslog-usg instance (or HA pair) receives syslog messages from hundreds to thousands of sources and writes them to durable storage or forwards them to a SIEM.

**Key Requirements:**
- Ingest via UDP (RFC 5426), TCP+TLS (RFC 5425), and optionally reliable TCP (RFC 3195)
- Parse and validate RFC 5424 message format with full structured data support
- Buffer messages in bounded in-memory queues during downstream backpressure
- Write to configurable outputs: files (with rotation), TCP/TLS forward, stdout
- Expose ingestion rate, queue depth, parse error, and drop-count metrics

**Relevant RFCs:** RFC 5424, RFC 5425, RFC 5426, RFC 9662, RFC 3195

---

### 2.2 Relay / Aggregation Tier

**Primary Persona:** Network Operator

**Description:** Deployed between edge devices and a central collector. Receives syslog from many sources over UDP, re-encapsulates in TLS, and forwards to a secure collector. May filter, re-prioritize, or enrich messages in transit.

**Key Requirements:**
- Protocol translation: UDP-in to TLS-out, or TLS-in to TLS-out
- Per-source and per-destination routing rules
- Message enrichment: add structured data elements (e.g., origin metadata)
- Bounded internal queue with configurable backpressure behavior (drop-oldest, block, drop-newest)
- Graceful degradation: if downstream is unavailable, queue and retry with exponential backoff

**Relevant RFCs:** RFC 5424, RFC 5425, RFC 5426, RFC 9662

---

### 2.3 Secure Gateway

**Primary Persona:** Security Engineer

**Description:** Acts as a TLS termination and mutual-authentication point at a network boundary. Only authenticated sources may submit logs; only authenticated destinations receive them.

**Key Requirements:**
- Mandatory mutual TLS with certificate-based authentication (RFC 5425)
- Updated cipher suites per RFC 9662: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 preferred, TLS 1.2 mandatory, TLS 1.3 recommended
- 0-RTT explicitly disabled (RFC 9662 requirement — no replay protection in syslog)
- Certificate fingerprint matching and PKI path validation
- Per-client access control: which facilities/severities a source may submit
- Audit log of connection establishment, authentication failures, and policy violations
- Signed syslog message verification and generation (RFC 5848, future)

**Relevant RFCs:** RFC 5425, RFC 9662, RFC 5848 (future), RFC 6012 (future)

---

### 2.4 Multi-Tenant Intake

**Primary Persona:** Platform Team / SRE

**Description:** A shared syslog-usg instance serves multiple tenants (teams, customers, environments). Each tenant's messages are isolated, routed to tenant-specific outputs, and metered independently.

**Key Requirements:**
- Tenant identification via TLS client certificate CN/SAN, source IP, or structured data field
- Per-tenant routing rules, output destinations, and rate limits
- Per-tenant metrics: ingestion rate, queue depth, drop count
- Tenant isolation: one tenant's backpressure must not block another
- Configuration hot-reload without dropping connections

**Relevant RFCs:** RFC 5424 (structured data for tenant tagging), RFC 5425

---

### 2.5 Edge Relay (Constrained Environments)

**Primary Persona:** Infrastructure Engineer (edge/IoT)

**Description:** A lightweight syslog-usg instance deployed at the edge (branch office, IoT gateway, Kubernetes sidecar) with minimal resource footprint. Collects local syslog, queues during network partitions, and forwards when connectivity is restored.

**Key Requirements:**
- Static binary, minimal dependencies, sub-10 MB RSS at idle
- Disk-backed queue for store-and-forward during network partitions (future; in-memory queue for MVP)
- UDP listener on constrained ports
- Configurable message batching for efficient forwarding
- Watchdog / liveness endpoint

**Relevant RFCs:** RFC 5424, RFC 5426, RFC 5425

---

### 2.6 Structured Logging Pipeline

**Primary Persona:** Platform Team / SRE

**Description:** syslog-usg as a pipeline stage that receives RFC 5424 messages, extracts structured data, applies transformations, and outputs in structured formats (JSON, CEF) for downstream analytics platforms.

**Key Requirements:**
- Full RFC 5424 structured data parsing with SD-ELEMENT and SD-PARAM extraction
- Output format plugins: JSON lines, CEF (future), key-value
- Field extraction from MSG body via configurable regex patterns (future)
- Tag/label injection for downstream routing (e.g., Prometheus labels, Loki labels)
- Ability to act as both a syslog receiver and a structured data producer

**Relevant RFCs:** RFC 5424

---

## 3. MVP Scope

The MVP delivers a functional, production-usable syslog server and relay with the core transport, parsing, and pipeline capabilities. Features are classified as MUST, SHOULD, or NICE-TO-HAVE.

### 3.1 MUST Have (Required for MVP Ship)

#### 3.1.1 RFC 5424 Message Parser

- Full HEADER parsing: PRI, VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID
- Full STRUCTURED-DATA parsing: SD-ELEMENT, SD-ID, SD-PARAM with proper escaping
- MSG body extraction with BOM detection (UTF-8 BOM handling)
- NILVALUE ("-") handling for all optional fields
- Facility and severity extraction from PRI value
- Timestamp parsing: RFC 3339 with optional fractional seconds and timezone offset
- Validation mode: strict (reject malformed) and lenient (best-effort parse with error annotations)
- Support for minimum message sizes: 480 octets MUST, 2048 octets SHOULD, configurable maximum

#### 3.1.2 RFC 3164 Legacy Parser (Compatibility)

- Best-effort parsing of BSD-format syslog messages (pre-RFC 5424)
- Auto-detection of RFC 5424 vs RFC 3164 format based on version field presence
- Translation of RFC 3164 messages into RFC 5424 internal representation

#### 3.1.3 UDP Transport — Receiver (RFC 5426)

- Bind to configurable address:port (default 514)
- IPv4 and IPv6 dual-stack support
- One message per datagram processing
- UDP checksum enforcement
- Configurable receive buffer size (SO_RCVBUF)
- Per-listener metrics: received count, parse errors, drops

#### 3.1.4 TLS Transport — Receiver and Sender (RFC 5425 + RFC 9662)

- TLS 1.2 mandatory, TLS 1.3 recommended
- Cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 mandatory (RFC 9662)
- Legacy cipher TLS_RSA_WITH_AES_128_CBC_SHA supported for backward compatibility
- 0-RTT explicitly disabled for TLS 1.3 (RFC 9662)
- Octet-counting framing: `MSG-LEN SP SYSLOG-MSG`
- Certificate-based mutual authentication
- Certificate path validation (PKI) and fingerprint matching (SHA-256; SHA-1 for compat)
- Self-signed certificate support
- Configurable CA bundle, cert, and key paths
- Default port 6514
- Graceful connection draining on shutdown
- Per-connection and per-listener metrics

#### 3.1.5 Relay Pipeline

- Input stage: receive from one or more listeners (UDP, TLS)
- Parse stage: RFC 5424/3164 parsing and validation
- Filter stage: include/exclude rules based on facility, severity, hostname, app-name, and SD-ID
- Route stage: match messages to one or more output destinations
- Output stage: forward via TLS (RFC 5425) or UDP (RFC 5426), or write to file/stdout
- Each stage connected by bounded async channels

#### 3.1.6 Bounded Internal Queueing

- Per-output bounded in-memory queue with configurable capacity (message count and byte size)
- Backpressure policies: `drop-oldest`, `drop-newest`, `block` (applies backpressure to input)
- Queue depth metrics exposed via metrics endpoint
- Overflow counter per queue

#### 3.1.7 Configuration

- TOML-based configuration file
- Configuration schema validation at startup with clear error messages
- Sections: listeners, outputs, routes, filters, tls, metrics, logging
- Environment variable substitution in config values (e.g., `${SYSLOG_TLS_CERT}`)
- Configuration validation subcommand (`syslog-usg validate-config`)
- Example configuration file shipped with the binary

#### 3.1.8 Metrics and Observability

- Prometheus exposition format metrics endpoint (HTTP)
- Core metrics:
  - `syslog_messages_received_total` (by listener, transport, facility, severity)
  - `syslog_messages_forwarded_total` (by output)
  - `syslog_messages_dropped_total` (by output, reason)
  - `syslog_parse_errors_total` (by listener, error_type)
  - `syslog_queue_depth` (by output)
  - `syslog_queue_capacity` (by output)
  - `syslog_connections_active` (by listener)
  - `syslog_tls_handshake_errors_total` (by listener, error_type)
  - `syslog_parse_duration_seconds` (histogram)
  - `syslog_forward_duration_seconds` (histogram)
- Structured logging (JSON) for syslog-usg's own operational logs
- Health check endpoint: `/health` returning 200 when ready

#### 3.1.9 Graceful Lifecycle Management

- SIGTERM/SIGINT handling: stop accepting new connections, drain queues, then exit
- Configurable drain timeout
- Startup validation: bind-check all listeners, validate TLS certificates, test output connectivity
- PID file support

---

### 3.2 SHOULD Have (Target for MVP, Acceptable to Defer)

#### 3.2.1 TCP Plain-Text Transport (Receiver)

- Non-TLS TCP listener with octet-counting framing
- Serves as migration path for environments not yet ready for TLS
- MUST log a warning when plain-text TCP is enabled

#### 3.2.2 File Output with Rotation

- Write messages to local files
- Configurable rotation by size and/or time
- Configurable retention (max files / max age)
- Atomic rename rotation (no message loss during rotate)

#### 3.2.3 Hot Configuration Reload

- SIGHUP-triggered configuration reload
- Reload adds/removes listeners and outputs without dropping existing connections
- Validation before applying: reject invalid config and continue with current

#### 3.2.4 Rate Limiting

- Per-source (IP) rate limiting with configurable burst and sustained rates
- Per-output rate limiting
- Rate limit events counted in metrics

#### 3.2.5 JSON Output Format

- Serialize parsed RFC 5424 messages as JSON lines for downstream ingestion
- Configurable field inclusion/exclusion
- Output to file or stdout

---

### 3.3 NICE-TO-HAVE (Stretch Goals, Post-MVP Acceptable)

#### 3.3.1 RFC 3195 Reliable Delivery (BEEP/TCP)

- RAW profile support for reliable syslog over TCP port 601
- Message acknowledgment semantics
- Note: BEEP is complex; this may be deferred if implementation cost is high

#### 3.3.2 systemd Integration

- `sd_notify` readiness notification
- Journal-native logging
- Socket activation

#### 3.3.3 Disk-Backed Queue

- Spill-to-disk when in-memory queue is full
- Automatic recovery on restart
- WAL-style append for crash safety

---

## 4. Future Feature Roadmap

Features planned for post-MVP releases, organized by theme.

### 4.1 Phase 2 — Security and Integrity

| Feature | Description | RFC |
|---------|-------------|-----|
| **DTLS Transport** | Datagram TLS for secure UDP transport. DTLS 1.2 mandatory, DTLS 1.3 recommended. Port 6514. | RFC 6012 + RFC 9662 |
| **Signed Syslog Messages** | Generate and verify signature blocks over message groups. SHA-256 hash, OpenPGP DSA signatures. Certificate block distribution. | RFC 5848 |
| **Message Sequencing and Loss Detection** | Detect missing, reordered, and replayed messages using RFC 5848 signature block sequence numbers. | RFC 5848 |

### 4.2 Phase 3 — Alarms and SNMP Integration

| Feature | Description | RFC |
|---------|-------------|-----|
| **Alarm Structured Data** | Parse and generate alarm SD-ELEMENTs: resource, probableCause, perceivedSeverity, eventType, trendIndication. ITU severity mapping. | RFC 5674 |
| **SNMP-to-Syslog Mapping** | Receive SNMP notifications and translate to RFC 5424 syslog messages with `snmp` SD-ID. Support for SNMPv3 context. | RFC 5675 |
| **Syslog-to-SNMP Mapping** | Translate received syslog messages to SNMP notifications via SYSLOG-MSG-MIB. Configurable notification generation. | RFC 5676 |

### 4.3 Phase 4 — Management Plane

| Feature | Description | RFC |
|---------|-------------|-----|
| **SNMP MIB: Textual Conventions** | Expose syslog facility/severity as SNMP textual conventions for network management integration. | RFC 5427 |
| **YANG Data Model** | Implement the ietf-syslog YANG module for NETCONF/RESTCONF-based configuration management. Console, file, and remote logging configuration via YANG. | RFC 9742 |

### 4.4 Phase 5 — Operational Excellence

| Feature | Description |
|---------|-------------|
| **Disk-Backed Persistent Queue** | WAL-based durable queue with crash recovery. Configurable memory/disk ratio. |
| **Clustering and HA** | Active-passive failover with shared queue state. Leader election via Raft or external coordinator. |
| **Output Plugins** | Kafka, Redis, S3/object-storage, Elasticsearch, generic HTTP/webhook outputs. |
| **CEF/LEEF Output** | ArcSight Common Event Format and QRadar LEEF output serialization. |
| **Regex Field Extraction** | Extract fields from unstructured MSG body using configurable patterns. |
| **Web UI** | Lightweight operational dashboard: pipeline status, metrics, config viewer. |

---

## 5. Non-Functional Requirements

### 5.1 Performance

| Requirement | Target | Notes |
|-------------|--------|-------|
| Sustained throughput (single node, UDP ingest) | >= 100,000 messages/sec | Measured with 512-byte average message size on 4-core/8GB commodity hardware |
| Sustained throughput (single node, TLS ingest) | >= 50,000 messages/sec | TLS handshake amortized over persistent connections |
| p50 parse latency (RFC 5424, in-memory) | < 2 microseconds | Excludes I/O; pure parsing of well-formed message |
| p99 parse latency (RFC 5424, in-memory) | < 10 microseconds | Includes structured data with 3+ SD-ELEMENTs |
| p99 end-to-end relay latency (UDP-in to TLS-out) | < 1 millisecond | Measured under sustained 50k msg/sec load |
| Memory footprint at idle | < 10 MB RSS | No messages in queue |
| Memory footprint under load | < 256 MB RSS | 100k msg/sec throughput with 10k-message queue depth |
| Startup time (cold, no queue recovery) | < 500 milliseconds | Time to first message accepted |
| Graceful shutdown drain time | Configurable, default 5 seconds | All queued messages forwarded or persisted |

### 5.2 Correctness

| Requirement | Description |
|-------------|-------------|
| RFC 5424 conformance | Parser MUST accept all valid RFC 5424 messages and MUST reject messages that violate the ABNF grammar (in strict mode) |
| No silent message loss | Every received message is either forwarded to an output, written to a drop log, or counted in `messages_dropped_total`. Zero unaccounted messages. |
| Ordered delivery | Messages from a single source on a single TCP/TLS connection MUST be delivered in order to a single output. UDP ordering is best-effort. |
| Idempotent configuration reload | Reloading the same configuration MUST produce no observable side effects. |
| Timestamp fidelity | Timestamps MUST be preserved at nanosecond precision through the pipeline. No lossy conversions. |

### 5.3 Memory Safety and Reliability

| Requirement | Description |
|-------------|-------------|
| No unsafe code in application logic | `#![forbid(unsafe_code)]` at the crate root. Unsafe permitted only in explicitly audited, isolated leaf dependencies. |
| Panic-free pipeline | All parse and I/O errors handled via `Result`. No `unwrap()` on fallible operations in hot paths. Panics in any task MUST NOT crash the process; supervisor tasks must catch and restart. |
| Bounded memory | All queues, buffers, and caches have configurable upper bounds. No unbounded allocations on the hot path. |
| Graceful degradation | Under overload: shed load according to policy, never OOM-kill. |

### 5.4 Security

| Requirement | Description |
|-------------|-------------|
| Secure by default | TLS listeners enabled by default in example config. Plain-text listeners require explicit opt-in and generate startup warnings. |
| Cipher suite compliance | RFC 9662 mandatory cipher suites. No export ciphers, no NULL encryption, no RC4, no 3DES. |
| No 0-RTT | TLS 1.3 early data explicitly disabled per RFC 9662. |
| Certificate validation | Full PKIX path validation by default. Fingerprint pinning as alternative. Configurable per-listener. |
| Privilege dropping | After binding privileged ports (514), drop to configured unprivileged user/group. |
| Input validation | All network input treated as untrusted. Parser hardened against oversized fields, deeply nested structures, and malformed UTF-8. |
| Secret handling | TLS private keys and passphrases never logged, never exposed in metrics or health endpoints. Config file permissions validated (warn if world-readable). |
| Dependency audit | All transitive dependencies audited via `cargo audit` in CI. No known CVEs at release time. |

### 5.5 Observability

| Requirement | Description |
|-------------|-------------|
| Prometheus metrics | Exposition format on configurable HTTP port. All pipeline stages instrumented. |
| Structured operational logging | syslog-usg's own logs in JSON format with severity, timestamp, component, and trace context. |
| Health endpoint | HTTP `/health` returning `200 OK` when all listeners are bound and at least one output is reachable. `503` otherwise. |
| Readiness vs. liveness | Separate `/ready` and `/live` endpoints for Kubernetes probes. |
| Trace context propagation | Each message assigned an internal trace ID for correlation through the pipeline. |

### 5.6 Scalability

| Requirement | Description |
|-------------|-------------|
| Vertical scaling | Utilize all available CPU cores via async runtime work-stealing. Linear throughput scaling up to 8 cores. |
| Horizontal scaling | Stateless relay mode allows horizontal scale-out behind a load balancer. No shared state between instances. |
| Connection scaling | Support >= 10,000 concurrent TLS connections per instance. |
| Source scaling | Support >= 50,000 unique source IPs (UDP) per instance. |

### 5.7 Testability

| Requirement | Description |
|-------------|-------------|
| Unit test coverage | >= 80% line coverage on parser, filter, and routing modules. |
| Integration tests | End-to-end tests for each transport: UDP-in/TLS-out, TLS-in/TLS-out, UDP-in/file-out. |
| Conformance test suite | Dedicated test corpus of valid and invalid RFC 5424 messages, derived from RFC ABNF. |
| Fuzz testing | Continuous fuzzing of parser with `cargo-fuzz` / `libfuzzer`. Integrated in CI on schedule. |
| Performance benchmarks | `criterion`-based benchmarks for parser, queue, and end-to-end pipeline. Tracked across commits for regression detection. |
| Load testing | Scripted load tests using purpose-built syslog traffic generators. Runbook for 100k msg/sec validation. |

---

## 6. RFC Compliance Scope Summary

### 6.1 Complete RFC Reference

| RFC | Title | Category | Phase |
|-----|-------|----------|-------|
| **RFC 5424** | The Syslog Protocol | Core: Message Format | **MVP** |
| **RFC 5426** | Transmission of Syslog Messages over UDP | Core: Transport | **MVP** |
| **RFC 5425** | TLS Transport Mapping for Syslog | Core: Transport | **MVP** |
| **RFC 9662** | Updates to Secure Syslog Cipher Suites | Core: Transport Security | **MVP** |
| **RFC 3195** | Reliable Delivery for Syslog (BEEP) | Core: Transport | MVP (stretch) / Phase 2 |
| **RFC 6012** | DTLS Transport Mapping for Syslog | Core: Transport | Phase 2 |
| **RFC 5848** | Signed Syslog Messages | Extension: Integrity | Phase 2 |
| **RFC 5674** | Alarms in Syslog | Extension: Alarms | Phase 3 |
| **RFC 5675** | Mapping SNMP Notifications to Syslog | Extension: SNMP | Phase 3 |
| **RFC 5676** | Syslog-to-SNMP Mapping (MIB) | Extension: SNMP | Phase 3 |
| **RFC 5427** | Textual Conventions for Syslog Management | Management: SNMP | Phase 4 |
| **RFC 9742** | YANG Data Model for Syslog | Management: YANG | Phase 4 |

### 6.2 MVP RFC Coverage Detail

**RFC 5424 — The Syslog Protocol:**
- HEADER: PRI, VERSION (1), TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID
- STRUCTURED-DATA: SD-ELEMENT, SD-ID (including reserved: timeQuality, origin, meta), SD-PARAM
- MSG: UTF-8 with optional BOM, octet fallback
- PRI encoding/decoding: facility (0-23), severity (0-7)
- Minimum message size: 480 octets MUST, 2048 SHOULD
- NILVALUE handling for all optional fields

**RFC 5426 — UDP Transport:**
- One message per datagram
- IPv4: handle messages up to 480 octets minimum; IPv6: 1180 octets minimum
- SHOULD support 2048 octets; configurable maximum
- Mandatory UDP checksums
- Default port 514
- Congestion awareness: rate limiting, drop counting

**RFC 5425 — TLS Transport:**
- TLS 1.2 mandatory, TLS 1.3 recommended
- Octet-counting framing: `MSG-LEN SP SYSLOG-MSG`
- Certificate-based mutual authentication
- PKI path validation and fingerprint matching
- Self-signed certificate support
- Default port 6514

**RFC 9662 — Cipher Suite Updates:**
- Mandatory: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- Legacy: TLS_RSA_WITH_AES_128_CBC_SHA (for migration)
- ECDHE suite preferred over RSA-only
- 0-RTT (TLS 1.3 early data) prohibited
- DTLS 1.0 prohibited (applies when DTLS implemented in Phase 2)
- DTLS 1.2 mandatory, DTLS 1.3 recommended (Phase 2)

---

## 7. Key Assumptions

### 7.1 Language and Toolchain

| Assumption | Value |
|------------|-------|
| Language | Rust |
| Edition | 2024 |
| Minimum Rust version (MSRV) | 1.92 |
| Async runtime | Tokio (multi-threaded, work-stealing) |
| TLS implementation | rustls (no OpenSSL dependency for default builds) |
| Build system | Cargo with workspace layout |

### 7.2 Target Platforms

| Platform | Tier | Notes |
|----------|------|-------|
| Linux x86_64 (glibc) | Primary | CI-tested, performance-validated |
| Linux aarch64 (glibc) | Primary | CI-tested |
| Linux x86_64 (musl) | Primary | Static binary target for containers |
| macOS x86_64 / aarch64 | Secondary | CI-tested, development platform |
| FreeBSD x86_64 | Tertiary | Best-effort, community-supported |
| Windows x86_64 | Not targeted | May work but not tested or supported at MVP |

### 7.3 Deployment Model

| Assumption | Description |
|------------|-------------|
| Binary distribution | Single static binary (musl target). No runtime dependencies. |
| Container image | Distroless or scratch-based OCI image. |
| Package formats | `.deb`, `.rpm` for Linux. Homebrew formula for macOS. Post-MVP. |
| Process management | Runs as a systemd service, Docker container, or Kubernetes pod. Supports PID files for legacy init systems. |
| Orchestration | Stateless by default (no inter-instance coordination). Horizontal scaling via load balancer. |

### 7.4 Configuration Format

| Assumption | Description |
|------------|-------------|
| Primary format | TOML |
| Schema validation | At startup and on reload. Errors are descriptive and reference the config key path. |
| Environment variables | `${VAR}` and `${VAR:-default}` substitution in string values. |
| Secrets | TLS key paths and passphrases via config file or environment variables. No built-in vault integration at MVP. |
| Config file location | `/etc/syslog-usg/syslog-usg.toml` (default), overridable via `--config` flag. |

### 7.5 Operational Assumptions

| Assumption | Description |
|------------|-------------|
| Clock synchronization | Hosts running syslog-usg are NTP-synchronized. Timestamps are not corrected by the relay. |
| Network | Managed networks for UDP transport (per RFC 5426). TLS for all other environments. |
| DNS resolution | Output hostnames resolved at startup and on config reload. Configurable TTL-based re-resolution. |
| Log retention | syslog-usg does not manage long-term retention. It forwards to systems that do (SIEM, object storage, databases). |

---

## 8. Major Risks

### 8.1 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **rustls lacks required cipher suites** | Low | High | Verify TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 support in rustls before committing. Fallback: optional openssl-sys feature gate. |
| **Tokio UDP recv performance at 100k msg/sec** | Medium | High | Benchmark early. Mitigations: `recvmmsg` via io_uring, multiple UDP sockets with SO_REUSEPORT, dedicated recv threads. |
| **Parser performance with complex structured data** | Low | Medium | Zero-copy parsing with byte slicing. Pre-allocate SD-ELEMENT vectors. Benchmark with pathological inputs. |
| **TLS handshake overhead limits connection scaling** | Medium | Medium | Session resumption, connection pooling for outputs. Benchmark at 10k concurrent connections. |
| **BEEP protocol complexity (RFC 3195)** | High | Low | BEEP has no mature Rust implementation. Defer to Phase 2 unless customer-critical. |
| **Async runtime footprint on edge/constrained deployments** | Low | Medium | Profile Tokio memory overhead. Consider optional single-threaded runtime feature. |

### 8.2 Compliance Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **RFC 5424 ABNF ambiguity** | Medium | Medium | Build conformance test suite from RFC examples and interoperability testing with rsyslog/syslog-ng. |
| **RFC 3164 wild variation** | High | Medium | Lenient parser with heuristics. Do not claim RFC 3164 compliance; document it as "best-effort legacy compatibility." |
| **RFC 9662 adoption lag** | Low | Low | Support both new and legacy cipher suites. Configurable cipher preference order. |
| **Incomplete structured data interop** | Medium | Medium | Test with real-world structured data from major vendors (Cisco, Palo Alto, Fortinet, Linux auditd). |

### 8.3 Ecosystem Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **No Rust BEEP library** | High | Low | Implement minimal BEEP framing from scratch or defer RFC 3195 entirely. |
| **rustls API instability** | Low | Medium | Pin version, wrap in abstraction layer. |
| **Tokio breaking changes** | Low | Medium | Pin major version. Async trait abstraction over runtime for future portability. |
| **SNMP crate maturity for Phase 3** | Medium | Medium | Evaluate `snmp` and `rasn` crates early. May require custom implementation. |

### 8.4 Operational Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Message loss during config reload** | Medium | High | Atomic config swap: validate new config, create new pipeline, drain old pipeline, then switch. |
| **Queue memory exhaustion under sustained overload** | Medium | High | Hard byte-size limit on queues. Backpressure propagation to input. Aggressive metrics alerting. |
| **Certificate expiry causing silent TLS failures** | Medium | High | Certificate expiry monitoring metric (`syslog_tls_cert_expiry_seconds`). Log warnings at 30/7/1 days before expiry. |
| **Noisy-neighbor in multi-tenant mode** | Medium | Medium | Per-tenant queue isolation and rate limiting. Circuit-breaker per output. |
| **Difficulty debugging message routing** | Medium | Medium | Internal trace ID per message. Debug-level logging with full message path trace. Dry-run route evaluation endpoint. |

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **Facility** | Numeric category (0-23) indicating the type of program generating the message (RFC 5424 Section 6.2.1) |
| **Severity** | Numeric level (0-7) indicating message urgency, from Emergency (0) to Debug (7) (RFC 5424 Section 6.2.1) |
| **PRI** | Priority value encoding facility and severity as `(facility * 8) + severity` |
| **SD-ELEMENT** | A named group of key-value parameters within STRUCTURED-DATA |
| **SD-ID** | Identifier for an SD-ELEMENT, either IANA-registered or in `name@enterprise-number` format |
| **Octet-counting** | Framing method where each message is preceded by its byte length and a space character |
| **BEEP** | Blocks Extensible Exchange Protocol, the transport used by RFC 3195 |
| **DTLS** | Datagram Transport Layer Security, TLS adapted for unreliable datagram transport |
| **NILVALUE** | The hyphen character (`-`) used to represent absent optional fields in RFC 5424 |

## Appendix B: Referenced Documents

1. RFC 5424 — The Syslog Protocol (March 2009)
2. RFC 3195 — Reliable Delivery for syslog (November 2001)
3. RFC 5425 — Transport Layer Security (TLS) Transport Mapping for Syslog (March 2009)
4. RFC 5426 — Transmission of Syslog Messages over UDP (March 2009)
5. RFC 6012 — Datagram Transport Layer Security (DTLS) Transport Mapping for Syslog (October 2010)
6. RFC 9662 — Updates to the Cipher Suites in Secure Syslog (October 2024)
7. RFC 5427 — Textual Conventions for Syslog Management (March 2009)
8. RFC 9742 — A YANG Data Model for Syslog Configuration (April 2025)
9. RFC 5848 — Signed Syslog Messages (May 2010)
10. RFC 5674 — Alarms in Syslog (October 2009)
11. RFC 5675 — Mapping SNMP Notifications to Syslog Messages (October 2009)
12. RFC 5676 — Definitions of Managed Objects for Mapping SYSLOG Messages to SNMP Notifications (October 2009)
13. RFC 3164 — The BSD Syslog Protocol (August 2001) — referenced for legacy compatibility only
