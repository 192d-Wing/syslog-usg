# Phase 12 — Documentation

## syslog-usg: Developer, Operator, and Deployment Documentation

**Version:** 1.0.0-draft
**Date:** 2026-03-11
**Status:** Draft
**Prerequisites:** [Phase 01 — Requirements](phase-01-requirements.md), [Phase 02 — RFC Analysis](phase-02-rfc-analysis.md), [Phase 03 — Architecture](phase-03-architecture.md), [Phase 04 — Rust Architecture](phase-04-rust-architecture.md), [Phase 05 — Transport Security](phase-05-transport-security.md), [Phase 06 — Parsing](phase-06-parsing.md), [Phase 09 — Observability](phase-09-observability.md), [Phase 11 — QA](phase-11-qa.md)

---

## Table of Contents

1. [README Outline](#1-readme-outline)
2. [Protocol Compliance Documentation](#2-protocol-compliance-documentation)
3. [Operator Guide](#3-operator-guide)
4. [Deployment Notes](#4-deployment-notes)
5. [Developer Guide](#5-developer-guide)
6. [Future Enhancements](#6-future-enhancements)

---

## 1. README Outline

The project README (`README.md` at the workspace root) should contain the following sections, written for a first-time visitor who may be evaluating syslog-usg against rsyslog, syslog-ng, or similar tools.

---

### 1.1 Header

```
# syslog-usg

A production-grade, RFC-compliant Syslog server and relay written in Rust.
```

---

### 1.2 Key Features

- **RFC Compliance** -- Full implementation of RFC 5424 (message format), RFC 5425 (TLS transport), RFC 5426 (UDP transport), and RFC 9662 (updated cipher suites). Compliance claims are traceable to tests.
- **High Performance** -- Sustained 100k+ messages/sec (UDP) and 50k+ messages/sec (TLS) on commodity 4-core hardware. Sub-2-microsecond p50 parse latency.
- **Memory Safe** -- Written in safe Rust (`#![forbid(unsafe_code)]` in all library crates). No buffer overflows, no use-after-free, no format string vulnerabilities.
- **Secure by Default** -- TLS 1.2+ mandatory, RFC 9662 cipher suites enforced, mutual TLS supported, 0-RTT explicitly disabled, privilege dropping after port binding.
- **Operationally Observable** -- Prometheus metrics endpoint, structured JSON logging, `/health`, `/ready`, and `/live` endpoints for Kubernetes.
- **Flexible Pipeline** -- Multi-input, multi-output relay with filtering by facility, severity, hostname, app-name, and structured data ID. Fan-out to multiple destinations. Bounded queues with configurable backpressure.
- **Simple Configuration** -- Single TOML file with environment variable substitution and startup validation. No bespoke DSL.

---

### 1.3 Quick Start

```
## Install

# From binary release (Linux x86_64):
curl -LO https://github.com/<org>/syslog-usg/releases/latest/download/syslog-usg-linux-amd64.tar.gz
tar xzf syslog-usg-linux-amd64.tar.gz
sudo mv syslog-usg /usr/local/bin/

# From source:
cargo install --path crates/syslog-server

## Minimal configuration

cat > /etc/syslog-usg/syslog-usg.toml << 'EOF'
[listeners.udp_514]
transport = "udp"
bind = "0.0.0.0:514"

[outputs.stdout]
type = "stdout"
format = "rfc5424"

[[routes]]
name = "default"
outputs = ["stdout"]
EOF

## Run

syslog-usg --config /etc/syslog-usg/syslog-usg.toml

## Validate configuration without running

syslog-usg validate-config --config /etc/syslog-usg/syslog-usg.toml
```

---

### 1.4 Configuration Reference Summary

| Section | Purpose |
|---------|---------|
| `[server]` | Global settings: drain timeout, PID file, privilege dropping |
| `[listeners.<name>]` | Input definitions: UDP, TCP, TLS with per-listener tuning |
| `[outputs.<name>]` | Output destinations: forward_tls, forward_tcp, forward_udp, file, stdout |
| `[[routes]]` | Ordered routing rules: filter name + output list |
| `[filters.<name>]` | Filter definitions: facility, severity, hostname, app-name, SD-ID matching |
| `[metrics]` | Prometheus metrics endpoint: enabled, bind address |
| `[logging]` | Operational log level and format (json/text) |

Full reference: see [Section 3.3 — Configuration File Reference](#33-configuration-file-reference).

---

### 1.5 Transport Support Table

| Transport | Direction | Default Port | RFC | Status |
|-----------|-----------|-------------|-----|--------|
| UDP | Inbound | 514 | RFC 5426 | Supported |
| TLS (TCP) | Inbound / Outbound | 6514 | RFC 5425 + RFC 9662 | Supported |
| TCP (plain) | Inbound | 514 | -- | Supported (warning emitted) |
| UDP | Outbound | -- | RFC 5426 | Supported |
| DTLS | Inbound / Outbound | 6514 | RFC 6012 | Planned (Phase 2) |

---

### 1.6 RFC Compliance Table

| RFC | Title | Status |
|-----|-------|--------|
| RFC 5424 | The Syslog Protocol | Full compliance |
| RFC 5425 | TLS Transport Mapping for Syslog | Full compliance |
| RFC 5426 | Transmission of Syslog Messages over UDP | Full compliance |
| RFC 9662 | Updates to Cipher Suites in Secure Syslog | Full compliance |
| RFC 3164 | BSD Syslog Protocol (legacy) | Best-effort compatibility |
| RFC 3195 | Reliable Delivery for Syslog (BEEP) | Stretch / Phase 2 |
| RFC 6012 | DTLS Transport Mapping | Planned (Phase 2) |
| RFC 5848 | Signed Syslog Messages | Planned (Phase 2) |
| RFC 5674 | Alarms in Syslog | Planned (Phase 3) |
| RFC 5675 | SNMP-to-Syslog Mapping | Planned (Phase 3) |
| RFC 5676 | Syslog-to-SNMP Mapping | Planned (Phase 3) |
| RFC 5427 | Textual Conventions for Syslog Management | Planned (Phase 4) |
| RFC 9742 | YANG Data Model for Syslog | Planned (Phase 4) |

Details: see [Section 2 — Protocol Compliance Documentation](#2-protocol-compliance-documentation).

---

### 1.7 Performance Characteristics

| Metric | Target | Conditions |
|--------|--------|------------|
| Sustained throughput (UDP ingest) | >= 100,000 msg/sec | 512-byte avg message, 4-core/8GB |
| Sustained throughput (TLS ingest) | >= 50,000 msg/sec | Persistent connections, amortized handshake |
| p50 parse latency (RFC 5424) | < 2 microseconds | In-memory, well-formed message |
| p99 parse latency (RFC 5424) | < 10 microseconds | 3+ SD-ELEMENTs |
| p99 end-to-end relay latency | < 1 millisecond | UDP-in to TLS-out, 50k msg/sec |
| Memory at idle | < 10 MB RSS | No queued messages |
| Memory under load | < 256 MB RSS | 100k msg/sec, 10k queue depth |
| Startup time | < 500 milliseconds | Cold start, no queue recovery |

---

### 1.8 Building from Source

```
## Prerequisites
- Rust 1.92+ (stable)
- No system dependencies required (rustls, no OpenSSL)

## Build
cargo build --release

## Binary location
target/release/syslog-usg

## Static binary (Linux musl)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

---

### 1.9 Running Tests

```
# All tests
cargo test

# Single crate
cargo test -p syslog-parse

# Clippy lints
cargo clippy --all-targets --all-features -- -D warnings

# Format check
cargo fmt --all -- --check

# Dependency audit
cargo audit

# Benchmarks
cargo bench -p syslog-bench

# Fuzz testing (requires nightly for cargo-fuzz)
cargo +nightly fuzz run fuzz_parse_5424
```

---

### 1.10 Contributing Guidelines Reference

The README should link to a `CONTRIBUTING.md` file covering:

- Fork and branch workflow
- PR requirements: tests pass, clippy clean, rustfmt applied
- RFC compliance comments required for protocol-relevant code
- Commit message format
- Code of conduct reference

---

### 1.11 License

State the project license. Recommended: MIT OR Apache-2.0 (dual-license), consistent with Rust ecosystem conventions.

---

## 2. Protocol Compliance Documentation

### 2.1 RFC Compliance Matrix

| RFC | Title | Compliance Level | Notes |
|-----|-------|-----------------|-------|
| RFC 5424 | The Syslog Protocol | **Full** | All MUST and SHOULD requirements implemented. Full HEADER, STRUCTURED-DATA, and MSG parsing. Strict and lenient validation modes. |
| RFC 5425 | TLS Transport Mapping for Syslog | **Full** | TLS 1.2 mandatory, TLS 1.3 supported. Octet-counting framing. Mutual authentication. PKI path validation and fingerprint matching. |
| RFC 5426 | Transmission of Syslog Messages over UDP | **Full** | One message per datagram. IPv4/IPv6 dual-stack. Configurable SO_RCVBUF. Mandatory UDP checksums. 480-octet minimum, 2048-octet SHOULD, configurable maximum. |
| RFC 9662 | Updates to Cipher Suites in Secure Syslog | **Full** | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 mandatory. Legacy TLS_RSA_WITH_AES_128_CBC_SHA for migration. ECDHE preferred. 0-RTT (TLS 1.3 early data) prohibited. |
| RFC 3164 | BSD Syslog Protocol | **Compatibility** | Best-effort parsing. Auto-detection of 5424 vs. 3164 format. Translation to RFC 5424 internal representation. No strict compliance claim. |
| RFC 3195 | Reliable Delivery for Syslog | **Not implemented** | BEEP protocol complexity deferred. No mature Rust BEEP library available. |
| RFC 6012 | DTLS Transport Mapping | **Not implemented** | Planned for Phase 2. |
| RFC 5848 | Signed Syslog Messages | **Not implemented** | Planned for Phase 2. Crate `syslog-sign` is a placeholder. |
| RFC 5674 | Alarms in Syslog | **Not implemented** | Planned for Phase 3. |
| RFC 5675 | SNMP-to-Syslog Mapping | **Not implemented** | Planned for Phase 3. |
| RFC 5676 | Syslog-to-SNMP Mapping | **Not implemented** | Planned for Phase 3. |
| RFC 5427 | Textual Conventions for Syslog Management | **Not implemented** | Planned for Phase 4. |
| RFC 9742 | YANG Data Model for Syslog | **Not implemented** | Planned for Phase 4. |

---

### 2.2 RFC 5424 — The Syslog Protocol (Full Coverage)

**MUST requirements implemented:**

| Ref | Requirement | Implementation |
|-----|-------------|---------------|
| S6.1 | Facility values 0-23 | `Facility` enum with `FromPrimitive`, range-checked at parse |
| S6.2 | Severity values 0-7 | `Severity` enum with `Ord`, range-checked at parse |
| S6 | HEADER character set: 7-bit ASCII in 8-bit field | Parser validates PRINTUSASCII range (33-126) for header fields |
| S6.1 | PRI: 3-5 characters including angle brackets | Parser validates `<PRIVAL>` where PRIVAL is 1-3 digits, range 0-191 |
| S6.1 | No leading zeros in PRI (except `<0>`) | Strict mode rejects leading zeros; lenient mode accepts with annotation |
| S6.2.1 | VERSION field format | Parser expects NONZERO-DIGIT followed by 0-2 digits |
| S6.2.3 | T and Z uppercase in TIMESTAMP | Parser validates uppercase requirement |
| S6.2.3 | T required between date and time | Parser enforces `FULL-DATE "T" FULL-TIME` structure |
| S6.2.3 | Leap seconds prohibited | Timestamp validation rejects second value 60 |
| S6.3.1 | STRUCTURED-DATA character set: 7-bit ASCII | SD-ID and PARAM-NAME validated against PRINTUSASCII minus reserved characters |
| S6.3.1 | No duplicate SD-IDs in a message | Strict mode rejects duplicate SD-IDs; lenient mode accepts with annotation |
| S6.3.3 | PARAM-VALUE encoded as UTF-8 | Validated when MSG starts with BOM |
| S6.3.3 | Escape `"`, `\`, `]` in PARAM-VALUE | Parser handles `\"`, `\\`, `\]` escape sequences |
| S6.3.5 | NILVALUE for empty STRUCTURED-DATA | Parser recognizes `-` as NILVALUE |
| S6.4 | BOM implies UTF-8 MSG body | If BOM detected, remainder validated as UTF-8 |
| S8 | Transport must not alter messages | Messages passed through pipeline without modification (unless enrichment configured) |
| S8.1 | Accept messages up to 480 octets minimum | All transports accept messages up to configurable maximum (default 8192) |
| S8.1 | Truncation at end only | If truncation occurs, it is always at the end of MSG |
| S9 | TLS-based transport required | TLS listener supported via RFC 5425 |

**SHOULD requirements implemented:**

| Ref | Requirement | Implementation |
|-----|-------------|---------------|
| S6.2.3 | Include TIME-SECFRAC if clock permits | Serializer includes fractional seconds when present in internal representation |
| S8.1 | Accept messages up to 2048 octets | Default `max_message_size` exceeds 2048 (set to 8192) |
| S9 | Support UDP-based transport | UDP listener implemented per RFC 5426 |

**Data model coverage:**

- HEADER: PRI, VERSION (1), TIMESTAMP (RFC 3339, nanosecond precision), HOSTNAME (up to 255), APP-NAME (up to 48), PROCID (up to 128), MSGID (up to 32)
- STRUCTURED-DATA: SD-ELEMENT, SD-ID (including IANA-registered: `timeQuality`, `origin`, `meta`), SD-PARAM with proper escaping
- MSG: UTF-8 with optional BOM, octet fallback for non-UTF-8
- NILVALUE (`-`) handling for all optional fields
- Private SD-ID format: `name@<enterprise-number>`

---

### 2.3 RFC 5425 — TLS Transport Mapping (Full Coverage)

| Requirement | Implementation |
|-------------|---------------|
| TLS 1.2 mandatory | Configured as minimum version via rustls |
| TLS 1.3 recommended | Enabled by default alongside TLS 1.2 |
| Octet-counting framing (`MSG-LEN SP SYSLOG-MSG`) | `tokio-util` codec implementation for framing/deframing |
| Certificate-based mutual authentication | Configurable `mutual_auth = true` on TLS listeners |
| PKI path validation | Full PKIX certificate chain validation via rustls/webpki |
| Certificate fingerprint matching | SHA-256 fingerprint pinning supported via `fingerprints` config |
| Self-signed certificate support | Supported by providing the self-signed cert as the CA |
| Default port 6514 | Documented and used in all examples |
| Graceful connection draining on shutdown | Configurable `drain_timeout` with stop-accept-then-drain sequence |

---

### 2.4 RFC 5426 — UDP Transport (Full Coverage)

| Requirement | Implementation |
|-------------|---------------|
| One message per datagram | Each UDP recv produces exactly one message |
| IPv4: 480-octet minimum acceptance | Accepted; configurable maximum |
| IPv6: 1180-octet minimum acceptance | Accepted; configurable maximum |
| 2048-octet SHOULD support | Default `max_message_size = 8192` exceeds SHOULD |
| Mandatory UDP checksums | Enabled by kernel default; syslog-usg does not disable checksums |
| Default port 514 | Documented and used in all examples |
| Congestion awareness | Rate limiting and drop counting implemented |
| Configurable SO_RCVBUF | `recv_buffer_size` config option, default 4 MiB |

---

### 2.5 RFC 9662 — Cipher Suite Updates (Full Coverage)

| Requirement | Implementation |
|-------------|---------------|
| Mandatory: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | Configured as required cipher in rustls |
| Legacy: TLS_RSA_WITH_AES_128_CBC_SHA | Available for backward compatibility |
| ECDHE suite preferred over RSA-only | Cipher preference order enforced |
| 0-RTT (TLS 1.3 early data) prohibited | Explicitly disabled in rustls configuration |
| No export ciphers, NULL encryption, RC4, 3DES | None of these are available in rustls |

---

### 2.6 Known Limitations and Deviations

| Area | Limitation | Rationale |
|------|-----------|-----------|
| RFC 3164 | No strict compliance claim | RFC 3164 is informational, not standards-track. Real-world variation is extreme. Parser uses heuristics for best-effort compatibility. |
| RFC 5424 S6.2.3 TIME-SECFRAC | Maximum 6 digits parsed (microsecond precision in ABNF); internal representation stores nanoseconds via `time::OffsetDateTime` | The ABNF specifies `1*6DIGIT` for TIME-SECFRAC. Higher precision from internal processing is preserved but not expected from wire format. |
| RFC 3195 (BEEP) | Not implemented | No mature Rust BEEP library. Protocol complexity is high relative to adoption. |
| TLS cipher suites | Constrained to what rustls supports | rustls does not support all legacy cipher suites. This is a deliberate security trade-off. |
| Certificate revocation | OCSP stapling not supported in MVP | rustls CRL support is available; OCSP stapling is a future enhancement. |

---

### 2.7 Compliance Verification

Compliance is verified through multiple test layers:

**RFC Conformance Test Suite** (`tests/conformance/`):
- `rfc5424_valid.rs` -- Corpus of valid RFC 5424 messages derived from the ABNF grammar and RFC examples. Every MUST requirement has at least one positive test.
- `rfc5424_invalid.rs` -- Corpus of invalid messages that MUST be rejected in strict mode. Covers all parse error variants.
- `rfc3164_compat.rs` -- Best-effort parsing of common legacy formats from real-world vendors.

**Fuzz Testing** (`fuzz/`):
- `fuzz_parse_5424.rs` -- Continuous fuzzing of the RFC 5424 parser using `cargo-fuzz` / `libfuzzer`.
- `fuzz_parse_3164.rs` -- Continuous fuzzing of the legacy parser.
- Fuzz targets are run on schedule in CI and on-demand by developers.

**Integration Tests** (`tests/integration/`):
- `udp_ingest.rs` -- UDP send, parse verification, output verification.
- `tls_ingest.rs` -- TLS connection, mutual auth, send, parse, verify.
- `relay_pipeline.rs` -- Full pipeline: ingest, filter, route, output.

**Interoperability Testing**:
- Tested against rsyslog and syslog-ng as both sender and receiver.
- Tested with real-world structured data from Cisco, Palo Alto, Fortinet, and Linux auditd.
- Vendor-specific message corpus maintained in the test suite.

**Benchmarks** (`benches/syslog-bench/`):
- `parse_5424.rs` -- Criterion benchmarks for RFC 5424 parsing throughput.
- `parse_3164.rs` -- Criterion benchmarks for legacy parsing.
- `pipeline.rs` -- End-to-end pipeline latency and throughput.
- Performance tracked across commits for regression detection.

---

## 3. Operator Guide

### 3.1 Installation Methods

#### Binary Release

Download the pre-built static binary for your platform from the GitHub releases page:

```bash
# Linux x86_64
curl -LO https://github.com/<org>/syslog-usg/releases/latest/download/syslog-usg-linux-amd64.tar.gz
tar xzf syslog-usg-linux-amd64.tar.gz
sudo mv syslog-usg /usr/local/bin/
sudo chmod +x /usr/local/bin/syslog-usg

# Linux aarch64
curl -LO https://github.com/<org>/syslog-usg/releases/latest/download/syslog-usg-linux-arm64.tar.gz
tar xzf syslog-usg-linux-arm64.tar.gz
sudo mv syslog-usg /usr/local/bin/

# Verify
syslog-usg --version
```

#### Container Image

```bash
docker pull ghcr.io/<org>/syslog-usg:latest
docker run -d \
  --name syslog-usg \
  -p 514:514/udp \
  -p 6514:6514/tcp \
  -p 9090:9090/tcp \
  -v /etc/syslog-usg:/etc/syslog-usg:ro \
  ghcr.io/<org>/syslog-usg:latest
```

#### Build from Source

```bash
git clone https://github.com/<org>/syslog-usg.git
cd syslog-usg
cargo build --release
sudo cp target/release/syslog-usg /usr/local/bin/
```

---

### 3.2 CLI Usage

```
syslog-usg [OPTIONS] [COMMAND]

Commands:
  validate-config    Validate configuration file and exit

Options:
  -c, --config <PATH>    Configuration file path [default: /etc/syslog-usg/syslog-usg.toml]
  -V, --version          Print version information
  -h, --help             Print help
```

---

### 3.3 Configuration File Reference

Default location: `/etc/syslog-usg/syslog-usg.toml`

Override with `--config`:

```bash
syslog-usg --config /path/to/config.toml
```

Environment variable substitution is supported in all string values:
- `${VAR}` -- substitute the value of environment variable `VAR` (error if unset)
- `${VAR:-default}` -- substitute the value of `VAR`, or `default` if unset

#### 3.3.1 `[server]` Section

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `drain_timeout` | Duration string | `"5s"` | Maximum time to drain queues during graceful shutdown. |
| `pid_file` | Path (optional) | none | Write PID file at this path on startup. |
| `user` | String (optional) | none | Drop to this unprivileged user after binding ports. |
| `group` | String (optional) | none | Drop to this group after binding ports. |

#### 3.3.2 `[listeners.<name>]` Section

Each listener is a named TOML table under `[listeners]`. The `transport` key determines the listener type.

**UDP Listener:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `transport` | String | -- | Must be `"udp"`. |
| `bind` | SocketAddr | -- | Address and port to bind (e.g., `"0.0.0.0:514"`). |
| `recv_buffer_size` | Integer (bytes) | `4194304` (4 MiB) | Kernel SO_RCVBUF size. Larger values reduce drops under burst. |
| `max_message_size` | Integer (bytes) | `8192` | Maximum accepted message size. Messages exceeding this are dropped. |

**TCP Listener:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `transport` | String | -- | Must be `"tcp"`. A warning is emitted at startup when plain TCP is enabled. |
| `bind` | SocketAddr | -- | Address and port to bind. |
| `max_message_size` | Integer (bytes) | `8192` | Maximum accepted message size. |
| `max_connections` | Integer | `10000` | Maximum concurrent TCP connections. |

**TLS Listener:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `transport` | String | -- | Must be `"tls"`. |
| `bind` | SocketAddr | -- | Address and port to bind (e.g., `"0.0.0.0:6514"`). |
| `max_message_size` | Integer (bytes) | `8192` | Maximum accepted message size. |
| `max_connections` | Integer | `10000` | Maximum concurrent TLS connections. |
| `tls` | TLS config table | -- | See [TLS Configuration](#334-tls-configuration). |

#### 3.3.3 `[outputs.<name>]` Section

Each output is a named TOML table under `[outputs]`. The `type` key determines the output type.

**TLS Forward:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | String | -- | Must be `"forward_tls"`. |
| `target` | String | -- | Destination `host:port`. |
| `tls` | TLS config table | -- | See [TLS Configuration](#334-tls-configuration). |
| `queue` | Queue config table | defaults | See [Queue Configuration](#335-queue-configuration). |

**TCP Forward:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | String | -- | Must be `"forward_tcp"`. |
| `target` | String | -- | Destination `host:port`. |
| `queue` | Queue config table | defaults | See [Queue Configuration](#335-queue-configuration). |

**UDP Forward:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | String | -- | Must be `"forward_udp"`. |
| `target` | String | -- | Destination `host:port`. |
| `queue` | Queue config table | defaults | See [Queue Configuration](#335-queue-configuration). |

**File Output:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | String | -- | Must be `"file"`. |
| `path` | Path | -- | Output file path. |
| `format` | String | `"rfc5424"` | Output format: `"rfc5424"` or `"json"`. |
| `rotation.max_size` | String (optional) | none | Rotate when file exceeds this size (e.g., `"100MB"`). |
| `rotation.max_age` | String (optional) | none | Rotate when file age exceeds this duration (e.g., `"7d"`). |
| `rotation.max_files` | Integer (optional) | none | Maximum number of rotated files to retain. |
| `queue` | Queue config table | defaults | See [Queue Configuration](#335-queue-configuration). |

**Stdout Output:**

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | String | -- | Must be `"stdout"`. |
| `format` | String | `"rfc5424"` | Output format: `"rfc5424"` or `"json"`. |

#### 3.3.4 TLS Configuration

Used in TLS listeners and TLS forward outputs.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cert` | Path | -- | Path to PEM certificate file. Supports `${ENV_VAR}` substitution. |
| `key` | Path | -- | Path to PEM private key file. Supports `${ENV_VAR}` substitution. |
| `ca_cert` | Path (optional) | none | Path to CA certificate bundle for peer verification. |
| `mutual_auth` | Boolean | `false` | Require client certificates (mutual TLS). |
| `versions` | String array | `["1.2", "1.3"]` | Allowed TLS protocol versions. |
| `fingerprints` | String array | `[]` | Certificate fingerprints for pinning (SHA-256 hex strings). |

#### 3.3.5 Queue Configuration

Each output has an associated bounded queue.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `capacity` | Integer | `10000` | Maximum number of messages in the queue. |
| `overflow_policy` | String | `"drop_newest"` | Backpressure policy: `"drop_newest"`, `"drop_oldest"`, or `"block"`. |

Overflow policies:
- `drop_newest` -- Discard incoming messages when the queue is full. Counted in `syslog_messages_dropped_total{reason="queue_full"}`.
- `drop_oldest` -- Discard the oldest message in the queue to make room. Counted in the same metric.
- `block` -- Apply backpressure to the input stage. Use with caution: this can cause upstream listeners to stall.

#### 3.3.6 `[[routes]]` Section

Routes are defined as a TOML array of tables, evaluated in order.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | String | -- | Route name (used in logging and metrics). |
| `filter` | String (optional) | none | Name of a filter from `[filters]`. If omitted, matches all messages. |
| `outputs` | String array | -- | List of output names to send matched messages to. |

A message can match multiple routes (fan-out). The first matching route does not stop evaluation -- all routes are evaluated for every message.

#### 3.3.7 `[filters.<name>]` Section

Filters are named and referenced by routes.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `facilities` | String array | `[]` (all) | Facility names to include (e.g., `["kern", "auth", "local0"]`). Empty means all. |
| `min_severity` | String (optional) | none | Minimum severity level (inclusive). Messages with numeric severity <= this pass. Values: `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`. |
| `hostnames` | String array | `[]` (all) | Hostname glob patterns (e.g., `["web-*", "db-*"]`). Empty means all. |
| `app_names` | String array | `[]` (all) | App-name glob patterns. Empty means all. |
| `sd_ids` | String array | `[]` (none required) | Structured data IDs that must be present. Empty means no SD-ID requirement. |
| `negate` | Boolean | `false` | Invert the filter: exclude messages that match instead of including them. |

#### 3.3.8 `[metrics]` Section

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | Boolean | `true` | Enable the metrics HTTP server. |
| `bind` | SocketAddr | `"0.0.0.0:9090"` | Bind address for the metrics/health HTTP server. |
| `detailed_facility_severity` | Boolean | `true` | Include per-facility and per-severity labels on `syslog_messages_received_total`. Set to `false` to reduce cardinality. |

#### 3.3.9 `[logging]` Section

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | String | `"info"` | Log level for syslog-usg's own operational logs. Values: `trace`, `debug`, `info`, `warn`, `error`. |
| `format` | String | `"json"` | Log output format. Values: `"json"` (structured, recommended for production) or `"text"` (human-readable, for development). |

The log level can also be set via the `RUST_LOG` environment variable, which takes precedence over the config file when set. Supports per-module filtering (e.g., `RUST_LOG=syslog_transport=debug,syslog_relay=info`).

---

### 3.4 Example Configurations

#### 3.4.1 Basic UDP Collector

Receive syslog over UDP and write to a local file:

```toml
[server]
drain_timeout = "5s"

[listeners.udp_514]
transport = "udp"
bind = "0.0.0.0:514"
recv_buffer_size = 4194304
max_message_size = 8192

[outputs.local_file]
type = "file"
path = "/var/log/syslog-usg/messages.log"
format = "rfc5424"

[outputs.local_file.rotation]
max_size = "100MB"
max_age = "7d"
max_files = 10

[outputs.local_file.queue]
capacity = 10000
overflow_policy = "drop_oldest"

[[routes]]
name = "all_to_file"
outputs = ["local_file"]

[metrics]
bind = "127.0.0.1:9090"

[logging]
level = "info"
format = "json"
```

#### 3.4.2 TLS Relay with Mutual Authentication

Receive over TLS, forward to a central SIEM over TLS:

```toml
[server]
drain_timeout = "10s"
user = "syslog"
group = "syslog"

[listeners.tls_6514]
transport = "tls"
bind = "0.0.0.0:6514"
max_message_size = 8192
max_connections = 10000

[listeners.tls_6514.tls]
cert = "/etc/syslog-usg/tls/server.crt"
key = "/etc/syslog-usg/tls/server.key"
ca_cert = "/etc/syslog-usg/tls/ca.crt"
mutual_auth = true
versions = ["1.2", "1.3"]

[outputs.siem]
type = "forward_tls"
target = "siem.internal.example.com:6514"

[outputs.siem.tls]
cert = "/etc/syslog-usg/tls/client.crt"
key = "/etc/syslog-usg/tls/client.key"
ca_cert = "/etc/syslog-usg/tls/ca.crt"

[outputs.siem.queue]
capacity = 50000
overflow_policy = "drop_oldest"

[[routes]]
name = "forward_all"
outputs = ["siem"]

[metrics]
bind = "0.0.0.0:9090"

[logging]
level = "info"
format = "json"
```

#### 3.4.3 Multi-Output Fan-Out with Filtering

Receive from UDP and TLS, filter by severity, route to multiple outputs:

```toml
[server]
drain_timeout = "10s"

# ── Listeners ──

[listeners.udp_514]
transport = "udp"
bind = "0.0.0.0:514"
recv_buffer_size = 8388608
max_message_size = 8192

[listeners.tls_6514]
transport = "tls"
bind = "0.0.0.0:6514"
max_connections = 10000

[listeners.tls_6514.tls]
cert = "/etc/syslog-usg/tls/server.crt"
key = "/etc/syslog-usg/tls/server.key"
ca_cert = "/etc/syslog-usg/tls/ca.crt"
mutual_auth = true

# ── Filters ──

[filters.critical_only]
min_severity = "crit"

[filters.auth_events]
facilities = ["auth", "authpriv"]

[filters.exclude_debug]
min_severity = "debug"
negate = true

# ── Outputs ──

[outputs.siem_tls]
type = "forward_tls"
target = "siem.example.com:6514"

[outputs.siem_tls.tls]
cert = "/etc/syslog-usg/tls/client.crt"
key = "/etc/syslog-usg/tls/client.key"
ca_cert = "/etc/syslog-usg/tls/ca.crt"

[outputs.siem_tls.queue]
capacity = 50000
overflow_policy = "drop_oldest"

[outputs.security_file]
type = "file"
path = "/var/log/syslog-usg/security.log"
format = "json"

[outputs.security_file.rotation]
max_size = "500MB"
max_files = 30

[outputs.security_file.queue]
capacity = 20000
overflow_policy = "drop_oldest"

[outputs.all_logs_file]
type = "file"
path = "/var/log/syslog-usg/all.log"
format = "rfc5424"

[outputs.all_logs_file.rotation]
max_size = "1GB"
max_files = 7

[outputs.all_logs_file.queue]
capacity = 10000
overflow_policy = "drop_oldest"

# ── Routes ──

[[routes]]
name = "critical_to_siem"
filter = "critical_only"
outputs = ["siem_tls"]

[[routes]]
name = "auth_to_security_file"
filter = "auth_events"
outputs = ["security_file"]

[[routes]]
name = "all_except_debug"
filter = "exclude_debug"
outputs = ["all_logs_file"]

# ── Observability ──

[metrics]
bind = "0.0.0.0:9090"

[logging]
level = "info"
format = "json"
```

---

### 3.5 TLS Setup Guide

#### 3.5.1 Generating a Self-Signed CA and Server Certificate

For testing and internal deployments:

```bash
# Create CA private key and certificate
openssl req -x509 -newkey rsa:4096 -days 3650 \
  -keyout ca.key -out ca.crt -nodes \
  -subj "/CN=syslog-usg-ca/O=Internal"

# Create server private key and CSR
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=syslog.example.com/O=Internal"

# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:syslog.example.com,IP:10.0.0.1")

# Create client certificate for mutual TLS
openssl req -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr \
  -subj "/CN=syslog-client/O=Internal"

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365
```

#### 3.5.2 File Permissions

```bash
# Restrictive permissions on key files
chmod 600 /etc/syslog-usg/tls/*.key
chmod 644 /etc/syslog-usg/tls/*.crt
chown syslog:syslog /etc/syslog-usg/tls/*
```

syslog-usg validates file permissions at startup and emits a warning if key files are world-readable.

#### 3.5.3 Configuring Mutual TLS

Set `mutual_auth = true` on the TLS listener and provide a `ca_cert` that can validate client certificates:

```toml
[listeners.tls_6514.tls]
cert = "/etc/syslog-usg/tls/server.crt"
key = "/etc/syslog-usg/tls/server.key"
ca_cert = "/etc/syslog-usg/tls/ca.crt"
mutual_auth = true
```

For outputs connecting to a server that requires mutual TLS, provide client cert and key:

```toml
[outputs.siem.tls]
cert = "/etc/syslog-usg/tls/client.crt"
key = "/etc/syslog-usg/tls/client.key"
ca_cert = "/etc/syslog-usg/tls/ca.crt"
```

#### 3.5.4 Certificate Fingerprint Pinning

For environments where PKI path validation is not desired, pin specific certificate fingerprints:

```toml
[listeners.tls_6514.tls]
cert = "/etc/syslog-usg/tls/server.crt"
key = "/etc/syslog-usg/tls/server.key"
fingerprints = [
  "a1:b2:c3:d4:e5:f6:...:ff"  # SHA-256 fingerprint of allowed client cert
]
```

Get a certificate's SHA-256 fingerprint:

```bash
openssl x509 -in client.crt -noout -fingerprint -sha256
```

---

### 3.6 Metrics and Monitoring

#### 3.6.1 Available Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/metrics` | GET | Prometheus exposition format metrics |
| `/health` | GET | Returns `200 OK` when all listeners are bound and at least one output is reachable; `503` otherwise |
| `/ready` | GET | Returns `200 OK` when the server is ready to accept traffic; `503` during startup or drain |
| `/live` | GET | Returns `200 OK` when the process is alive; always `200` unless the process is unresponsive |

All endpoints are served on the metrics HTTP server (default `0.0.0.0:9090`).

#### 3.6.2 Key Metrics

**Counters** (monotonically increasing):

| Metric | Labels | Description |
|--------|--------|-------------|
| `syslog_messages_received_total` | `listener`, `transport`, `facility`, `severity` | Messages successfully parsed |
| `syslog_messages_forwarded_total` | `output`, `transport` | Messages successfully delivered |
| `syslog_messages_dropped_total` | `output`, `reason` | Messages dropped (`queue_full`, `output_error`, `filter`, `rate_limit`) |
| `syslog_parse_errors_total` | `listener`, `error_type` | Parse failures by error variant |
| `syslog_tls_handshake_errors_total` | `listener`, `error_type` | TLS handshake failures |
| `syslog_bytes_received_total` | `listener`, `transport` | Raw bytes received |
| `syslog_bytes_forwarded_total` | `output`, `transport` | Wire bytes sent |
| `syslog_config_reloads_total` | `result` | Config reload attempts (`success`/`failure`) |

**Gauges** (current values):

| Metric | Labels | Description |
|--------|--------|-------------|
| `syslog_connections_active` | `listener` | Current open TCP/TLS connections |
| `syslog_queue_depth` | `output` | Current messages in output queue |
| `syslog_queue_capacity` | `output` | Configured maximum queue size |
| `syslog_tls_cert_expiry_seconds` | `listener`, `subject` | Seconds until certificate expiry |
| `syslog_build_info` | `version`, `commit`, `rust_version` | Build metadata (always 1) |

**Histograms** (latency distributions):

| Metric | Labels | Description |
|--------|--------|-------------|
| `syslog_parse_duration_seconds` | `format` | Parse latency per message |
| `syslog_forward_duration_seconds` | `output` | Delivery latency per message |
| `syslog_message_size_bytes` | `listener` | Received message sizes |
| `syslog_queue_wait_duration_seconds` | `output` | Time messages spend in queue |

#### 3.6.3 Prometheus Scrape Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'syslog-usg'
    scrape_interval: 15s
    static_configs:
      - targets: ['syslog-usg-host:9090']
    metric_relabel_configs:
      # Optional: drop high-cardinality per-facility/severity breakdown
      - source_labels: [__name__]
        regex: 'syslog_messages_received_total'
        action: keep
```

#### 3.6.4 Recommended Alerting Rules

```yaml
groups:
  - name: syslog-usg
    rules:
      # Queue approaching capacity
      - alert: SyslogQueueNearFull
        expr: syslog_queue_depth / syslog_queue_capacity > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "syslog-usg queue {{ $labels.output }} is above 80% capacity"

      # Messages being dropped
      - alert: SyslogMessagesDropped
        expr: rate(syslog_messages_dropped_total[5m]) > 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "syslog-usg is dropping messages on output {{ $labels.output }}"

      # TLS certificate expiring soon
      - alert: SyslogTlsCertExpiringSoon
        expr: syslog_tls_cert_expiry_seconds < 604800  # 7 days
        labels:
          severity: warning
        annotations:
          summary: "TLS certificate for {{ $labels.subject }} expires in less than 7 days"

      # Process down
      - alert: SyslogUsgDown
        expr: up{job="syslog-usg"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "syslog-usg instance is unreachable"
```

#### 3.6.5 Grafana Dashboard

A recommended Grafana dashboard should include:

- **Throughput panel**: `rate(syslog_messages_received_total[1m])` by listener
- **Forward rate panel**: `rate(syslog_messages_forwarded_total[1m])` by output
- **Drop rate panel**: `rate(syslog_messages_dropped_total[1m])` by output and reason
- **Queue utilization panel**: `syslog_queue_depth / syslog_queue_capacity` by output
- **Parse latency panel**: `histogram_quantile(0.99, rate(syslog_parse_duration_seconds_bucket[5m]))` by format
- **Forward latency panel**: `histogram_quantile(0.99, rate(syslog_forward_duration_seconds_bucket[5m]))` by output
- **Active connections panel**: `syslog_connections_active` by listener
- **TLS cert expiry panel**: `syslog_tls_cert_expiry_seconds` by subject
- **Parse errors panel**: `rate(syslog_parse_errors_total[5m])` by error_type
- **Build info panel**: `syslog_build_info` displaying version and commit

---

### 3.7 Health Checks and Kubernetes Deployment

#### 3.7.1 Kubernetes Probe Configuration

```yaml
livenessProbe:
  httpGet:
    path: /live
    port: 9090
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /ready
    port: 9090
  initialDelaySeconds: 5
  periodSeconds: 5
  failureThreshold: 3

startupProbe:
  httpGet:
    path: /health
    port: 9090
  initialDelaySeconds: 2
  periodSeconds: 2
  failureThreshold: 15
```

#### 3.7.2 Probe Semantics

| Probe | Endpoint | Healthy When |
|-------|----------|-------------|
| Startup | `/health` | All listeners bound and at least one output reachable |
| Liveness | `/live` | Process is alive and responsive |
| Readiness | `/ready` | Ready to accept traffic; not draining |

---

### 3.8 Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| High `syslog_messages_dropped_total{reason="queue_full"}` | Downstream output is slower than input rate | Increase `queue.capacity`, add more output instances, or switch to `drop_oldest` policy |
| High `syslog_parse_errors_total{error_type="invalid_pri"}` | Sources sending malformed messages or non-syslog traffic on syslog port | Identify source IPs from logs; verify syslog client configuration |
| `syslog_tls_handshake_errors_total` increasing | Certificate mismatch, expired certificates, or protocol version mismatch | Check `error_type` label. Verify cert/key paths. Ensure client and server agree on TLS version. |
| Zero `syslog_messages_received_total` | Listener not bound, firewall blocking, or source not configured | Check startup logs for bind errors. Verify `ss -tulnp` shows syslog-usg listening. Check firewall rules. |
| High p99 `syslog_forward_duration_seconds` | Network latency to downstream, DNS resolution delays, or downstream overload | Check network path. Verify DNS resolution. Monitor downstream health. |
| `syslog_connections_active` at `max_connections` | Connection limit reached | Increase `max_connections` or investigate clients that hold connections open without sending. |
| Process exits immediately at startup | Configuration validation failure | Run `syslog-usg validate-config` for detailed error output. Check config file syntax and cross-references. |
| Memory usage growing unboundedly | Queue sizes too large or byte-level limits not configured | Review queue capacities. Ensure outputs are draining. Check for connection leaks. |

---

### 3.9 Graceful Shutdown and Reload

#### Graceful Shutdown

On receiving SIGTERM or SIGINT, syslog-usg:

1. Stops accepting new connections on all listeners
2. Finishes parsing in-flight messages
3. Drains all output queues (up to `drain_timeout`)
4. Closes all connections
5. Exits with code 0

If queues are not fully drained within `drain_timeout`, remaining messages are dropped and counted in `syslog_messages_dropped_total{reason="output_error"}`.

#### Configuration Reload

On receiving SIGHUP, syslog-usg:

1. Reads and validates the new configuration file
2. If validation fails: logs the error, increments `syslog_config_reloads_total{result="failure"}`, and continues with the current configuration
3. If validation succeeds: atomically swaps to the new pipeline -- new listeners/outputs are created, old ones are drained
4. Existing connections are not dropped during reload

```bash
# Trigger reload
kill -HUP $(cat /run/syslog-usg.pid)

# Or via systemd
systemctl reload syslog-usg
```

---

### 3.10 Performance Tuning

#### 3.10.1 UDP Receive Buffer

For high-throughput UDP ingestion, increase the kernel receive buffer:

```toml
[listeners.udp_514]
recv_buffer_size = 8388608  # 8 MiB
```

Also set the system-level maximum:

```bash
# /etc/sysctl.d/99-syslog-usg.conf
net.core.rmem_max = 16777216
net.core.rmem_default = 8388608
```

#### 3.10.2 Queue Sizing

Queue capacity should be based on expected burst duration and output throughput:

```
capacity = burst_rate_msg_per_sec * max_burst_duration_sec
```

For example, if you expect 50k msg/sec bursts lasting up to 10 seconds:

```toml
[outputs.siem.queue]
capacity = 500000
```

Monitor `syslog_queue_depth` relative to `syslog_queue_capacity` to right-size queues.

#### 3.10.3 Worker Threads

syslog-usg uses Tokio's multi-threaded runtime with work-stealing. By default, it uses one worker thread per CPU core. Override with the `TOKIO_WORKER_THREADS` environment variable:

```bash
TOKIO_WORKER_THREADS=8 syslog-usg --config /etc/syslog-usg/syslog-usg.toml
```

#### 3.10.4 File Descriptor Limits

For deployments with many concurrent TLS connections, increase the file descriptor limit:

```bash
# /etc/security/limits.d/syslog-usg.conf
syslog  soft  nofile  65536
syslog  hard  nofile  65536
```

Or in the systemd unit:

```ini
[Service]
LimitNOFILE=65536
```

---

## 4. Deployment Notes

### 4.1 systemd Service File

```ini
# /etc/systemd/system/syslog-usg.service
[Unit]
Description=syslog-usg - Production Syslog Server/Relay
Documentation=https://github.com/<org>/syslog-usg
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=syslog
Group=syslog
ExecStart=/usr/local/bin/syslog-usg --config /etc/syslog-usg/syslog-usg.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/syslog-usg
ReadOnlyPaths=/etc/syslog-usg
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

# Resource limits
LimitNOFILE=65536
LimitMEMLOCK=infinity

# Capabilities for binding privileged ports
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=syslog-usg

[Install]
WantedBy=multi-user.target
```

Install and enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now syslog-usg
sudo systemctl status syslog-usg
```

---

### 4.2 Docker / OCI Container

#### Dockerfile

```dockerfile
# ── Build stage ──
FROM rust:1.92-slim AS builder

WORKDIR /build
COPY . .
RUN apt-get update && apt-get install -y musl-tools && \
    rustup target add x86_64-unknown-linux-musl && \
    cargo build --release --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/syslog-usg

# ── Runtime stage ──
FROM scratch

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/syslog-usg /syslog-usg

# Default config location
VOLUME ["/etc/syslog-usg"]

# Syslog UDP
EXPOSE 514/udp
# Syslog TLS
EXPOSE 6514/tcp
# Metrics/Health HTTP
EXPOSE 9090/tcp

USER 65534:65534

ENTRYPOINT ["/syslog-usg"]
CMD ["--config", "/etc/syslog-usg/syslog-usg.toml"]
```

#### Docker Compose Example

```yaml
version: '3.8'
services:
  syslog-usg:
    image: ghcr.io/<org>/syslog-usg:latest
    ports:
      - "514:514/udp"
      - "6514:6514/tcp"
      - "9090:9090/tcp"
    volumes:
      - ./config:/etc/syslog-usg:ro
      - ./tls:/etc/syslog-usg/tls:ro
      - syslog-data:/var/log/syslog-usg
    restart: unless-stopped
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE

volumes:
  syslog-data:
```

---

### 4.3 Kubernetes Manifests

#### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: syslog-usg-config
  namespace: logging
data:
  syslog-usg.toml: |
    [server]
    drain_timeout = "10s"

    [listeners.udp_514]
    transport = "udp"
    bind = "0.0.0.0:514"
    recv_buffer_size = 8388608

    [listeners.tls_6514]
    transport = "tls"
    bind = "0.0.0.0:6514"
    max_connections = 10000

    [listeners.tls_6514.tls]
    cert = "/tls/tls.crt"
    key = "/tls/tls.key"
    ca_cert = "/tls/ca.crt"
    mutual_auth = true

    [outputs.siem]
    type = "forward_tls"
    target = "siem.logging.svc.cluster.local:6514"

    [outputs.siem.tls]
    cert = "/tls/client.crt"
    key = "/tls/client.key"
    ca_cert = "/tls/ca.crt"

    [outputs.siem.queue]
    capacity = 50000
    overflow_policy = "drop_oldest"

    [[routes]]
    name = "forward_all"
    outputs = ["siem"]

    [metrics]
    bind = "0.0.0.0:9090"

    [logging]
    level = "info"
    format = "json"
```

#### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: syslog-usg
  namespace: logging
  labels:
    app: syslog-usg
spec:
  replicas: 2
  selector:
    matchLabels:
      app: syslog-usg
  template:
    metadata:
      labels:
        app: syslog-usg
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        runAsGroup: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: syslog-usg
          image: ghcr.io/<org>/syslog-usg:latest
          args: ["--config", "/etc/syslog-usg/syslog-usg.toml"]
          ports:
            - name: syslog-udp
              containerPort: 514
              protocol: UDP
            - name: syslog-tls
              containerPort: 6514
              protocol: TCP
            - name: metrics
              containerPort: 9090
              protocol: TCP
          resources:
            requests:
              cpu: "500m"
              memory: "128Mi"
            limits:
              cpu: "4"
              memory: "512Mi"
          livenessProbe:
            httpGet:
              path: /live
              port: 9090
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 9090
            initialDelaySeconds: 5
            periodSeconds: 5
          startupProbe:
            httpGet:
              path: /health
              port: 9090
            initialDelaySeconds: 2
            periodSeconds: 2
            failureThreshold: 15
          volumeMounts:
            - name: config
              mountPath: /etc/syslog-usg
              readOnly: true
            - name: tls
              mountPath: /tls
              readOnly: true
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
              add:
                - NET_BIND_SERVICE
      volumes:
        - name: config
          configMap:
            name: syslog-usg-config
        - name: tls
          secret:
            secretName: syslog-usg-tls
```

#### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: syslog-usg
  namespace: logging
  labels:
    app: syslog-usg
spec:
  type: LoadBalancer
  ports:
    - name: syslog-udp
      port: 514
      targetPort: 514
      protocol: UDP
    - name: syslog-tls
      port: 6514
      targetPort: 6514
      protocol: TCP
    - name: metrics
      port: 9090
      targetPort: 9090
      protocol: TCP
  selector:
    app: syslog-usg
```

#### Metrics Service (for Prometheus ServiceMonitor)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: syslog-usg-metrics
  namespace: logging
  labels:
    app: syslog-usg
spec:
  ports:
    - name: metrics
      port: 9090
      targetPort: 9090
  selector:
    app: syslog-usg
  clusterIP: None
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: syslog-usg
  namespace: logging
spec:
  selector:
    matchLabels:
      app: syslog-usg
  endpoints:
    - port: metrics
      interval: 15s
      path: /metrics
```

---

### 4.4 Resource Recommendations

| Deployment Size | Throughput | CPU | Memory | File Descriptors |
|----------------|-----------|-----|--------|-----------------|
| Small (dev/test) | < 1k msg/sec | 1 core | 64 MB | 1024 |
| Medium (department) | 1k-10k msg/sec | 2 cores | 256 MB | 8192 |
| Large (data center) | 10k-100k msg/sec | 4 cores | 512 MB | 65536 |
| Very Large (multi-DC) | 100k+ msg/sec | 8 cores | 1 GB | 65536 |

Memory usage scales primarily with queue depth and concurrent connection count, not message throughput. Each queued message consumes approximately 1-2 KB. Each TLS connection holds approximately 10-20 KB of state.

---

### 4.5 Security Hardening

#### 4.5.1 Non-Root Execution

syslog-usg is designed to bind privileged ports (514) and then drop privileges. Two approaches:

**Approach A: Linux capabilities (preferred)**

```bash
# Set capability on the binary
sudo setcap cap_net_bind_service=+ep /usr/local/bin/syslog-usg
# Run as unprivileged user
sudo -u syslog syslog-usg --config /etc/syslog-usg/syslog-usg.toml
```

**Approach B: Privilege dropping in config**

```toml
[server]
user = "syslog"
group = "syslog"
```

syslog-usg binds all listeners as root, then drops to the specified user/group before processing any messages.

#### 4.5.2 File System Restrictions

- Configuration directory: read-only (`/etc/syslog-usg`)
- TLS key files: read-only, mode 600, owned by the syslog user
- Log directory: read-write (`/var/log/syslog-usg`)
- All other directories: no access needed

#### 4.5.3 Seccomp Profile

For container deployments, the default `RuntimeDefault` seccomp profile is sufficient. syslog-usg uses only standard system calls: `socket`, `bind`, `recvfrom`, `sendto`, `read`, `write`, `epoll`, `futex`, `mmap`, `mprotect`, `clock_gettime`.

#### 4.5.4 Network Policies

In Kubernetes, restrict network access:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: syslog-usg
  namespace: logging
spec:
  podSelector:
    matchLabels:
      app: syslog-usg
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Allow syslog traffic from any source
    - ports:
        - port: 514
          protocol: UDP
        - port: 6514
          protocol: TCP
    # Allow Prometheus scraping
    - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - port: 9090
          protocol: TCP
  egress:
    # Allow forwarding to SIEM
    - to:
        - namespaceSelector:
            matchLabels:
              name: logging
      ports:
        - port: 6514
          protocol: TCP
    # Allow DNS
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
```

---

### 4.6 High Availability Patterns

syslog-usg is stateless by design (in-memory queues only at MVP). This makes horizontal scaling straightforward:

#### UDP High Availability

Deploy multiple syslog-usg instances behind a network load balancer distributing UDP traffic. Each instance processes independently. Message ordering is best-effort for UDP regardless.

```
             ┌──────────────┐
UDP Sources ─┤  L4 Load     ├─── syslog-usg instance 1
             │  Balancer    ├─── syslog-usg instance 2
             │  (UDP 514)   ├─── syslog-usg instance 3
             └──────────────┘
```

#### TLS High Availability

Deploy behind a TCP load balancer (L4) or use DNS round-robin. TLS connections are persistent, so new connections are balanced across instances. Existing connections remain on their current instance.

#### Considerations

- No shared state between instances. Each instance maintains its own queues.
- If an instance fails, messages in its queue are lost (in-memory queues). Disk-backed queues (future) will address this.
- Monitor each instance independently via Prometheus.
- Use Kubernetes Deployment with `replicas > 1` for automatic failover.

---

### 4.7 Capacity Planning

**Messages per second to bytes per second:**

```
bytes/sec = messages/sec * avg_message_size_bytes
```

Typical syslog messages are 200-600 bytes. For planning, use 512 bytes as the average.

**Network bandwidth:**

| Throughput | Bandwidth (512-byte avg) |
|-----------|-------------------------|
| 10k msg/sec | ~5 MB/sec (~40 Mbps) |
| 50k msg/sec | ~25 MB/sec (~200 Mbps) |
| 100k msg/sec | ~50 MB/sec (~400 Mbps) |

**Queue memory:**

```
queue_memory = queue_capacity * avg_message_size_bytes * num_outputs
```

For 50k capacity across 3 outputs at 512 bytes average: ~75 MB.

**Disk I/O (file output):**

File output throughput is limited by disk write speed. At 100k msg/sec with 512-byte messages, expect ~50 MB/sec sustained write throughput. Use SSDs for high-throughput file output.

---

## 5. Developer Guide

### 5.1 Workspace Structure and Crate Responsibilities

```
syslog-usg/                    Workspace root
├── crates/
│   ├── syslog-proto/          Core protocol model (RFC 5424 types)
│   │                          - Facility, Severity, Pri enums
│   │                          - SyslogTimestamp (RFC 3339, nanosecond precision)
│   │                          - StructuredData, SdElement, SdParam types
│   │                          - SyslogMessage struct (the internal representation)
│   │                          - No dependencies on other workspace crates
│   │
│   ├── syslog-parse/          Parser and serializer
│   │                          - RFC 5424 parser (strict and lenient modes)
│   │                          - RFC 3164 legacy parser (best-effort)
│   │                          - Format auto-detection
│   │                          - Serializer (RFC 5424 wire format, JSON)
│   │                          - Depends on: syslog-proto
│   │
│   ├── syslog-transport/      Network listeners and senders
│   │                          - UDP listener (RFC 5426)
│   │                          - TLS listener and sender (RFC 5425)
│   │                          - TCP plain-text listener
│   │                          - Octet-counting framing codec
│   │                          - TLS configuration and certificate handling
│   │                          - Depends on: syslog-proto, syslog-parse
│   │
│   ├── syslog-relay/          Routing, filtering, fan-out pipeline
│   │                          - Pipeline construction and lifecycle
│   │                          - Filter stage (facility, severity, hostname, etc.)
│   │                          - Router stage (match rules to output names)
│   │                          - Bounded async queue with backpressure policies
│   │                          - Fan-out (clone message to multiple outputs)
│   │                          - Enrichment (add/modify structured data)
│   │                          - Depends on: syslog-proto
│   │
│   ├── syslog-config/         Configuration loading and validation
│   │                          - TOML deserialization (serde)
│   │                          - Environment variable substitution
│   │                          - Semantic validation (cross-field references)
│   │                          - No dependencies on other workspace crates
│   │
│   ├── syslog-observe/        Metrics, tracing, health
│   │                          - Prometheus metrics endpoint (HTTP)
│   │                          - tracing-subscriber initialization
│   │                          - Health/readiness/liveness state management
│   │                          - HTTP server (axum): /metrics, /health, /ready, /live
│   │                          - No dependencies on other workspace crates
│   │
│   ├── syslog-server/         Binary entrypoint
│   │                          - CLI parsing (clap)
│   │                          - Startup sequence and shutdown coordination
│   │                          - Signal handlers (SIGTERM, SIGINT, SIGHUP)
│   │                          - Hot config reload logic
│   │                          - Depends on: all other crates
│   │
│   ├── syslog-sign/           Signed syslog (RFC 5848) — placeholder
│   └── syslog-mgmt/           Management model (RFC 5427/9742) — placeholder
│
├── tests/
│   ├── integration/           End-to-end integration tests
│   └── conformance/           RFC conformance test corpus
│
├── benches/
│   └── syslog-bench/          Criterion benchmarks
│
├── fuzz/
│   └── fuzz_targets/          cargo-fuzz targets
│
├── examples/
│   └── syslog-usg.toml       Reference configuration
│
└── docs/                      Design documents (this directory)
```

**Dependency DAG:**

```
                    ┌──────────────┐
                    │ syslog-server│  (binary)
                    └──────┬───────┘
           ┌───────┬───────┼────────┬──────────┐
           │       │       │        │          │
           v       v       v        v          v
      syslog-   syslog-  syslog-  syslog-   syslog-
      transport  relay   config   observe    parse
           │       │                          │
           v       v                          v
      syslog-  syslog-                   syslog-
      parse    proto                     proto
           │
           v
      syslog-
      proto
```

Key design rules:
- `syslog-config` has no protocol dependency (plain data structs + serde).
- `syslog-observe` has no protocol dependency (metrics facade + HTTP server).
- `syslog-relay` depends only on `syslog-proto` (operates on parsed messages, not bytes).
- `syslog-transport` depends on `syslog-parse` (must frame and parse incoming bytes).

---

### 5.2 Building and Testing Locally

```bash
# Prerequisites: Rust 1.92+ (stable)
rustup update stable

# Build all crates
cargo build

# Build release binary
cargo build --release

# Run all tests
cargo test

# Run tests for a single crate
cargo test -p syslog-parse

# Run clippy (must pass with zero warnings)
cargo clippy --all-targets --all-features -- -D warnings

# Check formatting
cargo fmt --all -- --check

# Apply formatting
cargo fmt --all

# Dependency audit
cargo audit

# Run benchmarks
cargo bench -p syslog-bench

# Run fuzz tests (requires nightly)
cargo +nightly fuzz run fuzz_parse_5424 -- -max_total_time=60
```

---

### 5.3 Adding a New Output Type

To add a new output type (e.g., Kafka):

**Step 1: Add the output variant to `syslog-config/src/model.rs`:**

```rust
#[serde(rename = "kafka")]
Kafka {
    brokers: Vec<String>,
    topic: String,
    #[serde(default)]
    queue: QueueConfig,
},
```

**Step 2: Implement the output in `syslog-relay`:**

Create a new file `crates/syslog-relay/src/output_kafka.rs` implementing message delivery. The output must:

- Accept `SyslogMessage` values from a bounded async channel receiver
- Serialize messages to the target format
- Handle retries with exponential backoff
- Record metrics: `syslog_messages_forwarded_total`, `syslog_forward_duration_seconds`, `syslog_output_retries_total`
- Support graceful shutdown (drain receiver, flush pending sends)

**Step 3: Wire the output into the pipeline in `syslog-server`:**

In the startup sequence, match the new `OutputConfig::Kafka` variant and construct the output task.

**Step 4: Add tests:**

- Unit tests in `crates/syslog-relay/src/output_kafka.rs`
- Integration test in `tests/integration/` verifying end-to-end flow
- Config validation test in `crates/syslog-config/` for the new config variant

**Step 5: Document:**

- Add the new output to the configuration reference in this document
- Update the example configuration

---

### 5.4 Adding a New Filter

Filters are defined in `crates/syslog-relay/src/filter.rs`. To add a new filter criterion (e.g., filtering by MSG body regex):

**Step 1: Extend `FilterConfig` in `syslog-config/src/model.rs`:**

```rust
pub struct FilterConfig {
    // ... existing fields ...

    /// Regex pattern to match against MSG body.
    pub msg_pattern: Option<String>,
}
```

**Step 2: Extend the filter evaluation in `syslog-relay/src/filter.rs`:**

Add a match arm that compiles and evaluates the regex against `SyslogMessage.msg`. Compile the regex once at pipeline construction time, not per-message.

**Step 3: Add tests:**

- Unit tests with messages that match and do not match the pattern
- Test that an invalid regex in config produces a validation error at startup

---

### 5.5 RFC Compliance Testing Approach

Every RFC compliance claim must be traceable to a test. The approach:

1. **Extract requirements**: For each RFC, list all MUST, SHOULD, and MAY requirements with section references (done in Phase 02).

2. **Write positive tests**: For each MUST and SHOULD requirement, write at least one test that verifies correct behavior when the requirement is satisfied. Place in `tests/conformance/`.

3. **Write negative tests**: For each MUST requirement, write at least one test that verifies rejection of invalid input in strict mode. Place in `tests/conformance/`.

4. **Tag tests with RFC references**: Use test function names and comments to link tests to RFC section numbers:

```rust
#[test]
fn rfc5424_s6_1_pri_range_0_to_191() {
    // RFC 5424 Section 6.1 MUST: Facility values MUST be in the range of 0 to 23
    // PRI = facility * 8 + severity, max = 23 * 8 + 7 = 191
    assert!(parse_strict(b"<191>1 ...").is_ok());
    assert!(parse_strict(b"<192>1 ...").is_err());
}
```

5. **Fuzz for edge cases**: Fuzz testing catches requirements violations that manual test cases miss. Run `cargo-fuzz` targets regularly.

6. **Interop testing**: Test against real syslog implementations to verify practical compatibility beyond RFC letter compliance.

---

### 5.6 Code Style

**Enforced by CI:**

- `cargo fmt --all -- --check` -- All code must be formatted with `rustfmt`
- `cargo clippy --all-targets --all-features -- -D warnings` -- Zero clippy warnings
- `cargo audit` -- No known vulnerabilities in dependencies

**Conventions:**

- `#![forbid(unsafe_code)]` at the root of every library crate. Unsafe is only permitted in the binary crate with explicit justification and documentation.
- Use `thiserror` for library error types, `anyhow` only in the binary entrypoint.
- No `unwrap()` on fallible operations in hot paths. Use `expect()` with a descriptive message only when the condition is provably infallible.
- Mark functions with `#[must_use]` when returning important values.
- All bounded queues and channels -- no unbounded buffers anywhere.
- RFC compliance comments on protocol-relevant code:
  ```rust
  // RFC 5424 S6.1 MUST: PRI value MUST be 1-3 digits in range 0-191
  ```
- Feature flags only for compile-time complexity reduction, not runtime branching.

---

### 5.7 PR and Review Process

1. **Branch naming**: `feature/<description>`, `fix/<description>`, `refactor/<description>`
2. **PR requirements before merge**:
   - All CI checks pass (tests, clippy, fmt, audit)
   - At least one approving review
   - No unresolved review comments
   - PR description explains the "why", not just the "what"
3. **RFC-related changes**: Must include the RFC section reference and corresponding test(s) in the PR
4. **Performance-sensitive changes**: Must include benchmark results (before/after) if touching parser, pipeline, or transport code
5. **Configuration changes**: Must update the configuration reference documentation and include a config validation test

---

## 6. Future Enhancements

### 6.1 Phase 2 -- Security and Integrity

| Feature | Description | RFC | Priority |
|---------|-------------|-----|----------|
| **DTLS Transport** | Datagram TLS for secure UDP transport. DTLS 1.2 mandatory, DTLS 1.3 recommended. Shares port 6514 with TLS. RFC 9662 cipher suite requirements apply. DTLS 1.0 is prohibited. | RFC 6012 + RFC 9662 | High |
| **Signed Syslog Messages** | Generate and verify cryptographic signature blocks over groups of syslog messages. SHA-256 hash, OpenPGP DSA signatures. Certificate block distribution. Enables tamper detection and non-repudiation. | RFC 5848 | Medium |
| **Message Sequencing and Loss Detection** | Detect missing, reordered, and replayed messages using RFC 5848 signature block sequence numbers. Complements signed syslog for audit-grade pipelines. | RFC 5848 | Medium |

**Implementation notes for DTLS**: Requires a Rust DTLS library (potentially via `rustls` DTLS support if available, or `openssl-sys` feature gate). The `syslog-transport` crate will need a new `DtlsListener` and `DtlsSender` behind the existing trait interface. Configuration will mirror TLS configuration with DTLS-specific options.

**Implementation notes for Signed Syslog**: The `syslog-sign` crate (currently a placeholder) will implement signature block generation, verification, and certificate block handling. Integration point is between the parse stage and the filter stage in the relay pipeline.

---

### 6.2 Phase 3 -- Alarms and SNMP Integration

| Feature | Description | RFC | Priority |
|---------|-------------|-----|----------|
| **Alarm Structured Data** | Parse and generate alarm SD-ELEMENTs: `resource`, `probableCause`, `perceivedSeverity`, `eventType`, `trendIndication`. Map ITU-T X.733 alarm severity levels to syslog severity. | RFC 5674 | Medium |
| **SNMP-to-Syslog Mapping** | Receive SNMP notifications (traps/informs) and translate them to RFC 5424 syslog messages with the `snmp` SD-ID. Support for SNMPv3 context engine ID and context name. | RFC 5675 | Low |
| **Syslog-to-SNMP Mapping** | Translate received syslog messages to SNMP notifications via the SYSLOG-MSG-MIB. Configurable notification generation based on facility/severity thresholds. | RFC 5676 | Low |

**Implementation notes for SNMP**: Requires evaluation of Rust SNMP crates (`snmp`, `rasn`). May require custom implementation for SNMPv3 support. The SNMP integration will be implemented as new input/output types in the pipeline.

---

### 6.3 Phase 4 -- Management Plane

| Feature | Description | RFC | Priority |
|---------|-------------|-----|----------|
| **SNMP MIB: Textual Conventions** | Expose syslog facility and severity as SNMP textual conventions for network management system integration. Enables NMS platforms to query syslog status. | RFC 5427 | Low |
| **YANG Data Model** | Implement the `ietf-syslog` YANG module for NETCONF/RESTCONF-based configuration management. Enables programmatic configuration of console, file, and remote logging via standard network management protocols. | RFC 9742 | Low |

**Implementation notes for YANG**: The `syslog-mgmt` crate (currently a placeholder) will implement the YANG model. This likely requires a RESTCONF HTTP endpoint in `syslog-observe` and a YANG-to-config translation layer. Evaluate `yang2` or similar Rust crates for YANG model parsing.

---

### 6.4 Phase 5 -- Operational Excellence

| Feature | Description | Priority |
|---------|-------------|----------|
| **Disk-Backed Persistent Queue** | WAL-based durable queue with crash recovery. Configurable memory/disk ratio. Messages spill to disk when in-memory queue is full. Automatic recovery on restart ensures no message loss during process restart. | High |
| **Clustering and HA** | Active-passive failover with shared queue state. Leader election via Raft or external coordinator (etcd). Enables zero-downtime upgrades and automatic failover. | Medium |
| **Output Plugins: Kafka** | Apache Kafka producer output. Messages published to configurable topics with key-based partitioning. At-least-once delivery semantics. | High |
| **Output Plugins: S3/Object Storage** | Batch messages and upload to S3-compatible object storage. Configurable batching by time and size. Parquet or JSON line format. | Medium |
| **Output Plugins: Elasticsearch** | Bulk index syslog messages to Elasticsearch. Configurable index naming, field mapping, and bulk size. | Medium |
| **Output Plugins: HTTP/Webhook** | Generic HTTP POST output for webhook-based integrations. Configurable URL, headers, and body template. | Low |
| **CEF/LEEF Output** | ArcSight Common Event Format and QRadar LEEF output serialization for SIEM integration. | Low |
| **Regex Field Extraction** | Extract fields from unstructured MSG body using configurable regex patterns. Populate structured data elements from extracted fields. | Medium |
| **Web UI** | Lightweight operational dashboard: pipeline status visualization, real-time metrics, configuration viewer, and message flow inspector. | Low |

---

### 6.5 Roadmap Summary

```
MVP (Current)
├── RFC 5424 full compliance
├── RFC 5425 TLS transport
├── RFC 5426 UDP transport
├── RFC 9662 cipher suite updates
├── RFC 3164 legacy compatibility
├── TOML configuration
├── Prometheus metrics
├── Health endpoints
└── Bounded in-memory queues

Phase 2 — Security & Integrity
├── RFC 6012 DTLS transport
├── RFC 5848 signed syslog
└── Message sequencing / loss detection

Phase 3 — Alarms & SNMP
├── RFC 5674 alarm structured data
├── RFC 5675 SNMP-to-syslog
└── RFC 5676 syslog-to-SNMP

Phase 4 — Management Plane
├── RFC 5427 SNMP textual conventions
└── RFC 9742 YANG data model

Phase 5 — Operational Excellence
├── Disk-backed persistent queues
├── Clustering and HA
├── Output plugins (Kafka, S3, Elasticsearch)
├── CEF/LEEF output formats
├── Regex field extraction
└── Web UI
```
