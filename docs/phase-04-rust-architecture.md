# Phase 04 — Rust Backend Architecture

## syslog-usg: Workspace Layout, Crate Boundaries, and Design Decisions

**Version:** 1.0.0-draft
**Date:** 2026-03-11
**Status:** Draft

---

## Table of Contents

1. [Cargo Workspace Layout](#1-cargo-workspace-layout)
2. [Crate Dependency Graph](#2-crate-dependency-graph)
3. [External Dependency Recommendations](#3-external-dependency-recommendations)
4. [Error Model](#4-error-model)
5. [Configuration Model](#5-configuration-model)
6. [Async/Concurrency Strategy](#6-asyncconcurrency-strategy)
7. [Trait Boundaries](#7-trait-boundaries)
8. [Memory Model](#8-memory-model)
9. [Initial File Tree](#9-initial-file-tree)

---

## 1. Cargo Workspace Layout

```
syslog-usg/
├── Cargo.toml                          # Workspace root manifest
├── Cargo.lock
├── rust-toolchain.toml                 # MSRV pinning: 1.92
├── rustfmt.toml
├── clippy.toml
├── deny.toml                           # cargo-deny configuration
├── CLAUDE.md
├── docs/
│   ├── phase-01-requirements.md
│   └── phase-04-rust-architecture.md
├── crates/
│   ├── syslog-proto/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # #![forbid(unsafe_code)], re-exports
│   │       ├── facility.rs             # Facility enum (0-23), Display, FromPrimitive
│   │       ├── severity.rs             # Severity enum (0-7), Display, Ord
│   │       ├── pri.rs                  # Pri value: encode/decode facility*8+severity
│   │       ├── timestamp.rs            # SyslogTimestamp: RFC 3339, nanosecond precision
│   │       ├── structured_data.rs      # StructuredData, SdElement, SdParam types
│   │       ├── message.rs              # SyslogMessage: the canonical message type
│   │       ├── message_id.rs           # MessageId newtype, validation
│   │       ├── hostname.rs             # Hostname newtype, validation (FQDN, IPv4, IPv6)
│   │       ├── app_name.rs             # AppName newtype, validation (printusascii, 1-48)
│   │       ├── proc_id.rs              # ProcId newtype, validation (printusascii, 1-128)
│   │       └── sd_id.rs                # SdId: registered vs enterprise-number format
│   │
│   ├── syslog-parse/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # #![forbid(unsafe_code)], public API
│   │       ├── rfc5424/
│   │       │   ├── mod.rs              # RFC 5424 parser module
│   │       │   ├── parser.rs           # Full 5424 ABNF parser
│   │       │   ├── header.rs           # PRI, VERSION, TIMESTAMP, HOSTNAME, etc.
│   │       │   ├── structured_data.rs  # SD-ELEMENT, SD-PARAM parsing with escaping
│   │       │   ├── msg.rs              # MSG body, BOM detection
│   │       │   └── serializer.rs       # SyslogMessage -> RFC 5424 wire format
│   │       ├── rfc3164/
│   │       │   ├── mod.rs              # RFC 3164 legacy parser module
│   │       │   ├── parser.rs           # Best-effort BSD syslog parsing
│   │       │   └── heuristics.rs       # Timestamp format guessing, hostname extraction
│   │       ├── detect.rs               # Auto-detect 5424 vs 3164 by version field
│   │       ├── octet_counting.rs       # MSG-LEN SP SYSLOG-MSG framing (RFC 5425)
│   │       ├── parse_mode.rs           # Strict vs Lenient parsing mode
│   │       └── error.rs                # ParseError enum
│   │
│   ├── syslog-transport/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # #![forbid(unsafe_code)], re-exports
│   │       ├── udp/
│   │       │   ├── mod.rs
│   │       │   ├── listener.rs         # UdpListener: bind, recv_from, parse dispatch
│   │       │   └── sender.rs           # UdpSender: sendto with rate awareness
│   │       ├── tcp/
│   │       │   ├── mod.rs
│   │       │   ├── listener.rs         # TcpListener: accept loop, connection tasks
│   │       │   ├── connection.rs       # Per-connection read loop, octet-counting decode
│   │       │   └── sender.rs           # TcpSender: connect, octet-counting encode
│   │       ├── tls/
│   │       │   ├── mod.rs
│   │       │   ├── listener.rs         # TlsListener: TLS accept, handshake, dispatch
│   │       │   ├── connection.rs       # TLS connection read loop
│   │       │   ├── sender.rs           # TlsSender: TLS connect, octet-counting write
│   │       │   ├── config.rs           # TLS configuration builder (rustls ServerConfig)
│   │       │   └── certs.rs            # Certificate loading, validation, fingerprint
│   │       ├── framing.rs              # Shared octet-counting frame codec
│   │       └── error.rs                # TransportError enum
│   │
│   ├── syslog-relay/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # #![forbid(unsafe_code)], pipeline construction
│   │       ├── pipeline.rs             # Pipeline: wire stages together, lifecycle
│   │       ├── filter.rs               # Filter stage: facility, severity, hostname, app-name, SD-ID
│   │       ├── router.rs               # Router stage: match rules -> output names
│   │       ├── queue.rs                # Bounded async queue with backpressure policies
│   │       ├── backpressure.rs         # BackpressurePolicy enum and implementation
│   │       ├── fanout.rs               # Fan-out: clone message to multiple outputs
│   │       ├── enrichment.rs           # Add/modify structured data elements in transit
│   │       └── error.rs                # RelayError enum
│   │
│   ├── syslog-config/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # #![forbid(unsafe_code)], public API
│   │       ├── model.rs                # All config structs (serde-derived)
│   │       ├── loader.rs               # File read, env var substitution, TOML parse
│   │       ├── validation.rs           # Semantic validation (cross-field, references)
│   │       ├── env_subst.rs            # ${VAR} and ${VAR:-default} expansion
│   │       ├── defaults.rs             # Default values for all config fields
│   │       └── error.rs                # ConfigError enum
│   │
│   ├── syslog-observe/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # #![forbid(unsafe_code)], init functions
│   │       ├── metrics.rs              # Metric names, registration, helpers
│   │       ├── tracing_setup.rs        # tracing-subscriber init, JSON formatter
│   │       ├── health.rs               # Health/readiness state management
│   │       └── server.rs               # HTTP server: /metrics, /health, /ready, /live
│   │
│   ├── syslog-server/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs                 # Entrypoint: CLI parse, config load, run
│   │       ├── cli.rs                  # clap argument definitions
│   │       ├── lifecycle.rs            # Startup sequence, shutdown coordination
│   │       ├── signals.rs              # SIGTERM, SIGINT, SIGHUP handlers
│   │       └── reload.rs               # Hot config reload logic
│   │
│   ├── syslog-sign/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                  # #![forbid(unsafe_code)], placeholder
│   │
│   └── syslog-mgmt/
│       ├── Cargo.toml
│       └── src/
│           └── lib.rs                  # #![forbid(unsafe_code)], placeholder
│
├── tests/
│   ├── integration/
│   │   ├── udp_ingest.rs              # UDP send -> verify parse -> verify output
│   │   ├── tls_ingest.rs              # TLS connect -> send -> verify
│   │   ├── tcp_ingest.rs              # Plain TCP -> send -> verify
│   │   ├── relay_pipeline.rs          # Full pipeline: ingest -> filter -> route -> output
│   │   ├── config_reload.rs           # SIGHUP reload without message loss
│   │   └── backpressure.rs            # Verify backpressure policies under load
│   └── conformance/
│       ├── rfc5424_valid.rs           # Corpus of valid RFC 5424 messages
│       ├── rfc5424_invalid.rs         # Corpus of invalid messages (strict reject)
│       └── rfc3164_compat.rs          # Legacy format best-effort parsing
│
├── benches/
│   └── syslog-bench/
│       ├── Cargo.toml
│       └── src/
│           └── lib.rs                  # Placeholder (benchmarks use benches/ dir)
│       └── benches/
│           ├── parse_5424.rs           # criterion: RFC 5424 parsing throughput
│           ├── parse_3164.rs           # criterion: RFC 3164 parsing throughput
│           ├── serialize.rs            # criterion: message serialization
│           └── pipeline.rs             # criterion: end-to-end pipeline
│
├── fuzz/
│   ├── Cargo.toml
│   └── fuzz_targets/
│       ├── fuzz_parse_5424.rs
│       └── fuzz_parse_3164.rs
│
└── examples/
    └── syslog-usg.toml                # Reference configuration file
```

---

## 2. Crate Dependency Graph

The DAG is intentionally shallow to keep compile times low and enforce separation of concerns. Arrows indicate "depends on."

```
                    ┌──────────────┐
                    │ syslog-server│  (binary)
                    └──────┬───────┘
           ┌───────┬───────┼────────┬──────────┐
           │       │       │        │          │
           ▼       ▼       ▼        ▼          ▼
      syslog-   syslog-  syslog-  syslog-   syslog-
      transport  relay   config   observe    parse
           │       │                          │
           │       │                          │
           ▼       ▼                          ▼
      syslog-  syslog-                   syslog-
      parse    proto                     proto
           │
           ▼
      syslog-
      proto
```

Expressed as a table:

| Crate | Internal Dependencies |
|-------|----------------------|
| `syslog-proto` | (none) |
| `syslog-parse` | `syslog-proto` |
| `syslog-transport` | `syslog-proto`, `syslog-parse` |
| `syslog-relay` | `syslog-proto` |
| `syslog-config` | (none — defines its own config structs, no protocol dependency) |
| `syslog-observe` | (none — defines metrics and tracing setup independently) |
| `syslog-server` | `syslog-proto`, `syslog-parse`, `syslog-transport`, `syslog-relay`, `syslog-config`, `syslog-observe` |
| `syslog-sign` | `syslog-proto` (future) |
| `syslog-mgmt` | `syslog-proto` (future) |

Design rationale:

- **`syslog-config` is independent** — Config structs are plain data with serde derives. The server crate bridges config types to runtime types, keeping config free of protocol knowledge.
- **`syslog-observe` is independent** — Metrics registration and tracing setup have no protocol dependency. Crates that record metrics use the `metrics` facade crate directly.
- **`syslog-relay` depends only on `syslog-proto`** — The relay pipeline operates on `SyslogMessage` values. It does not parse or serialize; those are transport concerns.
- **`syslog-transport` depends on `syslog-parse`** — Transport listeners must frame and parse incoming bytes into messages. This is the only crate that bridges raw I/O to parsed messages.

---

## 3. External Dependency Recommendations

Every dependency must justify its inclusion. The project follows a minimal-dependency philosophy: if the standard library can do it in under 50 lines, do not add a crate.

### 3.1 Runtime and Async

| Crate | Version | Used By | Justification |
|-------|---------|---------|---------------|
| `tokio` | 1.x | `syslog-transport`, `syslog-relay`, `syslog-server` | The async runtime. Features: `rt-multi-thread`, `net`, `io-util`, `sync`, `signal`, `macros`, `time`. Tokio is the only production-grade multi-threaded async runtime in the Rust ecosystem. Its work-stealing scheduler maps directly to the requirements (vertical scaling, 100k msg/sec). No alternative has comparable maturity or ecosystem support. |
| `tokio-util` | 0.7.x | `syslog-transport` | Provides `codec` module for framing (LengthDelimitedCodec basis for octet-counting). Avoids reimplementing buffered codec state machines. |

### 3.2 TLS

| Crate | Version | Used By | Justification |
|-------|---------|---------|---------------|
| `tokio-rustls` | 0.26.x | `syslog-transport` | Async TLS integration wrapping rustls for Tokio. No OpenSSL system dependency required. |
| `rustls` | 0.23.x | `syslog-transport` | Pure-Rust TLS implementation. Supports TLS 1.2 and 1.3, the cipher suites mandated by RFC 9662, and certificate-based mutual authentication. Using `ring` as the crypto backend (default). Chosen over OpenSSL for: memory safety, no system library dependency, reproducible builds, static linking compatibility. |
| `rustls-pemfile` | 2.x | `syslog-transport` | PEM certificate and key file parsing. Small, focused crate maintained by the rustls team. |
| `webpki-roots` | 0.26.x | `syslog-transport` | Mozilla root CA bundle embedded at compile time. Provides a reasonable default trust store without requiring system CA configuration. |

### 3.3 Buffers and Serialization

| Crate | Version | Used By | Justification |
|-------|---------|---------|---------------|
| `bytes` | 1.x | `syslog-proto`, `syslog-parse`, `syslog-transport` | Reference-counted byte buffer (`Bytes`) enables zero-copy message passing through the pipeline. A parsed message can hold `Bytes` slices into the original network buffer without copying. This is critical for the p50 < 2us parse latency target. Standard library has no equivalent. |
| `smallvec` | 1.x | `syslog-proto` | Stack-allocated small vectors for structured data elements. Most messages have 0-3 SD-ELEMENTs; `SmallVec<[SdElement; 4]>` avoids heap allocation in the common case. Measured impact on parse benchmarks justifies the dependency. |

### 3.4 Configuration

| Crate | Version | Used By | Justification |
|-------|---------|---------|---------------|
| `serde` | 1.x | `syslog-config` | The standard Rust serialization framework. Required for TOML deserialization. Features: `derive`. |
| `toml` | 0.8.x | `syslog-config` | TOML parser and deserializer. The project requires TOML configuration per requirements. This is the canonical TOML crate. |

### 3.5 Logging and Observability

| Crate | Version | Used By | Justification |
|-------|---------|---------|---------------|
| `tracing` | 0.1.x | all crates | Structured, span-based instrumentation. Used as the logging facade throughout the codebase. Chosen over `log` because: spans enable per-message trace context through the pipeline, structured fields enable JSON output, and async-aware span entry/exit is built in. |
| `tracing-subscriber` | 0.3.x | `syslog-observe` | Subscriber implementation with JSON formatting, environment-based filtering, and layered composition. Features: `json`, `env-filter`. |
| `metrics` | 0.24.x | all crates that record metrics | Lightweight metrics facade. Crates call `metrics::counter!()`, `metrics::gauge!()`, `metrics::histogram!()` without knowing the exporter. Decouples instrumentation from export. |
| `metrics-exporter-prometheus` | 0.16.x | `syslog-observe` | Prometheus exposition format exporter. Renders `/metrics` endpoint. The only exporter needed for MVP. |

### 3.6 Timestamps

| Crate | Version | Used By | Justification |
|-------|---------|---------|---------------|
| `time` | 0.3.x | `syslog-proto`, `syslog-parse` | **Recommended over `chrono`.** Rationale: (1) `time` has no dependency on `libc` for formatting/parsing, reducing the attack surface and improving musl compatibility; (2) `time` supports nanosecond precision natively via `OffsetDateTime`; (3) `time` has a smaller dependency tree; (4) `chrono` historically had soundness issues with its `Local::now()` in multithreaded contexts (though now fixed, the smaller footprint of `time` is preferred). Features: `parsing`, `formatting`, `serde`. |

### 3.7 Error Handling

| Crate | Version | Used By | Justification |
|-------|---------|---------|---------------|
| `thiserror` | 2.x | all library crates | Derive macro for `std::error::Error` on per-crate error enums. Eliminates boilerplate while keeping error types concrete and matchable. Zero runtime cost. |
| `anyhow` | 1.x | `syslog-server` only | Erased error type for the binary entrypoint where errors are reported to operators, not matched programmatically. Used only in `main()` and CLI-facing code. Never exposed in library APIs. |

### 3.8 CLI

| Crate | Version | Used By | Justification |
|-------|---------|---------|---------------|
| `clap` | 4.x | `syslog-server` | CLI argument parsing with derive API. Provides `--config`, `--validate-config`, `--version`, `--help`. Clap is the standard Rust CLI framework; alternatives (argh, lexopt) lack feature parity for subcommands and shell completions. Features: `derive`. |

### 3.9 HTTP (Admin/Metrics Server)

| Crate | Version | Used By | Justification |
|-------|---------|---------|---------------|
| `axum` | 0.8.x | `syslog-observe` | **Recommended over raw `hyper`.** The admin HTTP server serves 4 endpoints (`/metrics`, `/health`, `/ready`, `/live`). Axum provides routing, extractors, and response types with minimal boilerplate over hyper. It is maintained by the Tokio team, ensuring tight runtime integration. Raw hyper would require reimplementing routing and response construction for no benefit. The admin server is not performance-critical (low request rate), so axum's minimal overhead is irrelevant. |

### 3.10 Summary: Full Dependency Count

| Category | Crates | Count |
|----------|--------|-------|
| Runtime | tokio, tokio-util | 2 |
| TLS | tokio-rustls, rustls, rustls-pemfile, webpki-roots | 4 |
| Buffers | bytes, smallvec | 2 |
| Config | serde, toml | 2 |
| Observability | tracing, tracing-subscriber, metrics, metrics-exporter-prometheus | 4 |
| Time | time | 1 |
| Errors | thiserror, anyhow | 2 |
| CLI | clap | 1 |
| HTTP | axum | 1 |
| **Total direct** | | **19** |

All dependencies are well-maintained, widely used, and auditable via `cargo audit` and `cargo deny`.

---

## 4. Error Model

### 4.1 Design Principles

1. **Per-crate concrete error enums** — Every library crate defines its own error type. Errors are matchable and inspectable by callers.
2. **`thiserror` for derivation** — All library error types derive `thiserror::Error` and `Debug`.
3. **`anyhow` only at the binary boundary** — `syslog-server/src/main.rs` uses `anyhow::Result` for startup errors reported to the operator. Library code never uses `anyhow`.
4. **No panics on the hot path** — All fallible operations return `Result`. `unwrap()` is permitted only in tests and provably-infallible contexts (e.g., after a length check).
5. **Errors carry context** — Parsing errors include byte offset and expected/found values. Transport errors include the remote address. Config errors include the TOML key path.
6. **Errors are `Send + Sync + 'static`** — Required for propagation across async task boundaries.

### 4.2 Per-Crate Error Types

#### `syslog-parse::ParseError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid PRI value at byte {offset}: expected 1-3 digits in range 0-191, found {found:?}")]
    InvalidPri { offset: usize, found: String },

    #[error("invalid version at byte {offset}: expected '1', found {found:?}")]
    InvalidVersion { offset: usize, found: u8 },

    #[error("invalid timestamp at byte {offset}: {reason}")]
    InvalidTimestamp { offset: usize, reason: String },

    #[error("invalid hostname at byte {offset}: {reason}")]
    InvalidHostname { offset: usize, reason: String },

    #[error("invalid app-name at byte {offset}: {reason}")]
    InvalidAppName { offset: usize, reason: String },

    #[error("invalid proc-id at byte {offset}: {reason}")]
    InvalidProcId { offset: usize, reason: String },

    #[error("invalid msg-id at byte {offset}: {reason}")]
    InvalidMsgId { offset: usize, reason: String },

    #[error("invalid structured data at byte {offset}: {reason}")]
    InvalidStructuredData { offset: usize, reason: String },

    #[error("invalid SD-ID at byte {offset}: {reason}")]
    InvalidSdId { offset: usize, reason: String },

    #[error("invalid SD-PARAM escape at byte {offset}")]
    InvalidSdParamEscape { offset: usize },

    #[error("message too short: {length} bytes, minimum {minimum}")]
    MessageTooShort { length: usize, minimum: usize },

    #[error("message too long: {length} bytes, maximum {maximum}")]
    MessageTooLong { length: usize, maximum: usize },

    #[error("unexpected end of input at byte {offset}, expected {expected}")]
    UnexpectedEof { offset: usize, expected: &'static str },

    #[error("invalid UTF-8 in MSG body at byte {offset}")]
    InvalidUtf8 { offset: usize },

    #[error("invalid octet-counting frame: {reason}")]
    InvalidFrame { reason: String },

    #[error("unrecognized message format")]
    UnrecognizedFormat,
}
```

#### `syslog-transport::TransportError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("I/O error on {context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },

    #[error("TLS handshake failed with {peer}: {reason}")]
    TlsHandshake { peer: String, reason: String },

    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("connection reset by {peer}")]
    ConnectionReset { peer: String },

    #[error("connection timeout after {duration:?} with {peer}")]
    ConnectionTimeout {
        peer: String,
        duration: std::time::Duration,
    },

    #[error("bind failed on {addr}: {source}")]
    BindFailed {
        addr: String,
        source: std::io::Error,
    },

    #[error("parse error on data from {peer}: {source}")]
    Parse {
        peer: String,
        source: crate::ParseError,
    },

    #[error("send failed to {peer}: {source}")]
    SendFailed {
        peer: String,
        source: std::io::Error,
    },
}
```

Note: `TransportError` wraps `ParseError` in its `Parse` variant because transport listeners parse incoming bytes. In `syslog-transport`, `ParseError` is re-exported from `syslog-parse`.

#### `syslog-config::ConfigError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    FileRead {
        path: std::path::PathBuf,
        source: std::io::Error,
    },

    #[error("TOML parse error in {path}: {source}")]
    TomlParse {
        path: std::path::PathBuf,
        source: toml::de::Error,
    },

    #[error("validation error at '{key}': {message}")]
    Validation { key: String, message: String },

    #[error("undefined environment variable '{var}' referenced at '{key}'")]
    UndefinedEnvVar { key: String, var: String },

    #[error("route '{route}' references undefined output '{output}'")]
    UndefinedOutput { route: String, output: String },

    #[error("route '{route}' references undefined filter '{filter}'")]
    UndefinedFilter { route: String, filter: String },

    #[error("duplicate listener name '{name}'")]
    DuplicateListener { name: String },

    #[error("duplicate output name '{name}'")]
    DuplicateOutput { name: String },

    #[error("TLS certificate file not found: {path}")]
    TlsCertNotFound { path: std::path::PathBuf },

    #[error("TLS key file not found: {path}")]
    TlsKeyNotFound { path: std::path::PathBuf },

    #[error("multiple validation errors: {errors:?}")]
    Multiple { errors: Vec<ConfigError> },
}
```

#### `syslog-relay::RelayError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("queue '{queue}' is full ({capacity} messages), policy: {policy}")]
    QueueFull {
        queue: String,
        capacity: usize,
        policy: String,
    },

    #[error("output '{output}' is unreachable: {reason}")]
    OutputUnreachable { output: String, reason: String },

    #[error("pipeline shutdown in progress")]
    Shutdown,

    #[error("filter evaluation error on filter '{filter}': {reason}")]
    FilterError { filter: String, reason: String },

    #[error("routing error: no matching output for message")]
    NoMatchingOutput,

    #[error("channel send error: receiver dropped")]
    ChannelClosed,
}
```

### 4.3 Error Propagation Strategy

```
Network bytes
    │
    ▼
syslog-transport (TransportError)
    │  wraps ParseError from syslog-parse
    │  logs + records metric on parse failures
    │  drops unparseable messages (does NOT propagate to relay)
    │
    ▼
syslog-relay (RelayError)
    │  filter/route errors logged + metered
    │  queue-full handled by backpressure policy
    │  output failures trigger retry logic
    │
    ▼
syslog-server (anyhow::Error)
    │  startup failures -> exit with descriptive message
    │  runtime errors handled by per-task supervisors
    │  fatal errors -> graceful shutdown
```

Key rules:
- **Parse errors do not crash the pipeline.** A malformed message is logged at `warn` level, counted in `syslog_parse_errors_total`, and dropped. The listener continues processing.
- **Output errors trigger retry with backoff.** The relay queue buffers messages during transient output failures. Persistent failures are logged and metered.
- **Config errors are fail-fast at startup.** All validation errors are collected and reported together, then the process exits with code 1.
- **Hot-reload config errors are fail-safe.** Invalid config is rejected; the running config remains active. The error is logged at `error` level.

---

## 5. Configuration Model

### 5.1 Rust Struct Definitions

```rust
// syslog-config/src/model.rs

use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Top-level server configuration.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Global server settings.
    #[serde(default)]
    pub server: ServerSection,

    /// Named listener definitions.
    #[serde(default)]
    pub listeners: HashMap<String, ListenerConfig>,

    /// Named output definitions.
    #[serde(default)]
    pub outputs: HashMap<String, OutputConfig>,

    /// Named route definitions (evaluated in order).
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// Named filter definitions (referenced by routes).
    #[serde(default)]
    pub filters: HashMap<String, FilterConfig>,

    /// Metrics and observability.
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Logging configuration for syslog-usg's own logs.
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerSection {
    /// Graceful shutdown drain timeout.
    #[serde(default = "default_drain_timeout", with = "humantime_serde")]
    pub drain_timeout: Duration,

    /// PID file path.
    pub pid_file: Option<PathBuf>,

    /// User to drop privileges to after binding.
    pub user: Option<String>,

    /// Group to drop privileges to after binding.
    pub group: Option<String>,
}

/// Listener (input) configuration.
#[derive(Debug, Deserialize)]
#[serde(tag = "transport")]
pub enum ListenerConfig {
    #[serde(rename = "udp")]
    Udp {
        bind: SocketAddr,
        #[serde(default = "default_udp_recv_buf")]
        recv_buffer_size: usize,
        #[serde(default = "default_max_message_size")]
        max_message_size: usize,
    },

    #[serde(rename = "tcp")]
    Tcp {
        bind: SocketAddr,
        #[serde(default = "default_max_message_size")]
        max_message_size: usize,
        #[serde(default = "default_max_connections")]
        max_connections: usize,
    },

    #[serde(rename = "tls")]
    Tls {
        bind: SocketAddr,
        tls: TlsConfig,
        #[serde(default = "default_max_message_size")]
        max_message_size: usize,
        #[serde(default = "default_max_connections")]
        max_connections: usize,
    },
}

/// Output (destination) configuration.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum OutputConfig {
    #[serde(rename = "forward_tls")]
    ForwardTls {
        /// Target host:port.
        target: String,
        tls: TlsConfig,
        #[serde(default)]
        queue: QueueConfig,
    },

    #[serde(rename = "forward_tcp")]
    ForwardTcp {
        target: String,
        #[serde(default)]
        queue: QueueConfig,
    },

    #[serde(rename = "forward_udp")]
    ForwardUdp {
        target: String,
        #[serde(default)]
        queue: QueueConfig,
    },

    #[serde(rename = "file")]
    File {
        path: PathBuf,
        #[serde(default)]
        format: OutputFormat,
        #[serde(default)]
        rotation: Option<RotationConfig>,
        #[serde(default)]
        queue: QueueConfig,
    },

    #[serde(rename = "stdout")]
    Stdout {
        #[serde(default)]
        format: OutputFormat,
    },
}

/// Output serialization format.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Rfc5424,
    Json,
}

/// File rotation configuration.
#[derive(Debug, Deserialize)]
pub struct RotationConfig {
    /// Maximum file size before rotation.
    pub max_size: Option<String>,
    /// Maximum age before rotation.
    pub max_age: Option<String>,
    /// Maximum number of rotated files to retain.
    pub max_files: Option<usize>,
}

/// Route definition: match filter -> send to outputs.
#[derive(Debug, Deserialize)]
pub struct RouteConfig {
    /// Route name (for logging/metrics).
    pub name: String,
    /// Filter name to apply (from [filters] section). None = match all.
    pub filter: Option<String>,
    /// Output names to send matched messages to.
    pub outputs: Vec<String>,
}

/// Filter definition.
#[derive(Debug, Deserialize)]
pub struct FilterConfig {
    /// Facility values to include (empty = all).
    #[serde(default)]
    pub facilities: Vec<String>,

    /// Minimum severity (inclusive). Messages with severity <= this value pass.
    pub min_severity: Option<String>,

    /// Hostname patterns (glob). Empty = all.
    #[serde(default)]
    pub hostnames: Vec<String>,

    /// App-name patterns (glob). Empty = all.
    #[serde(default)]
    pub app_names: Vec<String>,

    /// SD-IDs that must be present. Empty = no requirement.
    #[serde(default)]
    pub sd_ids: Vec<String>,

    /// If true, invert the filter (exclude matching messages).
    #[serde(default)]
    pub negate: bool,
}

/// TLS configuration for listeners and outputs.
#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Path to PEM certificate file.
    pub cert: PathBuf,

    /// Path to PEM private key file.
    pub key: PathBuf,

    /// Path to CA certificate bundle for peer verification.
    pub ca_cert: Option<PathBuf>,

    /// Require client certificates (mutual TLS).
    #[serde(default)]
    pub mutual_auth: bool,

    /// Allowed TLS protocol versions.
    #[serde(default = "default_tls_versions")]
    pub versions: Vec<String>,

    /// Certificate fingerprints for pinning (SHA-256 hex).
    #[serde(default)]
    pub fingerprints: Vec<String>,
}

/// Per-output queue configuration.
#[derive(Debug, Deserialize)]
pub struct QueueConfig {
    /// Maximum number of messages in the queue.
    #[serde(default = "default_queue_capacity")]
    pub capacity: usize,

    /// Backpressure policy when queue is full.
    #[serde(default)]
    pub overflow_policy: OverflowPolicy,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverflowPolicy {
    #[default]
    DropNewest,
    DropOldest,
    Block,
}

/// Metrics / observability HTTP server.
#[derive(Debug, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics endpoint.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Bind address for metrics HTTP server.
    #[serde(default = "default_metrics_bind")]
    pub bind: SocketAddr,
}

/// Logging configuration for syslog-usg itself.
#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error.
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format: json or text.
    #[serde(default = "default_log_format")]
    pub format: String,
}
```

### 5.2 Reference TOML Configuration

```toml
# syslog-usg.toml — Reference Configuration

[server]
drain_timeout = "5s"
# pid_file = "/run/syslog-usg.pid"
# user = "syslog"
# group = "syslog"

# ─── Listeners ───────────────────────────────────────────────

[listeners.udp_514]
transport = "udp"
bind = "0.0.0.0:514"
recv_buffer_size = 4194304          # 4 MiB SO_RCVBUF
max_message_size = 8192

[listeners.tls_6514]
transport = "tls"
bind = "0.0.0.0:6514"
max_message_size = 8192
max_connections = 10000

[listeners.tls_6514.tls]
cert = "${SYSLOG_TLS_CERT:-/etc/syslog-usg/tls/server.crt}"
key = "${SYSLOG_TLS_KEY:-/etc/syslog-usg/tls/server.key}"
ca_cert = "/etc/syslog-usg/tls/ca.crt"
mutual_auth = true
versions = ["1.2", "1.3"]

# [listeners.tcp_514]
# transport = "tcp"
# bind = "0.0.0.0:514"
# max_message_size = 8192
# max_connections = 10000

# ─── Outputs ─────────────────────────────────────────────────

[outputs.central_tls]
type = "forward_tls"
target = "siem.internal.example.com:6514"

[outputs.central_tls.tls]
cert = "/etc/syslog-usg/tls/client.crt"
key = "/etc/syslog-usg/tls/client.key"
ca_cert = "/etc/syslog-usg/tls/ca.crt"
mutual_auth = false

[outputs.central_tls.queue]
capacity = 10000
overflow_policy = "drop_oldest"

[outputs.local_file]
type = "file"
path = "/var/log/syslog-usg/messages.log"
format = "rfc5424"

[outputs.local_file.rotation]
max_size = "100MB"
max_age = "7d"
max_files = 10

[outputs.local_file.queue]
capacity = 5000
overflow_policy = "block"

[outputs.debug_stdout]
type = "stdout"
format = "json"

# ─── Filters ─────────────────────────────────────────────────

[filters.critical_only]
min_severity = "crit"               # emergency, alert, crit

[filters.not_debug]
min_severity = "info"

[filters.network_devices]
hostnames = ["switch-*", "router-*", "fw-*"]

[filters.app_auth]
app_names = ["sshd", "sudo", "pam*"]

# ─── Routes (evaluated in order) ─────────────────────────────

[[routes]]
name = "critical_to_central"
filter = "critical_only"
outputs = ["central_tls"]

[[routes]]
name = "network_to_file"
filter = "network_devices"
outputs = ["local_file", "central_tls"]

[[routes]]
name = "catch_all"
# no filter = match all remaining messages
outputs = ["local_file"]

# ─── Metrics ─────────────────────────────────────────────────

[metrics]
enabled = true
bind = "127.0.0.1:9090"

# ─── Logging ─────────────────────────────────────────────────

[logging]
level = "info"
format = "json"
```

### 5.3 Environment Variable Substitution

The config loader supports `${VAR}` and `${VAR:-default}` syntax in all string values. Substitution occurs before TOML parsing, operating on the raw file text.

Rules:
- `${VAR}` — replaced by the value of environment variable `VAR`. Error if unset.
- `${VAR:-fallback}` — replaced by `VAR` if set, otherwise `fallback`.
- Nested substitution is not supported.
- Non-string fields (numbers, booleans) are not subject to substitution.

---

## 6. Async/Concurrency Strategy

### 6.1 Runtime Configuration

```rust
// syslog-server/src/main.rs
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Tokio multi-threaded runtime with default worker count (= CPU cores)
    // Runtime is configured via #[tokio::main] defaults.
    // For tuning: TOKIO_WORKER_THREADS env var.
    // ...
}
```

### 6.2 Task Architecture

The server spawns a set of long-lived tasks connected by bounded channels:

```
┌─────────────┐     mpsc      ┌──────────┐     mpsc      ┌──────────┐
│ UDP Listener ├──────────────►│          │──────────────►│ Output:  │
└─────────────┘               │          │               │ TLS Fwd  │
                              │  Router  │               └──────────┘
┌─────────────┐     mpsc      │  Task    │     mpsc      ┌──────────┐
│ TLS Listener ├──────────────►│          │──────────────►│ Output:  │
│  (per-conn)  │              │          │               │ File     │
└─────────────┘               └──────────┘               └──────────┘
```

Task responsibilities:

| Task | Spawned By | Count | Description |
|------|-----------|-------|-------------|
| **UDP Listener** | lifecycle | 1 per listener config | `loop { recv_from() -> parse -> send to router channel }` |
| **TLS Acceptor** | lifecycle | 1 per TLS listener | `loop { accept() -> spawn connection task }` |
| **TLS Connection** | TLS Acceptor | 1 per connection | Read loop: frame decode -> parse -> send to router channel |
| **TCP Acceptor** | lifecycle | 1 per TCP listener | Same as TLS without handshake |
| **TCP Connection** | TCP Acceptor | 1 per connection | Same as TLS connection without TLS |
| **Router** | lifecycle | 1 | Receive from all input channels, evaluate routes, fan-out to output channels |
| **Output Worker** | lifecycle | 1 per output config | Receive from per-output channel, serialize, write/send |
| **Metrics Server** | lifecycle | 1 | Axum HTTP server for /metrics, /health, /ready, /live |
| **Signal Handler** | lifecycle | 1 | Listens for SIGTERM, SIGINT, SIGHUP; triggers shutdown or reload |

### 6.3 Channel Design

All inter-task channels are `tokio::sync::mpsc::channel` (bounded).

```rust
// Channel between listeners and router
let (ingest_tx, ingest_rx) = tokio::sync::mpsc::channel::<ParsedMessage>(8192);

// Channel between router and each output
let (output_tx, output_rx) = tokio::sync::mpsc::channel::<Arc<SyslogMessage>>(queue_config.capacity);
```

Design decisions:
- **Bounded everywhere.** No `unbounded_channel` calls in the entire codebase. Capacities are configurable.
- **`mpsc` for fan-in** (multiple listeners -> one router). Each listener clones `ingest_tx`.
- **Dedicated channel per output** for isolation. One slow output does not block others.
- **`Arc<SyslogMessage>`** for fan-out. When a message routes to multiple outputs, the router clones the `Arc` rather than the message data. The message itself contains `Bytes` slices, so even the `Arc` contents are cheap.
- **`broadcast` not used.** Broadcast channels drop messages when a receiver is slow, with no policy control. Explicit fan-out with per-output channels gives us configurable backpressure policies.

### 6.4 Shutdown Coordination

Shutdown uses `tokio_util::sync::CancellationToken` for cooperative cancellation:

```rust
use tokio_util::sync::CancellationToken;

let shutdown = CancellationToken::new();

// Each task receives a clone of the token
let task_shutdown = shutdown.clone();
tokio::spawn(async move {
    loop {
        tokio::select! {
            _ = task_shutdown.cancelled() => {
                // Drain remaining items, then return
                break;
            }
            msg = rx.recv() => {
                match msg {
                    Some(m) => { /* process */ }
                    None => break, // channel closed
                }
            }
        }
    }
});

// Signal handler triggers shutdown
shutdown.cancel();
```

Shutdown sequence:
1. Signal handler calls `shutdown.cancel()`.
2. Listener tasks stop accepting new connections/datagrams.
3. Existing TLS/TCP connection tasks drain their read buffers, then close.
4. Listener tasks drop their `ingest_tx` senders. Router's `ingest_rx` eventually yields `None`.
5. Router drains remaining messages, routes them, then drops its `output_tx` senders.
6. Output workers drain their channels, flush buffers, close connections, then return.
7. Main task awaits all `JoinHandle`s with a `tokio::time::timeout(drain_timeout)`.
8. If timeout expires, remaining tasks are aborted and the process exits.

### 6.5 Backpressure Propagation

Backpressure flows backward through the channel chain:

```
Output slow -> output channel fills -> router blocks on send (or drops per policy)
  -> ingest channel fills -> listener blocks on send -> recv_from blocks
  -> OS socket buffer fills -> kernel drops UDP packets (counted in metrics)
```

Per-output backpressure policies:
- **`drop_newest`** — `try_send()` on the output channel; if full, drop the current message and increment `syslog_messages_dropped_total{reason="queue_full"}`.
- **`drop_oldest`** — Not directly supported by `mpsc`. Implemented with a wrapper: when `try_send()` fails, `try_recv()` one message (discard it), then `send()` the new one.
- **`block`** — `send().await` on the output channel. This blocks the router, which eventually blocks listeners. Use with caution; appropriate for file outputs where temporary disk latency should not cause drops.

### 6.6 SIGHUP Reload

Hot reload replaces the pipeline without dropping existing connections:

1. SIGHUP received by signal handler task.
2. Load and validate new config. If invalid, log error and continue with current config.
3. Diff new config against current: identify added/removed/changed listeners, outputs, routes, filters.
4. For added listeners: spawn new listener tasks with the existing `ingest_tx`.
5. For removed listeners: cancel their tasks (connections drain).
6. For changed outputs: spawn new output workers with new channels; router atomically swaps its output channel map (via `Arc<RwLock<...>>` or by replacing the router task).
7. Routes/filters are lightweight data; replace atomically in the router.

---

## 7. Trait Boundaries

These traits define the extension points for the system. All traits are object-safe and async.

### 7.1 MessageSource

```rust
// syslog-transport/src/lib.rs

use async_trait::async_trait;
use syslog_proto::SyslogMessage;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// A source of syslog messages (listener).
///
/// Implementations bind to a network address, accept connections or datagrams,
/// parse incoming bytes, and send parsed messages to the provided channel.
#[async_trait]
pub trait MessageSource: Send + Sync + 'static {
    /// Run the source until cancellation.
    ///
    /// The source should:
    /// 1. Bind to its configured address.
    /// 2. Accept incoming data.
    /// 3. Parse messages and send them to `tx`.
    /// 4. Stop accepting when `cancel` is triggered.
    /// 5. Drain in-flight data, then return.
    async fn run(
        &self,
        tx: mpsc::Sender<ParsedMessage>,
        cancel: CancellationToken,
    ) -> Result<(), TransportError>;

    /// Human-readable name for logging and metrics labels.
    fn name(&self) -> &str;
}
```

### 7.2 MessageSink

```rust
// syslog-relay/src/lib.rs

use std::sync::Arc;
use async_trait::async_trait;
use syslog_proto::SyslogMessage;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// A destination for syslog messages (output).
///
/// Implementations serialize messages and write them to a target
/// (network, file, stdout).
#[async_trait]
pub trait MessageSink: Send + Sync + 'static {
    /// Run the sink, consuming messages from `rx` until cancellation or channel close.
    ///
    /// The sink should:
    /// 1. Establish connection to the target (if network).
    /// 2. Read messages from `rx`.
    /// 3. Serialize and write each message.
    /// 4. On `cancel`, drain `rx` and flush, then return.
    async fn run(
        &self,
        rx: mpsc::Receiver<Arc<SyslogMessage>>,
        cancel: CancellationToken,
    ) -> Result<(), RelayError>;

    /// Human-readable name for logging and metrics labels.
    fn name(&self) -> &str;

    /// Check if the output target is reachable. Used for health checks.
    async fn health_check(&self) -> Result<(), RelayError>;
}
```

### 7.3 MessageFilter

```rust
// syslog-relay/src/filter.rs

use syslog_proto::SyslogMessage;

/// A predicate over syslog messages.
///
/// Filters are synchronous and infallible — they inspect a message
/// and return true (pass) or false (drop). Filters must be cheap;
/// they run in the router's hot path.
pub trait MessageFilter: Send + Sync + 'static {
    /// Returns `true` if the message passes the filter.
    fn matches(&self, message: &SyslogMessage) -> bool;

    /// Human-readable name for logging.
    fn name(&self) -> &str;
}
```

### 7.4 MessageRouter

```rust
// syslog-relay/src/router.rs

use std::sync::Arc;
use syslog_proto::SyslogMessage;

/// Determines which outputs a message should be sent to.
///
/// The router evaluates routes in order. The first matching route
/// determines the output set. A message may match multiple routes
/// if routes are non-exclusive.
pub trait MessageRouter: Send + Sync + 'static {
    /// Given a message, return the names of outputs it should be sent to.
    ///
    /// Returns an empty slice if no route matches (message is dropped).
    /// The returned names must correspond to configured output names.
    fn route<'a>(&'a self, message: &SyslogMessage) -> &'a [RouteDecision];

    /// Reload routing rules from new configuration.
    fn reload(&mut self, routes: Vec<RouteRule>);
}

/// A routing decision: output name and whether to continue evaluating routes.
#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub output: String,
}

/// A compiled route rule.
#[derive(Debug)]
pub struct RouteRule {
    pub name: String,
    pub filter: Option<Box<dyn MessageFilter>>,
    pub outputs: Vec<String>,
}
```

### 7.5 Trait Composition in the Pipeline

```rust
// syslog-relay/src/pipeline.rs

/// The assembled pipeline.
pub struct Pipeline {
    sources: Vec<Box<dyn MessageSource>>,
    router: Box<dyn MessageRouter>,
    sinks: HashMap<String, Box<dyn MessageSink>>,
    ingest_capacity: usize,
}

impl Pipeline {
    /// Build a pipeline from configuration.
    pub fn from_config(config: &ServerConfig) -> Result<Self, RelayError> {
        // ...
    }

    /// Run the pipeline until shutdown.
    pub async fn run(self, cancel: CancellationToken) -> Result<(), RelayError> {
        // Spawn source tasks, router task, sink tasks.
        // Await all JoinHandles.
        // ...
    }
}
```

---

## 8. Memory Model

### 8.1 Message Lifecycle

A syslog message passes through four memory stages:

```
Stage 1: Raw Network Bytes
  │  OS recv buffer -> tokio reads into BytesMut (pre-allocated)
  │  Allocation: one BytesMut per recv batch (UDP) or per frame (TCP/TLS)
  │
  ▼
Stage 2: Framed Bytes
  │  Octet-counting decoder extracts a single Bytes slice per message
  │  Bytes::split_to() on the BytesMut — zero-copy, reference-counted
  │
  ▼
Stage 3: Parsed SyslogMessage
  │  Parser produces SyslogMessage with Bytes slices into Stage 2 buffer
  │  Hostname, AppName, MsgId, MSG body are all Bytes references
  │  No string copying in the common case
  │
  ▼
Stage 4: Routed Arc<SyslogMessage>
  │  Router wraps in Arc for fan-out to multiple outputs
  │  Each output holds an Arc clone — message data is shared, not copied
  │  Arc dropped when last output finishes serializing
  │
  ▼
Stage 5: Serialized Output
  │  Serializer writes directly to output's BytesMut write buffer
  │  Or formats into a pre-allocated String buffer for JSON
  │  Original Bytes slices from Stage 2 can be written directly (zero-copy)
```

### 8.2 Key Type: `SyslogMessage`

```rust
// syslog-proto/src/message.rs

use bytes::Bytes;
use smallvec::SmallVec;
use time::OffsetDateTime;

/// A parsed syslog message. Fields reference the original network buffer
/// via `Bytes` for zero-copy operation.
#[derive(Debug, Clone)]
pub struct SyslogMessage {
    /// Facility (extracted from PRI).
    pub facility: Facility,

    /// Severity (extracted from PRI).
    pub severity: Severity,

    /// Protocol version (always 1 for RFC 5424).
    pub version: u8,

    /// Timestamp with nanosecond precision and timezone offset.
    /// `None` represents NILVALUE.
    pub timestamp: Option<OffsetDateTime>,

    /// Hostname. `None` represents NILVALUE.
    /// References the original buffer via Bytes.
    pub hostname: Option<Bytes>,

    /// Application name. `None` represents NILVALUE.
    pub app_name: Option<Bytes>,

    /// Process ID. `None` represents NILVALUE.
    pub proc_id: Option<Bytes>,

    /// Message ID. `None` represents NILVALUE.
    pub msg_id: Option<Bytes>,

    /// Structured data elements. SmallVec avoids heap allocation
    /// for the common case of 0-3 elements.
    pub structured_data: SmallVec<[SdElement; 4]>,

    /// Message body (after the structured data).
    /// References the original buffer via Bytes.
    pub msg: Option<Bytes>,

    /// Whether the message was originally RFC 3164 format
    /// (translated to 5424 internal representation).
    pub is_legacy: bool,

    /// The complete raw message bytes, retained for passthrough forwarding
    /// where re-serialization can be avoided.
    pub raw: Bytes,
}
```

### 8.3 Zero-Copy Parsing Strategy

The parser operates on a `Bytes` input and produces `Bytes` slices:

```rust
// Conceptual parse flow (simplified)
pub fn parse_rfc5424(input: Bytes) -> Result<SyslogMessage, ParseError> {
    let raw = input.clone(); // cheap Arc increment
    let mut cursor = 0;

    // Parse PRI — small fixed field, extract as integers (no allocation)
    let (facility, severity) = parse_pri(&input, &mut cursor)?;

    // Parse HOSTNAME — slice the Bytes buffer (no copy)
    let hostname = parse_hostname(&input, &mut cursor)?
        .map(|(start, end)| input.slice(start..end));

    // ... same for app_name, proc_id, msg_id

    // Parse structured data — each SD-PARAM value is a Bytes slice
    let structured_data = parse_structured_data(&input, &mut cursor)?;

    // MSG body — the remainder is a Bytes slice
    let msg = if cursor < input.len() {
        Some(input.slice(cursor..))
    } else {
        None
    };

    Ok(SyslogMessage {
        facility,
        severity,
        hostname,
        // ...
        raw,
    })
}
```

When copies are necessary:
- **Timestamp parsing**: The timestamp string is parsed into `time::OffsetDateTime`, which is a stack-allocated struct. The string itself is not retained.
- **SD-PARAM unescaping**: If an SD-PARAM value contains escape sequences (`\"`, `\\`, `\]`), the unescaped value must be a new allocation. In the common case (no escapes), the `Bytes` slice is used directly.
- **RFC 3164 translation**: Legacy messages may require constructing synthetic fields (e.g., generating a hostname from the source IP), which allocates.

### 8.4 Buffer Sizing and Pooling

**UDP receive buffers:**
- Pre-allocate a `BytesMut` with capacity matching the configured `max_message_size` (default 8192).
- After parsing, `BytesMut::split()` freezes the used portion into `Bytes` (zero-copy).
- The `BytesMut` is then reused for the next recv (remaining capacity).
- If remaining capacity is less than `max_message_size`, allocate a new `BytesMut`.

**TCP/TLS read buffers:**
- Each connection has a `BytesMut` read buffer sized to 64 KiB.
- The octet-counting framer reads frames from this buffer.
- `BytesMut` is reused across frames within the same connection.

**Output write buffers:**
- Each output worker has a `BytesMut` write buffer.
- For passthrough forwarding (same format), the serializer writes `raw` directly.
- For format conversion (e.g., to JSON), the serializer writes into a `String` buffer.

### 8.5 SmallVec for Structured Data

Most syslog messages have 0-3 structured data elements. `SmallVec<[SdElement; 4]>` stores up to 4 elements on the stack (within the `SyslogMessage`), falling back to heap allocation only for messages with 5+ elements.

Similarly, within each `SdElement`:

```rust
#[derive(Debug, Clone)]
pub struct SdElement {
    /// SD-ID (e.g., "timeQuality", "myapp@12345").
    pub id: Bytes,

    /// SD-PARAMs. Most elements have 1-4 params.
    pub params: SmallVec<[SdParam; 4]>,
}

#[derive(Debug, Clone)]
pub struct SdParam {
    pub name: Bytes,
    pub value: Bytes,
}
```

### 8.6 Arena/Pool Considerations

For the MVP, explicit arena or pool allocation is not used. The combination of `Bytes` (reference-counted, zero-copy slicing) and `SmallVec` (stack allocation for small collections) achieves the performance targets without the complexity of custom allocators.

If profiling reveals allocation pressure under extreme load (>200k msg/sec), the following can be introduced later without API changes:
- **`BytesMut` pool**: A `crossbeam` or `flurry` pool of pre-allocated `BytesMut` buffers for UDP receive. Reduces allocator contention under high message rates.
- **`SyslogMessage` object pool**: Reuse parsed message structs via a channel-based pool. The `Bytes` slices inside would still reference the original network buffers.

These optimizations are deferred because premature pooling adds complexity and the `Bytes` crate already provides efficient reference-counted buffers.

---

## 9. Initial File Tree

Complete listing of every file in the workspace scaffold. Files marked `(stub)` contain minimal compilable content (e.g., `#![forbid(unsafe_code)]` and a module declaration or empty struct). Files marked `(config)` contain project configuration.

```
syslog-usg/
├── Cargo.toml                                      (config) workspace manifest
├── Cargo.lock                                       (generated)
├── rust-toolchain.toml                              (config) channel = "stable", msrv
├── rustfmt.toml                                     (config) formatting rules
├── clippy.toml                                      (config) clippy configuration
├── deny.toml                                        (config) cargo-deny advisories/licenses
├── .gitignore                                       (config)
├── CLAUDE.md                                        (existing)
│
├── docs/
│   ├── phase-01-requirements.md                     (existing)
│   └── phase-04-rust-architecture.md                (this document)
│
├── examples/
│   └── syslog-usg.toml                             (config) reference TOML configuration
│
├── crates/
│   ├── syslog-proto/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── facility.rs
│   │       ├── severity.rs
│   │       ├── pri.rs
│   │       ├── timestamp.rs
│   │       ├── structured_data.rs
│   │       ├── message.rs
│   │       ├── message_id.rs
│   │       ├── hostname.rs
│   │       ├── app_name.rs
│   │       ├── proc_id.rs
│   │       └── sd_id.rs
│   │
│   ├── syslog-parse/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs
│   │       ├── detect.rs
│   │       ├── octet_counting.rs
│   │       ├── parse_mode.rs
│   │       ├── rfc5424/
│   │       │   ├── mod.rs
│   │       │   ├── parser.rs
│   │       │   ├── header.rs
│   │       │   ├── structured_data.rs
│   │       │   ├── msg.rs
│   │       │   └── serializer.rs
│   │       └── rfc3164/
│   │           ├── mod.rs
│   │           ├── parser.rs
│   │           └── heuristics.rs
│   │
│   ├── syslog-transport/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs
│   │       ├── framing.rs
│   │       ├── udp/
│   │       │   ├── mod.rs
│   │       │   ├── listener.rs
│   │       │   └── sender.rs
│   │       ├── tcp/
│   │       │   ├── mod.rs
│   │       │   ├── listener.rs
│   │       │   ├── connection.rs
│   │       │   └── sender.rs
│   │       └── tls/
│   │           ├── mod.rs
│   │           ├── listener.rs
│   │           ├── connection.rs
│   │           ├── sender.rs
│   │           ├── config.rs
│   │           └── certs.rs
│   │
│   ├── syslog-relay/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs
│   │       ├── pipeline.rs
│   │       ├── filter.rs
│   │       ├── router.rs
│   │       ├── queue.rs
│   │       ├── backpressure.rs
│   │       ├── fanout.rs
│   │       └── enrichment.rs
│   │
│   ├── syslog-config/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs
│   │       ├── model.rs
│   │       ├── loader.rs
│   │       ├── validation.rs
│   │       ├── env_subst.rs
│   │       └── defaults.rs
│   │
│   ├── syslog-observe/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── metrics.rs
│   │       ├── tracing_setup.rs
│   │       ├── health.rs
│   │       └── server.rs
│   │
│   ├── syslog-server/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── cli.rs
│   │       ├── lifecycle.rs
│   │       ├── signals.rs
│   │       └── reload.rs
│   │
│   ├── syslog-sign/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── lib.rs                               (stub) placeholder for RFC 5848
│   │
│   └── syslog-mgmt/
│       ├── Cargo.toml
│       └── src/
│           └── lib.rs                               (stub) placeholder for RFC 5427/9742
│
├── tests/
│   ├── integration/
│   │   ├── udp_ingest.rs
│   │   ├── tls_ingest.rs
│   │   ├── tcp_ingest.rs
│   │   ├── relay_pipeline.rs
│   │   ├── config_reload.rs
│   │   └── backpressure.rs
│   └── conformance/
│       ├── rfc5424_valid.rs
│       ├── rfc5424_invalid.rs
│       └── rfc3164_compat.rs
│
├── benches/
│   └── syslog-bench/
│       ├── Cargo.toml
│       └── benches/
│           ├── parse_5424.rs
│           ├── parse_3164.rs
│           ├── serialize.rs
│           └── pipeline.rs
│
└── fuzz/
    ├── Cargo.toml
    └── fuzz_targets/
        ├── fuzz_parse_5424.rs
        └── fuzz_parse_3164.rs
```

**Total file count:** 84 files (excluding generated Cargo.lock and target/).

### 9.1 Workspace Cargo.toml

```toml
[workspace]
resolver = "3"
members = [
    "crates/syslog-proto",
    "crates/syslog-parse",
    "crates/syslog-transport",
    "crates/syslog-relay",
    "crates/syslog-config",
    "crates/syslog-observe",
    "crates/syslog-server",
    "crates/syslog-sign",
    "crates/syslog-mgmt",
    "benches/syslog-bench",
]

[workspace.package]
edition = "2024"
rust-version = "1.92"
license = "MIT OR Apache-2.0"
repository = "https://github.com/example/syslog-usg"

[workspace.dependencies]
# Internal crates
syslog-proto     = { path = "crates/syslog-proto" }
syslog-parse     = { path = "crates/syslog-parse" }
syslog-transport = { path = "crates/syslog-transport" }
syslog-relay     = { path = "crates/syslog-relay" }
syslog-config    = { path = "crates/syslog-config" }
syslog-observe   = { path = "crates/syslog-observe" }
syslog-sign      = { path = "crates/syslog-sign" }
syslog-mgmt      = { path = "crates/syslog-mgmt" }

# External dependencies — pinned to compatible ranges
tokio            = { version = "1", features = ["rt-multi-thread", "net", "io-util", "sync", "signal", "macros", "time"] }
tokio-util       = { version = "0.7", features = ["codec"] }
tokio-rustls     = { version = "0.26", default-features = false, features = ["ring"] }
rustls           = { version = "0.23", default-features = false, features = ["ring", "std"] }
rustls-pemfile   = "2"
webpki-roots     = "0.26"
bytes            = "1"
smallvec         = { version = "1", features = ["serde"] }
serde            = { version = "1", features = ["derive"] }
toml             = "0.8"
tracing          = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
metrics          = "0.24"
metrics-exporter-prometheus = "0.16"
time             = { version = "0.3", features = ["parsing", "formatting", "serde"] }
thiserror        = "2"
anyhow           = "1"
clap             = { version = "4", features = ["derive"] }
axum             = "0.8"
async-trait      = "0.1"
criterion        = { version = "0.5", features = ["async_tokio"] }
```

### 9.2 rust-toolchain.toml

```toml
[toolchain]
channel = "stable"
```

---

## Appendix: Crate-Level Cargo.toml Templates

### syslog-proto/Cargo.toml

```toml
[package]
name = "syslog-proto"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "Core protocol types for RFC 5424 syslog messages"

[dependencies]
bytes.workspace = true
smallvec.workspace = true
time.workspace = true
serde.workspace = true
thiserror.workspace = true
```

### syslog-parse/Cargo.toml

```toml
[package]
name = "syslog-parse"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "Parser and serializer for RFC 5424 and RFC 3164 syslog"

[dependencies]
syslog-proto.workspace = true
bytes.workspace = true
thiserror.workspace = true
tracing.workspace = true
time.workspace = true
```

### syslog-transport/Cargo.toml

```toml
[package]
name = "syslog-transport"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "UDP, TCP, and TLS transport listeners and senders for syslog"

[dependencies]
syslog-proto.workspace = true
syslog-parse.workspace = true
tokio.workspace = true
tokio-util.workspace = true
tokio-rustls.workspace = true
rustls.workspace = true
rustls-pemfile.workspace = true
webpki-roots.workspace = true
bytes.workspace = true
thiserror.workspace = true
tracing.workspace = true
metrics.workspace = true
async-trait.workspace = true
```

### syslog-relay/Cargo.toml

```toml
[package]
name = "syslog-relay"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "Relay pipeline: filter, route, queue, and fan-out for syslog messages"

[dependencies]
syslog-proto.workspace = true
tokio.workspace = true
thiserror.workspace = true
tracing.workspace = true
metrics.workspace = true
async-trait.workspace = true
```

### syslog-config/Cargo.toml

```toml
[package]
name = "syslog-config"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "Configuration loading, validation, and environment variable substitution"

[dependencies]
serde.workspace = true
toml.workspace = true
thiserror.workspace = true
tracing.workspace = true
```

### syslog-observe/Cargo.toml

```toml
[package]
name = "syslog-observe"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "Metrics, tracing, and health endpoints for syslog-usg"

[dependencies]
tokio.workspace = true
axum.workspace = true
metrics.workspace = true
metrics-exporter-prometheus.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
```

### syslog-server/Cargo.toml

```toml
[package]
name = "syslog-server"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "syslog-usg binary entrypoint"

[[bin]]
name = "syslog-usg"
path = "src/main.rs"

[dependencies]
syslog-proto.workspace = true
syslog-parse.workspace = true
syslog-transport.workspace = true
syslog-relay.workspace = true
syslog-config.workspace = true
syslog-observe.workspace = true
tokio.workspace = true
tokio-util = { workspace = true }
anyhow.workspace = true
clap.workspace = true
tracing.workspace = true
```

### syslog-sign/Cargo.toml

```toml
[package]
name = "syslog-sign"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "RFC 5848 signed syslog messages (future)"

[dependencies]
syslog-proto.workspace = true
```

### syslog-mgmt/Cargo.toml

```toml
[package]
name = "syslog-mgmt"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
description = "RFC 5427/9742 syslog management model (future)"

[dependencies]
syslog-proto.workspace = true
```

### benches/syslog-bench/Cargo.toml

```toml
[package]
name = "syslog-bench"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish = false

[dev-dependencies]
syslog-proto.workspace = true
syslog-parse.workspace = true
syslog-relay.workspace = true
criterion.workspace = true
bytes.workspace = true
tokio.workspace = true

[[bench]]
name = "parse_5424"
harness = false

[[bench]]
name = "parse_3164"
harness = false

[[bench]]
name = "serialize"
harness = false

[[bench]]
name = "pipeline"
harness = false
```

