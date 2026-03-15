# Changelog

All notable changes to syslog-usg are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-03-15

### Added

#### Core Protocol Support
- RFC 5424 syslog message parsing and serialization with strict field validation
- RFC 3164 (BSD syslog) best-effort parser with auto-detection
- RFC 5425 TLS transport mapping with octet-counting framing
- RFC 5426 UDP transport mapping with configurable receive buffers
- RFC 6012 DTLS transport types and plaintext-fallback listener
- RFC 5848 signed syslog — ECDSA P-256 signing and verification with hash chains
- RFC 5674 alarm structured data types with severity ordering
- RFC 9742/5427 management model with selectors, patterns, actions, and atomic counters

#### Server & Relay Pipeline
- Multi-transport listener support (UDP, TCP, TLS, DTLS)
- Relay pipeline with filter → sign → route → output architecture
- Severity filtering with configurable threshold
- Alarm filtering with event type, resource pattern, and non-alarm policy
- Routing table with selector-based output delivery (RFC 9742 actions)
- Bounded queue with configurable drop policies (drop-newest, drop-oldest, block)
- Fan-out to multiple outputs with independent queues
- Signing stage with configurable hash algorithm, signature group, and cert emission
- Verification stage with multi-key support and replay detection
- Graceful shutdown with configurable drain timeout

#### Output Types
- Network output with TCP/TLS support and exponential backoff reconnection
- File output — append-mode, lazy-open, RFC 5424 serialization
- Buffer output — in-memory ring buffer with configurable capacity
- Console output — stdout writer for debugging

#### Configuration
- TOML-based configuration with `${VAR}` and `${VAR:-default}` environment variable substitution
- SIGHUP hot-reload for log level with change detection for all settings
- Path traversal validation on all file paths
- Upper-bound validation for channel_buffer_size, max_message_size, max_connections
- Secure defaults: max_connections=1000, read_timeout_secs=30 for TCP/TLS

#### Observability
- Prometheus metrics endpoint (`/metrics`)
- Health probes (`/healthz`, `/readyz`) for load balancer integration
- RFC 9742 management endpoints (`/management/state`, `/management/features`, `/management/counters`)
- Structured JSON logging with runtime log level reload
- Atomic message counters (received, forwarded, dropped, malformed)

#### Security
- `unsafe_code = "forbid"` at workspace level — zero unsafe in all workspace crates
- Constant-time bearer token comparison (subtle crate)
- Constant-time hash chain verification
- Auth brute-force rate limiting (10 failures per IP per 60s → HTTP 429)
- Bearer token zeroization on drop (zeroize crate)
- RFC 9662 explicit TLS cipher suite enforcement (GCM-only, forward secrecy)
- Mutual TLS (mTLS) client certificate verification
- Per-source-IP connection limits for TCP/TLS
- Per-source-IP rate limiting for UDP
- TCP_NODELAY and backpressure timeout on channel sends
- Maximum message size (2 MiB) at parser entry
- Maximum PARAM-VALUE length (8192 bytes)
- Certificate reassembly TPBL cap (1 MiB) and fragment count limit (2048)
- Replay detection via GBC monotonicity enforcement per RSID
- Private key file permission checks (warn on group/world readable)
- File output symlink protection (O_NOFOLLOW on Unix)
- Log injection prevention (control character sanitization)
- SHA-1 deprecation warning
- Path traversal validation on all config file paths

#### Persistence
- RSID persistence across restarts via state_dir with atomic file writes
- Replay detector state persistence via state_path (load at startup, save at shutdown)
- PEM and DER auto-detection for all key/certificate file loading

#### Testing & Quality
- 608 unit and integration tests
- 12 fuzz targets covering parser, codec, config, signing, replay detection, PEM loading
- Property-based tests via proptest
- Differential tests against syslog_rfc5424 and syslog_loose reference implementations
- Miri verification (256 tests across proto, parse, mgmt — no undefined behavior)
- cargo-geiger verification (zero unsafe in all workspace crates)
- Workspace clippy lints: unwrap_used, expect_used, indexing_slicing, panic = deny

#### CI/CD
- GitHub Actions: test, clippy, fmt, cargo-audit, cargo-deny, secret scanning (TruffleHog), SAST (Semgrep)
- Dependabot for automated dependency updates
- cargo-deny: advisories, license allowlist, openssl/chrono bans, source controls

#### Release Packaging
- Multi-stage Dockerfile (rust:1.85 → distroless/static, ~15 MB)
- Docker Compose for local development
- Systemd service unit with full sandboxing
- Makefile with build, test, check, docker, install/uninstall targets
- Deployment guide with configuration reference and security checklist
- Secure and minimal configuration examples

### Dependencies
- Runtime: tokio, rustls, ring, axum, metrics, time, compact_str, smallvec, subtle, zeroize
- No OpenSSL — pure Rust crypto stack
- No unsafe in workspace code
