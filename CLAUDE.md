# syslog-usg — Production-Grade Syslog Server/Relay

## Project Overview
High-performance, RFC-compliant Syslog server and relay written in Rust.

## Build & Test Commands
- Build: `cargo build`
- Test all: `cargo test`
- Test single crate: `cargo test -p <crate-name>`
- Clippy: `cargo clippy --all-targets --all-features -- -D warnings`
- Format: `cargo fmt --all`
- Audit: `cargo audit`
- Bench: `cargo bench -p syslog-bench`

## Language & Toolchain
- Rust edition 2024, minimum version 1.92
- Stable Rust only — no nightly features
- Target: multi-platform (Linux primary, macOS dev)

## Code Style & Conventions
- Idiomatic Rust: strong types, explicit errors, minimal allocation
- Error types: use `thiserror` for library errors, `anyhow` only in binary entrypoints
- Async runtime: `tokio` (multi-threaded)
- No unnecessary `unsafe` — justify and document any unsafe blocks
- RFC compliance comments: mark MUST/SHOULD/MAY with RFC number and section
  - Example: `// RFC 5424 §6.1 MUST: PRI value MUST be 1-3 digits`
- Prefer `#[must_use]` on functions returning important values
- Bounded queues and channels everywhere — no unbounded buffers
- Feature flags only to reduce compile-time complexity, not for runtime branching

## Workspace Structure
```
syslog-usg/           — workspace root
├── crates/
│   ├── syslog-proto/  — core protocol model (RFC 5424 types)
│   ├── syslog-parse/  — parser and serializer
│   ├── syslog-transport/ — UDP, TLS, DTLS listeners/senders
│   ├── syslog-relay/  — routing, filtering, fan-out pipeline
│   ├── syslog-config/ — configuration loading and validation
│   ├── syslog-mgmt/   — management model (RFC 5427/9742)
│   ├── syslog-sign/   — signed syslog (RFC 5848)
│   ├── syslog-observe/ — metrics, tracing, health
│   └── syslog-server/ — binary entrypoint
├── benches/           — benchmarks
├── tests/             — integration tests
└── docs/              — design documents
```

## RFC Compliance
This project targets compliance with:
- RFC 5424, 3195, 5425, 5426, 6012, 9662 (core/transport/security)
- RFC 5427, 9742 (management)
- RFC 5848, 5674, 5675, 5676 (extensions)

All compliance claims must be traceable to tests.
