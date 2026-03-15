# syslog-usg v0.1.0

Production-grade, RFC-compliant syslog server and relay written in Rust.

## Highlights

- **Full RFC compliance** — RFC 5424 (syslog protocol), 5425 (TLS transport), 5426 (UDP transport), 5848 (signed syslog), 5674 (alarm types), 9742/5427 (management model), 9662 (TLS cipher suites)
- **Zero unsafe** — `unsafe_code = "forbid"` at workspace level, verified by cargo-geiger
- **Security-first** — constant-time auth, replay detection, rate limiting, TLS cipher pinning, key zeroization, path traversal validation, auth brute-force protection
- **High performance** — async pipeline on tokio, bounded channels everywhere, zero-copy parsing with Bytes, SmallVec for structured data
- **Production ready** — Dockerfile, systemd unit, Prometheus metrics, health probes, SIGHUP reload, graceful shutdown

## Quick Start

### Binary

```bash
cargo install --path crates/syslog-server
syslog-usg --config examples/config-minimal.toml
```

### Docker

```bash
docker build -f container/Dockerfile -t syslog-usg .
docker run -v $(pwd)/examples/config-docker.toml:/etc/syslog-usg/config.toml syslog-usg
```

### Systemd

```bash
sudo make install
sudo systemctl enable --now syslog-usg
```

## Architecture

```
UDP/TCP/TLS/DTLS → Parser → [Verify] → [Filter] → [Sign] → [Route] → Outputs
                                                                        ├── Network (TCP/TLS)
                                                                        ├── File
                                                                        ├── Buffer
                                                                        └── Console
```

9 workspace crates: proto, parse, transport, relay, config, observe, server, sign, mgmt

## What's Included

| Component | Description |
|-----------|-------------|
| **Listeners** | UDP, TCP, TLS (mTLS), DTLS (plaintext fallback) |
| **Outputs** | Network (TCP/TLS), File, Buffer (ring), Console |
| **Signing** | ECDSA P-256 via ring, SHA-256 hash chains, cert block emission |
| **Verification** | Multi-key, replay detection (GBC/RSID), state persistence |
| **Filtering** | Severity threshold, alarm-aware (RFC 5674), routing table |
| **Management** | RFC 9742 selectors/actions, atomic counters, feature flags |
| **Observability** | Prometheus metrics, health/readiness probes, JSON logging |
| **Security** | Constant-time auth, rate limiting, TLS pinning, key zeroization |

## Quality

| Metric | Value |
|--------|-------|
| Tests | 608 |
| Fuzz targets | 12 |
| Miri verified | 256 tests (no UB) |
| Unsafe in workspace | 0 (cargo-geiger) |
| Clippy | Clean (deny on unwrap/expect/panic/indexing) |
| Cargo audit | 0 advisories |
| Cargo deny | All checks pass |

## Key Files

| Path | Purpose |
|------|---------|
| `examples/config-secure.toml` | Hardened production config |
| `examples/config-minimal.toml` | Quick-start dev config |
| `docs/deployment-guide.md` | Full deployment documentation |
| `container/Dockerfile` | Multi-stage distroless build |
| `dist/syslog-usg.service` | Hardened systemd unit |
| `deny.toml` | Supply-chain security policy |

## Breaking Changes

None — this is the initial release.

## Known Limitations

- **DTLS**: No pure-Rust DTLS library exists. The DTLS listener falls back to plaintext UDP with a security warning. Use network-level encryption (IPsec/WireGuard) or TLS instead.
- **RSID persistence**: Uses file-based persistence. Not suitable for ephemeral containers without mounted volumes.
- **Hot reload**: SIGHUP reloads log level only. Listener, output, pipeline, signing, and verification changes require a restart.
- **SHA-1**: Supported per RFC 5848 but deprecated. A warning is logged on first use.

## License

Apache-2.0
