# syslog-usg Deployment Guide

Production deployment guide for syslog-usg — a high-performance, RFC-compliant
syslog server and relay.

## Prerequisites

- Rust 1.85+ (build only)
- Linux (primary) or macOS (development)
- TLS certificates if using RFC 5425 transport
- ECDSA P-256 key pair if using RFC 5848 message signing (PEM or DER)

## Building

```bash
cargo build --release
# Binary: target/release/syslog-usg
```

## Running

```bash
syslog-usg --config /etc/syslog-usg/config.toml
```

Override log level at startup:
```bash
syslog-usg --config /etc/syslog-usg/config.toml --log-level debug
```

Reload configuration without restart (SIGHUP):
```bash
kill -HUP $(pidof syslog-usg)
```

SIGHUP hot-reloads log level immediately. Changes to listeners, outputs,
pipeline, signing, verification, and metrics settings are detected and
logged as warnings — a full restart is required to apply them.

## Privilege Management

syslog-usg should **never run as root** in production.

If you need to bind to privileged port 514:

```bash
# Grant the binary the capability to bind low ports
sudo setcap cap_net_bind_service=+ep target/release/syslog-usg

# Run as an unprivileged user
sudo -u syslog syslog-usg --config /etc/syslog-usg/config.toml
```

Or use a systemd unit with `AmbientCapabilities`:

```ini
[Service]
User=syslog
Group=syslog
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/syslog-usg --config /etc/syslog-usg/config.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
```

## File Permissions

```bash
# Configuration
chmod 0640 /etc/syslog-usg/config.toml
chown root:syslog /etc/syslog-usg/config.toml

# TLS private keys — must not be group/world readable
chmod 0600 /etc/syslog-usg/tls/server.key
chown syslog:syslog /etc/syslog-usg/tls/server.key

# TLS certificates — can be world-readable
chmod 0644 /etc/syslog-usg/tls/server.crt

# Signing keys (RFC 5848) — PEM or DER format
chmod 0600 /etc/syslog-usg/sign/signing.key
chown syslog:syslog /etc/syslog-usg/sign/signing.key

# State directories (RSID persistence, replay detector)
chmod 0700 /var/lib/syslog-usg
chown syslog:syslog /var/lib/syslog-usg
```

The server warns at startup if key files have insecure permissions.

## Key Format Support

All signing and verification key/certificate paths accept both **PEM** and **DER** format.
The server auto-detects based on file content (PEM files start with `-----BEGIN`).

TLS transport keys/certs also accept PEM (via rustls).

## Resource Limits

Recommended `ulimit` settings for production:

```bash
# File descriptors (connections + internal)
ulimit -n 65536

# Or via systemd:
# LimitNOFILE=65536
```

## Configuration Reference

### Listener Options

| Field | Default | Description |
|-------|---------|-------------|
| `protocol` | (required) | `udp`, `tcp`, `tls`, or `dtls` |
| `bind_address` | (required) | Socket address, e.g. `"0.0.0.0:514"` |
| `max_connections` | `1000` | Max concurrent TCP/TLS connections |
| `max_connections_per_ip` | (none) | Max connections from a single source IP |
| `read_timeout_secs` | `30` | Per-frame read timeout (TCP/TLS) |

### Pipeline Options

| Field | Default | Max | Description |
|-------|---------|-----|-------------|
| `channel_buffer_size` | `4096` | `1000000` | Async channel capacity |
| `max_message_size` | `8192` | `2097152` | Max accepted message size (bytes) |
| `signing_fail_open` | `true` | — | Forward unsigned on signing failure |

### Signing Options (RFC 5848)

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable message signing |
| `key_path` | (required) | PKCS#8 private key (PEM or DER) |
| `cert_path` | (none) | X.509 certificate (PEM or DER) |
| `hash_algorithm` | `"sha256"` | `"sha256"` or `"sha1"` (deprecated) |
| `signature_group` | `"global"` | `"global"`, `"per-pri"`, `"pri-ranges"`, `"custom"` |
| `max_hashes_per_block` | `25` | Messages per signature block |
| `cert_emit_interval_secs` | `3600` | Certificate block emission interval |
| `state_dir` | (none) | Directory for RSID persistence across restarts |

### Verification Options (RFC 5848)

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable signature verification |
| `trusted_key_paths` | `[]` | Paths to trusted public keys (PEM or DER) |
| `reject_unverified` | `false` | Reject unsigned messages |
| `state_path` | (none) | File for replay detector state persistence |

### Management Action Types

| Type | Description |
|------|-------------|
| `remote` | Forward to a remote syslog receiver (UDP/TCP/TLS) |
| `file` | Write to a local file (append mode, RFC 5424 serialized) |
| `buffer` | Store last N messages in a named ring buffer |
| `console` | Write to stdout |
| `discard` | Drop matching messages |

### Metrics Options

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable metrics HTTP server |
| `bind_address` | `"127.0.0.1:9090"` | Bind address for HTTP server |
| `bearer_token` | (none) | Auth token for `/metrics` and `/management/*` |

## Monitoring

### Health Probes

- `GET /healthz` — liveness (always 200)
- `GET /readyz` — readiness (200 when ready, 503 during startup/shutdown)

These endpoints are always unauthenticated for load-balancer use.

### Metrics

- `GET /metrics` — Prometheus scrape endpoint

Protected by bearer token when configured. Rate-limited on auth failures
(10 failures per IP per 60s window → HTTP 429).

### Management (RFC 9742)

- `GET /management/state` — JSON: uptime, features, counters
- `GET /management/features` — JSON array of enabled features
- `GET /management/counters` — JSON: received, forwarded, dropped, malformed

Protected by bearer token when configured.

### Key Metrics to Alert On

| Metric | Condition | Meaning |
|--------|-----------|---------|
| `relay_messages_rejected_total` | Increasing | Signature verification failures |
| `relay_messages_filtered_total` | Spikes | Filter rules dropping messages |
| `relay_signing_failures_total` | Any | Signing key issues |
| `syslog_messages_parsed_total{format="invalid"}` | High rate | Malformed input flood |

## Security Checklist

- [ ] Running as unprivileged user (not root)
- [ ] TLS key files are mode 0600
- [ ] Signing key files are mode 0600
- [ ] `metrics.bearer_token` is set in config
- [ ] Management HTTP bound to loopback or internal network
- [ ] `max_connections` set (default: 1000)
- [ ] `max_connections_per_ip` set for TCP/TLS listeners
- [ ] `read_timeout_secs` set (default: 30s)
- [ ] UDP listeners on trusted networks only (no authentication)
- [ ] TLS listeners use mTLS (`client_auth = true`) for authenticated ingestion
- [ ] `signing.state_dir` set for RSID persistence across restarts
- [ ] `verification.state_path` set for replay detection persistence
- [ ] `cargo audit` and `cargo deny check` run in CI
- [ ] Fuzz targets run periodically
- [ ] Log output directed to secure destination
- [ ] Secrets not present in environment variables visible to other users
- [ ] File output paths do not contain `..` (validated at config load)

## Generating Keys

### TLS Certificate (self-signed, for testing)

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout server.key -out server.crt -days 365 -nodes \
  -subj "/CN=syslog.example.com"
```

### RFC 5848 Signing Key (ECDSA P-256)

PEM format (recommended):
```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out signing.key
openssl pkey -in signing.key -pubout -out signing.pub
```

DER format:
```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -outform DER -out signing.key
openssl pkey -in signing.key -inform DER -pubout -outform DER -out signing.pub
```

Both formats are auto-detected at load time.

## Troubleshooting

### "private key file is readable by group/other"

```bash
chmod 0600 /path/to/key.pem
```

### "metrics/management endpoints are unauthenticated on a non-loopback address"

Set a bearer token in your config:

```toml
[metrics]
enabled = true
bind_address = "0.0.0.0:9090"
bearer_token = "${SYSLOG_METRICS_TOKEN}"
```

### "verification enabled but no trusted keys were loaded"

Check that `trusted_key_paths` contains valid file paths:

```toml
[verification]
enabled = true
trusted_key_paths = ["/etc/syslog-usg/sign/trusted.pub"]
reject_unverified = false
```

### "DTLS listener falling back to PLAINTEXT UDP"

No pure-Rust DTLS library is available. The DTLS listener accepts plaintext
UDP datagrams with a security warning. Use network-level encryption (IPsec,
WireGuard) or switch to TLS for authenticated transport.

### "signing/verification key: PEM base64 decode" error

The PEM file may be corrupted or use an unsupported encoding. Verify with:
```bash
openssl pkey -in signing.key -noout  # Should print nothing on success
```

### High memory usage

- `pipeline.channel_buffer_size` — reduce if set very high (default: 4096)
- `max_connections` — reduce concurrent TCP connections (default: 1000)
- `max_connections_per_ip` — set per-source limits to prevent single-source floods
- Buffer action `size` — reduce ring buffer capacity
