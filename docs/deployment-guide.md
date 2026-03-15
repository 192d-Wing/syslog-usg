# syslog-usg Deployment Guide

Production deployment guide for syslog-usg — a high-performance, RFC-compliant
syslog server and relay.

## Prerequisites

- Rust 1.92+ (build only)
- Linux (primary) or macOS (development)
- TLS certificates if using RFC 5425 transport
- PKCS#8 ECDSA P-256 key pair if using RFC 5848 message signing

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

Reload configuration (log level only) without restart:
```bash
kill -HUP $(pidof syslog-usg)
```

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

# Signing keys (RFC 5848)
chmod 0600 /etc/syslog-usg/sign/signing.key
chown syslog:syslog /etc/syslog-usg/sign/signing.key
```

The server warns at startup if key files have insecure permissions.

## Resource Limits

Recommended `ulimit` settings for production:

```bash
# File descriptors (connections + internal)
ulimit -n 65536

# Or via systemd:
# LimitNOFILE=65536
```

## Monitoring

### Health Probes

- `GET /healthz` — liveness (always 200)
- `GET /readyz` — readiness (200 when ready, 503 during startup/shutdown)

These endpoints are always unauthenticated for load-balancer use.

### Metrics

- `GET /metrics` — Prometheus scrape endpoint

Protected by bearer token when configured (recommended for non-loopback).

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
- [ ] `read_timeout_secs` set (default: 30s)
- [ ] UDP listeners on trusted networks only (no authentication)
- [ ] TLS listeners use mTLS (`client_auth = true`) for authenticated ingestion
- [ ] `cargo audit` and `cargo deny check` run in CI
- [ ] Fuzz targets run periodically
- [ ] Log output directed to secure destination
- [ ] Secrets not present in environment variables visible to other users

## Generating Keys

### TLS Certificate (self-signed, for testing)

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout server.key -out server.crt -days 365 -nodes \
  -subj "/CN=syslog.example.com"
```

### RFC 5848 Signing Key (ECDSA P-256, PKCS#8 DER)

```bash
# Generate PKCS#8 DER key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -outform DER -out signing.key

# Extract public key (raw, for verification config)
openssl pkey -in signing.key -inform DER -pubout -outform DER -out signing.pub
```

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

Check that `trusted_key_paths` contains valid file paths to raw public key files:

```toml
[verification]
enabled = true
trusted_key_paths = ["/etc/syslog-usg/sign/trusted.pub"]
reject_unverified = false
```

### High memory usage

Check `pipeline.channel_buffer_size` — reduce if set very high. Default is 4096.
Check `max_connections` — reduce if accepting too many concurrent TCP connections.
