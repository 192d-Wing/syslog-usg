# Phase 08 — Management and Data Model

## syslog-usg: Management Interfaces, YANG Alignment, and Runtime State

**Version:** 1.0.0-draft
**Date:** 2026-03-11
**Status:** Draft
**Prerequisites:** [Phase 01 — Requirements](phase-01-requirements.md), [Phase 02 — RFC Analysis](phase-02-rfc-analysis.md), [Phase 03 — Architecture](phase-03-architecture.md), [Phase 04 — Rust Architecture](phase-04-rust-architecture.md)

---

## Table of Contents

1. [Management Model Summary](#1-management-model-summary)
2. [YANG Alignment Notes](#2-yang-alignment-notes)
3. [Runtime Config/State Model](#3-runtime-configstate-model)
4. [Administrative Operations](#4-administrative-operations)
5. [RFC 5427 Textual Convention Mapping](#5-rfc-5427-textual-convention-mapping)
6. [Monitoring/Management Integration Points](#6-monitoringmanagement-integration-points)

---

## 1. Management Model Summary

syslog-usg exposes four categories of management capability: configuration management, runtime state inspection, administrative operations, and health/readiness probes. The MVP delivers all four via TOML configuration files, an HTTP admin API, and Prometheus-format metrics. Future phases add YANG/NETCONF/RESTCONF and SNMP MIB support.

### 1.1 Configuration Management

| Capability | Mechanism | Notes |
|------------|-----------|-------|
| Initial configuration | TOML file at startup | Default path `/etc/syslog-usg/syslog-usg.toml`, override via `--config` |
| Configuration validation | `syslog-usg validate-config` subcommand | Validates syntax, semantic cross-references, TLS cert existence, and filter/route consistency; exits 0 on success, 1 on error |
| Hot reload | `SIGHUP` signal or `POST /api/v1/reload` | New config is validated before applying; on failure the running config remains active |
| Environment substitution | `${VAR}` and `${VAR:-default}` in string values | Evaluated at load time, before TOML parsing |
| Config versioning | Internal monotonic config generation counter | Incremented on each successful reload; exposed in status API and metrics |

**Reload semantics:** A reload performs an atomic config swap. The server validates the new configuration, constructs new pipeline components, drains the old pipeline, then switches. Existing TLS connections are not dropped unless their listener is removed from the new configuration.

### 1.2 Runtime State Inspection

The server tracks operational state across all pipeline stages. This state is observable through two channels:

- **Prometheus metrics** (`GET /metrics`) — Counters, gauges, and histograms for throughput, latency, queue depth, errors, and connection counts. Suitable for time-series alerting and dashboards.
- **JSON status API** (`GET /api/v1/status`) — A point-in-time snapshot of the full runtime state tree. Suitable for ad-hoc inspection, debugging, and integration with orchestration tooling.

### 1.3 Administrative Operations

| Operation | Trigger | Behavior |
|-----------|---------|----------|
| **Reload** | `SIGHUP` or `POST /api/v1/reload` | Validate new config, atomic swap, no connection drops for unchanged listeners |
| **Drain** | `POST /api/v1/drain` | Stop accepting new messages, flush all output queues, then report completion |
| **Shutdown** | `SIGTERM` / `SIGINT` | Stop accepting, drain queues (up to `drain_timeout`), exit |
| **Liveness check** | `GET /health` | Returns 200 if the process is alive and the event loop is responsive |
| **Readiness check** | `GET /ready` | Returns 200 only when all listeners are bound and at least one output is reachable |

### 1.4 Health and Readiness Probes

The health model distinguishes liveness from readiness, following the Kubernetes probe contract:

- **Liveness** (`/health`): The process is alive and the Tokio runtime is responsive. A failed liveness probe indicates the process should be restarted. Implementation: a dedicated health-check task that writes a timestamp to a shared `AtomicU64`; the endpoint verifies the timestamp is recent (within 5 seconds).
- **Readiness** (`/ready`): The server is ready to accept and process traffic. This requires: (a) all configured listeners have successfully bound, (b) at least one output has established connectivity or passed its initial health check, and (c) configuration has been loaded and validated. During a drain operation, `/ready` returns 503 to shed traffic before shutdown.

---

## 2. YANG Alignment Notes

RFC 9742 defines the `ietf-syslog` YANG module for configuring syslog implementations. syslog-usg's TOML configuration is designed to map cleanly onto the YANG model, enabling a future RESTCONF API that directly serves the YANG tree. This section documents the mapping between TOML config concepts and RFC 9742 YANG nodes.

### 2.1 Mapping Overview

```
RFC 9742 YANG                           syslog-usg TOML
─────────────────────────────────────   ──────────────────────────────
/syslog                                 (top-level config file)
/syslog/actions/console                 [outputs.console_out] type = "stdout"
/syslog/actions/file/log-file           [outputs.<name>] type = "file"
/syslog/actions/remote/destination      [outputs.<name>] type = "forward_tls" | "forward_udp"
syslog-selector (facility+severity)     [filters.<name>] facilities + min_severity
pattern-match                           [filters.<name>] (future: regex field)
file-rotation                           [outputs.<name>.rotation]
structured-data                         [outputs.<name>] format = "rfc5424" (SD preserved)
signing                                 (future: Phase 2, RFC 5848)
```

### 2.2 syslog-selector to Filter Config

The YANG `syslog-selector` grouping pairs a facility with a severity comparison operator. In the TOML config, this maps to the `FilterConfig` struct:

| YANG Node | TOML Equivalent | Notes |
|-----------|----------------|-------|
| `facility-list/facility` | `filters.<name>.facilities` | List of facility names (e.g., `["kern", "auth", "local0"]`) |
| `facility-list/severity` | `filters.<name>.min_severity` | Severity threshold; YANG default is "equals-or-higher" |
| `severity` special value `all` | `min_severity` omitted | Omitting severity matches all severities |
| `severity` special value `none` | `filters.<name>.negate = true` with broad match | Suppresses all messages matching the facility list |
| `select-adv-compare` feature | Future: `filters.<name>.severity_compare = "equals"` | MVP uses "equals-or-higher" only; exact-match is a future addition |

**Mapping example:**

```
# YANG: facility kern, severity error (equals-or-higher)
# syslog/actions/remote/destination[name="central"]/filter/facility-list[facility=kern][severity=error]

# TOML equivalent:
[filters.kern_errors]
facilities = ["kern"]
min_severity = "error"
```

### 2.3 console-action to Stdout Output

The YANG `console-action` configures logging to the system console. In syslog-usg, this maps to a stdout output:

| YANG Node | TOML Equivalent |
|-----------|----------------|
| `/syslog/actions/console` (presence) | `[outputs.<name>]` with `type = "stdout"` |
| `console/filter` | Route referencing a filter, targeting the stdout output |

### 2.4 file-action to File Output

| YANG Node | TOML Equivalent |
|-----------|----------------|
| `log-file/name` | `[outputs.<name>]` — the TOML table key serves as the name |
| `log-file/name` (value, `file:` URI) | `outputs.<name>.path` — plain filesystem path (no URI scheme required in TOML; YANG requires `file:` scheme) |
| `log-file/structured-data` | `outputs.<name>.format = "rfc5424"` preserves SD; `format = "json"` extracts SD into JSON fields |
| `file-rotation/number-of-files` | `outputs.<name>.rotation.max_files` |
| `file-rotation/max-file-size` | `outputs.<name>.rotation.max_size` — string with unit suffix (e.g., `"100MB"`) |
| `file-rotation/rollover` | `outputs.<name>.rotation.max_age` — string with unit suffix (e.g., `"7d"`) |
| `file-rotation/retention` | Derived from `max_files * max_age` — explicit retention period is a future addition |

### 2.5 remote-action to Forward Outputs

| YANG Node | TOML Equivalent |
|-----------|----------------|
| `destination/name` | `[outputs.<name>]` — the TOML table key |
| `destination/transport/udp` | `type = "forward_udp"` |
| `destination/transport/tls` | `type = "forward_tls"` |
| `destination/transport/udp/port` | Included in `target` (e.g., `"collector.example.com:514"`) |
| `destination/transport/tls/port` | Included in `target` (e.g., `"collector.example.com:6514"`) |
| `destination/transport/tls/client-identity` | `outputs.<name>.tls.cert` and `outputs.<name>.tls.key` |
| `destination/transport/tls/server-authentication` | `outputs.<name>.tls.ca_cert` and `outputs.<name>.tls.fingerprints` |
| `destination/structured-data` | `outputs.<name>.format = "rfc5424"` |
| `destination/facility-override` | Future: `outputs.<name>.facility_override` |
| `destination/source-interface` | Future: `outputs.<name>.source_interface` |
| `destination/filter` | Route filter referencing this output |

### 2.6 structured-data-action to SD Preservation

RFC 9742's `structured-data` boolean controls whether structured data elements are preserved in output messages. In syslog-usg:

- `format = "rfc5424"` — SD elements are preserved verbatim in the output. This is the default.
- `format = "json"` — SD elements are extracted into JSON fields under a `structured_data` key.

Both formats preserve all SD-ELEMENTs and SD-PARAMs. No SD content is ever silently dropped.

### 2.7 Future: RESTCONF API Serving the YANG Model

Post-MVP, syslog-usg will expose a RESTCONF (RFC 8040) API that serves the `ietf-syslog` YANG tree directly. The implementation plan:

1. **YANG-to-Rust codegen** — Generate Rust types from the `ietf-syslog.yang` module using a build-time tool. These types mirror the YANG tree structure with proper leaf types, list keys, and presence containers.
2. **Bidirectional mapping** — Implement `From` conversions between the YANG-derived types and the existing `ServerConfig` types. The internal config model remains the source of truth; YANG types are a projection.
3. **RESTCONF endpoints** — Serve under `/restconf/data/ietf-syslog:syslog/` using axum routes. Support `GET` (read config), `PUT`/`PATCH` (modify config), and `POST` (create new list entries like destinations).
4. **NETCONF transport** — Optionally expose the same data model over NETCONF (RFC 6241) using SSH subsystem transport for environments that require it.

---

## 3. Runtime Config/State Model

### 3.1 State Tree Overview

The runtime state model organizes observable data into four domains: per-listener state, per-output state, per-route state, and global state. All state is maintained in lock-free or low-contention structures suitable for concurrent access from the metrics endpoint and the status API.

```
RuntimeState
├── global
│   ├── uptime_seconds: f64
│   ├── start_time: RFC 3339 timestamp
│   ├── config_version: u64
│   ├── config_loaded_at: RFC 3339 timestamp
│   ├── total_messages_received: u64
│   ├── total_messages_forwarded: u64
│   ├── total_messages_dropped: u64
│   └── total_parse_errors: u64
├── listeners[]
│   ├── name: String
│   ├── bind_address: SocketAddr
│   ├── transport: "udp" | "tcp" | "tls"
│   ├── state: "running" | "draining" | "stopped"
│   ├── connections_active: u64          (TCP/TLS only)
│   ├── connections_total: u64           (TCP/TLS only)
│   ├── messages_received: u64
│   ├── parse_errors: u64
│   ├── bytes_received: u64
│   └── tls_handshake_errors: u64        (TLS only)
├── outputs[]
│   ├── name: String
│   ├── destination: String
│   ├── transport: "tls" | "tcp" | "udp" | "file" | "stdout"
│   ├── state: "connected" | "connecting" | "backoff" | "draining" | "stopped"
│   ├── queue_depth: u64
│   ├── queue_capacity: u64
│   ├── messages_sent: u64
│   ├── messages_dropped: u64
│   ├── bytes_sent: u64
│   ├── send_errors: u64
│   ├── last_error: Option<String>
│   ├── last_error_at: Option<RFC 3339 timestamp>
│   └── last_successful_send_at: Option<RFC 3339 timestamp>
└── routes[]
    ├── name: String
    ├── filter: Option<String>
    ├── outputs: Vec<String>
    ├── messages_matched: u64
    ├── messages_not_matched: u64
    └── last_match_at: Option<RFC 3339 timestamp>
```

### 3.2 Rust Struct Definitions

```rust
// syslog-mgmt/src/state.rs

use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use time::OffsetDateTime;

/// Complete runtime state snapshot, serializable to JSON.
#[derive(Debug, Serialize)]
pub struct RuntimeStateSnapshot {
    pub global: GlobalState,
    pub listeners: Vec<ListenerState>,
    pub outputs: Vec<OutputState>,
    pub routes: Vec<RouteState>,
}

#[derive(Debug, Serialize)]
pub struct GlobalState {
    pub uptime_seconds: f64,
    pub start_time: String,
    pub config_version: u64,
    pub config_loaded_at: String,
    pub total_messages_received: u64,
    pub total_messages_forwarded: u64,
    pub total_messages_dropped: u64,
    pub total_parse_errors: u64,
}

#[derive(Debug, Serialize)]
pub struct ListenerState {
    pub name: String,
    pub bind_address: SocketAddr,
    pub transport: TransportType,
    pub state: ComponentState,
    pub connections_active: Option<u64>,
    pub connections_total: Option<u64>,
    pub messages_received: u64,
    pub parse_errors: u64,
    pub bytes_received: u64,
    pub tls_handshake_errors: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct OutputState {
    pub name: String,
    pub destination: String,
    pub transport: TransportType,
    pub state: OutputConnectionState,
    pub queue_depth: u64,
    pub queue_capacity: u64,
    pub messages_sent: u64,
    pub messages_dropped: u64,
    pub bytes_sent: u64,
    pub send_errors: u64,
    pub last_error: Option<String>,
    pub last_error_at: Option<String>,
    pub last_successful_send_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RouteState {
    pub name: String,
    pub filter: Option<String>,
    pub outputs: Vec<String>,
    pub messages_matched: u64,
    pub messages_not_matched: u64,
    pub last_match_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Udp,
    Tcp,
    Tls,
    File,
    Stdout,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentState {
    Running,
    Draining,
    Stopped,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputConnectionState {
    Connected,
    Connecting,
    Backoff,
    Draining,
    Stopped,
}
```

### 3.3 Live State Counters

The runtime state is tracked using atomic counters to avoid lock contention on the hot path. Each listener and output holds an `Arc<ComponentCounters>` shared between the worker task and the state-collection layer.

```rust
// syslog-mgmt/src/counters.rs

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters for a single pipeline component.
/// Shared between the worker task (writes) and the status
/// API (reads). All operations use Relaxed ordering; exact
/// consistency is not required for monitoring data.
pub struct ComponentCounters {
    pub messages_in: AtomicU64,
    pub messages_out: AtomicU64,
    pub messages_dropped: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub errors: AtomicU64,
    pub connections_active: AtomicU64,
    pub connections_total: AtomicU64,
    pub queue_depth: AtomicU64,
}

impl ComponentCounters {
    pub fn new() -> Self {
        Self {
            messages_in: AtomicU64::new(0),
            messages_out: AtomicU64::new(0),
            messages_dropped: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            connections_active: AtomicU64::new(0),
            connections_total: AtomicU64::new(0),
            queue_depth: AtomicU64::new(0),
        }
    }

    /// Create a snapshot for serialization. Reads use Relaxed
    /// ordering — counters may be slightly stale but never torn.
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            messages_in: self.messages_in.load(Ordering::Relaxed),
            messages_out: self.messages_out.load(Ordering::Relaxed),
            messages_dropped: self.messages_dropped.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            connections_active: self.connections_active.load(Ordering::Relaxed),
            connections_total: self.connections_total.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CounterSnapshot {
    pub messages_in: u64,
    pub messages_out: u64,
    pub messages_dropped: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub errors: u64,
    pub connections_active: u64,
    pub connections_total: u64,
    pub queue_depth: u64,
}
```

### 3.4 Prometheus Metrics Mapping

Each runtime state field has a corresponding Prometheus metric. The status API and Prometheus metrics are backed by the same `ComponentCounters`, ensuring consistency.

| Runtime State Field | Prometheus Metric | Type | Labels |
|--------------------|--------------------|------|--------|
| `listener.messages_received` | `syslog_messages_received_total` | counter | `listener`, `transport`, `facility`, `severity` |
| `listener.parse_errors` | `syslog_parse_errors_total` | counter | `listener`, `error_type` |
| `listener.connections_active` | `syslog_connections_active` | gauge | `listener`, `transport` |
| `listener.tls_handshake_errors` | `syslog_tls_handshake_errors_total` | counter | `listener`, `error_type` |
| `listener.bytes_received` | `syslog_bytes_received_total` | counter | `listener`, `transport` |
| `output.messages_sent` | `syslog_messages_forwarded_total` | counter | `output` |
| `output.messages_dropped` | `syslog_messages_dropped_total` | counter | `output`, `reason` |
| `output.queue_depth` | `syslog_queue_depth` | gauge | `output` |
| `output.queue_capacity` | `syslog_queue_capacity` | gauge | `output` |
| `output.send_errors` | `syslog_output_errors_total` | counter | `output`, `error_type` |
| `output.bytes_sent` | `syslog_bytes_sent_total` | counter | `output` |
| `route.messages_matched` | `syslog_route_matches_total` | counter | `route` |
| `global.config_version` | `syslog_config_version` | gauge | — |
| `global.uptime_seconds` | `syslog_uptime_seconds` | gauge | — |
| (parse latency) | `syslog_parse_duration_seconds` | histogram | `format` |
| (forward latency) | `syslog_forward_duration_seconds` | histogram | `output` |
| (TLS cert expiry) | `syslog_tls_cert_expiry_seconds` | gauge | `listener`, `subject` |

---

## 4. Administrative Operations

### 4.1 HTTP Admin API

The admin API is served by the same axum HTTP server that serves metrics. It binds to the address configured in `[metrics].bind` (default `127.0.0.1:9090`). All admin endpoints share the same listener.

#### Endpoint Summary

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | None | Liveness probe — returns 200 if event loop is responsive |
| `GET` | `/ready` | None | Readiness probe — returns 200 when all listeners bound and outputs reachable |
| `GET` | `/metrics` | None | Prometheus exposition format metrics |
| `GET` | `/api/v1/status` | API key | Full runtime state as JSON |
| `POST` | `/api/v1/reload` | API key | Trigger configuration reload |
| `POST` | `/api/v1/drain` | API key | Initiate graceful drain |

#### 4.1.1 GET /health

Returns 200 with a minimal JSON body when the server is alive. Returns 503 if the health-check task has not updated its heartbeat within 5 seconds (indicating a stalled runtime).

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "ok"
}
```

#### 4.1.2 GET /ready

Returns 200 when all startup conditions are met and the server is accepting traffic. Returns 503 during startup (before listeners are bound), during drain, or when all outputs are unreachable.

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "ready",
  "listeners_bound": 2,
  "outputs_reachable": 3
}
```

```
HTTP/1.1 503 Service Unavailable
Content-Type: application/json

{
  "status": "not_ready",
  "reason": "draining",
  "listeners_bound": 2,
  "outputs_reachable": 0
}
```

#### 4.1.3 GET /metrics

Standard Prometheus exposition format. No authentication required (metrics endpoints are conventionally open for scraping). Access control should be enforced at the network level (bind to localhost or use a sidecar proxy).

```
# HELP syslog_messages_received_total Total syslog messages received
# TYPE syslog_messages_received_total counter
syslog_messages_received_total{listener="udp_514",transport="udp",facility="kern",severity="error"} 42891
syslog_messages_received_total{listener="tls_6514",transport="tls",facility="auth",severity="info"} 18234
...
```

#### 4.1.4 GET /api/v1/status

Returns the complete `RuntimeStateSnapshot` as JSON. Requires authentication.

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "global": {
    "uptime_seconds": 86421.3,
    "start_time": "2026-03-10T08:00:00.000Z",
    "config_version": 3,
    "config_loaded_at": "2026-03-10T14:30:12.000Z",
    "total_messages_received": 1284903,
    "total_messages_forwarded": 1284811,
    "total_messages_dropped": 12,
    "total_parse_errors": 80
  },
  "listeners": [
    {
      "name": "udp_514",
      "bind_address": "0.0.0.0:514",
      "transport": "udp",
      "state": "running",
      "connections_active": null,
      "connections_total": null,
      "messages_received": 984210,
      "parse_errors": 73,
      "bytes_received": 503412480,
      "tls_handshake_errors": null
    }
  ],
  "outputs": [
    {
      "name": "central_tls",
      "destination": "siem.internal.example.com:6514",
      "transport": "tls",
      "state": "connected",
      "queue_depth": 42,
      "queue_capacity": 10000,
      "messages_sent": 984137,
      "messages_dropped": 0,
      "bytes_sent": 503100000,
      "send_errors": 2,
      "last_error": "connection reset by peer",
      "last_error_at": "2026-03-10T12:15:33.000Z",
      "last_successful_send_at": "2026-03-11T08:00:21.000Z"
    }
  ],
  "routes": [
    {
      "name": "critical_to_central",
      "filter": "critical_only",
      "outputs": ["central_tls"],
      "messages_matched": 127,
      "messages_not_matched": 1284776,
      "last_match_at": "2026-03-11T07:59:44.000Z"
    }
  ]
}
```

#### 4.1.5 POST /api/v1/reload

Triggers a configuration reload. The server re-reads the config file, validates it, and applies changes atomically. Returns the result of the reload operation.

**Request:**
```
POST /api/v1/reload HTTP/1.1
X-API-Key: <token>
```

**Success response:**
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "ok",
  "config_version": 4,
  "changes": {
    "listeners_added": [],
    "listeners_removed": [],
    "outputs_added": ["backup_file"],
    "outputs_removed": [],
    "routes_changed": true
  }
}
```

**Failure response (invalid config):**
```
HTTP/1.1 422 Unprocessable Entity
Content-Type: application/json

{
  "status": "error",
  "config_version": 3,
  "errors": [
    "validation error at 'outputs.broken_tls.tls.cert': file not found: /etc/syslog-usg/tls/missing.crt"
  ]
}
```

#### 4.1.6 POST /api/v1/drain

Initiates a graceful drain. The server stops accepting new messages on all listeners, flushes all output queues, and transitions the readiness state to "not ready." The drain operation respects the configured `drain_timeout`. After drain completes, the server remains running (it does not exit) — this allows load balancers to redirect traffic before a controlled shutdown.

**Request:**
```
POST /api/v1/drain HTTP/1.1
X-API-Key: <token>

{
  "timeout_seconds": 30
}
```

**Response:**
```
HTTP/1.1 202 Accepted
Content-Type: application/json

{
  "status": "draining",
  "timeout_seconds": 30
}
```

The drain status can be polled via `GET /api/v1/status` (check the `state` field of listeners and outputs) or `GET /ready` (returns 503 during drain).

### 4.2 Authentication

The admin API supports two authentication mechanisms. Health and metrics endpoints are unauthenticated (required for Prometheus scraping and Kubernetes probes). The `/api/v1/*` endpoints require authentication.

#### 4.2.1 API Key Header (MVP)

A pre-shared API key is configured in the server config and presented via the `X-API-Key` request header.

```toml
[admin]
api_key = "${SYSLOG_ADMIN_API_KEY}"
```

```
POST /api/v1/reload HTTP/1.1
X-API-Key: sk-syslog-usg-a1b2c3d4e5f6
```

If the `[admin].api_key` field is not set, the `/api/v1/*` endpoints return 403 for all requests (fail-closed). The API key is never logged or exposed in metrics.

#### 4.2.2 Mutual TLS (Future)

For production deployments, the admin HTTP server can be configured to require client certificates. This is the same mTLS mechanism used for syslog transport, reusing the existing TLS configuration infrastructure.

```toml
[admin]
tls.cert = "/etc/syslog-usg/tls/admin-server.crt"
tls.key = "/etc/syslog-usg/tls/admin-server.key"
tls.ca_cert = "/etc/syslog-usg/tls/admin-ca.crt"
tls.mutual_auth = true
```

When mTLS is enabled, the API key header is not required (client certificate identity is sufficient).

### 4.3 Admin Config Struct

```rust
// syslog-config/src/model.rs (addition to existing ServerConfig)

/// Administrative API configuration.
#[derive(Debug, Deserialize)]
pub struct AdminConfig {
    /// Pre-shared API key for /api/v1/* endpoints.
    /// If unset, admin endpoints return 403 for all requests.
    pub api_key: Option<String>,

    /// Optional TLS configuration for the admin HTTP server.
    /// When set with mutual_auth = true, enables mTLS authentication.
    pub tls: Option<TlsConfig>,

    /// Bind address for the admin/metrics HTTP server.
    /// Defaults to 127.0.0.1:9090.
    #[serde(default = "default_metrics_bind")]
    pub bind: SocketAddr,
}
```

---

## 5. RFC 5427 Textual Convention Mapping

RFC 5427 defines the `SyslogFacility` and `SyslogSeverity` SNMP textual conventions, establishing the canonical name-to-number mapping for syslog facility and severity codes. These enumerations are used throughout syslog-usg: in configuration files, log output, metrics labels, the status API, and future SNMP MIB exposure.

### 5.1 Facility Enum

```rust
// syslog-proto/src/facility.rs

use std::fmt;

/// Syslog facility codes as defined by RFC 5424 Section 6.2.1
/// and RFC 5427 Section 2 (SNMP textual convention).
///
/// The Display impl produces the RFC 5427 canonical names used
/// in TOML config, Prometheus labels, and JSON output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Facility {
    Kern     = 0,
    User     = 1,
    Mail     = 2,
    Daemon   = 3,
    Auth     = 4,
    Syslog   = 5,
    Lpr      = 6,
    News     = 7,
    Uucp     = 8,
    Cron     = 9,
    Authpriv = 10,
    Ftp      = 11,
    Ntp      = 12,
    Audit    = 13,
    Console  = 14,
    Cron2    = 15,
    Local0   = 16,
    Local1   = 17,
    Local2   = 18,
    Local3   = 19,
    Local4   = 20,
    Local5   = 21,
    Local6   = 22,
    Local7   = 23,
}

impl Facility {
    /// All valid facility values, ordered by numeric code.
    pub const ALL: [Facility; 24] = [
        Self::Kern, Self::User, Self::Mail, Self::Daemon,
        Self::Auth, Self::Syslog, Self::Lpr, Self::News,
        Self::Uucp, Self::Cron, Self::Authpriv, Self::Ftp,
        Self::Ntp, Self::Audit, Self::Console, Self::Cron2,
        Self::Local0, Self::Local1, Self::Local2, Self::Local3,
        Self::Local4, Self::Local5, Self::Local6, Self::Local7,
    ];

    /// Return the numeric code (0-23).
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Return the RFC 5427 canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kern     => "kern",
            Self::User     => "user",
            Self::Mail     => "mail",
            Self::Daemon   => "daemon",
            Self::Auth     => "auth",
            Self::Syslog   => "syslog",
            Self::Lpr      => "lpr",
            Self::News     => "news",
            Self::Uucp     => "uucp",
            Self::Cron     => "cron",
            Self::Authpriv => "authpriv",
            Self::Ftp      => "ftp",
            Self::Ntp      => "ntp",
            Self::Audit    => "audit",
            Self::Console  => "console",
            Self::Cron2    => "cron2",
            Self::Local0   => "local0",
            Self::Local1   => "local1",
            Self::Local2   => "local2",
            Self::Local3   => "local3",
            Self::Local4   => "local4",
            Self::Local5   => "local5",
            Self::Local6   => "local6",
            Self::Local7   => "local7",
        }
    }
}

impl fmt::Display for Facility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl From<Facility> for u8 {
    fn from(f: Facility) -> u8 {
        f.code()
    }
}

impl TryFrom<u8> for Facility {
    type Error = InvalidFacility;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::ALL
            .get(value as usize)
            .copied()
            .ok_or(InvalidFacility(value))
    }
}

impl TryFrom<&str> for Facility {
    type Error = UnknownFacilityName;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        // Case-insensitive lookup to tolerate config variations.
        let lower = name.to_ascii_lowercase();
        Self::ALL
            .iter()
            .find(|f| f.name() == lower)
            .copied()
            .ok_or_else(|| UnknownFacilityName(name.to_owned()))
    }
}

/// Error returned when a numeric facility code is out of range (>23).
#[derive(Debug, thiserror::Error)]
#[error("invalid facility code: {0} (valid range: 0-23)")]
pub struct InvalidFacility(pub u8);

/// Error returned when a facility name string is not recognized.
#[derive(Debug, thiserror::Error)]
#[error("unknown facility name: {0:?}")]
pub struct UnknownFacilityName(pub String);
```

### 5.2 Severity Enum

```rust
// syslog-proto/src/severity.rs

use std::fmt;

/// Syslog severity levels as defined by RFC 5424 Section 6.2.1
/// and RFC 5427 Section 2 (SNMP textual convention).
///
/// Severity is ordered by urgency: Emergency (0) is most urgent,
/// Debug (7) is least urgent. The Ord implementation reflects
/// this: Emergency > Alert > Critical > ... > Debug.
///
/// The Display impl produces the RFC 5427 canonical names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Severity {
    Emergency     = 0,
    Alert         = 1,
    Critical      = 2,
    Error         = 3,
    Warning       = 4,
    Notice        = 5,
    Informational = 6,
    Debug         = 7,
}

impl Severity {
    /// All valid severity values, ordered by numeric code
    /// (most urgent first).
    pub const ALL: [Severity; 8] = [
        Self::Emergency, Self::Alert, Self::Critical, Self::Error,
        Self::Warning, Self::Notice, Self::Informational, Self::Debug,
    ];

    /// Return the numeric code (0-7).
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Return the RFC 5427 canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Emergency     => "emergency",
            Self::Alert         => "alert",
            Self::Critical      => "critical",
            Self::Error         => "error",
            Self::Warning       => "warning",
            Self::Notice        => "notice",
            Self::Informational => "informational",
            Self::Debug         => "debug",
        }
    }

    /// Return common short aliases accepted in configuration.
    /// These are not RFC 5427 names but are widely used.
    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::Emergency     => &["emerg", "panic"],
            Self::Alert         => &["alert"],
            Self::Critical      => &["crit"],
            Self::Error         => &["err"],
            Self::Warning       => &["warn"],
            Self::Notice        => &["notice"],
            Self::Informational => &["info"],
            Self::Debug         => &["debug"],
        }
    }

    /// Returns true if this severity is at least as urgent as
    /// `threshold`. Used for "equals-or-higher" filter matching
    /// per RFC 9742 default semantics.
    ///
    /// Example: `Severity::Error.is_at_least(Severity::Warning)` is true
    /// because Error (3) is more urgent than Warning (4).
    pub const fn is_at_least(self, threshold: Severity) -> bool {
        self.code() <= threshold.code()
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Ordering by urgency: lower numeric code = higher urgency = "greater."
/// This means Emergency > Alert > ... > Debug in Ord terms,
/// matching the intuitive "severity comparison" in filter rules.
impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse numeric order: lower code = higher severity.
        other.code().cmp(&self.code())
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<Severity> for u8 {
    fn from(s: Severity) -> u8 {
        s.code()
    }
}

impl TryFrom<u8> for Severity {
    type Error = InvalidSeverity;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::ALL
            .get(value as usize)
            .copied()
            .ok_or(InvalidSeverity(value))
    }
}

impl TryFrom<&str> for Severity {
    type Error = UnknownSeverityName;

    /// Parse a severity name. Accepts both RFC 5427 canonical
    /// names ("emergency", "informational") and common short
    /// aliases ("emerg", "crit", "err", "warn", "info").
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        let lower = name.to_ascii_lowercase();
        // Check canonical names first.
        if let Some(s) = Self::ALL.iter().find(|s| s.name() == lower) {
            return Ok(*s);
        }
        // Check aliases.
        if let Some(s) = Self::ALL.iter().find(|s| {
            s.aliases().iter().any(|a| *a == lower)
        }) {
            return Ok(*s);
        }
        Err(UnknownSeverityName(name.to_owned()))
    }
}

/// Error returned when a numeric severity code is out of range (>7).
#[derive(Debug, thiserror::Error)]
#[error("invalid severity code: {0} (valid range: 0-7)")]
pub struct InvalidSeverity(pub u8);

/// Error returned when a severity name string is not recognized.
#[derive(Debug, thiserror::Error)]
#[error("unknown severity name: {0:?}")]
pub struct UnknownSeverityName(pub String);
```

### 5.3 Serde Integration

Both enums implement `Serialize` and `Deserialize` using their RFC 5427 canonical names. This ensures consistent representation across TOML config, JSON API output, and Prometheus labels.

```rust
// syslog-proto/src/facility.rs (additional impls)

impl serde::Serialize for Facility {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

impl<'de> serde::Deserialize<'de> for Facility {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let name = String::deserialize(d)?;
        Facility::try_from(name.as_str()).map_err(serde::de::Error::custom)
    }
}
```

```rust
// syslog-proto/src/severity.rs (additional impls)

impl serde::Serialize for Severity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

impl<'de> serde::Deserialize<'de> for Severity {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let name = String::deserialize(d)?;
        Severity::try_from(name.as_str()).map_err(serde::de::Error::custom)
    }
}
```

### 5.4 Usage Across the System

| Context | Representation | Example |
|---------|---------------|---------|
| TOML config filter | RFC 5427 name or alias | `min_severity = "error"` or `min_severity = "err"` |
| TOML config facility list | RFC 5427 name | `facilities = ["kern", "auth", "local0"]` |
| Prometheus metric label | RFC 5427 name | `facility="kern"`, `severity="error"` |
| JSON status API | RFC 5427 name | `"facility": "kern"` |
| Internal PRI encoding | Numeric | `facility.code() * 8 + severity.code()` |
| Log output (RFC 5424 wire) | Numeric (in PRI) | `<34>` = auth(4) * 8 + critical(2) |
| Future SNMP MIB | RFC 5427 enumeration value | `SyslogFacility ::= kern(0)` |
| Future YANG/RESTCONF | RFC 9742 identity | `syslog-types:kern` |

### 5.5 RFC 5427 Compliance Notes

1. **Closed enumeration:** The facility range is 0-23 and severity range is 0-7. `TryFrom<u8>` returns an error for out-of-range values. No extension mechanism exists in the RFC.
2. **OS-specific ambiguity:** Codes 4/10 (`auth`/`authpriv`), 9/15 (`cron`/`cron2`), and 13/14 (`audit`/`console`) have overlapping meanings across operating systems. syslog-usg uses the RFC 5427 canonical names and does not attempt OS-specific remapping.
3. **Name stability:** The `Display` impl and serde serialization always produce the RFC 5427 canonical name (e.g., `"informational"`, not `"info"`). Short aliases are accepted on input only.

---

## 6. Monitoring/Management Integration Points

This section describes how external systems interact with syslog-usg for monitoring, configuration management, and orchestration.

### 6.1 Prometheus Scraping

**Integration pattern:** Prometheus (or a compatible agent such as Grafana Agent, Victoria Metrics, etc.) scrapes the `/metrics` endpoint at a configured interval.

**Configuration:**

```yaml
# prometheus.yml
scrape_configs:
  - job_name: syslog-usg
    scrape_interval: 15s
    static_configs:
      - targets: ["syslog-usg.internal:9090"]
```

**Key metrics for alerting:**

| Alert Condition | Metric Expression |
|----------------|-------------------|
| Message drops occurring | `rate(syslog_messages_dropped_total[5m]) > 0` |
| Queue approaching capacity | `syslog_queue_depth / syslog_queue_capacity > 0.8` |
| Parse error spike | `rate(syslog_parse_errors_total[5m]) > 100` |
| TLS certificate expiring | `syslog_tls_cert_expiry_seconds < 604800` (7 days) |
| Output unreachable | `syslog_output_errors_total` increasing with no `syslog_messages_forwarded_total` increase |
| No messages received | `rate(syslog_messages_received_total[5m]) == 0` (for normally active listeners) |

### 6.2 Kubernetes Probes

**Integration pattern:** Kubernetes uses HTTP probes against `/health` and `/ready` to manage pod lifecycle.

```yaml
# Kubernetes deployment spec (excerpt)
containers:
  - name: syslog-usg
    ports:
      - containerPort: 514
        protocol: UDP
      - containerPort: 6514
        protocol: TCP
      - containerPort: 9090
        name: admin
    livenessProbe:
      httpGet:
        path: /health
        port: admin
      initialDelaySeconds: 5
      periodSeconds: 10
      failureThreshold: 3
    readinessProbe:
      httpGet:
        path: /ready
        port: admin
      initialDelaySeconds: 3
      periodSeconds: 5
      failureThreshold: 2
    startupProbe:
      httpGet:
        path: /ready
        port: admin
      initialDelaySeconds: 1
      periodSeconds: 2
      failureThreshold: 30
```

**Behavior during lifecycle events:**

| Event | `/health` | `/ready` |
|-------|-----------|----------|
| Starting (before listeners bind) | 200 | 503 |
| Running normally | 200 | 200 |
| Config reload in progress | 200 | 200 (existing config still active) |
| Draining (pre-shutdown) | 200 | 503 |
| Runtime stall (event loop blocked) | 503 | 503 |

### 6.3 Configuration Management Tools

**Integration pattern:** External tools (Ansible, Puppet, Chef, Terraform, or custom automation) write the TOML config file and signal the process to reload.

**Workflow:**

1. Config management tool renders the TOML template with host-specific values.
2. Tool writes the file to `/etc/syslog-usg/syslog-usg.toml` (atomic rename for safety).
3. Tool validates the config by running `syslog-usg validate-config --config /etc/syslog-usg/syslog-usg.toml`.
4. If validation passes, tool sends `SIGHUP` to the process: `kill -HUP $(cat /run/syslog-usg.pid)`.
5. Alternatively, tool calls `POST /api/v1/reload` and checks the response for errors.

**Ansible example:**

```yaml
- name: Deploy syslog-usg config
  template:
    src: syslog-usg.toml.j2
    dest: /etc/syslog-usg/syslog-usg.toml
    owner: syslog
    group: syslog
    mode: "0640"
  notify: reload syslog-usg

- name: Validate config before reload
  command: syslog-usg validate-config --config /etc/syslog-usg/syslog-usg.toml
  changed_when: false

handlers:
  - name: reload syslog-usg
    systemd:
      name: syslog-usg
      state: reloaded
```

### 6.4 Future: NETCONF/RESTCONF for YANG-Native Management

**Target phase:** Phase 4 (Management Plane)

NETCONF and RESTCONF provide standards-based configuration management using the RFC 9742 YANG model. This enables network management systems (NMS) that already speak YANG to manage syslog-usg without syslog-specific integration code.

**RESTCONF integration:**

| Operation | HTTP Method | Path | YANG Node |
|-----------|-------------|------|-----------|
| Read full config | `GET` | `/restconf/data/ietf-syslog:syslog` | `/syslog` |
| Read remote destinations | `GET` | `/restconf/data/ietf-syslog:syslog/actions/remote` | `/syslog/actions/remote` |
| Add a remote destination | `POST` | `/restconf/data/ietf-syslog:syslog/actions/remote/destination` | new list entry |
| Modify file rotation | `PATCH` | `/restconf/data/ietf-syslog:syslog/actions/file/log-file=messages/file-rotation` | leaf update |
| Delete a file output | `DELETE` | `/restconf/data/ietf-syslog:syslog/actions/file/log-file=messages` | remove list entry |

**NETCONF integration:**

The same YANG model is served over NETCONF (RFC 6241) using SSH subsystem transport. This is the preferred management protocol for network equipment and existing NMS deployments.

**Implementation approach:**

1. YANG model compiled into Rust types at build time.
2. RESTCONF served as additional axum routes on the admin HTTP server.
3. NETCONF served via a dedicated SSH listener (separate from the admin HTTP server) using an async SSH library.
4. Both protocols share the same internal config-apply logic: validate, build pipeline, atomic swap.

### 6.5 Future: SNMP Agent for RFC 5427 MIB Exposure

**Target phase:** Phase 4 (Management Plane)

An embedded SNMP agent exposes the RFC 5427 textual conventions and operational state via standard MIB objects. This enables legacy NMS platforms that use SNMP for monitoring.

**MIB objects exposed:**

| OID (conceptual) | Description | Source |
|-------------------|-------------|--------|
| `syslogMsgFacility` | Facility of last received message | RFC 5427 TC |
| `syslogMsgSeverity` | Severity of last received message | RFC 5427 TC |
| `syslogMsgReceivedTotal` | Total messages received | `ComponentCounters.messages_in` |
| `syslogMsgForwardedTotal` | Total messages forwarded | `ComponentCounters.messages_out` |
| `syslogMsgDroppedTotal` | Total messages dropped | `ComponentCounters.messages_dropped` |
| `syslogQueueDepth` | Current queue depth per output | `ComponentCounters.queue_depth` |

**SNMP trap generation:** When configured, syslog-usg can generate SNMP traps for critical operational events (output unreachable, queue overflow, TLS certificate expiry). This uses the syslog-to-SNMP mapping defined in RFC 5676.

**Implementation approach:**

1. Embed a lightweight SNMPv3 agent using the `rasn` crate for ASN.1 encoding or a purpose-built SNMP responder.
2. MIB objects map directly to the existing `ComponentCounters` atomic fields.
3. Agent listens on a configurable UDP port (default 161) and responds to GET/GETNEXT/GETBULK requests.
4. SNMPv3 with USM (User-based Security Model) for authentication and privacy.

### 6.6 Integration Architecture Summary

```
                    ┌───────────────────────────────────────────────┐
                    │                syslog-usg                      │
                    │                                               │
 Syslog sources ──► │  Listeners ─► Pipeline ─► Outputs ──►  Destinations
                    │       │                      │               │
                    │       └──────┬───────────────┘               │
                    │              │                                │
                    │     ComponentCounters (AtomicU64)             │
                    │              │                                │
                    │   ┌──────────┼──────────┐                    │
                    │   │          │          │                     │
                    │   ▼          ▼          ▼                     │
                    │ /metrics  /api/v1/*  /health                  │
                    │ /ready                                        │
                    └──┬──────────┬──────────┬─────────────────────┘
                       │          │          │
                       ▼          ▼          ▼
                  Prometheus   Config     Kubernetes
                  scraper      mgmt       probes
                               tools
                       │          │
                       ▼          ▼
                  Grafana     Ansible/
                  dashboards  Terraform
```

**Future additions (dashed lines in the architecture):**

- RESTCONF endpoint alongside `/api/v1/*` on the admin HTTP server.
- NETCONF listener on a dedicated SSH port.
- SNMP agent on UDP port 161.
- All three share the same `ComponentCounters` and config-apply infrastructure.

---

## Appendix A: Admin API Quick Reference

| Method | Path | Auth | Status Codes | Purpose |
|--------|------|------|-------------|---------|
| `GET` | `/health` | None | 200, 503 | Liveness probe |
| `GET` | `/ready` | None | 200, 503 | Readiness probe |
| `GET` | `/metrics` | None | 200 | Prometheus metrics |
| `GET` | `/api/v1/status` | API key / mTLS | 200, 401, 403 | Runtime state snapshot |
| `POST` | `/api/v1/reload` | API key / mTLS | 200, 401, 403, 422 | Trigger config reload |
| `POST` | `/api/v1/drain` | API key / mTLS | 202, 401, 403 | Initiate graceful drain |

## Appendix B: YANG-to-TOML Mapping Table

| RFC 9742 YANG Path | TOML Path | Notes |
|--------------------|-----------|----|
| `/syslog` | (root) | Presence container = config file exists |
| `/syslog/actions/console/filter` | `[filters.<name>]` referenced by route targeting stdout output | Indirect mapping via route |
| `/syslog/actions/file/log-file[name]` | `[outputs.<name>]` with `type = "file"` | YANG `name` is a `file:` URI; TOML uses plain path |
| `/syslog/actions/file/log-file/file-rotation/number-of-files` | `outputs.<name>.rotation.max_files` | |
| `/syslog/actions/file/log-file/file-rotation/max-file-size` | `outputs.<name>.rotation.max_size` | YANG: uint32 in MB; TOML: string with unit |
| `/syslog/actions/file/log-file/file-rotation/rollover` | `outputs.<name>.rotation.max_age` | YANG: uint32 in minutes; TOML: string with unit |
| `/syslog/actions/remote/destination[name]` | `[outputs.<name>]` with `type = "forward_tls"` or `"forward_udp"` | |
| `/syslog/actions/remote/destination/transport/udp` | `type = "forward_udp"`, port in `target` | |
| `/syslog/actions/remote/destination/transport/tls` | `type = "forward_tls"`, TLS config in `outputs.<name>.tls` | |
| `/syslog/actions/remote/destination/transport/tls/client-identity` | `outputs.<name>.tls.cert` + `outputs.<name>.tls.key` | |
| `/syslog/actions/remote/destination/filter/facility-list` | `[filters.<name>].facilities` + `min_severity` | |
| `/syslog/actions/remote/destination/structured-data` | `outputs.<name>.format` | `rfc5424` = SD preserved; `json` = SD in JSON |
| `/syslog/actions/remote/destination/facility-override` | Future: `outputs.<name>.facility_override` | |
| `/syslog/actions/remote/destination/signing` | Future: Phase 2 (RFC 5848) | |

## Appendix C: Referenced RFCs

| RFC | Title | Relevance to This Document |
|-----|-------|----|
| RFC 5424 | The Syslog Protocol | Facility/severity definitions, message format |
| RFC 5427 | Textual Conventions for Syslog Management | Canonical facility/severity enumerations |
| RFC 9742 | A YANG Data Model for Syslog Configuration | Configuration model alignment |
| RFC 5425 | TLS Transport Mapping for Syslog | TLS config model |
| RFC 5426 | Transmission of Syslog Messages over UDP | UDP transport config |
| RFC 5848 | Signed Syslog Messages | Future signing configuration |
| RFC 8040 | RESTCONF Protocol | Future management API |
| RFC 6241 | Network Configuration Protocol (NETCONF) | Future management protocol |

