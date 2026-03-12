# Phase 09 — Observability and Operations

## syslog-usg: Metrics, Logging, Tracing, Health Endpoints, and Operational Dashboards

**Version:** 1.0.0-draft
**Date:** 2026-03-11
**Status:** Draft
**Prerequisites:** [Phase 01 — Requirements](phase-01-requirements.md), [Phase 03 — Architecture](phase-03-architecture.md), [Phase 04 — Rust Architecture](phase-04-rust-architecture.md)

---

## Table of Contents

1. [Metrics Catalog](#1-metrics-catalog)
2. [Telemetry Plan](#2-telemetry-plan)
3. [Structured Logging](#3-structured-logging)
4. [Health, Readiness, and Liveness Endpoints](#4-health-readiness-and-liveness-endpoints)
5. [Operational Dashboards](#5-operational-dashboards)
6. [Capacity Metrics](#6-capacity-metrics)

---

## 1. Metrics Catalog

All metric names are prefixed with `syslog_` to avoid collisions in shared Prometheus environments. The metric naming convention follows the [Prometheus naming best practices](https://prometheus.io/docs/practices/naming/): `syslog_<subsystem>_<name>_<unit>`.

### 1.1 Counters

Counters are monotonically increasing values that reset only on process restart. They are used for events that can only go up: messages received, errors encountered, connections accepted.

| Metric Name | Labels | Description |
|-------------|--------|-------------|
| `syslog_messages_received_total` | `listener`, `transport`, `facility`, `severity` | Total messages successfully parsed from all ingress listeners. Incremented after parse succeeds. The `transport` label is one of `udp`, `tcp`, `tls`. The `facility` label uses the numeric code (0-23). The `severity` label uses the numeric code (0-7). |
| `syslog_messages_forwarded_total` | `output`, `transport` | Total messages successfully delivered to an output destination. Incremented only after the output confirms acceptance (TCP ACK for TLS/TCP, sendto return for UDP). |
| `syslog_messages_dropped_total` | `output`, `reason` | Total messages dropped before delivery. The `reason` label is one of: `queue_full` (backpressure policy discarded the message), `output_error` (delivery failed after all retries), `filter` (message excluded by a filter rule), `rate_limit` (per-source or per-output rate limit exceeded). |
| `syslog_parse_errors_total` | `listener`, `error_type` | Total messages that failed to parse. The `error_type` label maps to the `ParseError` variant name in snake_case: `invalid_pri`, `invalid_version`, `invalid_timestamp`, `invalid_hostname`, `invalid_structured_data`, `message_too_short`, `message_too_long`, `unexpected_eof`, `invalid_utf8`, `invalid_frame`, `unrecognized_format`. |
| `syslog_tls_handshake_errors_total` | `listener`, `error_type` | Total TLS handshake failures. The `error_type` label is one of: `certificate_expired`, `certificate_unknown`, `certificate_revoked`, `handshake_failure`, `protocol_version`, `timeout`, `other`. |
| `syslog_connections_accepted_total` | `listener` | Total TCP/TLS connections accepted (not applicable to UDP). |
| `syslog_connections_closed_total` | `listener`, `reason` | Total TCP/TLS connections closed. The `reason` label is one of: `client_closed` (clean close by remote), `server_closed` (server-initiated close, e.g., drain), `timeout` (idle timeout), `error` (I/O or protocol error), `reset` (TCP RST). |
| `syslog_route_matches_total` | `route` | Total messages matched by each routing rule. A single message may increment multiple routes if it matches multiple rules (fan-out). |
| `syslog_filter_drops_total` | `filter` | Total messages dropped by a named filter rule. This is a subset of `syslog_messages_dropped_total{reason="filter"}` broken down by individual filter name. |
| `syslog_output_retries_total` | `output` | Total retry attempts across all outputs. Each retry attempt increments this counter, regardless of whether the retry succeeds. |
| `syslog_config_reloads_total` | `result` | Total configuration reload attempts triggered by SIGHUP. The `result` label is `success` or `failure`. |
| `syslog_bytes_received_total` | `listener`, `transport` | Total bytes received from the network across all listeners. Counted at the raw network layer before parsing. |
| `syslog_bytes_forwarded_total` | `output`, `transport` | Total bytes sent to output destinations. Counted at the wire-format layer after serialization. |

### 1.2 Gauges

Gauges represent a value that can go up or down. They reflect current state rather than accumulated events.

| Metric Name | Labels | Description |
|-------------|--------|-------------|
| `syslog_connections_active` | `listener` | Current number of open TCP/TLS connections per listener. Incremented on accept, decremented on close. Not applicable to UDP listeners. |
| `syslog_queue_depth` | `output` | Current number of messages waiting in the per-output queue. This is the primary backpressure indicator. |
| `syslog_queue_capacity` | `output` | Configured maximum capacity (in messages) for each output queue. This is a static value set at startup or config reload. Exposed as a gauge so that `syslog_queue_depth / syslog_queue_capacity` yields utilization as a ratio. |
| `syslog_queue_bytes` | `output` | Current estimated byte size of messages in the per-output queue. Used for byte-based capacity limits and memory pressure monitoring. |
| `syslog_uptime_seconds` | (none) | Seconds since the process started. Updated lazily when the `/metrics` endpoint is scraped (computed as `now - start_time`). |
| `syslog_tls_cert_expiry_seconds` | `listener`, `subject` | Seconds until the TLS certificate expires. Negative values indicate an already-expired certificate. The `subject` label contains the certificate CN or first SAN entry. Updated on startup and on config reload. |
| `syslog_build_info` | `version`, `commit`, `rust_version` | Always set to `1`. A pseudo-gauge used to export build metadata as Prometheus labels, following the `*_build_info` convention. |

### 1.3 Histograms

Histograms track the distribution of values over time. They are used for latencies and sizes where understanding percentile behavior is critical.

| Metric Name | Labels | Bucket Boundaries | Description |
|-------------|--------|-------------------|-------------|
| `syslog_parse_duration_seconds` | `format` | 0.000001, 0.000002, 0.000005, 0.00001, 0.00002, 0.00005, 0.0001, 0.0005, 0.001 | Time to parse a single syslog message. The `format` label is `rfc5424` or `rfc3164`. Bucket boundaries are tuned for the sub-10-microsecond target (Phase 01, Section 5.1). |
| `syslog_forward_duration_seconds` | `output` | 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0 | Time from dequeue to confirmed delivery for a single message. Includes network round-trip for TCP/TLS outputs. |
| `syslog_message_size_bytes` | `listener` | 64, 128, 256, 480, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 | Size in bytes of each received message (raw wire format). Bucket boundaries align with RFC-significant sizes: 480 (RFC 5424 minimum), 2048 (SHOULD support), and powers of two for general size classification. |
| `syslog_queue_wait_duration_seconds` | `output` | 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0 | Time a message spends waiting in the output queue, from enqueue to dequeue. Indicates downstream backpressure severity. |

### 1.4 Label Cardinality Analysis

Label cardinality must be bounded to prevent metric explosion. Unbounded labels (e.g., source IP, hostname, message content) are never used as metric labels.

| Label | Possible Values | Cardinality | Bound Source |
|-------|-----------------|-------------|--------------|
| `listener` | Named in config | Low (typically 1-5) | Configuration |
| `output` | Named in config | Low (typically 1-10) | Configuration |
| `transport` | `udp`, `tcp`, `tls` | 3 | Enum |
| `facility` | `0` through `23` | 24 | RFC 5424 Section 6.2.1 |
| `severity` | `0` through `7` | 8 | RFC 5424 Section 6.2.1 |
| `reason` (drop) | `queue_full`, `output_error`, `filter`, `rate_limit` | 4 | Enum |
| `error_type` (parse) | 11 ParseError variants | 11 | Enum |
| `error_type` (TLS) | 7 handshake failure categories | 7 | Enum |
| `reason` (conn close) | `client_closed`, `server_closed`, `timeout`, `error`, `reset` | 5 | Enum |
| `format` | `rfc5424`, `rfc3164` | 2 | Enum |
| `result` (reload) | `success`, `failure` | 2 | Enum |
| `route` | Named in config | Low (typically 1-10) | Configuration |
| `filter` | Named in config | Low (typically 1-10) | Configuration |
| `subject` (cert) | Per-certificate CN | Very low (typically 1-3) | Configuration |

**Worst-case cardinality for `syslog_messages_received_total`:** 5 listeners x 3 transports x 24 facilities x 8 severities = 2,880 time series. In practice, most deployments use 1-2 listeners and 2-3 facility/severity combinations, yielding fewer than 50 time series.

**Mitigation for high cardinality:** If a deployment produces excessive time series from facility/severity labels, the operator can disable per-facility/severity breakdown via configuration:

```toml
[metrics]
detailed_facility_severity = false  # Collapses facility and severity labels to "_all"
```

---

## 2. Telemetry Plan

### 2.1 Crate Topology

Metric instrumentation follows the workspace crate boundary design from Phase 04:

```
syslog-observe         # Owns: metric registration, tracing setup, HTTP server
  (no internal deps)   # All other crates use `metrics` facade directly

syslog-transport       # Records: messages_received, parse_errors, connections_*,
                       #          tls_handshake_errors, message_size_bytes,
                       #          parse_duration, bytes_received

syslog-relay           # Records: messages_forwarded, messages_dropped, route_matches,
                       #          filter_drops, queue_depth, queue_bytes,
                       #          forward_duration, queue_wait_duration,
                       #          output_retries, bytes_forwarded

syslog-server          # Records: config_reloads, uptime_seconds, build_info
```

Each crate depends on the `metrics` facade crate (version 0.24.x) and calls `counter!()`, `gauge!()`, and `histogram!()` macros directly. The `syslog-observe` crate installs the `metrics-exporter-prometheus` recorder at process startup before any metric is recorded.

### 2.2 Metric Registration at Startup

All metrics are eagerly registered during the initialization phase in `syslog-observe::metrics::register_all()`. Eager registration ensures that:

1. All metrics appear in `/metrics` output from the first scrape, even before any events occur (counters at 0, gauges at initial values).
2. `describe_*!()` macros attach HELP strings to every metric for Prometheus/Grafana discoverability.
3. Label validation happens once at startup rather than on every hot-path increment.

```rust
// syslog-observe/src/metrics.rs (illustrative)

use metrics::{describe_counter, describe_gauge, describe_histogram};

pub fn register_all() {
    // Counters
    describe_counter!(
        "syslog_messages_received_total",
        "Total syslog messages successfully parsed from all ingress listeners"
    );
    describe_counter!(
        "syslog_messages_forwarded_total",
        "Total syslog messages successfully delivered to output destinations"
    );
    describe_counter!(
        "syslog_messages_dropped_total",
        "Total syslog messages dropped before delivery"
    );
    describe_counter!(
        "syslog_parse_errors_total",
        "Total syslog messages that failed to parse"
    );
    describe_counter!(
        "syslog_tls_handshake_errors_total",
        "Total TLS handshake failures"
    );
    describe_counter!(
        "syslog_connections_accepted_total",
        "Total TCP/TLS connections accepted"
    );
    describe_counter!(
        "syslog_connections_closed_total",
        "Total TCP/TLS connections closed"
    );
    describe_counter!(
        "syslog_route_matches_total",
        "Total messages matched by each routing rule"
    );
    describe_counter!(
        "syslog_filter_drops_total",
        "Total messages dropped by a named filter rule"
    );
    describe_counter!(
        "syslog_output_retries_total",
        "Total retry attempts across all outputs"
    );
    describe_counter!(
        "syslog_config_reloads_total",
        "Total configuration reload attempts"
    );
    describe_counter!(
        "syslog_bytes_received_total",
        "Total bytes received from the network"
    );
    describe_counter!(
        "syslog_bytes_forwarded_total",
        "Total bytes sent to output destinations"
    );

    // Gauges
    describe_gauge!(
        "syslog_connections_active",
        "Current number of open TCP/TLS connections"
    );
    describe_gauge!(
        "syslog_queue_depth",
        "Current number of messages in the output queue"
    );
    describe_gauge!(
        "syslog_queue_capacity",
        "Configured maximum capacity of the output queue"
    );
    describe_gauge!(
        "syslog_queue_bytes",
        "Current estimated byte size of the output queue"
    );
    describe_gauge!(
        "syslog_uptime_seconds",
        "Seconds since the process started"
    );
    describe_gauge!(
        "syslog_tls_cert_expiry_seconds",
        "Seconds until the TLS certificate expires"
    );
    describe_gauge!(
        "syslog_build_info",
        "Build metadata as labels (always 1)"
    );

    // Histograms
    describe_histogram!(
        "syslog_parse_duration_seconds",
        "Time to parse a single syslog message"
    );
    describe_histogram!(
        "syslog_forward_duration_seconds",
        "Time from dequeue to confirmed delivery"
    );
    describe_histogram!(
        "syslog_message_size_bytes",
        "Size in bytes of each received message"
    );
    describe_histogram!(
        "syslog_queue_wait_duration_seconds",
        "Time a message spends waiting in the output queue"
    );
}
```

### 2.3 Hot-Path Instrumentation Strategy

The syslog-usg pipeline must sustain 100k+ messages/sec. Metric updates on the hot path must not introduce contention, allocations, or system calls.

**Principle: no mutex on the hot path.** The `metrics` crate with the `metrics-exporter-prometheus` backend uses atomic operations internally. Counter increments compile down to a single `AtomicU64::fetch_add(1, Relaxed)` instruction. Gauge updates use `AtomicU64::store()`. These are wait-free on all target architectures.

**Histogram implementation:** The `metrics-exporter-prometheus` exporter uses a summary-based approach with configurable quantiles or histogram buckets. We configure explicit bucket boundaries (Section 1.3) at exporter installation time:

```rust
// syslog-observe/src/metrics.rs

use metrics_exporter_prometheus::PrometheusBuilder;
use std::time::Duration;

pub fn install_exporter() -> PrometheusHandle {
    PrometheusBuilder::new()
        // Parse duration: microsecond-scale buckets
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full("syslog_parse_duration_seconds".to_string()),
            &[0.000_001, 0.000_002, 0.000_005, 0.000_01, 0.000_02,
              0.000_05, 0.000_1, 0.000_5, 0.001],
        )
        .expect("valid buckets")
        // Forward duration: millisecond-to-second scale
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full("syslog_forward_duration_seconds".to_string()),
            &[0.000_1, 0.000_5, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
        )
        .expect("valid buckets")
        // Message size: byte-scale buckets
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full("syslog_message_size_bytes".to_string()),
            &[64.0, 128.0, 256.0, 480.0, 512.0, 1024.0, 2048.0,
              4096.0, 8192.0, 16384.0, 32768.0, 65536.0],
        )
        .expect("valid buckets")
        // Queue wait: millisecond-to-second scale
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Full("syslog_queue_wait_duration_seconds".to_string()),
            &[0.000_1, 0.000_5, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0],
        )
        .expect("valid buckets")
        .idle_timeout(
            metrics_exporter_prometheus::formatting::MetricKind::Counter,
            Some(Duration::from_secs(300)),
        )
        .install_recorder()
        .expect("failed to install metrics recorder")
}
```

**Idle metric expiration:** Time series for labels that stop appearing (e.g., a listener removed after config reload) are expired after 5 minutes of inactivity. This prevents stale time series from accumulating in Prometheus.

### 2.4 Recording Patterns

Each subsystem records metrics using lightweight inline calls. Below are the canonical patterns.

**Counter increment (ingress hot path):**

```rust
// syslog-transport/src/udp/listener.rs
use metrics::counter;

fn on_message_parsed(listener_name: &str, msg: &SyslogMessage) {
    counter!("syslog_messages_received_total",
        "listener" => listener_name.to_string(),
        "transport" => "udp",
        "facility" => msg.facility().code().to_string(),
        "severity" => msg.severity().code().to_string(),
    )
    .increment(1);
}
```

**Gauge update (queue depth):**

```rust
// syslog-relay/src/queue.rs
use metrics::gauge;

fn update_depth_metric(&self) {
    gauge!("syslog_queue_depth",
        "output" => self.output_name.clone(),
    )
    .set(self.len() as f64);
}
```

**Histogram observation (parse timing):**

```rust
// syslog-transport/src/udp/listener.rs
use metrics::histogram;
use std::time::Instant;

fn parse_and_record(buf: &[u8], listener_name: &str) -> Result<SyslogMessage, ParseError> {
    let start = Instant::now();
    let result = parse(buf);
    let elapsed = start.elapsed();
    let format = match &result {
        Ok(msg) if msg.version().is_some() => "rfc5424",
        Ok(_) => "rfc3164",
        Err(_) => return result, // Don't record parse duration for failures
    };
    histogram!("syslog_parse_duration_seconds",
        "format" => format,
    )
    .record(elapsed.as_secs_f64());
    result
}
```

### 2.5 Label Caching

To avoid per-message `String` allocation for label values, label key-value pairs for static dimensions (listener name, output name, transport) are pre-computed at startup and stored as `metrics::Label` values. The `metrics` crate accepts `&'static str` and `String` labels; for hot-path counters, listener names and transport strings are interned into `&'static str` via `Box::leak` at configuration time (bounded by config-defined names, so this is a fixed, small set of allocations).

```rust
// syslog-transport/src/udp/listener.rs (startup)

struct UdpListenerMetrics {
    listener_name: &'static str,
    transport: &'static str,
}

impl UdpListenerMetrics {
    fn new(name: String) -> Self {
        Self {
            listener_name: Box::leak(name.into_boxed_str()),
            transport: "udp",
        }
    }
}
```

### 2.6 Prometheus Exposition

The `/metrics` endpoint is served by the axum HTTP server in `syslog-observe`. The `PrometheusHandle` returned by the exporter installation provides a `render()` method that produces the Prometheus text exposition format.

```rust
// syslog-observe/src/server.rs

use axum::{Router, routing::get, response::IntoResponse};

async fn metrics_handler(
    State(handle): State<PrometheusHandle>,
) -> impl IntoResponse {
    handle.render()
}
```

**Endpoint:** `GET /metrics`
**Content-Type:** `text/plain; version=0.0.4; charset=utf-8`
**Authentication:** None by default. The admin HTTP server should be bound to a localhost or internal-only address. Optional basic auth can be configured:

```toml
[admin]
listen = "127.0.0.1:9090"
# Optional:
# basic_auth_user = "prometheus"
# basic_auth_password = "${ADMIN_PASSWORD}"
```

---

## 3. Structured Logging

syslog-usg's own operational logs (distinct from the syslog messages it processes) use the `tracing` crate with `tracing-subscriber` for structured, JSON-formatted output.

### 3.1 Output Format

All operational logs are emitted as single-line JSON objects to stderr. The format is designed for ingestion by log aggregation systems (Loki, Elasticsearch, CloudWatch).

```json
{
  "timestamp": "2026-03-11T14:32:01.847392Z",
  "level": "INFO",
  "target": "syslog_transport::tls::listener",
  "message": "TLS connection accepted",
  "span": {
    "listener": "tls-input-1",
    "peer": "10.0.1.50:48291"
  },
  "fields": {
    "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "tls_version": "1.3",
    "client_cn": "web-server-01.example.com"
  }
}
```

**Field definitions:**

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | RFC 3339 string | UTC timestamp with microsecond precision. |
| `level` | String | One of: `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`. |
| `target` | String | Rust module path of the log callsite (e.g., `syslog_relay::queue`). |
| `message` | String | Human-readable event description. |
| `span` | Object | Fields from the enclosing `tracing::Span` hierarchy, flattened. |
| `fields` | Object | Event-specific structured fields from `tracing::event!()` calls. |

### 3.2 Tracing Subscriber Initialization

```rust
// syslog-observe/src/tracing_setup.rs

use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_tracing(log_level: &str) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .json()
                .with_timer(fmt::time::UtcTime::rfc_3339())
                .with_target(true)
                .with_current_span(true)
                .with_span_list(false)
                .with_file(false)      // Omit source file paths in production
                .with_line_number(false)
                .flatten_event(false)
                .with_writer(std::io::stderr)
        )
        .init();
}
```

**Configuration:**

```toml
[logging]
level = "info"                # Default log level
# Override per-module:
# RUST_LOG=syslog_transport=debug,syslog_relay::queue=trace
format = "json"               # "json" or "text" (text for local development)
```

### 3.3 Log Level Policy

Each log level has a clear contract for what events it contains. Operators can rely on these contracts when configuring alerting and log retention.

| Level | Contract | Examples |
|-------|----------|----------|
| **ERROR** | An unrecoverable failure in a subsystem. Requires operator attention. The process may continue but is degraded. | Output unreachable after all retries. TLS certificate load failure. Listener bind failure. Panic caught in task supervisor. |
| **WARN** | A recoverable problem or degraded condition. The process continues operating but something is not optimal. | Queue depth exceeds 80% capacity. TLS certificate expires in < 30 days. Config reload failed (continuing with previous config). Output reconnecting after transient failure. Rate limit applied to a source. |
| **INFO** | Normal lifecycle events. Useful for understanding what the process is doing at a high level. | Process started/stopped. Listener bound on address:port. Output connected. Config reloaded successfully. Graceful shutdown initiated. Queue drained. |
| **DEBUG** | Message flow and decision tracing. Useful for diagnosing routing and filtering behavior. One log event per message is acceptable at this level. | Message routed to output X. Message matched filter Y. Message enqueued. Message dequeued and forwarded. Connection established from peer. Retry attempt N for output Z. |
| **TRACE** | Byte-level and parsing detail. Extremely verbose. Intended for development and deep troubleshooting only. | Raw bytes received. Parse state machine transitions. Octet-counting frame boundary detection. TLS handshake protocol messages. Individual SD-PARAM parsing steps. |

### 3.4 Span Hierarchy

Spans provide structured context that flows through the async task tree. Each span adds fields that are automatically included in all events emitted within its scope.

```
server                                    # Top-level: version, config_path
  listener{name="tls-input-1", transport="tls", bind="0.0.0.0:6514"}
    connection{peer="10.0.1.50:48291", conn_id="a1b2c3"}
      message{trace_id="d4e5f6", facility=1, severity=6}
        route{route="default"}
          output{output="central-collector"}
```

**Span field definitions:**

| Span | Fields | Description |
|------|--------|-------------|
| `server` | `version`, `config_path`, `pid` | Created once at process startup. |
| `listener` | `name`, `transport`, `bind` | Created when a listener binds. One span per listener. |
| `connection` | `peer`, `conn_id`, `tls_version`, `client_cn` | Created on TCP/TLS connection accept. One span per connection. Includes TLS metadata after handshake. |
| `message` | `trace_id`, `facility`, `severity`, `hostname`, `app_name` | Created for each message in the pipeline at DEBUG level and above. The `trace_id` is a 16-byte random identifier assigned at parse time for correlation. |
| `route` | `route` | Entered when the router evaluates a routing rule. |
| `output` | `output`, `transport` | Entered when a message is dispatched to an output. |

### 3.5 Rate-Limited Logging

Repetitive error conditions (e.g., a downstream output that is persistently unreachable) must not flood the operational log. syslog-usg implements rate-limited logging for high-frequency error patterns.

**Implementation:** A per-callsite rate limiter that allows the first occurrence, then suppresses subsequent identical events for a configurable window (default: 60 seconds), emitting a summary count when the window expires.

```rust
// Example: rate-limited error logging for output failures

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::atomic::AtomicI64;

struct RateLimitedLog {
    suppressed_count: AtomicU64,
    last_logged_at: AtomicI64,  // Unix timestamp in seconds
    window_secs: i64,
}

impl RateLimitedLog {
    fn should_log(&self) -> (bool, u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let last = self.last_logged_at.load(Ordering::Relaxed);
        if now - last >= self.window_secs {
            let suppressed = self.suppressed_count.swap(0, Ordering::Relaxed);
            self.last_logged_at.store(now, Ordering::Relaxed);
            (true, suppressed)
        } else {
            self.suppressed_count.fetch_add(1, Ordering::Relaxed);
            (false, 0)
        }
    }
}
```

When the window expires and logging resumes:

```json
{
  "timestamp": "2026-03-11T14:33:01.000000Z",
  "level": "ERROR",
  "target": "syslog_relay::output",
  "message": "output unreachable (repeated)",
  "fields": {
    "output": "central-collector",
    "suppressed_count": 1247,
    "window_seconds": 60,
    "last_error": "connection refused"
  }
}
```

### 3.6 Sensitive Data Policy

syslog-usg processes untrusted network input that may contain sensitive information. The operational logs must never leak this data.

| Data Category | Policy |
|---------------|--------|
| **Message content (MSG body)** | Never logged at INFO or below. At DEBUG, only the first 64 bytes are logged, hex-encoded, and only when the message fails to parse. At TRACE, the full message body may be logged for development. |
| **Structured data values** | Never logged at INFO or below. SD-IDs (keys) may appear at DEBUG for routing diagnostics. SD-PARAM values are never logged. |
| **TLS private keys** | Never logged at any level. The `tracing` span for TLS configuration includes only the certificate path, never key material. |
| **TLS session keys** | Never logged. SSLKEYLOGFILE support is compile-time gated behind a `debug-tls` feature flag that is never enabled in release builds. |
| **Client certificate details** | CN and SAN entries may appear at INFO (connection accepted). Full certificate chain is never logged. |
| **Source IP addresses** | Logged at INFO (connection events) and DEBUG (per-message). This is considered operational data, not sensitive. Operators who require IP anonymization should use an external log pipeline. |

---

## 4. Health, Readiness, and Liveness Endpoints

The admin HTTP server exposes health check endpoints compatible with Kubernetes probe configuration and traditional load balancer health checks.

### 4.1 Endpoint Summary

| Endpoint | Method | Purpose | Returns 200 When | Returns 503 When |
|----------|--------|---------|-------------------|-------------------|
| `/health` | GET | Alias for `/live`. General-purpose health check for load balancers. | Process is running and event loop is responsive. | Never under normal conditions (see deadlock detection below). |
| `/live` | GET | Kubernetes liveness probe. Indicates the process is alive and should not be killed. | Process is running and event loop is responsive. | Never under normal conditions. |
| `/ready` | GET | Kubernetes readiness probe. Indicates the process can accept traffic. | All listeners are bound AND at least one output is healthy. | During startup (before initialization completes), or when all outputs are unhealthy. |

### 4.2 Liveness: `/health` and `/live`

The liveness check is intentionally simple. If the HTTP server can respond, the process is alive. There is no application logic in the liveness check beyond confirming the Tokio event loop is processing tasks.

**Response (200 OK):**

```json
{
  "status": "alive",
  "uptime_seconds": 86412
}
```

**Deadlock detection:** The liveness handler includes a timeout. The axum handler spawns a small `tokio::time::sleep(Duration::ZERO)` future and awaits it. If the event loop is deadlocked, the HTTP connection itself will time out (configured via the admin server's `health_check_timeout`), and the probe will fail at the orchestrator level.

### 4.3 Readiness: `/ready`

The readiness check evaluates the health of all subsystems and returns a composite status.

**Response (200 OK):**

```json
{
  "status": "ready",
  "uptime_seconds": 86412,
  "components": {
    "listeners": {
      "status": "ok",
      "details": {
        "udp-input-1": { "status": "ok", "bind": "0.0.0.0:514" },
        "tls-input-1": { "status": "ok", "bind": "0.0.0.0:6514", "connections": 42 }
      }
    },
    "outputs": {
      "status": "ok",
      "details": {
        "central-collector": {
          "status": "ok",
          "queue_depth": 128,
          "queue_capacity": 10000,
          "last_success": "2026-03-11T14:32:59Z"
        },
        "backup-file": {
          "status": "ok",
          "queue_depth": 0,
          "queue_capacity": 5000,
          "last_success": "2026-03-11T14:32:58Z"
        }
      }
    },
    "pipeline": {
      "status": "ok"
    }
  }
}
```

**Response (503 Service Unavailable):**

```json
{
  "status": "not_ready",
  "uptime_seconds": 3,
  "reason": "no healthy outputs",
  "components": {
    "listeners": {
      "status": "ok",
      "details": {
        "tls-input-1": { "status": "ok", "bind": "0.0.0.0:6514", "connections": 0 }
      }
    },
    "outputs": {
      "status": "degraded",
      "details": {
        "central-collector": {
          "status": "error",
          "queue_depth": 10000,
          "queue_capacity": 10000,
          "last_error": "connection refused",
          "last_error_at": "2026-03-11T14:32:55Z"
        }
      }
    },
    "pipeline": {
      "status": "ok"
    }
  }
}
```

### 4.4 Readiness Conditions

The `/ready` endpoint returns 200 if and only if all of the following conditions are met:

1. **All configured listeners are bound.** A listener that failed to bind during startup makes the service not ready.
2. **At least one output is healthy.** An output is considered healthy if it has successfully delivered at least one message within the last `health_check_timeout` period, or if it was successfully connected at startup and has not yet failed.
3. **Initialization is complete.** The pipeline stages are wired and processing. During the startup phase (before all listeners are bound), `/ready` returns 503.

A single unhealthy output does not make the service unready, as long as at least one output remains healthy. This prevents a single flaky downstream from removing the service from the load balancer.

### 4.5 Health State Management

Health state is tracked in `syslog-observe::health` using a shared, lock-free state structure:

```rust
// syslog-observe/src/health.rs

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct HealthState {
    inner: Arc<HealthStateInner>,
}

struct HealthStateInner {
    initialized: AtomicBool,
    start_time: std::time::Instant,
    listeners: RwLock<HashMap<String, ListenerHealth>>,
    outputs: RwLock<HashMap<String, OutputHealth>>,
}

pub struct ListenerHealth {
    pub bound: AtomicBool,
    pub bind_address: String,
    pub active_connections: AtomicU64,
}

pub struct OutputHealth {
    pub healthy: AtomicBool,
    pub queue_depth: AtomicU64,
    pub queue_capacity: u64,
    pub last_success_epoch: AtomicU64,
    pub last_error: RwLock<Option<String>>,
    pub last_error_epoch: AtomicU64,
}
```

The `RwLock` on the `HashMap` collections is only acquired for writes during config reload (adding/removing listeners or outputs). Read access for health checks uses a snapshot approach: the handler reads the `RwLock` once, then reads atomic fields without holding any lock.

### 4.6 Configuration

```toml
[admin]
listen = "127.0.0.1:9090"          # Admin HTTP server bind address
health_check_timeout = "5s"         # Timeout for output health freshness
                                    # An output is considered unhealthy if it has
                                    # not successfully delivered a message within
                                    # this duration. Default: 5 seconds.

# Kubernetes probe configuration example:
# livenessProbe:
#   httpGet:
#     path: /live
#     port: 9090
#   initialDelaySeconds: 2
#   periodSeconds: 10
#   timeoutSeconds: 3
#   failureThreshold: 3
#
# readinessProbe:
#   httpGet:
#     path: /ready
#     port: 9090
#   initialDelaySeconds: 5
#   periodSeconds: 5
#   timeoutSeconds: 3
#   failureThreshold: 2
#
# startupProbe:
#   httpGet:
#     path: /ready
#     port: 9090
#   initialDelaySeconds: 1
#   periodSeconds: 2
#   timeoutSeconds: 3
#   failureThreshold: 15
```

### 4.7 Admin HTTP Router

```rust
// syslog-observe/src/server.rs

use axum::{Router, routing::get, extract::State};

#[derive(Clone)]
pub struct AdminState {
    pub prometheus_handle: PrometheusHandle,
    pub health_state: HealthState,
}

pub fn admin_router(state: AdminState) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(liveness_handler))
        .route("/live", get(liveness_handler))
        .route("/ready", get(readiness_handler))
        .with_state(state)
}
```

---

## 5. Operational Dashboards

This section defines Grafana dashboard panels and Prometheus alerting rules for syslog-usg. All queries assume the metric names defined in Section 1.

### 5.1 Overview Dashboard

The overview dashboard provides a single-pane view of system health. It is the first dashboard an operator opens during an incident.

#### Panel: Messages Per Second (In vs. Out vs. Dropped)

```promql
# Ingest rate
sum(rate(syslog_messages_received_total[5m]))

# Forward rate
sum(rate(syslog_messages_forwarded_total[5m]))

# Drop rate
sum(rate(syslog_messages_dropped_total[5m]))
```

**Visualization:** Time series graph with three lines. Green for received, blue for forwarded, red for dropped. The gap between received and forwarded+dropped indicates messages currently in queues.

#### Panel: Pipeline Balance Ratio

```promql
# Forwarded-to-received ratio (should be near 1.0)
sum(rate(syslog_messages_forwarded_total[5m]))
/
sum(rate(syslog_messages_received_total[5m]))
```

**Visualization:** Single stat gauge. Green >= 0.99, yellow 0.95-0.99, red < 0.95.

#### Panel: Drop Rate Breakdown

```promql
sum by (reason) (rate(syslog_messages_dropped_total[5m]))
```

**Visualization:** Stacked area chart, broken down by drop reason.

#### Panel: Active Connections

```promql
sum(syslog_connections_active)
```

**Visualization:** Single stat with sparkline.

#### Panel: Queue Utilization (All Outputs)

```promql
max(syslog_queue_depth / syslog_queue_capacity)
```

**Visualization:** Single stat gauge. Green < 0.5, yellow 0.5-0.8, red > 0.8.

#### Panel: Uptime

```promql
syslog_uptime_seconds
```

**Visualization:** Single stat, formatted as human-readable duration.

### 5.2 Per-Listener Dashboard

One row per configured listener, using the `listener` label for filtering.

#### Panel: Throughput Per Listener

```promql
sum by (listener) (rate(syslog_messages_received_total[5m]))
```

#### Panel: Parse Error Rate Per Listener

```promql
sum by (listener, error_type) (rate(syslog_parse_errors_total[5m]))
```

**Visualization:** Stacked bar chart by error type.

#### Panel: Connections Per Listener

```promql
syslog_connections_active
```

#### Panel: Connection Accept/Close Rate

```promql
sum by (listener) (rate(syslog_connections_accepted_total[5m]))
sum by (listener, reason) (rate(syslog_connections_closed_total[5m]))
```

#### Panel: TLS Handshake Errors

```promql
sum by (listener, error_type) (rate(syslog_tls_handshake_errors_total[5m]))
```

#### Panel: Message Size Distribution

```promql
histogram_quantile(0.50, sum by (le, listener) (rate(syslog_message_size_bytes_bucket[5m])))
histogram_quantile(0.95, sum by (le, listener) (rate(syslog_message_size_bytes_bucket[5m])))
histogram_quantile(0.99, sum by (le, listener) (rate(syslog_message_size_bytes_bucket[5m])))
```

#### Panel: Bytes/sec Per Listener

```promql
sum by (listener) (rate(syslog_bytes_received_total[5m]))
```

### 5.3 Per-Output Dashboard

One row per configured output, using the `output` label for filtering.

#### Panel: Delivery Rate

```promql
sum by (output) (rate(syslog_messages_forwarded_total[5m]))
```

#### Panel: Queue Depth Over Time

```promql
syslog_queue_depth
```

**Visualization:** Time series with horizontal threshold line at `syslog_queue_capacity`.

#### Panel: Queue Utilization Percentage

```promql
syslog_queue_depth / syslog_queue_capacity * 100
```

**Visualization:** Gauge (0-100%).

#### Panel: Forward Latency (p50, p95, p99)

```promql
histogram_quantile(0.50, sum by (le, output) (rate(syslog_forward_duration_seconds_bucket[5m])))
histogram_quantile(0.95, sum by (le, output) (rate(syslog_forward_duration_seconds_bucket[5m])))
histogram_quantile(0.99, sum by (le, output) (rate(syslog_forward_duration_seconds_bucket[5m])))
```

#### Panel: Queue Wait Time (p50, p95, p99)

```promql
histogram_quantile(0.50, sum by (le, output) (rate(syslog_queue_wait_duration_seconds_bucket[5m])))
histogram_quantile(0.95, sum by (le, output) (rate(syslog_queue_wait_duration_seconds_bucket[5m])))
histogram_quantile(0.99, sum by (le, output) (rate(syslog_queue_wait_duration_seconds_bucket[5m])))
```

#### Panel: Retry Rate

```promql
sum by (output) (rate(syslog_output_retries_total[5m]))
```

#### Panel: Drop Rate Per Output

```promql
sum by (output, reason) (rate(syslog_messages_dropped_total[5m]))
```

#### Panel: Bytes/sec Per Output

```promql
sum by (output) (rate(syslog_bytes_forwarded_total[5m]))
```

### 5.4 System Dashboard

System-level metrics from the process and host. These metrics come from the Prometheus node_exporter and the process itself, not from syslog-usg's custom metrics.

#### Panel: CPU Usage

```promql
rate(process_cpu_seconds_total[5m])
```

#### Panel: Memory RSS

```promql
process_resident_memory_bytes
```

#### Panel: Open File Descriptors

```promql
process_open_fds
process_max_fds  # horizontal threshold line
```

#### Panel: Uptime and Restarts

```promql
syslog_uptime_seconds
changes(process_start_time_seconds[24h])
```

#### Panel: Config Reloads

```promql
sum by (result) (rate(syslog_config_reloads_total[1h]))
```

### 5.5 TLS Dashboard

#### Panel: Certificate Expiry

```promql
syslog_tls_cert_expiry_seconds
```

**Visualization:** Table with color-coded rows. Red < 7 days, yellow < 30 days, green otherwise.

#### Panel: TLS Handshake Error Rate

```promql
sum(rate(syslog_tls_handshake_errors_total[5m]))
```

#### Panel: TLS Handshake Errors by Type

```promql
sum by (error_type) (rate(syslog_tls_handshake_errors_total[5m]))
```

### 5.6 Alerting Rules

Alerting rules are defined in Prometheus alerting rule format. Operators should adapt thresholds to their deployment.

```yaml
groups:
  - name: syslog-usg
    rules:

      # Message drops exceeding threshold
      - alert: SyslogHighDropRate
        expr: >
          sum(rate(syslog_messages_dropped_total[5m])) > 0
          and
          sum(rate(syslog_messages_dropped_total[5m]))
          / sum(rate(syslog_messages_received_total[5m]))
          > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "syslog-usg drop rate exceeds 1%"
          description: >
            {{ $value | humanizePercentage }} of messages are being dropped.
            Check queue depths and output health.

      # Queue nearing capacity
      - alert: SyslogQueueNearCapacity
        expr: >
          syslog_queue_depth / syslog_queue_capacity > 0.8
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "syslog-usg queue {{ $labels.output }} at {{ $value | humanizePercentage }} capacity"
          description: >
            Output queue is filling up. Downstream may be slow or unreachable.

      # Queue full (critical)
      - alert: SyslogQueueFull
        expr: >
          syslog_queue_depth / syslog_queue_capacity > 0.95
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "syslog-usg queue {{ $labels.output }} is full"
          description: >
            Output queue is at {{ $value | humanizePercentage }} capacity.
            Messages are being dropped.

      # TLS certificate expiring soon
      - alert: SyslogTlsCertExpiringSoon
        expr: >
          syslog_tls_cert_expiry_seconds < 7 * 24 * 3600
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "TLS certificate for {{ $labels.subject }} expires in {{ $value | humanizeDuration }}"
          description: >
            Certificate on listener {{ $labels.listener }} expires soon. Renew immediately.

      # TLS certificate expired
      - alert: SyslogTlsCertExpired
        expr: >
          syslog_tls_cert_expiry_seconds < 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "TLS certificate for {{ $labels.subject }} has expired"
          description: >
            Certificate on listener {{ $labels.listener }} is expired.
            TLS connections will fail.

      # No messages received (possible ingestion failure)
      - alert: SyslogNoMessagesReceived
        expr: >
          sum(rate(syslog_messages_received_total[5m])) == 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "syslog-usg has not received any messages for 10 minutes"
          description: >
            No syslog messages have been received. Check network connectivity
            and upstream senders.

      # High parse error rate
      - alert: SyslogHighParseErrorRate
        expr: >
          sum(rate(syslog_parse_errors_total[5m]))
          / sum(rate(syslog_messages_received_total[5m]))
          > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "syslog-usg parse error rate exceeds 5%"
          description: >
            {{ $value | humanizePercentage }} of messages are failing to parse.
            Check sender configurations and message formats.

      # Output retrying persistently
      - alert: SyslogOutputRetrying
        expr: >
          sum by (output) (rate(syslog_output_retries_total[5m])) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "syslog-usg output {{ $labels.output }} is retrying"
          description: >
            Output has been retrying for 5 minutes. Check downstream availability.

      # Forward latency spike
      - alert: SyslogHighForwardLatency
        expr: >
          histogram_quantile(0.99,
            sum by (le, output) (rate(syslog_forward_duration_seconds_bucket[5m]))
          ) > 1.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "syslog-usg p99 forward latency for {{ $labels.output }} exceeds 1 second"
          description: >
            Downstream is slow. Current p99: {{ $value | humanizeDuration }}.

      # Process restarted unexpectedly
      - alert: SyslogProcessRestarted
        expr: >
          changes(process_start_time_seconds[10m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "syslog-usg process restarted"
          description: >
            The syslog-usg process has restarted. Check logs for crash details.

      # Config reload failure
      - alert: SyslogConfigReloadFailed
        expr: >
          increase(syslog_config_reloads_total{result="failure"}[5m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "syslog-usg configuration reload failed"
          description: >
            A SIGHUP-triggered config reload was rejected. The process continues
            with the previous configuration. Check logs for validation errors.
```

---

## 6. Capacity Metrics

This section defines the metrics and queries used for capacity planning. These are not additional metrics beyond Section 1; they are derived views of the existing metrics that answer capacity questions.

### 6.1 Ingest Rate (Messages Per Second)

**Query:**

```promql
sum(rate(syslog_messages_received_total[5m]))
```

**Capacity signal:** Compare against the 100k msg/sec target (Phase 01, Section 5.1). When sustained ingest rate exceeds 80% of benchmark-validated throughput, plan for vertical scaling (more CPU cores) or horizontal scaling (additional instances).

**Trend query (weekly growth):**

```promql
avg_over_time(sum(rate(syslog_messages_received_total[5m]))[7d:1h])
```

### 6.2 Forward Rate (Messages Per Second)

**Query:**

```promql
sum(rate(syslog_messages_forwarded_total[5m]))
```

**Capacity signal:** Forward rate should closely track ingest rate. A persistent gap indicates queue buildup and eventual drops. The ratio `forward_rate / ingest_rate` should be >= 0.99 under normal operation.

### 6.3 Bytes Per Second

**Queries:**

```promql
# Ingest bandwidth
sum(rate(syslog_bytes_received_total[5m]))

# Egress bandwidth
sum(rate(syslog_bytes_forwarded_total[5m]))
```

**Capacity signal:** Network interface saturation. For a 1 Gbps interface, alert when sustained throughput exceeds 80% (100 MB/s). For TLS outputs, account for TLS overhead (~5-10% above plaintext).

### 6.4 Connection Count Trends

**Query:**

```promql
syslog_connections_active
```

**Capacity signal:** File descriptor limit. Default Linux limit is 1024 (soft), 65536 (hard). syslog-usg should set its own soft limit to match the hard limit at startup. Alert when `syslog_connections_active` exceeds 80% of `process_max_fds`.

**Trend query:**

```promql
max_over_time(sum(syslog_connections_active)[7d:1h])
```

### 6.5 Queue Utilization Percentage

**Query:**

```promql
syslog_queue_depth / syslog_queue_capacity
```

**Capacity signal:** Persistent queue utilization above 50% indicates that egress cannot keep up with ingress. This is a leading indicator of message drops. Actions:
- 0-50%: Normal operation.
- 50-80%: Investigate downstream performance. Consider increasing output parallelism or queue capacity.
- 80-95%: Warning. Drops are imminent. Scale output capacity or reduce ingest rate.
- 95-100%: Critical. Messages are being dropped according to the backpressure policy.

**Byte-based utilization:** If queues are configured with byte-size limits:

```promql
syslog_queue_bytes / syslog_queue_byte_capacity
```

### 6.6 Parse Error Rate

**Query:**

```promql
sum(rate(syslog_parse_errors_total[5m]))
/ sum(rate(syslog_messages_received_total[5m]) + rate(syslog_parse_errors_total[5m]))
```

Note: The denominator includes parse errors because `messages_received_total` only counts successful parses. The total attempt count is `received + parse_errors`.

**Capacity signal:** Parse error rate is an indicator of sender health, not syslog-usg capacity. However, a sudden spike in parse errors may indicate:
- A misconfigured sender flooding malformed messages (operational issue).
- A new sender using an unsupported format (feature gap).
- A network issue corrupting messages in transit.

Baseline: < 0.1% parse error rate. Alert at > 1%.

### 6.7 Memory Usage Trend

**Query:**

```promql
process_resident_memory_bytes
```

**Capacity signal:** Memory usage should be roughly proportional to total queue depth across all outputs. The formula:

```
expected_rss ≈ base_rss + (total_queue_depth * avg_message_size * overhead_factor)
```

Where `base_rss` is ~10 MB (Phase 01 idle target), `avg_message_size` can be derived from `syslog_message_size_bytes`, and `overhead_factor` is ~2x to account for internal data structures. Under the Phase 01 load target (100k msg/sec, 10k queue depth, 512 byte avg): `10 MB + (10000 * 512 * 2) ≈ 20 MB`.

If observed RSS significantly exceeds the expected value, investigate for memory leaks.

**Trend query (daily peak):**

```promql
max_over_time(process_resident_memory_bytes[24h])
```

### 6.8 Capacity Planning Summary Table

| Dimension | Metric | Warning Threshold | Critical Threshold | Action |
|-----------|--------|-------------------|---------------------|--------|
| Ingest throughput | `rate(syslog_messages_received_total[5m])` | > 80% of benchmarked max | > 95% of benchmarked max | Add CPU cores or instances |
| Network bandwidth | `rate(syslog_bytes_received_total[5m])` | > 80% of NIC capacity | > 95% of NIC capacity | Upgrade NIC or add instances |
| Connection count | `syslog_connections_active` | > 80% of `process_max_fds` | > 95% of `process_max_fds` | Raise file descriptor limit |
| Queue utilization | `queue_depth / queue_capacity` | > 50% sustained | > 80% sustained | Scale output or increase queue |
| Memory | `process_resident_memory_bytes` | > 75% of available | > 90% of available | Reduce queue sizes or add memory |
| Parse errors | `parse_errors / total_attempts` | > 1% | > 5% | Investigate sender health |
| Forward latency | `p99(forward_duration)` | > 100ms | > 1s | Investigate downstream |
| Cert expiry | `tls_cert_expiry_seconds` | < 30 days | < 7 days | Renew certificate |

