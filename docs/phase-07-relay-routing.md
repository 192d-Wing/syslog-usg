# Phase 07 — Relay Pipeline: Routing, Filtering, Queueing, and Delivery

## syslog-usg: A Production-Grade Syslog Server/Relay in Rust

**Version:** 1.0.0-draft
**Date:** 2026-03-11
**Status:** Draft
**Prerequisites:** [Phase 01 — Requirements and Scope](phase-01-requirements.md), [Phase 03 — System Architecture](phase-03-architecture.md)

---

## Table of Contents

1. [Routing Architecture](#1-routing-architecture)
2. [Filter Design](#2-filter-design)
3. [Queue Model](#3-queue-model)
4. [Backpressure Strategy](#4-backpressure-strategy)
5. [Retry Strategy](#5-retry-strategy)
6. [Delivery Guarantees](#6-delivery-guarantees)
7. [Fan-Out Design](#7-fan-out-design)
8. [Dead Letter Queue](#8-dead-letter-queue)
9. [Pipeline Lifecycle](#9-pipeline-lifecycle)
10. [Throughput Optimization](#10-throughput-optimization)

---

## 1. Routing Architecture

The router is the fan-out stage of the pipeline. It receives filtered `Arc<SyslogMessage>` values from the filter stage and dispatches clones to one or more per-output bounded queues. The routing table is compiled once at configuration load and swapped atomically on reload.

### 1.1 Route Configuration

Each route is a named rule mapping a set of match predicates to a set of output destinations.

```toml
[[routes]]
name = "security-critical"
match.facility = ["auth", "authpriv"]        # facility range or list
match.severity_min = "warning"               # severity >= warning (0-4)
match.hostname = "fw-*.example.com"          # glob pattern
outputs = ["siem-tls", "local-archive"]
```

A route configuration consists of:

| Field | Type | Description |
|-------|------|-------------|
| `name` | `String` | Unique identifier for the route. Used in metrics labels. |
| `match` | `MatchRule` | Predicate set. All specified predicates must match (logical AND). |
| `outputs` | `Vec<String>` | Output names this route delivers to. Must reference defined outputs. |
| `continue` | `bool` | If `true`, continue evaluating subsequent routes even after this route matches. Default: `true`. |
| `priority` | `u16` | Evaluation order. Lower values are evaluated first. Routes at the same priority are evaluated in config-file order. |

### 1.2 Match Rules

Match rules are the predicates within a route. All specified fields must match for the route to fire (logical AND). Omitted fields are treated as wildcards (match anything).

| Predicate | Config Syntax | Compiled Form | Description |
|-----------|--------------|---------------|-------------|
| `facility` | `["auth", "authpriv", "local0..local7"]` | `BitSet<24>` | Set membership test. Facility names are resolved to numeric codes at config load. Ranges supported via `..` syntax. |
| `severity_min` | `"warning"` | `u8` threshold | Message severity <= threshold (lower numeric value = higher severity). |
| `severity_max` | `"debug"` | `u8` threshold | Message severity >= threshold. Combined with `severity_min` to define a range. |
| `hostname` | `"fw-*.example.com"` | Pre-compiled `globset::Glob` | Glob match against `SyslogMessage.hostname`. Case-insensitive. NILVALUE hostnames never match hostname globs. |
| `app_name` | `"sshd"` or `"nginx*"` | Pre-compiled `globset::Glob` | Glob match against `SyslogMessage.app_name`. |
| `msg_id` | `"ID47"` | Exact string or glob | Match against `SyslogMessage.msg_id`. |
| `sd_id` | `"timeQuality"` | `HashSet<CompactString>` | Route matches if at least one of the listed SD-IDs is present in the message's structured data. |
| `msg_regex` | `"error|fail|panic"` | Pre-compiled `regex::Regex` | Regex match against the MSG body. Most expensive predicate; evaluated last. |
| `source_addr` | `"10.0.0.0/8"` | Parsed IP network prefix | Match against `SyslogMessage.source_addr` IP. Supports CIDR notation. |
| `listener` | `"tls-primary"` | `HashSet<CompactString>` | Match against `SyslogMessage.listener_id`. |

### 1.3 Compiled Route Table

At configuration load (and on each reload), the router compiles the route table into an optimized in-memory structure:

```rust
/// A compiled route table, immutable after construction.
/// Swapped atomically via Arc on config reload.
pub struct CompiledRouteTable {
    /// Routes sorted by (priority, config_order).
    routes: Vec<CompiledRoute>,
    /// Index from output name to its queue sender handle.
    output_senders: HashMap<CompactString, OutputHandle>,
    /// Pre-built default route (catch-all), if configured.
    default_route: Option<CompiledRoute>,
}

pub struct CompiledRoute {
    name: CompactString,
    matcher: CompiledMatcher,
    output_indices: SmallVec<[usize; 4]>,
    continue_evaluation: bool,
}

pub struct CompiledMatcher {
    facility_set: Option<BitSet<24>>,
    severity_min: Option<u8>,
    severity_max: Option<u8>,
    hostname_glob: Option<globset::GlobMatcher>,
    app_name_glob: Option<globset::GlobMatcher>,
    msg_id_matcher: Option<GlobOrExact>,
    sd_id_set: Option<HashSet<CompactString>>,
    msg_regex: Option<regex::Regex>,
    source_network: Option<IpNet>,
    listener_set: Option<HashSet<CompactString>>,
}
```

**Compilation guarantees:**
- All regexes are compiled once with `regex::Regex::new`. Invalid patterns produce a config validation error at load time, not at runtime.
- Glob patterns are compiled via `globset::Glob::new` at load time.
- Facility names (e.g., `"auth"`) are resolved to numeric codes (4) at compile time. Unknown facility names produce a config error.
- Severity names are resolved to numeric codes (e.g., `"warning"` to 4).
- The route list is sorted by `(priority, config_file_order)` at compile time so runtime evaluation is a simple linear scan.

### 1.4 Route Evaluation

The pipeline dispatcher evaluates routes for each message as follows:

```
for each route in compiled_route_table.routes (sorted by priority):
    if route.matcher.matches(message):
        for each output in route.outputs:
            dispatch message Arc clone to output queue
        increment route.matched_count (atomic)
        if not route.continue_evaluation:
            stop evaluating further routes
            break

if no route matched AND default_route is configured:
    dispatch to default_route outputs
    increment default_route.matched_count

if no route matched AND no default_route:
    increment unrouted_messages_total metric
    drop message
```

**Predicate evaluation order within a single route** is optimized for short-circuit: cheapest predicates first, most expensive last.

1. `facility_set` — single bitset lookup, O(1)
2. `severity_min` / `severity_max` — integer comparison
3. `listener_set` — hash set lookup
4. `source_network` — IP prefix match
5. `hostname_glob` — glob match on short string
6. `app_name_glob` — glob match on short string
7. `sd_id_set` — iterate message's SD-IDs (typically 0-3), hash lookup each
8. `msg_id_matcher` — glob or exact match
9. `msg_regex` — regex execution on MSG body (most expensive, evaluated last)

A `None` field in the matcher means "don't check this predicate" (wildcard), so it is skipped entirely.

### 1.5 Default Route

A default (catch-all) route ensures no messages are silently lost:

```toml
[[routes]]
name = "default"
match_all = true                 # matches every message unconditionally
outputs = ["general-output"]
priority = 65535                 # evaluated last
```

When `match_all = true`, all predicates are ignored and the route always matches. This is syntactic sugar for a route with no match predicates specified.

If no default route is configured, unmatched messages are dropped and counted in `syslog_messages_unrouted_total`.

### 1.6 Multiple Route Matching (Fan-Out)

Multiple routes can match a single message. When `continue = true` (the default), evaluation proceeds to the next route after a match. This enables fan-out patterns:

```toml
# Route 1: all auth messages go to the SIEM
[[routes]]
name = "auth-to-siem"
match.facility = ["auth", "authpriv"]
outputs = ["siem"]
continue = true       # keep evaluating

# Route 2: everything goes to long-term storage
[[routes]]
name = "archive-all"
match_all = true
outputs = ["s3-archive"]
priority = 1000
```

An auth message matches route 1 (dispatched to `siem`) and then route 2 (dispatched to `s3-archive`). A non-auth message skips route 1, matches route 2.

To implement exclusive routing (first-match-wins), set `continue = false` on routes:

```toml
[[routes]]
name = "high-severity"
match.severity_min = "err"
outputs = ["pagerduty-webhook"]
continue = false      # stop after this match
```

### 1.7 Route Metrics

Each compiled route tracks:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `syslog_route_matched_total` | Counter | `route` | Messages matched by this route |
| `syslog_route_evaluation_total` | Counter | — | Total route evaluations (messages entering the router) |
| `syslog_messages_unrouted_total` | Counter | — | Messages that matched no route and no default route |

All counters are `AtomicU64` with `Relaxed` ordering, updated inline in the dispatcher hot path.

---

## 2. Filter Design

Filters are evaluated before routing. They determine which messages enter the routing stage and which are dropped early. Filters form an ordered chain; each message passes through every filter in sequence unless explicitly dropped.

### 2.1 Filter Chain Model

```
Message from parser
    │
    ▼
┌──────────┐   pass   ┌──────────┐   pass   ┌──────────┐   pass
│ Filter 1 │ ───────► │ Filter 2 │ ───────► │ Filter 3 │ ───────► Router
│ (exclude │          │ (include │          │ (modify  │
│  debug)  │          │  auth*)  │          │  & pass) │
└──────────┘          └──────────┘          └──────────┘
    │ drop                │ drop                │ drop
    ▼                     ▼                     ▼
  (counted)            (counted)            (counted)
```

Filters are evaluated in config-file order. A message exits the chain as soon as any filter drops it, or after passing all filters.

### 2.2 Filter Types

#### 2.2.1 Exclude Filters (Blacklist)

Messages matching the filter's predicates are dropped. Non-matching messages pass through.

```toml
[[filters]]
name = "drop-debug"
action = "exclude"
match.severity_max = "debug"     # drop severity == debug (7)
```

```toml
[[filters]]
name = "drop-noisy-app"
action = "exclude"
match.app_name = "healthcheck"
match.facility = ["local7"]
```

#### 2.2.2 Include Filters (Whitelist)

Only messages matching the filter's predicates pass through. Non-matching messages are dropped. Use with caution: an include filter drops everything that does not match.

```toml
[[filters]]
name = "only-security"
action = "include"
match.facility = ["auth", "authpriv", "local6"]
```

#### 2.2.3 Modify-and-Pass Filters

Messages matching the predicates are modified in place and then passed through. Non-matching messages pass through unmodified. Modifications operate on a mutable copy of the message (since messages are `Arc`-wrapped, a `make_mut`-style clone is triggered on modification).

```toml
[[filters]]
name = "redact-passwords"
action = "modify"
match.app_name = "sudo"
modify.msg_regex_replace = { pattern = "password=\\S+", replacement = "password=REDACTED" }
```

```toml
[[filters]]
name = "tag-important"
action = "modify"
match.severity_min = "err"
modify.add_sd_element = { id = "syslog-usg@0", params = { "tagged" = "important" } }
```

Supported modification actions:

| Action | Description |
|--------|-------------|
| `msg_regex_replace` | Regex find-and-replace on the MSG body |
| `set_severity` | Override severity to a fixed value |
| `set_facility` | Override facility to a fixed value |
| `add_sd_element` | Append an SD-ELEMENT to structured data |
| `set_hostname` | Override hostname field |

### 2.3 Filter Match Predicates

Filters use the same `CompiledMatcher` predicate structure as routes (Section 1.2). All specified fields must match (logical AND). The same compilation and short-circuit evaluation optimizations apply.

### 2.4 Filter Compilation

Filters are compiled at config load alongside routes:

```rust
pub struct CompiledFilterChain {
    filters: Vec<CompiledFilter>,
}

pub struct CompiledFilter {
    name: CompactString,
    action: FilterAction,
    matcher: CompiledMatcher,
    modification: Option<Modification>,
    // Metrics
    evaluated_count: AtomicU64,
    matched_count: AtomicU64,
    dropped_count: AtomicU64,
}

pub enum FilterAction {
    Exclude,
    Include,
    Modify,
}
```

### 2.5 Filter Evaluation Logic

```rust
fn evaluate_filters(
    chain: &CompiledFilterChain,
    msg: &mut Arc<SyslogMessage>,
) -> FilterResult {
    for filter in &chain.filters {
        filter.evaluated_count.fetch_add(1, Relaxed);
        let matches = filter.matcher.matches(msg);

        match filter.action {
            FilterAction::Exclude if matches => {
                filter.matched_count.fetch_add(1, Relaxed);
                filter.dropped_count.fetch_add(1, Relaxed);
                return FilterResult::Drop;
            }
            FilterAction::Include if !matches => {
                filter.evaluated_count.fetch_add(1, Relaxed);
                filter.dropped_count.fetch_add(1, Relaxed);
                return FilterResult::Drop;
            }
            FilterAction::Modify if matches => {
                filter.matched_count.fetch_add(1, Relaxed);
                // Clone-on-write: Arc::make_mut clones the inner
                // SyslogMessage only if refcount > 1.
                let msg_mut = Arc::make_mut(msg);
                filter.modification.as_ref().unwrap().apply(msg_mut);
                // Invalidate raw bytes since message was modified
                msg_mut.raw = None;
            }
            _ => {
                // Exclude didn't match (pass), Include matched (pass),
                // Modify didn't match (pass unmodified).
                if matches {
                    filter.matched_count.fetch_add(1, Relaxed);
                }
            }
        }
    }
    FilterResult::Pass
}
```

Key behaviors:
- **Exclude + match = drop.** The message is discarded immediately.
- **Include + no match = drop.** The message does not satisfy the whitelist.
- **Modify + match = mutate and continue.** The message is modified in place (via `Arc::make_mut` copy-on-write) and evaluation continues to the next filter.
- **Modify invalidates raw bytes.** After any modification, `SyslogMessage.raw` is set to `None`, forcing re-serialization at output time. The passthrough optimization is no longer available for modified messages.

### 2.6 Filter Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `syslog_filter_evaluated_total` | Counter | `filter` | Messages evaluated by this filter |
| `syslog_filter_matched_total` | Counter | `filter` | Messages matching this filter's predicates |
| `syslog_filter_dropped_total` | Counter | `filter` | Messages dropped by this filter |
| `syslog_messages_filtered_total` | Counter | — | Total messages dropped by any filter (aggregate) |

---

## 3. Queue Model

Each output destination has a dedicated bounded queue. The queue decouples the pipeline dispatcher (producer) from the output sender task (consumer), absorbing bursts and isolating slow outputs from the rest of the pipeline.

### 3.1 Implementation

The per-output queue is implemented as a `tokio::sync::mpsc` bounded channel wrapped in a capacity-tracking layer.

```rust
pub struct OutputQueue {
    /// Channel sender, cloned into the pipeline dispatcher.
    tx: mpsc::Sender<Arc<SyslogMessage>>,
    /// Channel receiver, owned by the output sender task.
    rx: mpsc::Receiver<Arc<SyslogMessage>>,
    /// Configured overflow policy.
    overflow_policy: OverflowPolicy,

    // ── Capacity tracking ──
    /// Maximum number of messages.
    max_messages: usize,
    /// Maximum aggregate byte size of queued messages.
    max_bytes: u64,
    /// Current estimated byte size of queued messages.
    current_bytes: AtomicU64,
    /// Current message count (enqueued - dequeued).
    current_messages: AtomicU64,

    // ── Metrics ──
    enqueued_total: AtomicU64,
    dequeued_total: AtomicU64,
    overflow_total: AtomicU64,
}

pub enum OverflowPolicy {
    DropNewest,
    DropOldest,
    Block,
}
```

### 3.2 Capacity Configuration

Each output queue has two capacity dimensions:

| Dimension | Config Key | Default | Description |
|-----------|-----------|---------|-------------|
| Message count | `queue_capacity` | 10,000 | Maximum number of messages in the queue |
| Byte size | `queue_byte_limit` | `"64MB"` | Maximum aggregate estimated byte size |

The queue is considered full when **either** limit is reached. This dual-limit design prevents a small number of very large messages from consuming excessive memory, and prevents a flood of tiny messages from exhausting the message count before memory is stressed.

```toml
[[outputs]]
name = "upstream-tls"
queue_capacity = 10000
queue_byte_limit = "64MB"
backpressure = "drop-newest"
```

### 3.3 Memory Accounting

Each `SyslogMessage` carries an estimated byte size computed once after parsing:

```rust
impl SyslogMessage {
    /// Estimated heap size of this message, including all owned fields.
    /// Used for queue byte-size accounting. Does not need to be exact;
    /// a consistent approximation is sufficient.
    pub fn estimated_size(&self) -> usize {
        size_of::<Self>()
            + self.raw.as_ref().map_or(0, |b| b.len())
            + self.message.as_ref().map_or(0, |b| b.len())
            + self.structured_data.iter().map(|sd| sd.estimated_size()).sum::<usize>()
    }
}
```

The `current_bytes` atomic is incremented on enqueue and decremented on dequeue. This is an approximation (it does not account for `Arc` overhead or allocator fragmentation) but is sufficient for capacity enforcement.

### 3.4 Overflow Policies

When the queue is full (either limit reached), the pipeline dispatcher applies the configured policy:

#### 3.4.1 Drop-Newest (Default)

The incoming message is discarded. The queue contents are undisturbed.

```rust
// In the pipeline dispatcher:
match output_queue.try_send(msg.clone()) {
    Ok(()) => { /* enqueued */ }
    Err(TrySendError::Full(_)) => {
        output_queue.overflow_total.fetch_add(1, Relaxed);
        // Message is dropped (Arc refcount decremented)
    }
}
```

This is the simplest and most predictable policy. It favors preserving older (already-queued) messages over new arrivals. Appropriate for most relay configurations where downstream will eventually catch up and historical messages are more valuable than the latest ones during overload.

#### 3.4.2 Drop-Oldest

The oldest message in the queue is evicted to make room for the new message.

Implementation: `drop-oldest` cannot be efficiently implemented with a standard `tokio::sync::mpsc` channel because the consumer end is owned by the sender task. Instead, this policy uses a custom bounded ring buffer behind a `Mutex`:

```rust
pub struct RingQueue {
    buffer: VecDeque<Arc<SyslogMessage>>,
    max_messages: usize,
    max_bytes: u64,
    current_bytes: u64,
    notify: tokio::sync::Notify, // wake the consumer
}
```

When the ring is full, `push_back` evicts from the front (`pop_front`), adjusting `current_bytes` accordingly. The `Mutex` is held only for the duration of the push/pop operations (sub-microsecond) and does not risk contention at 100k msg/sec because there is exactly one producer (the dispatcher) and one consumer (the sender task).

This policy favors recency: in an overload, the queue always contains the newest messages. Appropriate when freshness matters more than completeness (e.g., real-time alerting outputs).

#### 3.4.3 Block (Backpressure)

The dispatcher awaits space in the queue. This is a standard bounded-channel `send().await`:

```rust
// Blocking send — will suspend the dispatcher task until space is available
output_queue.tx.send(msg.clone()).await?;
```

**Warning:** Block policy on any output causes backpressure to propagate upstream through the entire pipeline. See Section 4 for the full backpressure analysis. Block policy must be used with extreme caution and is only appropriate when message loss is unacceptable and the output is expected to recover quickly.

### 3.5 Batch Dequeue

The output sender task dequeues messages in batches for efficiency:

```rust
// In the output sender task:
let mut batch: Vec<Arc<SyslogMessage>> = Vec::with_capacity(BATCH_SIZE);

loop {
    // Block until at least one message is available.
    match rx.recv().await {
        Some(msg) => batch.push(msg),
        None => break, // channel closed, shutdown
    }

    // Drain up to BATCH_SIZE - 1 more messages without waiting.
    while batch.len() < BATCH_SIZE {
        match rx.try_recv() {
            Ok(msg) => batch.push(msg),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => break,
        }
    }

    // Process the batch (serialize + write).
    output.send_batch(&batch).await?;

    // Update byte accounting.
    let batch_bytes: u64 = batch.iter().map(|m| m.estimated_size() as u64).sum();
    queue.current_bytes.fetch_sub(batch_bytes, Relaxed);
    queue.current_messages.fetch_sub(batch.len() as u64, Relaxed);
    queue.dequeued_total.fetch_add(batch.len() as u64, Relaxed);

    batch.clear(); // reuse allocation
}
```

The batch size is configurable per output (default 64). Batch dequeue amortizes channel receive overhead and enables vectored I/O writes in the output sender.

### 3.6 Queue Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `syslog_queue_depth` | Gauge | `output` | Current messages in queue (`enqueued_total - dequeued_total`) |
| `syslog_queue_bytes` | Gauge | `output` | Current estimated bytes in queue |
| `syslog_queue_capacity` | Gauge | `output` | Configured max message count (static) |
| `syslog_queue_byte_capacity` | Gauge | `output` | Configured max byte size (static) |
| `syslog_queue_overflow_total` | Counter | `output`, `policy` | Messages lost due to queue overflow |

---

## 4. Backpressure Strategy

Backpressure is the mechanism by which downstream slowness propagates upstream through the pipeline. The design ensures that one slow output does not bring down the entire system.

### 4.1 Backpressure Propagation Path

```
Output slow/down
    │
    ▼
Per-output queue fills
    │
    ├── drop-newest policy: message dropped at dispatcher, other outputs unaffected
    ├── drop-oldest policy: oldest evicted, new message enqueued, other outputs unaffected
    └── block policy: dispatcher blocks on this output's send
            │
            ▼
        Dispatcher stalls (cannot process messages for ANY output)
            │
            ▼
        Ingress channel fills (parser tasks block on channel send)
            │
            ├── UDP listener: channel full → message dropped (cannot backpressure UDP)
            └── TLS listener: channel full → task blocks on send → stops reading
                    │
                    ▼
                TCP receive buffer fills → TCP flow control kicks in
                    │
                    ▼
                Sender's TCP write blocks → natural TCP backpressure
```

### 4.2 Cross-Output Isolation

The fundamental design principle: **one slow output must not block message delivery to other outputs.** This is achieved through architecture:

1. **Separate channel per output.** The dispatcher holds a `Sender` handle for each output queue. Sends to different queues are independent operations.

2. **Non-blocking dispatch (default).** With `drop-newest` or `drop-oldest` policies, the dispatcher uses `try_send` (non-blocking). If one output's queue is full, the dispatcher drops/evicts for that output and continues dispatching to the next output immediately.

3. **Block policy breaks isolation.** With `block` policy, the dispatcher `send().await`s on the full queue. While suspended, it cannot process messages for any output. This is by design: `block` policy is an explicit choice to prioritize message delivery to a critical output over pipeline throughput.

**Recommended configuration:** Use `drop-newest` (default) or `drop-oldest` for all outputs. Reserve `block` for at most one output that is designated as the critical delivery target, and only in environments where the output's recovery time is bounded (e.g., a local file output that is temporarily at disk capacity).

### 4.3 UDP Listener Backpressure

UDP is inherently fire-and-forget. The kernel's receive buffer is the only buffering point. When the pipeline cannot keep up:

1. The ingress channel is full (or the listener is blocked on a full channel send).
2. The UDP listener task cannot call `recv_from` because it is blocked/yielded.
3. The kernel `SO_RCVBUF` fills up.
4. The kernel drops subsequent datagrams silently.

**Mitigation:**

- **Large `SO_RCVBUF`.** Configure a large kernel receive buffer (default 4 MB, configurable). This absorbs short bursts of backpressure.
- **Drop-and-count at the listener.** If the ingress channel is full, the UDP listener drops the message immediately (does not block) and increments `syslog_udp_listener_drops_total`. This prevents the listener from stalling.
- **Metric alerting.** Operators monitor `syslog_udp_listener_drops_total` to detect sustained overload and scale out or tune queue sizes.

```rust
// UDP listener hot loop:
loop {
    let n = socket.recv_from(&mut buf).await?;
    let msg = parse_and_wrap(&buf[..n]);

    match ingress_tx.try_send(msg) {
        Ok(()) => { received_total.fetch_add(1, Relaxed); }
        Err(TrySendError::Full(_)) => {
            udp_drops_total.fetch_add(1, Relaxed);
        }
        Err(TrySendError::Disconnected) => break, // shutdown
    }
}
```

### 4.4 TLS Listener Backpressure

TLS over TCP has natural flow control:

1. The per-connection task blocks on `ingress_tx.send().await` (bounded channel send).
2. While the task is blocked, it does not read from the `TlsStream`.
3. The kernel TCP receive buffer fills.
4. TCP window shrinks to zero, signaling the sender to stop.
5. The remote sender's TCP write blocks.

This is correct and desirable behavior for TLS inputs. The sender is naturally throttled, and no messages are lost (they are buffered in the sender's TCP stack until the receiver catches up). This is the at-least-once delivery path for TLS inputs.

**Per-connection timeout:** To prevent a backpressured connection from holding resources indefinitely, each connection task has a configurable read idle timeout (default 60 seconds). If the task is blocked on channel send for longer than this timeout and no progress is being made, the connection is closed with a log warning. The remote client is expected to reconnect and retry.

### 4.5 Backpressure Configuration Summary

| Component | Backpressure Behavior | Configurable? |
|-----------|----------------------|---------------|
| UDP listener | Drop and count on full ingress channel | Ingress channel size, `SO_RCVBUF` |
| TLS connection | Block on full ingress channel (TCP flow control) | Ingress channel size, read idle timeout |
| Ingress channel | Bounded `tokio::sync::mpsc`, capacity in messages | `pipeline.ingress_channel_capacity` (default 10,000) |
| Pipeline dispatcher | Per-output policy: `try_send` or `send().await` | Per-output `backpressure` setting |
| Per-output queue | Bounded by message count and byte size | `queue_capacity`, `queue_byte_limit` |

---

## 5. Retry Strategy

When an output sender fails to deliver messages (connection refused, write error, timeout), a retry strategy determines how the sender recovers.

### 5.1 Exponential Backoff with Jitter

On delivery failure, the sender enters a reconnection loop:

```rust
pub struct RetryConfig {
    /// Initial delay before the first retry attempt.
    pub initial_delay: Duration,     // default: 100ms
    /// Maximum delay between retry attempts.
    pub max_delay: Duration,         // default: 30s
    /// Multiplicative factor for each successive retry.
    pub multiplier: f64,             // default: 2.0
    /// Maximum number of retries before giving up on a message batch.
    pub max_retries: u32,            // default: 5 (0 = infinite)
    /// Jitter factor (0.0 to 1.0). Applied as random +-jitter% of the delay.
    pub jitter: f64,                 // default: 0.25
}
```

Retry sequence for default configuration:
```
Attempt 1: 100ms  +/- 25ms jitter  → actual delay: 75ms - 125ms
Attempt 2: 200ms  +/- 50ms jitter  → actual delay: 150ms - 250ms
Attempt 3: 400ms  +/- 100ms jitter → actual delay: 300ms - 500ms
Attempt 4: 800ms  +/- 200ms jitter → actual delay: 600ms - 1000ms
Attempt 5: 1600ms +/- 400ms jitter → actual delay: 1200ms - 2000ms
...capped at max_delay (30s)
```

Jitter prevents thundering-herd reconnection storms when multiple outputs target the same downstream server.

### 5.2 Circuit Breaker

After repeated consecutive failures, the sender transitions to a circuit-open state, stopping delivery attempts temporarily.

```
States:
  CLOSED  ──[failure]──► counting failures
              │                 │
              │         [N consecutive failures]
              │                 │
              ▼                 ▼
          (normal)          OPEN ──── [cooldown timer] ────► HALF-OPEN
                              │                                  │
                              │                            [probe succeeds]
                              │                                  │
                              │                                  ▼
                              │                              CLOSED
                              │                                  │
                              │                            [probe fails]
                              │                                  │
                              └──────────────────────────────────┘
                                        (back to OPEN)
```

```rust
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to trip the breaker.
    pub failure_threshold: u32,       // default: 5
    /// Duration to remain in OPEN state before probing.
    pub cooldown: Duration,           // default: 30s
    /// Number of successful probes to transition back to CLOSED.
    pub success_threshold: u32,       // default: 1
}
```

**OPEN state behavior:**
- The sender task does not attempt delivery. Messages continue to accumulate in the queue (subject to overflow policy).
- After the cooldown period, the sender transitions to HALF-OPEN.

**HALF-OPEN state behavior:**
- The sender attempts a single health-check probe: connect to the downstream, optionally send a probe message.
- On success: transition to CLOSED, resume normal delivery, drain the queue.
- On failure: transition back to OPEN, restart the cooldown timer.

**Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `syslog_output_circuit_state` | Gauge | `output` | 0 = closed, 1 = open, 2 = half-open |
| `syslog_output_circuit_trips_total` | Counter | `output` | Times the circuit breaker tripped |

### 5.3 Failed Message Handling

When a message batch fails all retry attempts:

1. **Re-queue:** Return the batch to the front of the queue for a later attempt. Risk: if the output is persistently down, the same batch retries indefinitely. Mitigated by the circuit breaker.
2. **Dead-letter:** Forward the batch to the dead letter queue (Section 8), if configured.
3. **Drop with metric:** Discard the batch and increment `syslog_messages_dropped_total{output, reason="delivery_failed"}`.

The behavior is configurable per output:

```toml
[[outputs]]
name = "upstream-tls"
retry.max_retries = 5
retry.initial_delay = "100ms"
retry.max_delay = "30s"
on_failure = "dead-letter"        # "requeue" | "dead-letter" | "drop"
circuit_breaker.failure_threshold = 5
circuit_breaker.cooldown = "30s"
```

---

## 6. Delivery Guarantees

This section documents what the system promises and does not promise about message delivery.

### 6.1 Guarantee Levels by Transport

| Input Transport | Guarantee | Rationale |
|----------------|-----------|-----------|
| UDP | **At-most-once** | UDP provides no acknowledgment. The kernel may drop datagrams before the application reads them. The listener may drop messages on ingress channel overflow. No retry mechanism exists for UDP inputs. |
| TLS (TCP) | **Best-effort, approaching at-least-once** | TCP guarantees delivery to the application layer. TLS connection tasks can apply backpressure via TCP flow control, preventing message loss at the input. However, messages in the in-memory queue are lost on process crash. True at-least-once requires persistent (disk-backed) queues, which are a post-MVP feature. |

### 6.2 Queue Persistence and Crash Behavior

**MVP (in-memory queue):** Messages in output queues are lost on process crash, `kill -9`, or power failure. The system provides no durability guarantee for queued messages.

**Future (disk-backed queue):** A WAL-style persistent queue will enable at-least-once delivery for TLS inputs. Messages are written to disk before being acknowledged to the output. On recovery, the queue replays unacknowledged messages. This is a Phase 5 feature (see Phase 01 Section 4.4).

### 6.3 Ordering Guarantees

| Scenario | Ordering | Rationale |
|----------|----------|-----------|
| Single TLS connection to single output | **Ordered** | Messages flow through a single-producer-single-consumer path: connection task pushes to ingress channel (FIFO) which is consumed by one dispatcher, which pushes to one output queue (FIFO), consumed by one sender. |
| Single TLS connection to multiple outputs (fan-out) | **Independent ordering per output** | Each output queue is drained independently. Output A may deliver message N before output B delivers message N-1. Ordering is preserved within each output. |
| Multiple UDP sources to single output | **Best-effort** | UDP datagrams from different sources may arrive in any order. Within a single source, ordering depends on network behavior and kernel scheduling. No reordering is applied by the pipeline. |
| Multiple TLS connections to single output | **Interleaved** | Messages from different connections are multiplexed into the ingress channel in arrival order. Within a single connection, ordering is preserved. Across connections, ordering depends on task scheduling. |

### 6.4 Exactly-Once Delivery

**Not supported.** Exactly-once semantics require end-to-end acknowledgment and deduplication, which the syslog protocol family does not provide. The closest approximation is RFC 3195 (BEEP-based reliable delivery with application-layer acknowledgment), which is a post-MVP feature.

Reasons exactly-once is not viable for syslog relay:
- UDP inputs cannot acknowledge.
- Fan-out cloning means a single input message becomes multiple output messages; deduplication scope is ambiguous.
- Network-level retransmission (TCP) may result in duplicate application-layer messages if the connection drops between message delivery and acknowledgment.

### 6.5 No-Silent-Loss Invariant

The system maintains a strict accounting invariant: every message that enters the pipeline is either:

1. **Delivered** to at least one output (counted in `syslog_messages_forwarded_total`), or
2. **Dropped with a reason** (counted in `syslog_messages_dropped_total{reason="..."}`)

Drop reasons:
- `filtered` — dropped by a filter rule
- `queue_full` — dropped due to output queue overflow
- `delivery_failed` — dropped after exhausting retries
- `unrouted` — matched no route and no default route
- `parse_error` — dropped due to parse failure in strict mode
- `shutdown` — dropped during graceful shutdown after drain timeout
- `udp_listener_full` — dropped at UDP listener because ingress channel was full

No message may vanish without being counted in one of these categories. This invariant is validated in integration tests.

---

## 7. Fan-Out Design

Fan-out occurs when a message matches multiple routes (or a single route with multiple outputs). The router must dispatch the message to each target output queue.

### 7.1 Clone Strategy

Messages flow through the pipeline as `Arc<SyslogMessage>`. Fan-out clones the `Arc`, not the message itself:

```rust
// In the pipeline dispatcher, after route evaluation:
for output_index in matched_output_indices {
    let msg_clone = Arc::clone(&msg);  // refcount increment, ~1ns
    output_queues[output_index].try_send(msg_clone)?;
}
```

**Clone cost analysis:**

| Operation | Cost | Notes |
|-----------|------|-------|
| `Arc::clone` | ~1 ns | Atomic refcount increment |
| `SyslogMessage` deep clone | ~100-500 ns | Allocates new strings, copies bytes; only needed if a filter modifies the message for a specific output |
| `Bytes::clone` | ~1 ns | Reference-counted; shares underlying allocation |

For unmodified fan-out (the common case), the cost is one `Arc::clone` per output: an atomic increment. The underlying `SyslogMessage` and its `Bytes` fields are shared read-only across all outputs.

### 7.2 Modification and Copy-on-Write

If a filter or output-specific transformation modifies a message, `Arc::make_mut` triggers a deep clone only when the reference count is greater than 1 (i.e., the message is shared with other outputs):

```rust
// Only clones the inner SyslogMessage if Arc strong_count > 1.
let msg_mut: &mut SyslogMessage = Arc::make_mut(&mut msg);
msg_mut.hostname = Some(CompactString::from("rewritten"));
msg_mut.raw = None; // invalidate passthrough
```

This copy-on-write semantics ensures that unmodified fan-out paths pay no clone cost, while modifications are isolated to the specific output that needs them.

### 7.3 Independent Failure Domains

Each output operates as an independent failure domain:

```
                    ┌─── Output A queue ───► Sender A (healthy) ✓
                    │
Dispatcher ─────────┼─── Output B queue ───► Sender B (DOWN) ✗
                    │
                    └─── Output C queue ───► Sender C (healthy) ✓
```

When output B fails:
- Output B's queue fills according to its capacity.
- Output B's overflow policy (e.g., `drop-newest`) applies.
- **Outputs A and C are completely unaffected.** The dispatcher's `try_send` to A and C succeeds normally.
- Messages dropped from B's queue are counted in `syslog_queue_overflow_total{output="B"}`.
- Output B's circuit breaker trips after N failures, reducing reconnection overhead.

This isolation is the primary reason the dispatcher uses `try_send` (non-blocking) by default. The `block` policy explicitly breaks this isolation for outputs where message loss is unacceptable.

### 7.4 Fan-Out Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `syslog_fanout_copies_total` | Counter | — | Total `Arc::clone` operations in the router (correlates with total dispatches) |
| `syslog_route_output_dispatched_total` | Counter | `route`, `output` | Messages dispatched from a specific route to a specific output |

---

## 8. Dead Letter Queue

The dead letter queue (DLQ) captures messages that could not be delivered to their intended output after exhausting retries. It provides a safety net for post-mortem analysis and manual reprocessing.

### 8.1 Configuration

The DLQ is disabled by default. When enabled, it is configured as a special output:

```toml
[dead_letter_queue]
enabled = true
output = "file"                  # "file" | "queue" (a named output)
path = "/var/log/syslog-usg/dead-letter.jsonl"
format = "json"                  # messages serialized as JSON with failure metadata
queue_capacity = 50000
queue_byte_limit = "128MB"
backpressure = "drop-oldest"     # DLQ itself can overflow; drop-oldest preserves newest failures
```

### 8.2 DLQ Message Format

Messages written to the DLQ are annotated with delivery failure metadata:

```rust
pub struct DeadLetterEnvelope {
    /// The original syslog message.
    pub message: Arc<SyslogMessage>,
    /// The output that failed to deliver.
    pub failed_output: CompactString,
    /// Reason for failure.
    pub failure_reason: CompactString,
    /// Number of delivery attempts made.
    pub attempts: u32,
    /// Timestamp of the last delivery attempt.
    pub last_attempt_at: SystemTime,
    /// Timestamp when the message was moved to the DLQ.
    pub dead_lettered_at: SystemTime,
}
```

JSON serialization example:

```json
{
  "dead_letter": {
    "failed_output": "upstream-tls",
    "failure_reason": "connection refused after 5 retries",
    "attempts": 5,
    "last_attempt_at": "2026-03-11T14:30:00.123Z",
    "dead_lettered_at": "2026-03-11T14:30:01.456Z"
  },
  "message": {
    "facility": 4,
    "severity": 3,
    "hostname": "fw-01.example.com",
    "app_name": "sshd",
    "timestamp": "2026-03-11T14:29:58.000Z",
    "msg": "Failed password for root from 192.168.1.100 port 22 ssh2",
    "raw": "<35>1 2026-03-11T14:29:58Z fw-01.example.com sshd 12345 - - Failed password..."
  }
}
```

### 8.3 DLQ Overflow

The DLQ itself has a bounded queue. If the DLQ overflows:
- The overflow policy (default `drop-oldest`) applies.
- Overflow is counted in `syslog_dlq_overflow_total`.
- A WARNING-level log is emitted (rate-limited to once per minute).

### 8.4 DLQ Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `syslog_dlq_enqueued_total` | Counter | `failed_output` | Messages sent to the DLQ |
| `syslog_dlq_overflow_total` | Counter | — | Messages dropped due to DLQ overflow |
| `syslog_dlq_depth` | Gauge | — | Current messages in the DLQ |

---

## 9. Pipeline Lifecycle

This section describes how the relay pipeline starts, stops, and reconfigures at runtime.

### 9.1 Startup Sequence

Startup proceeds in reverse-pipeline order: outputs first, then pipeline, then inputs. This ensures all downstream components are ready before messages begin flowing.

```
1. Load and validate configuration
     │
2. Initialize metrics registry
     │
3. Create per-output queues (bounded channels)
     │
4. Spawn output sender tasks
   (each owns the rx end of its queue, establishes connections)
     │
5. Compile filter chain and route table
     │
6. Spawn pipeline dispatcher task
   (receives from ingress channel, applies filters, evaluates routes,
    dispatches to output queues)
     │
7. Create ingress channel (bounded mpsc)
     │
8. Spawn listener tasks (UDP, TLS acceptors)
   (each sends into the ingress channel)
     │
9. Start admin HTTP server (/health, /metrics)
     │
10. Signal readiness (sd_notify, /ready returns 200)
```

**Startup validation** (step 1):
- All listener addresses must be bindable (fail fast on port conflicts).
- All TLS certificates must be loadable and valid.
- All output targets must resolve via DNS (warning, not error, if unreachable).
- All routes must reference defined outputs.
- All filters must have valid compiled predicates (regexes, globs).

### 9.2 Shutdown Sequence

Graceful shutdown drains the pipeline from front to back, ensuring in-flight messages are delivered where possible.

```
1. Signal handler receives SIGTERM/SIGINT
     │
2. Cancel ingress_token
   - UDP listeners: stop recv loop, task exits
   - TLS acceptor: stop accepting new connections
   - TLS connections: finish current message, then close
     │
3. Wait for all ingress tasks to complete (with timeout)
     │
4. Close ingress channel sender (all tx handles dropped)
     │
5. Pipeline dispatcher drains ingress_rx to completion
   - For each remaining message: filter, route, dispatch to queues
   - When ingress_rx returns None (channel closed): dispatcher exits
     │
6. Close all output queue senders (dispatcher's tx handles dropped)
     │
7. Output sender tasks drain their rx to completion
   - Serialize and send all remaining messages
   - On output error during drain: apply DLQ/drop policy
     │
8. Wait for all output sender tasks to complete (with drain timeout)
   - Default drain timeout: 5 seconds
   - On timeout: count remaining messages as dropped{reason="shutdown"}
     │
9. Shut down admin HTTP server
     │
10. Flush metrics one final time
     │
11. Exit process (code 0)
```

### 9.3 Configuration Reload

Hot reload is triggered by SIGHUP. The strategy is validate-then-swap: the new configuration is fully validated and compiled before any changes are applied to the running pipeline.

```
1. SIGHUP received
     │
2. Load and validate new configuration from disk
   - On validation failure: log error, keep current config, no disruption
     │
3. Diff new config against current config
   - Identify: added/removed/changed listeners, outputs, filters, routes
     │
4. Build new compiled artifacts:
   - New CompiledFilterChain
   - New CompiledRouteTable
   - New output queues and sender tasks (for added/changed outputs)
     │
5. Atomic swap:
   a. Swap filter chain (Arc::swap or ArcSwap)
   b. Swap route table (Arc::swap or ArcSwap)
      - The dispatcher reads the route table via Arc clone on each message.
      - After swap, new messages use the new table.
      - In-flight messages (already past the dispatcher) continue with old routing.
   c. Start new listener tasks (for added listeners)
   d. Signal removed listener tasks to shut down and drain
   e. For changed outputs: start new sender tasks, drain old queues, then drop old senders
     │
6. Log successful reload with summary of changes
```

**Key invariants during reload:**
- **No message loss.** Messages in flight in the old pipeline continue through to delivery.
- **No connection drops.** Existing TLS connections are not terminated on reload. They continue under the configuration that was active when they connected.
- **Idempotent.** Reloading the same configuration produces no observable side effects.

### 9.4 Task Supervision

All spawned tasks are monitored for panics:

```rust
// In the lifecycle manager:
let mut task_set = JoinSet::new();

// Spawn output sender with supervision:
task_set.spawn(async move {
    output_sender_task(rx, output_config).await
});

// Monitor loop:
loop {
    match task_set.join_next().await {
        Some(Ok(())) => {
            // Task completed normally (shutdown).
        }
        Some(Err(join_error)) if join_error.is_panic() => {
            error!("Output sender task panicked: {}", join_error);
            syslog_task_panics_total.fetch_add(1, Relaxed);
            // Respawn the task with the same configuration.
            task_set.spawn(async move {
                output_sender_task(rx_clone, output_config_clone).await
            });
        }
        None => break, // All tasks completed.
    }
}
```

**Restart policy:**
- Output sender tasks are always restarted after panic. The queue is preserved (the `rx` handle is re-acquired from the queue structure).
- Listener tasks are restarted after panic. The listener socket is re-bound.
- The pipeline dispatcher is restarted after panic. The ingress channel `rx` is re-acquired.
- Restart attempts are rate-limited (max 3 restarts per 10 seconds per task). If the rate limit is exceeded, the task enters a failed state and an alert-severity log is emitted.

---

## 10. Throughput Optimization

This section consolidates the performance design decisions that enable 100k msg/sec sustained throughput with p99 relay latency under 1ms.

### 10.1 Minimize Channel Hops

The pipeline has exactly two channel hops on the hot path:

```
Listener → [ingress channel] → Dispatcher → [output queue] → Sender
            (hop 1)                          (hop 2)
```

Filter and route evaluation happen inline within the dispatcher task, adding zero channel hops. The dispatcher performs:
1. Receive from ingress channel (async, wakes on message arrival)
2. Evaluate filter chain (synchronous, CPU-bound, typically < 1us)
3. Evaluate route table (synchronous, CPU-bound, typically < 1us)
4. Send to matched output queues (async, non-blocking `try_send`)

Total dispatcher overhead per message: ~2-5us (dominated by channel operations, not filter/route logic). This is well within the 10us budget that allows 100k msg/sec on a single dispatcher task.

### 10.2 Batch Processing

Batching amortizes per-operation overhead across multiple messages:

| Stage | Batch Operation | Batch Size | Benefit |
|-------|----------------|------------|---------|
| UDP recv (future) | `recvmmsg` / `io_uring` batch recv | 32-64 datagrams | Reduces syscall count by 32-64x |
| Output sender dequeue | `recv_many` / drain loop | 64 messages (configurable) | Amortizes channel receive overhead |
| TLS output write | Vectored write of serialized batch | 64 messages | Reduces TLS record overhead, fewer `write` syscalls |
| File output write | Buffered write, flush per batch | 64 messages | Reduces `write` syscalls |
| Metrics rendering | Compute queue depth from `enqueued - dequeued` | On demand | Avoids per-message gauge updates |

### 10.3 Allocation Budget

Target: at most 1 heap allocation per message on the hot path (the `SyslogMessage` struct itself).

| Hot-Path Operation | Allocation? | Strategy |
|-------------------|------------|----------|
| UDP `recv_from` | No | Reusable stack buffer |
| Parse (zero-copy phase) | No | Borrows from recv buffer |
| Parse (owned phase) | **Yes (1x)** | Allocate `SyslogMessage` with owned fields |
| `Arc` wrap | No | `Arc::new` uses the already-allocated `SyslogMessage` (single allocation for Arc+inner) |
| Ingress channel send | No | Moves the `Arc` pointer |
| Filter evaluation | No | Reads fields by reference |
| Route evaluation | No | Reads fields by reference |
| `Arc::clone` for fan-out | No | Atomic refcount increment |
| Output queue send | No | Moves the `Arc` pointer |
| Batch dequeue | No | Reusable `Vec` (cleared, not deallocated) |
| TLS serialization | No | Reusable write buffer per sender task |

**Exception: modify filters.** A filter with `action = "modify"` triggers `Arc::make_mut`, which deep-clones the `SyslogMessage` if the reference count is > 1. This is an additional allocation on the modified path only.

### 10.4 Lock-Free Metrics

All pipeline metrics use `AtomicU64` with `Relaxed` ordering:

```rust
pub struct PipelineMetrics {
    pub messages_received: AtomicU64,
    pub messages_forwarded: AtomicU64,
    pub messages_dropped: AtomicU64,
    pub parse_errors: AtomicU64,
    // Per-output, per-filter, per-route metrics are in their respective structs.
}
```

- **Counters:** `fetch_add(1, Relaxed)`. Single atomic instruction on x86_64. No bus lock contention in the typical case (one writer per counter per task).
- **Gauges (queue depth):** Computed at render time as `enqueued_total - dequeued_total`. No per-message gauge update needed.
- **Histograms:** Fixed-bucket with atomic per-bucket counters. Bucket boundaries are compile-time constants. Parse latency histograms are sampled (every 64th message) to reduce `Instant::now()` syscall overhead.

### 10.5 Channel Implementation: tokio::sync::mpsc vs. Alternatives

The default channel implementation is `tokio::sync::mpsc`. This section evaluates alternatives.

| Implementation | Throughput (msg/sec) | Latency (p99) | Async? | Notes |
|---------------|---------------------|---------------|--------|-------|
| `tokio::sync::mpsc` | ~5M | ~200ns | Yes | Waker-based, integrates with Tokio runtime. Default choice. |
| `crossbeam::channel` | ~10M | ~100ns | No | Lock-free, higher raw throughput. Requires `spawn_blocking` or busy-poll bridge for async integration. |
| `flume` | ~8M | ~150ns | Yes (optional) | Async support via feature flag. Slightly higher throughput than tokio mpsc. |
| Custom ring buffer | ~15M | ~50ns | No | Maximum throughput for SPSC. Requires manual async integration. |

**Decision:** Use `tokio::sync::mpsc` for MVP. At 5M msg/sec capacity, it is 50x above the 100k msg/sec requirement. The async integration (waker-based wake on send/recv) is essential for the backpressure model. If profiling reveals channel operations as a bottleneck at higher throughputs (post-MVP), `flume` or a custom SPSC ring buffer can be substituted behind a trait abstraction.

**Drop-oldest ring buffer:** For output queues with `drop-oldest` policy, a custom `Mutex<VecDeque>` ring buffer is used instead of `tokio::sync::mpsc` (see Section 3.4.2). The `Mutex` hold time is bounded (sub-microsecond push/pop) and contention is minimal (one producer, one consumer).

### 10.6 Pipeline Dispatcher Scaling

At 100k msg/sec, the dispatcher processes one message every 10us. With filter+route evaluation taking ~2-5us, there is headroom for moderate filter/route complexity. However, if the configuration includes expensive `msg_regex` patterns evaluated on most messages, the dispatcher may become CPU-bound.

**Scaling strategy (post-MVP):** Shard the dispatcher into N parallel tasks, each reading from the same ingress channel (tokio mpsc supports multiple consumers via `Arc<Mutex<Receiver>>`; alternatively, use N separate channels with round-robin distribution from listeners).

```
Ingress ──► Dispatcher 1 ──► output queues
        ──► Dispatcher 2 ──► output queues
        ──► Dispatcher 3 ──► output queues
```

**Trade-off:** Sharded dispatchers break per-source ordering guarantees across the pipeline (messages from the same source may be processed by different dispatchers and arrive at the output queue out of order). This is acceptable if ordering is not required, or if the output re-sorts by timestamp.

For MVP, a single dispatcher task is sufficient and preserves ordering.

### 10.7 Hot Path Summary

```
UDP recv_from (0 alloc)
    │ 50ns
    ▼
Parse zero-copy (0 alloc)
    │ 2-8us
    ▼
Allocate SyslogMessage (1 alloc)
    │ 50-200ns
    ▼
Arc::new (0 additional alloc)
    │ 10ns
    ▼
Ingress channel try_send (0 alloc)
    │ 100-300ns
    ▼
Filter chain evaluate (0 alloc)
    │ 0.5-2us
    ▼
Route table evaluate (0 alloc)
    │ 0.5-2us
    ▼
Arc::clone + output try_send (0 alloc, per output)
    │ 100-300ns per output
    ▼
[In output sender task]
Batch dequeue (0 alloc, reuse Vec)
    │ amortized ~50ns per message
    ▼
Serialize to write buffer (0 alloc, reuse buffer)
    │ 1-5us per message
    ▼
TLS write_all
    │ amortized ~1-10us per message (batched)
    ▼
Done
```

**Total estimated hot-path time (UDP-in, single TLS-out, no fan-out):** 5-15us per message, well within the 1ms p99 relay latency target.

---

## Appendix A: Complete Configuration Example

```toml
# syslog-usg.toml — Relay pipeline configuration

[server]
drain_timeout_seconds = 5

[pipeline]
ingress_channel_capacity = 10000

# ── Filters ──────────────────────────────────────────────

[[filters]]
name = "drop-debug"
action = "exclude"
match.severity_max = "debug"

[[filters]]
name = "drop-healthcheck"
action = "exclude"
match.app_name = "healthcheck-*"
match.facility = ["local7"]

[[filters]]
name = "redact-passwords"
action = "modify"
match.msg_regex = "password=\\S+"
modify.msg_regex_replace = { pattern = "password=\\S+", replacement = "password=[REDACTED]" }

[[filters]]
name = "only-important"
action = "include"
match.severity_min = "info"
# Note: this drops everything with severity > info (debug is already excluded above)

# ── Outputs ──────────────────────────────────────────────

[[outputs]]
name = "upstream-siem"
transport = "tls"
target = "siem.example.com:6514"
queue_capacity = 20000
queue_byte_limit = "128MB"
backpressure = "drop-newest"
batch_size = 64
retry.max_retries = 5
retry.initial_delay = "100ms"
retry.max_delay = "30s"
on_failure = "dead-letter"
circuit_breaker.failure_threshold = 5
circuit_breaker.cooldown = "30s"

[outputs.tls]
cert = "/etc/syslog-usg/client.crt"
key = "/etc/syslog-usg/client.key"
ca = "/etc/syslog-usg/siem-ca.crt"

[[outputs]]
name = "local-archive"
transport = "file"
path = "/var/log/syslog-usg/archive.log"
format = "rfc5424"
queue_capacity = 5000
queue_byte_limit = "32MB"
backpressure = "drop-oldest"
batch_size = 128

[[outputs]]
name = "json-stdout"
transport = "stdout"
format = "json"
queue_capacity = 1000
backpressure = "drop-newest"

# ── Routes ───────────────────────────────────────────────

[[routes]]
name = "security-events"
priority = 10
match.facility = ["auth", "authpriv"]
match.severity_min = "warning"
outputs = ["upstream-siem"]
continue = true

[[routes]]
name = "firewall-logs"
priority = 20
match.hostname = "fw-*.example.com"
outputs = ["upstream-siem", "local-archive"]
continue = true

[[routes]]
name = "application-errors"
priority = 30
match.severity_min = "err"
match.msg_regex = "error|exception|panic|fatal"
outputs = ["upstream-siem"]
continue = true

[[routes]]
name = "default-archive"
priority = 1000
match_all = true
outputs = ["local-archive", "json-stdout"]

# ── Dead Letter Queue ────────────────────────────────────

[dead_letter_queue]
enabled = true
output = "file"
path = "/var/log/syslog-usg/dead-letter.jsonl"
format = "json"
queue_capacity = 50000
queue_byte_limit = "128MB"
backpressure = "drop-oldest"
```

## Appendix B: Metric Reference

All metrics introduced in this document, consolidated:

| Metric | Type | Labels | Section |
|--------|------|--------|---------|
| `syslog_route_matched_total` | Counter | `route` | 1.7 |
| `syslog_route_evaluation_total` | Counter | — | 1.7 |
| `syslog_messages_unrouted_total` | Counter | — | 1.7 |
| `syslog_filter_evaluated_total` | Counter | `filter` | 2.6 |
| `syslog_filter_matched_total` | Counter | `filter` | 2.6 |
| `syslog_filter_dropped_total` | Counter | `filter` | 2.6 |
| `syslog_messages_filtered_total` | Counter | — | 2.6 |
| `syslog_queue_depth` | Gauge | `output` | 3.6 |
| `syslog_queue_bytes` | Gauge | `output` | 3.6 |
| `syslog_queue_capacity` | Gauge | `output` | 3.6 |
| `syslog_queue_byte_capacity` | Gauge | `output` | 3.6 |
| `syslog_queue_overflow_total` | Counter | `output`, `policy` | 3.6 |
| `syslog_udp_listener_drops_total` | Counter | `listener` | 4.3 |
| `syslog_output_circuit_state` | Gauge | `output` | 5.2 |
| `syslog_output_circuit_trips_total` | Counter | `output` | 5.2 |
| `syslog_messages_dropped_total` | Counter | `output`, `reason` | 6.5 |
| `syslog_fanout_copies_total` | Counter | — | 7.4 |
| `syslog_route_output_dispatched_total` | Counter | `route`, `output` | 7.4 |
| `syslog_dlq_enqueued_total` | Counter | `failed_output` | 8.4 |
| `syslog_dlq_overflow_total` | Counter | — | 8.4 |
| `syslog_dlq_depth` | Gauge | — | 8.4 |
| `syslog_task_panics_total` | Counter | `task_type` | 9.4 |

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| **Dispatcher** | The single Tokio task that receives messages from the ingress channel, applies filters, evaluates routes, and dispatches to output queues. The fan-out point of the pipeline. |
| **Fan-out** | Delivering a single message to multiple outputs by cloning the `Arc<SyslogMessage>`. |
| **Backpressure** | The mechanism by which downstream slowness propagates upstream, causing producers to slow down or drop messages. |
| **Circuit breaker** | A pattern that stops delivery attempts to a failing output after N consecutive failures, probing periodically to detect recovery. |
| **Dead letter queue (DLQ)** | A secondary output that captures messages that could not be delivered after exhausting retries. |
| **Drop-newest** | Overflow policy: discard the incoming message when the queue is full. Preserves older queued messages. |
| **Drop-oldest** | Overflow policy: evict the oldest message from the queue to make room for the incoming message. Preserves recency. |
| **Block** | Overflow policy: the producer awaits space in the queue. Propagates backpressure upstream. |
| **Ingress channel** | The bounded `tokio::sync::mpsc` channel connecting all listener tasks to the pipeline dispatcher. |
| **Output queue** | A per-output bounded channel or ring buffer connecting the dispatcher to an output sender task. |
| **Passthrough** | Forwarding a message using its original wire-format bytes (`SyslogMessage.raw`) without re-serialization. |
| **Route table** | The compiled, immutable set of routing rules evaluated by the dispatcher for each message. |

