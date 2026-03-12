# Phase 10 -- Security, Robustness, and Hardening

## syslog-usg: Threat Analysis, Security Recommendations, and Hardening Guide

**Version:** 1.0.0-draft
**Date:** 2026-03-11
**Status:** Draft
**Prerequisites:** [Phase 01](phase-01-requirements.md), [Phase 03](phase-03-architecture.md), [Phase 04](phase-04-rust-architecture.md), [Phase 05](phase-05-transport-security.md)

---

## Table of Contents

1. [Threat and Abuse-Case Review](#1-threat-and-abuse-case-review)
2. [Security Recommendations](#2-security-recommendations)
3. [Robustness Requirements](#3-robustness-requirements)
4. [Fuzzing Targets](#4-fuzzing-targets)
5. [Must-Fix Issues](#5-must-fix-issues)
6. [Hardening Checklist](#6-hardening-checklist)

---

## 1. Threat and Abuse-Case Review

syslog-usg processes untrusted network input from arbitrary sources in environments where availability and integrity are critical (government networks, enterprise SOCs, compliance-grade logging infrastructure). The threat model assumes a network-adjacent adversary with the ability to send arbitrary data to listening ports, establish TLS connections, and attempt to disrupt the logging pipeline.

### 1.1 Malformed Syslog Messages

| Attack Vector | Description | Affected Component |
|--------------|-------------|-------------------|
| **Oversized PRI** | PRI field with more than 3 digits or value exceeding 191. Parser must reject without allocating proportionally to the claimed size. | `syslog-parse` |
| **Invalid UTF-8 in HEADER fields** | Bytes outside the 7-bit ASCII range in HOSTNAME, APP-NAME, PROCID, or MSGID. RFC 5424 S6 requires HEADER fields to be 7-bit ASCII. | `syslog-parse` |
| **Invalid UTF-8 in MSG body** | MSG body prefixed with BOM but containing invalid UTF-8 sequences. RFC 5424 S6.4 requires valid UTF-8 after BOM. | `syslog-parse` |
| **Huge STRUCTURED-DATA** | A message with hundreds of SD-ELEMENTs, each containing hundreds of SD-PARAMs. Designed to consume CPU during parsing and memory during storage. | `syslog-parse`, `syslog-proto` |
| **Deeply nested SD-PARAM escape sequences** | PARAM-VALUE containing long chains of backslash-escaped characters (`\"`, `\\`, `\]`) or incomplete escape sequences at the end of input. | `syslog-parse` |
| **Oversized individual fields** | HOSTNAME exceeding 255 bytes, APP-NAME exceeding 48 bytes, PROCID exceeding 128 bytes, MSGID exceeding 32 bytes. | `syslog-parse` |
| **Truncated messages** | Messages that end mid-field (e.g., PRI without closing `>`, timestamp without timezone). | `syslog-parse` |
| **Empty messages** | Zero-length datagrams or TLS frames. | `syslog-transport` |
| **Binary payloads** | Arbitrary binary data with no resemblance to syslog format. | `syslog-parse` |
| **RFC 3164 ambiguity exploitation** | Messages crafted to exploit heuristic differences between RFC 5424 and RFC 3164 auto-detection, causing incorrect field extraction. | `syslog-parse` |
| **Timestamp boundary abuse** | Dates like `2024-02-30T25:61:61Z`, leap second values, timestamps at `i64` boundaries, year 0, year 9999+. | `syslog-parse` |
| **PRI value zero** | `<0>` is technically valid (facility 0, severity 0 = kernel emergency). Parser must handle this correctly, not as an error. | `syslog-parse` |

### 1.2 UDP Flood and Amplification Attacks

| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| **Single-source UDP flood** | An attacker sends datagrams at wire speed from one IP to port 514. The listener must process or drop each datagram. | CPU exhaustion in the recv loop; kernel buffer overflow causing drops for legitimate sources. |
| **Distributed UDP flood** | Many spoofed source IPs each send at moderate rates. Per-source rate limiting is ineffective because no single source exceeds its limit. | Aggregate throughput exceeds pipeline capacity; legitimate messages are dropped. |
| **Amplification via syslog-usg** | An attacker spoofs a victim's IP as the source and sends to syslog-usg. If syslog-usg generates any response to the source IP (it should not), this becomes an amplifier. | syslog-usg is receive-only on UDP and generates no responses, so direct amplification is not possible. Indirect amplification occurs if the pipeline forwards to a destination that does respond. |
| **Small-packet flood** | Minimum-size datagrams (< 10 bytes) designed to maximize packet rate while consuming recv loop CPU on validity checks. | CPU consumed by per-packet processing even though messages are immediately dropped. |

### 1.3 TLS Connection Storms

| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| **Handshake flood** | An attacker opens thousands of TCP connections to port 6514 and initiates TLS handshakes but never completes them, or completes them slowly. Each incomplete handshake consumes a connection slot and CPU for cryptographic operations. | Connection slot exhaustion (legitimate clients cannot connect); CPU saturation from RSA/EC operations during handshake. |
| **Slowloris on TLS** | Attacker completes TLS handshake but sends syslog frames extremely slowly (one byte per second). Each slow connection occupies a connection slot indefinitely. | Connection slot exhaustion with minimal bandwidth from attacker. |
| **Post-handshake data flood** | Attacker establishes many TLS connections and floods octet-counted frames at high speed. Each frame must be decrypted and parsed. | CPU exhaustion from TLS decryption; memory pressure from frame buffering. |
| **Renegotiation abuse** | Attacker triggers repeated TLS renegotiations to amplify CPU cost. Note: rustls does not support TLS 1.2 renegotiation, eliminating this vector structurally. | Not applicable with rustls. |
| **Client certificate bomb** | Attacker presents an extremely large or deeply chained client certificate during mutual TLS handshake. | CPU and memory consumed during certificate validation. rustls limits chain depth. |

### 1.4 Memory Exhaustion via Queue Filling

| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| **Sustained overload** | Legitimate or malicious traffic exceeds the pipeline's processing capacity. Per-output queues fill to capacity. | Queue overflow triggers backpressure policy. If policy is `block`, ingress stalls and other outputs may be affected. If policy is `drop`, messages are lost. |
| **Asymmetric output failure** | One output destination goes offline while others remain healthy. The offline output's queue fills while the pipeline continues processing for healthy outputs. | With `drop-newest` or `drop-oldest`: messages to the failed output are dropped; other outputs unaffected. With `block`: the pipeline dispatcher blocks on the failed output's queue, creating head-of-line blocking for ALL outputs. |
| **Large message amplification** | Attacker sends messages near `max_message_size` (e.g., 64 KiB) with structured data. The per-message memory footprint is proportional to message size. At default queue capacity (10,000 messages), the queue could consume 640 MiB. | Memory exhaustion; possible OOM kill. |
| **Arc reference leak** | A bug in the pipeline or output causes `Arc<SyslogMessage>` references to accumulate without being dropped. Messages are never freed. | Gradual memory growth leading to OOM. This is a correctness bug, not an attack vector, but has the same impact. |

### 1.5 CPU Exhaustion via Parser Complexity

| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| **Regex bomb in MSG matching** | If filter rules use regex matching on the MSG body (future feature), a crafted message body could trigger catastrophic backtracking in a naive regex engine. | CPU exhaustion; pipeline stall. A single message could block the filter stage for seconds or longer. |
| **Pathological structured data** | A message with the maximum allowed SD-ELEMENTs (128), each with the maximum allowed SD-PARAMs, each with maximum-length PARAM-VALUE containing many escape sequences. Parsing time is proportional to the product of these counts. | CPU time for a single message parse could exceed milliseconds, degrading throughput. |
| **Timestamp parsing with edge cases** | Timestamps with maximum fractional-second precision (nanosecond) and unusual timezone offsets. While not typically expensive, repeated parsing of malformed timestamps that require extensive validation could add up. | Minor CPU impact per message; significant under flood. |
| **Filter rule explosion** | A configuration with hundreds of filter rules, each evaluated per message. Routing evaluation becomes O(messages * rules). | CPU proportional to configuration complexity. Not an external attack but a configuration risk. |

### 1.6 Certificate Abuse

| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| **Expired certificates presented by clients** | Clients with expired certificates attempt to connect with mutual TLS. | Handshake failure; connection rejected. No pipeline impact. Risk: if expiry checking is disabled by misconfiguration, expired certificates would be accepted. |
| **Revoked certificates** | A client's certificate has been revoked but CRL/OCSP checking is not enabled (not in MVP). | Revoked certificate accepted. The attacker can submit messages as the revoked identity. |
| **Self-signed certificates without fingerprint pinning** | Without explicit fingerprint configuration, self-signed certificates are rejected by default. If an operator disables PKI validation without fingerprint pinning, any self-signed certificate would be accepted. | Unauthorized access. |
| **CA compromise** | The CA that signed client certificates is compromised. Any certificate signed by the compromised CA is accepted. | Complete authentication bypass for mutual TLS. Fingerprint pinning is the only defense. |
| **Certificate with wildcard abuse** | A client presents a certificate with a wildcard CN/SAN that matches unintended identities. | Identity confusion in per-client routing. |

### 1.7 Log Injection

| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| **Newline injection in MSG** | Attacker embeds newline characters (`\n`, `\r\n`) in the MSG body. If a downstream system processes output line-by-line (e.g., file output without octet-counting), the injected newlines create fake log entries. | Downstream log corruption; potential for masking real events or injecting false alerts. |
| **Control character injection** | Attacker embeds terminal control sequences (ANSI escape codes) in HOSTNAME, APP-NAME, or MSG. If logs are viewed in a terminal, these can alter display output or execute terminal-specific commands. | Visual confusion; potential terminal exploitation in rare cases. |
| **Structured data injection** | Attacker crafts a message where the MSG body contains text that looks like structured data brackets `[id key="value"]`. If a downstream parser re-parses the serialized output, it might interpret MSG content as structured data. | Semantic confusion in downstream systems. |
| **HOSTNAME spoofing** | Attacker sets HOSTNAME to the value of another legitimate host. On UDP (no authentication), the source IP is the only distinguishing factor, and it is spoofable. | Attribution confusion; SIEM correlates messages under the wrong host identity. |
| **Timestamp manipulation** | Attacker sets the syslog timestamp to a past or future time. Without message signing (RFC 5848), there is no way to verify timestamp authenticity. | Timeline corruption in forensic analysis; messages can be hidden in the past or appear to predate an incident. |
| **SD-ID collision with reserved IDs** | Attacker uses IANA-reserved SD-IDs (`timeQuality`, `origin`, `meta`) with fabricated values. Downstream systems that trust these fields may be misled. | False metadata injection; for example, setting `timeQuality isSynced="1"` to claim clock synchronization. |

### 1.8 Configuration Injection via Environment Variables

| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| **Env var override of TLS paths** | The config file uses `${SYSLOG_TLS_CERT}` for certificate paths. An attacker with local access to the environment (e.g., shared container, compromised CI) can set this variable to point to an attacker-controlled certificate. | Attacker's certificate is loaded as the server identity. All TLS connections are MITM-able. |
| **Env var override of bind address** | `${SYSLOG_BIND_ADDR}` is set to `0.0.0.0:0`, binding to a random port. Or set to a port that an attacker is already listening on. | Listener binds to unintended address; messages may be sent to attacker-controlled port. |
| **Env var override of output targets** | Output target address is set via environment variable. Attacker redirects log output to a server they control. | Log exfiltration; loss of log delivery to intended destination. |
| **Nested substitution abuse** | If the substitution engine processes `${VAR}` recursively, an attacker could craft `VAR=\${OTHER_SECRET}` to leak unrelated environment variables. The design document specifies no nested substitution, which mitigates this. | Information disclosure. Mitigated by design (no recursion). |
| **NULL byte injection in env vars** | An environment variable containing null bytes could truncate file paths or cause unexpected behavior in TOML parsing. | Undefined behavior in path resolution. |

### 1.9 Denial of Service via Config Reload Abuse

| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| **Rapid SIGHUP** | An attacker with local signal-sending capability (same user, or via `kill -HUP`) sends SIGHUP repeatedly. Each reload triggers config file read, parse, validate, and potentially listener restart. | CPU and I/O consumed by repeated reload cycles. Transient message loss during listener restart. |
| **Config file swap during reload** | Attacker modifies the config file to be invalid between SIGHUP signals, causing repeated validation failures. Each failure is logged at ERROR level. | Log volume amplification (operator's own logs fill disk). Minor CPU impact. |
| **Config file grows unbounded** | Config file is replaced with a multi-gigabyte file. The TOML parser attempts to load and parse it entirely into memory. | Memory exhaustion during config load. |
| **Symlink race on config file** | Config file path is a symlink. Attacker races to swap the symlink target between validation and application. | Validated config differs from applied config. Time-of-check-to-time-of-use (TOCTOU) vulnerability. |

### 1.10 Replay Attacks on UDP-Delivered Messages

| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| **Network-level replay** | Attacker captures UDP datagrams and replays them. Since UDP has no sequence numbers or authentication, replayed datagrams are indistinguishable from original messages. | Duplicate messages in the logging pipeline. Could mask real events or inflate event counts. |
| **Replay across time boundaries** | Attacker replays messages from days or weeks ago. The embedded syslog timestamp will be stale, but the pipeline processes messages based on receive time, not message time. | Stale messages injected into the current log stream. Detectable by timestamp mismatch but not automatically prevented. |
| **Replay to inflate rate limits** | Attacker replays messages from a legitimate source to exhaust that source's rate limit allowance, causing the legitimate source's real messages to be dropped. | Denial of service against a specific source identity. |

**Replay mitigation status:** UDP replay is inherent to the protocol and cannot be fully prevented without message signing (RFC 5848, future Phase 2). TLS connections are not vulnerable to replay because TLS provides its own replay protection at the record layer. DTLS (future) will include anti-replay via sequence number windows.

---

## 2. Security Recommendations

### 2.1 Input Size Limits

All limits apply at the earliest possible point in the processing pipeline (before parsing where possible).

| Control | Enforcement Point | Default | Hard Ceiling | Configurable |
|---------|-------------------|---------|-------------|-------------|
| Maximum UDP datagram size | `UdpListener::recv_from` buffer size | 8,192 bytes | 65,536 bytes | Yes |
| Maximum TLS frame size (MSG-LEN) | `OctetCountingDecoder` | 65,536 bytes | 1,048,576 bytes (1 MiB) | Yes |
| Maximum PRI value | Parser, before allocation | 191 | 191 (RFC) | No |
| Maximum PRI digit count | Parser | 3 digits | 3 digits (RFC) | No |
| Maximum HOSTNAME length | Parser | 255 bytes | 255 bytes (RFC 5424 S6.2.1) | No |
| Maximum APP-NAME length | Parser | 48 bytes | 48 bytes (RFC 5424 S6.2.5) | No |
| Maximum PROCID length | Parser | 128 bytes | 128 bytes (RFC 5424 S6.2.6) | No |
| Maximum MSGID length | Parser | 32 bytes | 32 bytes (RFC 5424 S6.2.7) | No |
| Maximum SD-ELEMENT count | Parser | 128 | 1,024 | Yes |
| Maximum SD-PARAM count per SD-ELEMENT | Parser | 64 | 256 | Yes |
| Maximum SD-ID length | Parser | 32 bytes | 32 bytes (RFC 5424 S6.3.2) | No |
| Maximum PARAM-NAME length | Parser | 32 bytes | 32 bytes (RFC 5424 S6.3.3) | No |
| Maximum PARAM-VALUE length | Parser | 16,384 bytes | 65,536 bytes | Yes |
| Maximum STRUCTURED-DATA total size | Parser | 32,768 bytes | 65,536 bytes | Yes |
| Maximum MSG body length | Parser | Remainder after STRUCTURED-DATA, bounded by frame size | Frame size limit | Indirect |
| Maximum config file size | Config loader | 1 MiB | 10 MiB | Yes |

**Implementation requirement:** All length checks MUST occur before allocation. The parser MUST NOT allocate a buffer proportional to a claimed length field without first validating that the claimed length is within bounds. Specifically:

- The octet-counting decoder MUST validate `MSG-LEN <= max_frame_size` before calling `src.reserve()`.
- The structured data parser MUST count SD-ELEMENTs and SD-PARAMs incrementally and reject the message when the count exceeds the configured limit.
- Field parsers MUST track byte position and stop scanning when the field-specific length limit is reached.

### 2.2 Parse Timeout and Complexity Budget

**Recommendation:** Implement a per-message complexity budget rather than a wall-clock timeout.

A wall-clock timeout is unreliable for parsing because:
- Parse operations are CPU-bound and complete in microseconds for valid messages.
- Tokio cooperative scheduling means a blocking parse would not yield to the timer.
- `tokio::time::timeout` wrapping a synchronous parse would require `spawn_blocking`, adding unacceptable overhead to the hot path.

Instead, use a **complexity counter** within the parser:

```
MAX_PARSE_OPERATIONS = 100,000
```

The parser increments a counter for each byte scanned, each field boundary checked, each escape sequence processed, and each SD-ELEMENT/SD-PARAM entered. If the counter exceeds `MAX_PARSE_OPERATIONS`, parsing is aborted with `ParseError::ComplexityExceeded`.

This approach is:
- Deterministic (same input always produces the same result).
- Zero-overhead when not triggered (branch prediction handles the check efficiently).
- Portable (no dependency on timing or scheduler behavior).

For filter rules that use regex matching (future feature), the regex engine MUST enforce a match complexity limit. Use the `regex` crate, which guarantees O(n) matching time by construction (no catastrophic backtracking). Never use `regex::Regex` with features that allow unbounded backtracking. Do not use PCRE-style regex.

### 2.3 Per-Source Rate Limiting (Token Bucket)

**Design:**

```
Algorithm: Token Bucket
Default rate: 10,000 messages/second per source IP
Default burst: 1,000 messages
Tracked sources: bounded by max_tracked_sources (default: 100,000)
Eviction: LRU when max_tracked_sources is reached
Storage: DashMap<IpAddr, TokenBucket>
Cleanup: background sweep every 60 seconds removes entries idle > 5 minutes
```

**Scope of application:**

| Transport | Rate-limited? | Key | Notes |
|-----------|--------------|-----|-------|
| UDP listener | Yes, MUST be enabled by default | Source IP from `recv_from` | Primary defense against UDP floods |
| TLS listener (connection rate) | Yes | Source IP from `accept` | Prevents handshake floods |
| TLS listener (message rate) | Optional | Source IP or client certificate CN | Per-connection backpressure provides natural limiting |

**Rate limit bypass list:** A configurable allowlist of source IPs or CIDR ranges that are exempt from rate limiting. This is necessary for high-volume legitimate sources (e.g., aggregation relays that forward from many origins).

**Metric exposure:**

```
syslog_rate_limited_total{listener, reason="per_source|global"}
syslog_rate_limit_tracked_sources{listener}
syslog_rate_limit_evictions_total{listener}
```

**Global rate limit:** An optional aggregate rate limit across all sources per listener. This provides a ceiling even when the per-source limit is not triggered (distributed flood). Default: disabled (set to `0` meaning unlimited). When enabled, excess messages are dropped and counted.

### 2.4 Connection Limits

| Limit | Default | Configurable | Enforcement Point |
|-------|---------|-------------|-------------------|
| Global max TLS connections per listener | 10,000 | Yes | `tls_accept_loop` before `accept` |
| Max connections per source IP | 100 | Yes | `tls_accept_loop` after `accept`, before handshake |
| Max new connections per source IP per second | 100 | Yes | Token bucket in `tls_accept_loop` |
| TLS handshake timeout | 10 seconds | Yes | `tokio::time::timeout` wrapping `acceptor.accept()` |
| Per-connection idle timeout | 300 seconds | Yes | Read timeout in `handle_tls_connection` |
| Per-connection read timeout (no data) | 60 seconds | Yes | Applied between frames |
| TCP accept backlog | 1,024 | OS-level | `TcpListener::bind` |

**Per-source connection tracking** uses a `DashMap<IpAddr, AtomicUsize>` incremented on accept and decremented on connection close (via `ConnectionGuard` RAII). The map is bounded by the same `max_tracked_sources` as rate limiting.

**Connection slot exhaustion response:** When `max_connections` is reached, the listener MUST:
1. Continue calling `accept()` to drain the TCP backlog.
2. Immediately close accepted connections with TCP RST (drop the `TcpStream` without TLS handshake).
3. Increment `syslog_tls_connections_rejected_total{reason="limit"}`.
4. NOT stop calling `accept()`, as that would cause the backlog to fill and the kernel to RST connections silently without metrics.

### 2.5 TLS Handshake Timeout

The 10-second handshake timeout (already specified in Phase 05 Section 3.5) is appropriate. Additional recommendations:

- **Handshake resource accounting:** Each in-progress handshake consumes CPU for key exchange. Track `syslog_tls_handshakes_in_progress{listener}` as a gauge. If this gauge exceeds a threshold (e.g., 500 concurrent handshakes), reject new connections at the TCP level until handshakes drain.
- **Handshake CPU isolation (future):** Consider running TLS handshakes on a dedicated thread pool (`spawn_blocking`) to prevent handshake CPU load from starving the data-plane tasks. This is a performance trade-off: spawn_blocking adds latency but isolates CPU impact.

### 2.6 Queue Byte-Size Caps

The current `QueueConfig` specifies `capacity` as a message count. This is insufficient because message sizes vary widely (a 50-byte message and a 64 KiB message consume the same queue slot but vastly different memory).

**Recommendation:** Add a `max_bytes` field to `QueueConfig`:

```
[outputs.central_tls.queue]
capacity = 10000           # Maximum message count
max_bytes = 67108864       # Maximum total bytes (64 MiB)
overflow_policy = "drop_oldest"
```

**Implementation:** The queue tracks cumulative byte size of enqueued messages using an `AtomicUsize` incremented by `msg.raw.len() + OVERHEAD` on enqueue and decremented on dequeue. The enqueue operation checks both message count and byte size before accepting a message. The `OVERHEAD` constant accounts for the `SyslogMessage` struct size and `Arc` header (approximately 400 bytes per message based on Phase 03 Section 8.3 analysis).

**Defaults:**

| Queue parameter | Default | Rationale |
|----------------|---------|-----------|
| `capacity` | 10,000 messages | Sufficient for brief output outages at 100k msg/sec |
| `max_bytes` | 64 MiB | 10,000 messages at average 6 KiB = 60 MiB. Provides headroom. |
| `overflow_policy` | `drop_newest` | Safest default; preserves older messages which are more likely to contain the beginning of an incident. |

**Metric exposure:**

```
syslog_queue_bytes{output}          # Gauge: current byte usage
syslog_queue_bytes_max{output}      # Gauge: configured max_bytes
```

### 2.7 Privilege Dropping After Port Binding

Phase 05 Section 10.5 specifies the privilege drop sequence. Additional requirements:

- **MUST drop privileges before starting the async runtime.** The privilege drop (`setuid`/`setgid`) MUST occur in `main()` before `#[tokio::main]` or equivalent runtime initialization. This ensures that no Tokio worker thread ever runs as root.
- **MUST fail closed.** If privilege dropping is configured (user/group specified) but fails, the process MUST exit with a non-zero status code and a clear error message. It MUST NOT fall back to running as root.
- **Supplementary group clearing.** `setgroups([])` MUST be called before `setgid` to ensure no inherited supplementary group memberships remain.
- **Verification.** After privilege drop, call `getuid()` and `getgid()` and log the effective credentials at INFO level. If `getuid() == 0`, exit immediately.
- **Linux capabilities (future).** On Linux, consider using `prctl(PR_SET_NO_NEW_PRIVS, 1)` after privilege drop to prevent any future privilege escalation, and retaining only `CAP_NET_BIND_SERVICE` if rebinding is needed on reload. This can be implemented via the `caps` crate.

### 2.8 Config File Permission Checks

At startup and on reload, the config loader MUST check:

| Check | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Config file world-readable | `mode & 0o004 != 0` | WARNING | Log warning; continue |
| Config file world-writable | `mode & 0o002 != 0` | ERROR | Refuse to load; exit |
| TLS private key world-readable | `mode & 0o077 != 0` | WARNING | Log warning; continue (already in Phase 05) |
| TLS private key world-writable | `mode & 0o002 != 0` | ERROR | Refuse to load; exit |
| Config file is a symlink | `fs::symlink_metadata` shows symlink | WARNING | Log warning with resolved target path; continue |
| Config file owned by root but process not root | `file.uid == 0 && getuid() != 0` | INFO | Normal for system services; informational only |

**Recommendation for TOCTOU mitigation:** Read the config file into memory in a single `fs::read()` call, then parse the in-memory buffer. Do not re-read the file between validation and application. This eliminates the symlink-race vulnerability described in Section 1.9.

**Config file size limit:** Reject config files larger than 1 MiB (configurable via `--max-config-size` CLI flag, hard ceiling 10 MiB). This prevents memory exhaustion from a maliciously large config file during reload.

### 2.9 Admin API Authentication

The admin HTTP server (metrics, health, readiness, liveness endpoints) is currently bound to `127.0.0.1:9090` by default. This is a good secure default, but additional controls are needed for deployments where the admin API must be accessible remotely.

**Requirements:**

| Control | Status | Description |
|---------|--------|-------------|
| Bind to loopback only by default | MUST (already designed) | `127.0.0.1:9090` prevents remote access by default |
| Startup warning if bound to non-loopback | MUST | Emit WARNING if admin API bind address is not `127.0.0.1` or `::1` |
| Optional bearer token authentication | SHOULD | If enabled, all admin endpoints require `Authorization: Bearer <token>` header |
| TLS for admin API | SHOULD (future) | Optional TLS configuration for the admin HTTP server |
| Read-only endpoints only | MUST | No state-changing operations via the admin API in MVP. Config reload MUST remain signal-based only. |
| No secret exposure | MUST | `/metrics` and `/health` endpoints MUST NOT include TLS private key material, certificate content, config file paths containing secrets, or environment variable values |

**Bearer token configuration:**

```toml
[metrics]
enabled = true
bind = "127.0.0.1:9090"
# auth_token = "${SYSLOG_METRICS_TOKEN}"  # Optional; if set, all requests require this token
```

When `auth_token` is configured, the admin HTTP server MUST return `401 Unauthorized` for requests without a valid `Authorization: Bearer <token>` header.

### 2.10 Structured Data Sanitization for Output

When serializing `SyslogMessage` to output formats, the serializer MUST prevent injection attacks on downstream consumers.

**RFC 5424 output (octet-counting framing):**

Octet-counting framing inherently prevents message injection because the receiver reads exactly `MSG-LEN` bytes. No additional sanitization is needed for the framing layer. However, the serializer MUST:

- Correctly escape `"`, `\`, and `]` in PARAM-VALUE when re-serializing (RFC 5424 S6.3.3).
- Preserve the BOM prefix in MSG body if the original message had one.
- Not introduce additional newlines or control characters during serialization.

**JSON output:**

The JSON serializer MUST:

- Escape all special JSON characters in string values (RFC 8259): `"`, `\`, and control characters U+0000 through U+001F.
- Use `\uXXXX` encoding for control characters, not raw bytes.
- Not include raw binary data in JSON string fields. Non-UTF-8 MSG bodies should be base64-encoded with an explicit encoding indicator field.
- Validate that no JSON injection is possible by using a proper JSON serializer (`serde_json`), never string concatenation.

**File output (line-delimited):**

If output format writes one message per line without octet-counting:

- Newlines (`\n`, `\r`) within the MSG body MUST be escaped as `\\n`, `\\r` or replaced with a space.
- This is a lossy transformation and MUST be documented.
- Alternatively, use octet-counting framing even for file output, which is the recommended approach.

---

## 3. Robustness Requirements

These are hard requirements that must be verified before production deployment. Each requirement includes its verification method.

### 3.1 Parser MUST NOT Panic on Any Input

**Requirement:** For any sequence of bytes `input: &[u8]` where `input.len() <= MAX_MESSAGE_SIZE`, calling the RFC 5424 parser, RFC 3164 parser, or format auto-detector MUST return `Ok(ParsedMessage)` or `Err(ParseError)`. It MUST NOT panic, abort, or invoke undefined behavior.

**Verification:**
- Fuzz testing with `cargo-fuzz` / `libFuzzer` for a minimum of 10 billion iterations (or 72 hours of continuous fuzzing, whichever is longer) with no panics.
- Property-based testing with `proptest` generating arbitrary byte sequences.
- `#[cfg(test)]` tests for every `ParseError` variant demonstrating the input that triggers it.
- CI enforcement: fuzz corpus is checked in and regression-tested on every commit.

**Implementation guidance:**
- No `unwrap()` or `expect()` in parser code paths.
- No `slice[index]` indexing; use `slice.get(index)` or iterator-based scanning.
- No `from_utf8` without a preceding `from_utf8_lossy` or explicit error handling.
- Integer arithmetic (PRI decoding, length calculations) MUST use `checked_add`/`checked_mul`.

### 3.2 Parser MUST Complete in Bounded Time for Any Input

**Requirement:** For any input of length `N` bytes, the parser MUST complete in `O(N)` time. There MUST be no super-linear behavior (no backtracking, no exponential branching).

**Verification:**
- Benchmark with `criterion` at input sizes 100, 1K, 10K, 64K bytes. Verify that parse time scales linearly with input size.
- Complexity counter (Section 2.2) enforced at `100,000` operations. Any input reaching this limit is rejected.
- Code review: verify that no parser loop can iterate more than `N` times for an `N`-byte input.
- No regex in the parser hot path. The `regex` crate (used in filters, future) guarantees `O(N)` but is still too slow for per-message field parsing.

### 3.3 Queue Overflow MUST Be Handled Per Policy

**Requirement:** When a per-output queue reaches its capacity (message count or byte size), the configured overflow policy MUST be applied. The system MUST NOT:
- Panic or crash.
- Silently drop messages without incrementing `syslog_messages_dropped_total`.
- Block indefinitely (even with `block` policy, a shutdown signal must break the block).
- Allocate beyond queue capacity.

**Verification:**
- Integration test: fill a queue to capacity and verify that the next enqueue triggers the configured policy.
- Test each policy (`drop_newest`, `drop_oldest`, `block`) under sustained overload.
- Verify that `syslog_messages_dropped_total{reason="queue_full", output="..."}` increments exactly once per dropped message.
- Verify that `block` policy responds to the cancellation token within 100 milliseconds.

### 3.4 TLS Errors MUST NOT Leak to Other Connections

**Requirement:** An error on one TLS connection (handshake failure, framing error, read error, decryption failure) MUST NOT affect any other TLS connection. The per-connection task MUST handle all errors locally and terminate only its own connection.

**Verification:**
- Integration test: establish 10 healthy TLS connections, then force an error on connection 5 (send malformed data). Verify that connections 1-4 and 6-10 continue processing messages without interruption.
- Verify that the `TlsAcceptor` and `ServerConfig` are shared via `Arc` and that no mutable state is shared between connection tasks.
- Verify that a panicking connection task is caught by the Tokio runtime and does not propagate.

**Implementation guidance:**
- Each connection task operates on its own `TlsStream` instance. The only shared state is:
  - `Arc<ServerConfig>` (immutable after construction).
  - `mpsc::Sender<RawMessage>` (cloned per connection; thread-safe by design).
  - `Arc<TlsMetrics>` (atomic counters only).
  - `Arc<ConnectionLimits>` (atomic counters only).
  - `CancellationToken` (thread-safe by design).
- No `Mutex`, `RwLock`, or other shared mutable state between connection tasks on the data path.

### 3.5 One Misbehaving Output MUST NOT Block Other Outputs

**Requirement:** If one output destination is unreachable, slow, or erroring, messages to other outputs MUST continue flowing without delay or loss (beyond normal queue policy).

**Verification:**
- Integration test: configure two outputs (A and B). Stop output A's destination. Send 1,000 messages that route to both A and B. Verify that all 1,000 messages are delivered to B within the expected time. Verify that output A's queue fills and the overflow policy applies only to A's queue.
- **Critical configuration warning:** The `block` overflow policy on ANY output can violate this requirement because the pipeline dispatcher blocks on the full queue, stalling dispatch to all other outputs. The configuration validator MUST emit a WARNING when `block` policy is used, explaining this coupling risk.

**Implementation guidance:**
- The pipeline dispatcher MUST use `try_send` (non-blocking) for output queues with `drop_newest` or `drop_oldest` policy.
- For `block` policy, the dispatcher uses `send().await` but with a timeout. If the timeout expires, the message is dropped (with metric) rather than blocking indefinitely.
- Consider: each output queue's send uses `tokio::select!` with the cancellation token to prevent shutdown deadlock.

### 3.6 Config Reload Failure MUST Preserve Working Config

**Requirement:** If a SIGHUP-triggered config reload fails at any stage (file read, TOML parse, schema validation, TLS certificate load, listener bind), the currently running configuration MUST remain entirely unchanged. No partial application.

**Verification:**
- Integration test: start with valid config. Replace config file with invalid TOML. Send SIGHUP. Verify:
  - Error logged at ERROR level with specific validation failure.
  - All existing listeners continue accepting messages.
  - All existing outputs continue forwarding.
  - All existing filter/route rules remain active.
  - Metrics endpoint continues responding.
- Test with each category of config error: syntax error, missing required field, invalid TLS cert path, invalid bind address, duplicate names.

**Implementation guidance:**
- Load new config into a completely separate `ServerConfig` struct.
- Validate new config fully (including TLS cert loading and address resolution).
- Only after full validation succeeds, atomically swap the config reference (e.g., `ArcSwap` or `Arc` swap).
- New listeners are started BEFORE old listeners are stopped. If new listener bind fails, abort the reload.
- Old listeners are stopped only after new listeners are confirmed listening.

### 3.7 Signal Handling MUST Be Safe

**Requirement:** Signal handlers MUST NOT perform async-signal-unsafe operations. The signal handler MUST only set a flag or write to a pipe/channel; all actual work (config reload, shutdown sequence) MUST happen in a normal async task.

**Verification:**
- Code review: verify that the signal handler task uses `tokio::signal::unix::signal()` which internally uses `signal_hook_registry` to set a flag and wake a future. No direct `libc::signal()` or `sigaction()` calls that install user-defined signal handlers with complex logic.
- Verify that no allocations, I/O, lock acquisitions, or logging occur inside the signal disposition. All such operations occur in the async task that is woken by the signal.

**Implementation guidance:**
- Use `tokio::signal::unix::SignalKind::hangup()` for SIGHUP and `tokio::signal::ctrl_c()` for SIGINT/SIGTERM.
- The signal task sends a `ReloadCommand` or `ShutdownCommand` via a `tokio::sync::mpsc` channel to the lifecycle manager.
- Never use `std::process::exit()` in the signal handler. Always go through the graceful shutdown path.

---

## 4. Fuzzing Targets

### 4.1 RFC 5424 Parser

**Target function:** `syslog_parse::rfc5424::parse(input: &[u8]) -> Result<ParsedMessage, ParseError>`

**Input generation strategy:**
- Corpus seeds: valid RFC 5424 messages from the conformance test suite, one per file.
- Mutation: `libFuzzer` default mutations (byte flips, insertions, deletions, crossover).
- Dictionary: `< > [ ] " \ - . : T Z + 0 1 2 3 4 5 6 7 8 9 SP BOM` (common syslog tokens).

**Expected invariants:**
- Never panics.
- Returns `Ok` or `Err` for every input.
- If `Ok`, the `ParsedMessage` has valid `Facility` (0-23) and `Severity` (0-7).
- If `Ok`, all string fields are valid UTF-8 where RFC requires it.
- If `Ok`, re-serializing the message and re-parsing produces the same `ParsedMessage` (round-trip property, tested separately).
- Memory allocated is bounded by `O(input.len())`.
- Execution time is bounded by `O(input.len())`.

**Fuzz harness:**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Reject inputs larger than max message size to match production behavior.
    if data.len() > 65536 {
        return;
    }
    let _ = syslog_parse::rfc5424::parse(data);
});
```

### 4.2 RFC 3164 Parser

**Target function:** `syslog_parse::rfc3164::parse(input: &[u8]) -> Result<ParsedMessage, ParseError>`

**Input generation strategy:**
- Corpus seeds: BSD syslog messages from real-world captures (Cisco, Linux, macOS formats).
- Mutation: standard `libFuzzer` mutations.
- Dictionary: `< > : / Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec SP`.

**Expected invariants:**
- Never panics.
- Returns `Ok` or `Err` for every input.
- If `Ok`, facility and severity are within valid ranges.
- Best-effort parser: `Ok` is expected for a wider range of inputs than RFC 5424. The invariant is that it never panics, not that it always produces correct field extraction.

### 4.3 Octet-Counting Frame Decoder

**Target function:** `syslog_transport::tls::framing::OctetCountingDecoder::decode(&mut self, src: &mut BytesMut) -> Result<Option<Bytes>, FrameError>`

**Input generation strategy:**
- Corpus seeds: correctly framed messages (`"123 " + 123 bytes of data`).
- Mutation: corrupt length digits, inject non-digit bytes, truncate mid-frame.
- Structured fuzzing: generate `(length: u32, body: &[u8])` pairs where length may or may not match body length.

**Expected invariants:**
- Never panics.
- Returns `Ok(None)` (need more data), `Ok(Some(frame))` (complete frame), or `Err(FrameError)`.
- If `Ok(Some(frame))`, `frame.len()` equals the declared `MSG-LEN`.
- No allocation larger than `max_frame_size`.
- Cumulative bytes consumed from `src` across multiple `decode()` calls equals the total bytes provided.
- After an `Err`, the decoder state is unrecoverable (no further `Ok` results without reset).

**Fuzz harness:**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use bytes::BytesMut;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut decoder = OctetCountingDecoder::new(65536);
    let mut buf = BytesMut::from(data);
    // Call decode repeatedly until exhausted or error.
    loop {
        match decoder.decode(&mut buf) {
            Ok(Some(_frame)) => continue,
            Ok(None) => break,
            Err(_) => break,
        }
    }
});
```

### 4.4 PRI Parser

**Target function:** `syslog_parse::pri::parse_pri(input: &[u8]) -> Result<(Facility, Severity, usize), ParseError>`

**Input generation strategy:**
- Boundary values: `<0>`, `<1>`, `<7>`, `<8>`, `<191>`, `<192>`, `<999>`, `<>`, `<-1>`, `<00>`, `<01>`.
- Structure-aware: `<` + 0-10 bytes + `>` + trailing data.
- Negative tests: missing `<`, missing `>`, non-digit content, empty string.

**Expected invariants:**
- Never panics.
- If `Ok`, facility is 0-23 and severity is 0-7.
- If `Ok`, `facility * 8 + severity` equals the parsed PRI value.
- PRI value > 191 returns `Err`.
- Leading zeros (except `<0>`) return `Err` in strict mode.

### 4.5 Timestamp Parser

**Target function:** `syslog_parse::timestamp::parse_timestamp(input: &[u8]) -> Result<(SyslogTimestamp, usize), ParseError>`

**Input generation strategy:**
- Valid timestamps: `2024-01-15T12:30:45.123456Z`, `2024-01-15T12:30:45+05:30`, NILVALUE `-`.
- Boundary dates: month 0, month 13, day 0, day 32, hour 24, minute 60, second 60.
- Fractional seconds: 0 digits, 1 digit, 9 digits, 20 digits.
- Timezone: `+00:00`, `-00:00`, `+23:59`, `-23:59`, `+24:00`, `Z`, missing timezone.
- Calendar edge cases: Feb 29 on leap year, Feb 29 on non-leap year, Dec 31, Jan 1.
- Extreme years: 0000, 9999, 10000 (5-digit year).

**Expected invariants:**
- Never panics.
- If `Ok`, the timestamp represents a valid date/time.
- Leap seconds (`:60`) return `Err` (RFC 5424 S6.2.3 MUST NOT use leap seconds).
- NILVALUE (`-`) returns `Ok` with `None` timestamp.

### 4.6 Structured Data Parser

**Target function:** `syslog_parse::structured_data::parse_sd(input: &[u8]) -> Result<(Vec<SdElement>, usize), ParseError>`

**Input generation strategy:**
- Valid SD: `[id1 key1="val1"][id2 key2="val2"]`, NILVALUE `-`.
- Escape sequences: `\"`, `\\`, `\]` in PARAM-VALUE. Incomplete escapes: `\` at end of input.
- Nesting depth: 128+ SD-ELEMENTs, each with 64+ SD-PARAMs.
- SD-ID formats: registered names, `name@12345` enterprise format.
- Edge cases: empty SD-ELEMENT `[]`, SD-ELEMENT with no params `[id]`, empty PARAM-VALUE `key=""`.
- Invalid: unmatched brackets, param without element, element without closing bracket.

**Expected invariants:**
- Never panics.
- If `Ok`, each SD-ELEMENT has a non-empty SD-ID.
- If `Ok`, PARAM-VALUE strings have escape sequences correctly unescaped.
- SD-ELEMENT count does not exceed configured maximum (checked during parsing, not after).
- Memory allocated for structured data is bounded by input size.

### 4.7 Config File Parser

**Target function:** `syslog_config::load(input: &[u8]) -> Result<ServerConfig, ConfigError>`

**Input generation strategy:**
- Valid TOML configs from the reference configuration.
- Malformed TOML: unclosed strings, invalid keys, type mismatches.
- Valid TOML but invalid config: missing required fields, unknown sections, out-of-range values.
- Environment variable substitution: `${UNSET_VAR}`, `${VAR:-}`, deeply nested `${${VAR}}`.
- Size boundary: empty file, 1-byte file, 1 MiB file.

**Expected invariants:**
- Never panics.
- Returns `Ok` or `Err`.
- If `Ok`, all referenced output names exist, all referenced filter names exist.
- Environment variable substitution does not recurse.
- File size exceeding 1 MiB returns `Err`.

### 4.8 TLS Certificate Loading

**Target function:** `syslog_transport::tls::cert::load_certificate_chain(input: &[u8]) -> Result<Vec<CertificateDer>, TlsConfigError>`

**Input generation strategy:**
- Valid PEM certificate files (single cert, chain of 2-3 certs).
- Malformed PEM: truncated base64, missing header/footer lines, binary DER data.
- Empty file, very large file (1 MiB of repeated PEM blocks).
- Files with mixed PEM and non-PEM content.
- Valid PEM headers but garbage base64 content.

**Expected invariants:**
- Never panics.
- Returns `Ok` with at least one certificate, or `Err`.
- Does not allocate more than `O(input.len())` memory.
- Handles both PEM and DER formats without crashing.

### 4.9 Fuzzing Infrastructure Requirements

| Requirement | Target |
|-------------|--------|
| CI integration | Fuzz targets compiled and run for 10 minutes per target on every PR |
| Continuous fuzzing | OSS-Fuzz or ClusterFuzz integration for sustained fuzzing |
| Corpus management | Fuzz corpus checked into `fuzz/corpus/<target>/` and grown over time |
| Crash triage | Any fuzz crash blocks the release pipeline |
| Coverage tracking | Fuzz coverage reported alongside unit test coverage |
| Regression tests | Every crash-inducing input is added as a unit test |

---

## 5. Must-Fix Issues

These are critical security requirements that MUST be resolved before any production deployment. Each item is a blocking gate for release.

### 5.1 No Unbounded Allocations on Network Input

**Severity:** CRITICAL

**Requirement:** No code path reachable from network input (UDP datagram or TLS frame content) may allocate memory proportional to an attacker-controlled value without first validating that value against a configured maximum.

**Specific areas to audit:**

| Area | Risk | Mitigation |
|------|------|------------|
| `OctetCountingDecoder::decode` — `src.reserve(expected_len)` | Attacker sends `MSG-LEN = 999999999`. Decoder calls `reserve(999999999)`. | Already mitigated: `max_frame_size` check occurs before `reserve()`. Verify in code review. |
| `Vec::with_capacity` for SD-ELEMENTs | Parser pre-allocates `Vec::with_capacity(sd_element_count)` based on a count parsed from input. | Use `SmallVec` with fixed inline capacity. Do not pre-allocate based on untrusted count. Grow incrementally and check against `max_sd_elements` on each push. |
| String allocation for PARAM-VALUE | Parser allocates a `String` for each PARAM-VALUE, sized by the value length in the input. | Enforce `max_param_value_length` before allocation. |
| `Bytes::copy_from_slice` in UDP recv | Copies `len` bytes from recv buffer. `len` is bounded by `max_message_size` (the recv buffer size). | Already bounded. Verify buffer size matches configured maximum. |
| `BytesMut` growth in `FramedRead` | `tokio_util::codec::FramedRead` uses an internal `BytesMut` that grows to accommodate the current frame. | Bounded by `max_frame_size` in the decoder. Verify the decoder returns `Err` before `BytesMut` grows beyond `max_frame_size`. |

**Verification:** Static analysis tool (e.g., `cargo clippy` with custom lint, or manual code review) to identify every `Vec::with_capacity`, `Vec::new()` followed by `push` in a loop without a cap, `String::with_capacity`, `BytesMut::reserve`, and `Bytes::copy_from_slice` on paths reachable from network input.

### 5.2 No Panic Paths Reachable from Network Input

**Severity:** CRITICAL

**Requirement:** No `panic!()`, `unwrap()`, `expect()`, array index out of bounds, or integer overflow can be triggered by any network input.

**Specific areas to audit:**

| Pattern | Risk | Rule |
|---------|------|------|
| `slice[index]` | Out-of-bounds panic | Use `slice.get(index)` in all parser code |
| `unwrap()` on `Result` from parse operations | Parse error causes panic | Use `?` operator or explicit match |
| `expect()` with network-derived context | Parse error causes panic | Forbidden in parser code |
| Integer arithmetic in PRI decode | `facility * 8 + severity` overflow for `u8` | Use `checked_mul`/`checked_add` or validate range first |
| `from_utf8().unwrap()` | Invalid UTF-8 causes panic | Use `from_utf8()` with `?` |
| `str::parse::<usize>().unwrap()` for MSG-LEN | Non-numeric MSG-LEN causes panic | Already handled by digit-by-digit parsing in `OctetCountingDecoder` |

**Verification:**
- `#[deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]` in `syslog-parse` and `syslog-transport` crate roots.
- Fuzz testing (Section 4) with panic detection.
- `cargo test` with `RUST_BACKTRACE=1` and `#[should_panic]` tests ONLY for tests that explicitly verify error handling.

### 5.3 TLS Minimum Version Enforced

**Severity:** CRITICAL

**Requirement:** The system MUST NOT negotiate TLS versions below 1.2. SSLv3, TLS 1.0, and TLS 1.1 MUST be rejected.

**Current status:** Mitigated by design. rustls does not implement TLS versions below 1.2. The `ServerConfig::builder_with_protocol_versions` call in Phase 05 Section 3.2 specifies only TLS 1.2 and TLS 1.3.

**Verification:**
- Integration test: attempt a TLS 1.1 connection to the listener using `openssl s_client -tls1_1`. Verify connection is refused.
- Integration test: attempt a TLS 1.0 connection. Verify connection is refused.
- Verify that `rustls::version::TLS12` and `rustls::version::TLS13` are the ONLY versions passed to `builder_with_protocol_versions`.
- Verify that no configuration option can add TLS 1.0 or 1.1 to the version list. The config deserializer for `versions` MUST reject values other than `"1.2"` and `"1.3"`.

### 5.4 Admin API Not Exposed on Public Interface by Default

**Severity:** CRITICAL

**Requirement:** The admin HTTP server (metrics, health endpoints) MUST bind to `127.0.0.1` by default. Binding to `0.0.0.0` or a non-loopback address MUST require explicit configuration and emit a startup WARNING.

**Current status:** Default bind is `127.0.0.1:9090` per Phase 04 Section 5.1. Verify implementation matches.

**Verification:**
- Check `default_metrics_bind()` function returns `127.0.0.1:9090`.
- Integration test: with default config, attempt to connect to `<external_ip>:9090`. Verify connection refused.
- Integration test: configure `bind = "0.0.0.0:9090"`. Verify startup WARNING is logged.

**Risk if violated:** The `/metrics` endpoint exposes queue depths, message rates, source IP patterns, TLS certificate expiry dates, error rates, and other operational data that aids attacker reconnaissance. The `/health` endpoint reveals whether the service is running.

### 5.5 Secrets Not Logged at Any Level

**Severity:** CRITICAL

**Requirement:** The following MUST never appear in log output, metrics labels, health endpoint responses, or error messages at any log level (including TRACE and DEBUG):

| Secret | Examples |
|--------|----------|
| TLS private key content | PEM-encoded key bytes, DER key bytes |
| TLS private key passphrase | `SYSLOG_TLS_KEY_PASSPHRASE` environment variable value |
| Certificate private key material | RSA `d`, `p`, `q` values; EC private scalar |
| Admin API bearer token | `SYSLOG_METRICS_TOKEN` value |
| Environment variable values containing secrets | Any `${VAR}` substitution result where `VAR` might contain a secret |

**What MAY be logged:**
- File paths to certificates and keys (these are not secrets).
- Certificate subjects, SANs, fingerprints, expiry dates.
- Cipher suite names, TLS version numbers.
- Source IP addresses (not secrets, but may be PII -- documented as operator responsibility).

**Verification:**
- Code review: search for `tracing::` calls in `syslog-transport` and `syslog-config` that format TLS-related fields. Verify no key material is included.
- Search for `Debug` or `Display` implementations on types containing key material. Verify they redact sensitive fields.
- Integration test: enable TRACE-level logging. Load TLS configuration. Grep log output for PEM markers (`-----BEGIN`, `-----END`, `PRIVATE KEY`). Verify zero matches.

### 5.6 PID File Created with Restrictive Permissions

**Severity:** HIGH

**Requirement:** If a PID file is configured, it MUST be created with mode `0644` (owner read/write, group/other read-only). The PID file MUST contain only the decimal PID followed by a newline. No other data.

**Risk if violated:** A world-writable PID file allows an attacker to overwrite it with an arbitrary PID. Process management tools (systemd, monit) that use the PID file might then send signals to the wrong process.

**Implementation requirements:**
- Create the PID file using `OpenOptions::new().write(true).create(true).truncate(true)` with explicit mode `0644` via `std::os::unix::fs::OpenOptionsExt::mode()`.
- Write PID atomically: write to a temporary file in the same directory, then `rename()` to the target path.
- Remove the PID file on graceful shutdown.
- If the PID file already exists and contains a PID of a running process, refuse to start (stale PID file detection).

### 5.7 Rate Limiting Enabled by Default for UDP Listeners

**Severity:** HIGH

**Requirement:** Per-source rate limiting MUST be enabled by default for all UDP listeners. The default configuration MUST include rate limiting parameters. An operator may explicitly disable rate limiting by setting `rate_limit.enabled = false`, but this MUST emit a startup WARNING.

**Rationale:** UDP is the most common syslog transport and the most vulnerable to flooding. A default-off rate limiter leaves the system exposed to trivial denial-of-service attacks. Government and enterprise environments (the target deployment) require defense-in-depth.

**Default values:**

```toml
[listeners.udp_514.rate_limit]
enabled = true
messages_per_second = 10000
burst = 1000
max_tracked_sources = 100000
```

**Verification:**
- Integration test: configure a UDP listener with no rate_limit section. Verify that rate limiting is active with default parameters.
- Integration test: send 50,000 messages from a single source in 1 second. Verify that approximately 11,000 (burst + 1 second of sustained rate) are accepted and the rest are dropped with metric increment.

---

## 6. Hardening Checklist

This section provides deployment-time security hardening recommendations. These are not code changes but operational practices.

### 6.1 Run as Non-Root User

**Priority:** REQUIRED

After binding privileged ports (514, 6514), drop to an unprivileged user. Create a dedicated service account:

```bash
# Create service user (no shell, no home directory)
useradd --system --no-create-home --shell /usr/sbin/nologin syslog-usg
groupadd syslog-usg

# Set file ownership
chown syslog-usg:syslog-usg /etc/syslog-usg/syslog-usg.toml
chown syslog-usg:syslog-usg /etc/syslog-usg/tls/
chmod 600 /etc/syslog-usg/tls/server.key
chmod 644 /etc/syslog-usg/tls/server.crt

# Configure in syslog-usg.toml
# [server]
# user = "syslog-usg"
# group = "syslog-usg"
```

Alternative on Linux: use `setcap` to grant port binding capability without running as root at all:

```bash
setcap 'cap_net_bind_service=+ep' /usr/local/bin/syslog-usg
```

### 6.2 systemd Security Directives

**Priority:** REQUIRED (Linux deployments)

```ini
[Unit]
Description=syslog-usg Syslog Server/Relay
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/syslog-usg --config /etc/syslog-usg/syslog-usg.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# User/Group
User=syslog-usg
Group=syslog-usg

# Capabilities
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

# Filesystem
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/etc/syslog-usg
ReadWritePaths=/var/log/syslog-usg /run/syslog-usg
PrivateTmp=yes
PrivateDevices=yes

# Network
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressDeny=any
IPAddressAllow=0.0.0.0/0 ::/0

# System calls
SystemCallFilter=@system-service
SystemCallArchitectures=native
SystemCallErrorNumber=EPERM

# Misc hardening
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
UMask=0077

# Resource limits
LimitNOFILE=65536
LimitNPROC=64

[Install]
WantedBy=multi-user.target
```

### 6.3 Restrict File System Access

**Priority:** REQUIRED

The syslog-usg process should have access only to:

| Path | Access | Purpose |
|------|--------|---------|
| `/etc/syslog-usg/` | Read-only | Configuration file and TLS certificates |
| `/var/log/syslog-usg/` | Read-write | File output destination (if configured) |
| `/run/syslog-usg/` | Read-write | PID file |
| syslog-usg binary | Execute | The binary itself |

All other filesystem paths should be inaccessible. Use `ProtectSystem=strict` and explicit `ReadWritePaths` in systemd, or mount namespace isolation in containers.

### 6.4 Enable seccomp and AppArmor/SELinux Profiles

**Priority:** RECOMMENDED

**seccomp:** The systemd `SystemCallFilter=@system-service` provides a baseline seccomp profile. For stricter confinement, create a custom seccomp profile allowing only:

- Socket operations: `socket`, `bind`, `listen`, `accept4`, `connect`, `sendto`, `recvfrom`, `setsockopt`, `getsockopt`
- File I/O: `read`, `write`, `open`, `openat`, `close`, `stat`, `fstat`
- Memory: `mmap`, `munmap`, `mprotect`, `brk`, `madvise`
- Threading: `clone`, `futex`, `set_robust_list`
- Signal: `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`
- Misc: `epoll_create1`, `epoll_ctl`, `epoll_wait`, `eventfd2`, `timerfd_create`, `timerfd_settime`
- Process: `exit_group`, `getpid`, `getuid`, `getgid`, `setuid`, `setgid`, `setgroups`

**AppArmor** (Ubuntu/Debian):

```
/etc/apparmor.d/usr.local.bin.syslog-usg

#include <tunables/global>

/usr/local/bin/syslog-usg {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Binary
  /usr/local/bin/syslog-usg mr,

  # Config (read-only)
  /etc/syslog-usg/** r,

  # TLS keys (read-only, restricted)
  /etc/syslog-usg/tls/*.key r,
  /etc/syslog-usg/tls/*.crt r,
  /etc/syslog-usg/tls/*.pem r,

  # Log output
  /var/log/syslog-usg/** rw,

  # PID file
  /run/syslog-usg/ rw,
  /run/syslog-usg/syslog-usg.pid rw,

  # Network
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,

  # Deny everything else
  deny /proc/** rw,
  deny /sys/** rw,
}
```

### 6.5 Monitor Certificate Expiry

**Priority:** REQUIRED

syslog-usg exposes `syslog_tls_cert_expiry_seconds{listener}` as a Prometheus gauge. Configure alerting:

```yaml
# Prometheus alerting rules
groups:
  - name: syslog-usg-tls
    rules:
      - alert: SyslogTLSCertExpiringSoon
        expr: syslog_tls_cert_expiry_seconds < 604800  # 7 days
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "syslog-usg TLS certificate expires in {{ $value | humanizeDuration }}"

      - alert: SyslogTLSCertExpiryCritical
        expr: syslog_tls_cert_expiry_seconds < 86400  # 1 day
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "syslog-usg TLS certificate expires in {{ $value | humanizeDuration }}"

      - alert: SyslogTLSCertExpired
        expr: syslog_tls_cert_expiry_seconds < 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "syslog-usg TLS certificate has EXPIRED"
```

Additionally, monitor `syslog_tls_sender_peer_cert_expiry_seconds` for outbound connections to downstream collectors.

### 6.6 Enable Audit Logging for Admin Operations

**Priority:** RECOMMENDED

The following events MUST be logged at INFO level with structured fields for audit trail:

| Event | Fields |
|-------|--------|
| Process startup | version, config_path, bind_addresses, user, pid |
| Process shutdown | reason (signal, error), drain_stats (messages_drained, messages_dropped) |
| Config reload attempt | trigger (SIGHUP), result (success/failure), error_detail |
| Config reload success | changes_summary (listeners_added, listeners_removed, outputs_changed) |
| TLS certificate loaded | cert_subject, cert_san, cert_fingerprint_sha256, cert_expiry |
| TLS certificate approaching expiry | cert_subject, days_remaining |
| TLS handshake failure (mutual auth) | peer_addr, error_type, cert_subject (if available) |
| Privilege drop | from_uid, to_uid, from_gid, to_gid |
| Rate limit activated for source | source_ip, listener, current_rate, limit |
| Connection limit reached | listener, active_connections, max_connections |

These audit events should be distinguishable from operational debug logs by a structured field such as `event_type = "audit"`.

### 6.7 Regular Dependency Audits

**Priority:** REQUIRED

```yaml
# CI pipeline step (GitHub Actions example)
- name: Security audit
  run: |
    cargo install cargo-audit
    cargo audit

- name: License and advisory check
  run: |
    cargo install cargo-deny
    cargo deny check advisories
    cargo deny check licenses
    cargo deny check bans
```

Run `cargo audit` on every CI build. Block merges if known vulnerabilities are found in dependencies.

Maintain a `deny.toml` configuration:

```toml
[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

[licenses]
unlicensed = "deny"
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"]

[bans]
multiple-versions = "warn"
deny = [
    # No OpenSSL in default build
    { name = "openssl-sys", wrappers = [] },
]
```

Schedule a weekly `cargo audit` run separate from CI to catch newly disclosed CVEs affecting existing dependencies.

### 6.8 Memory Limits via cgroups

**Priority:** REQUIRED (Linux production deployments)

Set memory limits to prevent OOM from affecting other services:

```ini
# systemd (cgroup v2)
[Service]
MemoryMax=512M
MemoryHigh=384M
```

Or with cgroup v1:

```bash
echo 536870912 > /sys/fs/cgroup/memory/syslog-usg/memory.limit_in_bytes
```

Sizing guidance:

| Component | Memory estimate |
|-----------|----------------|
| Base process (idle) | ~10 MiB |
| Per TLS connection | ~50-100 KiB |
| 10,000 TLS connections | ~500 MiB - 1 GiB |
| Per-output queue (10k messages at 500 bytes avg) | ~5 MiB |
| 5 output queues | ~25 MiB |
| Parser buffers and temporary allocations | ~10 MiB |
| **Total for typical deployment** | **128-256 MiB** |
| **Total for max connections (10k)** | **512 MiB - 1 GiB** |

Set `MemoryMax` to 2x the expected working set. The `MemoryHigh` threshold triggers kernel memory pressure reclaim without killing the process.

### 6.9 Network Namespace Isolation for Multi-Tenant

**Priority:** RECOMMENDED (multi-tenant deployments)

For deployments serving multiple tenants (Section 2.4 of Phase 01), consider running separate syslog-usg instances in isolated network namespaces:

```bash
# Create per-tenant namespace
ip netns add tenant-a
ip link add veth-a0 type veth peer name veth-a1
ip link set veth-a1 netns tenant-a

# Run syslog-usg in the namespace
ip netns exec tenant-a /usr/local/bin/syslog-usg --config /etc/syslog-usg/tenant-a.toml
```

Alternative: Use Kubernetes with NetworkPolicy to isolate per-tenant syslog-usg pods:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: syslog-usg-tenant-a
spec:
  podSelector:
    matchLabels:
      app: syslog-usg
      tenant: tenant-a
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              tenant: tenant-a
      ports:
        - port: 514
          protocol: UDP
        - port: 6514
          protocol: TCP
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              role: log-collector
      ports:
        - port: 6514
          protocol: TCP
```

For single-instance multi-tenant mode (per-tenant queues within one process), the isolation is logical (separate queues, separate metrics labels, per-tenant rate limits) rather than network-level. This provides performance isolation but not security isolation -- a vulnerability in the process affects all tenants.

### 6.10 Additional Deployment Hardening

| Item | Priority | Description |
|------|----------|-------------|
| **Disable core dumps** | REQUIRED | Core dumps may contain TLS private keys. Set `ulimit -c 0` or `LimitCORE=0` in systemd. |
| **Read-only root filesystem** | RECOMMENDED | Run the container or host with a read-only root filesystem. Only `/var/log/syslog-usg` and `/run/syslog-usg` need write access. |
| **Distroless container image** | RECOMMENDED | Use `gcr.io/distroless/static` or `scratch` as the container base. No shell, no package manager, no unnecessary libraries. |
| **Binary integrity** | RECOMMENDED | Sign the release binary. Verify checksums before deployment. Use `cosign` for container image signing. |
| **Log forwarding for syslog-usg's own logs** | REQUIRED | syslog-usg's operational logs (JSON format) should be forwarded to a separate logging system, not written to the same pipeline it processes. This prevents circular dependencies and ensures operational visibility during pipeline failures. |
| **Separate admin and data networks** | RECOMMENDED | Bind the admin HTTP server to a management network interface, separate from the syslog data interfaces. |
| **DNS pinning** | RECOMMENDED | When output destinations are specified by hostname, resolve DNS at startup and on reload only. Do not resolve per-message. Cache resolutions to prevent DNS poisoning from redirecting log output. |
| **Clock integrity** | RECOMMENDED | Monitor NTP synchronization. syslog-usg adds `received_at` timestamps; if the system clock is wrong, these timestamps are wrong. Use `chronyc tracking` or `timedatectl status` for monitoring. |

---

## Appendix A: Security Requirement Traceability

| Requirement ID | Section | Priority | Verification Method |
|---------------|---------|----------|-------------------|
| SEC-001 | 5.1 | CRITICAL | Code review + fuzz testing |
| SEC-002 | 5.2 | CRITICAL | Clippy lints + fuzz testing |
| SEC-003 | 5.3 | CRITICAL | Integration test + rustls structural guarantee |
| SEC-004 | 5.4 | CRITICAL | Integration test + default value verification |
| SEC-005 | 5.5 | CRITICAL | Code review + integration test (TRACE log grep) |
| SEC-006 | 5.6 | HIGH | Unit test for file permissions |
| SEC-007 | 5.7 | HIGH | Integration test for default rate limiting |
| SEC-008 | 3.1 | CRITICAL | Fuzz testing (10B+ iterations) |
| SEC-009 | 3.2 | CRITICAL | Benchmark + complexity counter |
| SEC-010 | 3.3 | HIGH | Integration test per policy |
| SEC-011 | 3.4 | HIGH | Integration test (multi-connection) |
| SEC-012 | 3.5 | HIGH | Integration test (asymmetric output failure) |
| SEC-013 | 3.6 | HIGH | Integration test (reload with invalid config) |
| SEC-014 | 3.7 | HIGH | Code review (signal handler implementation) |
| ROB-001 | 2.1 | HIGH | Code review (bounds checks before allocation) |
| ROB-002 | 2.2 | MEDIUM | Complexity counter implementation + benchmark |
| ROB-003 | 2.3 | HIGH | Integration test (flood + rate limit verification) |
| ROB-004 | 2.6 | HIGH | Integration test (byte-size queue cap) |
| ROB-005 | 2.7 | HIGH | Integration test (privilege drop verification) |
| ROB-006 | 2.8 | MEDIUM | Unit test (permission checks) |
| ROB-007 | 2.9 | MEDIUM | Integration test (admin API access) |
| ROB-008 | 2.10 | HIGH | Unit test (output sanitization) |

## Appendix B: Attack Surface Summary

```
                    ATTACK SURFACE MAP

    Internet / Untrusted Network
    ============================
         |                  |
    [UDP port 514]    [TCP port 6514]
         |                  |
    +----v----+        +----v----+
    | Rate    |        | TLS     |   <-- Handshake floods, slowloris,
    | Limiter |        | Accept  |       cert bombs, connection storms
    +----+----+        +----+----+
         |                  |
    +----v----+        +----v----+
    | Size    |        | Frame   |   <-- Oversized MSG-LEN, malformed
    | Check   |        | Decode  |       framing, partial reads
    +----+----+        +----+----+
         |                  |
         +--------+---------+
                  |
             +----v----+
             | Parser  |   <-- Malformed PRI, timestamps, structured
             |         |       data, UTF-8 violations, complexity bombs
             +----+----+
                  |
             +----v----+
             | Filter  |   <-- Regex bombs (future), rule explosion
             | /Route  |
             +----+----+
                  |
         +--------+---------+
         |        |         |
    +----v--+ +---v---+ +---v---+
    | Queue | | Queue | | Queue |   <-- Memory exhaustion, backpressure
    +----+--+ +---+---+ +---+---+       coupling, large message amplification
         |        |         |
    +----v--+ +---v---+ +---v---+
    | TLS   | | UDP   | | File  |   <-- Output injection, serialization
    | Send  | | Send  | | Write |       errors, downstream confusion
    +-------+ +-------+ +-------+

    Localhost / Management
    ======================
         |              |
    [SIGHUP]    [HTTP :9090]
         |              |
    +----v----+    +----v----+
    | Config  |    | Admin   |   <-- Config injection, reload abuse,
    | Reload  |    | API     |       secret exposure, unauthorized access
    +---------+    +---------+
```

