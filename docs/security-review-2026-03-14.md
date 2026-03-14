# Security Review: syslog-usg

**Date:** 2026-03-14
**Reviewer:** Automated security review (Claude)
**Scope:** Full codebase — all 9 workspace crates, dependencies, CI/CD, and architecture

## Executive Summary

**Overall Risk Rating: HIGH**

This is a well-structured Rust project with strong foundational security practices (zero `unsafe` code, workspace-level clippy deny on `unwrap`/`expect`/`panic`/`indexing_slicing`, clean `cargo audit`). However, several high-severity gaps make it unsuitable for Internet-exposed production deployment without remediation.

### Top 5 Most Serious Findings

| # | Finding | Severity |
|---|---------|----------|
| 1 | **mTLS configuration silently ignored** — `client_auth` and `client_ca_path` are accepted but never used; server always calls `.with_no_client_auth()` | CRITICAL |
| 2 | **No TCP connection limits or timeouts** — unbounded `tokio::spawn` per connection with no idle/read timeout enables slow loris and memory exhaustion | HIGH |
| 3 | **Management/metrics API unauthenticated on 0.0.0.0** — `/metrics`, `/management/*` endpoints exposed without auth on all interfaces by default | HIGH |
| 4 | **Signing failure silently forwards unsigned messages** — pipeline falls back to forwarding original unsigned message when signing fails, bypassing security policy | HIGH |
| 5 | **UDP `recv_buf_size` config is a no-op** — code sets `SO_BROADCAST` instead of `SO_RCVBUF`, silently ignoring the configuration | HIGH |

### Deployment Readiness

| Context | Assessment |
|---------|------------|
| **Lab/development** | Safe with caveats |
| **Internal network** | Acceptable after fixing mTLS and adding connection limits |
| **Internet-exposed production** | **Not recommended** until all Critical and High findings are remediated |

---

## Findings

### F-01: Mutual TLS Configuration Silently Ignored
**Severity: CRITICAL**
**Component:** `crates/syslog-transport/src/tls/mod.rs:42`

The `TlsConfig` struct accepts `client_auth: bool` and `client_ca_path: Option<String>`, but `build_server_config()` hardcodes `.with_no_client_auth()`, ignoring both fields entirely.

**Why it matters:** Operators configuring mTLS believe client certificate authentication is enforced. In reality, any client can connect without a certificate. This is a silent security policy bypass.

**Exploit scenario:** An attacker connects to the TLS syslog port without presenting a client certificate. Despite the operator's configuration requiring mTLS, the connection succeeds and the attacker can inject arbitrary syslog messages.

**Remediation:**
```rust
let server_config = if config.client_auth {
    let ca_path = config.client_ca_path.as_deref()
        .ok_or_else(|| TransportError::InvalidFrame("client_auth requires client_ca_path".into()))?;
    let ca_certs = load_certs(ca_path)?;
    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).map_err(TransportError::Tls)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;
    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, private_key)?
} else {
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?
};
```

---

### F-02: No TCP/TLS Connection Limits or Timeouts
**Severity: HIGH**
**Component:** `crates/syslog-transport/src/tcp/mod.rs:79`

Every TCP/TLS connection spawns an unbounded `tokio::spawn` task. There is no:
- Maximum concurrent connection limit
- Per-connection read timeout
- Idle connection timeout
- TLS handshake timeout (beyond rustls internal defaults)

**Exploit scenario (Slow Loris):** Attacker opens thousands of connections, each sending partial octet-counting frames (e.g., `"999999 "` followed by 1 byte per minute). Each connection holds a tokio task and a `pending_len` buffer indefinitely, exhausting server memory.

**Remediation:** Add a `tokio::sync::Semaphore` for connection limits and wrap `framed.next()` in `tokio::time::timeout()`:
```rust
let semaphore = Arc::new(Semaphore::new(max_connections));
// In accept loop:
let permit = semaphore.clone().acquire_owned().await?;
tokio::spawn(async move {
    let _permit = permit; // released on drop
    tokio::time::timeout(idle_timeout, handle_connection(...)).await;
});
```

---

### F-03: Unauthenticated Management/Metrics API on All Interfaces
**Severity: HIGH**
**Component:** `crates/syslog-observe/src/health.rs`, default bind `0.0.0.0:9090`

Six endpoints are exposed without authentication:
- `GET /healthz`, `GET /readyz` (acceptable for probes)
- `GET /metrics` — full Prometheus metrics
- `GET /management/state` — uptime, counters, features
- `GET /management/features` — feature flags
- `GET /management/counters` — message throughput

**Exploit scenario:** An attacker on the network enumerates enabled features, monitors message throughput to detect filtering patterns, and uses counter deltas to infer whether specific messages were dropped.

**Remediation:**
1. Default bind to `127.0.0.1:9090` instead of `0.0.0.0:9090`
2. Add optional bearer token authentication middleware for `/management/*` and `/metrics`
3. `/healthz` and `/readyz` should remain unauthenticated for load balancer probes

---

### F-04: Signing Failure Silently Forwards Unsigned Messages
**Severity: HIGH**
**Component:** `crates/syslog-relay/src/pipeline.rs:299-305`

When signing fails, the pipeline logs a warning and forwards the original unsigned message:
```rust
Err(e) => {
    warn!(error = %e, "signing failed, forwarding original");
    vec![message]  // forwards UNSIGNED
}
```

**Exploit scenario:** An attacker triggers a signing failure (e.g., by sending a message that causes serialization issues). The unsigned message reaches downstream consumers that expect all messages to be signed, bypassing integrity verification.

**Remediation:** Make the fail-open/fail-closed behavior configurable:
```rust
Err(e) => {
    if self.signing_fail_open {
        warn!(error = %e, "signing failed, forwarding original (fail-open)");
        vec![message]
    } else {
        error!(error = %e, "signing failed, dropping message (fail-closed)");
        metrics::counter!("relay_signing_failures_total").increment(1);
        continue;
    }
}
```

---

### F-05: UDP `recv_buf_size` Configuration Bug
**Severity: HIGH**
**Component:** `crates/syslog-transport/src/udp/mod.rs:60-63`

```rust
if config.recv_buf_size > 0 {
    if let Err(e) = socket.set_broadcast(true) {  // BUG: sets SO_BROADCAST, not SO_RCVBUF
        warn!("failed to set SO_BROADCAST: {e}");
    }
}
```

The `recv_buf_size` config parameter is accepted but sets `SO_BROADCAST` instead of `SO_RCVBUF`. Under high UDP volume, the kernel will drop datagrams because the receive buffer is at OS default size.

**Remediation:** Use `socket2` crate for portable `SO_RCVBUF` support:
```rust
if config.recv_buf_size > 0 {
    let std_socket = socket.into_std()?;
    let sock2 = socket2::Socket::from(std_socket);
    sock2.set_recv_buffer_size(config.recv_buf_size)?;
    socket = UdpSocket::from_std(sock2.into())?;
}
```

---

### F-06: Output TLS Trusts Only System Root CAs — No Custom CA Support
**Severity: HIGH**
**Component:** `crates/syslog-server/src/main.rs` (~L579-584)

Output TLS connections trust only `webpki_roots::TLS_SERVER_ROOTS`. There is no way to specify a custom CA for internal PKI, and no certificate pinning support.

**Exploit scenario:** In an enterprise environment with an internal CA, the syslog relay cannot validate output server certificates signed by internal CAs, forcing operators to either disable TLS or use public CAs for internal infrastructure.

**Remediation:** Accept an optional `ca_cert_path` in output configuration and load those certificates into the root store.

---

### F-07: DTLS/Signing Configured but Silently Non-Functional
**Severity: MEDIUM-HIGH**
**Component:** `crates/syslog-server/src/main.rs` — DTLS listener skip, signing/verification stubs

Three features accept configuration but silently do nothing:
- **DTLS listeners**: Logged as "not yet implemented" and skipped (no error)
- **Signing**: Returns `None` with info log "key loading not yet implemented"
- **Verification**: Same pattern

**Exploit scenario:** An operator deploys the server configured for DTLS + message signing, believing both are active. Neither is enforced.

**Remediation:** Fail at startup with an error if unimplemented features are configured:
```rust
ListenerProtocol::Dtls => {
    return Err(anyhow::anyhow!("DTLS listener configured but not yet implemented"));
}
```

---

### F-08: Hardcoded Ingest Channel Size Ignores Configuration
**Severity: MEDIUM**
**Component:** `crates/syslog-server/src/main.rs` (~L316, L394)

UDP and TCP ingest channels are hardcoded to capacity 4096, ignoring `config.pipeline.channel_buffer_size`. Operators cannot tune backpressure behavior.

**Remediation:** Use the configured value: `mpsc::channel(config.pipeline.channel_buffer_size)`

---

### F-09: No Output Reconnection Backoff
**Severity: MEDIUM**
**Component:** `crates/syslog-server/src/network_output.rs:97-139`

`ensure_connected()` attempts connection on every `send()` call with no backoff. If the output server is down, every message triggers a `TcpStream::connect()` that fails immediately, creating a storm of connection attempts and error logs.

**Remediation:** Implement exponential backoff with jitter. Track last connection attempt time and minimum retry interval.

---

### F-10: Verification Stage Allows Empty Verifier List
**Severity: MEDIUM**
**Component:** `crates/syslog-relay/src/verification.rs:48`

`VerificationStage::new(vec![], false)` creates a verification stage with no verifiers and `reject_unverified=false`. All messages (signed or unsigned) pass through. There's no validation that at least one verifier is configured.

**Remediation:** Add a constructor-time check or at minimum a `warn!` log if `verifiers.is_empty()` and verification is supposedly enabled.

---

### F-11: Parse Error Messages May Contain Unsanitized Binary Data
**Severity: MEDIUM**
**Component:** `crates/syslog-server/src/main.rs` (~L340-344)

Parse errors from untrusted syslog messages are logged directly via `warn!("parse error: {e}")`. The error `{e}` may contain raw bytes from malformed input. If logs are consumed by systems that interpret escape sequences (terminal emulators, log aggregators), this enables log injection.

**Remediation:** Truncate and sanitize error messages from untrusted input, or log only error codes/variants without embedded data.

---

### F-12: IPv6 Server Name Parsing Failure in Output TLS
**Severity: MEDIUM**
**Component:** `crates/syslog-server/src/main.rs` (~L588-593)

Server name for TLS SNI is extracted via `address.split(':').next()`. For IPv6 addresses like `[::1]:6514`, this produces `[`, which is not a valid `ServerName`. TLS connections to IPv6 outputs will fail.

**Remediation:** Parse the address as `SocketAddr` first, then extract the hostname properly.

---

### F-13: Signing Key Path Logged at INFO Level
**Severity: LOW-MEDIUM**
**Component:** `crates/syslog-server/src/main.rs` (~L499-505)

The path to the private signing key is logged at `info!` level. If logs are forwarded to an insecure system, this reveals the filesystem location of key material.

**Remediation:** Log only that signing is configured, not the key path. Use `debug!` level at most.

---

### F-14: TLS Certificate Load Errors Expose File Paths
**Severity: LOW**
**Component:** `crates/syslog-transport/src/tls/mod.rs:56-75`

Error messages include full file paths: `format!("cert file {path}: {e}")`. Reveals directory structure to log consumers.

---

## Protocol Security Review

### RFC 5424 Handling
- **Parser is robust**: Bounds-checked field parsing, `checked_add()` for position arithmetic, limits on SD-ELEMENT count (128) and SD-PARAM count (64 per element)
- **Risk: No max message size at parser level**: The `MessageTooLarge` error variant exists but is never raised by the parser. The transport layer's `max_frame_size` is the only defense
- **Risk: Serializer doesn't re-validate field lengths**: Programmatically constructed messages with oversized fields serialize without error, producing non-compliant output

### RFC 5425 TLS
- **mTLS not implemented** despite config support (F-01)
- **No explicit cipher suite enforcement** per RFC 9662 (rustls defaults are strong but not explicitly locked)
- **Octet-counting codec is correct**: Frame size validated, digits validated, length checked against `max_frame_size`

### RFC 5426 UDP
- **No source address validation or rate limiting**: Any host can send datagrams
- **Silent drops when channel is full**: `try_send()` drops with a warning log but no counter increment (though management counters exist)
- **UDP amplification**: No protection against spoofed source addresses used in reflection attacks

### RFC 6012 DTLS
- **Not implemented** — type stubs only. Configuration accepted but silently skipped (F-07)

### RFC 5848 Signed Syslog
- **Signing key loading not implemented** in server binary (stubs only)
- **Verification logic is sound** when configured with verifiers
- **OpenPGP DSA scheme accepted in parsing** but never implemented for verification — a message claiming OpenPGP DSA will have its signature block parsed but verification will fail (correctly rejects)
- **Certificate block reassembly doesn't validate fragment length matches FLEN**: `block.fragment.len()` is not checked against `block.flen`
- **Counter fields (RSID, GBC, FMN) parsed as u64 without RFC range validation**: RFC 5848 limits these to 10 decimal digits

### Relay/Forwarding Trust Boundaries
- **Signing failure forwards unsigned** (F-04) — trust boundary violation
- **No multi-tenancy isolation** — single pipeline for all sources
- **Routing rule output indices not validated at construction** — invalid indices silently drop messages

---

## Rust-Specific Security Review

### unsafe Usage
**Zero `unsafe` blocks in the entire workspace.** The workspace-level lint `unsafe_code = "forbid"` enforces this. This is excellent.

### panic/unwrap/expect Review
Workspace lints deny `unwrap_used`, `expect_used`, `indexing_slicing`, and `panic` in library code. All indexing uses `.get()` with proper fallback. No panic paths exist in release library code. Test code uses `#[allow()]` for these where needed. **This is well-handled.**

### Lifetime/Ownership
- `Bytes::copy_from_slice()` is used throughout, avoiding lifetime issues but adding allocation cost. Acceptable for correctness.
- `Arc<Mutex<Option<Connection>>>` in `NetworkOutput` is correct but holds the lock during `write_all()` + `flush()`, which could block other senders. Single-writer pattern makes this acceptable.

### Concurrency/Async
- **`tokio::select! { biased; ... }` in pipeline**: Correctly prioritizes shutdown over message processing
- **No deadlock risk identified**: Lock ordering is simple (one mutex per `NetworkOutput`, no nested locks)
- **Risk**: `send().await` on TCP ingest channel blocks the connection handler indefinitely if the pipeline is slow. No timeout on this await.

### Feature Flags and Crate Risk
- All dependencies are well-maintained, current versions
- `ring` 0.17.14 for cryptography — industry standard
- `rustls` 0.23.37 — no OpenSSL, pure Rust
- `regex` crate uses finite automaton engine — resistant to catastrophic backtracking but still vulnerable to state explosion on complex patterns
- `cargo audit`: 0 vulnerabilities across 233 dependencies
- `cargo deny` configured for advisories and licenses

---

## Resilience / DoS Review

### CPU Exhaustion
- **Regex patterns in routing selectors**: While the `regex` crate is NFA-based, extremely complex patterns can still cause significant compilation time. No complexity limits or compilation timeouts.
- **No per-message processing budget**: A malformed message with maximum-size structured data (128 elements × 64 params each) will consume more CPU than a simple message, but within reasonable bounds.

### Memory Exhaustion
- **TCP connections unbounded** (F-02): Primary DoS vector. Each connection holds a codec buffer and tokio task.
- **Parser copies full message to `raw` field**: `Bytes::copy_from_slice(input)` — bounded by transport frame size.
- **Alarm state table bounded by `max_entries`**: Correctly prevents unbounded growth.
- **Pipeline channel bounded**: 4096 entries (hardcoded).

### Disk Exhaustion
- **No file output in current implementation**: Not applicable.
- **Logging**: Tracing output could grow unbounded. Recommend log rotation configuration.

### Socket Exhaustion
- **TCP listener**: No connection limit → file descriptor exhaustion possible.
- **Output connections**: Lazy connect with broken-connection cleanup. Single connection per output (mutex-protected). Not a socket exhaustion risk.

### Queue/Backpressure Weaknesses
- **UDP**: `try_send()` drops silently when full — correct for UDP but needs metrics.
- **TCP**: `send().await` blocks — correct backpressure but no timeout.
- **BoundedQueue `DropOldest`**: Race condition where both the dropped message and the retry can be lost.

### Recommended Limits and Safe Defaults

| Control | Current | Recommended |
|---------|---------|-------------|
| Max TCP connections | Unlimited | 1,000 |
| Connection idle timeout | None | 300s |
| Read timeout per frame | None | 30s |
| TLS handshake timeout | None (rustls default) | 10s |
| UDP rate limit | None | 10,000/s per source |
| Max message size | 65,535 (UDP), 64KB (TCP) | Keep as-is |
| Metrics bind address | `0.0.0.0:9090` | `127.0.0.1:9090` |
| Output reconnect backoff | None (immediate) | 1s → 60s exponential |
| Pipeline channel size | 4096 (hardcoded) | Use config value |

---

## Hardening Recommendations

### Immediate Fixes (Pre-Deployment)
1. **Fix mTLS implementation** — actually use `client_auth` and `client_ca_path` (F-01)
2. **Add TCP connection limits and timeouts** — semaphore + `tokio::time::timeout` (F-02)
3. **Default metrics bind to localhost** — change default from `0.0.0.0` to `127.0.0.1` (F-03)
4. **Fix UDP `recv_buf_size` bug** — replace `set_broadcast` with actual `SO_RCVBUF` (F-05)
5. **Fail startup on unimplemented features** — DTLS, signing, verification (F-07)

### Near-Term Improvements
6. **Make signing failure policy configurable** — fail-open vs fail-closed (F-04)
7. **Add output reconnection backoff** (F-09)
8. **Use configured channel buffer size** instead of hardcoded 4096 (F-08)
9. **Add authentication to management endpoints** (F-03)
10. **Support custom CA for output TLS** (F-06)
11. **Validate routing rule output indices at construction time**
12. **Add `overflow-checks = true` to release profile**

### Production Hardening Checklist
- [ ] mTLS enforced for all TLS listeners
- [ ] Connection limits configured
- [ ] Idle/read timeouts configured
- [ ] Metrics endpoint bound to localhost or authenticated
- [ ] DTLS/signing/verification either implemented or rejected at config time
- [ ] Log rotation configured
- [ ] Privilege dropping implemented (run as non-root after binding ports)
- [ ] Config file permissions validated (warn on world-readable, error on world-writable)
- [ ] Private key file permissions validated
- [ ] Rate limiting enabled for UDP sources
- [ ] Output reconnection backoff enabled
- [ ] `overflow-checks = true` in release profile

---

## Secure Coding Follow-Ups

### Concrete Code Changes Needed
1. `crates/syslog-transport/src/tls/mod.rs:42` — implement mTLS
2. `crates/syslog-transport/src/tcp/mod.rs:79` — add connection semaphore
3. `crates/syslog-transport/src/tcp/mod.rs:118` — add `tokio::time::timeout` around `framed.next().await`
4. `crates/syslog-transport/src/udp/mod.rs:61` — fix SO_RCVBUF
5. `crates/syslog-relay/src/pipeline.rs:303` — configurable signing fail policy
6. `crates/syslog-observe/src/health.rs:80` — add auth middleware option
7. `crates/syslog-server/src/network_output.rs:97` — add reconnect backoff

### Fuzz Targets (Priority Order)
1. **RFC 5424 parser** — `syslog_parse::rfc5424::parser::parse()` with arbitrary bytes
2. **Octet-counting codec** — `OctetCountingCodec::decode()` with arbitrary `BytesMut`
3. **RFC 3164 parser** — `syslog_parse::rfc3164::parser::parse_rfc3164()` with arbitrary bytes
4. **Structured data parser** — `parse_structured_data()` with crafted SD strings
5. **Signature block parser** — `SignatureBlock::from_sd_element()` with crafted SD elements
6. **Certificate block reassembly** — `reassemble_certificate()` with crafted fragments

### Tooling Recommendations
- **`cargo fuzz`**: Add fuzz targets for all parsers (highest impact)
- **`cargo audit`**: Already in CI — continue running
- **`cargo deny`**: Already configured — continue running
- **`cargo geiger`**: Run to confirm zero unsafe transitively (beyond `ring`/`rustls` which are expected)
- **Property testing**: Add `proptest` or `quickcheck` for parser roundtrip properties (`parse(serialize(msg)) == msg`)
- **Miri**: Run unit tests under Miri for undefined behavior detection (limited to non-async code)
- **`clippy`**: Already strict — maintain current configuration
- **Dependency pinning**: `Cargo.lock` is committed — ensure CI validates it with `--locked`

### Malicious Test Cases to Add
```rust
// Slow loris - partial frame that never completes
// MSG-LEN claims 999999 bytes, sends 1 byte per second

// Log injection via structured data
"<13>1 - - - - - [id@1 key=\"value\nfake_field=injected\"] msg"

// Oversized PRI
"<99999>1 - - - - - - msg"

// Certificate fragment overlap attack
// Fragment 1: INDEX=1, FLEN=100, data=[100 bytes]
// Fragment 2: INDEX=50, FLEN=100, data=[100 bytes]  // overlaps!

// UDP source spoofing flood
// 100k datagrams/sec from random source IPs to fill channel
```
