# Phase 11 — QA Strategy and Test Plan

## syslog-usg: Comprehensive Testing for RFC Compliance, Correctness, Performance, and Resilience

**Version:** 1.0.0-draft
**Date:** 2026-03-11
**Status:** Draft
**Prerequisites:** [Phase 01 — Requirements](phase-01-requirements.md), [Phase 02 — RFC Analysis](phase-02-rfc-analysis.md), [Phase 03 — Architecture](phase-03-architecture.md), [Phase 04 — Rust Architecture](phase-04-rust-architecture.md), [Phase 05 — Transport Security](phase-05-transport-security.md)

---

## Table of Contents

1. [Test Strategy](#1-test-strategy)
2. [RFC Compliance Validation Plan](#2-rfc-compliance-validation-plan)
3. [Unit, Integration, and E2E Plan](#3-unit-integration-and-e2e-plan)
4. [Fuzzing Plan](#4-fuzzing-plan)
5. [Benchmark Plan](#5-benchmark-plan)
6. [Interoperability Test Plan](#6-interoperability-test-plan)
7. [Test Corpus](#7-test-corpus)
8. [CI/CD Integration](#8-cicd-integration)
9. [Coverage and Quality Gates](#9-coverage-and-quality-gates)

---

## 1. Test Strategy

### 1.1 Guiding Principles

Every compliance claim must be traceable to a test (CLAUDE.md: "All compliance claims must be traceable to tests"). The test strategy is organized in layers of increasing scope and cost, with fast feedback loops at the bottom and thorough validation at the top.

**Defense in depth:** No single test layer is sufficient. A parser bug might pass unit tests but fail under fuzz. A transport issue might pass integration tests but fail under interop with rsyslog. Each layer catches different classes of defects.

**Determinism:** All tests below the interop layer must be fully deterministic. No flaky tests are acceptable in CI. Network-dependent tests use loopback interfaces with ephemeral ports.

**Performance as correctness:** A parse latency regression from 2us to 20us is a bug, not a style issue. Performance targets from Phase 01 are enforced in CI via criterion baselines.

### 1.2 Test Layers

| Layer | Tool | Location | Frequency | What It Catches |
|-------|------|----------|-----------|-----------------|
| **Unit tests** | `#[test]`, `#[tokio::test]` | `crates/*/src/**/*.rs` (inline `#[cfg(test)]` modules) | Every commit | Logic errors in individual functions |
| **Property-based tests** | `proptest` | `crates/*/src/**/*.rs` and `crates/*/tests/` | Every commit | Invariant violations across input space |
| **Integration tests** | `#[tokio::test]` | `tests/` workspace root | Every commit | Cross-crate pipeline correctness |
| **Conformance tests** | `#[test]` with RFC-derived vectors | `tests/rfc_conformance/` | Every commit | RFC specification violations |
| **Fuzz tests** | `cargo-fuzz` (libfuzzer) | `fuzz/` | Scheduled (nightly) + pre-release | Panics, hangs, unbounded allocations |
| **Benchmarks** | `criterion` | `benches/` | Every PR (compare), nightly (full) | Performance regressions |
| **Load tests** | Custom binary + scripts | `tests/load/` | Weekly + pre-release | Sustained throughput validation |
| **Interop tests** | Docker Compose + rsyslog/syslog-ng | `tests/interop/` | Weekly + pre-release | Real-world compatibility |

### 1.3 Test Naming Conventions

All test functions follow a consistent naming scheme for grep-ability and CI reporting:

```
test_<module>_<behavior>_<condition>
```

Examples:
- `test_parse_rfc5424_valid_minimal_message`
- `test_parse_rfc5424_rejects_pri_value_192`
- `test_udp_listener_receives_single_datagram`
- `test_tls_rejects_expired_certificate`
- `test_filter_matches_severity_range`

Property-based tests use the prefix `proptest_`:
- `proptest_parse_rfc5424_never_panics`
- `proptest_serialize_roundtrip_is_identity`

Benchmark functions use the prefix `bench_`:
- `bench_parse_rfc5424_minimal`
- `bench_parse_rfc5424_typical`

### 1.4 Test Data Management

Test fixtures are stored in `tests/fixtures/` organized by category:

```
tests/
├── fixtures/
│   ├── rfc5424/
│   │   ├── valid/           # Valid RFC 5424 messages, one per file
│   │   ├── invalid/         # Malformed messages with expected error
│   │   └── rfc_examples/    # Messages copied verbatim from RFC 5424 Section 6.5
│   ├── rfc3164/
│   │   ├── valid/
│   │   └── invalid/
│   ├── real_world/
│   │   ├── linux_kernel.txt
│   │   ├── systemd.txt
│   │   ├── cisco_ios.txt
│   │   ├── palo_alto.txt
│   │   └── aws_cloudwatch.txt
│   ├── certs/               # Test certificates (generated, NOT production)
│   │   ├── ca.pem
│   │   ├── server.pem
│   │   ├── server.key
│   │   ├── client.pem
│   │   ├── client.key
│   │   ├── expired.pem
│   │   ├── wrong_ca.pem
│   │   └── self_signed.pem
│   └── configs/
│       ├── minimal.toml
│       ├── full.toml
│       └── invalid/         # Configs that must fail validation
```

---

## 2. RFC Compliance Validation Plan

### 2.1 RFC 5424 — The Syslog Protocol

Each test case references the specific RFC section and ABNF rule it validates.

#### 2.1.1 PRI Field (Section 6.2.1)

| Test ID | Description | Input | Expected Result | RFC Section |
|---------|-------------|-------|-----------------|-------------|
| PRI-001 | Minimum valid PRI | `<0>1 - - - - - -` | Parse OK, facility=0 (kern), severity=0 (emerg) | 6.2.1 |
| PRI-002 | Maximum valid PRI | `<191>1 - - - - - -` | Parse OK, facility=23 (local7), severity=7 (debug) | 6.2.1 |
| PRI-003 | Typical PRI | `<34>1 - - - - - -` | Parse OK, facility=4 (auth), severity=2 (crit) | 6.2.1 |
| PRI-004 | PRI value 192 (invalid, facility>23) | `<192>1 - - - - - -` | Strict: ParseError::InvalidPri; Lenient: best-effort | 6.2.1 |
| PRI-005 | PRI value 999 (3-digit, invalid) | `<999>1 - - - - - -` | ParseError::InvalidPri | 6.2.1 |
| PRI-006 | PRI value 4-digit | `<1000>1 - - - - - -` | ParseError::InvalidPri | 6.2.1 |
| PRI-007 | PRI missing angle brackets | `34>1 - - - - - -` | ParseError::InvalidPri | 6.2.1 |
| PRI-008 | PRI empty | `<>1 - - - - - -` | ParseError::InvalidPri | 6.2.1 |
| PRI-009 | PRI non-numeric | `<abc>1 - - - - - -` | ParseError::InvalidPri | 6.2.1 |
| PRI-010 | PRI with leading zero | `<034>1 - - - - - -` | Parse OK (leading zeros permitted by ABNF PRIVAL = 1*3DIGIT) | 6.2.1 |
| PRI-011 | PRI negative value | `<-1>1 - - - - - -` | ParseError::InvalidPri | 6.2.1 |

#### 2.1.2 VERSION Field (Section 6.2.2)

| Test ID | Description | Input | Expected Result | RFC Section |
|---------|-------------|-------|-----------------|-------------|
| VER-001 | Version 1 (only valid version) | `<34>1 - - - - - -` | Parse OK, version=1 | 6.2.2 |
| VER-002 | Version 0 (invalid) | `<34>0 - - - - - -` | ParseError::InvalidVersion | 6.2.2 |
| VER-003 | Version 2 (reserved) | `<34>2 - - - - - -` | ParseError::InvalidVersion | 6.2.2 |
| VER-004 | Version missing | `<34> - - - - - -` | ParseError::InvalidVersion | 6.2.2 |
| VER-005 | Version multi-digit | `<34>10 - - - - - -` | ParseError::InvalidVersion (currently only "1" defined) | 6.2.2 |

#### 2.1.3 TIMESTAMP Field (Section 6.2.3)

| Test ID | Description | Input (TIMESTAMP portion) | Expected Result | RFC Section |
|---------|-------------|---------------------------|-----------------|-------------|
| TS-001 | Full precision with Z | `2023-10-11T22:14:15.003000Z` | Parse OK, nanosecond precision preserved | 6.2.3 |
| TS-002 | Full precision with positive offset | `2023-10-11T22:14:15.003000+05:30` | Parse OK, offset stored | 6.2.3 |
| TS-003 | Full precision with negative offset | `2023-10-11T22:14:15.003000-08:00` | Parse OK, offset stored | 6.2.3 |
| TS-004 | No fractional seconds | `2023-10-11T22:14:15Z` | Parse OK, fractional = 0 | 6.2.3 |
| TS-005 | Fractional 1 digit | `2023-10-11T22:14:15.0Z` | Parse OK | 6.2.3 |
| TS-006 | Fractional 6 digits (microseconds) | `2023-10-11T22:14:15.000003Z` | Parse OK, nanosecond precision | 6.2.3 |
| TS-007 | Fractional 9 digits (nanoseconds) | `2023-10-11T22:14:15.000000001Z` | Parse OK | 6.2.3 |
| TS-008 | NILVALUE timestamp | `-` | Parse OK, timestamp = None | 6.2.3 |
| TS-009 | Invalid month 13 | `2023-13-11T22:14:15Z` | ParseError::InvalidTimestamp | 6.2.3 |
| TS-010 | Invalid day 32 | `2023-10-32T22:14:15Z` | ParseError::InvalidTimestamp | 6.2.3 |
| TS-011 | Invalid hour 25 | `2023-10-11T25:14:15Z` | ParseError::InvalidTimestamp | 6.2.3 |
| TS-012 | Missing timezone | `2023-10-11T22:14:15` | ParseError::InvalidTimestamp (TIME-OFFSET is mandatory) | 6.2.3 |
| TS-013 | Leap second | `2023-12-31T23:59:60Z` | Parse OK (RFC 3339 permits leap seconds) | 6.2.3 |
| TS-014 | Date boundary (midnight) | `2023-10-12T00:00:00Z` | Parse OK | 6.2.3 |
| TS-015 | Feb 29 leap year | `2024-02-29T12:00:00Z` | Parse OK | 6.2.3 |
| TS-016 | Feb 29 non-leap year | `2023-02-29T12:00:00Z` | ParseError::InvalidTimestamp | 6.2.3 |

#### 2.1.4 HOSTNAME, APP-NAME, PROCID, MSGID Fields (Sections 6.2.4-6.2.7)

| Test ID | Description | Expected Result | RFC Section |
|---------|-------------|-----------------|-------------|
| HOST-001 | FQDN hostname | `mymachine.example.com` -> Parse OK | 6.2.4 |
| HOST-002 | IPv4 hostname | `192.168.1.1` -> Parse OK | 6.2.4 |
| HOST-003 | IPv6 hostname | `2001:db8::1` -> Parse OK | 6.2.4 |
| HOST-004 | NILVALUE hostname | `-` -> hostname = None | 6.2.4 |
| HOST-005 | Maximum length hostname (255 chars) | 255-char PRINTUSASCII -> Parse OK | 6.2.4 |
| HOST-006 | Hostname exceeds 255 chars | 256-char string -> strict: ParseError, lenient: truncate | 6.2.4 |
| APP-001 | Typical app-name | `evntslog` -> Parse OK | 6.2.5 |
| APP-002 | NILVALUE app-name | `-` -> app_name = None | 6.2.5 |
| APP-003 | Maximum length app-name (48 chars) | 48-char PRINTUSASCII -> Parse OK | 6.2.5 |
| APP-004 | App-name exceeds 48 chars | 49-char string -> strict: ParseError, lenient: truncate | 6.2.5 |
| PID-001 | Typical procid | `12345` -> Parse OK | 6.2.6 |
| PID-002 | NILVALUE procid | `-` -> procid = None | 6.2.6 |
| PID-003 | Maximum length procid (128 chars) | 128-char PRINTUSASCII -> Parse OK | 6.2.6 |
| PID-004 | Procid exceeds 128 chars | 129-char string -> strict: ParseError, lenient: truncate | 6.2.6 |
| MID-001 | Typical msgid | `ID47` -> Parse OK | 6.2.7 |
| MID-002 | NILVALUE msgid | `-` -> msgid = None | 6.2.7 |
| MID-003 | Maximum length msgid (32 chars) | 32-char PRINTUSASCII -> Parse OK | 6.2.7 |
| MID-004 | Msgid exceeds 32 chars | 33-char string -> strict: ParseError, lenient: truncate | 6.2.7 |

#### 2.1.5 STRUCTURED-DATA (Section 6.3)

| Test ID | Description | Input (SD portion) | Expected Result | RFC Section |
|---------|-------------|-------------------|-----------------|-------------|
| SD-001 | NILVALUE structured data | `-` | sd = None | 6.3 |
| SD-002 | Single SD-ELEMENT, one param | `[exampleSDID@32473 iut="3"]` | 1 element, 1 param | 6.3.1 |
| SD-003 | Single SD-ELEMENT, multiple params | `[exampleSDID@32473 iut="3" eventSource="App" eventID="1011"]` | 1 element, 3 params | 6.3.1 |
| SD-004 | Multiple SD-ELEMENTs | `[id1@1 a="1"][id2@2 b="2"]` | 2 elements | 6.3.1 |
| SD-005 | SD-PARAM with escaped quote | `[id@1 msg="say \"hello\""]` | param value = `say "hello"` | 6.3.5 |
| SD-006 | SD-PARAM with escaped backslash | `[id@1 path="C:\\\\logs"]` | param value = `C:\\logs` | 6.3.5 |
| SD-007 | SD-PARAM with escaped closing bracket | `[id@1 msg="close\\]here"]` | param value = `close]here` | 6.3.5 |
| SD-008 | IANA-registered SD-ID (timeQuality) | `[timeQuality tzKnown="1" isSynced="1" syncAccuracy="60000"]` | Parse OK, recognized SD-ID | 6.3.2 |
| SD-009 | IANA-registered SD-ID (origin) | `[origin ip="192.168.1.1"]` | Parse OK | 6.3.2 |
| SD-010 | IANA-registered SD-ID (meta) | `[meta sequenceId="1" sysUpTime="1234" language="en"]` | Parse OK | 6.3.2 |
| SD-011 | Enterprise SD-ID format | `[myid@32473 key="val"]` | Parse OK, enterprise number parsed | 6.3.2 |
| SD-012 | Empty SD-ELEMENT (no params) | `[id@1]` | 1 element, 0 params (valid per ABNF) | 6.3.1 |
| SD-013 | SD-PARAM value with UTF-8 | `[id@1 msg="\xC3\xA9v\xC3\xA9nement"]` | Parse OK, UTF-8 preserved | 6.3.3 |
| SD-014 | SD-PARAM empty value | `[id@1 key=""]` | Parse OK, empty string value | 6.3.3 |
| SD-015 | Malformed: missing closing bracket | `[id@1 key="val"` | ParseError::InvalidStructuredData | 6.3 |
| SD-016 | Malformed: missing opening bracket | `id@1 key="val"]` | ParseError::InvalidStructuredData | 6.3 |
| SD-017 | Malformed: unescaped quote in value | `[id@1 key="val"ue"]` | ParseError::InvalidStructuredData | 6.3.5 |
| SD-018 | Many SD-ELEMENTs (stress) | 50 SD-ELEMENTs | Parse OK, bounded allocation | 6.3 |

#### 2.1.6 MSG Body (Section 6.4)

| Test ID | Description | Input | Expected Result | RFC Section |
|---------|-------------|-------|-----------------|-------------|
| MSG-001 | MSG with UTF-8 BOM | BOM + `An application event` | Parse OK, BOM detected, content extracted | 6.4 |
| MSG-002 | MSG without BOM | `An application event` | Parse OK | 6.4 |
| MSG-003 | Empty MSG | (no MSG after SD) | Parse OK, msg = empty | 6.4 |
| MSG-004 | MSG with non-UTF-8 octets | Arbitrary bytes after SP | Lenient: raw bytes preserved; strict: depends on mode | 6.4 |
| MSG-005 | MSG with control characters | Embedded \x00, \x01 | Parse OK (MSG is free-form) | 6.4 |
| MSG-006 | MSG with multi-byte UTF-8 | Unicode CJK characters | Parse OK, byte boundaries correct | 6.4 |

#### 2.1.7 Message Size Boundaries (Section 6.1)

| Test ID | Description | Expected Result | RFC Section |
|---------|-------------|-----------------|-------------|
| SIZE-001 | Message exactly 480 octets | Parse OK (MUST accept) | 6.1 |
| SIZE-002 | Message exactly 2048 octets | Parse OK (SHOULD accept) | 6.1 |
| SIZE-003 | Message at configured maximum | Parse OK | 6.1 |
| SIZE-004 | Message one byte over configured maximum | ParseError::MessageTooLong | 6.1 |
| SIZE-005 | Minimum valid message (shortest possible) | `<0>1 - - - - - -` (26 bytes) -> Parse OK | 6.1 |
| SIZE-006 | Empty input | ParseError::UnexpectedEof | 6.1 |
| SIZE-007 | Single byte input | ParseError | 6.1 |

#### 2.1.8 RFC 5424 Examples (Section 6.5)

Each example from RFC 5424 Section 6.5 is a test case. These are transcribed verbatim.

| Test ID | RFC Example | Full Message |
|---------|-------------|--------------|
| EX-001 | Example 1 | `<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8` |
| EX-002 | Example 2 | `<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.` |
| EX-003 | Example 3 | `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMAn application event log entry...` |
| EX-004 | Example 4 | `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][examplePriority@32473 class="high"]` |

For EX-003, the literal BOM (0xEF 0xBB 0xBF) must precede "An application event".

#### 2.1.9 Full Message Roundtrip

| Test ID | Description | Invariant |
|---------|-------------|-----------|
| RT-001 | Parse then serialize any valid message | `serialize(parse(input)) == input` (modulo whitespace normalization) |
| RT-002 | Serialize then parse any SyslogMessage | `parse(serialize(msg)).fields == msg.fields` |
| RT-003 | Roundtrip preserves nanosecond timestamp | No precision loss through parse-serialize cycle |
| RT-004 | Roundtrip preserves all SD-PARAM escaping | Escaped characters survive roundtrip |
| RT-005 | Roundtrip preserves NILVALUE fields | NIL fields remain NIL, not empty strings |

### 2.2 RFC 5426 — Transmission of Syslog Messages over UDP

| Test ID | Description | Expected Result | RFC Section |
|---------|-------------|-----------------|-------------|
| UDP-001 | Receive single message in single datagram | Parse OK, one message produced | 3.1 |
| UDP-002 | Receive on IPv4 address | Message received and parsed | 3.1 |
| UDP-003 | Receive on IPv6 address | Message received and parsed | 3.1 |
| UDP-004 | Receive on dual-stack (::) | Both IPv4 and IPv6 sources accepted | 3.1 |
| UDP-005 | Datagram with 480-octet message (IPv4 minimum) | Parse OK | 3.2 |
| UDP-006 | Datagram with 1180-octet message (IPv6 minimum) | Parse OK | 3.2 |
| UDP-007 | Datagram with 2048-octet message | Parse OK (SHOULD accept) | 3.2 |
| UDP-008 | Datagram exceeding configured max | Message dropped, counter incremented | 3.2 |
| UDP-009 | Truncated message (incomplete PRI) | ParseError, metrics incremented | 3.1 |
| UDP-010 | Multiple rapid datagrams (burst) | All messages received, none silently dropped | 3.1 |
| UDP-011 | Source IP recorded in metadata | Source IP available for filtering/logging | 3.1 |
| UDP-012 | Default port 514 bind | Listener binds to 514 | 3.1 |
| UDP-013 | Custom port bind | Listener binds to configured port | 3.1 |
| UDP-014 | Configurable receive buffer (SO_RCVBUF) | setsockopt applied, verified via getsockopt | 3.1 |
| UDP-015 | Empty datagram | Ignored (no parse error counter, not a valid message) | 3.1 |

### 2.3 RFC 5425 — TLS Transport Mapping for Syslog

#### 2.3.1 Connection and Framing

| Test ID | Description | Expected Result | RFC Section |
|---------|-------------|-----------------|-------------|
| TLS-001 | TLS 1.2 connection establishment | Handshake succeeds, messages flow | 4.1 |
| TLS-002 | TLS 1.3 connection establishment | Handshake succeeds, messages flow | 4.1 |
| TLS-003 | Octet-counting frame: single message | `MSG-LEN SP SYSLOG-MSG` decoded correctly | 4.3 |
| TLS-004 | Octet-counting frame: multiple messages on one connection | All messages decoded, boundaries correct | 4.3 |
| TLS-005 | Octet-counting frame: message split across TLS records | Reassembly produces correct message | 4.3 |
| TLS-006 | Octet-counting frame: MSG-LEN = 0 | Rejected (zero-length message is invalid) | 4.3 |
| TLS-007 | Octet-counting frame: MSG-LEN mismatch (too short) | ParseError::InvalidFrame | 4.3 |
| TLS-008 | Octet-counting frame: MSG-LEN mismatch (too long) | ParseError::InvalidFrame or timeout | 4.3 |
| TLS-009 | Octet-counting frame: MSG-LEN non-numeric | ParseError::InvalidFrame | 4.3 |
| TLS-010 | Octet-counting frame: MSG-LEN extremely large (DoS) | Rejected, bounded allocation enforced | 4.3 |
| TLS-011 | Multiple messages interleaved with partial reads | All messages decoded correctly | 4.3 |
| TLS-012 | Connection close with close_notify | Clean shutdown, no message loss | 4.1 |
| TLS-013 | Connection reset without close_notify | Detect as error, log, increment metric | 4.1 |
| TLS-014 | Default port 6514 bind | Listener binds to 6514 | 4.1 |
| TLS-015 | Message size 2048 octets (minimum MUST) | Parse OK | 4.3.1 |
| TLS-016 | Message size 8192 octets (SHOULD) | Parse OK | 4.3.1 |
| TLS-017 | Idle connection timeout | Connection closed after configurable timeout | 4.1 |

#### 2.3.2 Authentication and Certificates

| Test ID | Description | Expected Result | RFC Section |
|---------|-------------|-----------------|-------------|
| CERT-001 | Valid CA-signed server certificate | Client connects successfully | 5 |
| CERT-002 | Valid mutual TLS (client certificate) | Both sides authenticate | 5 |
| CERT-003 | Expired server certificate | Connection rejected, `tls_handshake_errors_total{error_type="certificate_expired"}` incremented | 5 |
| CERT-004 | Expired client certificate | Connection rejected | 5 |
| CERT-005 | Certificate signed by wrong CA | Connection rejected, `error_type="certificate_unknown"` | 5 |
| CERT-006 | Self-signed certificate (when allowed) | Connection succeeds | 5 |
| CERT-007 | Self-signed certificate (when disallowed) | Connection rejected | 5 |
| CERT-008 | Certificate fingerprint match (SHA-256) | Connection succeeds | 5 |
| CERT-009 | Certificate fingerprint mismatch | Connection rejected | 5 |
| CERT-010 | Certificate with wildcard SAN | Matches `*.example.com` correctly | 5 |
| CERT-011 | Certificate CN vs SAN precedence | SAN preferred over CN per RFC 6125 | 5 |
| CERT-012 | Missing client certificate when mutual TLS required | Connection rejected | 5 |
| CERT-013 | Revoked certificate (CRL, if supported) | Connection rejected | 5 |

### 2.4 RFC 9662 — Updates to Cipher Suites in Secure Syslog

| Test ID | Description | Expected Result | RFC Section |
|---------|-------------|-----------------|-------------|
| CS-001 | Negotiate TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | Handshake succeeds with mandatory cipher | 4 |
| CS-002 | Negotiate TLS_RSA_WITH_AES_128_CBC_SHA (legacy) | Handshake succeeds | 4 |
| CS-003 | ECDHE suite preferred over RSA-only | When both offered, ECDHE selected | 4 |
| CS-004 | Reject TLS 1.0 connection | Handshake fails, metrics incremented | 3 |
| CS-005 | Reject TLS 1.1 connection | Handshake fails, metrics incremented | 3 |
| CS-006 | Reject NULL cipher suites | Handshake fails | 4 |
| CS-007 | Reject RC4 cipher suites | Handshake fails | 4 |
| CS-008 | Reject 3DES cipher suites | Handshake fails | 4 |
| CS-009 | 0-RTT explicitly disabled (TLS 1.3) | Early data rejected, full handshake required | 5 |
| CS-010 | TLS 1.3 cipher suites work | TLS_AES_128_GCM_SHA256 negotiated | 4 |
| CS-011 | Client offering only weak ciphers | Connection rejected | 4 |

### 2.5 RFC 3164 — BSD Syslog (Legacy Compatibility)

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| BSD-001 | Typical BSD syslog message | `<34>Oct 11 22:14:15 mymachine su: 'su root' failed` -> Parse OK |
| BSD-002 | BSD timestamp with single-digit day | `<34>Oct  1 22:14:15 ...` -> Parse OK, day=1 |
| BSD-003 | Auto-detect RFC 5424 vs 3164 | `<34>1 ...` -> 5424; `<34>Oct ...` -> 3164 |
| BSD-004 | Translate 3164 to 5424 internal representation | All fields mapped, missing fields set to NILVALUE |
| BSD-005 | BSD with no hostname | Best-effort parse, hostname from source IP |
| BSD-006 | BSD with tag (app-name:pid) | `app[1234]:` parsed into app_name + procid |
| BSD-007 | BSD with unusual timestamp format | Non-standard but common formats handled gracefully |

---

## 3. Unit, Integration, and E2E Plan

### 3.1 Unit Test Organization (Per-Crate)

#### syslog-proto

| Module | Tests | Focus |
|--------|-------|-------|
| `facility.rs` | 10+ | All 24 facility codes, Display, FromPrimitive, invalid values |
| `severity.rs` | 10+ | All 8 severity codes, ordering (Emergency > Debug), Display |
| `pri.rs` | 15+ | Encode: facility*8+severity, decode: extract facility/severity, boundary values |
| `timestamp.rs` | 20+ | Construction, formatting, comparison, timezone handling, nanosecond precision, edge cases (leap second, Feb 29) |
| `structured_data.rs` | 15+ | Construction, SD-ELEMENT ordering, SD-PARAM escaping, equality, display |
| `message.rs` | 10+ | SyslogMessage construction, field accessors, builder pattern, validation |
| `hostname.rs` | 10+ | FQDN validation, IPv4, IPv6, length limits, PRINTUSASCII check |
| `app_name.rs` | 8+ | Length 1-48, PRINTUSASCII validation, edge cases |
| `proc_id.rs` | 8+ | Length 1-128, PRINTUSASCII validation |
| `message_id.rs` | 8+ | Length 1-32, PRINTUSASCII validation |

#### syslog-parse

| Module | Tests | Focus |
|--------|-------|-------|
| `rfc5424/parser.rs` | 50+ | Full message parsing (all PRI/TS/SD/MSG combinations from Section 2.1) |
| `rfc5424/header.rs` | 25+ | Individual header field parsing functions |
| `rfc5424/structured_data.rs` | 20+ | SD-ELEMENT parsing, escaping, nested structures |
| `rfc5424/msg.rs` | 10+ | MSG body extraction, BOM detection |
| `rfc5424/serializer.rs` | 20+ | Serialization of all field combinations, roundtrip tests |
| `rfc3164/parser.rs` | 20+ | BSD format parsing, timestamp variants, hostname extraction |
| `rfc3164/heuristics.rs` | 10+ | Format detection, timestamp guessing |
| `detect.rs` | 10+ | Auto-detection accuracy across message variants |
| `octet_counting.rs` | 15+ | Frame encode/decode, partial reads, boundary cases |
| `parse_mode.rs` | 5+ | Strict vs lenient mode behavior differences |
| `error.rs` | 5+ | Error variant coverage, Display impl |

#### syslog-transport

| Module | Tests | Focus |
|--------|-------|-------|
| `udp/listener.rs` | 15+ | Receive loop, buffer management, metrics, ephemeral port binding |
| `udp/sender.rs` | 10+ | Send to destination, error handling |
| `tls/listener.rs` | 15+ | Accept loop, TLS handshake, connection management |
| `tls/connection.rs` | 15+ | Per-connection read loop, framing, graceful close |
| `tls/sender.rs` | 15+ | Connect, octet-counting write, reconnection |
| `tls/config.rs` | 15+ | ServerConfig construction, cipher suite selection, certificate loading |
| `tls/certs.rs` | 15+ | Certificate loading, fingerprint computation, validation |
| `framing.rs` | 15+ | Octet-counting codec, streaming decode, encode |

#### syslog-relay

| Module | Tests | Focus |
|--------|-------|-------|
| `filter.rs` | 25+ | All filter predicates: facility, severity, hostname, app-name, SD-ID, regex |
| `route.rs` | 20+ | Route matching, fan-out to multiple outputs, default route |
| `pipeline.rs` | 10+ | Stage-to-stage channel flow, backpressure propagation |
| `enrich.rs` | 10+ | SD-ELEMENT injection, metadata addition |

#### syslog-config

| Module | Tests | Focus |
|--------|-------|-------|
| `loader.rs` | 15+ | TOML parsing, env var substitution, file reading |
| `validation.rs` | 20+ | Schema validation, required fields, type checking, cross-reference validation |
| `tls.rs` | 10+ | TLS config validation (cert exists, key matches, cipher suites valid) |

#### syslog-observe

| Module | Tests | Focus |
|--------|-------|-------|
| `metrics.rs` | 10+ | Counter/gauge/histogram registration, increment, observe |
| `health.rs` | 5+ | Health check logic, readiness/liveness |

### 3.2 Property-Based Tests (proptest)

Property-based tests generate thousands of random inputs to validate invariants that must hold for all inputs. These complement hand-written test vectors.

```rust
// In syslog-parse/src/rfc5424/parser.rs (test module)

use proptest::prelude::*;

// Strategy to generate valid PRI values
fn valid_pri() -> impl Strategy<Value = u8> {
    0u8..=191
}

// Strategy to generate arbitrary byte strings
fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..65536)
}

proptest! {
    /// Parser never panics on any input
    #[test]
    fn proptest_parse_rfc5424_never_panics(input in arbitrary_bytes()) {
        let _ = parse_rfc5424(&input);
        // Test passes if we reach here without panic
    }

    /// Parser never panics on any input (RFC 3164)
    #[test]
    fn proptest_parse_rfc3164_never_panics(input in arbitrary_bytes()) {
        let _ = parse_rfc3164(&input);
    }

    /// Octet-counting decoder never panics on any input
    #[test]
    fn proptest_octet_frame_decode_never_panics(input in arbitrary_bytes()) {
        let _ = decode_octet_frame(&input);
    }

    /// Valid PRI values always decode to valid facility/severity
    #[test]
    fn proptest_pri_decode_always_valid(pri in valid_pri()) {
        let facility = pri / 8;
        let severity = pri % 8;
        assert!(facility <= 23);
        assert!(severity <= 7);
    }

    /// Serialize then parse is identity for all valid messages
    #[test]
    fn proptest_serialize_roundtrip(msg in arb_syslog_message()) {
        let serialized = serialize_rfc5424(&msg);
        let parsed = parse_rfc5424(&serialized).unwrap();
        assert_eq!(parsed.facility, msg.facility);
        assert_eq!(parsed.severity, msg.severity);
        assert_eq!(parsed.hostname, msg.hostname);
        assert_eq!(parsed.app_name, msg.app_name);
        assert_eq!(parsed.proc_id, msg.proc_id);
        assert_eq!(parsed.msg_id, msg.msg_id);
        assert_eq!(parsed.structured_data, msg.structured_data);
    }

    /// Parse result is always Ok or Err, never hangs
    /// (proptest timeout handles the "never hangs" part)
    #[test]
    fn proptest_parse_always_terminates(input in arbitrary_bytes()) {
        let result = parse_rfc5424(&input);
        assert!(result.is_ok() || result.is_err());
    }

    /// SD-PARAM escaping roundtrips correctly
    #[test]
    fn proptest_sd_param_escape_roundtrip(
        value in "[^\x00]*"  // any string without null
    ) {
        let escaped = escape_sd_param_value(&value);
        let unescaped = unescape_sd_param_value(&escaped);
        assert_eq!(unescaped, value);
    }

    /// Timestamp roundtrip preserves precision
    #[test]
    fn proptest_timestamp_roundtrip(ts in arb_syslog_timestamp()) {
        let formatted = ts.to_rfc3339();
        let parsed = SyslogTimestamp::parse(&formatted).unwrap();
        assert_eq!(parsed, ts);
    }
}
```

**Required proptest strategies (custom generators):**

| Strategy | Description |
|----------|-------------|
| `arb_syslog_message()` | Generates a valid `SyslogMessage` with random but valid field values |
| `arb_syslog_timestamp()` | Generates a valid RFC 3339 timestamp with random precision |
| `arb_structured_data()` | Generates 0-10 SD-ELEMENTs with random valid SD-IDs and SD-PARAMs |
| `arb_sd_id()` | Generates either IANA-registered or enterprise-number SD-IDs |
| `arb_printusascii(max_len)` | Generates strings of PRINTUSASCII chars within length bounds |
| `arb_hostname()` | Generates FQDNs, IPv4, IPv6, or NILVALUE |

### 3.3 Integration Tests

Integration tests exercise the cross-crate pipeline end-to-end within a single process. They live in the workspace-level `tests/` directory.

```
tests/
├── pipeline_udp_to_file.rs       # UDP ingest -> parse -> filter -> file output
├── pipeline_udp_to_tls.rs        # UDP ingest -> parse -> route -> TLS output
├── pipeline_tls_to_tls.rs        # TLS ingest -> parse -> route -> TLS output
├── pipeline_filter_drop.rs       # Messages filtered out reach drop counter, not output
├── pipeline_fanout.rs            # One message routed to multiple outputs
├── pipeline_backpressure.rs      # Slow output causes queue fill, backpressure policy applied
├── pipeline_graceful_shutdown.rs # SIGTERM -> drain queues -> exit
├── config_reload.rs              # SIGHUP -> reload config -> verify new routes active
├── config_validation.rs          # Invalid configs rejected with descriptive errors
├── rfc_conformance/
│   ├── rfc5424_valid.rs          # All valid test vectors from Section 2.1
│   ├── rfc5424_invalid.rs        # All invalid test vectors from Section 2.1
│   ├── rfc5424_examples.rs       # RFC 5424 Section 6.5 examples (EX-001 through EX-004)
│   ├── rfc5426_udp.rs            # UDP transport test vectors (UDP-001 through UDP-015)
│   ├── rfc5425_tls.rs            # TLS transport test vectors (TLS-001 through TLS-017)
│   ├── rfc5425_certs.rs          # Certificate test vectors (CERT-001 through CERT-013)
│   ├── rfc9662_ciphers.rs        # Cipher suite test vectors (CS-001 through CS-011)
│   └── rfc3164_legacy.rs         # BSD syslog test vectors (BSD-001 through BSD-007)
└── helpers/
    ├── mod.rs                    # Shared test utilities
    ├── mock_output.rs            # In-memory output that records all received messages
    ├── test_certs.rs             # Generate ephemeral test certificates (rcgen)
    ├── udp_sender.rs             # Send test messages via UDP
    ├── tls_client.rs             # Connect and send via TLS
    └── fixtures.rs               # Load test fixtures from tests/fixtures/
```

#### Integration Test Patterns

**In-process pipeline test:**

```rust
#[tokio::test]
async fn test_pipeline_udp_to_file() {
    // 1. Create a minimal config with UDP listener on ephemeral port
    // 2. Create a mock file output (in-memory Vec<SyslogMessage>)
    // 3. Start the pipeline
    // 4. Send test messages via UDP
    // 5. Wait for messages to arrive at mock output
    // 6. Assert: correct message count, correct field values, correct order
    // 7. Shutdown cleanly
}
```

**Network-level E2E test:**

```rust
#[tokio::test]
async fn test_e2e_tls_ingest_and_forward() {
    // 1. Generate ephemeral CA + server + client certs (rcgen)
    // 2. Start syslog-usg with TLS listener on ephemeral port
    // 3. Start a mock TLS receiver on another ephemeral port
    // 4. Connect TLS client, send octet-counted messages
    // 5. Verify mock receiver gets correct messages
    // 6. Verify metrics: received_total, forwarded_total match
}
```

### 3.4 Test Helpers

#### Certificate Generation (rcgen-based)

```rust
/// Generate a test CA, server cert, and client cert for integration tests.
/// All certs are ephemeral — created fresh for each test.
pub fn generate_test_certs() -> TestCerts {
    // CA: self-signed root
    // Server: signed by CA, SAN=localhost,127.0.0.1,::1
    // Client: signed by CA, CN=test-client
    // Expired: signed by CA, not_after = yesterday
    // Wrong CA: signed by a different self-signed root
}
```

#### Mock Output

```rust
/// A test output that captures all messages into a shared Vec.
/// Supports configurable latency simulation for backpressure testing.
pub struct MockOutput {
    messages: Arc<Mutex<Vec<SyslogMessage>>>,
    delay: Option<Duration>,
}
```

#### UDP Test Sender

```rust
/// Send a single syslog message via UDP to the specified address.
/// Returns the number of bytes sent.
pub async fn send_udp(addr: SocketAddr, message: &[u8]) -> io::Result<usize>;

/// Send multiple messages via UDP in rapid succession.
pub async fn send_udp_burst(addr: SocketAddr, messages: &[&[u8]]) -> io::Result<()>;
```

---

## 4. Fuzzing Plan

### 4.1 Fuzz Targets

Each fuzz target exercises a specific parser entry point. All targets share the same invariants: no panic, no unbounded allocation, always terminates.

```
fuzz/
├── Cargo.toml
├── fuzz_targets/
│   ├── fuzz_parse_rfc5424.rs         # Full RFC 5424 message parser
│   ├── fuzz_parse_rfc3164.rs         # Legacy BSD syslog parser
│   ├── fuzz_parse_timestamp.rs       # Timestamp parser in isolation
│   ├── fuzz_parse_structured_data.rs # SD-ELEMENT/SD-PARAM parser
│   ├── fuzz_decode_octet_frame.rs    # Octet-counting frame decoder
│   ├── fuzz_parse_pri.rs             # PRI field parser
│   ├── fuzz_detect_format.rs         # RFC 5424 vs 3164 auto-detection
│   └── fuzz_serialize_roundtrip.rs   # Parse then serialize, verify no crash
└── corpus/
    ├── rfc5424/                       # Seed corpus: valid messages
    ├── rfc3164/                       # Seed corpus: BSD messages
    ├── timestamps/                    # Seed corpus: timestamp strings
    ├── structured_data/               # Seed corpus: SD strings
    └── octet_frames/                  # Seed corpus: framed messages
```

### 4.2 Fuzz Target Implementation Pattern

```rust
// fuzz/fuzz_targets/fuzz_parse_rfc5424.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Invariant 1: Never panic
    let result = syslog_parse::parse_rfc5424(data);

    // Invariant 2: Result is always Ok or Err
    match result {
        Ok(msg) => {
            // Invariant 3: If parse succeeds, all fields are valid
            assert!(msg.facility.code() <= 23);
            assert!(msg.severity.code() <= 7);
            assert!(msg.version == 1);

            // Invariant 4: Serialization does not panic
            let _ = syslog_parse::serialize_rfc5424(&msg);

            // Invariant 5: Hostname length within bounds
            if let Some(ref h) = msg.hostname {
                assert!(h.len() <= 255);
            }
            if let Some(ref a) = msg.app_name {
                assert!(a.len() <= 48);
            }
            if let Some(ref p) = msg.proc_id {
                assert!(p.len() <= 128);
            }
            if let Some(ref m) = msg.msg_id {
                assert!(m.len() <= 32);
            }
        }
        Err(_) => {
            // Parse failure is acceptable — the input was arbitrary bytes
        }
    }
});
```

### 4.3 Fuzz Invariants Summary

| Target | Invariants |
|--------|-----------|
| `fuzz_parse_rfc5424` | No panic; Ok or Err; valid field bounds on Ok; serialization does not panic |
| `fuzz_parse_rfc3164` | No panic; Ok or Err; translated fields within RFC 5424 bounds |
| `fuzz_parse_timestamp` | No panic; Ok or Err; valid date/time components on Ok |
| `fuzz_parse_structured_data` | No panic; Ok or Err; no unbounded Vec growth; all SD-PARAMs properly escaped on Ok |
| `fuzz_decode_octet_frame` | No panic; Ok or Err or NeedMoreData; never allocates > configured max message size |
| `fuzz_parse_pri` | No panic; Ok or Err; Ok value in 0..=191 |
| `fuzz_detect_format` | No panic; always returns Rfc5424 or Rfc3164 or Unknown |
| `fuzz_serialize_roundtrip` | If parse(input) = Ok(msg), then parse(serialize(msg)) = Ok(msg2) where msg ~= msg2 |

### 4.4 Seed Corpus

The seed corpus must include:
- All RFC 5424 Section 6.5 examples (EX-001 through EX-004)
- All valid test vectors from Section 2.1 of this document
- Minimal valid messages with all NILVALUE fields
- Maximum-length field values
- Messages with 0, 1, 5, 50 SD-ELEMENTs
- Messages with escaped characters in SD-PARAMs
- Real-world messages from the interop corpus (Section 7)
- Known edge cases: empty input, single byte, PRI-only, truncated at each field boundary

### 4.5 Bounded Allocation Enforcement

Fuzz targets run under a custom allocator (or with `ASAN_OPTIONS`) that detects:
- Allocations exceeding 1 MB (no single message should require this)
- Total allocations exceeding 10 MB per parse invocation
- Memory leaks (allocation without matching deallocation)

```rust
// In fuzz target, enforce max allocation size:
#[global_allocator]
static ALLOC: cap::Cap<std::alloc::System> =
    cap::Cap::new(std::alloc::System, 10 * 1024 * 1024); // 10 MB cap
```

### 4.6 CI Integration

- **Nightly schedule:** Each fuzz target runs for 30 minutes (total 4 hours for all targets)
- **Pre-release:** Each fuzz target runs for 2 hours (total 16 hours)
- **Crash triage:** Any crash is automatically filed as a P0 bug
- **Corpus growth:** New corpus entries discovered during CI runs are committed back to the repository
- **Coverage tracking:** `cargo-fuzz coverage` run weekly to identify unreached parser paths

---

## 5. Benchmark Plan

### 5.1 Criterion Benchmarks

All benchmarks live in `benches/` and use the `criterion` crate for statistical rigor (configurable warm-up, sample size, outlier detection, regression comparison).

```
benches/
├── Cargo.toml
├── parse_rfc5424.rs        # RFC 5424 parser benchmarks
├── parse_rfc3164.rs        # RFC 3164 parser benchmarks
├── serialize.rs            # Serializer benchmarks
├── octet_framing.rs        # Frame encode/decode benchmarks
├── filter.rs               # Filter evaluation benchmarks
├── route.rs                # Route matching benchmarks
├── structured_data.rs      # SD parsing in isolation
└── timestamp.rs            # Timestamp parsing in isolation
```

### 5.2 Benchmark Definitions

#### Parser Benchmarks

| Benchmark | Input | Baseline Target | Description |
|-----------|-------|-----------------|-------------|
| `bench_parse_rfc5424_minimal` | `<0>1 - - - - - -` | < 500 ns | Smallest valid RFC 5424 message |
| `bench_parse_rfc5424_no_sd` | `<34>1 2023-10-11T22:14:15.003Z host app 1234 ID47 - Message text` | < 1 us | Typical message without structured data |
| `bench_parse_rfc5424_typical` | Full message with 2 SD-ELEMENTs (from RFC 5424 Example 3) | < 2 us (p50 target) | Realistic production message |
| `bench_parse_rfc5424_complex` | Message with 10 SD-ELEMENTs, max-length fields | < 10 us (p99 target) | Worst-case realistic message |
| `bench_parse_rfc5424_escaped_sd` | SD-PARAM with multiple escapes | < 3 us | Escape handling overhead |
| `bench_parse_rfc3164_typical` | `<34>Oct 11 22:14:15 mymachine su: 'su root' failed` | < 1 us | Typical BSD syslog |
| `bench_parse_auto_detect` | Both 5424 and 3164 messages | < overhead of format-specific parse | Auto-detection overhead |

#### Serializer Benchmarks

| Benchmark | Input | Baseline Target | Description |
|-----------|-------|-----------------|-------------|
| `bench_serialize_rfc5424_minimal` | Minimal SyslogMessage (all NILVALUE) | < 300 ns | Minimal serialization |
| `bench_serialize_rfc5424_typical` | Typical SyslogMessage with 2 SD-ELEMENTs | < 1 us | Realistic serialization |
| `bench_serialize_rfc5424_complex` | Complex SyslogMessage with 10 SD-ELEMENTs | < 5 us | Worst-case serialization |

#### Framing Benchmarks

| Benchmark | Input | Baseline Target | Description |
|-----------|-------|-----------------|-------------|
| `bench_octet_frame_encode` | 512-byte message | < 100 ns | Frame encoding (prepend length) |
| `bench_octet_frame_decode` | Octet-counted frame with 512-byte payload | < 200 ns | Frame decoding |
| `bench_octet_frame_decode_stream` | 100 concatenated frames in a byte buffer | < 15 us | Streaming decode of multiple frames |

#### Pipeline Component Benchmarks

| Benchmark | Input | Baseline Target | Description |
|-----------|-------|-----------------|-------------|
| `bench_filter_single_severity` | Message + severity filter | < 50 ns | Single-predicate filter |
| `bench_filter_complex` | Message + 5-predicate filter (severity + facility + hostname regex + app-name + SD-ID) | < 500 ns | Multi-predicate filter |
| `bench_route_single` | Message + 1 route rule | < 100 ns | Single route evaluation |
| `bench_route_fanout_10` | Message + 10 route rules, matching 3 | < 500 ns | Fan-out route evaluation |
| `bench_pri_encode` | facility=4, severity=2 | < 10 ns | PRI value computation |
| `bench_pri_decode` | pri=34 | < 10 ns | facility/severity extraction |
| `bench_timestamp_parse` | `2023-10-11T22:14:15.003000Z` | < 200 ns | Timestamp parsing in isolation |
| `bench_timestamp_format` | SyslogTimestamp value | < 200 ns | Timestamp formatting |

### 5.3 Benchmark Methodology

**Statistical rigor:**
- Warm-up: 3 seconds per benchmark
- Measurement: 5 seconds per benchmark, 100+ iterations minimum
- Outlier detection: criterion's default outlier classification
- Reports: HTML reports with throughput graphs stored as CI artifacts

**Regression detection:**
- Each PR compares against the `main` branch baseline
- Regression threshold: **10% slowdown** triggers CI warning
- Regression threshold: **25% slowdown** triggers CI failure
- Baselines are stored in `target/criterion/` and committed as CI artifacts (not in-repo)

**Environment standardization:**
- Benchmarks run on dedicated CI runners (not shared)
- CPU frequency scaling disabled (`performance` governor on Linux)
- Process pinned to a single core to reduce variance
- No concurrent workloads during benchmark runs

### 5.4 Throughput Benchmarks

Beyond per-operation latency, we validate sustained throughput:

| Benchmark | Configuration | Target | Measurement |
|-----------|--------------|--------|-------------|
| `bench_parse_throughput_rfc5424` | Parse 100,000 typical messages sequentially | > 100,000 msg/sec | Wall-clock time / message count |
| `bench_parse_throughput_mixed` | Parse 100,000 messages (70% 5424, 30% 3164) | > 80,000 msg/sec | Wall-clock time / message count |
| `bench_serialize_throughput` | Serialize 100,000 typical messages | > 100,000 msg/sec | Wall-clock time / message count |

---

## 6. Interoperability Test Plan

### 6.1 Test Environment

A Docker Compose environment provides reproducible interop testing with real syslog implementations.

```yaml
# tests/interop/docker-compose.yml
services:
  syslog-usg:
    build: ../..
    ports:
      - "10514:514/udp"
      - "16514:6514/tcp"
    volumes:
      - ./configs/syslog-usg.toml:/etc/syslog-usg/syslog-usg.toml
      - ./certs:/certs

  rsyslog-sender:
    image: rsyslog/syslog_appliance_alpine:latest
    volumes:
      - ./configs/rsyslog-sender.conf:/etc/rsyslog.conf

  rsyslog-receiver:
    image: rsyslog/syslog_appliance_alpine:latest
    volumes:
      - ./configs/rsyslog-receiver.conf:/etc/rsyslog.conf

  syslog-ng-sender:
    image: balabit/syslog-ng:latest
    volumes:
      - ./configs/syslog-ng.conf:/etc/syslog-ng/syslog-ng.conf

  traffic-generator:
    build: ./traffic-gen
    depends_on:
      - syslog-usg
```

### 6.2 Interop Test Scenarios

#### Inbound (Other -> syslog-usg)

| Test ID | Scenario | Protocol | Validation |
|---------|----------|----------|------------|
| INTEROP-IN-001 | rsyslog sends RFC 5424 over UDP | UDP | syslog-usg parses correctly, all fields match |
| INTEROP-IN-002 | rsyslog sends RFC 5424 over TLS | TLS | TLS handshake succeeds, messages parsed correctly |
| INTEROP-IN-003 | rsyslog sends RFC 3164 (legacy) over UDP | UDP | syslog-usg auto-detects 3164, translates to 5424 |
| INTEROP-IN-004 | syslog-ng sends RFC 5424 over UDP | UDP | syslog-usg parses correctly |
| INTEROP-IN-005 | syslog-ng sends RFC 5424 over TLS | TLS | TLS handshake succeeds, messages parsed correctly |
| INTEROP-IN-006 | syslog-ng sends RFC 5424 with structured data | TLS | SD-ELEMENTs parsed correctly, params match |
| INTEROP-IN-007 | logger(1) sends via UDP | UDP | Standard Linux logger utility messages parsed |

#### Outbound (syslog-usg -> Other)

| Test ID | Scenario | Protocol | Validation |
|---------|----------|----------|------------|
| INTEROP-OUT-001 | syslog-usg forwards to rsyslog over TLS | TLS | rsyslog receives and logs correctly |
| INTEROP-OUT-002 | syslog-usg forwards to rsyslog over UDP | UDP | rsyslog receives and logs correctly |
| INTEROP-OUT-003 | syslog-usg forwards to syslog-ng over TLS | TLS | syslog-ng receives and logs correctly |
| INTEROP-OUT-004 | syslog-usg relays: rsyslog -> syslog-usg -> rsyslog | TLS/UDP | End-to-end message fidelity preserved |

#### Real-World Message Sources

| Test ID | Source | Description | Key Validation |
|---------|--------|-------------|----------------|
| REAL-001 | Linux kernel | `kern.warn` messages from dmesg | Facility=0, severity=4, parse OK |
| REAL-002 | systemd-journald | Messages forwarded from journald | RFC 5424 with structured data from journald |
| REAL-003 | Cisco IOS | Network device syslog (often RFC 3164) | Legacy format auto-detected, timestamp parsed |
| REAL-004 | Palo Alto PAN-OS | Firewall logs with structured data | Complex SD-ELEMENTs parsed correctly |
| REAL-005 | AWS CloudWatch | CloudWatch agent syslog forwarding | Non-standard timestamp handling |
| REAL-006 | nginx | Access/error log via syslog output | app-name extraction, message body |
| REAL-007 | PostgreSQL | Database log messages | Multi-line handling (if applicable) |
| REAL-008 | Docker syslog driver | Container logs via syslog driver | Structured data with container metadata |

### 6.3 Interop Validation Method

For each interop test:
1. Send a known message from the source
2. Capture the message as received by syslog-usg (via debug log or mock output)
3. Compare parsed fields against expected values
4. Verify no parse errors in metrics
5. For outbound tests: verify the downstream receiver logs the message correctly

Validation scripts are written in Python or shell and check:
- Message count (sent == received, within acceptable UDP loss tolerance)
- Field-by-field comparison (facility, severity, timestamp, hostname, app-name, procid, msgid, SD, MSG)
- No unexpected parse errors or connection failures

---

## 7. Test Corpus

### 7.1 Canonical Test Messages

Each message is assigned an ID for cross-reference from test cases.

#### Valid RFC 5424 Messages

```
CORPUS-V001 (Minimal valid):
<0>1 - - - - - -

CORPUS-V002 (All NILVALUE):
<0>1 - - - - - -

CORPUS-V003 (Typical with SD):
<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry

CORPUS-V004 (Multiple SD-ELEMENTs):
<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][examplePriority@32473 class="high"]

CORPUS-V005 (With BOM):
<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] <BOM>An application event log entry...

CORPUS-V006 (No MSG):
<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 [timeQuality tzKnown="1" isSynced="1"]

CORPUS-V007 (Maximum PRI):
<191>1 2023-10-11T22:14:15Z host app pid msgid - Message

CORPUS-V008 (Negative timezone offset):
<34>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.

CORPUS-V009 (IPv6 hostname):
<34>1 2023-10-11T22:14:15Z 2001:db8::1 app - - - Message from IPv6 host

CORPUS-V010 (IANA SD-IDs):
<34>1 2023-10-11T22:14:15Z host app - - [timeQuality tzKnown="1" isSynced="1" syncAccuracy="60000"][origin ip="192.168.1.1" enterpriseId="32473"][meta sequenceId="1" sysUpTime="123456" language="en"] Message with IANA SD-IDs

CORPUS-V011 (Max-length fields):
<191>1 2023-10-11T22:14:15.123456789Z <255-char-hostname> <48-char-appname> <128-char-procid> <32-char-msgid> - Maximum length fields

CORPUS-V012 (SD-PARAM with all escape types):
<34>1 2023-10-11T22:14:15Z host app - - [test@1 q="say \"hello\"" b="back\\slash" c="close\]bracket"] Escaped SD params

CORPUS-V013 (Empty MSG, SD present):
<34>1 2023-10-11T22:14:15Z host app - - [id@1 k="v"]

CORPUS-V014 (Large number of SD-ELEMENTs):
<34>1 2023-10-11T22:14:15Z host app - - [a@1 k="v"][b@1 k="v"][c@1 k="v"]...[z@1 k="v"]

CORPUS-V015 (Nanosecond precision timestamp):
<34>1 2023-10-11T22:14:15.123456789Z host app - - - Nanosecond timestamp
```

#### Valid RFC 3164 Messages

```
CORPUS-L001 (Typical BSD):
<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8

CORPUS-L002 (Single-digit day):
<34>Oct  1 22:14:15 mymachine su: message

CORPUS-L003 (With PID):
<13>Feb 25 14:09:07 myhost myapp[12345]: Application started

CORPUS-L004 (Minimal):
<34>Oct 11 22:14:15 host msg

CORPUS-L005 (No hostname):
<34>Oct 11 22:14:15 message with no hostname marker
```

#### Invalid / Malformed Messages

```
CORPUS-E001 (Empty):
(empty string)

CORPUS-E002 (Single byte):
<

CORPUS-E003 (PRI only):
<34>

CORPUS-E004 (Invalid PRI value):
<999>1 - - - - - -

CORPUS-E005 (PRI > 191):
<192>1 - - - - - -

CORPUS-E006 (No version):
<34>- - - - - -

CORPUS-E007 (Bad timestamp):
<34>1 not-a-timestamp - - - - -

CORPUS-E008 (Truncated mid-header):
<34>1 2023-10-11T22:

CORPUS-E009 (Truncated mid-SD):
<34>1 2023-10-11T22:14:15Z host app - - [id@1 k="v

CORPUS-E010 (Oversized, 1MB of 'A'):
<34>1 - - - - - - AAAA...AAAA (1,048,576 bytes)

CORPUS-E011 (NULL bytes in PRI):
<3\x004>1 - - - - - -

CORPUS-E012 (Non-ASCII in header fields):
<34>1 2023-10-11T22:14:15Z host\xFF app - - - msg

CORPUS-E013 (Negative PRI):
<-1>1 - - - - - -

CORPUS-E014 (Version 0):
<34>0 - - - - - -

CORPUS-E015 (Missing SP between fields):
<34>12023-10-11T22:14:15Zhost app - - - msg

CORPUS-E016 (Invalid SD: unescaped quote):
<34>1 - - - - - [id@1 k="val"ue"] msg

CORPUS-E017 (Feb 29 non-leap year):
<34>1 2023-02-29T12:00:00Z host app - - - msg

CORPUS-E018 (Octet-counting: length mismatch):
50 <34>1 - - - - - - short
```

### 7.2 Corpus File Format

Each corpus file is a single raw syslog message (binary). Metadata (expected parse result, RFC section, test ID) is stored in a companion `.json` file:

```json
{
  "id": "CORPUS-V003",
  "description": "Typical with SD",
  "rfc": "5424",
  "section": "6.5",
  "expected": "ok",
  "expected_fields": {
    "facility": 20,
    "severity": 5,
    "version": 1,
    "hostname": "mymachine.example.com",
    "app_name": "evntslog",
    "proc_id": null,
    "msg_id": "ID47",
    "sd_element_count": 1,
    "msg_starts_with": "An application event"
  }
}
```

---

## 8. CI/CD Integration

### 8.1 Pipeline Stages

```
┌──────────────────────────────────────────────────┐
│  Every Commit / PR                                │
│  ┌─────────┐ ┌──────────┐ ┌────────────────────┐ │
│  │ clippy   │ │ fmt      │ │ cargo audit        │ │
│  │ --all    │ │ --check  │ │ (advisory check)   │ │
│  └─────────┘ └──────────┘ └────────────────────┘ │
│  ┌──────────────────────────────────────────────┐ │
│  │ cargo test --workspace                       │ │
│  │ (unit + integration + conformance)           │ │
│  └──────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────┐ │
│  │ criterion benchmarks (compare against main)  │ │
│  │ Warn on >10% regression, fail on >25%        │ │
│  └──────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│  Nightly Schedule                                 │
│  ┌──────────────────────────────────────────────┐ │
│  │ cargo fuzz run (30 min per target)           │ │
│  └──────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────┐ │
│  │ Full benchmark suite (extended run)          │ │
│  └──────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────┐ │
│  │ cargo-fuzz coverage report                   │ │
│  └──────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│  Weekly Schedule                                  │
│  ┌──────────────────────────────────────────────┐ │
│  │ Docker Compose interop tests                 │ │
│  │ (rsyslog, syslog-ng)                         │ │
│  └──────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────┐ │
│  │ Load test: 100k msg/sec sustained for 10 min │ │
│  └──────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│  Pre-Release                                      │
│  ┌──────────────────────────────────────────────┐ │
│  │ Extended fuzz (2 hr per target)              │ │
│  └──────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────┐ │
│  │ Full interop suite                           │ │
│  └──────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────┐ │
│  │ Load test: 100k msg/sec sustained for 1 hr   │ │
│  └──────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────┐ │
│  │ Memory leak validation (valgrind/heaptrack)  │ │
│  └──────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

### 8.2 Platform Matrix

| Platform | Tier | CI Actions |
|----------|------|------------|
| Linux x86_64 (glibc) | Primary | Full test suite, benchmarks, fuzz, interop |
| Linux aarch64 (glibc) | Primary | Full test suite (no benchmarks — different hardware baseline) |
| Linux x86_64 (musl) | Primary | Full test suite, static binary build verification |
| macOS x86_64 | Secondary | Full test suite |
| macOS aarch64 | Secondary | Full test suite |

### 8.3 Test Execution Times (Budget)

| Test Category | Expected Duration | Parallelism |
|---------------|-------------------|-------------|
| Unit tests (all crates) | < 30 seconds | Cargo's native parallelism |
| Integration tests | < 2 minutes | Per-test parallelism with ephemeral ports |
| Conformance tests | < 30 seconds | Fully parallel (pure parsing, no I/O) |
| Benchmarks (PR comparison) | < 5 minutes | Sequential (to avoid interference) |
| Fuzz (nightly, per target) | 30 minutes | One target per core |
| Interop (weekly) | < 15 minutes | Docker Compose sequential |
| Load test (weekly) | 10 minutes | Single instance |

**Total CI time budget per PR:** < 10 minutes (unit + integration + conformance + benchmark comparison).

---

## 9. Coverage and Quality Gates

### 9.1 Coverage Targets

| Crate | Line Coverage Target | Branch Coverage Target | Rationale |
|-------|---------------------|----------------------|-----------|
| `syslog-proto` | >= 95% | >= 90% | Core types must be thoroughly validated |
| `syslog-parse` | >= 90% | >= 85% | Parser correctness is critical; every code path matters |
| `syslog-transport` | >= 80% | >= 70% | Network code has inherent test difficulty (TLS, timeouts) |
| `syslog-relay` | >= 85% | >= 80% | Filter/route logic must be covered |
| `syslog-config` | >= 85% | >= 80% | Config validation protects against runtime failures |
| `syslog-observe` | >= 75% | >= 65% | Metrics plumbing, less critical |
| `syslog-server` | >= 70% | >= 60% | Binary entrypoint, lifecycle management |
| **Workspace total** | >= 80% | >= 75% | Phase 01 requirement (Section 5.7) |

### 9.2 Quality Gates (PR Merge Requirements)

| Gate | Condition | Enforcement |
|------|-----------|-------------|
| All tests pass | `cargo test --workspace` exits 0 | CI required check |
| No clippy warnings | `cargo clippy --all-targets --all-features -- -D warnings` exits 0 | CI required check |
| Formatting | `cargo fmt --all -- --check` exits 0 | CI required check |
| No known vulnerabilities | `cargo audit` exits 0 | CI required check |
| No benchmark regression > 25% | criterion comparison against main | CI required check |
| Benchmark regression 10-25% | criterion comparison against main | CI warning (review required) |
| Coverage does not decrease | tarpaulin/llvm-cov comparison | CI advisory (not blocking) |

### 9.3 RFC Compliance Traceability

Every test case in Section 2 maps to a specific RFC section. This traceability is maintained in two ways:

1. **Test annotations:** Each test function includes a doc comment referencing the RFC section:

```rust
/// RFC 5424 Section 6.2.1: PRI value MUST be 0-191
/// Test ID: PRI-004
#[test]
fn test_parse_rfc5424_rejects_pri_value_192() {
    let result = parse_rfc5424(b"<192>1 - - - - - -");
    assert!(result.is_err());
}
```

2. **Compliance matrix:** A generated report maps RFC sections to test IDs, updated on each CI run. The report confirms:
   - Every MUST requirement has at least one test
   - Every SHOULD requirement has at least one test
   - Coverage gaps are documented and tracked

### 9.4 Test Count Estimates

| Category | Estimated Count |
|----------|----------------|
| Unit tests (syslog-proto) | ~100 |
| Unit tests (syslog-parse) | ~200 |
| Unit tests (syslog-transport) | ~100 |
| Unit tests (syslog-relay) | ~80 |
| Unit tests (syslog-config) | ~60 |
| Unit tests (syslog-observe) | ~30 |
| Unit tests (syslog-server) | ~20 |
| Property-based tests | ~30 strategies, 10,000+ generated cases each |
| Integration tests | ~40 |
| Conformance test vectors | ~150 (from Section 2) |
| Fuzz targets | 8 |
| Benchmarks | ~25 |
| Interop scenarios | ~15 |
| **Total hand-written tests** | **~825+** |

---

## Appendix A: Load Test Procedure

### A.1 Traffic Generator

A purpose-built Rust binary (`tests/load/traffic-gen/`) sends syslog messages at configurable rates:

```
traffic-gen --target 127.0.0.1:514 \
            --protocol udp \
            --rate 100000 \
            --duration 600s \
            --message-size 512 \
            --format rfc5424 \
            --report-interval 10s
```

### A.2 Load Test Scenarios

| Scenario | Protocol | Rate | Duration | Pass Criteria |
|----------|----------|------|----------|---------------|
| LT-001: UDP sustained | UDP | 100k msg/sec | 10 min | 0 dropped (at syslog-usg), RSS < 256 MB |
| LT-002: TLS sustained | TLS | 50k msg/sec | 10 min | 0 dropped, RSS < 256 MB, 100 connections |
| LT-003: Mixed protocol | UDP + TLS | 75k + 25k | 10 min | 0 dropped, RSS < 256 MB |
| LT-004: Burst absorption | UDP | 200k msg/sec burst, 3s on / 3s off | 5 min | Queue absorbs bursts, no OOM |
| LT-005: Backpressure | UDP | 100k msg/sec, slow output (10k msg/sec) | 5 min | Queue fills, policy applied, no crash |
| LT-006: Connection churn | TLS | 10k msg/sec, reconnect every 100 msgs | 5 min | No connection leak, no crash |

### A.3 Metrics to Capture During Load Test

- `syslog_messages_received_total` (rate)
- `syslog_messages_forwarded_total` (rate)
- `syslog_messages_dropped_total` (should be 0 for LT-001 through LT-003)
- `syslog_parse_duration_seconds` (p50, p99, max)
- `syslog_queue_depth` (max observed)
- Process RSS (via `/proc/self/status` or `ps`)
- CPU utilization (via `top` or `/proc/self/stat`)
- System-level: UDP receive buffer overflows (`netstat -su`)

---

## Appendix B: Test Certificate Generation

Integration and interop tests require TLS certificates. These are generated at test time using `rcgen` (for Rust integration tests) or `openssl` CLI (for Docker-based interop tests).

### B.1 Certificate Hierarchy

```
Test Root CA (self-signed, RSA 2048)
├── Server Certificate (SAN: localhost, 127.0.0.1, ::1)
├── Client Certificate (CN: test-client)
├── Expired Server Certificate (not_after: yesterday)
├── Wrong-CA Server Certificate (signed by a different root)
└── Wildcard Certificate (SAN: *.test.local)

Separate Self-Signed Certificate (no CA relationship)
```

### B.2 Generation Script

```bash
#!/bin/bash
# tests/fixtures/certs/generate.sh
# Regenerate test certificates. Run when certificates expire or algo changes.

set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"

# Root CA
openssl req -x509 -newkey rsa:2048 -keyout "$DIR/ca.key" -out "$DIR/ca.pem" \
  -days 3650 -nodes -subj "/CN=Test Root CA"

# Server cert
openssl req -newkey rsa:2048 -keyout "$DIR/server.key" -out "$DIR/server.csr" \
  -nodes -subj "/CN=localhost"
openssl x509 -req -in "$DIR/server.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" \
  -CAcreateserial -out "$DIR/server.pem" -days 3650 \
  -extfile <(echo "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1")

# Client cert
openssl req -newkey rsa:2048 -keyout "$DIR/client.key" -out "$DIR/client.csr" \
  -nodes -subj "/CN=test-client"
openssl x509 -req -in "$DIR/client.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" \
  -CAcreateserial -out "$DIR/client.pem" -days 3650

# Expired cert
openssl req -newkey rsa:2048 -keyout "$DIR/expired.key" -out "$DIR/expired.csr" \
  -nodes -subj "/CN=expired"
openssl x509 -req -in "$DIR/expired.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" \
  -CAcreateserial -out "$DIR/expired.pem" -days 0

# Wrong CA
openssl req -x509 -newkey rsa:2048 -keyout "$DIR/wrong_ca.key" \
  -out "$DIR/wrong_ca.pem" -days 3650 -nodes -subj "/CN=Wrong CA"
openssl req -newkey rsa:2048 -keyout "$DIR/wrong_ca_server.key" \
  -out "$DIR/wrong_ca_server.csr" -nodes -subj "/CN=wrong-ca-server"
openssl x509 -req -in "$DIR/wrong_ca_server.csr" \
  -CA "$DIR/wrong_ca.pem" -CAkey "$DIR/wrong_ca.key" \
  -CAcreateserial -out "$DIR/wrong_ca_server.pem" -days 3650

# Self-signed (no CA)
openssl req -x509 -newkey rsa:2048 -keyout "$DIR/self_signed.key" \
  -out "$DIR/self_signed.pem" -days 3650 -nodes -subj "/CN=self-signed"

# Cleanup CSRs
rm -f "$DIR"/*.csr "$DIR"/*.srl
```

---

## Appendix C: Glossary of Test Terms

| Term | Definition |
|------|------------|
| **Test vector** | A specific input/output pair derived from an RFC specification |
| **Conformance test** | A test that validates behavior against a specific RFC MUST or SHOULD requirement |
| **Property-based test** | A test that generates random inputs and checks that invariants hold for all of them |
| **Fuzz target** | A function that accepts arbitrary bytes and validates safety invariants |
| **Seed corpus** | A collection of known-interesting inputs used to bootstrap coverage-guided fuzzing |
| **Baseline** | A reference benchmark measurement against which regressions are detected |
| **Interop test** | A test that validates compatibility with a real third-party syslog implementation |
| **Load test** | A test that validates sustained throughput and resource consumption under stress |
| **Quality gate** | A CI check that must pass before a PR can be merged |
| **Ephemeral port** | A port assigned by the OS (port 0), used in tests to avoid port conflicts |
