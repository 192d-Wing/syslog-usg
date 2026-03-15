# RFC Compliance Matrix

**Last updated:** 2026-03-14

This document tracks which RFCs syslog-usg implements, the level of compliance, and where the implementation lives.

---

## Core Protocol

### RFC 5424 — The Syslog Protocol

**Status: Fully Implemented**
**Crates:** `syslog-proto`, `syslog-parse`, `syslog-server`

| Section | Requirement | Level | Implementation |
|---------|-------------|-------|----------------|
| §6.1 | Message size SHOULD be ≤2048 octets | SHOULD | Convention constant `MAX_MESSAGE_SIZE = 2048` in `syslog-mgmt`; transport layer default is 64 KiB (configurable) |
| §6.2.1 | PRI value 0–191, Facility 0–23, Severity 0–7 | MUST | `syslog-proto` `Facility`/`Severity` enums, parser validates range |
| §6.2.2 | VERSION = "1" | MUST | Parser validates, serializer emits "1" |
| §6.2.3 | TIMESTAMP in RFC 3339 format or NILVALUE | MUST | `time` crate formatting, NILVALUE ("-") supported |
| §6.2.4 | HOSTNAME ≤255 printable US-ASCII | MUST | Length and character validation in types |
| §6.2.5 | APP-NAME ≤48 printable US-ASCII | MUST | Length and character validation in types |
| §6.2.6 | PROCID ≤128 printable US-ASCII | MUST | Length and character validation in types |
| §6.2.7 | MSGID ≤32 printable US-ASCII | MUST | Length and character validation in types |
| §6.3 | STRUCTURED-DATA format | MUST | Full SD-ELEMENT/SD-PARAM parsing and serialization |
| §6.3.2 | SD-ID prohibits '=', SP, ']', '"' | MUST | Validated in parser and constructor |
| §6.3.3 | SD-PARAM value escaping ('"', '\\', ']') | MUST | Escape/unescape in parser and serializer |
| §6.4 | MSG encoding UTF-8 or other with BOM | MAY | UTF-8 assumed; BOM detection supported |

**Implementation limits (not RFC-mandated):** SD-ELEMENT count capped at 128, SD-PARAM count per element at 64, PARAM-VALUE at 8192 bytes. These are defensive limits to bound resource allocation.

### RFC 3164 — BSD Syslog Protocol (Legacy)

**Status: Best-Effort Parser**
**Crate:** `syslog-parse`

Best-effort heuristic parser with fallback for legacy BSD syslog messages. Not a conformance target — implemented for interoperability with legacy systems. BSD timestamps lack year heuristic and are returned as NILVALUE.

---

## Transport

### RFC 5425 — TLS Transport Mapping for Syslog

**Status: Implemented**
**Crates:** `syslog-transport`, `syslog-server`

| Section | Requirement | Level | Implementation |
|---------|-------------|-------|----------------|
| §4.3 | Octet-counting framing | MUST | `OctetCountingCodec` in `syslog-transport` |
| §5.2 | TLS with server certificate | MUST | `rustls` server config with cert chain |
| §5.2 | Mutual TLS (client certificate) | SHOULD | `WebPkiClientVerifier` with CA bundle validation when `client_auth` is enabled |

### RFC 5426 — Transmission of Syslog Messages over UDP

**Status: Implemented**
**Crate:** `syslog-transport`

| Section | Requirement | Level | Implementation |
|---------|-------------|-------|----------------|
| §3.1 | One message per UDP datagram | MUST | `UdpListener` reads one datagram at a time |
| §3.6 | Handle message bursts | SHOULD | Bounded channel with `try_send()` drop on overflow; configurable `SO_RCVBUF` |

### RFC 6587 — Transmission of Syslog Messages over TCP

**Status: Implemented (Octet-Counting Only)**
**Crate:** `syslog-transport`

| Section | Requirement | Level | Implementation |
|---------|-------------|-------|----------------|
| §3.4.1 | SYSLOG-FRAME = MSG-LEN SP SYSLOG-MSG | MUST | `OctetCountingCodec` with validated length prefix |
| §3.4.2 | Non-transparent framing (LF-delimited) | MAY | **Not implemented** — only octet-counting is supported. Senders must be configured for octet-counting framing. |

### RFC 6012 — DTLS Transport Mapping for Syslog

**Status: Types and Session Tracking (Plaintext UDP Fallback)**
**Crate:** `syslog-transport`

| Section | Requirement | Level | Implementation |
|---------|-------------|-------|----------------|
| §4 | DTLS session state per peer | — | Type definitions and session tracking; listener falls back to plaintext UDP (no pure-Rust DTLS library available) |

Configuration is accepted but the listener is skipped at runtime. See security review F-07.

---

## Security & Cipher Suites

### RFC 9662 — Updates to the TLS Cipher Suites in Secure Syslog

**Status: Implemented**
**Crate:** `syslog-transport`

| Requirement | Level | Implementation |
|-------------|-------|----------------|
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 required | MUST | Explicitly pinned in `build_server_config()` via `CryptoProvider` with GCM-only TLS 1.2 suites; verified by `rfc9662_cipher_suites_pinned` test |
| TLS_RSA_WITH_AES_128_CBC_SHA (legacy) | MUST | **Not supported** — `rustls` deliberately excludes static RSA key exchange (no forward secrecy). Acceptable: RFC 9662 marks this as legacy/migration-only and the ECDHE suite is the SHOULD-prefer suite. |
| 0-RTT disabled | MUST | Disabled by default in `rustls` `ServerConfig` (server-side 0-RTT not supported by rustls) |

### RFC 5848 — Signed Syslog Messages

**Status: Substantially Implemented (see deviations)**
**Crates:** `syslog-sign`, `syslog-relay`, `syslog-config`

| Section | Requirement | Level | Implementation |
|---------|-------------|-------|----------------|
| §4.2 | VER field (version + hash algo + signature scheme) | MUST | `SignatureBlock` type with `Version`, `HashAlgorithm`, `SignatureScheme` |
| §4.2.1 | SHA-1 and SHA-256 hash algorithms | SHOULD/MUST | Both implemented via `ring` |
| §4.2.2 | DSA-based signature scheme | MUST | **Deviation:** ECDSA P-256 via `ring` (scheme=2) instead of OpenPGP DSA (scheme=1). Incoming DSA signatures are logged as warnings and rejected. See deviations below. |
| §4.2.3 | Signature Group (SG) modes 0–3 | MUST | Types defined for all 4 modes. Only SG=0 (Global) is wired for signing; SG=1/2/3 are parsed but not functionally supported in the pipeline. |
| §4.2.4 | Restart Sequence ID (RSID), 0–9999999999 | MUST | Validated range in type |
| §4.2.5 | Global Block Counter (GBC), wrapping | MUST | Counter with wrap-around |
| §4.2.6 | Key Blob Type — PKIX certificates (RFC 5280) | MUST | Certificate loading, fragmentation, and X.509 path validation via `rustls`/`webpki` |
| §4.2.7 | CNT, HB (hash block fields) | MUST | Parsed and validated |
| §4.2.8 | Certificate fragmentation | MUST | Fragment/reassemble with FLEN tracking; OOM protections (1 MiB max, 2048 fragment cap) |

Signing and verification are integrated as pipeline stages in `syslog-relay`.

**Known deviations:**

1. **ECDSA P-256 instead of DSA (§4.2.2):** RFC 5848 mandates OpenPGP DSA (scheme=1) as the mandatory-to-implement signature scheme. This implementation uses ECDSA P-256 (scheme=2) instead. DSA was deprecated by NIST in 2018; ECDSA P-256 provides equivalent or stronger security with constant-time operations via `ring`. Incoming DSA-signed messages are logged with a warning and rejected. This deviation breaks interoperability with peers using the original DSA scheme.

2. **Signature groups SG=1/2/3 (§4.2.3):** Per-PRI (SG=1), PRI-ranges (SG=2), and custom (SG=3) grouping modes are type-defined and can be parsed, but only SG=0 (Global) is functionally wired in the signing pipeline. All messages are signed in a single global group. Configuration validation rejects SG modes 1-3 with an explicit error.

3. **X.509 path validation (§4.2.6):** Implemented via `validate_certificate()` in `syslog-sign`, using `rustls-webpki` for RFC 5280 chain validation. Callers should use `Verifier::from_validated_certificate()` to enforce trust anchors.

---

## Management

### RFC 5427 — Textual Conventions for Syslog Management

**Status: Implemented**
**Crates:** `syslog-proto`, `syslog-mgmt`

| Section | Requirement | Level | Implementation |
|---------|-------------|-------|----------------|
| §3 | Severity and Facility textual names | MUST | `Display` impls on `Severity`/`Facility` enums |
| §3 | OID prefix conventions | SHOULD | Referenced in management model |

### RFC 9742 — YANG Data Model for Syslog Configuration

**Status: Implemented (Model Only)**
**Crates:** `syslog-mgmt`, `syslog-observe`, `syslog-config`, `syslog-relay`

| Section | Requirement | Level | Implementation |
|---------|-------------|-------|----------------|
| §3 | Configuration actions (selectors + actions) | MUST | `Action`, `Selector` types in `syslog-mgmt` |
| §4 | Feature reporting | MUST | `/management/features` endpoint |
| §5 | Operational counters | MUST | `/management/counters` endpoint, atomic counters |
| §6 | State model | MUST | `/management/state` endpoint, `SharedSyslogState` |

The YANG model is implemented as a Rust data model with JSON API endpoints, not as a NETCONF/RESTCONF server.

---

## Extensions

### RFC 5674 — Alarms in Syslog

**Status: Implemented**
**Crates:** `syslog-proto`, `syslog-relay`, `syslog-config`

| Feature | Implementation |
|---------|----------------|
| Alarm structured data elements | `AlarmNotification` type with ITU X.733 event types |
| Perceived severity (critical/major/minor/warning/indeterminate/cleared) | `PerceivedSeverity` enum with ordering |
| Alarm filtering | `AlarmFilter` in relay pipeline (severity, event type, trend) |
| Alarm state tracking | `AlarmStateTable` with bounded entry count |

### RFC 6347 / RFC 9147 — DTLS 1.2 / DTLS 1.3

**Status: Types Only**
**Crate:** `syslog-transport`

Version types defined for future DTLS transport support. No I/O implementation.

---

## Supporting Standards (Used Internally)

| Standard | Usage |
|----------|-------|
| RFC 5280 — PKIX Certificates | Certificate handling and X.509 path validation for RFC 5848 signing |
| RFC 4648 — Base64 Encoding | Signature and certificate block encoding in RFC 5848 |
| RFC 3339 — Date and Time on the Internet | Timestamp format for RFC 5424 TIMESTAMP field |

---

## Not Implemented

| RFC | Title | Status |
|-----|-------|--------|
| RFC 3195 | Reliable Delivery for Syslog | Documented in design docs; not implemented |
| RFC 5675 | Mapping SNMP Notifications to Syslog Messages | Documented in design docs; not implemented |
| RFC 5676 | Definitions of Managed Objects for Mapping SNMP Notifications to Syslog Messages | Documented in design docs; not implemented |

---

## Test Coverage

All compliance claims are backed by tests across the workspace:

| Crate | Tests | Key RFC Coverage |
|-------|-------|-----------------|
| `syslog-proto` | 114 | RFC 5424 types, RFC 5427 names, RFC 5674 alarms |
| `syslog-parse` | 38 | RFC 5424 parser/serializer roundtrip, RFC 3164 best-effort |
| `syslog-transport` | 37 | RFC 5425 TLS, RFC 5426 UDP, octet-counting codec, RFC 9662 cipher suite verification |
| `syslog-config` | 29 | Config validation for all RFC features |
| `syslog-relay` | 91 | Pipeline stages: alarm filter, signing, verification (incl. DSA scheme rejection), routing |
| `syslog-observe` | 18 | RFC 9742 management endpoints |
| `syslog-server` | 9 | End-to-end integration (UDP/TCP) |
| `syslog-sign` | 84 | RFC 5848 signing/verification, hash chains, cert fragmentation, X.509 path validation |
| `syslog-mgmt` | 106 | RFC 9742/5427 model, selectors, actions, counters |

Additional testing: property-based tests (`proptest`), fuzz targets, and differential tests against reference implementations.
