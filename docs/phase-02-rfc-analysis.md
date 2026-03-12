# Phase 02: RFC Protocol Compliance Analysis

**Document Version:** 1.0
**Date:** 2026-03-11
**Scope:** Comprehensive protocol compliance analysis for a production-grade Syslog Server/Relay in Rust, covering 12 RFCs across core protocol, transport, security, management, and extension domains.

---

## Table of Contents

1. [RFC 5424 — The Syslog Protocol](#1-rfc-5424--the-syslog-protocol)
2. [RFC 3195 — Reliable Delivery for Syslog](#2-rfc-3195--reliable-delivery-for-syslog)
3. [RFC 5425 — TLS Transport Mapping for Syslog](#3-rfc-5425--tls-transport-mapping-for-syslog)
4. [RFC 5426 — Transmission of Syslog Messages over UDP](#4-rfc-5426--transmission-of-syslog-messages-over-udp)
5. [RFC 6012 — DTLS Transport Mapping for Syslog](#5-rfc-6012--dtls-transport-mapping-for-syslog)
6. [RFC 9662 — Updates to Cipher Suites in Secure Syslog](#6-rfc-9662--updates-to-cipher-suites-in-secure-syslog)
7. [RFC 5427 — Textual Conventions for Syslog Management](#7-rfc-5427--textual-conventions-for-syslog-management)
8. [RFC 9742 — YANG Data Model for Syslog Management](#8-rfc-9742--yang-data-model-for-syslog-management)
9. [RFC 5848 — Signed Syslog Messages](#9-rfc-5848--signed-syslog-messages)
10. [RFC 5674 — Alarms in Syslog](#10-rfc-5674--alarms-in-syslog)
11. [RFC 5675 — Mapping SNMP Notifications to SYSLOG Messages](#11-rfc-5675--mapping-snmp-notifications-to-syslog-messages)
12. [RFC 5676 — Managed Objects for Mapping SYSLOG to SNMP Notifications](#12-rfc-5676--managed-objects-for-mapping-syslog-to-snmp-notifications)
13. [Traceability Matrix](#13-traceability-matrix)

---

## 1. RFC 5424 — The Syslog Protocol

### 1.1 RFC Summary

RFC 5424 defines the core syslog message format and architecture. It supersedes the de-facto BSD syslog format (RFC 3164) and introduces structured data, explicit character encoding, and precise timestamp formatting. This is the foundational specification; all other syslog RFCs depend on or extend it.

**Key relationships:**
- Transport mappings: RFC 5425 (TLS), RFC 5426 (UDP), RFC 6012 (DTLS)
- Extensions: RFC 5848 (signing), RFC 5674 (alarms), RFC 5675/5676 (SNMP mapping)
- Management: RFC 5427 (textual conventions), RFC 9742 (YANG model)

### 1.2 MUST Requirements

| Ref | Requirement |
|-----|-------------|
| S6.1 | Facility values MUST be in the range of 0 to 23 inclusive |
| S6.2 | Severity values MUST be in the range of 0 to 7 inclusive |
| S6 | HEADER character set MUST be seven-bit ASCII in an eight-bit field |
| S6.1 | PRI part MUST have three, four, or five characters (including angle brackets) |
| S6.1 | Leading zeros MUST NOT be used in PRI values (except `<0>`) |
| S6.2.1 | VERSION MUST be incremented for any new syslog protocol specification that changes the HEADER |
| S6.2.3 | The `T` and `Z` characters in TIMESTAMP MUST be upper case |
| S6.2.3 | Usage of the `T` character between date and time is REQUIRED |
| S6.2.3 | Leap seconds MUST NOT be used |
| S6.3.1 | STRUCTURED-DATA character set MUST be seven-bit ASCII |
| S6.3.1 | The same SD-ID MUST NOT exist more than once in a message |
| S6.3.3 | PARAM-VALUE MUST be encoded using UTF-8 |
| S6.3.3 | Characters `"`, `\`, and `]` inside PARAM-VALUE MUST be escaped as `\"`, `\\`, `\]` |
| S6.3.5 | When zero structured data elements, STRUCTURED-DATA field MUST contain the NILVALUE |
| S6.4 | MSG encoding: if MSG starts with BOM `%xEF.BB.BF`, rest MUST be valid UTF-8 |
| S8 | Transport protocols MUST NOT deliberately alter the syslog message |
| S8.1 | Any transport receiver MUST be able to accept messages of up to 480 octets |
| S8.1 | If a transport receiver truncates messages, the truncation MUST occur at the end |
| S9 | All implementations MUST support a TLS-based transport |

### 1.3 SHOULD Requirements

| Ref | Requirement |
|-----|-------------|
| S6.2.1 | HOSTNAME field SHOULD contain the hostname and domain name in FQDN format |
| S6.2.1 | Syslog applications SHOULD consistently use the same value in HOSTNAME |
| S6.2.1 | NILVALUE SHOULD only be used when unable to obtain real hostname |
| S6.2.3 | Originator SHOULD include TIME-SECFRAC if clock accuracy permits |
| S6.2.5 | APP-NAME SHOULD identify the device or application that originated the message |
| S6.2.7 | MSGID SHOULD identify the type of message |
| S6.4 | MSG character set SHOULD be UNICODE, encoded using UTF-8 |
| S6.4 | Syslog application SHOULD avoid octet values below 32 (control characters) |
| S8.1 | Transport receivers SHOULD be able to accept messages up to 2048 octets |
| S9 | All implementations SHOULD also support UDP-based transport |
| S9 | It is RECOMMENDED that deployments use TLS-based transport |

### 1.4 MAY Requirements

| Ref | Requirement |
|-----|-------------|
| S6.2.5 | APP-NAME NILVALUE MAY be used when unable to provide value |
| S6.2.6 | PROCID NILVALUE MAY be used when no value is provided |
| S6.3.3 | An SD-PARAM MAY be repeated multiple times inside an SD-ELEMENT |
| S6.4 | If unable to encode in UTF-8, MAY use any other encoding |
| S6.4 | Syslog application MAY modify messages containing control characters |
| S8.1 | Transport receivers MAY receive messages larger than 2048 octets |
| S8.1 | Transport receivers MAY discard or MAY try to process oversized messages |
| S8.2 | A collector MAY ignore malformed STRUCTURED-DATA elements |

### 1.5 Data Model Implications

**ABNF Grammar:**
```
SYSLOG-MSG      = HEADER SP STRUCTURED-DATA [SP MSG]
HEADER          = PRI VERSION SP TIMESTAMP SP HOSTNAME
                  SP APP-NAME SP PROCID SP MSGID
PRI             = "<" PRIVAL ">"
PRIVAL          = 1*3DIGIT          ; range 0..191
VERSION         = NONZERO-DIGIT 0*2DIGIT
HOSTNAME        = NILVALUE / 1*255PRINTUSASCII
APP-NAME        = NILVALUE / 1*48PRINTUSASCII
PROCID          = NILVALUE / 1*128PRINTUSASCII
MSGID           = NILVALUE / 1*32PRINTUSASCII

TIMESTAMP       = NILVALUE / FULL-DATE "T" FULL-TIME
FULL-DATE       = DATE-FULLYEAR "-" DATE-MONTH "-" DATE-MDAY
DATE-FULLYEAR   = 4DIGIT
DATE-MONTH      = 2DIGIT            ; 01-12
DATE-MDAY       = 2DIGIT            ; 01-28/29/30/31
FULL-TIME       = PARTIAL-TIME TIME-OFFSET
PARTIAL-TIME    = TIME-HOUR ":" TIME-MINUTE ":" TIME-SECOND
                  [TIME-SECFRAC]
TIME-HOUR       = 2DIGIT            ; 00-23
TIME-MINUTE     = 2DIGIT            ; 00-59
TIME-SECOND     = 2DIGIT            ; 00-59
TIME-SECFRAC    = "." 1*6DIGIT
TIME-OFFSET     = "Z" / TIME-NUMOFFSET
TIME-NUMOFFSET  = ("+" / "-") TIME-HOUR ":" TIME-MINUTE

STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT
SD-ELEMENT      = "[" SD-ID *(SP SD-PARAM) "]"
SD-PARAM        = PARAM-NAME "=" %d34 PARAM-VALUE %d34
SD-ID           = SD-NAME
PARAM-NAME      = SD-NAME
PARAM-VALUE     = UTF-8-STRING      ; '"', '\', ']' MUST be escaped
SD-NAME         = 1*32PRINTUSASCII  ; except '=', SP, ']', '"'

MSG             = MSG-ANY / MSG-UTF8
MSG-ANY         = *OCTET            ; not starting with BOM
MSG-UTF8        = BOM UTF-8-STRING
BOM             = %xEF.BB.BF

NILVALUE        = "-"
PRINTUSASCII    = %d33-126
NONZERO-DIGIT   = %d49-57
```

**PRI Calculation:** `PRIVAL = (Facility * 8) + Severity` — Range: 0..191

**Facility Codes (0-23):**

| Code | Keyword | Description |
|------|---------|-------------|
| 0 | kern | Kernel messages |
| 1 | user | User-level messages |
| 2 | mail | Mail system |
| 3 | daemon | System daemons |
| 4 | auth | Security/authorization (note 1) |
| 5 | syslog | Syslog internal messages |
| 6 | lpr | Line printer subsystem |
| 7 | news | Network news subsystem |
| 8 | uucp | UUCP subsystem |
| 9 | cron | Clock daemon (note 2) |
| 10 | authpriv | Security/authorization (note 1) |
| 11 | ftp | FTP daemon |
| 12 | ntp | NTP subsystem |
| 13 | audit | Log audit |
| 14 | alert | Log alert |
| 15 | cron2 | Clock daemon (note 2) |
| 16-23 | local0-local7 | Local use 0-7 |

**Severity Codes (0-7):**

| Code | Keyword | Description |
|------|---------|-------------|
| 0 | emerg | System is unusable |
| 1 | alert | Action must be taken immediately |
| 2 | crit | Critical conditions |
| 3 | err | Error conditions |
| 4 | warning | Warning conditions |
| 5 | notice | Normal but significant condition |
| 6 | info | Informational messages |
| 7 | debug | Debug-level messages |

**Field Length Constraints:**

| Field | Max Length | Character Set |
|-------|-----------|---------------|
| HOSTNAME | 255 | PRINTUSASCII |
| APP-NAME | 48 | PRINTUSASCII |
| PROCID | 128 | PRINTUSASCII |
| MSGID | 32 | PRINTUSASCII |
| SD-NAME (SD-ID, PARAM-NAME) | 32 | PRINTUSASCII (no `=`, SP, `]`, `"`) |
| PARAM-VALUE | unbounded | UTF-8 |

**IANA-Registered SD-IDs:**

- **timeQuality**: `tzKnown` (0/1), `isSynced` (0/1), `syncAccuracy` (microseconds)
- **origin**: `ip` (repeatable), `enterpriseId`, `software` (max 48), `swVersion` (max 32)
- **meta**: `sequenceId` (1-2147483647, wraps to 1), `sysUpTime`, `language` (BCP 47)

**Private SD-ID format:** `name@<private-enterprise-number>` (e.g., `mySD@32473`)

### 1.6 Transport Requirements

- TLS transport MUST be supported (RFC 5425)
- UDP transport SHOULD be supported (RFC 5426)
- Transport MUST NOT alter message content
- Minimum acceptance: 480 octets (MUST), 2048 octets (SHOULD)
- Truncation only at end of message

### 1.7 Security Requirements

- TLS-based transport is RECOMMENDED for deployment
- No message-level security in this RFC (see RFC 5848 for signing)
- Relays MUST NOT alter messages (integrity preservation)

### 1.8 Edge Cases and Gotchas

1. **Leading zeros in PRI:** `<034>` is invalid; must be `<34>`. Only `<0>` has a leading zero.
2. **Fractional seconds precision:** `22:13:14.003` (3ms) is not the same as `22:13:14.3` (300ms). Parser must preserve all digits.
3. **SD-ELEMENT adjacency:** Elements are concatenated without spaces: `[id1][id2]`, NOT `[id1] [id2]`.
4. **PARAM-VALUE escape sequences:** Only `\"`, `\\`, `\]` are valid escapes. A backslash followed by any other character is NOT an escape and must be preserved literally.
5. **NILVALUE is a single hyphen** (`-`), not an empty string or null.
6. **MSG field is optional:** The ABNF uses `[SP MSG]` — a message with only HEADER and STRUCTURED-DATA is valid, but if MSG is present, it MUST be preceded by SP.
7. **UTF-8 BOM detection:** If MSG starts with `EF BB BF`, the rest MUST be treated as UTF-8. Without BOM, encoding is unspecified.
8. **UTF-8 shortest form:** Non-shortest-form UTF-8 sequences must not be interpreted (Unicode TR36 compliance).
9. **SD-PARAM name scoping:** The same PARAM-NAME can appear in different SD-ELEMENTs. Duplicate PARAM-NAMEs within the same SD-ELEMENT are allowed (same SD-PARAM MAY be repeated).
10. **IPv6 in HOSTNAME:** Must use RFC 4291 textual format (e.g., `2001:db8::1`), not bracketed.
11. **Relay forwarding:** Relays must not rewrite malformed STRUCTURED-DATA; collectors may choose to ignore it.

### 1.9 Implementation Areas

| Module | Responsibility |
|--------|---------------|
| `syslog-core::message` | Message struct, PRI calculation, field validation |
| `syslog-core::parser` | ABNF-based parser for HEADER, STRUCTURED-DATA, MSG |
| `syslog-core::serializer` | Message serialization with field length enforcement |
| `syslog-core::timestamp` | RFC 3339 timestamp parsing/generation |
| `syslog-core::structured_data` | SD-ELEMENT, SD-PARAM, escaping, SD-ID validation |
| `syslog-core::facility` | Facility enum (0-23) |
| `syslog-core::severity` | Severity enum (0-7) |
| `syslog-core::validation` | Field length checks, charset validation, NILVALUE handling |

### 1.10 Compliance Test Checklist

- [ ] Parse valid message with all fields populated
- [ ] Parse message with NILVALUE for each optional field individually
- [ ] Parse message with all fields set to NILVALUE
- [ ] Reject PRI with leading zeros (e.g., `<034>`)
- [ ] Accept PRI range 0-191; reject 192+
- [ ] Validate facility 0-23 extracted correctly from PRI
- [ ] Validate severity 0-7 extracted correctly from PRI
- [ ] Parse TIMESTAMP with `Z` offset
- [ ] Parse TIMESTAMP with numeric offset (`+05:30`, `-07:00`)
- [ ] Parse TIMESTAMP with fractional seconds (1-6 digits)
- [ ] Reject TIMESTAMP with lowercase `t` or `z`
- [ ] Reject TIMESTAMP with leap second (`:60`)
- [ ] Enforce HOSTNAME max 255 chars
- [ ] Enforce APP-NAME max 48 chars
- [ ] Enforce PROCID max 128 chars
- [ ] Enforce MSGID max 32 chars
- [ ] Enforce SD-NAME max 32 chars
- [ ] Parse STRUCTURED-DATA with multiple SD-ELEMENTs
- [ ] Parse SD-PARAM with escaped `\"`, `\\`, `\]`
- [ ] Reject duplicate SD-IDs in same message
- [ ] Accept duplicate SD-PARAMs within same SD-ELEMENT
- [ ] Parse MSG with UTF-8 BOM
- [ ] Parse MSG without BOM (treat as opaque octets)
- [ ] Handle message with no MSG part (HEADER + SD only)
- [ ] Accept messages up to 480 octets (MUST)
- [ ] Accept messages up to 2048 octets (SHOULD)
- [ ] Truncation occurs at end of message only
- [ ] Serialize message round-trip preserves all fields
- [ ] Private SD-ID format `name@PEN` validated correctly
- [ ] IANA SD-IDs (timeQuality, origin, meta) parsed with correct params

---

## 2. RFC 3195 — Reliable Delivery for Syslog

### 2.1 RFC Summary

RFC 3195 defines reliable delivery for syslog using BEEP (Blocks Extensible Exchange Protocol, RFC 3080) as the transport framework. It provides two profiles: RAW (binary syslog) and COOKED (XML-structured syslog). This RFC predates RFC 5424 and references RFC 3164 message format.

**Key relationships:**
- Built on BEEP (RFC 3080) and BEEP over TCP (RFC 3081)
- Message format references RFC 3164 (superseded by RFC 5424)
- Provides reliable, ordered, connection-oriented delivery as alternative to UDP

**Implementation priority: LOW** — BEEP adoption is minimal in modern deployments. Most reliable syslog delivery now uses TCP with TLS (RFC 5425). Include as a future extension.

### 2.2 MUST Requirements

| Ref | Requirement |
|-----|-------------|
| S3.3 | RAW profile messages MUST be formatted according to RFC 3164 Section 4 |
| S3.3 | RAW messages MUST be 1024 bytes or less, excluding BEEP framing overhead |
| S3.3 | Final syslog entry in aggregated ANS frame MUST NOT end with CRLF |
| S4.4.2 | COOKED relay receiving malformed messages MUST follow RFC 3164 S4.2.2 rules |
| S4.4.2 | Original message content MUST be preserved in entry element CDATA |
| S4.4.2 | Device attributes MUST NOT be added if another relay has sent the iam element |
| S4.4.1 | toIP and fromIP attributes MUST be the actual IP address of interfaces |

### 2.3 SHOULD Requirements

| Ref | Requirement |
|-----|-------------|
| S2 | Devices and relays SHOULD discover relays/collectors via DNS SRV algorithm |
| S2 | Device SHOULD add deviceFQDN and deviceIP attributes before relay forwarding |
| S4.4.1 | fromFQDN/toFQDN SHOULD be the FQDN of sending/receiving interface |
| S5.1-5.4 | Authentication implementations SHOULD use SASL DIGEST-MD5 |
| S5.1-5.4 | Observation protection SHOULD use the TLS profile |

### 2.4 MAY Requirements

| Ref | Requirement |
|-----|-------------|
| S4.4.2 | Relay MAY parse raw messages in a more sophisticated way |
| S4.4.2 | Peer MAY optionally generate path element from UDP-received messages |
| S2 | Peers MAY discover via DNS SRV |

### 2.5 Data Model Implications

**RAW Profile:**
- URI: `http://xml.resource.org/profiles/syslog/RAW`
- Content-Type: `application/octet-stream`
- Messages: RFC 3164 format, max 1024 bytes
- Multiple messages per ANS frame, separated by CRLF (no trailing CRLF)

**COOKED Profile:**
- URI: `http://xml.resource.org/profiles/syslog/COOKED`
- Content-Type: `application/beep+xml`
- Elements: `<iam>`, `<entry>`, `<path>`, `<ok>`, `<error>`
- Entry attributes: facility, severity, timestamp, tag, hostname, deviceFQDN, deviceIP, pathID
- Path linkprops flags: `o` (weak privacy), `O` (strong privacy), `U` (authenticated user), `A` (auth layer), `R` (replay protection), `I` (integrity), `L` (reliable delivery), `D` (device origin)

**Error/Reply codes:** 200 (success), 421 (unavailable), 451 (local error), 530 (auth required), 535 (auth failure), 537 (unauthorized), 550 (not taken), 554 (policy violation)

### 2.6 Transport Requirements

- Well-known port: TCP **601** (syslog-conn)
- DNS SRV: service `syslog`, protocol `tcp`
- BEEP channel lifecycle: create, negotiate profile, exchange, close
- Reliable, ordered delivery within individual BEEP channels
- TCP provides retransmission; no syslog-level ACK in RAW profile

### 2.7 Security Requirements

- SASL DIGEST-MD5 for authentication (SHOULD)
- TLS for observation protection (SHOULD)
- Legacy recommended cipher: `TLS_RSA_WITH_3DES_EDE_CBC_SHA`
- Security operates at BEEP session level, transparent to syslog profiles

### 2.8 Edge Cases and Gotchas

1. **BEEP complexity:** Implementing BEEP from scratch is a substantial undertaking; no mature Rust BEEP crate exists.
2. **RFC 3164 dependency:** Message format references the obsoleted BSD syslog format, not RFC 5424.
3. **Path element nesting:** Multi-hop relay scenarios create complex nested path elements.
4. **Message aggregation in RAW:** Multiple messages in a single ANS frame require careful CRLF handling.
5. **Legacy crypto:** DIGEST-MD5 and 3DES are both deprecated by modern standards.

### 2.9 Implementation Areas

| Module | Responsibility |
|--------|---------------|
| `transport::beep` | BEEP protocol implementation (future) |
| `transport::beep::raw_profile` | RAW syslog profile |
| `transport::beep::cooked_profile` | COOKED XML syslog profile |
| `syslog-core::legacy_parser` | RFC 3164 message parsing |

### 2.10 Compliance Test Checklist

- [ ] Establish BEEP session over TCP port 601
- [ ] Negotiate RAW profile on channel
- [ ] Send/receive RAW messages within 1024-byte limit
- [ ] Aggregate multiple RAW messages in single ANS frame with CRLF separation
- [ ] Negotiate COOKED profile on channel
- [ ] Send/receive COOKED `<entry>` elements with all attributes
- [ ] Exchange `<iam>` elements during channel setup
- [ ] Validate `<path>` elements with linkprops flags
- [ ] Handle all error reply codes (421, 451, 530, 535, 537, 550, 554)
- [ ] DNS SRV discovery for syslog service

---

## 3. RFC 5425 — TLS Transport Mapping for Syslog

### 3.1 RFC Summary

RFC 5425 defines how syslog messages are transported over TLS, providing confidentiality, integrity, and authentication. It specifies octet-counting framing, mutual certificate authentication, and connection management. Updated by RFC 9662 for cipher suites.

**Key relationships:**
- Implements transport for RFC 5424 messages
- Updated by RFC 9662 (cipher suite modernization)
- Referenced by RFC 6012 (DTLS mirrors many requirements)
- Port 6514 (shared with DTLS)

### 3.2 MUST Requirements

| Ref | Requirement |
|-----|-------------|
| S4.2 | Implementations MUST support TLS 1.2 |
| S4.2 | Mandatory cipher suite: `TLS_RSA_WITH_AES_128_CBC_SHA` (see RFC 9662 updates) |
| S4.2.1 | MUST implement certificate-based authentication |
| S4.2.1 | MUST support certification path validation per RFC 5280 |
| S4.2.1 | MUST support end-entity certificate matching via fingerprints |
| S4.2.1 | MUST provide mechanisms to generate key pairs and self-signed certificates |
| S4.2.1 | MUST record end-entity certificates for correlation |
| S4.2.2 | MUST make certificate fingerprints available through management interfaces |
| S4.2.2 | MUST support SHA-1 fingerprint algorithm with label `sha-1` |
| S4.3 | Transport receiver MUST use message length as delimiter |
| S4.3 | MUST process messages up to 2048 octets |
| S4.4 | Transport sender MUST close connections not expected to deliver future messages |
| S4.4 | MUST send TLS `close_notify` alert before closure |
| S4.4 | Transport receiver MUST reply with `close_notify` |
| S5.2 | MUST support certification path validation for authorization |
| S5.2 | MUST support matching hostnames against dNSName in subjectAltName |
| S5.2 | MUST support wildcard matching in DNS names |
| S5.2 | MUST convert internationalized domain names to ACE |

### 3.3 SHOULD Requirements

| Ref | Requirement |
|-----|-------------|
| S4.2 | Session resumption security parameters SHOULD be checked against requirements |
| S4.3 | SHOULD process messages up to 8192 octets |
| S5.2 | SHOULD check common name in subject distinguished name |

### 3.4 MAY Requirements

| Ref | Requirement |
|-----|-------------|
| S4.4 | Receiver MAY close connection after inactivity |
| S4.4 | MUST attempt `close_notify` exchange before inactivity closure |
| S5.2 | Implementations MAY provide option to disable wildcard matching |

### 3.5 Data Model Implications

**Message Framing (octet-counting):**
```
SYSLOG-FRAME = MSG-LEN SP SYSLOG-MSG
MSG-LEN      = NONZERO-DIGIT *DIGIT
SP            = %d32
SYSLOG-MSG   = (per RFC 5424)
```

The `MSG-LEN` is the number of octets in `SYSLOG-MSG`, expressed as a decimal integer with no leading zeros.

**Certificate Fingerprint Format:** Colon-separated hexadecimal bytes
Example: `sha-1:E1:2D:53:2B:7C:6B:8A:29:A2:76:C8:64:36:0B:08:4B:7A:F1:9E:9D`

### 3.6 Transport Requirements

- Default port: TCP **6514**
- TLS 1.2 minimum (TLS 1.3 SHOULD per RFC 9662)
- Octet-counting framing (not newline-delimited)
- Message size: MUST handle up to 2048, SHOULD handle up to 8192
- Clean connection shutdown via `close_notify` exchange

### 3.7 Security Requirements

- Mutual certificate authentication (both client and server)
- Certificate path validation per RFC 5280
- Certificate fingerprint support (SHA-1 minimum)
- Subject name authorization via subjectAltName dNSName
- Wildcard support in leftmost DNS label only
- Unauthenticated configurations are NOT RECOMMENDED
- Authenticated transport sender identity is NOT necessarily related to HOSTNAME field in syslog message

### 3.8 Edge Cases and Gotchas

1. **Framing is NOT newline-based:** Must use octet-counting. A common implementation error is to use newline framing.
2. **MSG-LEN is decimal, no leading zeros:** `0123` is invalid; must be `123`.
3. **Certificate identity vs. syslog HOSTNAME:** The authenticated TLS identity does not necessarily match the HOSTNAME in the syslog message (relays forward on behalf of originators).
4. **Session resumption:** Security parameters must be re-validated on resumption; do not blindly accept cached sessions.
5. **Connection reuse:** Multiple syslog messages can be sent on the same TLS connection; each is independently framed.
6. **Partial reads:** TCP may deliver partial frames; implementation must buffer until MSG-LEN octets are received.

### 3.9 Implementation Areas

| Module | Responsibility |
|--------|---------------|
| `transport::tls` | TLS connection management, handshake, session resumption |
| `transport::tls::framing` | Octet-counting frame encoder/decoder |
| `transport::tls::cert` | Certificate validation, fingerprinting, path validation |
| `transport::tls::auth` | Subject name authorization, wildcard matching |
| `config::tls` | TLS configuration (certs, keys, cipher suites, ports) |

### 3.10 Compliance Test Checklist

- [ ] Establish TLS 1.2 connection on port 6514
- [ ] Establish TLS 1.3 connection on port 6514
- [ ] Mutual certificate authentication succeeds
- [ ] Reject connection with invalid server certificate
- [ ] Reject connection with invalid client certificate
- [ ] Octet-counting framing: send and receive correctly framed messages
- [ ] Parse MSG-LEN correctly for messages of varying sizes
- [ ] Handle messages up to 2048 octets
- [ ] Handle messages up to 8192 octets
- [ ] Reject MSG-LEN with leading zeros
- [ ] Send `close_notify` on graceful shutdown
- [ ] Respond to `close_notify` with `close_notify`
- [ ] Certificate fingerprint generation (SHA-1)
- [ ] Subject name matching against subjectAltName dNSName
- [ ] Wildcard matching (`*.example.com` matches `host.example.com`)
- [ ] Reject wildcard in non-leftmost position
- [ ] Handle partial TCP reads correctly (buffering)
- [ ] Multiple messages on same TLS connection
- [ ] Session resumption with parameter re-validation

---

## 4. RFC 5426 — Transmission of Syslog Messages over UDP

### 4.1 RFC Summary

RFC 5426 defines UDP transport for syslog messages. It is the simplest transport — one syslog message per UDP datagram, no framing, no reliability guarantees. Intended for managed networks only.

**Key relationships:**
- Transports RFC 5424 messages
- Security extension: RFC 6012 (DTLS over UDP)
- Supersedes implicit UDP transport in RFC 3164

### 4.2 MUST Requirements

| Ref | Requirement |
|-----|-------------|
| S3.1 | Each syslog UDP datagram MUST contain only one syslog message |
| S3.2 | IPv4 receivers MUST accept datagrams with messages up to 480 octets |
| S3.2 | IPv6 receivers MUST accept datagrams with messages up to 1180 octets |
| S3.3 | Receivers MUST support accepting datagrams on UDP port 514 |
| S3.3 | Senders MUST support sending datagrams to UDP port 514 |
| S3.6 | Senders MUST NOT disable UDP checksums |
| S3.6 | Receivers MUST NOT disable UDP checksum checks |

### 4.3 SHOULD Requirements

| Ref | Requirement |
|-----|-------------|
| S3.2 | All receivers SHOULD accept datagrams with messages up to 2048 octets |
| S3.2 | Senders SHOULD restrict message sizes to avoid IP fragmentation (fit in smallest MTU) |
| S3.4 | Source IP SHOULD NOT be interpreted as the message originator identifier |
| S3.6 | IPv4 senders SHOULD use UDP checksums |
| S3.6 | IPv4 receivers SHOULD accept messages with zero checksum |
| S4.3 | On non-managed networks, TLS transport SHOULD be used instead |
| S4.4 | Arrival order SHOULD NOT be used as authoritative sequence of events |

### 4.4 MAY Requirements

| Ref | Requirement |
|-----|-------------|
| S3.3 | Both senders and receivers MAY be configured for a different port |
| S3.3 | Senders MAY use any source UDP port |
| S4.3 | UDP transport MAY only be used on managed networks explicitly provisioned for syslog |

### 4.5 Data Model Implications

**Message Size Limits:**

| Limit | Value | Notes |
|-------|-------|-------|
| IPv4 minimum acceptance | 480 octets | MUST |
| IPv6 minimum acceptance | 1180 octets | MUST |
| Recommended acceptance | 2048 octets | SHOULD |
| Theoretical maximum | 65,507 octets | 65535 - 20 (IP) - 8 (UDP) |
| IPv4 MTU assumption | 576 octets | Minus headers = ~480 payload |
| IPv6 MTU assumption | 1280 octets | Minus headers = ~1180 payload |

No framing is needed — the UDP datagram boundary IS the message boundary.

### 4.6 Transport Requirements

- Default port: UDP **514**
- One message per datagram (no aggregation)
- No reliability, ordering, or congestion control
- No framing overhead
- Suitable only for managed networks

### 4.7 Security Requirements

- **No built-in security** — cleartext, no authentication, no integrity
- Message forgery is trivial
- Replay attacks are possible
- For security, use DTLS (RFC 6012) or switch to TLS (RFC 5425)
- Source IP is not a reliable indicator of message origin

### 4.8 Edge Cases and Gotchas

1. **IP fragmentation:** Messages exceeding MTU will be fragmented. Loss of any fragment loses the entire message. Keep messages within MTU.
2. **Source IP spoofing:** Trivially possible on UDP; never trust source IP as origin proof.
3. **Message loss is silent:** No mechanism to detect dropped messages. High-volume environments will lose data.
4. **IPv4 vs IPv6 minimum sizes differ:** Must handle both correctly.
5. **Zero-checksum datagrams:** IPv4 allows zero checksum; receiver should accept these. IPv6 mandates checksum.
6. **Port 514 conflict:** Some systems use port 514 for other services (e.g., rsh on older Unix).

### 4.9 Implementation Areas

| Module | Responsibility |
|--------|---------------|
| `transport::udp` | UDP socket management, send/receive |
| `transport::udp::receiver` | Datagram reception, size validation |
| `transport::udp::sender` | Datagram transmission, MTU awareness |
| `config::udp` | Port, bind address, buffer size configuration |

### 4.10 Compliance Test Checklist

- [ ] Send single syslog message per UDP datagram
- [ ] Receive on port 514
- [ ] Send to port 514
- [ ] Accept messages up to 480 octets (IPv4)
- [ ] Accept messages up to 1180 octets (IPv6)
- [ ] Accept messages up to 2048 octets
- [ ] Reject datagrams containing multiple messages
- [ ] UDP checksum enabled on send
- [ ] Accept zero-checksum datagrams on IPv4
- [ ] Configurable send/receive port
- [ ] Handle oversized datagrams gracefully (truncate or discard)
- [ ] Source IP is not used as HOSTNAME source

---

## 5. RFC 6012 — DTLS Transport Mapping for Syslog

### 5.1 RFC Summary

RFC 6012 defines DTLS (Datagram TLS) transport for syslog over UDP, providing the security benefits of TLS (confidentiality, integrity, authentication) while preserving UDP's datagram semantics. Updated by RFC 9662 for cipher suites.

**Key relationships:**
- Secures RFC 5426 UDP transport
- Mirrors RFC 5425 security model (references it extensively)
- Updated by RFC 9662 (cipher suites, DTLS version requirements)
- Port 6514 (shared with TLS)

### 5.2 MUST Requirements

| Ref | Requirement |
|-----|-------------|
| S5.1 | MUST support DTLS over UDP |
| S5.1 | MUST NOT use syslog over DTLS over TCP |
| S5.3 | MUST support DTLS 1.2 (per RFC 9662 update; originally DTLS 1.0) |
| S5.3 | MUST NOT use DTLS 1.0 (per RFC 9662) |
| S5.3 | MUST NOT negotiate NULL integrity or authentication cipher suites |
| S5.3 | MUST support denial-of-service countermeasures (DTLS cookie exchange) |
| S5.3.1 | MUST implement certificate-based authentication (per RFC 5425 S4.2.1/4.2.2) |
| S5.3.1 | MUST provide means to generate key pairs and self-signed certificates |
| S5.4 | Transport sender MUST NOT send syslog messages before DTLS handshake completes |
| S5.4 | All syslog messages MUST be sent as DTLS application data |
| S5.4.1 | Receiver MUST use message length to delimit syslog messages |
| S5.4.1 | Receiver MUST process messages up to 2048 octets |
| S5.5 | Sender MUST close DTLS connection when no further messages expected |
| S5.5 | MUST send DTLS `close_notify` alert |
| S5.5 | Receiver MUST reply with `close_notify` |
| S9.1 | If renegotiation allowed, RFC 5746 MUST be followed |

### 5.3 SHOULD Requirements

| Ref | Requirement |
|-----|-------------|
| S5.1 | SHOULD support DTLS over DCCP |
| S5.3 | SHOULD support DTLS 1.3 (per RFC 9662) |
| S5.3.1 | SHOULD record certificate or fingerprint |
| S5.4.1 | SHOULD process messages up to 8192 octets |
| S6 | DCCP is RECOMMENDED over UDP for congestion control |
| S9.1 | Renegotiation is RECOMMENDED to be disabled |

### 5.4 MAY Requirements

| Ref | Requirement |
|-----|-------------|
| S5.5 | Receiver MAY close connection after inactivity |

### 5.5 Data Model Implications

- Message framing: each DTLS record contains exactly one syslog message
- Message length determined by DTLS record length (no octet-counting needed unlike TLS)
- PMTU affects maximum message size over UDP

### 5.6 Transport Requirements

- Default port: UDP **6514** (also DCCP 6514)
- DTLS 1.2 minimum (DTLS 1.3 SHOULD)
- Transport sender is always DTLS client; receiver is always DTLS server
- DTLS cookie exchange for DoS mitigation
- DCCP preferred over UDP for congestion control
- DCCP implementations MUST support CCID 3, SHOULD support CCID 2

### 5.7 Security Requirements

- All RFC 5425 Section 5 security policies apply
- Certificate-based mutual authentication
- No NULL cipher suites
- DoS countermeasures (cookie exchange) mandatory
- Renegotiation disabled by default; if enabled, must use RFC 5746 secure renegotiation
- No early data (0-RTT) per RFC 9662

### 5.8 Edge Cases and Gotchas

1. **PMTU discovery:** DTLS over UDP is subject to path MTU limitations. Large syslog messages may not fit in a single DTLS record without fragmentation, and DTLS handles this differently than TCP.
2. **DTLS over TCP prohibited:** Explicitly forbidden — if TCP is available, use TLS (RFC 5425) instead.
3. **Shared port 6514:** Both TLS and DTLS use 6514 but on different transport protocols (TCP vs UDP). Configuration must distinguish.
4. **DTLS record overhead:** DTLS adds ~25-40 bytes of overhead per record, reducing effective payload compared to plain UDP.
5. **Cookie exchange adds latency:** The DoS countermeasure adds a round-trip to initial handshake.
6. **Renegotiation vulnerability:** If renegotiation is enabled without RFC 5746, it is vulnerable to MitM attacks.

### 5.9 Implementation Areas

| Module | Responsibility |
|--------|---------------|
| `transport::dtls` | DTLS session management, handshake, cookie exchange |
| `transport::dtls::sender` | DTLS client implementation |
| `transport::dtls::receiver` | DTLS server implementation |
| `transport::dtls::cert` | Certificate handling (reuses TLS cert module) |
| `config::dtls` | DTLS-specific configuration |

### 5.10 Compliance Test Checklist

- [ ] DTLS 1.2 handshake over UDP port 6514
- [ ] DTLS 1.3 handshake over UDP port 6514
- [ ] Reject DTLS 1.0 connections
- [ ] Cookie exchange (HelloVerifyRequest/HelloRetransmit)
- [ ] Mutual certificate authentication
- [ ] Reject NULL cipher suite negotiation
- [ ] Send syslog message only after handshake complete
- [ ] Receive and delimit messages by DTLS record length
- [ ] Handle messages up to 2048 octets
- [ ] Handle messages up to 8192 octets
- [ ] `close_notify` exchange on shutdown
- [ ] Reject renegotiation without RFC 5746
- [ ] Verify DTLS over TCP is rejected/not offered
- [ ] No 0-RTT / early data

---

## 6. RFC 9662 — Updates to Cipher Suites in Secure Syslog

### 6.1 RFC Summary

RFC 9662 modernizes the cipher suite requirements for secure syslog transport (updating RFC 5425 and RFC 6012). It shifts from RSA-only suites to forward-secret ECDHE variants and addresses TLS 1.3 and DTLS 1.3 support.

**Key relationships:**
- Updates RFC 5425 (TLS cipher suites and version requirements)
- Updates RFC 6012 (DTLS cipher suites and version requirements)
- References RFC 8446 (TLS 1.3), RFC 9147 (DTLS 1.3)

### 6.2 MUST Requirements

| Ref | Requirement |
|-----|-------------|
| S5 | MUST implement `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` |
| S5 | MUST implement `TLS_RSA_WITH_AES_128_CBC_SHA` (backward compatibility) |
| S5 | TLS: MUST continue to support TLS 1.2 as mandatory-to-implement |
| S5 | DTLS: MUST use DTLS 1.2 (MUST NOT use DTLS 1.0) |
| S5 | Implementations MUST NOT use early data (0-RTT) |

### 6.3 SHOULD Requirements

| Ref | Requirement |
|-----|-------------|
| S5 | SHOULD support TLS 1.3 with preference when implemented |
| S5 | SHOULD support DTLS 1.3 with preference when implemented |
| S5 | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` SHOULD be preferred over legacy suite |

### 6.4 MAY Requirements

| Ref | Requirement |
|-----|-------------|
| S5 | `TLS_RSA_WITH_AES_128_CBC_SHA` MAY be used as migration path only |

### 6.5 Data Model Implications

**Cipher Suite Configuration Model:**

| Cipher Suite | TLS Version | Status | Notes |
|-------------|-------------|--------|-------|
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 1.2 | MUST implement, SHOULD prefer | Forward secrecy |
| `TLS_RSA_WITH_AES_128_CBC_SHA` | 1.2 | MUST implement, MAY use | Legacy, no forward secrecy |
| TLS 1.3 mandatory suites | 1.3 | Follow RFC 8446 | `TLS_AES_128_GCM_SHA256`, etc. |

### 6.6 Transport Requirements

No additional transport requirements beyond those in RFC 5425/6012.

### 6.7 Security Requirements

- Forward secrecy (ECDHE) is the preferred mode
- Legacy RSA key exchange retained only for backward compatibility during migration
- 0-RTT / early data is explicitly forbidden (syslog lacks replay protection at application layer)
- DTLS 1.0 is explicitly deprecated and forbidden

### 6.8 Edge Cases and Gotchas

1. **Dual cipher suite requirement:** Both suites MUST be implemented, but the ECDHE suite SHOULD be preferred. Configuration should default to preferring ECDHE.
2. **0-RTT prohibition:** Even though TLS 1.3 supports 0-RTT, syslog MUST NOT use it because syslog messages lack replay protection.
3. **DTLS 1.0 ban:** Existing deployments using DTLS 1.0 must be upgraded; the implementation must reject DTLS 1.0 negotiation.
4. **TLS 1.3 cipher suite naming:** TLS 1.3 uses different cipher suite identifiers; implementations must handle both TLS 1.2 and 1.3 suite namespaces.

### 6.9 Implementation Areas

| Module | Responsibility |
|--------|---------------|
| `transport::tls::cipher` | Cipher suite configuration and preference ordering |
| `transport::dtls::cipher` | DTLS cipher suite configuration |
| `config::tls` | Default cipher suite lists, version constraints |
| `config::dtls` | DTLS version constraints (reject 1.0) |

### 6.10 Compliance Test Checklist

- [ ] `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` is offered and accepted
- [ ] `TLS_RSA_WITH_AES_128_CBC_SHA` is offered and accepted
- [ ] ECDHE suite is preferred over RSA suite when both available
- [ ] TLS 1.3 handshake succeeds when supported
- [ ] DTLS 1.3 handshake succeeds when supported
- [ ] DTLS 1.0 negotiation is rejected
- [ ] 0-RTT / early data is rejected in TLS 1.3
- [ ] 0-RTT / early data is rejected in DTLS 1.3
- [ ] Correct TLS 1.3 mandatory cipher suites when using TLS 1.3

---

## 7. RFC 5427 — Textual Conventions for Syslog Management

### 7.1 RFC Summary

RFC 5427 defines SNMP textual conventions (`SyslogFacility` and `SyslogSeverity`) for consistent representation of syslog facility and severity codes within MIB modules. It is a definitional document used by RFC 5676 and other management MIBs.

**Key relationships:**
- Used by RFC 5676 (syslog-to-SNMP managed objects)
- Referenced by RFC 9742 (YANG model uses same enumerations)
- Defines the canonical name-to-number mapping for facilities and severities

### 7.2 MUST Requirements

| Ref | Requirement |
|-----|-------------|
| S2 | The mapping specified MUST be used in a MIB network management interface |

### 7.3 SHOULD Requirements

None specified beyond the general requirement.

### 7.4 MAY Requirements

None specified.

### 7.5 Data Model Implications

**SyslogFacility Enumeration (TC):**
```
kern(0), user(1), mail(2), daemon(3), auth(4), syslog(5),
lpr(6), news(7), uucp(8), cron(9), authpriv(10), ftp(11),
ntp(12), audit(13), console(14), cron2(15),
local0(16), local1(17), local2(18), local3(19),
local4(20), local5(21), local6(22), local7(23)
```

**SyslogSeverity Enumeration (TC):**
```
emergency(0), alert(1), critical(2), error(3),
warning(4), notice(5), informational(6), debug(7)
```

**Note:** Facility label mappings vary across operating systems, particularly for codes 4, 10, 13, 14, and the cron code (9 vs 15).

### 7.6 Transport Requirements

None — this is a management data definition only.

### 7.7 Security Requirements

Standard SNMP security considerations apply. No syslog-specific security requirements.

### 7.8 Edge Cases and Gotchas

1. **OS-specific facility label ambiguity:** Codes 4/10 (auth/authpriv), 9/15 (cron/cron2), 13/14 (audit/alert) have overlapping or OS-specific meanings.
2. **Enumeration is closed:** Only 0-23 for facility, 0-7 for severity. No extension mechanism.

### 7.9 Implementation Areas

| Module | Responsibility |
|--------|---------------|
| `syslog-core::facility` | Facility enum with name-to-code mapping |
| `syslog-core::severity` | Severity enum with name-to-code mapping |
| `management::snmp::tc` | SNMP textual convention support (if SNMP management implemented) |

### 7.10 Compliance Test Checklist

- [ ] Facility enum contains all 24 values (0-23)
- [ ] Severity enum contains all 8 values (0-7)
- [ ] Name-to-code mapping matches RFC specification
- [ ] Code-to-name mapping matches RFC specification
- [ ] Enum serialization for management interfaces uses specified names

---

## 8. RFC 9742 — YANG Data Model for Syslog Management

### 8.1 RFC Summary

RFC 9742 defines a YANG data model for configuring and managing syslog implementations. It covers actions (console, file, remote), filters (facility/severity, pattern matching), transport (UDP, TLS), file rotation, and signed message configuration.

**Key relationships:**
- Configures RFC 5424 message handling
- Configures RFC 5425 (TLS) and RFC 5426 (UDP) transports
- Configures RFC 5848 (signed messages)
- Uses RFC 5427 facility/severity definitions
- References YANG 1.1 (RFC 7950)

### 8.2 MUST Requirements

| Ref | Requirement |
|-----|-------------|
| S5.1 | File URIs MUST use the `file:` scheme |
| S5.1 | TLS transport MUST specify client identity |
| S8 | Pattern-match regex implementations MUST ensure patterns avoid DoS |
| S8 | Private key specifications MUST NOT specify keys used for other purposes |

### 8.3 SHOULD Requirements

| Ref | Requirement |
|-----|-------------|
| S4 | Vendors SHOULD use feature statements for optional feature support |
| S4.1 | Implementations SHOULD augment the model for proprietary extensions |

### 8.4 MAY Requirements

| Ref | Requirement |
|-----|-------------|
| S5.1 | Implementations MAY support structured data format options |

### 8.5 Data Model Implications

**YANG Tree Structure:**
```
module: ietf-syslog
  +--rw syslog!                              # presence container
     +--rw actions
        +--rw console!                       # {console-action}
        |  +--rw filter
        |  |  +--rw facility-list* [facility severity]
        |  +--rw pattern-match?              # {select-match}
        +--rw file                           # {file-action}
        |  +--rw log-file* [name]
        |     +--rw name                     # inet:uri (file:)
        |     +--rw filter
        |     +--rw pattern-match?
        |     +--rw structured-data?         # boolean
        |     +--rw file-rotation
        |        +--rw number-of-files?      # uint32
        |        +--rw max-file-size?        # uint32 (MB)
        |        +--rw rollover?             # uint32 (minutes)
        |        +--rw retention?            # uint32 (minutes)
        +--rw remote                         # {remote-action}
           +--rw destination* [name]
              +--rw name                     # string
              +--rw (transport)
              |  +--:(udp)                   # port default 514
              |  +--:(tls)                   # port default 6514
              |     +--rw client-identity!
              |     +--rw server-authentication
              |     +--rw hello-params
              |     +--rw keepalives
              +--rw filter
              +--rw pattern-match?
              +--rw structured-data?
              +--rw facility-override?
              +--rw source-interface?
              +--rw signing!                 # {signed-messages}
```

**Feature Flags:**
- `console-action` — Console logging
- `file-action` — File logging
- `file-limit-size` — Size-based file rotation
- `file-limit-duration` — Time-based file rotation
- `remote-action` — Remote server forwarding
- `remote-source-interface` — Source interface selection
- `select-adv-compare` — Advanced severity comparison (equals vs equals-or-higher)
- `select-match` — POSIX regex pattern matching
- `structured-data` — RFC 5424 structured data support
- `signed-messages` — RFC 5848 signed message support

**Filter Logic:**
- Facility-severity pair matching (default: equals-or-higher severity)
- Optional POSIX regex on SYSLOG-MSG field
- Both facility-list AND pattern must match for selection
- Action types: `log` (forward), `block` (drop), `stop` (drop + halt processing)

**Severity Special Values:**
- `none` (2147483647) — suppress all
- `all` (-2147483648) — match all

### 8.6 Transport Requirements

Configures UDP (port 514) and TLS (port 6514) transports per RFC 5426 and RFC 5425 respectively.

### 8.7 Security Requirements

- TLS client identity is mandatory for TLS transport
- Private keys must not be reused across purposes
- Regex patterns must be validated to prevent ReDoS

### 8.8 Edge Cases and Gotchas

1. **ReDoS vulnerability:** Pattern-match regex must be validated/constrained to prevent denial-of-service via catastrophic backtracking.
2. **Feature flag dependency:** Many model nodes are conditional on feature flags; implementation must track which features are enabled.
3. **File URI requirement:** Log file paths must be valid `file:` URIs, not plain filesystem paths.
4. **Facility override:** Remote destinations can override the facility code, which affects PRI calculation.
5. **Signing configuration:** Detailed timing parameters (cert-initial-repeat, sig-max-delay, etc.) must be configurable.

### 8.9 Implementation Areas

| Module | Responsibility |
|--------|---------------|
| `config::model` | YANG-derived configuration data model |
| `config::filter` | Facility/severity filter evaluation |
| `config::pattern` | POSIX regex pattern matching with ReDoS protection |
| `config::file` | File action and rotation configuration |
| `config::remote` | Remote destination and transport configuration |
| `config::signing` | Signed message configuration (RFC 5848 params) |
| `server::actions` | Action dispatch (console, file, remote) |

### 8.10 Compliance Test Checklist

- [ ] Parse YANG-derived configuration with all feature flags
- [ ] Facility-severity filter with equals-or-higher comparison
- [ ] Facility-severity filter with equals comparison
- [ ] Pattern-match filter with POSIX regex
- [ ] Combined facility-severity + pattern filter
- [ ] File action with size-based rotation
- [ ] File action with time-based rotation
- [ ] Remote action with UDP transport (port 514 default)
- [ ] Remote action with TLS transport (port 6514 default)
- [ ] TLS client identity configuration
- [ ] Facility override on remote destination
- [ ] Action types: log, block, stop
- [ ] Special severity values: none, all
- [ ] ReDoS-resistant regex validation
- [ ] File URI validation

---

## 9. RFC 5848 — Signed Syslog Messages

### 9.1 RFC Summary

RFC 5848 defines a mechanism for adding digital signatures to syslog messages using RFC 5424 structured data. Signatures cover groups of messages via hash chains, enabling offline verification of message integrity, authenticity, and completeness (detecting missing/reordered/replayed messages).

**Key relationships:**
- Extension to RFC 5424 (uses STRUCTURED-DATA mechanism)
- Configured via RFC 9742 YANG model (signing parameters)
- Transport-agnostic (works over any RFC 5424 transport)

### 9.2 MUST Requirements

| Ref | Requirement |
|-----|-------------|
| General | Implementations MUST support messages up to 2048 octets |
| General | Hash size MUST NOT be shorter than 160 bits without padding |
| RSID | Reboot Session ID MUST strictly monotonically increase across reboots |
| RSID | If persistence cannot be guaranteed, RSID MUST always be 0 |
| Key Blob | Key Blob Type 'C' (PKIX certificate) MUST be supported |
| Verification | X.509 path validation per RFC 5280 MUST be implemented |
| Verification | Certificate fingerprint matching per RFC 5425 S4.2.2 MUST be implemented |

### 9.3 SHOULD Requirements

| Ref | Requirement |
|-----|-------------|
| General | SHA-1 and SHA-256 SHOULD be supported |
| General | UDP transport is NOT RECOMMENDED (480-byte limit) |

### 9.4 MAY Requirements

| Ref | Requirement |
|-----|-------------|
| Key Blob | Types 'P' (OpenPGP), 'K' (raw DSA), 'N' (none), 'U' (vendor) MAY be supported |

### 9.5 Data Model Implications

**Signature Block (SD-ID: `ssign`):**

| Field | Size | Description |
|-------|------|-------------|
| VER | 4 octets | Protocol Version [2] + Hash Algorithm [1] + Signature Scheme [1] |
| RSID | 1-10 octets | Reboot Session ID (decimal 0-9999999999) |
| SG | 1 octet | Signature Group mode (0-3) |
| SPRI | 1-3 octets | Signature Priority (0-191) |
| GBC | 1-10 octets | Global Block Counter (0-9999999999) |
| FMN | 1-10 octets | First Message Number (group-relative) |
| CNT | 1-2 octets | Count of message hashes (1-99) |
| HB | variable | Hash Block (base64 hashes, space-separated) |
| SIGN | variable | Digital signature (base64 OpenPGP DSA r,s) |

**VER field encoding:**
- Protocol Version: `01` (this specification)
- Hash Algorithm: `1` = SHA-1, `2` = SHA-256
- Signature Scheme: `1` = OpenPGP DSA

**Certificate Block (SD-ID: `ssign-cert`):**

| Field | Size | Description |
|-------|------|-------------|
| VER | 4 octets | Same as signature block |
| RSID | 1-10 octets | Reboot Session ID |
| SG | 1 octet | Signature Group |
| SPRI | 1-3 octets | Signature Priority |
| TPBL | 1-8 octets | Total Payload Block Length (decimal) |
| INDEX | 1-8 octets | Byte offset into payload (1-based) |
| FLEN | 1-4 octets | Fragment length (decimal) |
| FRAG | variable | Payload fragment (base64) |
| SIGN | variable | Signature over complete message excluding SIGN |

**Key Blob Types:**
- `C` — PKIX certificate (RFC 5280) — MUST support
- `P` — OpenPGP KeyID (8 octets) + certificate
- `K` — Raw DSA public key (p, q, g, y multiprecision integers)
- `N` — No key (pre-distributed)
- `U` — Vendor-specific key exchange

**Signature Group Modes:**

| SG | Mode | Description |
|----|------|-------------|
| 0 | Single group | All messages signed regardless of PRI |
| 1 | Per-PRI | One group per unique PRI value |
| 2 | PRI ranges | Contiguous PRI ranges with configured boundaries |
| 3 | Custom | Requires pre-arrangement between originator and collector |

### 9.6 Transport Requirements

- Transport-agnostic, but UDP is NOT RECOMMENDED due to 480-byte limit
- Signature and certificate blocks are standard syslog messages themselves
- TLS or TCP transport recommended for reliable delivery of signature blocks

### 9.7 Security Requirements

- OpenPGP DSA signatures (Protocol Version 01)
- SHA-1 minimum hash (160 bits); SHA-256 recommended
- PKIX certificate validation (RFC 5280) mandatory
- Certificate fingerprint support mandatory
- Reboot Session ID must monotonically increase (anti-replay)
- Offline verification: hash chain enables detection of missing, reordered, or replayed messages
- Collector should check for duplicate messages before writing to authenticated log

### 9.8 Edge Cases and Gotchas

1. **Message size explosion:** Signature blocks can be large (multiple base64 hashes). Combined with certificate blocks, this may exceed transport limits.
2. **Certificate block fragmentation:** Large certificates must be fragmented across multiple certificate block messages. Reassembly requires tracking TPBL, INDEX, FLEN.
3. **Reboot Session ID persistence:** If the system cannot persist RSID across reboots (e.g., no stable storage), it must use 0, weakening replay detection.
4. **Global Block Counter wrap:** GBC wraps at 9999999999 — implementation must handle wrap-around.
5. **Signature Group complexity:** SG modes 1-3 require maintaining separate hash chains per group, with independent counters.
6. **Hash chain ordering:** Messages must be verified in the order they were signed. Out-of-order delivery (especially over UDP) breaks verification.
7. **OpenPGP DSA specifics:** The signature format uses RFC 4880 multiprecision integer encoding, not raw DSA output.
8. **Base64 in structured data:** Base64-encoded values within PARAM-VALUE must still escape `"`, `\`, `]`.

### 9.9 Implementation Areas

| Module | Responsibility |
|--------|---------------|
| `signing::signer` | Signature block generation, hash chain management |
| `signing::verifier` | Signature verification, hash chain validation |
| `signing::certificate` | Certificate block generation/reassembly |
| `signing::keymgmt` | Key blob handling, PKIX validation |
| `signing::groups` | Signature group management (SG 0-3) |
| `signing::counter` | GBC, FMN, RSID management and persistence |
| `syslog-core::structured_data` | ssign and ssign-cert SD-ID support |

### 9.10 Compliance Test Checklist

- [ ] Generate signature block with SHA-1 hash
- [ ] Generate signature block with SHA-256 hash
- [ ] Verify signature block with SHA-1
- [ ] Verify signature block with SHA-256
- [ ] Generate certificate block with PKIX certificate (Type C)
- [ ] Fragment large certificate across multiple certificate blocks
- [ ] Reassemble certificate from fragments
- [ ] Reboot Session ID monotonically increases across restarts
- [ ] RSID=0 when persistence unavailable
- [ ] Global Block Counter increments correctly across groups
- [ ] SG=0 single group signing
- [ ] SG=1 per-PRI group signing
- [ ] Hash chain detects missing messages
- [ ] Hash chain detects reordered messages
- [ ] Hash chain detects replayed messages
- [ ] OpenPGP DSA signature format correct
- [ ] Base64 encoding/decoding within SD-PARAM values
- [ ] Escape special characters in base64 PARAM-VALUEs
- [ ] X.509 certificate path validation

---

## 10. RFC 5674 — Alarms in Syslog

### 10.1 RFC Summary

RFC 5674 defines how to represent alarm notifications in syslog using RFC 5424 structured data. It maps ITU-T X.733 alarm model concepts to syslog SD-PARAMs within the `alarm` SD-ID.

**Key relationships:**
- Extension to RFC 5424 STRUCTURED-DATA
- Maps ITU-T X.733 alarm model to syslog
- Uses IANA-registered SD-ID `alarm`
- Referenced by network management systems

### 10.2 MUST Requirements

| Ref | Requirement |
|-----|-------------|
| S3.1 | `resource` parameter MUST be included to identify the alarming resource |
| S3.2 | `probableCause` parameter MUST be included (IANAItuProbableCause mnemonic) |
| S3.3 | `perceivedSeverity` parameter MUST be included |

### 10.3 SHOULD Requirements

| Ref | Requirement |
|-----|-------------|
| S2 | ITU perceived severities SHOULD be mapped to syslog severities per Table 1 |
| S3.4 | `eventType` parameter SHOULD be included (IANAItuEventType mnemonic) |
| S3.5 | `trendIndication` parameter SHOULD be included |
| S3.6 | `resourceURI` parameter SHOULD be included (RFC 3986 URI) |

### 10.4 MAY Requirements

None explicitly stated beyond the optional parameters above.

### 10.5 Data Model Implications

**SD-ID:** `alarm`

**Mandatory Parameters:**

| Parameter | Values | Description |
|-----------|--------|-------------|
| `resource` | string | Unique resource identifier within network element scope |
| `probableCause` | IANAItuProbableCause mnemonic | e.g., `transmissionError`, `lossOfSignal` |
| `perceivedSeverity` | `cleared`, `indeterminate`, `critical`, `major`, `minor`, `warning` | Current alarm severity |

**Optional Parameters:**

| Parameter | Values | Description |
|-----------|--------|-------------|
| `eventType` | IANAItuEventType mnemonic | e.g., `environmentalAlarm`, `equipmentAlarm` |
| `trendIndication` | `moreSevere`, `noChange`, `lessSevere` | Severity trend |
| `resourceURI` | RFC 3986 URI | Resource URI; SNMP resources use RFC 4088 syntax |

**Severity Mapping (ITU to Syslog):**

| ITU Perceived Severity | Syslog Severity |
|------------------------|-----------------|
| Critical | Alert (1) |
| Major | Critical (2) |
| Minor | Error (3) |
| Warning | Warning (4) |
| Indeterminate | Notice (5) |
| Cleared | Notice (5) |

### 10.6 Transport Requirements

No transport-specific requirements. Alarm messages are standard RFC 5424 messages.

### 10.7 Security Requirements

No additional security requirements beyond RFC 5424.

### 10.8 Edge Cases and Gotchas

1. **probableCause is an IANA-maintained enumeration:** The list of valid values may grow over time. Implementation should handle unknown values gracefully.
2. **perceivedSeverity vs syslog severity:** These are independent. The syslog PRI severity and the `perceivedSeverity` SD-PARAM may differ (the mapping table is SHOULD, not MUST).
3. **resourceURI for SNMP:** When the resource is an SNMP managed object, the URI must follow RFC 4088 format.
4. **Alarm correlation:** This RFC defines individual alarm messages, not alarm correlation. Correlation (matching clear to raise) must be handled by the collector.

### 10.9 Implementation Areas

| Module | Responsibility |
|--------|---------------|
| `syslog-core::structured_data::alarm` | Alarm SD-ID parameter handling |
| `extensions::alarm` | Alarm message construction and parsing |
| `extensions::alarm::severity_map` | ITU-to-syslog severity mapping |

### 10.10 Compliance Test Checklist

- [ ] Generate alarm message with all mandatory parameters
- [ ] Parse alarm message with all mandatory parameters
- [ ] Validate `perceivedSeverity` values (cleared, indeterminate, critical, major, minor, warning)
- [ ] Include and parse optional `eventType`
- [ ] Include and parse optional `trendIndication`
- [ ] Include and parse optional `resourceURI`
- [ ] ITU-to-syslog severity mapping matches Table 1
- [ ] Handle unknown `probableCause` values gracefully
- [ ] Alarm SD-ID registered correctly in STRUCTURED-DATA

---

## 11. RFC 5675 — Mapping SNMP Notifications to SYSLOG Messages

### 11.1 RFC Summary

RFC 5675 defines how SNMP trap and inform notifications are translated into syslog messages. It specifies the mapping of SNMP PDU fields to syslog HEADER and STRUCTURED-DATA, including varbind encoding rules.

**Key relationships:**
- Produces RFC 5424 compliant syslog messages from SNMP notifications
- Uses SD-ID `snmp` for varbind data
- Reverse direction defined in RFC 5676
- Uses RFC 5427 facility/severity conventions

**Implementation priority: MEDIUM** — Useful for environments bridging SNMP and syslog.

### 11.2 MUST Requirements

| Ref | Requirement |
|-----|-------------|
| S3.0 | Implementations MUST drop invalid SNMP messages before translation |
| S3.1 | Header character set MUST be seven-bit ASCII per RFC 5424 |
| S3.2 | SNMPv3 notifications MUST include `ctxEngine` and `ctxName` parameters |
| S4 | When tunneling syslog-to-SNMP, relevant SYSLOG-MSG-MIB tables MUST NOT be populated |
| S4 | Missing parameters during tunneling MUST be retrieved from SYSLOG-MSG-MIB |

### 11.3 SHOULD Requirements

| Ref | Requirement |
|-----|-------------|
| S3.1 | Default facility level SHOULD be 3 (daemon) |
| S3.1 | Default severity level SHOULD be 5 (notice) |
| S3.2 | Configuration to enable/disable OID labels SHOULD be provided |
| S3.3 | MSG character set SHOULD be UTF-8 |
| S5 | Origin SD-ID parameters SHOULD identify SNMP originator |

### 11.4 MAY Requirements

| Ref | Requirement |
|-----|-------------|
| S3.2 | SYSLOG messages MAY include additional structured data elements |
| S3.2 | MIB-aware implementations MAY generate `lN` (label) parameters |
| S3.2 | MIB-aware implementations MAY include `aN` (alternate representation) parameters |
| S3.3 | Non-Unicode encoding MAY be used if UTF-8 not possible |
| S5 | `ip` parameter MAY derive from snmpTrapAddress varbind |

### 11.5 Data Model Implications

**SD-ID:** `snmp`

**Context Parameters (SNMPv3):**
- `ctxEngine` — hexadecimal ContextEngineID
- `ctxName` — UTF-8 ContextName

**Varbind Parameters (positional, N = varbind index):**

| Param | SNMP Type | Encoding |
|-------|-----------|----------|
| `vN` | OID | Dotted decimal notation |
| `oN` | OBJECT IDENTIFIER value | Dotted decimal |
| `xN` | OCTET STRING | Hexadecimal |
| `cN` | Counter32 | Unsigned decimal |
| `CN` | Counter64 | Unsigned decimal |
| `uN` | Unsigned32 | Unsigned decimal |
| `dN` | INTEGER/Integer32 | Signed decimal |
| `iN` | IpAddress | Dotted quad |
| `pN` | Opaque | Hexadecimal BER |
| `tN` | TimeTicks | Unsigned decimal |
| `nN` | NULL | Zero-length string |
| `lN` | (label) | MIB descriptor + instance (optional) |
| `aN` | (alternate) | Textual representation (optional) |

**Mapping Algorithm:**
1. Receive SNMP notification (v1/v2c/v3)
2. Validate SNMP message; drop invalid
3. Generate syslog HEADER (translator's local params, facility=3, severity=5 default)
4. Create SD-ELEMENT with SD-ID `snmp`
5. For SNMPv3: include `ctxEngine`, `ctxName`
6. Encode varbinds sequentially with position identifiers
7. Apply type-specific value encoding
8. Optionally include MIB labels and alternate representations

### 11.6 Transport Requirements

No transport-specific requirements. Output is standard RFC 5424 messages.

### 11.7 Security Requirements

- SNMP message validation before translation
- SNMPv3 context information must be preserved
- Translation does not add or remove SNMP security properties

### 11.8 Edge Cases and Gotchas

1. **Varbind index is 1-based:** First varbind uses `v1`, `d1`, etc.
2. **OCTET STRING encoding:** Always hexadecimal, even for printable strings (unless alternate representation provided).
3. **Large notifications:** SNMP notifications with many varbinds may produce syslog messages exceeding transport limits.
4. **MIB awareness optional:** Without MIB knowledge, only raw OIDs and hex values are available.
5. **Facility/severity are translator defaults:** They do not reflect the SNMP notification's actual severity.

### 11.9 Implementation Areas

| Module | Responsibility |
|--------|---------------|
| `extensions::snmp_to_syslog` | SNMP notification to syslog translator |
| `extensions::snmp_to_syslog::varbind` | Varbind encoding per type |
| `extensions::snmp_to_syslog::context` | SNMPv3 context parameter handling |
| `syslog-core::structured_data::snmp` | `snmp` SD-ID parameter definitions |

### 11.10 Compliance Test Checklist

- [ ] Translate SNMPv2c trap to syslog message
- [ ] Translate SNMPv3 trap with context parameters
- [ ] Drop invalid SNMP messages
- [ ] Default facility=3, severity=5
- [ ] Varbind OID in dotted decimal
- [ ] OCTET STRING in hexadecimal
- [ ] Counter32/64 in unsigned decimal
- [ ] Integer32 in signed decimal
- [ ] IpAddress in dotted quad
- [ ] TimeTicks in unsigned decimal
- [ ] NULL as zero-length string
- [ ] SNMPv3 `ctxEngine` and `ctxName` present
- [ ] Optional MIB label parameters
- [ ] Optional alternate representation parameters

---

## 12. RFC 5676 — Managed Objects for Mapping SYSLOG to SNMP Notifications

### 12.1 RFC Summary

RFC 5676 defines a MIB module (SYSLOG-MSG-MIB) for storing syslog messages as SNMP managed objects and generating SNMP notifications from received syslog messages. This enables SNMP-based management systems to monitor syslog data.

**Key relationships:**
- Reverse direction of RFC 5675 (syslog-to-SNMP vs SNMP-to-syslog)
- Uses RFC 5427 textual conventions (SyslogFacility, SyslogSeverity)
- References RFC 5424 message format
- Defines `syslogMsgNotification` SNMP notification

**Implementation priority: LOW** — Only needed if SNMP management is required.

### 12.2 MUST Requirements

| Ref | Requirement |
|-----|-------------|
| S4 | Messages in syslogMsgTable for longest time MUST be discarded first when reducing table limits |
| S6 | Forwarding apps MUST retrieve missing parameters from SYSLOG-MSG-MIB |

### 12.3 SHOULD Requirements

| Ref | Requirement |
|-----|-------------|
| S7 | syslogMsgTableMaxSize SHOULD be kept in nonvolatile memory |
| S10 | SNMPv3 SHOULD be used (pre-SNMPv3 NOT RECOMMENDED) |
| S10 | SYSLOG security mechanisms SHOULD be used to prevent malicious injection |

### 12.4 MAY Requirements

| Ref | Requirement |
|-----|-------------|
| S7 | Implementations MAY truncate the MSG part |
| S7 | syslogMsgNotification MAY include syslogMsgSDParamValue objects |

### 12.5 Data Model Implications

**MIB Structure:**

Control Group:
- `syslogMsgTableMaxSize` (Unsigned32, read-write) — max retained messages; 0 = no limit
- `syslogMsgEnableNotifications` (TruthValue, read-write) — toggle notifications

Main Message Table (`syslogMsgTable`, indexed by `syslogMsgIndex`):
- `syslogMsgIndex` (Unsigned32, wraps at 4,294,967,295)
- Facility (SyslogFacility TC)
- Severity (SyslogSeverity TC)
- Version (0-999; 0 = unknown)
- Timestamp (SyslogTimeStamp TC)
- Hostname, AppName, ProcID, MsgID (DisplayString)
- SDParams count (Unsigned32)
- Message content (OCTET STRING)

Structured Data Table (`syslogMsgSDTable`):
- Indexed by: syslogMsgIndex, syslogMsgSDParamIndex, syslogMsgSDID, syslogMsgSDParamName
- `syslogMsgSDParamValue` (UTF-8, unescaped)

**Notification:** `syslogMsgNotification` carries facility, severity, version, timestamp, hostname, app-name, proc-id, msg-id, param count, and message content.

**Compliance Levels:**
1. Full (read-write control)
2. Read-only (no write)
3. Notification-only (minimal read + notifications)

### 12.6 Transport Requirements

No syslog transport requirements. SNMP transport is used for the MIB/notification side.

### 12.7 Security Requirements

- SNMPv3 with authentication and encryption recommended
- Pre-SNMPv3 NOT RECOMMENDED
- Syslog security mechanisms should prevent malicious data injection into MIB

### 12.8 Edge Cases and Gotchas

1. **Table overflow:** When syslogMsgTableMaxSize is reached, oldest messages are evicted (FIFO).
2. **Index wrapping:** syslogMsgIndex wraps at 2^32 - 1; implementation must handle this.
3. **Message truncation:** Large syslog messages may be truncated to fit SNMP constraints.
4. **UTF-8 BOM detection:** If first octets are `EF BB BF`, the rest of MSG is UTF-8.
5. **Bidirectional tunneling:** Combined with RFC 5675, messages can loop (SNMP->syslog->SNMP). Implementations must prevent this.

### 12.9 Implementation Areas

| Module | Responsibility |
|--------|---------------|
| `extensions::syslog_to_snmp` | Syslog message to SNMP notification translator |
| `extensions::syslog_to_snmp::mib` | SYSLOG-MSG-MIB implementation |
| `extensions::syslog_to_snmp::table` | Message table with FIFO eviction |
| `management::snmp` | SNMP agent integration |

### 12.10 Compliance Test Checklist

- [ ] Store syslog message in syslogMsgTable
- [ ] Retrieve message fields via SNMP GET
- [ ] syslogMsgTableMaxSize limits table entries
- [ ] Oldest messages evicted first when table full
- [ ] syslogMsgIndex wraps correctly
- [ ] Generate syslogMsgNotification for received syslog message
- [ ] Enable/disable notifications via syslogMsgEnableNotifications
- [ ] Structured data parameters accessible via syslogMsgSDTable
- [ ] UTF-8 BOM detection in message content
- [ ] Message truncation handled gracefully
- [ ] No SNMP->syslog->SNMP loop

---

## 13. Traceability Matrix

| RFC | Feature Area | Implementation Module | Mandatory Behaviors | Optional Behaviors | Planned Tests | Compliance Risks |
|-----|-------------|----------------------|--------------------|--------------------|---------------|-----------------|
| **5424** | Core Protocol | `syslog-core::message`, `syslog-core::parser`, `syslog-core::serializer`, `syslog-core::timestamp`, `syslog-core::structured_data`, `syslog-core::facility`, `syslog-core::severity`, `syslog-core::validation` | PRI 0-191, facility 0-23, severity 0-7, HEADER ASCII, TIMESTAMP RFC 3339, SD escaping, NILVALUE handling, field length limits, TLS transport support, 480-octet minimum acceptance | UTF-8 BOM in MSG, >2048 octet messages, malformed SD handling, control char modification | 35 | TIMESTAMP precision loss, SD-ELEMENT adjacency parsing, PARAM-VALUE escape edge cases, UTF-8 shortest form validation |
| **3195** | Reliable Delivery (BEEP) | `transport::beep`, `syslog-core::legacy_parser` | BEEP channel lifecycle, RAW 1024-byte limit, COOKED entry preservation, path element IP verification | DNS SRV discovery, sophisticated message parsing, path element generation from UDP | 10 | No mature Rust BEEP crate, RFC 3164 format dependency, legacy crypto (DIGEST-MD5, 3DES), complex path nesting |
| **5425** | TLS Transport | `transport::tls`, `transport::tls::framing`, `transport::tls::cert`, `transport::tls::auth`, `config::tls` | TLS 1.2+, certificate auth, path validation, fingerprints (SHA-1), octet-counting framing, 2048-octet messages, close_notify, hostname matching, wildcard support, ACE conversion | 8192-octet messages, inactivity timeout closure, session resumption validation | 18 | Octet-counting vs newline framing confusion, partial TCP reads, certificate identity vs HOSTNAME mismatch, session resumption security |
| **5426** | UDP Transport | `transport::udp`, `config::udp` | One message per datagram, 480/1180-octet acceptance (IPv4/IPv6), port 514, UDP checksums enabled | 2048-octet acceptance, configurable ports, MTU-aware sending | 12 | Silent message loss, IP fragmentation, source IP spoofing, no congestion control, IPv4 zero-checksum acceptance |
| **6012** | DTLS Transport | `transport::dtls`, `config::dtls` | DTLS 1.2+ (not 1.0), certificate auth, no NULL ciphers, cookie exchange, 2048-octet messages, close_notify, no pre-handshake messages | DTLS 1.3, DCCP transport, 8192-octet messages, CCID 3 for DCCP | 14 | DTLS over TCP prohibited, shared port 6514, PMTU limitations, DTLS record overhead, renegotiation vulnerability |
| **9662** | Cipher Suite Updates | `transport::tls::cipher`, `transport::dtls::cipher`, `config::tls`, `config::dtls` | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_RSA_WITH_AES_128_CBC_SHA`, DTLS 1.2+ (not 1.0), no 0-RTT | TLS 1.3, DTLS 1.3, legacy RSA suite as migration path | 9 | Dual cipher suite requirement, 0-RTT prohibition enforcement, DTLS 1.0 rejection, TLS 1.3 suite namespace differences |
| **5427** | Management Textual Conventions | `syslog-core::facility`, `syslog-core::severity`, `management::snmp::tc` | Facility/severity name-to-code mapping in MIB interfaces | None | 5 | OS-specific facility label ambiguity (codes 4/10, 9/15, 13/14), closed enumeration |
| **9742** | YANG Configuration Model | `config::model`, `config::filter`, `config::pattern`, `config::file`, `config::remote`, `config::signing`, `server::actions` | File URI scheme, TLS client identity, ReDoS-safe regex, key isolation | Structured data format options, vendor augmentation, feature flags | 15 | ReDoS in pattern matching, feature flag dependency tracking, file URI requirement, facility override PRI recalculation |
| **5848** | Signed Messages | `signing::signer`, `signing::verifier`, `signing::certificate`, `signing::keymgmt`, `signing::groups`, `signing::counter`, `syslog-core::structured_data` | 2048-octet messages, 160-bit minimum hash, RSID monotonic increase, PKIX cert support (Type C), X.509 path validation | SHA-256, OpenPGP/raw DSA key blobs, vendor key exchange, SG modes 2-3 | 19 | Message size explosion with signatures, certificate fragmentation/reassembly, RSID persistence, GBC wrap-around, hash chain ordering, OpenPGP DSA format |
| **5674** | Alarms | `extensions::alarm`, `syslog-core::structured_data::alarm` | `resource`, `probableCause`, `perceivedSeverity` parameters in `alarm` SD-ID | `eventType`, `trendIndication`, `resourceURI` parameters, ITU severity mapping | 9 | probableCause enumeration growth, perceivedSeverity vs syslog severity independence, alarm correlation (not defined) |
| **5675** | SNMP-to-Syslog | `extensions::snmp_to_syslog`, `syslog-core::structured_data::snmp` | Drop invalid SNMP, ASCII header, SNMPv3 context params, no SYSLOG-MSG-MIB population during tunneling | OID labels, alternate representations, non-UTF-8 encoding | 14 | Large notification size, OCTET STRING always hex, facility/severity are translator defaults not notification severity, MIB awareness optional |
| **5676** | Syslog-to-SNMP MIB | `extensions::syslog_to_snmp`, `management::snmp` | FIFO eviction, retrieve missing params from MIB | Message truncation, SD params in notification, table size = 0 (unlimited) | 11 | Index wrapping at 2^32, bidirectional tunneling loops, message truncation, UTF-8 BOM detection, SNMPv3 requirement |

---

## Appendix A: Implementation Priority

Based on deployment prevalence and dependency analysis:

| Priority | RFC | Rationale |
|----------|-----|-----------|
| **P0 — Critical** | RFC 5424 | Core message format; everything depends on it |
| **P0 — Critical** | RFC 5425 | Primary secure transport; production deployments require TLS |
| **P0 — Critical** | RFC 5426 | Most common transport; backward compatibility essential |
| **P0 — Critical** | RFC 9662 | Mandatory cipher suite updates for RFC 5425/6012 |
| **P1 — High** | RFC 5427 | Foundational data types used by management interfaces |
| **P1 — High** | RFC 6012 | Secure UDP transport for environments needing datagram semantics |
| **P2 — Medium** | RFC 5848 | Message signing for high-integrity environments |
| **P2 — Medium** | RFC 5674 | Alarm support for network management integration |
| **P2 — Medium** | RFC 9742 | Standard configuration model; enables interoperable management |
| **P3 — Low** | RFC 5675 | SNMP bridge; niche use case |
| **P3 — Low** | RFC 5676 | SNMP bridge (reverse); niche use case |
| **P4 — Deferred** | RFC 3195 | BEEP transport; minimal modern adoption, no Rust BEEP ecosystem |

## Appendix B: Cross-RFC Dependency Graph

```
RFC 5424 (Core Protocol)
 ├── RFC 5425 (TLS Transport)
 │    └── RFC 9662 (Cipher Suite Updates) ──updates──> RFC 5425
 ├── RFC 5426 (UDP Transport)
 │    └── RFC 6012 (DTLS Transport)
 │         └── RFC 9662 (Cipher Suite Updates) ──updates──> RFC 6012
 ├── RFC 5848 (Signed Messages) ──uses SD──> RFC 5424
 │    └── RFC 9742 (YANG Model) ──configures──> RFC 5848
 ├── RFC 5674 (Alarms) ──uses SD──> RFC 5424
 ├── RFC 5675 (SNMP→Syslog) ──produces──> RFC 5424 messages
 │    └── RFC 5676 (Syslog→SNMP) ──reverse of──> RFC 5675
 ├── RFC 5427 (Textual Conventions) ──used by──> RFC 5676, RFC 9742
 ├── RFC 9742 (YANG Model) ──configures──> RFC 5424, RFC 5425, RFC 5426
 └── RFC 3195 (Reliable/BEEP) ──transports──> RFC 3164 (legacy)
```

## Appendix C: Consolidated Port Assignments

| Port | Protocol | RFC | Service |
|------|----------|-----|---------|
| 514 | UDP | RFC 5426 | Syslog (cleartext) |
| 601 | TCP | RFC 3195 | Syslog-conn (BEEP) |
| 6514 | TCP | RFC 5425 | Syslog-TLS |
| 6514 | UDP | RFC 6012 | Syslog-DTLS |
| 6514 | DCCP | RFC 6012 | Syslog-DTLS (preferred) |

## Appendix D: Consolidated Message Size Requirements

| Context | Minimum (MUST) | Recommended (SHOULD) | Maximum |
|---------|----------------|---------------------|---------|
| RFC 5424 (any transport) | 480 octets | 2048 octets | Transport-defined |
| RFC 5425 (TLS) | 2048 octets | 8192 octets | Unlimited (TCP stream) |
| RFC 5426 (UDP, IPv4) | 480 octets | 2048 octets | 65,507 octets |
| RFC 5426 (UDP, IPv6) | 1180 octets | 2048 octets | 65,507 octets |
| RFC 6012 (DTLS) | 2048 octets | 8192 octets | PMTU-limited |
| RFC 3195 (BEEP RAW) | N/A | N/A | 1024 octets |
| RFC 5848 (Signed) | 2048 octets | N/A | Transport-defined |

