# Phase 06 — Message Parsing, Validation, and Normalization

**Document Version:** 1.0
**Date:** 2026-03-11
**Status:** Draft
**Scope:** Parser architecture, message model, RFC 5424/3164 parsing, validation, error taxonomy, serialization, extension handling, and performance strategy for the syslog-usg parsing pipeline.

---

## Table of Contents

1. [Parsing Pipeline Design](#1-parsing-pipeline-design)
2. [Message Model](#2-message-model)
3. [RFC 5424 Parser](#3-rfc-5424-parser)
4. [RFC 3164 Legacy Parser](#4-rfc-3164-legacy-parser)
5. [Validation Rules](#5-validation-rules)
6. [Error Taxonomy](#6-error-taxonomy)
7. [Serializer](#7-serializer)
8. [Extension Handling](#8-extension-handling)
9. [Parser Performance Considerations](#9-parser-performance-considerations)

---

## 1. Parsing Pipeline Design

### 1.1 Architecture Overview

The parser operates as a stateless, synchronous function that transforms raw bytes into a validated `SyslogMessage`. It is deliberately not async — parsing is CPU-bound work that completes in microseconds, and introducing async machinery would add overhead with no benefit. The async transport layer calls the parser synchronously after receiving a complete message frame.

```
Raw Bytes (&[u8] or Bytes)
        |
        v
  +-----------------+
  | Format Detector |  -- Peek at bytes after PRI to detect version field
  +-----------------+
        |
   +----+----+
   |         |
   v         v
+-------+  +-------+
| RFC   |  | RFC   |
| 5424  |  | 3164  |
| Parser|  | Parser|
+-------+  +-------+
   |         |
   v         v
  +-----------------+
  | Validation Pass |  -- Strict mode: fail on violation; Lenient: annotate
  +-----------------+
        |
        v
  Result<SyslogMessage, ParseError>
```

### 1.2 Input Types

The parser accepts two input forms:

```rust
/// Parse from a borrowed byte slice. Zero-copy where possible by
/// returning string references into the input. Suitable for UDP
/// datagrams and stack-local buffers.
pub fn parse(input: &[u8], opts: &ParseOptions) -> Result<SyslogMessage<'_>, ParseError>;

/// Parse from an owned `Bytes` buffer. Enables zero-copy field extraction
/// via `Bytes::slice()` without lifetime entanglement. Suitable for
/// TCP/TLS streams where the buffer outlives the parse call.
pub fn parse_bytes(input: Bytes, opts: &ParseOptions) -> Result<OwnedSyslogMessage, ParseError>;
```

The dual-signature approach avoids forcing callers into a single ownership model. The borrowed variant (`SyslogMessage<'_>`) is used on hot paths where the message is immediately forwarded or serialized. The owned variant (`OwnedSyslogMessage`) is used when the message must be stored, queued, or passed across task boundaries.

### 1.3 Two-Phase Detection

Format detection is cheap — it examines at most 5 bytes after the PRI closing `>`:

1. Extract PRI (both formats share `<PRIVAL>` syntax).
2. Peek at the byte immediately after `>`:
   - If it is an ASCII digit `1`-`9` and the next byte is a space (`0x20`), this is RFC 5424 (the VERSION field).
   - Otherwise, assume RFC 3164 (BSD legacy).

This heuristic is reliable because RFC 3164 messages place a timestamp (starting with a month abbreviation letter) or a hostname immediately after PRI, never a bare digit followed by a space.

```rust
fn detect_format(input: &[u8], pri_end: usize) -> MessageFormat {
    if pri_end + 2 <= input.len() {
        let first = input[pri_end];
        let second = input[pri_end + 1];
        if first >= b'1' && first <= b'9' && second == b' ' {
            return MessageFormat::Rfc5424;
        }
    }
    MessageFormat::Rfc3164
}

enum MessageFormat {
    Rfc5424,
    Rfc3164,
}
```

### 1.4 Parse Modes

```rust
/// Controls parser strictness and metadata attachment.
pub struct ParseOptions {
    /// Strict: reject on any ABNF violation.
    /// Lenient: best-effort parse with error annotations.
    pub mode: ParseMode,

    /// Maximum message size in bytes. Messages exceeding this are
    /// rejected before parsing begins. Default: 8192.
    pub max_message_size: usize,

    /// If true, preserve the raw input bytes in the parsed message
    /// for relay passthrough without re-serialization.
    pub preserve_raw: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMode {
    /// Reject the message on any deviation from the ABNF grammar.
    Strict,
    /// Parse as much as possible, collecting warnings for each
    /// deviation. The message is still returned if the essential
    /// structure (PRI) can be extracted.
    Lenient,
}
```

In **strict mode**, the parser returns `Err(ParseError)` on the first violation. This is used for conformance testing and environments that require exact RFC compliance.

In **lenient mode**, the parser accumulates `ParseWarning` annotations on the `SyslogMessage` and makes best-effort substitutions:
- Unparseable timestamps become `None` (with a `InvalidTimestamp` warning).
- Over-length fields are accepted but annotated with `FieldTooLong`.
- Invalid characters in header fields are preserved but annotated.
- Malformed structured data is stored as raw bytes and annotated.

### 1.5 Return Type

The top-level return type is `Result<SyslogMessage, ParseError>`. In lenient mode, the `Err` variant is returned only when the input is so malformed that no useful structure can be extracted (e.g., no PRI present, message is empty, message exceeds max size).

---

## 2. Message Model

### 2.1 Core Enums

```rust
/// Syslog facility codes (RFC 5424 Section 6.2.1).
/// Backed by u8 for compact storage and fast PRI arithmetic.
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
    Alert    = 14,
    Clock    = 15,
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
    /// Convert from the raw numeric code. Returns `None` for values > 23.
    pub fn from_u8(val: u8) -> Option<Facility> {
        if val <= 23 {
            // SAFETY: repr(u8) and values 0-23 are all defined variants.
            Some(unsafe { std::mem::transmute(val) })
        } else {
            None
        }
    }
}

/// Syslog severity codes (RFC 5424 Section 6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    pub fn from_u8(val: u8) -> Option<Severity> {
        if val <= 7 {
            Some(unsafe { std::mem::transmute(val) })
        } else {
            None
        }
    }
}
```

Note on `unsafe`: The `Facility::from_u8` and `Severity::from_u8` functions are the only uses of unsafe in the parser crate. They are isolated, trivially auditable (the `repr(u8)` guarantee plus range check makes the transmute sound), and exist purely for performance — avoiding a 24-arm or 8-arm match in a function called for every single message. The crate uses `#![deny(unsafe_code)]` at the crate root with an explicit `#[allow(unsafe_code)]` only on these two `impl` blocks. An alternative safe implementation using a match is provided behind a `cfg(miri)` gate for Miri-based testing.

### 2.2 Timestamp Representation

```rust
/// Syslog timestamp with nanosecond precision and timezone offset.
///
/// Uses `time::OffsetDateTime` internally for correct calendar arithmetic,
/// but preserves the original fractional-second precision digit count
/// for lossless round-trip serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogTimestamp {
    /// The parsed date-time with UTC offset.
    pub datetime: time::OffsetDateTime,
    /// Number of fractional-second digits in the original representation
    /// (0 = no fractional part, 1-6 = .X through .XXXXXX).
    /// Used to preserve precision during re-serialization.
    pub secfrac_digits: u8,
}
```

Using the `time` crate (not `chrono`) because:
- `time` has a smaller dependency footprint.
- `time` avoids the `localtime_r` soundness issue that affects `chrono` on some platforms.
- `OffsetDateTime` natively supports UTC offsets, matching the RFC 5424 TIME-OFFSET semantics exactly.

### 2.3 Structured Data Types

```rust
/// A single structured data element: `[SD-ID param1="val1" param2="val2"]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdElement<'a> {
    /// The SD-ID (e.g., "timeQuality", "mySD@32473").
    /// Max 32 PRINTUSASCII characters, excluding '=', SP, ']', '"'.
    pub id: FieldStr<'a>,
    /// Parameters within this element. Most elements have 1-4 params;
    /// SmallVec avoids heap allocation for the common case.
    pub params: SmallVec<[SdParam<'a>; 4]>,
}

/// A single SD-PARAM: `name="value"` within an SD-ELEMENT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdParam<'a> {
    /// Parameter name. Max 32 PRINTUSASCII characters, same restrictions as SD-ID.
    pub name: FieldStr<'a>,
    /// Parameter value. UTF-8 encoded, with escape sequences already resolved.
    /// The original escaping (`\"`, `\\`, `\]`) is decoded during parsing.
    pub value: ParamValue<'a>,
}

/// A field string — either a zero-copy reference into the input buffer,
/// or an owned String for cases requiring allocation (e.g., escape decoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldStr<'a> {
    /// Zero-copy borrow from the input buffer.
    Borrowed(&'a str),
    /// Owned copy, used when the field had to be modified during parsing.
    Owned(String),
}

/// A parameter value — either a zero-copy slice (when no escapes present)
/// or an owned String (when escape sequences were decoded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamValue<'a> {
    /// The raw bytes contained no escape sequences; this is a direct
    /// reference into the input buffer.
    Borrowed(&'a str),
    /// Escape sequences were decoded, requiring a new allocation.
    Owned(String),
}
```

### 2.4 The SyslogMessage Struct

```rust
/// A parsed syslog message with all RFC 5424 fields.
///
/// Lifetime `'a` is tied to the input buffer for zero-copy field access.
/// Use `OwnedSyslogMessage` (via `.to_owned()`) when the message must
/// outlive the input buffer.
#[derive(Debug, Clone)]
pub struct SyslogMessage<'a> {
    // === PRI ===

    /// Raw PRI value (0-191). Preserved for lossless round-trip.
    pub pri: u8,
    /// Facility extracted from PRI (pri / 8).
    pub facility: Facility,
    /// Severity extracted from PRI (pri % 8).
    pub severity: Severity,

    // === HEADER ===

    /// Protocol version. Currently always 1 for RFC 5424.
    /// `None` for RFC 3164 messages mapped to this struct.
    pub version: Option<u8>,
    /// Message timestamp. `None` if NILVALUE or unparseable (lenient mode).
    pub timestamp: Option<SyslogTimestamp>,
    /// Hostname. `None` if NILVALUE.
    pub hostname: Option<FieldStr<'a>>,
    /// Application name. `None` if NILVALUE.
    pub app_name: Option<FieldStr<'a>>,
    /// Process ID. `None` if NILVALUE.
    pub proc_id: Option<FieldStr<'a>>,
    /// Message ID. `None` if NILVALUE.
    pub msg_id: Option<FieldStr<'a>>,

    // === STRUCTURED-DATA ===

    /// Structured data elements. Empty vec if NILVALUE ("-").
    /// SmallVec<[SdElement; 2]> since most messages have 0-2 elements.
    pub structured_data: SmallVec<[SdElement<'a>; 2]>,

    // === MSG ===

    /// The message body. `None` if no MSG part was present.
    pub msg: Option<MessageBody<'a>>,

    // === RAW ===

    /// Original raw bytes, preserved for relay passthrough.
    /// Only populated when `ParseOptions::preserve_raw` is true.
    pub raw: Option<Bytes>,

    // === METADATA ===

    /// Metadata attached by the transport layer, not part of the
    /// syslog protocol itself.
    pub metadata: MessageMetadata,

    // === PARSE QUALITY ===

    /// The original message format that was detected.
    pub source_format: MessageFormat,
    /// Warnings accumulated during lenient-mode parsing.
    /// Empty in strict mode (violations cause errors instead).
    pub warnings: SmallVec<[ParseWarning; 2]>,
}

/// The MSG body with encoding information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageBody<'a> {
    /// MSG started with BOM (EF BB BF); content is valid UTF-8.
    Utf8 {
        /// The UTF-8 string content (BOM stripped).
        content: &'a str,
        /// Whether the BOM was present (for round-trip fidelity).
        had_bom: bool,
    },
    /// MSG did not start with BOM or was not valid UTF-8.
    /// Treated as opaque octets per RFC 5424 Section 6.4.
    Bytes(&'a [u8]),
}

/// Transport-level metadata attached to each message.
#[derive(Debug, Clone, Default)]
pub struct MessageMetadata {
    /// Timestamp when the message was received by this server.
    /// Always populated by the transport layer.
    pub receive_time: Option<time::OffsetDateTime>,
    /// Source address of the sender (IP:port for network transports).
    pub source_addr: Option<std::net::SocketAddr>,
    /// Identifier of the listener that received this message
    /// (matches the listener name from configuration).
    pub listener_id: Option<String>,
    /// Transport protocol used.
    pub transport: Option<Transport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
}
```

### 2.5 Owned Variant

For messages that must cross async task boundaries or be stored in queues:

```rust
/// Fully owned variant of `SyslogMessage` with `'static` lifetime.
/// All string fields use `String` or `Bytes` instead of borrowed references.
///
/// Constructed via `SyslogMessage::to_owned()` or by parsing with
/// `parse_bytes()` which leverages `Bytes::slice()` for cheap cloning.
pub type OwnedSyslogMessage = SyslogMessage<'static>;

impl<'a> SyslogMessage<'a> {
    /// Convert to a fully owned message by cloning all borrowed data.
    pub fn to_owned_message(&self) -> OwnedSyslogMessage {
        // ... clone all FieldStr::Borrowed to FieldStr::Owned, etc.
    }
}
```

When using `parse_bytes()` with a `Bytes` input, the parser can produce an `OwnedSyslogMessage` where `FieldStr` variants hold `Bytes` sub-slices rather than `&str` borrows. This avoids copying while still being `'static`. The implementation uses a `FieldStr::Shared(Bytes)` variant internally:

```rust
pub enum FieldStr<'a> {
    Borrowed(&'a str),
    Shared(Bytes),   // zero-copy from Bytes input; valid UTF-8 guaranteed
    Owned(String),
}
```

---

## 3. RFC 5424 Parser

### 3.1 Parser State Machine

The RFC 5424 parser is implemented as a sequential field-by-field parser operating on a cursor over the input bytes. There is no separate lexer stage — each parse function advances the cursor directly.

```rust
/// Internal parser cursor. Tracks position within the input buffer.
struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn remaining(&self) -> &'a [u8] { &self.input[self.pos..] }
    fn peek(&self) -> Option<u8> { self.input.get(self.pos).copied() }
    fn advance(&mut self, n: usize) { self.pos += n; }
    fn expect_byte(&mut self, b: u8) -> Result<(), ParseError> { ... }
    fn take_while<F: Fn(u8) -> bool>(&mut self, pred: F) -> &'a [u8] { ... }
    fn take_sp_delimited_field(&mut self, max_len: usize) -> Result<&'a [u8], ParseError> { ... }
}
```

### 3.2 PRI Parsing

```rust
/// Parse the PRI field: '<' 1*3DIGIT '>'
///
/// Validates:
/// - Opening '<' and closing '>'
/// - 1 to 3 ASCII digits between brackets
/// - No leading zeros (except for PRI value 0, which is "<0>")
/// - Resulting value in range 0..=191
///
/// Returns the raw PRI value. The caller decomposes into facility and severity.
fn parse_pri(cursor: &mut Cursor) -> Result<u8, ParseError> {
    cursor.expect_byte(b'<').map_err(|_| ParseError::MissingPri)?;

    let start = cursor.pos;
    let digits = cursor.take_while(|b| b.is_ascii_digit());

    if digits.is_empty() || digits.len() > 3 {
        return Err(ParseError::InvalidPri {
            span: Span { start: start - 1, end: cursor.pos },
        });
    }

    // Check for leading zeros: "<034>" is invalid, "<0>" is valid.
    if digits.len() > 1 && digits[0] == b'0' {
        return Err(ParseError::InvalidPri {
            span: Span { start, end: start + digits.len() },
        });
    }

    cursor.expect_byte(b'>').map_err(|_| ParseError::InvalidPri {
        span: Span { start: start - 1, end: cursor.pos },
    })?;

    // Manual ASCII-to-u8 conversion (faster than str::parse for 1-3 digits).
    let val: u16 = digits.iter().fold(0u16, |acc, &d| acc * 10 + (d - b'0') as u16);

    if val > 191 {
        return Err(ParseError::PriOutOfRange { value: val });
    }

    Ok(val as u8)
}
```

Facility and severity decomposition:

```rust
fn decompose_pri(pri: u8) -> (Facility, Severity) {
    // These unwraps are safe because pri <= 191 guarantees
    // facility <= 23 and severity <= 7.
    let facility = Facility::from_u8(pri >> 3).unwrap();
    let severity = Severity::from_u8(pri & 0x07).unwrap();
    (facility, severity)
}
```

### 3.3 VERSION Parsing

```rust
/// Parse the VERSION field immediately after PRI.
///
/// RFC 5424 defines VERSION = NONZERO-DIGIT 0*2DIGIT.
/// The only defined version is "1". We parse the general form
/// but reject versions other than 1 in strict mode.
fn parse_version(cursor: &mut Cursor, mode: ParseMode) -> Result<u8, ParseError> {
    let start = cursor.pos;
    let digits = cursor.take_while(|b| b.is_ascii_digit());

    if digits.is_empty() || digits[0] == b'0' {
        return Err(ParseError::InvalidVersion {
            span: Span { start, end: cursor.pos },
        });
    }

    if digits.len() > 3 {
        return Err(ParseError::InvalidVersion {
            span: Span { start, end: cursor.pos },
        });
    }

    let version: u16 = digits.iter().fold(0u16, |acc, &d| acc * 10 + (d - b'0') as u16);

    if version != 1 && mode == ParseMode::Strict {
        return Err(ParseError::UnsupportedVersion { version: version as u8 });
    }

    cursor.expect_byte(b' ')?;
    Ok(version as u8)
}
```

### 3.4 TIMESTAMP Parsing

The timestamp parser handles the full RFC 3339 profile specified by RFC 5424:

```
TIMESTAMP       = NILVALUE / FULL-DATE "T" FULL-TIME
FULL-DATE       = DATE-FULLYEAR "-" DATE-MONTH "-" DATE-MDAY
FULL-TIME       = PARTIAL-TIME TIME-OFFSET
PARTIAL-TIME    = TIME-HOUR ":" TIME-MINUTE ":" TIME-SECOND [TIME-SECFRAC]
TIME-SECFRAC    = "." 1*6DIGIT
TIME-OFFSET     = "Z" / TIME-NUMOFFSET
TIME-NUMOFFSET  = ("+" / "-") TIME-HOUR ":" TIME-MINUTE
```

```rust
/// Parse RFC 5424 TIMESTAMP field.
///
/// Returns `None` for NILVALUE ("-").
/// Returns the parsed timestamp with preserved fractional-second precision.
///
/// Key validations:
/// - "T" and "Z" must be uppercase (RFC 5424 S6.2.3)
/// - Leap seconds (second == 60) are rejected (RFC 5424 S6.2.3)
/// - Fractional seconds limited to 6 digits
/// - Timezone offset hour/minute ranges validated
/// - Calendar date validity checked (e.g., no Feb 30)
fn parse_timestamp(cursor: &mut Cursor) -> Result<Option<SyslogTimestamp>, ParseError> {
    // Check for NILVALUE
    if cursor.peek() == Some(b'-') {
        cursor.advance(1);
        return Ok(None);
    }

    let start = cursor.pos;

    // DATE-FULLYEAR "-" DATE-MONTH "-" DATE-MDAY
    let year = parse_fixed_digits::<4>(cursor)?;   // 4DIGIT
    cursor.expect_byte(b'-')?;
    let month = parse_fixed_digits::<2>(cursor)?;   // 2DIGIT (01-12)
    cursor.expect_byte(b'-')?;
    let day = parse_fixed_digits::<2>(cursor)?;     // 2DIGIT (01-31)

    // "T" (must be uppercase)
    let t_byte = cursor.peek().ok_or(ParseError::UnexpectedEndOfInput)?;
    if t_byte != b'T' {
        return Err(ParseError::InvalidTimestamp {
            reason: TimestampError::LowercaseSeparator,
            span: Span { start, end: cursor.pos + 1 },
        });
    }
    cursor.advance(1);

    // PARTIAL-TIME
    let hour = parse_fixed_digits::<2>(cursor)?;    // 00-23
    cursor.expect_byte(b':')?;
    let minute = parse_fixed_digits::<2>(cursor)?;  // 00-59
    cursor.expect_byte(b':')?;
    let second = parse_fixed_digits::<2>(cursor)?;  // 00-59

    // Reject leap seconds
    if second >= 60 {
        return Err(ParseError::InvalidTimestamp {
            reason: TimestampError::LeapSecond,
            span: Span { start, end: cursor.pos },
        });
    }

    // TIME-SECFRAC (optional)
    let (nanos, secfrac_digits) = if cursor.peek() == Some(b'.') {
        cursor.advance(1);
        let frac_start = cursor.pos;
        let frac_bytes = cursor.take_while(|b| b.is_ascii_digit());
        let frac_len = frac_bytes.len();

        if frac_len == 0 || frac_len > 6 {
            return Err(ParseError::InvalidTimestamp {
                reason: TimestampError::InvalidFractionalSeconds,
                span: Span { start: frac_start - 1, end: cursor.pos },
            });
        }

        // Convert to nanoseconds, padding to 9 digits.
        let mut nanos: u32 = frac_bytes.iter()
            .fold(0u32, |acc, &d| acc * 10 + (d - b'0') as u32);
        for _ in 0..(9 - frac_len) {
            nanos *= 10;
        }

        (nanos, frac_len as u8)
    } else {
        (0u32, 0u8)
    };

    // TIME-OFFSET
    let offset = match cursor.peek() {
        Some(b'Z') => {
            cursor.advance(1);
            time::UtcOffset::UTC
        }
        Some(b'z') => {
            return Err(ParseError::InvalidTimestamp {
                reason: TimestampError::LowercaseUtc,
                span: Span { start: cursor.pos, end: cursor.pos + 1 },
            });
        }
        Some(b'+') | Some(b'-') => {
            let sign = if cursor.peek() == Some(b'+') { 1i8 } else { -1i8 };
            cursor.advance(1);
            let off_h = parse_fixed_digits::<2>(cursor)?;
            cursor.expect_byte(b':')?;
            let off_m = parse_fixed_digits::<2>(cursor)?;

            if off_h > 23 || off_m > 59 {
                return Err(ParseError::InvalidTimestamp {
                    reason: TimestampError::InvalidOffset,
                    span: Span { start, end: cursor.pos },
                });
            }

            let total_seconds = sign as i32 * (off_h as i32 * 3600 + off_m as i32 * 60);
            time::UtcOffset::from_whole_seconds(total_seconds)
                .map_err(|_| ParseError::InvalidTimestamp {
                    reason: TimestampError::InvalidOffset,
                    span: Span { start, end: cursor.pos },
                })?
        }
        _ => {
            return Err(ParseError::InvalidTimestamp {
                reason: TimestampError::MissingOffset,
                span: Span { start, end: cursor.pos },
            });
        }
    };

    // Construct the datetime, validating calendar date.
    let date = time::Date::from_calendar_date(
        year as i32,
        time::Month::try_from(month as u8).map_err(|_| ParseError::InvalidTimestamp {
            reason: TimestampError::InvalidMonth,
            span: Span { start, end: cursor.pos },
        })?,
        day as u8,
    ).map_err(|_| ParseError::InvalidTimestamp {
        reason: TimestampError::InvalidDate,
        span: Span { start, end: cursor.pos },
    })?;

    let time = time::Time::from_hms_nano(hour as u8, minute as u8, second as u8, nanos)
        .map_err(|_| ParseError::InvalidTimestamp {
            reason: TimestampError::InvalidTime,
            span: Span { start, end: cursor.pos },
        })?;

    Ok(Some(SyslogTimestamp {
        datetime: time::OffsetDateTime::new_in_offset(date, time, offset),
        secfrac_digits,
    }))
}

/// Parse exactly N ASCII digit bytes, returning the numeric value.
fn parse_fixed_digits<const N: usize>(cursor: &mut Cursor) -> Result<u32, ParseError> {
    if cursor.pos + N > cursor.input.len() {
        return Err(ParseError::UnexpectedEndOfInput);
    }
    let slice = &cursor.input[cursor.pos..cursor.pos + N];
    if !slice.iter().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::InvalidTimestamp {
            reason: TimestampError::ExpectedDigit,
            span: Span { start: cursor.pos, end: cursor.pos + N },
        });
    }
    cursor.advance(N);
    Ok(slice.iter().fold(0u32, |acc, &d| acc * 10 + (d - b'0') as u32))
}
```

### 3.5 Header Field Parsing (HOSTNAME, APP-NAME, PROCID, MSGID)

All four header fields share the same structure: either NILVALUE ("-") or 1 to N characters of PRINTUSASCII (%d33-126), delimited by SP (space).

```rust
/// Field length limits per RFC 5424 Section 6.
const HOSTNAME_MAX_LEN: usize = 255;
const APP_NAME_MAX_LEN: usize = 48;
const PROC_ID_MAX_LEN: usize = 128;
const MSG_ID_MAX_LEN: usize = 32;

/// Parse a space-delimited header field.
///
/// Returns `None` for NILVALUE ("-").
/// Validates:
/// - Field length <= max_len
/// - All bytes in PRINTUSASCII range (%d33-126)
fn parse_header_field<'a>(
    cursor: &mut Cursor<'a>,
    field_name: &'static str,
    max_len: usize,
    mode: ParseMode,
) -> Result<Option<FieldStr<'a>>, ParseError> {
    let start = cursor.pos;

    // Take bytes until next SP or end of input.
    let field_bytes = cursor.take_while(|b| b != b' ');

    // Check for NILVALUE
    if field_bytes == b"-" {
        return Ok(None);
    }

    // Validate length
    if field_bytes.len() > max_len {
        if mode == ParseMode::Strict {
            return Err(ParseError::FieldTooLong {
                field: field_name,
                max: max_len,
                actual: field_bytes.len(),
            });
        }
        // Lenient: accept but caller adds warning
    }

    // Validate character set: PRINTUSASCII = %d33-126
    for (i, &b) in field_bytes.iter().enumerate() {
        if b < 33 || b > 126 {
            if mode == ParseMode::Strict {
                return Err(ParseError::InvalidCharacter {
                    field: field_name,
                    position: start + i,
                    byte: b,
                });
            }
            // Lenient: accept
        }
    }

    // Safe because we verified all bytes are in 33-126 (ASCII printable).
    let s = std::str::from_utf8(field_bytes).expect("PRINTUSASCII is valid UTF-8");
    Ok(Some(FieldStr::Borrowed(s)))
}
```

### 3.6 STRUCTURED-DATA Parsing

Structured data is the most complex part of the RFC 5424 grammar due to nesting, escaping, and the requirement to detect adjacent elements without intermediate spaces.

```
STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT
SD-ELEMENT      = "[" SD-ID *(SP SD-PARAM) "]"
SD-PARAM        = PARAM-NAME "=" %d34 PARAM-VALUE %d34
SD-ID           = SD-NAME
PARAM-NAME      = SD-NAME
SD-NAME         = 1*32PRINTUSASCII  ; except '=', SP, ']', '"'
PARAM-VALUE     = *(... escaping for ", \, ])
```

```rust
/// Characters forbidden in SD-NAME (SD-ID and PARAM-NAME).
fn is_sd_name_char(b: u8) -> bool {
    b >= 33 && b <= 126 && b != b'=' && b != b' ' && b != b']' && b != b'"'
}

/// Parse the STRUCTURED-DATA field.
///
/// Returns an empty SmallVec for NILVALUE.
fn parse_structured_data<'a>(
    cursor: &mut Cursor<'a>,
    mode: ParseMode,
) -> Result<SmallVec<[SdElement<'a>; 2]>, ParseError> {
    // Check for NILVALUE
    if cursor.peek() == Some(b'-') {
        cursor.advance(1);
        return Ok(SmallVec::new());
    }

    let mut elements = SmallVec::new();

    // Parse 1 or more SD-ELEMENTs (each starts with '[')
    while cursor.peek() == Some(b'[') {
        elements.push(parse_sd_element(cursor, mode)?);
    }

    if elements.is_empty() {
        return Err(ParseError::MalformedStructuredData {
            reason: "expected NILVALUE or at least one SD-ELEMENT".into(),
            span: Span { start: cursor.pos, end: cursor.pos },
        });
    }

    // Validate no duplicate SD-IDs (RFC 5424 S6.3.1 MUST).
    if mode == ParseMode::Strict {
        for i in 0..elements.len() {
            for j in (i + 1)..elements.len() {
                if elements[i].id == elements[j].id {
                    return Err(ParseError::DuplicateSdId {
                        id: elements[i].id.to_string(),
                    });
                }
            }
        }
    }

    Ok(elements)
}

/// Parse a single SD-ELEMENT: "[" SD-ID *(SP SD-PARAM) "]"
fn parse_sd_element<'a>(
    cursor: &mut Cursor<'a>,
    mode: ParseMode,
) -> Result<SdElement<'a>, ParseError> {
    cursor.expect_byte(b'[')?;

    // Parse SD-ID
    let id_start = cursor.pos;
    let id_bytes = cursor.take_while(is_sd_name_char);
    if id_bytes.is_empty() || id_bytes.len() > 32 {
        return Err(ParseError::MalformedStructuredData {
            reason: "SD-ID must be 1-32 valid SD-NAME characters".into(),
            span: Span { start: id_start, end: cursor.pos },
        });
    }
    let id_str = std::str::from_utf8(id_bytes).unwrap();
    let id = FieldStr::Borrowed(id_str);

    // Parse SD-PARAMs
    let mut params = SmallVec::new();
    while cursor.peek() == Some(b' ') {
        cursor.advance(1); // consume SP
        params.push(parse_sd_param(cursor, mode)?);
    }

    cursor.expect_byte(b']').map_err(|_| ParseError::MalformedStructuredData {
        reason: "expected ']' to close SD-ELEMENT".into(),
        span: Span { start: id_start - 1, end: cursor.pos },
    })?;

    Ok(SdElement { id, params })
}

/// Parse a single SD-PARAM: PARAM-NAME "=" DQUOTE PARAM-VALUE DQUOTE
fn parse_sd_param<'a>(
    cursor: &mut Cursor<'a>,
    mode: ParseMode,
) -> Result<SdParam<'a>, ParseError> {
    // PARAM-NAME
    let name_start = cursor.pos;
    let name_bytes = cursor.take_while(is_sd_name_char);
    if name_bytes.is_empty() || name_bytes.len() > 32 {
        return Err(ParseError::MalformedStructuredData {
            reason: "PARAM-NAME must be 1-32 valid SD-NAME characters".into(),
            span: Span { start: name_start, end: cursor.pos },
        });
    }
    let name = FieldStr::Borrowed(std::str::from_utf8(name_bytes).unwrap());

    cursor.expect_byte(b'=')?;
    cursor.expect_byte(b'"')?;

    // PARAM-VALUE with escape handling
    let value = parse_param_value(cursor, mode)?;

    cursor.expect_byte(b'"').map_err(|_| ParseError::MalformedStructuredData {
        reason: "expected closing '\"' for PARAM-VALUE".into(),
        span: Span { start: name_start, end: cursor.pos },
    })?;

    Ok(SdParam { name, value })
}

/// Parse PARAM-VALUE content between the double quotes.
///
/// Valid escape sequences: `\"`, `\\`, `\]`
/// Any other `\X` sequence is invalid per RFC 5424.
///
/// Optimization: scan first without copying. If no escapes are found,
/// return a zero-copy borrow. Only allocate if escapes are present.
fn parse_param_value<'a>(
    cursor: &mut Cursor<'a>,
    mode: ParseMode,
) -> Result<ParamValue<'a>, ParseError> {
    let start = cursor.pos;

    // Fast scan: check if any backslash exists in the value.
    let mut has_escape = false;
    let mut scan_pos = cursor.pos;
    loop {
        if scan_pos >= cursor.input.len() {
            return Err(ParseError::UnexpectedEndOfInput);
        }
        match cursor.input[scan_pos] {
            b'"' => break,       // End of value (unescaped quote)
            b'\\' => {
                has_escape = true;
                scan_pos += 2;   // Skip escape sequence
            }
            _ => scan_pos += 1,
        }
    }

    if !has_escape {
        // Zero-copy path: no escapes, take the slice directly.
        let value_bytes = &cursor.input[start..scan_pos];
        cursor.pos = scan_pos;
        // PARAM-VALUE is UTF-8 per RFC 5424 S6.3.3
        let s = std::str::from_utf8(value_bytes).map_err(|_| ParseError::Utf8Error {
            span: Span { start, end: scan_pos },
        })?;
        return Ok(ParamValue::Borrowed(s));
    }

    // Slow path: decode escape sequences into a new String.
    let mut decoded = String::with_capacity(scan_pos - start);
    cursor.pos = start;

    loop {
        if cursor.pos >= cursor.input.len() {
            return Err(ParseError::UnexpectedEndOfInput);
        }
        match cursor.input[cursor.pos] {
            b'"' => break,
            b'\\' => {
                cursor.advance(1);
                match cursor.peek() {
                    Some(b'"') => { decoded.push('"'); cursor.advance(1); }
                    Some(b'\\') => { decoded.push('\\'); cursor.advance(1); }
                    Some(b']') => { decoded.push(']'); cursor.advance(1); }
                    Some(other) => {
                        if mode == ParseMode::Strict {
                            return Err(ParseError::InvalidSdEscape {
                                byte: other,
                                position: cursor.pos,
                            });
                        }
                        // Lenient: preserve the backslash and following byte literally.
                        decoded.push('\\');
                        decoded.push(other as char);
                        cursor.advance(1);
                    }
                    None => return Err(ParseError::UnexpectedEndOfInput),
                }
            }
            b => {
                // Multi-byte UTF-8 handling
                let remaining = &cursor.input[cursor.pos..];
                match std::str::from_utf8(remaining) {
                    Ok(_) => {
                        // Find next special character
                        let chunk_end = remaining.iter()
                            .position(|&x| x == b'"' || x == b'\\')
                            .unwrap_or(remaining.len());
                        let chunk = std::str::from_utf8(&remaining[..chunk_end]).unwrap();
                        decoded.push_str(chunk);
                        cursor.advance(chunk_end);
                    }
                    Err(e) => {
                        // Partial valid prefix
                        let valid_up_to = e.valid_up_to();
                        if valid_up_to > 0 {
                            let chunk = std::str::from_utf8(&remaining[..valid_up_to]).unwrap();
                            decoded.push_str(chunk);
                            cursor.advance(valid_up_to);
                        } else {
                            return Err(ParseError::Utf8Error {
                                span: Span { start: cursor.pos, end: cursor.pos + 1 },
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(ParamValue::Owned(decoded))
}
```

### 3.7 MSG Parsing

```rust
/// The UTF-8 BOM: EF BB BF
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Parse the optional MSG field.
///
/// Called after STRUCTURED-DATA. If there is a space followed by
/// more data, that is the MSG. If input ends after STRUCTURED-DATA,
/// MSG is absent.
fn parse_msg<'a>(cursor: &mut Cursor<'a>) -> Result<Option<MessageBody<'a>>, ParseError> {
    // Check for SP delimiter before MSG
    if cursor.peek() != Some(b' ') {
        return Ok(None);  // No MSG present
    }
    cursor.advance(1); // consume SP

    if cursor.pos >= cursor.input.len() {
        return Ok(None); // SP was trailing; no actual MSG content
    }

    let msg_bytes = &cursor.input[cursor.pos..];

    // BOM detection
    if msg_bytes.len() >= 3 && msg_bytes[..3] == UTF8_BOM {
        let content = &msg_bytes[3..];
        // If BOM present, content MUST be valid UTF-8 (RFC 5424 S6.4)
        match std::str::from_utf8(content) {
            Ok(s) => Ok(Some(MessageBody::Utf8 { content: s, had_bom: true })),
            Err(_) => Err(ParseError::Utf8Error {
                span: Span { start: cursor.pos + 3, end: cursor.input.len() },
            }),
        }
    } else {
        // No BOM: try UTF-8, fall back to raw bytes
        match std::str::from_utf8(msg_bytes) {
            Ok(s) => Ok(Some(MessageBody::Utf8 { content: s, had_bom: false })),
            Err(_) => Ok(Some(MessageBody::Bytes(msg_bytes))),
        }
    }
}
```

### 3.8 Top-Level RFC 5424 Parse Function

```rust
/// Parse a complete RFC 5424 message.
///
/// Precondition: PRI has already been parsed and format detected as 5424.
fn parse_rfc5424<'a>(
    cursor: &mut Cursor<'a>,
    pri: u8,
    opts: &ParseOptions,
) -> Result<SyslogMessage<'a>, ParseError> {
    let (facility, severity) = decompose_pri(pri);

    let version = parse_version(cursor, opts.mode)?;
    let timestamp = parse_timestamp(cursor)?;
    cursor.expect_byte(b' ')?;
    let hostname = parse_header_field(cursor, "hostname", HOSTNAME_MAX_LEN, opts.mode)?;
    cursor.expect_byte(b' ')?;
    let app_name = parse_header_field(cursor, "app_name", APP_NAME_MAX_LEN, opts.mode)?;
    cursor.expect_byte(b' ')?;
    let proc_id = parse_header_field(cursor, "proc_id", PROC_ID_MAX_LEN, opts.mode)?;
    cursor.expect_byte(b' ')?;
    let msg_id = parse_header_field(cursor, "msg_id", MSG_ID_MAX_LEN, opts.mode)?;
    cursor.expect_byte(b' ')?;
    let structured_data = parse_structured_data(cursor, opts.mode)?;
    let msg = parse_msg(cursor)?;

    Ok(SyslogMessage {
        pri,
        facility,
        severity,
        version: Some(version),
        timestamp,
        hostname,
        app_name,
        proc_id,
        msg_id,
        structured_data,
        msg,
        raw: None,    // populated by caller if preserve_raw is set
        metadata: MessageMetadata::default(),
        source_format: MessageFormat::Rfc5424,
        warnings: SmallVec::new(),
    })
}
```

---

## 4. RFC 3164 Legacy Parser

### 4.1 Overview

RFC 3164 (BSD syslog) is a de-facto standard with significant variation in real-world implementations. The parser is best-effort: it extracts what it can and maps the result into the RFC 5424 `SyslogMessage` internal representation.

Key differences from RFC 5424:
- No VERSION field.
- Timestamp is `Mmm dd HH:MM:SS` (no year, no timezone, no fractional seconds).
- No structured data.
- No explicit field delimiters — hostname and tag are heuristically extracted.

### 4.2 Timestamp Parsing

```rust
/// BSD syslog months for lookup.
static BSD_MONTHS: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun",
    b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Pre-computed perfect hash lookup table for 3-letter month abbreviations.
/// Index: (first_byte ^ third_byte) & 0x1F
/// This avoids 12-way comparison for the common case.
///
/// Populated at compile time; entries map hash -> (month_index, expected_bytes).
static MONTH_HASH_TABLE: [(u8, [u8; 3]); 32] = build_month_hash_table();

/// Parse the BSD syslog timestamp: "Mmm dd HH:MM:SS" or "Mmm  d HH:MM:SS"
///
/// The timestamp has no year component. We supply the current year from the
/// receive timestamp, with December/January rollover correction.
///
/// Returns `None` if the timestamp cannot be parsed.
fn parse_bsd_timestamp(
    cursor: &mut Cursor,
    receive_time: time::OffsetDateTime,
) -> Option<SyslogTimestamp> {
    // Month: exactly 3 ASCII letters
    if cursor.pos + 3 > cursor.input.len() { return None; }
    let month_bytes = &cursor.input[cursor.pos..cursor.pos + 3];

    let month_index = match lookup_month(month_bytes) {
        Some(idx) => idx,
        None => return None,
    };
    cursor.advance(3);

    // Space
    if cursor.peek() != Some(b' ') { return None; }
    cursor.advance(1);

    // Day: " d" or "dd" (space-padded single digit or two digits)
    let day = if cursor.peek() == Some(b' ') {
        cursor.advance(1);
        let d = cursor.peek()?;
        if !d.is_ascii_digit() { return None; }
        cursor.advance(1);
        (d - b'0') as u8
    } else {
        let d1 = cursor.peek()?;
        if !d1.is_ascii_digit() { return None; }
        cursor.advance(1);
        let d2 = cursor.peek()?;
        if !d2.is_ascii_digit() { return None; }
        cursor.advance(1);
        (d1 - b'0') * 10 + (d2 - b'0')
    };

    // Space
    if cursor.peek() != Some(b' ') { return None; }
    cursor.advance(1);

    // HH:MM:SS
    let hour = parse_2digit(cursor)?;
    if cursor.peek() != Some(b':') { return None; }
    cursor.advance(1);
    let minute = parse_2digit(cursor)?;
    if cursor.peek() != Some(b':') { return None; }
    cursor.advance(1);
    let second = parse_2digit(cursor)?;

    // Year inference: use receive_time's year, adjusting for Dec->Jan rollover.
    let mut year = receive_time.year();
    if month_index == 0 && receive_time.month() == time::Month::December {
        year += 1;  // Message from January received in December
    } else if month_index == 11 && receive_time.month() == time::Month::January {
        year -= 1;  // Message from December received in January
    }

    let date = time::Date::from_calendar_date(
        year,
        time::Month::try_from(month_index as u8 + 1).ok()?,
        day,
    ).ok()?;
    let time = time::Time::from_hms(hour, minute, second).ok()?;

    Some(SyslogTimestamp {
        datetime: time::OffsetDateTime::new_in_offset(date, time, time::UtcOffset::UTC),
        secfrac_digits: 0,
    })
}

fn lookup_month(bytes: &[u8]) -> Option<usize> {
    // Fast path: hash lookup
    let hash = ((bytes[0] ^ bytes[2]) as usize) & 0x1F;
    let (idx, expected) = MONTH_HASH_TABLE[hash];
    if idx != 0xFF && expected == *bytes {
        return Some(idx as usize);
    }
    // Fallback: linear scan (handles unexpected hash collisions)
    BSD_MONTHS.iter().position(|m| *m == bytes)
}
```

### 4.3 Hostname Heuristic

After the timestamp, BSD syslog optionally includes a hostname followed by a space before the tag/message. The heuristic:

1. Take the next whitespace-delimited token.
2. If it contains a colon (`:`) or bracket (`[`), it is likely a tag, not a hostname. In this case, there is no hostname in the message.
3. Otherwise, treat it as the hostname.

```rust
/// Attempt to extract hostname and tag from the post-timestamp portion
/// of a BSD syslog message.
///
/// Format variations:
///   "hostname tag[pid]: message"
///   "hostname tag: message"
///   "tag[pid]: message"       (no hostname)
///   "tag: message"            (no hostname)
///   "free-form message"       (no hostname, no tag)
fn parse_bsd_host_and_tag<'a>(
    cursor: &mut Cursor<'a>,
) -> (Option<&'a str>, Option<&'a str>, Option<&'a str>) {
    // hostname, app_name (tag), proc_id
    let token_start = cursor.pos;
    let first_token = cursor.take_while(|b| b != b' ');

    if first_token.is_empty() {
        return (None, None, None);
    }

    let first_str = std::str::from_utf8(first_token).unwrap_or("-");

    // If first token contains ':' or '[', it is a tag, not hostname.
    if first_str.contains(':') || first_str.contains('[') {
        let (tag, pid) = extract_tag_pid(first_str);
        return (None, tag, pid);
    }

    // Otherwise, first token is hostname. Next token is tag.
    if cursor.peek() == Some(b' ') {
        cursor.advance(1);
        let tag_token = cursor.take_while(|b| b != b' ');
        let tag_str = std::str::from_utf8(tag_token).unwrap_or("-");
        let (tag, pid) = extract_tag_pid(tag_str);
        return (Some(first_str), tag, pid);
    }

    (Some(first_str), None, None)
}

/// Extract tag name and optional PID from a tag token.
///
/// Examples:
///   "sshd[1234]:"  -> (Some("sshd"), Some("1234"))
///   "sshd:"        -> (Some("sshd"), None)
///   "sshd[1234]"   -> (Some("sshd"), Some("1234"))
///   "sshd"         -> (Some("sshd"), None)
fn extract_tag_pid(token: &str) -> (Option<&str>, Option<&str>) {
    let token = token.trim_end_matches(':');
    if let Some(bracket_start) = token.find('[') {
        let tag = &token[..bracket_start];
        let pid = token[bracket_start + 1..].trim_end_matches(']');
        (
            if tag.is_empty() { None } else { Some(tag) },
            if pid.is_empty() { None } else { Some(pid) },
        )
    } else {
        (if token.is_empty() { None } else { Some(token) }, None)
    }
}
```

### 4.4 Top-Level RFC 3164 Parser

```rust
/// Parse a BSD syslog (RFC 3164) message into SyslogMessage.
///
/// This is a best-effort parser. It never returns an error — if parsing
/// fails at any stage, the remaining unparsed bytes become the MSG body
/// and the corresponding fields are set to None.
fn parse_rfc3164<'a>(
    cursor: &mut Cursor<'a>,
    pri: u8,
    opts: &ParseOptions,
    receive_time: time::OffsetDateTime,
) -> SyslogMessage<'a> {
    let (facility, severity) = decompose_pri(pri);

    // Attempt timestamp parse
    let checkpoint = cursor.pos;
    let timestamp = parse_bsd_timestamp(cursor, receive_time);
    if timestamp.is_none() {
        cursor.pos = checkpoint; // Rewind; treat everything as message
    } else if cursor.peek() == Some(b' ') {
        cursor.advance(1);
    }

    // Attempt hostname/tag extraction
    let (hostname, app_name, proc_id) = if timestamp.is_some() {
        parse_bsd_host_and_tag(cursor)
    } else {
        (None, None, None)
    };

    // Skip colon+space after tag if present
    if cursor.peek() == Some(b':') { cursor.advance(1); }
    if cursor.peek() == Some(b' ') { cursor.advance(1); }

    // Everything remaining is the message body
    let msg = if cursor.pos < cursor.input.len() {
        let body = &cursor.input[cursor.pos..];
        match std::str::from_utf8(body) {
            Ok(s) => Some(MessageBody::Utf8 { content: s, had_bom: false }),
            Err(_) => Some(MessageBody::Bytes(body)),
        }
    } else {
        None
    };

    SyslogMessage {
        pri,
        facility,
        severity,
        version: None,
        timestamp,
        hostname: hostname.map(|s| FieldStr::Borrowed(s)),
        app_name: app_name.map(|s| FieldStr::Borrowed(s)),
        proc_id: proc_id.map(|s| FieldStr::Borrowed(s)),
        msg_id: None,
        structured_data: SmallVec::new(),
        msg,
        raw: None,
        metadata: MessageMetadata::default(),
        source_format: MessageFormat::Rfc3164,
        warnings: SmallVec::new(),
    }
}
```

---

## 5. Validation Rules

### 5.1 Validation Matrix

Validation is applied during parsing in strict mode and as post-parse annotation in lenient mode. The following table enumerates all validation rules, their RFC source, and when they are enforced.

| Rule | RFC Reference | Strict Mode | Lenient Mode |
|------|--------------|-------------|--------------|
| PRI present (`<` ... `>`) | RFC 5424 S6.1 | Reject | Reject (cannot parse without PRI) |
| PRI value 0-191 | RFC 5424 S6.1 | Reject | Reject |
| PRI no leading zeros (except `<0>`) | RFC 5424 S6.1 | Reject | Warn, accept |
| VERSION is `1` | RFC 5424 S6.2.1 | Reject if not 1 | Warn, accept other values |
| TIMESTAMP uppercase `T` separator | RFC 5424 S6.2.3 | Reject | Warn, accept lowercase |
| TIMESTAMP uppercase `Z` for UTC | RFC 5424 S6.2.3 | Reject | Warn, accept lowercase |
| TIMESTAMP no leap second (`:60`) | RFC 5424 S6.2.3 | Reject | Warn, clamp to `:59` |
| TIMESTAMP fractional seconds 1-6 digits | RFC 5424 S6.2.3 | Reject if >6 | Warn, truncate to 6 |
| TIMESTAMP valid calendar date | RFC 5424 S6.2.3 | Reject | Warn, set to None |
| HOSTNAME <= 255 chars | RFC 5424 S6.2.1 | Reject | Warn, accept |
| APP-NAME <= 48 chars | RFC 5424 S6.2.5 | Reject | Warn, accept |
| PROCID <= 128 chars | RFC 5424 S6.2.6 | Reject | Warn, accept |
| MSGID <= 32 chars | RFC 5424 S6.2.7 | Reject | Warn, accept |
| Header fields PRINTUSASCII only | RFC 5424 S6 | Reject | Warn, accept |
| SD-NAME <= 32 chars | RFC 5424 S6.3.2 | Reject | Warn, accept |
| SD-NAME no `=`, SP, `]`, `"` | RFC 5424 S6.3.2 | Reject | Warn, accept |
| SD-ID unique within message | RFC 5424 S6.3.1 | Reject | Warn, accept |
| SD-PARAM escape sequences valid | RFC 5424 S6.3.3 | Reject | Warn, preserve literally |
| PARAM-VALUE UTF-8 | RFC 5424 S6.3.3 | Reject | Warn, accept as bytes |
| MSG with BOM must be valid UTF-8 | RFC 5424 S6.4 | Reject | Warn, treat as bytes |
| Total message size <= configured max | RFC 5424 S8.1 | Reject | Reject (pre-parse check) |

### 5.2 SD-ID Format Validation

SD-IDs come in two forms:

- **IANA-registered names**: simple names without `@` (e.g., `timeQuality`, `origin`, `meta`). These are reserved; custom SD-IDs without `@` are invalid.
- **Private enterprise names**: `name@PEN` format where PEN is a Private Enterprise Number (e.g., `mySD@32473`).

```rust
/// Registered IANA SD-IDs that do not require an enterprise number.
const IANA_SD_IDS: &[&str] = &["timeQuality", "origin", "meta"];

/// Validate SD-ID format.
///
/// Returns Ok(SdIdKind) indicating whether this is an IANA-registered
/// or private-enterprise SD-ID.
fn validate_sd_id(id: &str, mode: ParseMode) -> Result<SdIdKind, ParseError> {
    if let Some(at_pos) = id.find('@') {
        // Private: name@PEN
        let name = &id[..at_pos];
        let pen = &id[at_pos + 1..];
        if name.is_empty() || pen.is_empty() {
            return Err(ParseError::MalformedStructuredData {
                reason: format!("invalid private SD-ID format: '{}'", id),
                span: Span::EMPTY,
            });
        }
        // PEN should be numeric
        if !pen.bytes().all(|b| b.is_ascii_digit()) && mode == ParseMode::Strict {
            return Err(ParseError::MalformedStructuredData {
                reason: format!("SD-ID enterprise number is not numeric: '{}'", pen),
                span: Span::EMPTY,
            });
        }
        Ok(SdIdKind::Private)
    } else if IANA_SD_IDS.contains(&id) {
        Ok(SdIdKind::Registered)
    } else if mode == ParseMode::Strict {
        Err(ParseError::MalformedStructuredData {
            reason: format!("unregistered SD-ID '{}' without enterprise number", id),
            span: Span::EMPTY,
        })
    } else {
        Ok(SdIdKind::Unknown)
    }
}

enum SdIdKind { Registered, Private, Unknown }
```

### 5.3 Message Size Enforcement

Message size is checked before parsing begins, not during:

```rust
/// Pre-parse size check. Applied in both strict and lenient modes.
fn check_message_size(input: &[u8], max_size: usize) -> Result<(), ParseError> {
    if input.is_empty() {
        return Err(ParseError::EmptyInput);
    }
    if input.len() > max_size {
        return Err(ParseError::MessageTooLarge {
            max: max_size,
            actual: input.len(),
        });
    }
    Ok(())
}
```

The default maximum is 8192 bytes. Per RFC 5424 Section 8.1:
- Receivers MUST accept messages up to 480 octets.
- Receivers SHOULD accept messages up to 2048 octets.
- Receivers MAY accept larger messages.

The configurable maximum allows operators to tune based on their environment.

---

## 6. Error Taxonomy

### 6.1 ParseError Enum

```rust
/// Byte-range span within the input buffer, used for error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Start byte offset (inclusive).
    pub start: usize,
    /// End byte offset (exclusive).
    pub end: usize,
}

impl Span {
    pub const EMPTY: Span = Span { start: 0, end: 0 };
}

/// Detailed classification of timestamp parsing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampError {
    /// "T" or "Z" was lowercase.
    LowercaseSeparator,
    LowercaseUtc,
    /// Seconds field was 60 (leap second).
    LeapSecond,
    /// Fractional seconds had 0 or >6 digits.
    InvalidFractionalSeconds,
    /// Timezone offset values out of range.
    InvalidOffset,
    /// No timezone offset present.
    MissingOffset,
    /// Month value outside 1-12.
    InvalidMonth,
    /// Calendar date invalid (e.g., Feb 30).
    InvalidDate,
    /// Time component invalid (e.g., hour 25).
    InvalidTime,
    /// Expected a digit character but found something else.
    ExpectedDigit,
}

/// Errors encountered during syslog message parsing.
///
/// Each variant carries enough context for diagnostic reporting:
/// byte offsets, field names, and expected-vs-actual values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    // === Input-Level ===

    /// The input buffer was empty.
    EmptyInput,

    /// The message exceeds the configured maximum size.
    MessageTooLarge {
        max: usize,
        actual: usize,
    },

    /// Input ended before a complete field could be parsed.
    UnexpectedEndOfInput,

    // === PRI ===

    /// No opening '<' found at the start of input.
    MissingPri,

    /// PRI field is syntactically invalid (wrong structure, non-digit
    /// characters, leading zeros, or missing '>').
    InvalidPri {
        span: Span,
    },

    /// PRI value parsed successfully but exceeds the valid range 0-191.
    PriOutOfRange {
        value: u16,
    },

    // === VERSION ===

    /// VERSION field is syntactically invalid.
    InvalidVersion {
        span: Span,
    },

    /// VERSION value is syntactically valid but not a supported version.
    /// Currently only version 1 is defined by RFC 5424.
    UnsupportedVersion {
        version: u8,
    },

    // === TIMESTAMP ===

    /// TIMESTAMP field could not be parsed.
    InvalidTimestamp {
        reason: TimestampError,
        span: Span,
    },

    // === HEADER FIELDS ===

    /// A header field exceeds its maximum permitted length.
    FieldTooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },

    /// A header field contains a byte outside PRINTUSASCII (%d33-126).
    InvalidCharacter {
        field: &'static str,
        position: usize,
        byte: u8,
    },

    // === STRUCTURED DATA ===

    /// STRUCTURED-DATA is syntactically malformed.
    MalformedStructuredData {
        reason: String,
        span: Span,
    },

    /// Duplicate SD-ID found in the same message (RFC 5424 S6.3.1 MUST NOT).
    DuplicateSdId {
        id: String,
    },

    /// Invalid escape sequence in SD-PARAM value. Only `\"`, `\\`, `\]`
    /// are valid per RFC 5424 S6.3.3.
    InvalidSdEscape {
        byte: u8,
        position: usize,
    },

    // === MSG / ENCODING ===

    /// MSG declared as UTF-8 (via BOM) but contains invalid UTF-8 sequences.
    Utf8Error {
        span: Span,
    },

    // === GENERIC ===

    /// Expected a specific byte at the given position but found another.
    ExpectedByte {
        expected: u8,
        found: Option<u8>,
        position: usize,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "empty input"),
            Self::MessageTooLarge { max, actual } =>
                write!(f, "message too large: {} bytes (max {})", actual, max),
            Self::UnexpectedEndOfInput =>
                write!(f, "unexpected end of input"),
            Self::MissingPri =>
                write!(f, "missing PRI field (expected '<' at start of message)"),
            Self::InvalidPri { span } =>
                write!(f, "invalid PRI at bytes {}..{}", span.start, span.end),
            Self::PriOutOfRange { value } =>
                write!(f, "PRI value {} out of range (max 191)", value),
            Self::InvalidVersion { span } =>
                write!(f, "invalid VERSION at bytes {}..{}", span.start, span.end),
            Self::UnsupportedVersion { version } =>
                write!(f, "unsupported syslog version {}", version),
            Self::InvalidTimestamp { reason, span } =>
                write!(f, "invalid timestamp ({:?}) at bytes {}..{}", reason, span.start, span.end),
            Self::FieldTooLong { field, max, actual } =>
                write!(f, "field '{}' too long: {} bytes (max {})", field, actual, max),
            Self::InvalidCharacter { field, position, byte } =>
                write!(f, "invalid character 0x{:02X} in '{}' at byte {}", byte, field, position),
            Self::MalformedStructuredData { reason, .. } =>
                write!(f, "malformed structured data: {}", reason),
            Self::DuplicateSdId { id } =>
                write!(f, "duplicate SD-ID '{}' in message", id),
            Self::InvalidSdEscape { byte, position } =>
                write!(f, "invalid escape sequence '\\{}' at byte {}", *byte as char, position),
            Self::Utf8Error { span } =>
                write!(f, "invalid UTF-8 at bytes {}..{}", span.start, span.end),
            Self::ExpectedByte { expected, found, position } =>
                write!(f, "expected '{}' at byte {}, found {:?}",
                    *expected as char, position, found.map(|b| b as char)),
        }
    }
}

impl std::error::Error for ParseError {}
```

### 6.2 ParseWarning

Used in lenient mode to annotate deviations without rejecting the message:

```rust
/// A non-fatal parse deviation encountered in lenient mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseWarning {
    /// The underlying issue that would have been an error in strict mode.
    pub kind: ParseError,
    /// How the parser handled it.
    pub resolution: WarningResolution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarningResolution {
    /// The field was accepted as-is despite the violation.
    AcceptedAsIs,
    /// The field was set to None/default.
    FieldCleared,
    /// The value was adjusted (e.g., timestamp second clamped from 60 to 59).
    ValueAdjusted,
    /// Raw bytes preserved instead of structured parse.
    PreservedAsRaw,
}
```

---

## 7. Serializer

### 7.1 RFC 5424 Serialization

The serializer converts a `SyslogMessage` back to wire format for relay forwarding. It writes directly to a `BufWriter` or `Vec<u8>` to minimize allocations.

```rust
/// Serialize a SyslogMessage to RFC 5424 wire format.
///
/// If `raw` bytes are present and passthrough is desired, this function
/// returns them directly without re-serialization — the fastest path
/// for relay mode.
pub fn serialize_rfc5424(msg: &SyslogMessage, buf: &mut Vec<u8>) {
    // Fast path: relay passthrough
    if let Some(ref raw) = msg.raw {
        buf.extend_from_slice(raw);
        return;
    }

    // PRI
    buf.push(b'<');
    write_u8_decimal(buf, msg.pri);
    buf.push(b'>');

    // VERSION
    buf.push(b'1');
    buf.push(b' ');

    // TIMESTAMP
    match &msg.timestamp {
        Some(ts) => serialize_timestamp(ts, buf),
        None => buf.push(b'-'),
    }
    buf.push(b' ');

    // HOSTNAME, APP-NAME, PROCID, MSGID
    serialize_field(buf, &msg.hostname);
    buf.push(b' ');
    serialize_field(buf, &msg.app_name);
    buf.push(b' ');
    serialize_field(buf, &msg.proc_id);
    buf.push(b' ');
    serialize_field(buf, &msg.msg_id);
    buf.push(b' ');

    // STRUCTURED-DATA
    if msg.structured_data.is_empty() {
        buf.push(b'-');
    } else {
        for elem in &msg.structured_data {
            serialize_sd_element(elem, buf);
        }
    }

    // MSG
    if let Some(ref body) = msg.msg {
        buf.push(b' ');
        match body {
            MessageBody::Utf8 { content, had_bom } => {
                if *had_bom {
                    buf.extend_from_slice(&UTF8_BOM);
                }
                buf.extend_from_slice(content.as_bytes());
            }
            MessageBody::Bytes(data) => {
                buf.extend_from_slice(data);
            }
        }
    }
}

/// Write a u8 value as decimal ASCII digits without allocation.
fn write_u8_decimal(buf: &mut Vec<u8>, val: u8) {
    if val >= 100 {
        buf.push(b'0' + val / 100);
        buf.push(b'0' + (val / 10) % 10);
        buf.push(b'0' + val % 10);
    } else if val >= 10 {
        buf.push(b'0' + val / 10);
        buf.push(b'0' + val % 10);
    } else {
        buf.push(b'0' + val);
    }
}

/// Serialize a timestamp preserving original fractional-second precision.
fn serialize_timestamp(ts: &SyslogTimestamp, buf: &mut Vec<u8>) {
    let dt = ts.datetime;
    // YYYY-MM-DDThh:mm:ss
    write!(buf, "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        dt.year(), dt.month() as u8, dt.day(),
        dt.hour(), dt.minute(), dt.second()
    ).unwrap();

    // Fractional seconds at original precision
    if ts.secfrac_digits > 0 {
        buf.push(b'.');
        let nanos = dt.nanosecond();
        let divisor = 10u32.pow(9 - ts.secfrac_digits as u32);
        let frac_val = nanos / divisor;
        write!(buf, "{:0>width$}", frac_val, width = ts.secfrac_digits as usize).unwrap();
    }

    // Timezone offset
    let offset = dt.offset();
    if offset.is_utc() {
        buf.push(b'Z');
    } else {
        let total_seconds = offset.whole_seconds();
        let sign = if total_seconds >= 0 { b'+' } else { b'-' };
        let abs = total_seconds.unsigned_abs();
        let hours = abs / 3600;
        let minutes = (abs % 3600) / 60;
        buf.push(sign);
        write!(buf, "{:02}:{:02}", hours, minutes).unwrap();
    }
}

/// Serialize an optional field, writing "-" for None.
fn serialize_field(buf: &mut Vec<u8>, field: &Option<FieldStr>) {
    match field {
        Some(s) => buf.extend_from_slice(s.as_bytes()),
        None => buf.push(b'-'),
    }
}

/// Serialize an SD-ELEMENT with proper escaping of PARAM-VALUEs.
fn serialize_sd_element(elem: &SdElement, buf: &mut Vec<u8>) {
    buf.push(b'[');
    buf.extend_from_slice(elem.id.as_bytes());
    for param in &elem.params {
        buf.push(b' ');
        buf.extend_from_slice(param.name.as_bytes());
        buf.push(b'=');
        buf.push(b'"');
        // Escape '"', '\', ']' in PARAM-VALUE
        for &b in param.value.as_bytes() {
            match b {
                b'"' => { buf.push(b'\\'); buf.push(b'"'); }
                b'\\' => { buf.push(b'\\'); buf.push(b'\\'); }
                b']' => { buf.push(b'\\'); buf.push(b']'); }
                _ => buf.push(b),
            }
        }
        buf.push(b'"');
    }
    buf.push(b']');
}
```

### 7.2 Octet-Counting Frame Wrapper

For TCP/TLS transport (RFC 5425), messages are framed with a byte-length prefix:

```rust
/// Wrap a serialized message with octet-counting framing.
/// Format: MSG-LEN SP SYSLOG-MSG
///
/// This writes the frame header, then calls the serializer to
/// write the message body. Uses a two-pass approach: serialize
/// to a temporary buffer to determine length, then write length
/// prefix and buffer.
///
/// For relay passthrough with known raw bytes, the length is
/// already known and the temporary buffer is avoided.
pub fn write_octet_counted_frame(
    msg: &SyslogMessage,
    writer: &mut impl std::io::Write,
) -> std::io::Result<()> {
    // Serialize to buffer
    let mut payload = Vec::with_capacity(512);
    serialize_rfc5424(msg, &mut payload);

    // Write frame: "<length> <payload>"
    write!(writer, "{} ", payload.len())?;
    writer.write_all(&payload)?;

    Ok(())
}
```

### 7.3 JSON Serialization

For structured output to downstream analytics pipelines:

```rust
/// Serialize a SyslogMessage as a JSON object.
///
/// Uses `serde_json` for correctness, but writes to a pre-allocated
/// buffer to minimize allocations. Field names match the RFC 5424
/// nomenclature for interoperability.
///
/// Output schema:
/// {
///   "pri": 134,
///   "facility": "local0",
///   "severity": "info",
///   "version": 1,
///   "timestamp": "2024-01-15T12:30:45.123456Z",
///   "hostname": "myhost.example.com",
///   "app_name": "myapp",
///   "proc_id": "1234",
///   "msg_id": "ID47",
///   "structured_data": {
///     "timeQuality": {"tzKnown": "1", "isSynced": "1"},
///     "mySD@32473": {"key": "value"}
///   },
///   "msg": "Application started successfully",
///   "metadata": {
///     "receive_time": "2024-01-15T12:30:45.200000Z",
///     "source_addr": "192.168.1.100:514",
///     "listener_id": "udp-main",
///     "transport": "udp"
///   }
/// }
impl serde::Serialize for SyslogMessage<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // ... implementation using serde derive or manual Serialize
    }
}
```

The `Serialize` implementation is derived via `#[derive(serde::Serialize)]` on all types with `#[serde(rename_all = "snake_case")]` for enum variants. The `FieldStr` type serializes as a plain string regardless of variant. Structured data is serialized as a map-of-maps for natural JSON access patterns.

---

## 8. Extension Handling

### 8.1 Design Principles

Extensions to the syslog format are carried entirely within STRUCTURED-DATA elements. The parser's approach to extensions follows three principles:

1. **Preserve everything**: All SD-ELEMENTs are parsed and stored, regardless of whether the SD-ID is known. Unknown SD-IDs are passed through transparently.
2. **Type-aware access for known extensions**: Known SD-IDs (IANA-registered and supported extensions) get typed accessor methods on `SyslogMessage`.
3. **Pluggable processing**: An `SdProcessor` trait allows downstream code to register handlers for specific SD-IDs without modifying the parser.

### 8.2 RFC 5848 — Signed Syslog Messages

RFC 5848 uses two SD-IDs:
- `ssign`: Contains signature block parameters (VER, RSID, SG, SPRI, GBC, FMN, CNT, HB, SIGN).
- `ssign-cert`: Contains certificate block parameters (VER, RSID, SG, SPRI, TBPL, INDEX, FLEN, FRAG, SIGN).

These are parsed as normal SD-ELEMENTs by the base parser. A dedicated verifier module provides typed access:

```rust
/// Typed accessor for RFC 5848 signature structured data.
pub struct SignatureBlock<'a> {
    pub version: &'a str,           // VER: "0111"
    pub reboot_session_id: u64,     // RSID
    pub signature_group: u8,        // SG: 0-3
    pub signature_priority: u8,     // SPRI: 0-191
    pub global_block_counter: u64,  // GBC
    pub first_message_number: u64,  // FMN
    pub count: u64,                 // CNT
    pub hash_block: &'a str,        // HB: space-separated hashes
    pub signature: &'a str,         // SIGN: base64-encoded signature
}

impl<'a> SyslogMessage<'a> {
    /// Extract the RFC 5848 signature block, if present.
    pub fn signature_block(&self) -> Option<Result<SignatureBlock<'a>, ParseError>> {
        self.find_sd_element("ssign").map(|elem| {
            // Extract and validate typed fields from elem.params
            SignatureBlock::from_sd_element(elem)
        })
    }

    /// Helper: find an SD-ELEMENT by ID.
    pub fn find_sd_element(&self, id: &str) -> Option<&SdElement<'a>> {
        self.structured_data.iter().find(|e| e.id.as_str() == id)
    }
}
```

### 8.3 RFC 5674 — Alarms in Syslog

RFC 5674 defines the `alarm` SD-ID with parameters:
- `resource` (required): Identifies the alarmed resource.
- `probableCause` (required): ITU probable cause enumeration.
- `perceivedSeverity` (required): `cleared`, `indeterminate`, `critical`, `major`, `minor`, `warning`.
- `eventType` (optional): ITU event type.
- `trendIndication` (optional): `moreSevere`, `noChange`, `lessSevere`.

```rust
/// Typed accessor for RFC 5674 alarm structured data.
pub struct AlarmData<'a> {
    pub resource: &'a str,
    pub probable_cause: u32,
    pub perceived_severity: AlarmSeverity,
    pub event_type: Option<&'a str>,
    pub trend_indication: Option<TrendIndication>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmSeverity {
    Cleared,
    Indeterminate,
    Critical,
    Major,
    Minor,
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrendIndication {
    MoreSevere,
    NoChange,
    LessSevere,
}

impl<'a> SyslogMessage<'a> {
    /// Extract the RFC 5674 alarm data, if present.
    pub fn alarm_data(&self) -> Option<Result<AlarmData<'a>, ParseError>> {
        self.find_sd_element("alarm").map(|elem| {
            AlarmData::from_sd_element(elem)
        })
    }
}
```

### 8.4 SdProcessor Trait

For custom and future extensions, a trait-based processing hook allows downstream consumers to register SD-ID-specific logic without modifying the parser:

```rust
/// Trait for processing specific structured data elements.
///
/// Implementations are registered on the pipeline and invoked for
/// each parsed message that contains matching SD-IDs.
pub trait SdProcessor: Send + Sync + 'static {
    /// The SD-IDs this processor handles. The pipeline invokes
    /// `process` only for messages containing at least one of these IDs.
    fn sd_ids(&self) -> &[&str];

    /// Process the structured data elements from a message.
    ///
    /// This is called during the pipeline's processing stage, after
    /// parsing is complete. The processor may:
    /// - Validate extension-specific constraints
    /// - Extract typed data for downstream use
    /// - Annotate the message with additional metadata
    ///
    /// Returning an error causes the message to be dropped (with metrics).
    fn process(&self, msg: &mut OwnedSyslogMessage) -> Result<(), Box<dyn std::error::Error>>;
}

/// Registry of SD processors, keyed by SD-ID.
pub struct SdProcessorRegistry {
    processors: HashMap<String, Vec<Arc<dyn SdProcessor>>>,
}

impl SdProcessorRegistry {
    pub fn register(&mut self, processor: Arc<dyn SdProcessor>) {
        for id in processor.sd_ids() {
            self.processors
                .entry(id.to_string())
                .or_default()
                .push(Arc::clone(&processor));
        }
    }

    /// Run all matching processors for a message.
    pub fn process(&self, msg: &mut OwnedSyslogMessage) -> Result<(), Box<dyn std::error::Error>> {
        for elem in &msg.structured_data {
            if let Some(processors) = self.processors.get(elem.id.as_str()) {
                for proc in processors {
                    proc.process(msg)?;
                }
            }
        }
        Ok(())
    }
}
```

### 8.5 Passthrough Guarantee

Unknown SD-IDs are always preserved in the `structured_data` vector without modification. This guarantees that relay nodes do not strip extension data they do not understand, as required by RFC 5424 Section 7.1.2.

---

## 9. Parser Performance Considerations

### 9.1 Performance Targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| p50 parse latency | < 2 us | Simple message, no structured data |
| p99 parse latency | < 10 us | Complex message with 3+ SD-ELEMENTs |
| p99.9 parse latency | < 50 us | Pathological input (max-size SD) |
| Allocation count (simple msg) | 0 | Zero-copy borrowed fields |
| Allocation count (complex msg) | 1-3 | SD param escape decoding only |
| Throughput | > 500k msg/sec single core | Amortized across parse + validation |

### 9.2 Zero-Copy Strategy

The primary performance lever is avoiding allocations and copies for the common case:

**Borrowed fields**: For `parse(&[u8])`, all `FieldStr` and `ParamValue` variants use `Borrowed` references into the input buffer. No heap allocation occurs unless a PARAM-VALUE contains escape sequences requiring decoding.

**Bytes slicing**: For `parse_bytes(Bytes)`, fields use `FieldStr::Shared(Bytes)` which are reference-counted sub-slices of the input. This enables `'static` lifetime without copying, at the cost of keeping the original buffer alive. For relay mode where the full buffer is preserved anyway, this cost is zero.

**Raw passthrough**: When `preserve_raw` is enabled, the serializer returns the original bytes directly. Combined with octet-counting framing, relay forwarding of unmodified messages requires zero parsing-related allocations.

### 9.3 SmallVec Tuning

Heap allocation for vector contents is avoided for common cases using `SmallVec`:

| Field | Inline Capacity | Rationale |
|-------|----------------|-----------|
| `structured_data` | 2 | Most messages have 0-2 SD-ELEMENTs. Messages from timeQuality-aware sources typically have 1. |
| `SdElement::params` | 4 | IANA-registered SD-IDs have 2-3 params. Private IDs rarely exceed 4. |
| `warnings` | 2 | Lenient mode rarely accumulates more than 1-2 warnings. |

When the inline capacity is exceeded, `SmallVec` spills to the heap. This is acceptable for the rare case since the allocation cost is amortized over the many messages that stay inline.

### 9.4 Lookup Tables

**Month name lookup (RFC 3164)**: A 32-entry perfect hash table maps 3-letter month abbreviations to month indices using `(first_byte ^ third_byte) & 0x1F` as the hash function. This replaces 12 sequential `memcmp` comparisons with a single table lookup and one `memcmp` confirmation. The table is computed at compile time.

**PRINTUSASCII validation**: Instead of a range check (`b >= 33 && b <= 126`), a 256-byte lookup table maps each byte to a boolean. This trades 256 bytes of static memory for branch-free validation, which matters when scanning long header fields.

```rust
/// Precomputed table: is_printusascii[b] == true iff b is in %d33-126.
static IS_PRINTUSASCII: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 33u8;
    while i <= 126 {
        table[i as usize] = true;
        i += 1;
    }
    table
};

#[inline(always)]
fn is_printusascii(b: u8) -> bool {
    IS_PRINTUSASCII[b as usize]
}
```

### 9.5 Digit Parsing Without `str::parse`

All numeric fields (PRI, VERSION, timestamp components) are parsed manually with inline arithmetic rather than converting to `&str` and calling `str::parse::<u32>()`. The manual approach avoids:
- UTF-8 validation overhead (we already know the bytes are ASCII digits).
- `FromStr` trait dispatch overhead.
- Error type allocation (`ParseIntError` is richer than needed).

The `parse_fixed_digits::<N>` generic function compiles to tight code for N=2 and N=4 (the only values used).

### 9.6 SIMD Potential

Two operations are candidates for SIMD acceleration:

1. **Space-delimited field scanning**: Finding the next `0x20` byte in the header uses sequential byte comparison. `memchr::memchr(b' ', slice)` already uses SIMD on x86_64 and aarch64, and is used via the `memchr` crate for all delimiter scanning in header fields.

2. **PRINTUSASCII validation of header fields**: Validating that all bytes in a hostname (up to 255 bytes) are in the range 33-126 could use SIMD range comparison. However, the lookup table approach is already fast enough for fields under 256 bytes, and the branch predictor handles the common case (all valid) efficiently.

SIMD is not pursued for structured data parsing because the control flow (escape detection, nested brackets) is too irregular for data-parallel processing.

### 9.7 Branch Prediction Hints

The parser uses `#[cold]` and `#[inline(never)]` on error-path functions to keep the happy path compact and hot:

```rust
#[cold]
#[inline(never)]
fn make_pri_error(span: Span) -> ParseError {
    ParseError::InvalidPri { span }
}
```

This keeps the instruction cache footprint of the hot path small and improves branch predictor accuracy, since error paths are rarely taken in production.

### 9.8 Benchmark Methodology

Benchmarks use `criterion` with the following message corpus:

| Test Case | Description | Expected Latency |
|-----------|-------------|-----------------|
| `minimal_5424` | `<14>1 - - - - - -` | < 500 ns |
| `typical_5424` | Full header, 1 SD-ELEMENT with 3 params, 100-byte MSG | < 2 us |
| `complex_5424` | Full header, 3 SD-ELEMENTs, escaped params, 500-byte MSG with BOM | < 5 us |
| `maxsize_5424` | 8192-byte message with large MSG body | < 8 us |
| `typical_3164` | BSD format with hostname, tag, and PID | < 1.5 us |
| `malformed_reject` | Various invalid messages (strict mode error path) | < 500 ns |
| `round_trip` | Parse then serialize back to bytes | < 4 us |

Each benchmark runs for 5 seconds with warm-up, reporting p50/p99/p99.9 latencies and throughput (messages/second). Benchmarks are tracked across commits using `criterion`'s comparison mode to detect regressions.

Memory allocation benchmarks use `dhat` to count heap allocations per parse call, verifying the zero-allocation property for simple messages.

Fuzz testing uses `cargo-fuzz` with `libfuzzer` to explore the parser's input space. The fuzz harness calls `parse()` in both strict and lenient modes and asserts that:
- The parser never panics.
- Strict mode either returns a valid message or a well-formed error.
- Lenient mode returns a message for any input with a valid PRI.
- Round-trip serialization of successfully parsed messages produces valid re-parseable output.

```rust
// fuzz/fuzz_targets/parse_fuzz.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let opts_strict = ParseOptions {
        mode: ParseMode::Strict,
        max_message_size: 65536,
        preserve_raw: false,
    };
    let opts_lenient = ParseOptions {
        mode: ParseMode::Lenient,
        max_message_size: 65536,
        preserve_raw: false,
    };

    // Must not panic in either mode
    let _ = syslog_core::parse(data, &opts_strict);

    if let Ok(msg) = syslog_core::parse(data, &opts_lenient) {
        // Round-trip check
        let mut buf = Vec::new();
        syslog_core::serialize_rfc5424(&msg, &mut buf);
        let reparsed = syslog_core::parse(&buf, &opts_strict);
        // Reparsed message should succeed (serializer produces valid output)
        assert!(reparsed.is_ok(), "round-trip failed: {:?}", reparsed.err());
    }
});
```

---

## Appendix A: Dependency Summary

| Crate | Version | Purpose |
|-------|---------|---------|
| `time` | 0.3.x | `OffsetDateTime` for timestamp representation |
| `bytes` | 1.x | `Bytes` for zero-copy owned buffer slicing |
| `smallvec` | 1.x | Inline-allocated vectors for SD-ELEMENTs and params |
| `memchr` | 2.x | SIMD-accelerated byte scanning for field delimiters |
| `serde` | 1.x | JSON serialization (optional feature) |
| `serde_json` | 1.x | JSON output (optional feature) |

No other dependencies are required for the core parsing module. The `serde` and `serde_json` dependencies are gated behind a `json` feature flag.

## Appendix B: Module Layout

```
syslog-core/
  src/
    lib.rs                  # Crate root, #![deny(unsafe_code)] with targeted allows
    message.rs              # SyslogMessage, MessageBody, MessageMetadata
    facility.rs             # Facility enum
    severity.rs             # Severity enum
    timestamp.rs            # SyslogTimestamp, serialize_timestamp
    structured_data.rs      # SdElement, SdParam, FieldStr, ParamValue
    parse/
      mod.rs                # parse(), parse_bytes(), ParseOptions, ParseMode
      detect.rs             # detect_format()
      rfc5424.rs            # parse_rfc5424() and sub-parsers
      rfc3164.rs            # parse_rfc3164()
      cursor.rs             # Cursor helper
      pri.rs                # parse_pri(), decompose_pri()
      timestamp.rs          # parse_timestamp(), parse_bsd_timestamp()
      header.rs             # parse_header_field()
      structured_data.rs    # parse_structured_data(), parse_sd_element(), etc.
      msg.rs                # parse_msg()
    validate.rs             # Post-parse validation helpers
    error.rs                # ParseError, ParseWarning, Span, TimestampError
    serialize/
      mod.rs                # serialize_rfc5424(), Serialize impls
      rfc5424.rs            # Wire-format serializer
      json.rs               # JSON serializer (feature-gated)
      frame.rs              # write_octet_counted_frame()
    extensions/
      mod.rs                # SdProcessor trait, SdProcessorRegistry
      signature.rs          # RFC 5848 SignatureBlock
      alarm.rs              # RFC 5674 AlarmData
```

