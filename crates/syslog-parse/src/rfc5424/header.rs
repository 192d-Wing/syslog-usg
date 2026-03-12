//! RFC 5424 header field parsing helpers.
//!
//! Parses PRI, VERSION, TIMESTAMP, and the SP-delimited header fields
//! (HOSTNAME, APP-NAME, PROCID, MSGID).

use compact_str::CompactString;
use syslog_proto::{Facility, Pri, Severity, SyslogTimestamp};
use time::format_description::well_known::Rfc3339;

use crate::error::ParseError;

/// RFC 5424 §6.1: PRINTUSASCII = %d33-126
fn is_printusascii(b: u8) -> bool {
    (33..=126).contains(&b)
}

/// Parse the PRI field: `<` PRIVAL `>`.
///
/// RFC 5424 §6.2.1 MUST: PRI is 1-3 digits, value 0-191.
/// Uses checked arithmetic for the digit accumulation.
pub fn parse_pri(input: &[u8], pos: &mut usize) -> Result<Pri, ParseError> {
    // Expect '<'
    if input.get(*pos).copied() != Some(b'<') {
        return Err(ParseError::MissingPri);
    }
    *pos = pos
        .checked_add(1)
        .ok_or(ParseError::UnexpectedEndOfInput { context: "PRI" })?;

    // Accumulate 1-3 digits with checked arithmetic
    let start = *pos;
    let mut value: u16 = 0;
    let mut digit_count: u8 = 0;

    loop {
        let b = input
            .get(*pos)
            .copied()
            .ok_or(ParseError::UnexpectedEndOfInput {
                context: "PRI digits",
            })?;

        if b == b'>' {
            break;
        }

        if !b.is_ascii_digit() {
            return Err(ParseError::InvalidPri(format!(
                "non-digit in PRI at position {}",
                *pos
            )));
        }

        digit_count = digit_count
            .checked_add(1)
            .ok_or_else(|| ParseError::InvalidPri("PRI digit count overflow".to_owned()))?;
        if digit_count > 3 {
            return Err(ParseError::InvalidPri("PRI exceeds 3 digits".to_owned()));
        }

        let digit = (b - b'0') as u16;
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(ParseError::InvalidPri("PRI arithmetic overflow".to_owned()))?;

        *pos = pos
            .checked_add(1)
            .ok_or(ParseError::UnexpectedEndOfInput { context: "PRI" })?;
    }

    if digit_count == 0 {
        return Err(ParseError::InvalidPri("PRI has no digits".to_owned()));
    }

    // RFC 5424 §6.2.1 MUST: PRI value range 0-191
    if value > 191 {
        return Err(ParseError::PriOutOfRange(value));
    }

    // Skip the '>'
    *pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
        context: "PRI close",
    })?;

    // Decode facility and severity
    let facility_code = (value / 8) as u8;
    let severity_code = (value % 8) as u8;

    let facility = Facility::try_from(facility_code).map_err(|e| {
        ParseError::InvalidPri(format!(
            "invalid facility {facility_code} from PRI {value}: {e}"
        ))
    })?;
    let severity = Severity::try_from(severity_code).map_err(|e| {
        ParseError::InvalidPri(format!(
            "invalid severity {severity_code} from PRI {value}: {e}"
        ))
    })?;

    let _ = start; // used only for context
    Ok(Pri::new(facility, severity))
}

/// Parse the VERSION field.
///
/// RFC 5424 §6.2.2 MUST: VERSION is NONZERO-DIGIT, currently only "1".
pub fn parse_version(input: &[u8], pos: &mut usize) -> Result<u8, ParseError> {
    let b = input
        .get(*pos)
        .copied()
        .ok_or(ParseError::UnexpectedEndOfInput { context: "VERSION" })?;

    if !b.is_ascii_digit() || b == b'0' {
        return Err(ParseError::InvalidVersion(format!(
            "expected nonzero digit, got 0x{b:02X}"
        )));
    }

    let version = b - b'0';

    // RFC 5424 §6.2.2: only version 1 is currently defined
    if version != 1 {
        return Err(ParseError::UnsupportedVersion(version));
    }

    *pos = pos
        .checked_add(1)
        .ok_or(ParseError::UnexpectedEndOfInput { context: "VERSION" })?;

    Ok(version)
}

/// Expect and consume a SP (space) character.
pub fn expect_sp(input: &[u8], pos: &mut usize, context: &'static str) -> Result<(), ParseError> {
    let b = input
        .get(*pos)
        .copied()
        .ok_or(ParseError::UnexpectedEndOfInput { context })?;

    if b != b' ' {
        return Err(ParseError::InvalidCharacter {
            field: context,
            position: *pos,
            byte: b,
        });
    }

    *pos = pos
        .checked_add(1)
        .ok_or(ParseError::UnexpectedEndOfInput { context })?;

    Ok(())
}

/// Parse the TIMESTAMP field.
///
/// RFC 5424 §6.2.3: TIMESTAMP = NILVALUE / FULL-DATE "T" FULL-TIME
/// FULL-DATE and FULL-TIME follow RFC 3339.
pub fn parse_timestamp(input: &[u8], pos: &mut usize) -> Result<SyslogTimestamp, ParseError> {
    // Check for NILVALUE
    if input.get(*pos).copied() == Some(b'-') {
        // Peek: if next char is SP or end-of-input, this is NILVALUE
        let next = input.get(pos.wrapping_add(1)).copied();
        if next == Some(b' ') || next.is_none() {
            *pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
                context: "TIMESTAMP",
            })?;
            return Ok(SyslogTimestamp::Nil);
        }
    }

    // Find the next SP to delimit the timestamp
    let start = *pos;
    let end = input
        .get(start..)
        .and_then(|slice| slice.iter().position(|&b| b == b' '))
        .and_then(|offset| start.checked_add(offset))
        .unwrap_or(input.len());

    let ts_bytes = input
        .get(start..end)
        .ok_or(ParseError::UnexpectedEndOfInput {
            context: "TIMESTAMP",
        })?;

    let ts_str = core::str::from_utf8(ts_bytes)
        .map_err(|_| ParseError::InvalidTimestamp("non-UTF-8 timestamp".to_owned()))?;

    // Parse as RFC 3339
    let dt = time::OffsetDateTime::parse(ts_str, &Rfc3339)
        .map_err(|e| ParseError::InvalidTimestamp(format!("{ts_str}: {e}")))?;

    *pos = end;

    Ok(SyslogTimestamp::Value(dt))
}

/// Parse a SP-delimited header field (HOSTNAME, APP-NAME, PROCID, MSGID).
///
/// RFC 5424 §6.2.4-6.2.7: Each field is NILVALUE or 1*N PRINTUSASCII,
/// where N is the maximum length for that field type.
pub fn parse_field(
    input: &[u8],
    pos: &mut usize,
    name: &'static str,
    max_len: usize,
) -> Result<Option<CompactString>, ParseError> {
    // Check for NILVALUE
    if input.get(*pos).copied() == Some(b'-') {
        let next = input.get(pos.wrapping_add(1)).copied();
        if next == Some(b' ') || next.is_none() {
            *pos = pos
                .checked_add(1)
                .ok_or(ParseError::UnexpectedEndOfInput { context: name })?;
            return Ok(None);
        }
    }

    // Scan until SP or end of input
    let start = *pos;
    while let Some(&b) = input.get(*pos) {
        if b == b' ' {
            break;
        }
        if !is_printusascii(b) {
            return Err(ParseError::InvalidCharacter {
                field: name,
                position: pos.saturating_sub(start),
                byte: b,
            });
        }
        *pos = pos
            .checked_add(1)
            .ok_or(ParseError::UnexpectedEndOfInput { context: name })?;
    }

    let len = pos.saturating_sub(start);
    if len == 0 {
        return Err(ParseError::UnexpectedEndOfInput { context: name });
    }
    if len > max_len {
        return Err(ParseError::FieldTooLong {
            field: name,
            max: max_len,
            actual: len,
        });
    }

    let field_bytes = input
        .get(start..*pos)
        .ok_or(ParseError::UnexpectedEndOfInput { context: name })?;
    let field_str = core::str::from_utf8(field_bytes)?;

    Ok(Some(CompactString::new(field_str)))
}
