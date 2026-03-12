//! Format auto-detection: determines whether input is RFC 5424 or RFC 3164.
//!
//! RFC 5424 §6.2.2: After PRI, the VERSION field is a single nonzero digit
//! followed by SP. Currently only version "1" is defined.

use crate::error::ParseError;
use syslog_proto::SyslogMessage;

/// Auto-detect the syslog format and parse accordingly.
///
/// After parsing the PRI (`<NNN>`), checks whether the next character is a
/// digit followed by a space. If so, treats the input as RFC 5424; otherwise
/// falls back to RFC 3164 (BSD syslog) best-effort parsing.
pub fn parse_auto(input: &[u8]) -> Result<SyslogMessage, ParseError> {
    if input.is_empty() {
        return Err(ParseError::EmptyInput);
    }

    // RFC 5424 §6.1 MUST: PRI starts with '<'
    if input.first().copied() != Some(b'<') {
        return Err(ParseError::MissingPri);
    }

    // Find the closing '>' to locate end of PRI
    let close_pos = find_pri_close(input)?;
    let after_pri = close_pos
        .checked_add(1)
        .ok_or(ParseError::UnexpectedEndOfInput {
            context: "after PRI",
        })?;

    // RFC 5424 §6.2.2: VERSION = NONZERO-DIGIT
    // Check if byte after PRI is '1' followed by SP (RFC 5424 version 1)
    let is_5424 = matches!(
        (input.get(after_pri), input.get(after_pri.wrapping_add(1))),
        (Some(&b'1'), Some(&b' '))
    );

    if is_5424 {
        crate::rfc5424::parser::parse(input)
    } else {
        crate::rfc3164::parser::parse(input)
    }
}

/// Find the position of the closing `>` in the PRI field.
fn find_pri_close(input: &[u8]) -> Result<usize, ParseError> {
    // PRI is at most `<NNN>` = 5 bytes, but we scan up to a reasonable limit
    let limit = if input.len() > 5 { 5 } else { input.len() };
    for i in 1..limit {
        match input.get(i) {
            Some(&b'>') => return Ok(i),
            Some(b) if b.is_ascii_digit() => continue,
            _ => {
                return Err(ParseError::InvalidPri(
                    String::from_utf8_lossy(input.get(..limit).unwrap_or_default()).into_owned(),
                ));
            }
        }
    }
    Err(ParseError::InvalidPri("PRI not terminated".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_rfc5424() {
        let input = b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8";
        let result = parse_auto(input);
        assert!(result.is_ok());
    }

    #[test]
    fn detect_rfc3164() {
        let input = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed";
        let result = parse_auto(input);
        assert!(result.is_ok());
    }

    #[test]
    fn empty_input() {
        assert!(matches!(parse_auto(b""), Err(ParseError::EmptyInput)));
    }

    #[test]
    fn missing_pri() {
        assert!(matches!(
            parse_auto(b"no pri here"),
            Err(ParseError::MissingPri)
        ));
    }
}
