//! RFC 5424 §6.3 — Structured data parsing.
//!
//! STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT
//! SD-ELEMENT = "[" SD-ID *(SP SD-PARAM) "]"
//! SD-PARAM = PARAM-NAME "=" %d34 PARAM-VALUE %d34
//! PARAM-VALUE may contain escaped characters: `\"`, `\\`, `\]`

use compact_str::CompactString;
use smallvec::SmallVec;
use syslog_proto::{SdElement, SdId, SdParam, StructuredData};

use crate::error::ParseError;

/// Maximum number of SD-ELEMENTs allowed.
const MAX_SD_ELEMENTS: usize = 128;
/// Maximum number of SD-PARAMs per element.
const MAX_SD_PARAMS: usize = 64;
/// Maximum length of a single PARAM-VALUE in bytes.
/// Prevents unbounded heap allocation from attacker-controlled input.
const MAX_PARAM_VALUE_LENGTH: usize = 8192;

/// Parse the STRUCTURED-DATA portion of an RFC 5424 message.
///
/// RFC 5424 §6.3: STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT
pub fn parse_structured_data(input: &[u8], pos: &mut usize) -> Result<StructuredData, ParseError> {
    // Check for NILVALUE
    if input.get(*pos).copied() == Some(b'-') {
        let next = input.get(pos.wrapping_add(1)).copied();
        if next == Some(b' ') || next.is_none() {
            *pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
                context: "STRUCTURED-DATA",
            })?;
            return Ok(StructuredData::nil());
        }
    }

    let mut elements: SmallVec<[SdElement; 2]> = SmallVec::new();

    // Parse one or more SD-ELEMENTs, each starting with '['
    while input.get(*pos).copied() == Some(b'[') {
        if elements.len() >= MAX_SD_ELEMENTS {
            return Err(ParseError::TooManySdElements {
                max: MAX_SD_ELEMENTS,
                actual: elements.len().saturating_add(1),
            });
        }
        let element = parse_sd_element(input, pos)?;
        elements.push(element);
    }

    if elements.is_empty() {
        return Err(ParseError::MalformedStructuredData(
            "expected NILVALUE or SD-ELEMENT".to_owned(),
        ));
    }

    Ok(StructuredData(elements))
}

/// Parse a single SD-ELEMENT: `[` SD-ID *(SP SD-PARAM) `]`
fn parse_sd_element(input: &[u8], pos: &mut usize) -> Result<SdElement, ParseError> {
    // Consume '['
    if input.get(*pos).copied() != Some(b'[') {
        return Err(ParseError::MalformedStructuredData(
            "expected '[' at start of SD-ELEMENT".to_owned(),
        ));
    }
    *pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
        context: "SD-ELEMENT",
    })?;

    // Parse SD-ID (terminated by SP or ']')
    let id = parse_sd_id(input, pos)?;

    // Parse SD-PARAMs
    let mut params: SmallVec<[SdParam; 4]> = SmallVec::new();

    while input.get(*pos).copied() == Some(b' ') {
        // Consume SP
        *pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
            context: "SD-PARAM separator",
        })?;

        // If we hit ']' after SP, that is the end (trailing space — lenient)
        if input.get(*pos).copied() == Some(b']') {
            break;
        }

        if params.len() >= MAX_SD_PARAMS {
            return Err(ParseError::MalformedStructuredData(format!(
                "too many SD-PARAMs: exceeds {MAX_SD_PARAMS}"
            )));
        }

        let param = parse_sd_param(input, pos)?;
        params.push(param);
    }

    // Consume ']'
    if input.get(*pos).copied() != Some(b']') {
        return Err(ParseError::MalformedStructuredData(
            "expected ']' at end of SD-ELEMENT".to_owned(),
        ));
    }
    *pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
        context: "SD-ELEMENT close",
    })?;

    Ok(SdElement { id, params })
}

/// Parse an SD-ID: 1*32 SD-NAME characters (PRINTUSASCII except '=', SP, ']', '"')
fn parse_sd_id(input: &[u8], pos: &mut usize) -> Result<SdId, ParseError> {
    let start = *pos;

    while let Some(&b) = input.get(*pos) {
        if b == b' ' || b == b']' {
            break;
        }
        if !is_sd_name_char(b) {
            return Err(ParseError::MalformedStructuredData(format!(
                "invalid character 0x{b:02X} in SD-ID at position {}",
                pos.saturating_sub(start)
            )));
        }
        *pos = pos
            .checked_add(1)
            .ok_or(ParseError::UnexpectedEndOfInput { context: "SD-ID" })?;
    }

    let len = pos.saturating_sub(start);
    if len == 0 {
        return Err(ParseError::MalformedStructuredData(
            "empty SD-ID".to_owned(),
        ));
    }
    if len > 32 {
        return Err(ParseError::FieldTooLong {
            field: "SD-ID",
            max: 32,
            actual: len,
        });
    }

    let id_bytes = input
        .get(start..*pos)
        .ok_or(ParseError::UnexpectedEndOfInput {
            context: "SD-ID bytes",
        })?;
    let id_str = core::str::from_utf8(id_bytes)?;

    SdId::new(id_str)
        .map_err(|e| ParseError::MalformedStructuredData(format!("invalid SD-ID: {e}")))
}

/// Parse an SD-PARAM: PARAM-NAME `=` `"` PARAM-VALUE `"`
fn parse_sd_param(input: &[u8], pos: &mut usize) -> Result<SdParam, ParseError> {
    // Parse PARAM-NAME (SD-NAME chars until '=')
    let name_start = *pos;
    while let Some(&b) = input.get(*pos) {
        if b == b'=' {
            break;
        }
        if !is_sd_name_char(b) {
            return Err(ParseError::MalformedStructuredData(format!(
                "invalid character 0x{b:02X} in PARAM-NAME"
            )));
        }
        *pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
            context: "PARAM-NAME",
        })?;
    }

    let name_len = pos.saturating_sub(name_start);
    if name_len == 0 {
        return Err(ParseError::MalformedStructuredData(
            "empty PARAM-NAME".to_owned(),
        ));
    }
    if name_len > 32 {
        return Err(ParseError::FieldTooLong {
            field: "PARAM-NAME",
            max: 32,
            actual: name_len,
        });
    }

    let name_bytes = input
        .get(name_start..*pos)
        .ok_or(ParseError::UnexpectedEndOfInput {
            context: "PARAM-NAME bytes",
        })?;
    let name_str = core::str::from_utf8(name_bytes)?;

    // Consume '='
    if input.get(*pos).copied() != Some(b'=') {
        return Err(ParseError::MalformedStructuredData(
            "expected '=' after PARAM-NAME".to_owned(),
        ));
    }
    *pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
        context: "PARAM-NAME =",
    })?;

    // Consume opening '"'
    if input.get(*pos).copied() != Some(b'"') {
        return Err(ParseError::MalformedStructuredData(
            "expected '\"' to start PARAM-VALUE".to_owned(),
        ));
    }
    *pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
        context: "PARAM-VALUE open quote",
    })?;

    // Parse PARAM-VALUE with escape handling
    let value = parse_param_value(input, pos)?;

    Ok(SdParam {
        name: CompactString::new(name_str),
        value: CompactString::new(&value),
    })
}

/// Parse a PARAM-VALUE, handling escape sequences.
///
/// RFC 5424 §6.3.3: Within PARAM-VALUE, `\"`, `\\`, and `\]` are the only
/// valid escape sequences.
fn parse_param_value(input: &[u8], pos: &mut usize) -> Result<String, ParseError> {
    let mut value = String::new();

    loop {
        let b = input
            .get(*pos)
            .copied()
            .ok_or(ParseError::UnexpectedEndOfInput {
                context: "PARAM-VALUE",
            })?;

        if b == b'"' {
            // End of PARAM-VALUE — consume closing quote
            *pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
                context: "PARAM-VALUE close quote",
            })?;
            return Ok(value);
        }

        // Enforce maximum PARAM-VALUE length to prevent unbounded allocation
        if value.len() >= MAX_PARAM_VALUE_LENGTH {
            return Err(ParseError::FieldTooLong {
                field: "PARAM-VALUE",
                max: MAX_PARAM_VALUE_LENGTH,
                actual: value.len().saturating_add(1),
            });
        }

        if b == b'\\' {
            // Escape sequence
            let escape_pos = *pos;
            *pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
                context: "PARAM-VALUE escape",
            })?;

            let escaped = input
                .get(*pos)
                .copied()
                .ok_or(ParseError::InvalidSdEscape {
                    position: escape_pos,
                })?;

            match escaped {
                b'"' | b'\\' | b']' => {
                    value.push(escaped as char);
                }
                _ => {
                    return Err(ParseError::InvalidSdEscape {
                        position: escape_pos,
                    });
                }
            }
        } else {
            value.push(b as char);
        }

        *pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
            context: "PARAM-VALUE byte",
        })?;
    }
}

/// Check whether a byte is valid in an SD-NAME.
/// RFC 5424 §6.3.2: PRINTUSASCII except '=', SP, ']', '"'
fn is_sd_name_char(b: u8) -> bool {
    (33..=126).contains(&b) && b != b'=' && b != b' ' && b != b']' && b != b'"'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nilvalue() {
        let input = b"- rest";
        let mut pos = 0;
        let result = parse_structured_data(input, &mut pos);
        assert!(result.is_ok());
        if let Ok(sd) = result {
            assert!(sd.is_nil());
        }
        assert_eq!(pos, 1);
    }

    #[test]
    fn single_element_no_params() {
        let input = b"[exampleSDID@32473] rest";
        let mut pos = 0;
        let result = parse_structured_data(input, &mut pos);
        assert!(result.is_ok());
        if let Ok(sd) = &result {
            assert_eq!(sd.iter().count(), 1);
        }
    }

    #[test]
    fn single_element_with_params() {
        let input =
            b"[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] rest";
        let mut pos = 0;
        let result = parse_structured_data(input, &mut pos);
        assert!(result.is_ok());
        if let Ok(sd) = &result {
            let elements: Vec<_> = sd.iter().collect();
            assert_eq!(elements.len(), 1);
            let el = elements.first();
            assert!(el.is_some());
            if let Some(el) = el {
                assert_eq!(el.id.as_str(), "exampleSDID@32473");
                assert_eq!(el.params.len(), 3);
            }
        }
    }

    #[test]
    fn multiple_elements() {
        let input = b"[id1 a=\"1\"][id2 b=\"2\"] rest";
        let mut pos = 0;
        let result = parse_structured_data(input, &mut pos);
        assert!(result.is_ok());
        if let Ok(sd) = &result {
            assert_eq!(sd.iter().count(), 2);
        }
    }

    #[test]
    fn escape_sequences() {
        let input = b"[test key=\"val\\\"ue\"] rest";
        let mut pos = 0;
        let result = parse_structured_data(input, &mut pos);
        assert!(result.is_ok());
        if let Ok(sd) = &result {
            let el = sd.iter().next();
            assert!(el.is_some());
            if let Some(el) = el {
                assert_eq!(el.param_value("key"), Some("val\"ue"));
            }
        }
    }

    #[test]
    fn escape_backslash() {
        let input = b"[test key=\"val\\\\ue\"] rest";
        let mut pos = 0;
        let result = parse_structured_data(input, &mut pos);
        assert!(result.is_ok());
        if let Ok(sd) = &result {
            let el = sd.iter().next();
            assert!(el.is_some());
            if let Some(el) = el {
                assert_eq!(el.param_value("key"), Some("val\\ue"));
            }
        }
    }

    #[test]
    fn escape_bracket() {
        let input = b"[test key=\"val\\]ue\"] rest";
        let mut pos = 0;
        let result = parse_structured_data(input, &mut pos);
        assert!(result.is_ok());
        if let Ok(sd) = &result {
            let el = sd.iter().next();
            assert!(el.is_some());
            if let Some(el) = el {
                assert_eq!(el.param_value("key"), Some("val]ue"));
            }
        }
    }

    #[test]
    fn invalid_escape() {
        let input = b"[test key=\"val\\xue\"]";
        let mut pos = 0;
        let result = parse_structured_data(input, &mut pos);
        assert!(result.is_err());
    }

    #[test]
    fn malformed_no_closing_bracket() {
        let input = b"[test key=\"value\"";
        let mut pos = 0;
        let result = parse_structured_data(input, &mut pos);
        assert!(result.is_err());
    }
}
