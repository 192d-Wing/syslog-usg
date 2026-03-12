//! Octet-counting framing codec for syslog over TCP.
//!
//! RFC 6587 §3.4.1: SYSLOG-FRAME = MSG-LEN SP SYSLOG-MSG
//! MSG-LEN is the number of octets in SYSLOG-MSG.

use crate::error::ParseError;

/// Parse the MSG-LEN prefix from an octet-counting framed syslog stream.
///
/// Returns `(msg_len, header_len)` where `header_len` is the number of bytes
/// consumed by the MSG-LEN and the trailing SP. The actual message starts at
/// byte offset `header_len` and is `msg_len` bytes long.
///
/// # Errors
/// Returns `ParseError` if the MSG-LEN is missing, not a valid number,
/// or the trailing SP is absent.
pub fn parse_frame_length(input: &[u8]) -> Result<(usize, usize), ParseError> {
    if input.is_empty() {
        return Err(ParseError::EmptyInput);
    }

    // Find the space delimiter after MSG-LEN
    let sp_pos = input
        .iter()
        .position(|&b| b == b' ')
        .ok_or(ParseError::UnexpectedEndOfInput {
            context: "octet-counting MSG-LEN",
        })?;

    if sp_pos == 0 {
        return Err(ParseError::InvalidPri("MSG-LEN is empty".to_owned()));
    }

    // Parse the digit string as MSG-LEN using checked arithmetic
    let len_bytes = input
        .get(..sp_pos)
        .ok_or(ParseError::UnexpectedEndOfInput {
            context: "octet-counting MSG-LEN digits",
        })?;

    let len_str = core::str::from_utf8(len_bytes)
        .map_err(|_| ParseError::InvalidPri("MSG-LEN contains non-ASCII".to_owned()))?;

    // Validate all digits
    for (i, &b) in len_bytes.iter().enumerate() {
        if !b.is_ascii_digit() {
            return Err(ParseError::InvalidCharacter {
                field: "MSG-LEN",
                position: i,
                byte: b,
            });
        }
    }

    let msg_len: usize = len_str
        .parse()
        .map_err(|_| ParseError::InvalidPri(format!("MSG-LEN too large: {len_str}")))?;

    // header_len = digits + SP
    let header_len = sp_pos
        .checked_add(1)
        .ok_or(ParseError::UnexpectedEndOfInput {
            context: "octet-counting header overflow",
        })?;

    Ok((msg_len, header_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_frame() {
        let input = b"11 <34>1 - - -";
        let result = parse_frame_length(input);
        assert!(result.is_ok());
        if let Ok((msg_len, header_len)) = result {
            assert_eq!(msg_len, 11);
            assert_eq!(header_len, 3); // "11 " = 3 bytes
        }
    }

    #[test]
    fn single_digit() {
        let input = b"5 hello";
        let result = parse_frame_length(input);
        assert!(result.is_ok());
        if let Ok((msg_len, header_len)) = result {
            assert_eq!(msg_len, 5);
            assert_eq!(header_len, 2);
        }
    }

    #[test]
    fn empty_input() {
        assert!(parse_frame_length(b"").is_err());
    }

    #[test]
    fn no_space() {
        assert!(parse_frame_length(b"123").is_err());
    }

    #[test]
    fn leading_space() {
        assert!(parse_frame_length(b" 123").is_err());
    }
}
