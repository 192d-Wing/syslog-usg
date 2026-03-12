//! RFC 5424 §6.4 — MSG body parsing.
//!
//! MSG = MSG-ANY / MSG-UTF8
//! MSG-UTF8 = BOM UTF-8-STRING
//! BOM = %xEF.BB.BF (UTF-8 Byte Order Mark)

use bytes::Bytes;

/// UTF-8 BOM bytes.
const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Parse the MSG portion of an RFC 5424 message.
///
/// The MSG starts after the SP following STRUCTURED-DATA and extends to the end
/// of the input. If a UTF-8 BOM is present, it is stripped from the returned
/// bytes (the rest is the UTF-8 message body).
///
/// Returns `None` if there is no MSG (i.e., the message ends after
/// STRUCTURED-DATA).
#[must_use]
pub fn parse_msg(input: &[u8], pos: usize) -> Option<Bytes> {
    // If pos is at or past the end, there is no MSG
    let remaining = input.get(pos..)?;
    if remaining.is_empty() {
        return None;
    }

    // Check for and strip the UTF-8 BOM
    if remaining.len() >= 3
        && remaining.first().copied() == Some(BOM[0])
        && remaining.get(1).copied() == Some(BOM[1])
        && remaining.get(2).copied() == Some(BOM[2])
    {
        let after_bom = remaining.get(3..)?;
        if after_bom.is_empty() {
            return None;
        }
        return Some(Bytes::copy_from_slice(after_bom));
    }

    Some(Bytes::copy_from_slice(remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_msg() {
        let input = b"<34>1 - - - - - -";
        assert!(parse_msg(input, input.len()).is_none());
    }

    #[test]
    fn plain_msg() {
        let input = b"hello world";
        let result = parse_msg(input, 0);
        assert!(result.is_some());
        if let Some(msg) = result {
            assert_eq!(&msg[..], b"hello world");
        }
    }

    #[test]
    fn msg_with_bom() {
        let mut input = Vec::new();
        input.extend_from_slice(&BOM);
        input.extend_from_slice(b"hello world");
        let result = parse_msg(&input, 0);
        assert!(result.is_some());
        if let Some(msg) = result {
            assert_eq!(&msg[..], b"hello world");
        }
    }

    #[test]
    fn bom_only() {
        let result = parse_msg(&BOM, 0);
        assert!(result.is_none());
    }

    #[test]
    fn msg_at_offset() {
        let input = b"prefix hello world";
        // MSG starts at position 7
        let result = parse_msg(input, 7);
        assert!(result.is_some());
        if let Some(msg) = result {
            assert_eq!(&msg[..], b"hello world");
        }
    }
}
