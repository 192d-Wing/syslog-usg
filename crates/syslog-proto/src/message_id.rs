// RFC 5424 §6.2.7 — MSGID
// 1-32 PRINTUSASCII characters, or NILVALUE

use compact_str::CompactString;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Validation error for message ID values.
#[derive(Debug, Clone, thiserror::Error)]
pub enum InvalidMessageId {
    /// The message ID is empty.
    #[error("message ID must not be empty")]
    Empty,
    /// The message ID exceeds the 32-character maximum.
    #[error("message ID exceeds 32-character limit: length {0}")]
    TooLong(usize),
    /// The message ID contains an invalid character.
    #[error("message ID contains invalid character: {0:?}")]
    InvalidChar(char),
}

/// A syslog MSGID value.
///
/// RFC 5424 §6.2.7: MSGID = NILVALUE / 1*32PRINTUSASCII
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageId {
    /// A validated message ID string.
    Value(CompactString),
    /// The NILVALUE "-", indicating the message ID is unknown.
    Nil,
}

/// Check whether a character is PRINTUSASCII (%d33-126).
fn is_printusascii(c: char) -> bool {
    let b = c as u32;
    (33..=126).contains(&b)
}

impl MessageId {
    /// Create a new `MessageId` from a string, validating RFC 5424 constraints.
    ///
    /// # Errors
    /// Returns `InvalidMessageId` if the string is empty, too long, or contains invalid characters.
    pub fn new(s: &str) -> Result<Self, InvalidMessageId> {
        if s.is_empty() {
            return Err(InvalidMessageId::Empty);
        }
        if s.len() > 32 {
            return Err(InvalidMessageId::TooLong(s.len()));
        }
        for c in s.chars() {
            if !is_printusascii(c) {
                return Err(InvalidMessageId::InvalidChar(c));
            }
        }
        Ok(Self::Value(CompactString::new(s)))
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(s) => f.write_str(s),
            Self::Nil => f.write_str("-"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_message_id() {
        let m = MessageId::new("ID47");
        assert!(m.is_ok());
        if let Ok(MessageId::Value(s)) = &m {
            assert_eq!(s.as_str(), "ID47");
        }
    }

    #[test]
    fn max_length_accepted() {
        let s = "a".repeat(32);
        assert!(MessageId::new(&s).is_ok());
    }

    #[test]
    fn too_long_rejected() {
        let s = "a".repeat(33);
        assert!(MessageId::new(&s).is_err());
    }

    #[test]
    fn empty_rejected() {
        assert!(MessageId::new("").is_err());
    }

    #[test]
    fn invalid_char_rejected() {
        assert!(MessageId::new("has space").is_err());
    }

    #[test]
    fn nil_display() {
        assert_eq!(MessageId::Nil.to_string(), "-");
    }

    #[test]
    fn value_display() {
        let m = MessageId::new("ID47");
        assert!(m.is_ok());
        if let Ok(m) = m {
            assert_eq!(m.to_string(), "ID47");
        }
    }
}
