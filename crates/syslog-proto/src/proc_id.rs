// RFC 5424 §6.2.6 — PROCID
// 1-128 PRINTUSASCII characters, or NILVALUE

use compact_str::CompactString;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Validation error for process ID values.
#[derive(Debug, Clone, thiserror::Error)]
pub enum InvalidProcId {
    /// The process ID is empty.
    #[error("process ID must not be empty")]
    Empty,
    /// The process ID exceeds the 128-character maximum.
    #[error("process ID exceeds 128-character limit: length {0}")]
    TooLong(usize),
    /// The process ID contains an invalid character.
    #[error("process ID contains invalid character: {0:?}")]
    InvalidChar(char),
}

/// A syslog PROCID value.
///
/// RFC 5424 §6.2.6: PROCID = NILVALUE / 1*128PRINTUSASCII
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcId {
    /// A validated process ID string.
    Value(CompactString),
    /// The NILVALUE "-", indicating the process ID is unknown.
    Nil,
}

/// Check whether a character is PRINTUSASCII (%d33-126).
fn is_printusascii(c: char) -> bool {
    let b = c as u32;
    (33..=126).contains(&b)
}

impl ProcId {
    /// Create a new `ProcId` from a string, validating RFC 5424 constraints.
    ///
    /// # Errors
    /// Returns `InvalidProcId` if the string is empty, too long, or contains invalid characters.
    pub fn new(s: &str) -> Result<Self, InvalidProcId> {
        if s.is_empty() {
            return Err(InvalidProcId::Empty);
        }
        if s.len() > 128 {
            return Err(InvalidProcId::TooLong(s.len()));
        }
        for c in s.chars() {
            if !is_printusascii(c) {
                return Err(InvalidProcId::InvalidChar(c));
            }
        }
        Ok(Self::Value(CompactString::new(s)))
    }
}

impl fmt::Display for ProcId {
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
    fn valid_proc_id() {
        let p = ProcId::new("12345");
        assert!(p.is_ok());
        if let Ok(ProcId::Value(s)) = &p {
            assert_eq!(s.as_str(), "12345");
        }
    }

    #[test]
    fn max_length_accepted() {
        let s = "a".repeat(128);
        assert!(ProcId::new(&s).is_ok());
    }

    #[test]
    fn too_long_rejected() {
        let s = "a".repeat(129);
        assert!(ProcId::new(&s).is_err());
    }

    #[test]
    fn empty_rejected() {
        assert!(ProcId::new("").is_err());
    }

    #[test]
    fn invalid_char_rejected() {
        assert!(ProcId::new("has space").is_err());
    }

    #[test]
    fn nil_display() {
        assert_eq!(ProcId::Nil.to_string(), "-");
    }

    #[test]
    fn value_display() {
        let p = ProcId::new("12345");
        assert!(p.is_ok());
        if let Ok(p) = p {
            assert_eq!(p.to_string(), "12345");
        }
    }
}
