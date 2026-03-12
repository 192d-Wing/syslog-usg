// RFC 5424 §6.2.4 — HOSTNAME
// 1-255 PRINTUSASCII characters, or NILVALUE

use compact_str::CompactString;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Validation error for hostname values.
#[derive(Debug, Clone, thiserror::Error)]
pub enum InvalidHostname {
    /// The hostname is empty.
    #[error("hostname must not be empty")]
    Empty,
    /// The hostname exceeds the 255-character maximum.
    #[error("hostname exceeds 255-character limit: length {0}")]
    TooLong(usize),
    /// The hostname contains an invalid character.
    #[error("hostname contains invalid character: {0:?}")]
    InvalidChar(char),
}

/// A syslog HOSTNAME value.
///
/// RFC 5424 §6.2.4: HOSTNAME = NILVALUE / 1*255PRINTUSASCII
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Hostname {
    /// A validated hostname string.
    Value(CompactString),
    /// The NILVALUE "-", indicating the hostname is unknown.
    Nil,
}

/// Check whether a character is PRINTUSASCII (%d33-126).
fn is_printusascii(c: char) -> bool {
    let b = c as u32;
    (33..=126).contains(&b)
}

impl Hostname {
    /// Create a new `Hostname` from a string, validating RFC 5424 constraints.
    ///
    /// # Errors
    /// Returns `InvalidHostname` if the string is empty, too long, or contains invalid characters.
    pub fn new(s: &str) -> Result<Self, InvalidHostname> {
        if s.is_empty() {
            return Err(InvalidHostname::Empty);
        }
        if s.len() > 255 {
            return Err(InvalidHostname::TooLong(s.len()));
        }
        for c in s.chars() {
            if !is_printusascii(c) {
                return Err(InvalidHostname::InvalidChar(c));
            }
        }
        Ok(Self::Value(CompactString::new(s)))
    }
}

impl fmt::Display for Hostname {
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
    fn valid_hostname() {
        let h = Hostname::new("myhost.example.com");
        assert!(h.is_ok());
        if let Ok(Hostname::Value(s)) = &h {
            assert_eq!(s.as_str(), "myhost.example.com");
        }
    }

    #[test]
    fn max_length_accepted() {
        let s = "a".repeat(255);
        assert!(Hostname::new(&s).is_ok());
    }

    #[test]
    fn too_long_rejected() {
        let s = "a".repeat(256);
        assert!(Hostname::new(&s).is_err());
    }

    #[test]
    fn empty_rejected() {
        assert!(Hostname::new("").is_err());
    }

    #[test]
    fn invalid_char_rejected() {
        assert!(Hostname::new("has space").is_err());
        assert!(Hostname::new("has\ttab").is_err());
    }

    #[test]
    fn nil_display() {
        assert_eq!(Hostname::Nil.to_string(), "-");
    }

    #[test]
    fn value_display() {
        let h = Hostname::new("example.com");
        assert!(h.is_ok());
        if let Ok(h) = h {
            assert_eq!(h.to_string(), "example.com");
        }
    }
}
