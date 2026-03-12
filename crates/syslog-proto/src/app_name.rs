// RFC 5424 §6.2.5 — APP-NAME
// 1-48 PRINTUSASCII characters, or NILVALUE

use compact_str::CompactString;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Validation error for app name values.
#[derive(Debug, Clone, thiserror::Error)]
pub enum InvalidAppName {
    /// The app name is empty.
    #[error("app name must not be empty")]
    Empty,
    /// The app name exceeds the 48-character maximum.
    #[error("app name exceeds 48-character limit: length {0}")]
    TooLong(usize),
    /// The app name contains an invalid character.
    #[error("app name contains invalid character: {0:?}")]
    InvalidChar(char),
}

/// A syslog APP-NAME value.
///
/// RFC 5424 §6.2.5: APP-NAME = NILVALUE / 1*48PRINTUSASCII
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppName {
    /// A validated application name string.
    Value(CompactString),
    /// The NILVALUE "-", indicating the app name is unknown.
    Nil,
}

/// Check whether a character is PRINTUSASCII (%d33-126).
fn is_printusascii(c: char) -> bool {
    let b = c as u32;
    (33..=126).contains(&b)
}

impl AppName {
    /// Create a new `AppName` from a string, validating RFC 5424 constraints.
    ///
    /// # Errors
    /// Returns `InvalidAppName` if the string is empty, too long, or contains invalid characters.
    pub fn new(s: &str) -> Result<Self, InvalidAppName> {
        if s.is_empty() {
            return Err(InvalidAppName::Empty);
        }
        if s.len() > 48 {
            return Err(InvalidAppName::TooLong(s.len()));
        }
        for c in s.chars() {
            if !is_printusascii(c) {
                return Err(InvalidAppName::InvalidChar(c));
            }
        }
        Ok(Self::Value(CompactString::new(s)))
    }
}

impl fmt::Display for AppName {
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
    fn valid_app_name() {
        let a = AppName::new("myapp");
        assert!(a.is_ok());
        if let Ok(AppName::Value(s)) = &a {
            assert_eq!(s.as_str(), "myapp");
        }
    }

    #[test]
    fn max_length_accepted() {
        let s = "a".repeat(48);
        assert!(AppName::new(&s).is_ok());
    }

    #[test]
    fn too_long_rejected() {
        let s = "a".repeat(49);
        assert!(AppName::new(&s).is_err());
    }

    #[test]
    fn empty_rejected() {
        assert!(AppName::new("").is_err());
    }

    #[test]
    fn invalid_char_rejected() {
        assert!(AppName::new("has space").is_err());
    }

    #[test]
    fn nil_display() {
        assert_eq!(AppName::Nil.to_string(), "-");
    }

    #[test]
    fn value_display() {
        let a = AppName::new("myapp");
        assert!(a.is_ok());
        if let Ok(a) = a {
            assert_eq!(a.to_string(), "myapp");
        }
    }
}
