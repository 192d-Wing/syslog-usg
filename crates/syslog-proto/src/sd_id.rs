// RFC 5424 §6.3.2 — SD-ID
// SD-NAME = 1*32 PRINTUSASCII except '=', SP, ']', '"'
// Registered: timeQuality, origin, meta (no '@')
// Enterprise: name@PEN format

use compact_str::CompactString;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Validation error for SD-ID values.
#[derive(Debug, Clone, thiserror::Error)]
pub enum InvalidSdId {
    /// The SD-ID is empty.
    #[error("SD-ID must not be empty")]
    Empty,
    /// The SD-ID exceeds the 32-character maximum.
    #[error("SD-ID exceeds 32-character limit: length {0}")]
    TooLong(usize),
    /// The SD-ID contains an invalid character.
    #[error("SD-ID contains invalid character: {0:?}")]
    InvalidChar(char),
}

/// An SD-ID identifying a structured data element.
///
/// RFC 5424 §6.3.2: SD-ID is either an IANA-registered name (no '@') or an
/// enterprise-specific name in `name@PEN` format.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SdId {
    /// IANA-registered SD-ID (e.g., "timeQuality", "origin", "meta").
    Registered(CompactString),
    /// Enterprise-specific SD-ID in `name@PEN` format.
    Enterprise(CompactString),
}

/// Check whether a character is valid in an SD-NAME.
/// RFC 5424 §6.3.2: PRINTUSASCII except '=', SP, ']', '"'
fn is_valid_sd_name_char(c: char) -> bool {
    // PRINTUSASCII is %d33-126
    let b = c as u32;
    (33..=126).contains(&b) && c != '=' && c != ' ' && c != ']' && c != '"'
}

/// Validate an SD-ID string according to RFC 5424 §6.3.2.
fn validate_sd_id(s: &str) -> Result<(), InvalidSdId> {
    if s.is_empty() {
        return Err(InvalidSdId::Empty);
    }
    if s.len() > 32 {
        return Err(InvalidSdId::TooLong(s.len()));
    }
    for c in s.chars() {
        if !is_valid_sd_name_char(c) {
            return Err(InvalidSdId::InvalidChar(c));
        }
    }
    Ok(())
}

impl SdId {
    /// Create a new SD-ID, automatically classifying as Registered or Enterprise.
    ///
    /// # Errors
    /// Returns `InvalidSdId` if the string violates RFC 5424 §6.3.2 constraints.
    pub fn new(s: &str) -> Result<Self, InvalidSdId> {
        validate_sd_id(s)?;
        if s.contains('@') {
            Ok(Self::Enterprise(CompactString::new(s)))
        } else {
            Ok(Self::Registered(CompactString::new(s)))
        }
    }

    /// Returns the string representation of this SD-ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Registered(s) | Self::Enterprise(s) => s.as_str(),
        }
    }
}

impl fmt::Display for SdId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_id() {
        let id = SdId::new("timeQuality");
        assert!(id.is_ok());
        assert!(
            matches!(&id, Ok(SdId::Registered(s)) if s.as_str() == "timeQuality"),
            "expected Registered('timeQuality'), got {id:?}"
        );
    }

    #[test]
    fn enterprise_id() {
        let id = SdId::new("myId@12345");
        assert!(id.is_ok());
        assert!(
            matches!(&id, Ok(SdId::Enterprise(s)) if s.as_str() == "myId@12345"),
            "expected Enterprise('myId@12345'), got {id:?}"
        );
    }

    #[test]
    fn empty_rejected() {
        assert!(SdId::new("").is_err());
    }

    #[test]
    fn too_long_rejected() {
        let long = "a".repeat(33);
        assert!(SdId::new(&long).is_err());
    }

    #[test]
    fn max_length_accepted() {
        let max = "a".repeat(32);
        assert!(SdId::new(&max).is_ok());
    }

    #[test]
    fn invalid_chars_rejected() {
        assert!(SdId::new("has space").is_err());
        assert!(SdId::new("has=equals").is_err());
        assert!(SdId::new("has]bracket").is_err());
        assert!(SdId::new("has\"quote").is_err());
    }

    #[test]
    fn display() {
        let id = SdId::new("origin");
        assert!(id.is_ok());
        if let Ok(id) = id {
            assert_eq!(id.to_string(), "origin");
        }
    }

    #[test]
    fn equality() {
        let a = SdId::new("origin");
        let b = SdId::new("origin");
        assert!(a.is_ok());
        assert!(b.is_ok());
        assert_eq!(a.ok(), b.ok());
    }
}
