//! Parse error types for syslog message parsing.

use core::fmt;

/// Errors that can occur while parsing a syslog message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input is empty.
    EmptyInput,
    /// The PRI field is missing (no leading `<`).
    MissingPri,
    /// The PRI field could not be parsed.
    InvalidPri(String),
    /// The PRI numeric value is out of the valid range (0-191).
    PriOutOfRange(u16),
    /// The VERSION field could not be parsed.
    InvalidVersion(String),
    /// The VERSION value is not supported (only version 1 is defined by RFC 5424).
    UnsupportedVersion(u8),
    /// The TIMESTAMP field could not be parsed.
    InvalidTimestamp(String),
    /// A header field exceeds its maximum allowed length.
    FieldTooLong {
        /// Name of the field.
        field: &'static str,
        /// Maximum allowed length.
        max: usize,
        /// Actual length encountered.
        actual: usize,
    },
    /// A header field contains an invalid character.
    InvalidCharacter {
        /// Name of the field.
        field: &'static str,
        /// Byte position within the field.
        position: usize,
        /// The invalid byte value.
        byte: u8,
    },
    /// The structured data section is malformed.
    MalformedStructuredData(String),
    /// An invalid escape sequence was found in structured data.
    InvalidSdEscape {
        /// Position of the invalid escape within the input.
        position: usize,
    },
    /// Too many SD-ELEMENTs in structured data.
    TooManySdElements {
        /// Maximum allowed number of elements.
        max: usize,
        /// Actual number of elements encountered.
        actual: usize,
    },
    /// The message exceeds the maximum allowed size.
    MessageTooLarge {
        /// Maximum allowed size in bytes.
        max: usize,
        /// Actual size in bytes.
        actual: usize,
    },
    /// Unexpected end of input while parsing a specific section.
    UnexpectedEndOfInput {
        /// Context describing what was being parsed.
        context: &'static str,
    },
    /// The input contains invalid UTF-8 where UTF-8 was required.
    Utf8Error(std::str::Utf8Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "empty input"),
            Self::MissingPri => write!(f, "missing PRI field"),
            Self::InvalidPri(s) => write!(f, "invalid PRI: {s}"),
            Self::PriOutOfRange(v) => write!(f, "PRI value out of range: {v} (must be 0-191)"),
            Self::InvalidVersion(s) => write!(f, "invalid version: {s}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version: {v}"),
            Self::InvalidTimestamp(s) => write!(f, "invalid timestamp: {s}"),
            Self::FieldTooLong { field, max, actual } => {
                write!(f, "{field} too long: {actual} bytes (max {max})")
            }
            Self::InvalidCharacter {
                field,
                position,
                byte,
            } => {
                write!(
                    f,
                    "invalid character in {field} at position {position}: 0x{byte:02X}"
                )
            }
            Self::MalformedStructuredData(s) => write!(f, "malformed structured data: {s}"),
            Self::InvalidSdEscape { position } => {
                write!(f, "invalid SD escape at position {position}")
            }
            Self::TooManySdElements { max, actual } => {
                write!(f, "too many SD elements: {actual} (max {max})")
            }
            Self::MessageTooLarge { max, actual } => {
                write!(f, "message too large: {actual} bytes (max {max})")
            }
            Self::UnexpectedEndOfInput { context } => {
                write!(f, "unexpected end of input while parsing {context}")
            }
            Self::Utf8Error(e) => write!(f, "UTF-8 error: {e}"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Utf8Error(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::str::Utf8Error> for ParseError {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::Utf8Error(e)
    }
}
