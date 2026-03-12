//! Error types for the syslog management model.

use core::fmt;

/// Errors that can occur during management model operations.
#[derive(Debug)]
pub enum MgmtError {
    /// An invalid selector specification was provided.
    InvalidSelector(String),
    /// An invalid pattern string was provided.
    InvalidPattern(String),
    /// An invalid action specification was provided.
    InvalidAction(String),
    /// A regex compilation error occurred.
    RegexError(regex::Error),
}

impl fmt::Display for MgmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSelector(msg) => write!(f, "invalid selector: {msg}"),
            Self::InvalidPattern(msg) => write!(f, "invalid pattern: {msg}"),
            Self::InvalidAction(msg) => write!(f, "invalid action: {msg}"),
            Self::RegexError(err) => write!(f, "regex error: {err}"),
        }
    }
}

impl std::error::Error for MgmtError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RegexError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<regex::Error> for MgmtError {
    fn from(err: regex::Error) -> Self {
        Self::RegexError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_selector_displays() {
        let err = MgmtError::InvalidSelector("bad facility".to_owned());
        let msg = format!("{err}");
        assert!(msg.contains("invalid selector"));
        assert!(msg.contains("bad facility"));
    }

    #[test]
    fn invalid_pattern_displays() {
        let err = MgmtError::InvalidPattern("unclosed group".to_owned());
        let msg = format!("{err}");
        assert!(msg.contains("invalid pattern"));
        assert!(msg.contains("unclosed group"));
    }

    #[test]
    fn invalid_action_displays() {
        let err = MgmtError::InvalidAction("unknown type".to_owned());
        let msg = format!("{err}");
        assert!(msg.contains("invalid action"));
        assert!(msg.contains("unknown type"));
    }

    #[test]
    fn regex_error_displays_and_has_source() {
        // Build an invalid regex to get a regex::Error.
        // Construct the pattern at runtime to avoid clippy::invalid_regex.
        let bad_pattern = String::from("[invalid");
        let regex_result = regex::Regex::new(&bad_pattern);
        let regex_err = match regex_result {
            Err(e) => e,
            Ok(_) => return,
        };
        let err = MgmtError::from(regex_err);
        let msg = format!("{err}");
        assert!(msg.contains("regex error"));
        // Verify source() returns Some
        assert!(std::error::Error::source(&err).is_some());
    }
}
