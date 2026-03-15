//! Regex-based pattern matching for syslog management selectors.
//!
//! Wraps `regex::Regex` with management-model error handling.

use crate::error::MgmtError;

/// A compiled regex pattern for matching syslog field values.
#[derive(Debug, Clone)]
pub struct Pattern {
    regex: regex::Regex,
}

impl Pattern {
    /// Compile a new pattern from the given regex string.
    ///
    /// # Errors
    ///
    /// Returns [`MgmtError::RegexError`] if the pattern is not valid regex.
    /// Maximum compiled NFA size (1 MiB) to prevent ReDoS.
    const MAX_REGEX_SIZE: usize = 1024 * 1024;

    pub fn new(pattern: &str) -> Result<Self, MgmtError> {
        let regex = regex::RegexBuilder::new(pattern)
            .size_limit(Self::MAX_REGEX_SIZE)
            .build()?;
        Ok(Self { regex })
    }

    /// Returns `true` if the pattern matches the given input string.
    #[must_use]
    pub fn matches(&self, input: &str) -> bool {
        self.regex.is_match(input)
    }

    /// Returns the original regex pattern string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.regex.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_simple_pattern() {
        let pat = Pattern::new("hello");
        assert!(pat.is_ok());
    }

    #[test]
    fn valid_regex_pattern() {
        let pat = Pattern::new(r"^host\d+$");
        assert!(pat.is_ok());
    }

    #[test]
    fn invalid_regex_returns_error() {
        let pat = Pattern::new("[unclosed");
        assert!(pat.is_err());
    }

    #[test]
    fn matches_simple_string() {
        let pat = match Pattern::new("hello") {
            Ok(p) => p,
            Err(_) => return,
        };
        assert!(pat.matches("hello world"));
        assert!(!pat.matches("goodbye world"));
    }

    #[test]
    fn matches_anchored_pattern() {
        let pat = match Pattern::new(r"^host\d+$") {
            Ok(p) => p,
            Err(_) => return,
        };
        assert!(pat.matches("host42"));
        assert!(pat.matches("host1"));
        assert!(!pat.matches("myhost42"));
        assert!(!pat.matches("host"));
    }

    #[test]
    fn matches_case_sensitive_by_default() {
        let pat = match Pattern::new("Hello") {
            Ok(p) => p,
            Err(_) => return,
        };
        assert!(pat.matches("Hello"));
        assert!(!pat.matches("hello"));
    }

    #[test]
    fn matches_with_case_insensitive_flag() {
        let pat = match Pattern::new("(?i)hello") {
            Ok(p) => p,
            Err(_) => return,
        };
        assert!(pat.matches("Hello"));
        assert!(pat.matches("HELLO"));
        assert!(pat.matches("hello"));
    }

    #[test]
    fn matches_special_chars() {
        let pat = match Pattern::new(r"192\.168\.\d+\.\d+") {
            Ok(p) => p,
            Err(_) => return,
        };
        assert!(pat.matches("192.168.1.1"));
        assert!(pat.matches("host 192.168.0.100 online"));
        assert!(!pat.matches("192x168x1x1"));
    }

    #[test]
    fn as_str_returns_original_pattern() {
        let pat = match Pattern::new(r"^test\d+$") {
            Ok(p) => p,
            Err(_) => return,
        };
        assert_eq!(pat.as_str(), r"^test\d+$");
    }

    #[test]
    fn empty_pattern_matches_everything() {
        let pat = match Pattern::new("") {
            Ok(p) => p,
            Err(_) => return,
        };
        assert!(pat.matches("anything"));
        assert!(pat.matches(""));
    }
}
