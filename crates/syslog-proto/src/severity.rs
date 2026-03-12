// RFC 5424 §6.2.1 — Severity values
// RFC 5427 — Textual conventions for severity names

use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Syslog severity levels as defined in RFC 5424 §6.2.1.
///
/// Ordering: `Emergency` > `Alert` > ... > `Debug` — higher urgency compares greater.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Severity {
    /// System is unusable
    Emergency = 0,
    /// Action must be taken immediately
    Alert = 1,
    /// Critical conditions
    Critical = 2,
    /// Error conditions
    Error = 3,
    /// Warning conditions
    Warning = 4,
    /// Normal but significant condition
    Notice = 5,
    /// Informational messages
    Informational = 6,
    /// Debug-level messages
    Debug = 7,
}

const ALL: [Severity; 8] = [
    Severity::Emergency,
    Severity::Alert,
    Severity::Critical,
    Severity::Error,
    Severity::Warning,
    Severity::Notice,
    Severity::Informational,
    Severity::Debug,
];

/// Error returned when a numeric severity code is out of range (0-7).
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid severity code: {0} (must be 0-7)")]
pub struct InvalidSeverity(pub u8);

/// Error returned when a severity name string is not recognized.
#[derive(Debug, Clone, thiserror::Error)]
#[error("unknown severity name: {0:?}")]
pub struct UnknownSeverityName(pub String);

// RFC 5424 §6.2.1 MUST: Emergency is the highest severity, Debug the lowest.
// We implement Ord so that higher urgency (lower numeric code) compares greater.
impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // Reverse numeric order: 0 (Emergency) is greatest
        (other.code()).cmp(&self.code())
    }
}

impl Severity {
    /// Returns the numeric severity code (0-7).
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the RFC 5427 canonical textual name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Emergency => "emerg",
            Self::Alert => "alert",
            Self::Critical => "crit",
            Self::Error => "err",
            Self::Warning => "warning",
            Self::Notice => "notice",
            Self::Informational => "info",
            Self::Debug => "debug",
        }
    }

    /// Returns all recognized aliases for this severity (including the canonical name).
    #[must_use]
    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Self::Emergency => &["emerg", "emergency"],
            Self::Alert => &["alert"],
            Self::Critical => &["crit", "critical"],
            Self::Error => &["err", "error"],
            Self::Warning => &["warning", "warn"],
            Self::Notice => &["notice"],
            Self::Informational => &["info", "informational"],
            Self::Debug => &["debug"],
        }
    }

    /// Returns `true` if this severity is at least as urgent as `threshold`.
    ///
    /// For example, `Error.is_at_least(Warning)` is `true` because Error is more urgent.
    #[must_use]
    pub fn is_at_least(self, threshold: Severity) -> bool {
        self >= threshold
    }

    /// Attempt to parse a severity from a case-insensitive name string.
    fn from_name(s: &str) -> Result<Self, UnknownSeverityName> {
        let lower: String = s.to_ascii_lowercase();
        match lower.as_str() {
            "emerg" | "emergency" => Ok(Self::Emergency),
            "alert" => Ok(Self::Alert),
            "crit" | "critical" => Ok(Self::Critical),
            "err" | "error" => Ok(Self::Error),
            "warning" | "warn" => Ok(Self::Warning),
            "notice" => Ok(Self::Notice),
            "info" | "informational" => Ok(Self::Informational),
            "debug" => Ok(Self::Debug),
            _ => Err(UnknownSeverityName(s.to_owned())),
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl TryFrom<u8> for Severity {
    type Error = InvalidSeverity;

    fn try_from(value: u8) -> Result<Self, <Severity as TryFrom<u8>>::Error> {
        ALL.get(value as usize)
            .copied()
            .ok_or(InvalidSeverity(value))
    }
}

impl TryFrom<&str> for Severity {
    type Error = UnknownSeverityName;

    fn try_from(value: &str) -> Result<Self, <Severity as TryFrom<&str>>::Error> {
        Self::from_name(value)
    }
}

impl Serialize for Severity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        Severity::from_name(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_severities_have_correct_codes() {
        for (i, sev) in ALL.iter().enumerate() {
            assert_eq!(sev.code() as usize, i);
        }
    }

    #[test]
    fn try_from_u8_valid() {
        for code in 0u8..8 {
            let sev = Severity::try_from(code);
            assert!(sev.is_ok());
            assert_eq!(sev.ok().map(|s| s.code()), Some(code));
        }
    }

    #[test]
    fn try_from_u8_invalid() {
        for code in 8u8..=255 {
            assert!(Severity::try_from(code).is_err());
        }
    }

    #[test]
    fn try_from_str_canonical() {
        for sev in &ALL {
            let parsed = Severity::try_from(sev.name());
            assert_eq!(parsed.ok(), Some(*sev));
        }
    }

    #[test]
    fn try_from_str_aliases() {
        assert_eq!(
            Severity::try_from("emergency").ok(),
            Some(Severity::Emergency)
        );
        assert_eq!(
            Severity::try_from("critical").ok(),
            Some(Severity::Critical)
        );
        assert_eq!(Severity::try_from("error").ok(), Some(Severity::Error));
        assert_eq!(Severity::try_from("warn").ok(), Some(Severity::Warning));
        assert_eq!(
            Severity::try_from("informational").ok(),
            Some(Severity::Informational)
        );
    }

    #[test]
    fn try_from_str_case_insensitive() {
        assert_eq!(Severity::try_from("EMERG").ok(), Some(Severity::Emergency));
        assert_eq!(Severity::try_from("Debug").ok(), Some(Severity::Debug));
    }

    #[test]
    fn try_from_str_unknown() {
        assert!(Severity::try_from("bogus").is_err());
    }

    #[test]
    fn ordering_emergency_is_greatest() {
        assert!(Severity::Emergency > Severity::Alert);
        assert!(Severity::Alert > Severity::Critical);
        assert!(Severity::Critical > Severity::Error);
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Notice);
        assert!(Severity::Notice > Severity::Informational);
        assert!(Severity::Informational > Severity::Debug);
    }

    #[test]
    fn is_at_least() {
        assert!(Severity::Emergency.is_at_least(Severity::Emergency));
        assert!(Severity::Emergency.is_at_least(Severity::Debug));
        assert!(Severity::Error.is_at_least(Severity::Warning));
        assert!(!Severity::Debug.is_at_least(Severity::Informational));
        assert!(!Severity::Warning.is_at_least(Severity::Error));
    }

    #[test]
    fn display_matches_name() {
        for sev in &ALL {
            assert_eq!(sev.to_string(), sev.name());
        }
    }

    #[test]
    fn serde_roundtrip() {
        for sev in &ALL {
            let json = serde_json::to_string(sev);
            assert!(json.is_ok());
            let json = json.ok().unwrap_or_default();
            let parsed: Result<Severity, _> = serde_json::from_str(&json);
            assert_eq!(parsed.ok(), Some(*sev));
        }
    }

    #[test]
    fn aliases_contain_canonical_name() {
        for sev in &ALL {
            assert!(sev.aliases().contains(&sev.name()));
        }
    }
}
