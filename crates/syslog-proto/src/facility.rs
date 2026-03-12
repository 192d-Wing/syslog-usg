// RFC 5424 §6.2.1 — Facility values
// RFC 5427 — Textual conventions for facility names

use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Syslog facility codes as defined in RFC 5424 §6.2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Facility {
    /// Kernel messages
    Kern = 0,
    /// User-level messages
    User = 1,
    /// Mail system
    Mail = 2,
    /// System daemons
    Daemon = 3,
    /// Security/authorization messages
    Auth = 4,
    /// Messages generated internally by syslogd
    Syslog = 5,
    /// Line printer subsystem
    Lpr = 6,
    /// Network news subsystem
    News = 7,
    /// UUCP subsystem
    Uucp = 8,
    /// Clock daemon
    Cron = 9,
    /// Security/authorization messages (private)
    Authpriv = 10,
    /// FTP daemon
    Ftp = 11,
    /// NTP subsystem
    Ntp = 12,
    /// Log audit
    Audit = 13,
    /// Log alert
    Alert = 14,
    /// Clock daemon (note 2)
    Clock = 15,
    /// Local use 0
    Local0 = 16,
    /// Local use 1
    Local1 = 17,
    /// Local use 2
    Local2 = 18,
    /// Local use 3
    Local3 = 19,
    /// Local use 4
    Local4 = 20,
    /// Local use 5
    Local5 = 21,
    /// Local use 6
    Local6 = 22,
    /// Local use 7
    Local7 = 23,
}

/// All facility values in numeric order.
pub const ALL: [Facility; 24] = [
    Facility::Kern,
    Facility::User,
    Facility::Mail,
    Facility::Daemon,
    Facility::Auth,
    Facility::Syslog,
    Facility::Lpr,
    Facility::News,
    Facility::Uucp,
    Facility::Cron,
    Facility::Authpriv,
    Facility::Ftp,
    Facility::Ntp,
    Facility::Audit,
    Facility::Alert,
    Facility::Clock,
    Facility::Local0,
    Facility::Local1,
    Facility::Local2,
    Facility::Local3,
    Facility::Local4,
    Facility::Local5,
    Facility::Local6,
    Facility::Local7,
];

/// Error returned when a numeric facility code is out of range (0-23).
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid facility code: {0} (must be 0-23)")]
pub struct InvalidFacility(pub u8);

/// Error returned when a facility name string is not recognized.
#[derive(Debug, Clone, thiserror::Error)]
#[error("unknown facility name: {0:?}")]
pub struct UnknownFacilityName(pub String);

impl Facility {
    /// Returns the numeric facility code (0-23).
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the RFC 5427 textual name for this facility.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kern => "kern",
            Self::User => "user",
            Self::Mail => "mail",
            Self::Daemon => "daemon",
            Self::Auth => "auth",
            Self::Syslog => "syslog",
            Self::Lpr => "lpr",
            Self::News => "news",
            Self::Uucp => "uucp",
            Self::Cron => "cron",
            Self::Authpriv => "authpriv",
            Self::Ftp => "ftp",
            Self::Ntp => "ntp",
            Self::Audit => "audit",
            Self::Alert => "alert",
            Self::Clock => "clock",
            Self::Local0 => "local0",
            Self::Local1 => "local1",
            Self::Local2 => "local2",
            Self::Local3 => "local3",
            Self::Local4 => "local4",
            Self::Local5 => "local5",
            Self::Local6 => "local6",
            Self::Local7 => "local7",
        }
    }

    /// Attempt to parse a facility from a case-insensitive name string.
    fn from_name(s: &str) -> Result<Self, UnknownFacilityName> {
        // Normalize to lowercase for case-insensitive matching
        let lower: String = s.to_ascii_lowercase();
        match lower.as_str() {
            "kern" | "kernel" => Ok(Self::Kern),
            "user" => Ok(Self::User),
            "mail" => Ok(Self::Mail),
            "daemon" => Ok(Self::Daemon),
            "auth" | "security" => Ok(Self::Auth),
            "syslog" => Ok(Self::Syslog),
            "lpr" => Ok(Self::Lpr),
            "news" => Ok(Self::News),
            "uucp" => Ok(Self::Uucp),
            "cron" => Ok(Self::Cron),
            "authpriv" => Ok(Self::Authpriv),
            "ftp" => Ok(Self::Ftp),
            "ntp" => Ok(Self::Ntp),
            "audit" => Ok(Self::Audit),
            "alert" => Ok(Self::Alert),
            "clock" => Ok(Self::Clock),
            "local0" => Ok(Self::Local0),
            "local1" => Ok(Self::Local1),
            "local2" => Ok(Self::Local2),
            "local3" => Ok(Self::Local3),
            "local4" => Ok(Self::Local4),
            "local5" => Ok(Self::Local5),
            "local6" => Ok(Self::Local6),
            "local7" => Ok(Self::Local7),
            _ => Err(UnknownFacilityName(s.to_owned())),
        }
    }
}

// RFC 5427 textual representation
impl fmt::Display for Facility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl TryFrom<u8> for Facility {
    type Error = InvalidFacility;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        ALL.get(value as usize)
            .copied()
            .ok_or(InvalidFacility(value))
    }
}

impl TryFrom<&str> for Facility {
    type Error = UnknownFacilityName;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_name(value)
    }
}

impl Serialize for Facility {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for Facility {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        Facility::from_name(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_facilities_have_correct_codes() {
        for (i, facility) in ALL.iter().enumerate() {
            assert_eq!(facility.code() as usize, i);
        }
    }

    #[test]
    fn try_from_u8_valid() {
        for code in 0u8..24 {
            let facility = Facility::try_from(code);
            assert!(facility.is_ok(), "code {code} should be valid");
            assert_eq!(facility.ok().map(|f| f.code()), Some(code));
        }
    }

    #[test]
    fn try_from_u8_invalid() {
        for code in 24u8..=255 {
            assert!(Facility::try_from(code).is_err());
        }
    }

    #[test]
    fn try_from_str_canonical() {
        for facility in &ALL {
            let parsed = Facility::try_from(facility.name());
            assert_eq!(parsed.ok(), Some(*facility));
        }
    }

    #[test]
    fn try_from_str_case_insensitive() {
        assert_eq!(Facility::try_from("KERN").ok(), Some(Facility::Kern));
        assert_eq!(Facility::try_from("Daemon").ok(), Some(Facility::Daemon));
        assert_eq!(Facility::try_from("LOCAL7").ok(), Some(Facility::Local7));
    }

    #[test]
    fn try_from_str_aliases() {
        assert_eq!(Facility::try_from("kernel").ok(), Some(Facility::Kern));
        assert_eq!(Facility::try_from("security").ok(), Some(Facility::Auth));
    }

    #[test]
    fn try_from_str_unknown() {
        assert!(Facility::try_from("bogus").is_err());
    }

    #[test]
    fn display_matches_name() {
        for facility in &ALL {
            assert_eq!(facility.to_string(), facility.name());
        }
    }

    #[test]
    fn serde_roundtrip() {
        for facility in &ALL {
            let json = serde_json::to_string(facility);
            assert!(json.is_ok());
            let json = json.ok().unwrap_or_default();
            let parsed: Result<Facility, _> = serde_json::from_str(&json);
            assert_eq!(parsed.ok(), Some(*facility));
        }
    }
}
