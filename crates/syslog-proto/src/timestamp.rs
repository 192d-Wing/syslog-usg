// RFC 5424 §6.2.3 — TIMESTAMP field
// Either a valid timestamp or NILVALUE "-"

use core::fmt;
use serde::{Deserialize, Serialize};

/// A syslog timestamp, which may be a concrete date-time or the NILVALUE "-".
///
/// RFC 5424 §6.2.3: TIMESTAMP = NILVALUE / FULL-DATE "T" FULL-TIME
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyslogTimestamp {
    /// A concrete timestamp value.
    Value(#[serde(with = "time::serde::rfc3339")] time::OffsetDateTime),
    /// The NILVALUE "-", indicating the timestamp is unknown.
    Nil,
}

impl fmt::Display for SyslogTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(dt) => {
                // RFC 3339 format
                let formatted = dt.format(&time::format_description::well_known::Rfc3339);
                match formatted {
                    Ok(s) => f.write_str(&s),
                    Err(_) => f.write_str("-"),
                }
            }
            Self::Nil => f.write_str("-"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn nil_displays_as_dash() {
        assert_eq!(SyslogTimestamp::Nil.to_string(), "-");
    }

    #[test]
    fn value_displays_rfc3339() {
        let ts = SyslogTimestamp::Value(OffsetDateTime::UNIX_EPOCH);
        let display = ts.to_string();
        assert!(display.contains("1970"));
        assert!(display.contains("T"));
    }

    #[test]
    fn equality() {
        assert_eq!(SyslogTimestamp::Nil, SyslogTimestamp::Nil);
        let epoch = SyslogTimestamp::Value(OffsetDateTime::UNIX_EPOCH);
        assert_eq!(epoch, epoch.clone());
        assert_ne!(
            SyslogTimestamp::Nil,
            SyslogTimestamp::Value(OffsetDateTime::UNIX_EPOCH)
        );
    }

    #[test]
    fn serde_roundtrip_nil() {
        let json = serde_json::to_string(&SyslogTimestamp::Nil);
        assert!(json.is_ok());
        let json = json.ok().unwrap_or_default();
        let parsed: Result<SyslogTimestamp, _> = serde_json::from_str(&json);
        assert_eq!(parsed.ok(), Some(SyslogTimestamp::Nil));
    }

    #[test]
    fn serde_roundtrip_value() {
        let ts = SyslogTimestamp::Value(OffsetDateTime::UNIX_EPOCH);
        let json = serde_json::to_string(&ts);
        assert!(json.is_ok());
        let json = json.ok().unwrap_or_default();
        let parsed: Result<SyslogTimestamp, _> = serde_json::from_str(&json);
        assert_eq!(parsed.ok(), Some(ts));
    }
}
