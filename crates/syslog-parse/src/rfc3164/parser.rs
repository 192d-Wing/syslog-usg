//! RFC 3164 (BSD syslog) best-effort parser.
//!
//! BSD syslog is loosely specified. This parser attempts to extract:
//!   <PRI>TIMESTAMP HOSTNAME APP-NAME[PID]: MSG
//!
//! Falls back gracefully when fields are missing or malformed.

use bytes::Bytes;
use compact_str::CompactString;
use syslog_proto::{StructuredData, SyslogMessage, SyslogTimestamp};

use crate::error::ParseError;
use crate::rfc5424::header::parse_pri;

/// Parse a BSD syslog (RFC 3164) message with best-effort extraction.
///
/// This parser is intentionally lenient. If it cannot parse the timestamp
/// or other fields, they are set to nil/None rather than returning an error.
pub fn parse(input: &[u8]) -> Result<SyslogMessage, ParseError> {
    let mut pos = 0;

    let pri = parse_pri(input, &mut pos)?;

    // Everything after PRI is the "content" — try to extract BSD fields
    let content = input.get(pos..).unwrap_or_default();
    let content_str = core::str::from_utf8(content).unwrap_or_default();

    // Attempt to parse BSD timestamp: "Mmm dd HH:MM:SS "
    let (timestamp, rest) = parse_bsd_timestamp(content_str);

    // After timestamp: HOSTNAME SP TAG: MSG
    let (hostname, app_name, proc_id, body) = parse_bsd_header(rest);

    let msg = if body.is_empty() {
        None
    } else {
        Some(Bytes::copy_from_slice(body.as_bytes()))
    };

    Ok(SyslogMessage {
        facility: pri.facility(),
        severity: pri.severity(),
        version: 0, // BSD syslog has no version field
        timestamp,
        hostname: if hostname.is_empty() {
            None
        } else {
            Some(CompactString::new(hostname))
        },
        app_name: if app_name.is_empty() {
            None
        } else {
            Some(CompactString::new(app_name))
        },
        proc_id: if proc_id.is_empty() {
            None
        } else {
            Some(CompactString::new(proc_id))
        },
        msg_id: None,
        structured_data: StructuredData::nil(),
        msg,
        raw: Some(Bytes::copy_from_slice(input)),
    })
}

/// Attempt to parse a BSD timestamp from the start of `s`.
///
/// Returns (timestamp, remaining_str).
fn parse_bsd_timestamp(s: &str) -> (SyslogTimestamp, &str) {
    // BSD timestamp: "Mmm dd HH:MM:SS " = 16 chars (including trailing space)
    if s.len() < 16 {
        return (SyslogTimestamp::Nil, s);
    }

    let month_part = s.get(..3).unwrap_or_default();
    if crate::rfc3164::heuristics::parse_bsd_month(month_part).is_none() {
        return (SyslogTimestamp::Nil, s);
    }

    // We found what looks like a BSD timestamp. We can't construct a full
    // OffsetDateTime without a year, so we store it as Nil for now.
    // A production system would use the current year as a heuristic.
    let rest = s.get(16..).unwrap_or(s.get(15..).unwrap_or(s));

    (SyslogTimestamp::Nil, rest)
}

/// Parse the BSD header after the timestamp: HOSTNAME TAG[PID]: MSG
///
/// Returns (hostname, app_name, proc_id, message_body).
fn parse_bsd_header(s: &str) -> (&str, &str, &str, &str) {
    // Split on first space to get hostname
    let (hostname, rest) = match s.find(' ') {
        Some(i) => (
            s.get(..i).unwrap_or_default(),
            s.get(i.saturating_add(1)..).unwrap_or_default(),
        ),
        None => return (s, "", "", ""),
    };

    // The rest is TAG[PID]: MSG or TAG: MSG
    let (tag_part, body) = match rest.find(": ") {
        Some(i) => (
            rest.get(..i).unwrap_or_default(),
            rest.get(i.saturating_add(2)..).unwrap_or_default(),
        ),
        None => (rest, ""),
    };

    // Extract PID from TAG[PID]
    let (app_name, proc_id) = match (tag_part.find('['), tag_part.find(']')) {
        (Some(open), Some(close)) if close > open => (
            tag_part.get(..open).unwrap_or_default(),
            tag_part
                .get(open.saturating_add(1)..close)
                .unwrap_or_default(),
        ),
        _ => (tag_part, ""),
    };

    (hostname, app_name, proc_id, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use syslog_proto::{Facility, Severity};

    #[test]
    fn parse_basic_bsd() {
        let input = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed";
        let result = parse(input);
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
        if let Ok(msg) = result {
            assert_eq!(msg.facility, Facility::Auth);
            assert_eq!(msg.severity, Severity::Critical);
            assert_eq!(msg.hostname.as_deref(), Some("mymachine"));
            assert_eq!(msg.app_name.as_deref(), Some("su"));
        }
    }

    #[test]
    fn parse_bsd_with_pid() {
        let input = b"<13>Oct 11 22:14:15 myhost sshd[1234]: Accepted publickey";
        let result = parse(input);
        assert!(result.is_ok());
        if let Ok(msg) = result {
            assert_eq!(msg.app_name.as_deref(), Some("sshd"));
            assert_eq!(msg.proc_id.as_deref(), Some("1234"));
        }
    }

    #[test]
    fn parse_bsd_minimal() {
        let input = b"<0>just a message";
        let result = parse(input);
        assert!(result.is_ok());
    }
}
