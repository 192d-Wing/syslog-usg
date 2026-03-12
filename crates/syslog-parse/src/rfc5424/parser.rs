//! Full RFC 5424 message parser.
//!
//! SYSLOG-MSG = HEADER SP STRUCTURED-DATA [SP MSG]
//! HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID

use bytes::Bytes;
use syslog_proto::SyslogMessage;

use crate::error::ParseError;
use crate::rfc5424::header::{expect_sp, parse_field, parse_pri, parse_timestamp, parse_version};
use crate::rfc5424::msg::parse_msg;
use crate::rfc5424::structured_data::parse_structured_data;

/// Parse a complete RFC 5424 syslog message from raw bytes.
///
/// # Errors
/// Returns `ParseError` if the input does not conform to RFC 5424.
pub fn parse(input: &[u8]) -> Result<SyslogMessage, ParseError> {
    let mut pos = 0;

    // HEADER
    let pri = parse_pri(input, &mut pos)?;
    let version = parse_version(input, &mut pos)?;
    expect_sp(input, &mut pos, "after VERSION")?;

    let timestamp = parse_timestamp(input, &mut pos)?;
    expect_sp(input, &mut pos, "after TIMESTAMP")?;

    let hostname = parse_field(input, &mut pos, "HOSTNAME", 255)?;
    expect_sp(input, &mut pos, "after HOSTNAME")?;

    let app_name = parse_field(input, &mut pos, "APP-NAME", 48)?;
    expect_sp(input, &mut pos, "after APP-NAME")?;

    let proc_id = parse_field(input, &mut pos, "PROCID", 128)?;
    expect_sp(input, &mut pos, "after PROCID")?;

    let msg_id = parse_field(input, &mut pos, "MSGID", 32)?;
    expect_sp(input, &mut pos, "after MSGID")?;

    // STRUCTURED-DATA
    let structured_data = parse_structured_data(input, &mut pos)?;

    // [SP MSG]
    let msg = if input.get(pos).copied() == Some(b' ') {
        pos = pos.checked_add(1).ok_or(ParseError::UnexpectedEndOfInput {
            context: "MSG separator",
        })?;
        parse_msg(input, pos)
    } else {
        None
    };

    Ok(SyslogMessage {
        facility: pri.facility(),
        severity: pri.severity(),
        version,
        timestamp,
        hostname,
        app_name,
        proc_id,
        msg_id,
        structured_data,
        msg,
        raw: Some(Bytes::copy_from_slice(input)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use syslog_proto::{Facility, Severity};

    #[test]
    fn rfc5424_example1() {
        let input = b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8";
        let result = parse(input);
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
        if let Ok(msg) = result {
            assert_eq!(msg.facility, Facility::Auth);
            assert_eq!(msg.severity, Severity::Critical);
            assert_eq!(msg.version, 1);
            assert_eq!(msg.hostname.as_deref(), Some("mymachine.example.com"));
            assert_eq!(msg.app_name.as_deref(), Some("su"));
            assert!(msg.proc_id.is_none());
            assert_eq!(msg.msg_id.as_deref(), Some("ID47"));
            assert!(msg.structured_data.is_nil());
        }
    }

    #[test]
    fn rfc5424_example3() {
        let input = b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] BOMAn application event log entry...";
        let result = parse(input);
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
        if let Ok(msg) = result {
            assert_eq!(msg.facility, Facility::Local4);
            assert_eq!(msg.severity, Severity::Notice);
            assert!(!msg.structured_data.is_nil());
            assert!(
                msg.structured_data
                    .find_by_id("exampleSDID@32473")
                    .is_some()
            );
        }
    }

    #[test]
    fn minimal_message() {
        let input = b"<0>1 - - - - - -";
        let result = parse(input);
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
        if let Ok(msg) = result {
            assert_eq!(msg.facility, Facility::Kern);
            assert_eq!(msg.severity, Severity::Emergency);
            assert!(msg.hostname.is_none());
            assert!(msg.app_name.is_none());
            assert!(msg.proc_id.is_none());
            assert!(msg.msg_id.is_none());
            assert!(msg.structured_data.is_nil());
            assert!(msg.msg.is_none());
        }
    }

    #[test]
    fn with_message_body() {
        let input = b"<13>1 - - - - - - hello world";
        let result = parse(input);
        assert!(result.is_ok());
        if let Ok(msg) = result {
            assert!(msg.msg.is_some());
            if let Some(body) = &msg.msg {
                assert_eq!(&body[..], b"hello world");
            }
        }
    }
}
