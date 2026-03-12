#![doc = "Syslog message parser and serializer for RFC 5424 and RFC 3164.\n\nThis crate provides parsers for both the structured RFC 5424 format and the\nlegacy BSD syslog (RFC 3164) format, plus a serializer that produces valid\nRFC 5424 wire-format output."]

pub mod detect;
pub mod error;
pub mod octet_counting;
pub mod parse_mode;
pub mod rfc3164;
pub mod rfc5424;

pub use error::ParseError;
pub use parse_mode::ParseMode;

use syslog_proto::SyslogMessage;

/// Auto-detect the syslog format (RFC 5424 vs RFC 3164) and parse the message.
///
/// After parsing the PRI field, this function inspects the version indicator
/// to determine the format. If the byte following the PRI is `1` followed by
/// a space, the message is parsed as RFC 5424; otherwise it is treated as
/// RFC 3164 (BSD syslog) with best-effort extraction.
///
/// # Errors
/// Returns `ParseError` if the message cannot be parsed.
pub fn parse(input: &[u8]) -> Result<SyslogMessage, ParseError> {
    detect::parse_auto(input)
}

/// Parse a message strictly as RFC 5424.
///
/// Unlike [`parse`], this function does not fall back to RFC 3164 parsing.
/// The input must be a valid RFC 5424 message or an error is returned.
///
/// # Errors
/// Returns `ParseError` if the message does not conform to RFC 5424.
pub fn parse_strict(input: &[u8]) -> Result<SyslogMessage, ParseError> {
    rfc5424::parser::parse(input)
}
