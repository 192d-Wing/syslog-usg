//! RFC 5424 message serializer — converts `SyslogMessage` to wire format.

use syslog_proto::{SyslogMessage, SyslogTimestamp};
use time::format_description::well_known::Rfc3339;
use tracing::warn;

/// Serialize an RFC 5424 `SyslogMessage` into its wire-format byte representation.
///
/// If the message has `raw` bytes, those are returned directly for lossless forwarding.
/// Otherwise, the message is reconstructed from its parsed fields.
pub fn serialize(msg: &SyslogMessage) -> Vec<u8> {
    // Lossless forwarding: prefer raw bytes if available
    if let Some(ref raw) = msg.raw {
        return raw.to_vec();
    }

    let mut buf = Vec::with_capacity(msg.estimated_size());

    // PRI
    buf.push(b'<');
    push_decimal(&mut buf, u32::from(msg.pri().value()));
    buf.push(b'>');

    // VERSION
    push_decimal(&mut buf, u32::from(msg.version));
    buf.push(b' ');

    // TIMESTAMP
    match &msg.timestamp {
        SyslogTimestamp::Nil => buf.push(b'-'),
        SyslogTimestamp::Value(dt) => {
            if let Ok(s) = dt.format(&Rfc3339) {
                buf.extend_from_slice(s.as_bytes());
            } else {
                // RFC 5424 §6.2.3: fall back to NILVALUE if formatting fails
                warn!("timestamp formatting failed, falling back to NILVALUE");
                buf.push(b'-');
            }
        }
    }
    buf.push(b' ');

    // HOSTNAME
    push_field(&mut buf, msg.hostname.as_deref());
    buf.push(b' ');

    // APP-NAME
    push_field(&mut buf, msg.app_name.as_deref());
    buf.push(b' ');

    // PROCID
    push_field(&mut buf, msg.proc_id.as_deref());
    buf.push(b' ');

    // MSGID
    push_field(&mut buf, msg.msg_id.as_deref());
    buf.push(b' ');

    // STRUCTURED-DATA
    if msg.structured_data.is_nil() {
        buf.push(b'-');
    } else {
        for el in msg.structured_data.iter() {
            buf.push(b'[');
            buf.extend_from_slice(el.id.as_str().as_bytes());
            for p in &el.params {
                buf.push(b' ');
                buf.extend_from_slice(p.name.as_bytes());
                buf.extend_from_slice(b"=\"");
                // Escape PARAM-VALUE per RFC 5424 §6.3.3
                for &b in p.value.as_bytes() {
                    match b {
                        b'"' => buf.extend_from_slice(b"\\\""),
                        b'\\' => buf.extend_from_slice(b"\\\\"),
                        b']' => buf.extend_from_slice(b"\\]"),
                        _ => buf.push(b),
                    }
                }
                buf.push(b'"');
            }
            buf.push(b']');
        }
    }

    // [SP MSG]
    if let Some(ref body) = msg.msg {
        buf.push(b' ');
        buf.extend_from_slice(body);
    }

    buf
}

/// Push a header field value, replacing any non-PRINTUSASCII bytes with `?`
/// to prevent newline injection and log smuggling.
///
/// RFC 5424 §6: header fields (HOSTNAME, APP-NAME, PROCID, MSGID) must
/// contain only PRINTUSASCII (%d33-126). The proto crate enforces this at
/// construction, but raw/programmatic construction could bypass it.
fn push_field(buf: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(s) => {
            for &b in s.as_bytes() {
                if (33..=126).contains(&b) {
                    buf.push(b);
                } else {
                    buf.push(b'?');
                }
            }
        }
        None => buf.push(b'-'),
    }
}

fn push_decimal(buf: &mut Vec<u8>, value: u32) {
    if value == 0 {
        buf.push(b'0');
        return;
    }
    let mut digits = [0u8; 10];
    let mut i = 0;
    let mut v = value;
    while v > 0 {
        if let Some(slot) = digits.get_mut(i) {
            *slot = (v % 10) as u8 + b'0';
        }
        v /= 10;
        i += 1;
    }
    // Reverse the digits into buf
    for j in (0..i).rev() {
        if let Some(&d) = digits.get(j) {
            buf.push(d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use compact_str::CompactString;
    use syslog_proto::{Facility, Severity, StructuredData};

    #[test]
    fn serialize_minimal() {
        let msg = SyslogMessage {
            facility: Facility::Kern,
            severity: Severity::Emergency,
            version: 1,
            timestamp: SyslogTimestamp::Nil,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            structured_data: StructuredData::nil(),
            msg: None,
            raw: None,
        };
        let output = serialize(&msg);
        assert_eq!(output, b"<0>1 - - - - - -");
    }

    #[test]
    fn serialize_with_body() {
        let msg = SyslogMessage {
            facility: Facility::User,
            severity: Severity::Notice,
            version: 1,
            timestamp: SyslogTimestamp::Nil,
            hostname: Some(CompactString::new("myhost")),
            app_name: Some(CompactString::new("myapp")),
            proc_id: Some(CompactString::new("1234")),
            msg_id: Some(CompactString::new("ID47")),
            structured_data: StructuredData::nil(),
            msg: Some(Bytes::from_static(b"hello world")),
            raw: None,
        };
        let output = serialize(&msg);
        let s = String::from_utf8_lossy(&output);
        assert!(s.starts_with("<13>1 "));
        assert!(s.contains("myhost"));
        assert!(s.ends_with("hello world"));
    }

    #[test]
    fn serialize_uses_raw_when_available() {
        let raw = Bytes::from_static(b"<34>1 raw message");
        let msg = SyslogMessage {
            facility: Facility::Auth,
            severity: Severity::Critical,
            version: 1,
            timestamp: SyslogTimestamp::Nil,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            structured_data: StructuredData::nil(),
            msg: None,
            raw: Some(raw.clone()),
        };
        let output = serialize(&msg);
        assert_eq!(output, raw.as_ref());
    }

    #[test]
    fn push_decimal_values() {
        let mut buf = Vec::new();
        push_decimal(&mut buf, 0);
        assert_eq!(buf, b"0");

        buf.clear();
        push_decimal(&mut buf, 191);
        assert_eq!(buf, b"191");

        buf.clear();
        push_decimal(&mut buf, 1);
        assert_eq!(buf, b"1");
    }
}
