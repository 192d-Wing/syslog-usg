// RFC 5424 §6 — The canonical syslog message representation

use bytes::Bytes;
use compact_str::CompactString;
use serde::{Deserialize, Serialize};

use crate::facility::Facility;
use crate::pri::Pri;
use crate::severity::Severity;
use crate::structured_data::StructuredData;
use crate::timestamp::SyslogTimestamp;

/// The canonical in-memory representation of an RFC 5424 syslog message.
///
/// All header fields are decoded and validated. The `raw` field optionally
/// retains the original wire bytes for lossless relay forwarding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogMessage {
    /// The facility that generated this message (RFC 5424 §6.2.1).
    pub facility: Facility,
    /// The severity of this message (RFC 5424 §6.2.1).
    pub severity: Severity,
    /// Protocol version (RFC 5424 §6.2.2). Currently always 1.
    pub version: u8,
    /// Timestamp (RFC 5424 §6.2.3).
    pub timestamp: SyslogTimestamp,
    /// Hostname (RFC 5424 §6.2.4). `None` represents NILVALUE.
    pub hostname: Option<CompactString>,
    /// Application name (RFC 5424 §6.2.5). `None` represents NILVALUE.
    pub app_name: Option<CompactString>,
    /// Process ID (RFC 5424 §6.2.6). `None` represents NILVALUE.
    pub proc_id: Option<CompactString>,
    /// Message ID (RFC 5424 §6.2.7). `None` represents NILVALUE.
    pub msg_id: Option<CompactString>,
    /// Structured data (RFC 5424 §6.3).
    pub structured_data: StructuredData,
    /// The free-form message body (RFC 5424 §6.4). `None` if absent.
    #[serde(
        serialize_with = "serialize_optional_bytes",
        deserialize_with = "deserialize_optional_bytes"
    )]
    pub msg: Option<Bytes>,
    /// The original raw bytes as received on the wire, for lossless forwarding.
    #[serde(skip)]
    pub raw: Option<Bytes>,
}

fn serialize_optional_bytes<S: serde::Serializer>(
    value: &Option<Bytes>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(b) => {
            let s = String::from_utf8_lossy(b);
            serializer.serialize_some(s.as_ref())
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_bytes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Bytes>, D::Error> {
    let opt: Option<String> = Option::deserialize(deserializer)?;
    Ok(opt.map(|s| Bytes::from(s.into_bytes())))
}

impl SyslogMessage {
    /// Compute the PRI value from this message's facility and severity.
    ///
    /// RFC 5424 §6.2.1: PRI = Facility * 8 + Severity
    #[must_use]
    pub fn pri(&self) -> Pri {
        Pri::new(self.facility, self.severity)
    }

    /// Estimate the total byte size of this message for queue accounting.
    ///
    /// Uses the raw bytes if available, otherwise sums up field sizes.
    #[must_use]
    pub fn estimated_size(&self) -> usize {
        if let Some(ref raw) = self.raw {
            return raw.len();
        }

        let mut size = 0usize;
        // PRI + version + spaces/delimiters (rough overhead)
        size += 8;
        // Timestamp
        size += match &self.timestamp {
            SyslogTimestamp::Nil => 1,
            SyslogTimestamp::Value(_) => 32, // RFC 3339 is roughly 25-32 chars
        };
        // Header fields
        size += self.hostname.as_ref().map_or(1, |s| s.len());
        size += self.app_name.as_ref().map_or(1, |s| s.len());
        size += self.proc_id.as_ref().map_or(1, |s| s.len());
        size += self.msg_id.as_ref().map_or(1, |s| s.len());
        // Structured data
        size += self.structured_data.estimated_size();
        // Message body
        size += self.msg.as_ref().map_or(0, |b| b.len());

        size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn sample_message() -> SyslogMessage {
        SyslogMessage {
            facility: Facility::User,
            severity: Severity::Notice,
            version: 1,
            timestamp: SyslogTimestamp::Value(OffsetDateTime::UNIX_EPOCH),
            hostname: Some(CompactString::new("myhost")),
            app_name: Some(CompactString::new("myapp")),
            proc_id: Some(CompactString::new("1234")),
            msg_id: Some(CompactString::new("ID47")),
            structured_data: StructuredData::nil(),
            msg: Some(Bytes::from_static(b"hello world")),
            raw: None,
        }
    }

    #[test]
    fn pri_computation() {
        let msg = sample_message();
        let pri = msg.pri();
        assert_eq!(pri.facility(), Facility::User);
        assert_eq!(pri.severity(), Severity::Notice);
        // User(1) * 8 + Notice(5) = 13
        assert_eq!(pri.value(), 13);
    }

    #[test]
    fn estimated_size_without_raw() {
        let msg = sample_message();
        let size = msg.estimated_size();
        // Should be a reasonable positive number
        assert!(size > 0);
    }

    #[test]
    fn estimated_size_with_raw() {
        let mut msg = sample_message();
        msg.raw = Some(Bytes::from_static(
            b"<13>1 2003-10-11T22:14:15.003Z myhost myapp 1234 ID47 - hello world",
        ));
        let raw_len = msg.raw.as_ref().map_or(0, |b| b.len());
        let size = msg.estimated_size();
        assert_eq!(size, raw_len);
    }

    #[test]
    fn estimated_size_nil_fields() {
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
        let size = msg.estimated_size();
        assert!(size > 0);
    }

    #[test]
    fn serde_roundtrip() {
        let msg = sample_message();
        let json = serde_json::to_string(&msg);
        assert!(json.is_ok());
        let json = json.ok().unwrap_or_default();
        let parsed: Result<SyslogMessage, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok());
        if let Ok(parsed) = parsed {
            assert_eq!(parsed.facility, msg.facility);
            assert_eq!(parsed.severity, msg.severity);
            assert_eq!(parsed.version, msg.version);
            assert_eq!(parsed.hostname, msg.hostname);
            assert_eq!(parsed.app_name, msg.app_name);
            // raw is skipped in serde
            assert!(parsed.raw.is_none());
        }
    }
}
