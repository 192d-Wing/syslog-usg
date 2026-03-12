//! Message filtering based on severity threshold.
//!
//! A [`SeverityFilter`] passes messages whose severity is at least as urgent
//! as a configurable threshold level.

use syslog_proto::{Severity, SyslogMessage};

/// A filter that passes messages with severity >= the configured threshold.
///
/// Because syslog severity ordering has `Emergency` as the *greatest* value
/// (most urgent), a threshold of `Warning` will pass `Emergency`, `Alert`,
/// `Critical`, `Error`, and `Warning`, while dropping `Notice`, `Informational`,
/// and `Debug`.
#[derive(Debug, Clone)]
pub struct SeverityFilter {
    /// Minimum severity level (inclusive). Messages at least this urgent pass.
    threshold: Severity,
}

impl SeverityFilter {
    /// Create a new severity filter with the given threshold.
    ///
    /// Messages whose severity is >= `threshold` (i.e., at least as urgent)
    /// will pass the filter.
    #[must_use]
    pub fn new(threshold: Severity) -> Self {
        Self { threshold }
    }

    /// Returns the current threshold severity.
    #[must_use]
    pub fn threshold(&self) -> Severity {
        self.threshold
    }

    /// Returns `true` if the message should be forwarded (passes the filter).
    #[must_use]
    pub fn should_pass(&self, message: &SyslogMessage) -> bool {
        message.severity.is_at_least(self.threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use compact_str::CompactString;
    use syslog_proto::{Facility, StructuredData, SyslogTimestamp};

    fn make_message(severity: Severity) -> SyslogMessage {
        SyslogMessage {
            facility: Facility::User,
            severity,
            version: 1,
            timestamp: SyslogTimestamp::Nil,
            hostname: Some(CompactString::new("testhost")),
            app_name: Some(CompactString::new("testapp")),
            proc_id: None,
            msg_id: None,
            structured_data: StructuredData::nil(),
            msg: Some(Bytes::from_static(b"test message")),
            raw: None,
        }
    }

    #[test]
    fn passes_messages_at_threshold() {
        let filter = SeverityFilter::new(Severity::Warning);
        let msg = make_message(Severity::Warning);
        assert!(filter.should_pass(&msg));
    }

    #[test]
    fn passes_messages_above_threshold() {
        let filter = SeverityFilter::new(Severity::Warning);
        // Emergency, Alert, Critical, Error are all more urgent than Warning
        assert!(filter.should_pass(&make_message(Severity::Emergency)));
        assert!(filter.should_pass(&make_message(Severity::Alert)));
        assert!(filter.should_pass(&make_message(Severity::Critical)));
        assert!(filter.should_pass(&make_message(Severity::Error)));
    }

    #[test]
    fn drops_messages_below_threshold() {
        let filter = SeverityFilter::new(Severity::Warning);
        // Notice, Informational, Debug are less urgent than Warning
        assert!(!filter.should_pass(&make_message(Severity::Notice)));
        assert!(!filter.should_pass(&make_message(Severity::Informational)));
        assert!(!filter.should_pass(&make_message(Severity::Debug)));
    }

    #[test]
    fn debug_threshold_passes_everything() {
        let filter = SeverityFilter::new(Severity::Debug);
        assert!(filter.should_pass(&make_message(Severity::Emergency)));
        assert!(filter.should_pass(&make_message(Severity::Alert)));
        assert!(filter.should_pass(&make_message(Severity::Critical)));
        assert!(filter.should_pass(&make_message(Severity::Error)));
        assert!(filter.should_pass(&make_message(Severity::Warning)));
        assert!(filter.should_pass(&make_message(Severity::Notice)));
        assert!(filter.should_pass(&make_message(Severity::Informational)));
        assert!(filter.should_pass(&make_message(Severity::Debug)));
    }

    #[test]
    fn emergency_threshold_passes_only_emergency() {
        let filter = SeverityFilter::new(Severity::Emergency);
        assert!(filter.should_pass(&make_message(Severity::Emergency)));
        assert!(!filter.should_pass(&make_message(Severity::Alert)));
        assert!(!filter.should_pass(&make_message(Severity::Critical)));
        assert!(!filter.should_pass(&make_message(Severity::Debug)));
    }

    #[test]
    fn threshold_accessor() {
        let filter = SeverityFilter::new(Severity::Error);
        assert_eq!(filter.threshold(), Severity::Error);
    }
}
