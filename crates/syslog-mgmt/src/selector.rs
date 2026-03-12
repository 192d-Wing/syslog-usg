//! Message selector for the syslog management model.
//!
//! A [`Selector`] defines which syslog messages match based on facility,
//! severity range, hostname pattern, and application name pattern.

use crate::error::MgmtError;
use crate::pattern::Pattern;
use syslog_proto::{Facility, Severity, SyslogMessage};

/// Selects syslog messages based on configurable criteria.
///
/// An empty selector (created with [`Selector::new`]) matches all messages.
/// Each configured field narrows the set of matching messages.
#[derive(Debug)]
pub struct Selector {
    /// If set, only messages from these facilities match.
    pub facilities: Option<Vec<Facility>>,
    /// If set, only messages with severity >= this value match.
    /// (Remember: Emergency > Alert > ... > Debug in the Ord impl.)
    pub min_severity: Option<Severity>,
    /// If set, only messages with severity <= this value match.
    pub max_severity: Option<Severity>,
    /// If set, compiled regex pattern for hostname matching.
    hostname_pattern: Option<Pattern>,
    /// If set, compiled regex pattern for app_name matching.
    app_name_pattern: Option<Pattern>,
}

impl Selector {
    /// Create a new selector that matches all messages.
    #[must_use]
    pub fn new() -> Self {
        Self {
            facilities: None,
            min_severity: None,
            max_severity: None,
            hostname_pattern: None,
            app_name_pattern: None,
        }
    }

    /// Set the hostname pattern for this selector.
    ///
    /// # Errors
    ///
    /// Returns [`MgmtError::InvalidPattern`] if the regex is invalid.
    pub fn with_hostname_pattern(mut self, pattern: &str) -> Result<Self, MgmtError> {
        let compiled = Pattern::new(pattern)
            .map_err(|e| MgmtError::InvalidPattern(format!("hostname pattern: {e}")))?;
        self.hostname_pattern = Some(compiled);
        Ok(self)
    }

    /// Set the app_name pattern for this selector.
    ///
    /// # Errors
    ///
    /// Returns [`MgmtError::InvalidPattern`] if the regex is invalid.
    pub fn with_app_name_pattern(mut self, pattern: &str) -> Result<Self, MgmtError> {
        let compiled = Pattern::new(pattern)
            .map_err(|e| MgmtError::InvalidPattern(format!("app_name pattern: {e}")))?;
        self.app_name_pattern = Some(compiled);
        Ok(self)
    }

    /// Set the facility filter for this selector.
    #[must_use]
    pub fn with_facilities(mut self, facilities: Vec<Facility>) -> Self {
        self.facilities = Some(facilities);
        self
    }

    /// Set the minimum severity (most urgent bound) for this selector.
    #[must_use]
    pub fn with_min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    /// Set the maximum severity (least urgent bound) for this selector.
    #[must_use]
    pub fn with_max_severity(mut self, severity: Severity) -> Self {
        self.max_severity = Some(severity);
        self
    }

    /// Returns `true` if the given message matches this selector.
    ///
    /// All configured criteria must match (AND logic). An unconfigured
    /// criterion always matches.
    #[must_use]
    pub fn matches(&self, msg: &SyslogMessage) -> bool {
        // Check facility filter
        if let Some(ref facilities) = self.facilities {
            if !facilities.contains(&msg.facility) {
                return false;
            }
        }

        // Check min severity (message must be at least this urgent)
        // Severity Ord: Emergency > Alert > ... > Debug
        if let Some(min) = self.min_severity {
            if msg.severity < min {
                return false;
            }
        }

        // Check max severity (message must be at most this urgent)
        if let Some(max) = self.max_severity {
            if msg.severity > max {
                return false;
            }
        }

        // Check hostname pattern
        if let Some(ref pattern) = self.hostname_pattern {
            match &msg.hostname {
                Some(hostname) => {
                    if !pattern.matches(hostname.as_str()) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Check app_name pattern
        if let Some(ref pattern) = self.app_name_pattern {
            match &msg.app_name {
                Some(app_name) => {
                    if !pattern.matches(app_name.as_str()) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }
}

impl Default for Selector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use compact_str::CompactString;
    use syslog_proto::{StructuredData, SyslogTimestamp};

    fn sample_msg() -> SyslogMessage {
        SyslogMessage {
            facility: Facility::User,
            severity: Severity::Warning,
            version: 1,
            timestamp: SyslogTimestamp::Nil,
            hostname: Some(CompactString::new("webserver01")),
            app_name: Some(CompactString::new("nginx")),
            proc_id: Some(CompactString::new("1234")),
            msg_id: None,
            structured_data: StructuredData::nil(),
            msg: Some(Bytes::from_static(b"test message")),
            raw: None,
        }
    }

    #[test]
    fn empty_selector_matches_all() {
        let sel = Selector::new();
        let msg = sample_msg();
        assert!(sel.matches(&msg));
    }

    #[test]
    fn default_selector_matches_all() {
        let sel = Selector::default();
        let msg = sample_msg();
        assert!(sel.matches(&msg));
    }

    #[test]
    fn facility_filter_matches() {
        let sel = Selector::new().with_facilities(vec![Facility::User, Facility::Daemon]);
        let msg = sample_msg();
        assert!(sel.matches(&msg));
    }

    #[test]
    fn facility_filter_rejects() {
        let sel = Selector::new().with_facilities(vec![Facility::Kern, Facility::Mail]);
        let msg = sample_msg();
        assert!(!sel.matches(&msg));
    }

    #[test]
    fn min_severity_matches() {
        // Warning is at least Warning
        let sel = Selector::new().with_min_severity(Severity::Warning);
        let msg = sample_msg();
        assert!(sel.matches(&msg));
    }

    #[test]
    fn min_severity_rejects_less_urgent() {
        // Warning < Error in urgency, so min_severity=Error rejects Warning
        let sel = Selector::new().with_min_severity(Severity::Error);
        let msg = sample_msg(); // severity = Warning
        assert!(!sel.matches(&msg));
    }

    #[test]
    fn max_severity_matches() {
        // Warning <= Emergency (max urgency)
        let sel = Selector::new().with_max_severity(Severity::Emergency);
        let msg = sample_msg();
        assert!(sel.matches(&msg));
    }

    #[test]
    fn max_severity_rejects_more_urgent() {
        // max_severity=Notice means only Notice and less urgent (Info, Debug)
        // Warning is more urgent than Notice, so it should be rejected
        let sel = Selector::new().with_max_severity(Severity::Notice);
        let msg = sample_msg(); // severity = Warning (more urgent than Notice)
        assert!(!sel.matches(&msg));
    }

    #[test]
    fn severity_range_matches() {
        // Error >= Warning >= Notice => Warning in [Notice, Error]
        let sel = Selector::new()
            .with_max_severity(Severity::Error)
            .with_min_severity(Severity::Notice);
        let msg = sample_msg(); // Warning
        assert!(sel.matches(&msg));
    }

    #[test]
    fn hostname_pattern_matches() {
        let sel = match Selector::new().with_hostname_pattern(r"^web") {
            Ok(s) => s,
            Err(_) => return,
        };
        let msg = sample_msg();
        assert!(sel.matches(&msg));
    }

    #[test]
    fn hostname_pattern_rejects() {
        let sel = match Selector::new().with_hostname_pattern(r"^db") {
            Ok(s) => s,
            Err(_) => return,
        };
        let msg = sample_msg();
        assert!(!sel.matches(&msg));
    }

    #[test]
    fn hostname_pattern_rejects_nil_hostname() {
        let sel = match Selector::new().with_hostname_pattern(r".*") {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut msg = sample_msg();
        msg.hostname = None;
        assert!(!sel.matches(&msg));
    }

    #[test]
    fn app_name_pattern_matches() {
        let sel = match Selector::new().with_app_name_pattern(r"nginx") {
            Ok(s) => s,
            Err(_) => return,
        };
        let msg = sample_msg();
        assert!(sel.matches(&msg));
    }

    #[test]
    fn app_name_pattern_rejects() {
        let sel = match Selector::new().with_app_name_pattern(r"^apache$") {
            Ok(s) => s,
            Err(_) => return,
        };
        let msg = sample_msg();
        assert!(!sel.matches(&msg));
    }

    #[test]
    fn app_name_pattern_rejects_nil_app_name() {
        let sel = match Selector::new().with_app_name_pattern(r".*") {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut msg = sample_msg();
        msg.app_name = None;
        assert!(!sel.matches(&msg));
    }

    #[test]
    fn combined_selector_all_match() {
        let sel = Selector::new()
            .with_facilities(vec![Facility::User])
            .with_min_severity(Severity::Warning);
        let sel = match sel.with_hostname_pattern(r"web") {
            Ok(s) => s,
            Err(_) => return,
        };
        let sel = match sel.with_app_name_pattern(r"nginx") {
            Ok(s) => s,
            Err(_) => return,
        };
        let msg = sample_msg();
        assert!(sel.matches(&msg));
    }

    #[test]
    fn combined_selector_one_fails() {
        // Facility matches, severity matches, but hostname doesn't
        let sel = Selector::new()
            .with_facilities(vec![Facility::User])
            .with_min_severity(Severity::Warning);
        let sel = match sel.with_hostname_pattern(r"^db") {
            Ok(s) => s,
            Err(_) => return,
        };
        let msg = sample_msg();
        assert!(!sel.matches(&msg));
    }

    #[test]
    fn invalid_hostname_pattern_returns_error() {
        let result = Selector::new().with_hostname_pattern("[bad");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_app_name_pattern_returns_error() {
        let result = Selector::new().with_app_name_pattern("[bad");
        assert!(result.is_err());
    }
}
