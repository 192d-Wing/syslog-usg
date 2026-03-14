//! Alarm-aware message filtering (RFC 5674).
//!
//! [`AlarmFilter`] inspects the structured data of syslog messages for
//! RFC 5674 alarm SD elements and applies configurable criteria to decide
//! whether a message should pass through the pipeline.

use syslog_proto::{Alarm, ItuEventType, PerceivedSeverity, SyslogMessage};

use crate::filter::MessageFilter;

/// Policy for handling messages that do not contain an alarm SD element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonAlarmPolicy {
    /// Non-alarm messages pass through the filter.
    Pass,
    /// Non-alarm messages are dropped.
    Drop,
}

/// A filter that examines RFC 5674 alarm structured data elements.
///
/// Criteria are combined with AND logic: a message must satisfy *all*
/// configured criteria to pass. If no criteria are configured the filter
/// passes all alarm messages (subject to `non_alarm_policy`).
#[derive(Debug)]
pub struct AlarmFilter {
    /// Minimum perceived severity (inclusive). `None` means no threshold.
    min_severity: Option<PerceivedSeverity>,
    /// Allowed ITU event types. Empty means all types are accepted.
    event_types: Vec<ItuEventType>,
    /// Resource substring patterns. Empty means all resources are accepted.
    resource_patterns: Vec<String>,
    /// What to do with messages that have no alarm SD element.
    non_alarm_policy: NonAlarmPolicy,
}

impl AlarmFilter {
    /// Create a new `AlarmFilter` builder.
    #[must_use]
    pub fn builder() -> AlarmFilterBuilder {
        AlarmFilterBuilder::new()
    }

    /// Returns `true` if the message should pass the filter.
    #[must_use]
    pub fn should_pass_msg(&self, message: &SyslogMessage) -> bool {
        let alarm_result = Alarm::extract_alarm(&message.structured_data);

        let alarm = match alarm_result {
            Some(Ok(a)) => a,
            Some(Err(_)) => {
                // Malformed alarm SD element — treat like non-alarm per policy
                return self.non_alarm_policy == NonAlarmPolicy::Pass;
            }
            None => {
                return self.non_alarm_policy == NonAlarmPolicy::Pass;
            }
        };

        // Check min severity
        if let Some(threshold) = self.min_severity {
            if !alarm.perceived_severity.is_at_least(threshold) {
                return false;
            }
        }

        // Check event types (if any specified)
        if !self.event_types.is_empty() && !self.event_types.contains(&alarm.event_type) {
            return false;
        }

        // Check resource patterns (if any specified) — substring match
        if !self.resource_patterns.is_empty() {
            let resource_str: &str = alarm.resource.as_str();
            if !self
                .resource_patterns
                .iter()
                .any(|pat| resource_str.contains(pat.as_str()))
            {
                return false;
            }
        }

        true
    }
}

impl MessageFilter for AlarmFilter {
    fn name(&self) -> &str {
        "alarm"
    }

    fn should_pass(&self, message: &SyslogMessage) -> bool {
        self.should_pass_msg(message)
    }
}

/// Builder for [`AlarmFilter`].
#[derive(Debug, Default)]
pub struct AlarmFilterBuilder {
    min_severity: Option<PerceivedSeverity>,
    event_types: Vec<ItuEventType>,
    resource_patterns: Vec<String>,
    non_alarm_policy: Option<NonAlarmPolicy>,
}

impl AlarmFilterBuilder {
    /// Create a new builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the minimum perceived severity threshold.
    #[must_use]
    pub fn min_severity(mut self, severity: PerceivedSeverity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    /// Add an allowed event type.
    #[must_use]
    pub fn event_type(mut self, event_type: ItuEventType) -> Self {
        self.event_types.push(event_type);
        self
    }

    /// Set the allowed event types (replaces any previously added).
    #[must_use]
    pub fn event_types(mut self, event_types: Vec<ItuEventType>) -> Self {
        self.event_types = event_types;
        self
    }

    /// Add a resource substring pattern.
    #[must_use]
    pub fn resource_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.resource_patterns.push(pattern.into());
        self
    }

    /// Set the resource patterns (replaces any previously added).
    #[must_use]
    pub fn resource_patterns(mut self, patterns: Vec<String>) -> Self {
        self.resource_patterns = patterns;
        self
    }

    /// Set the policy for messages without alarm SD elements.
    #[must_use]
    pub fn non_alarm_policy(mut self, policy: NonAlarmPolicy) -> Self {
        self.non_alarm_policy = Some(policy);
        self
    }

    /// Build the [`AlarmFilter`].
    #[must_use]
    pub fn build(self) -> AlarmFilter {
        AlarmFilter {
            min_severity: self.min_severity,
            event_types: self.event_types,
            resource_patterns: self.resource_patterns,
            non_alarm_policy: self.non_alarm_policy.unwrap_or(NonAlarmPolicy::Pass),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use compact_str::CompactString;
    use smallvec::SmallVec;
    use syslog_proto::{
        Alarm, Facility, ItuEventType, PerceivedSeverity, Severity, StructuredData, SyslogTimestamp,
    };

    fn make_alarm(resource: &str, severity: PerceivedSeverity, event_type: ItuEventType) -> Alarm {
        Alarm {
            resource: CompactString::new(resource),
            perceived_severity: severity,
            event_type,
            probable_cause: None,
            trend_indication: None,
        }
    }

    fn make_message_with_alarm(alarm: &Alarm) -> SyslogMessage {
        let elem = match alarm.to_sd_element() {
            Ok(e) => e,
            Err(_) => {
                // Return a nil-SD message as fallback; tests should not hit this.
                return make_plain_message();
            }
        };
        let sd = StructuredData(SmallVec::from_vec(vec![elem]));
        SyslogMessage {
            facility: Facility::User,
            severity: Severity::Error,
            version: 1,
            timestamp: SyslogTimestamp::Nil,
            hostname: Some(CompactString::new("testhost")),
            app_name: Some(CompactString::new("testapp")),
            proc_id: None,
            msg_id: None,
            structured_data: sd,
            msg: Some(Bytes::from_static(b"alarm message")),
            raw: None,
        }
    }

    fn make_plain_message() -> SyslogMessage {
        SyslogMessage {
            facility: Facility::User,
            severity: Severity::Error,
            version: 1,
            timestamp: SyslogTimestamp::Nil,
            hostname: Some(CompactString::new("testhost")),
            app_name: Some(CompactString::new("testapp")),
            proc_id: None,
            msg_id: None,
            structured_data: StructuredData::nil(),
            msg: Some(Bytes::from_static(b"plain message")),
            raw: None,
        }
    }

    #[test]
    fn default_filter_passes_all_alarms() {
        let filter = AlarmFilter::builder().build();
        let alarm = make_alarm("eth0", PerceivedSeverity::Warning, ItuEventType::Other);
        let msg = make_message_with_alarm(&alarm);
        assert!(filter.should_pass(&msg));
    }

    #[test]
    fn default_filter_passes_non_alarm() {
        let filter = AlarmFilter::builder().build();
        let msg = make_plain_message();
        assert!(filter.should_pass(&msg));
    }

    #[test]
    fn drop_policy_drops_non_alarm() {
        let filter = AlarmFilter::builder()
            .non_alarm_policy(NonAlarmPolicy::Drop)
            .build();
        let msg = make_plain_message();
        assert!(!filter.should_pass(&msg));
    }

    #[test]
    fn min_severity_filters_below_threshold() {
        let filter = AlarmFilter::builder()
            .min_severity(PerceivedSeverity::Major)
            .build();

        let warning_alarm = make_alarm("eth0", PerceivedSeverity::Warning, ItuEventType::Other);
        assert!(!filter.should_pass(&make_message_with_alarm(&warning_alarm)));

        let major_alarm = make_alarm("eth0", PerceivedSeverity::Major, ItuEventType::Other);
        assert!(filter.should_pass(&make_message_with_alarm(&major_alarm)));

        let critical_alarm = make_alarm("eth0", PerceivedSeverity::Critical, ItuEventType::Other);
        assert!(filter.should_pass(&make_message_with_alarm(&critical_alarm)));
    }

    #[test]
    fn event_type_filter() {
        let filter = AlarmFilter::builder()
            .event_type(ItuEventType::CommunicationsAlarm)
            .event_type(ItuEventType::EquipmentAlarm)
            .build();

        let comms = make_alarm(
            "eth0",
            PerceivedSeverity::Major,
            ItuEventType::CommunicationsAlarm,
        );
        assert!(filter.should_pass(&make_message_with_alarm(&comms)));

        let proc_err = make_alarm(
            "cpu0",
            PerceivedSeverity::Major,
            ItuEventType::ProcessingErrorAlarm,
        );
        assert!(!filter.should_pass(&make_message_with_alarm(&proc_err)));
    }

    #[test]
    fn resource_pattern_filter() {
        let filter = AlarmFilter::builder()
            .resource_pattern("eth")
            .resource_pattern("link")
            .build();

        let eth_alarm = make_alarm("eth0:down", PerceivedSeverity::Major, ItuEventType::Other);
        assert!(filter.should_pass(&make_message_with_alarm(&eth_alarm)));

        let link_alarm = make_alarm(
            "linkDown:port1",
            PerceivedSeverity::Major,
            ItuEventType::Other,
        );
        assert!(filter.should_pass(&make_message_with_alarm(&link_alarm)));

        let cpu_alarm = make_alarm("cpu:host42", PerceivedSeverity::Major, ItuEventType::Other);
        assert!(!filter.should_pass(&make_message_with_alarm(&cpu_alarm)));
    }

    #[test]
    fn combined_criteria_and_logic() {
        let filter = AlarmFilter::builder()
            .min_severity(PerceivedSeverity::Major)
            .event_type(ItuEventType::CommunicationsAlarm)
            .resource_pattern("eth")
            .build();

        // Passes: Major comms alarm on eth0
        let good = make_alarm(
            "eth0",
            PerceivedSeverity::Major,
            ItuEventType::CommunicationsAlarm,
        );
        assert!(filter.should_pass(&make_message_with_alarm(&good)));

        // Fails: severity too low
        let low_sev = make_alarm(
            "eth0",
            PerceivedSeverity::Warning,
            ItuEventType::CommunicationsAlarm,
        );
        assert!(!filter.should_pass(&make_message_with_alarm(&low_sev)));

        // Fails: wrong event type
        let wrong_type = make_alarm(
            "eth0",
            PerceivedSeverity::Critical,
            ItuEventType::ProcessingErrorAlarm,
        );
        assert!(!filter.should_pass(&make_message_with_alarm(&wrong_type)));

        // Fails: wrong resource
        let wrong_resource = make_alarm(
            "cpu0",
            PerceivedSeverity::Critical,
            ItuEventType::CommunicationsAlarm,
        );
        assert!(!filter.should_pass(&make_message_with_alarm(&wrong_resource)));
    }

    #[test]
    fn non_alarm_policy_pass_with_criteria() {
        let filter = AlarmFilter::builder()
            .min_severity(PerceivedSeverity::Major)
            .non_alarm_policy(NonAlarmPolicy::Pass)
            .build();
        let msg = make_plain_message();
        assert!(filter.should_pass(&msg));
    }

    #[test]
    fn non_alarm_policy_drop_with_criteria() {
        let filter = AlarmFilter::builder()
            .min_severity(PerceivedSeverity::Major)
            .non_alarm_policy(NonAlarmPolicy::Drop)
            .build();
        let msg = make_plain_message();
        assert!(!filter.should_pass(&msg));
    }

    #[test]
    fn alarm_filter_name() {
        let filter = AlarmFilter::builder().build();
        assert_eq!(MessageFilter::name(&filter), "alarm");
    }

    #[test]
    fn empty_event_types_accepts_all() {
        let filter = AlarmFilter::builder().build();
        let alarm = make_alarm(
            "any",
            PerceivedSeverity::Warning,
            ItuEventType::EnvironmentalAlarm,
        );
        assert!(filter.should_pass(&make_message_with_alarm(&alarm)));
    }

    #[test]
    fn empty_resource_patterns_accepts_all() {
        let filter = AlarmFilter::builder().build();
        let alarm = make_alarm(
            "anything:goes:here",
            PerceivedSeverity::Warning,
            ItuEventType::Other,
        );
        assert!(filter.should_pass(&make_message_with_alarm(&alarm)));
    }
}
