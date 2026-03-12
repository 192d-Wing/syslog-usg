//! Top-level syslog management configuration model.
//!
//! RFC 9742 — YANG data model alignment. The [`SyslogConfig`] struct
//! is the root container for all management-model configuration.

use crate::action::Action;
use crate::feature::SyslogFeatures;
use syslog_proto::SyslogMessage;

/// Top-level management configuration for a syslog instance.
///
/// RFC 9742 §3 — the syslog configuration contains a list of actions
/// and the set of features supported by this implementation.
#[derive(Debug)]
pub struct SyslogConfig {
    /// Configured actions (selector + action type pairs).
    pub actions: Vec<Action>,
    /// Global feature capabilities.
    pub global_features: SyslogFeatures,
}

impl SyslogConfig {
    /// Create a new empty configuration with no actions and no features.
    #[must_use]
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            global_features: SyslogFeatures::empty(),
        }
    }

    /// Create a new configuration with the specified features.
    #[must_use]
    pub fn with_features(features: SyslogFeatures) -> Self {
        Self {
            actions: Vec::new(),
            global_features: features,
        }
    }

    /// Add an action to this configuration.
    pub fn add_action(&mut self, action: Action) {
        self.actions.push(action);
    }

    /// Returns all actions whose selectors match the given message.
    #[must_use]
    pub fn matching_actions(&self, msg: &SyslogMessage) -> Vec<&Action> {
        self.actions
            .iter()
            .filter(|a| a.selector.matches(msg))
            .collect()
    }

    /// Returns the number of configured actions.
    #[must_use]
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{ActionType, TransportProtocol};
    use crate::selector::Selector;
    use bytes::Bytes;
    use compact_str::CompactString;
    use syslog_proto::{Facility, Severity, StructuredData, SyslogTimestamp};

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

    fn kern_emerg_msg() -> SyslogMessage {
        SyslogMessage {
            facility: Facility::Kern,
            severity: Severity::Emergency,
            version: 1,
            timestamp: SyslogTimestamp::Nil,
            hostname: Some(CompactString::new("dbserver01")),
            app_name: Some(CompactString::new("kernel")),
            proc_id: None,
            msg_id: None,
            structured_data: StructuredData::nil(),
            msg: Some(Bytes::from_static(b"panic")),
            raw: None,
        }
    }

    #[test]
    fn new_config_is_empty() {
        let cfg = SyslogConfig::new();
        assert!(cfg.actions.is_empty());
        assert_eq!(cfg.action_count(), 0);
        assert!(cfg.global_features.is_empty());
    }

    #[test]
    fn default_config_is_empty() {
        let cfg = SyslogConfig::default();
        assert!(cfg.actions.is_empty());
    }

    #[test]
    fn with_features_sets_features() {
        let cfg = SyslogConfig::with_features(SyslogFeatures::default_relay());
        assert!(cfg.global_features.is_transport_capable());
        assert!(cfg.actions.is_empty());
    }

    #[test]
    fn add_action_increases_count() {
        let mut cfg = SyslogConfig::new();
        cfg.add_action(Action::new(Selector::new(), ActionType::Console));
        assert_eq!(cfg.action_count(), 1);
        cfg.add_action(Action::new(Selector::new(), ActionType::Discard));
        assert_eq!(cfg.action_count(), 2);
    }

    #[test]
    fn matching_actions_returns_all_matching() {
        let mut cfg = SyslogConfig::new();
        // Action 1: matches all
        cfg.add_action(Action::new(Selector::new(), ActionType::Console));
        // Action 2: matches all
        cfg.add_action(Action::new(Selector::new(), ActionType::Discard));

        let msg = sample_msg();
        let matched = cfg.matching_actions(&msg);
        assert_eq!(matched.len(), 2);
    }

    #[test]
    fn matching_actions_filters_by_facility() {
        let mut cfg = SyslogConfig::new();
        // Matches User facility
        cfg.add_action(Action::new(
            Selector::new().with_facilities(vec![Facility::User]),
            ActionType::Console,
        ));
        // Matches only Kern facility
        cfg.add_action(Action::new(
            Selector::new().with_facilities(vec![Facility::Kern]),
            ActionType::Discard,
        ));

        let msg = sample_msg(); // User facility
        let matched = cfg.matching_actions(&msg);
        assert_eq!(matched.len(), 1);
        assert!(matches!(
            matched.first().map(|a| &a.action_type),
            Some(ActionType::Console)
        ));
    }

    #[test]
    fn matching_actions_filters_by_severity() {
        let mut cfg = SyslogConfig::new();
        // Only Emergency
        cfg.add_action(Action::new(
            Selector::new().with_min_severity(Severity::Emergency),
            ActionType::Console,
        ));
        // Warning and above
        cfg.add_action(Action::new(
            Selector::new().with_min_severity(Severity::Warning),
            ActionType::Discard,
        ));

        let msg = sample_msg(); // Warning
        let matched = cfg.matching_actions(&msg);
        // Only the second action should match (Warning >= Warning is true, Warning >= Emergency is false)
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn matching_actions_with_hostname_pattern() {
        let mut cfg = SyslogConfig::new();

        let sel = match Selector::new().with_hostname_pattern(r"^web") {
            Ok(s) => s,
            Err(_) => return,
        };
        cfg.add_action(Action::new(sel, ActionType::Console));

        let sel = match Selector::new().with_hostname_pattern(r"^db") {
            Ok(s) => s,
            Err(_) => return,
        };
        cfg.add_action(Action::new(sel, ActionType::Discard));

        let msg = sample_msg(); // hostname = webserver01
        let matched = cfg.matching_actions(&msg);
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn matching_actions_empty_config_returns_empty() {
        let cfg = SyslogConfig::new();
        let msg = sample_msg();
        let matched = cfg.matching_actions(&msg);
        assert!(matched.is_empty());
    }

    #[test]
    fn matching_actions_none_match() {
        let mut cfg = SyslogConfig::new();
        cfg.add_action(Action::new(
            Selector::new().with_facilities(vec![Facility::Mail]),
            ActionType::Console,
        ));

        let msg = sample_msg(); // User facility
        let matched = cfg.matching_actions(&msg);
        assert!(matched.is_empty());
    }

    #[test]
    fn matching_actions_multiple_messages() {
        let mut cfg = SyslogConfig::new();
        cfg.add_action(Action::new(
            Selector::new().with_facilities(vec![Facility::Kern]),
            ActionType::Console,
        ));
        cfg.add_action(Action::new(
            Selector::new().with_facilities(vec![Facility::User]),
            ActionType::Discard,
        ));

        let user_msg = sample_msg();
        let kern_msg = kern_emerg_msg();

        let user_matched = cfg.matching_actions(&user_msg);
        let kern_matched = cfg.matching_actions(&kern_msg);

        assert_eq!(user_matched.len(), 1);
        assert_eq!(kern_matched.len(), 1);
    }

    #[test]
    fn matching_actions_with_remote_action() {
        let mut cfg = SyslogConfig::new();
        cfg.add_action(Action::new(
            Selector::new().with_min_severity(Severity::Error),
            ActionType::Remote {
                host: "10.0.0.1".to_owned(),
                port: 514,
                protocol: TransportProtocol::Tls,
            },
        ));

        let msg = kern_emerg_msg(); // Emergency >= Error
        let matched = cfg.matching_actions(&msg);
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn matching_actions_with_app_name_pattern() {
        let mut cfg = SyslogConfig::new();

        let sel = match Selector::new().with_app_name_pattern(r"nginx") {
            Ok(s) => s,
            Err(_) => return,
        };
        cfg.add_action(Action::new(sel, ActionType::Console));

        let nginx_msg = sample_msg();
        let kern_msg = kern_emerg_msg();

        assert_eq!(cfg.matching_actions(&nginx_msg).len(), 1);
        assert_eq!(cfg.matching_actions(&kern_msg).len(), 0);
    }

    #[test]
    fn matching_actions_complex_selector() {
        let mut cfg = SyslogConfig::new();

        let sel = Selector::new()
            .with_facilities(vec![Facility::User])
            .with_min_severity(Severity::Warning);
        let sel = match sel.with_hostname_pattern(r"^web") {
            Ok(s) => s,
            Err(_) => return,
        };
        cfg.add_action(Action::new(sel, ActionType::Console));

        let msg = sample_msg(); // User, Warning, webserver01
        assert_eq!(cfg.matching_actions(&msg).len(), 1);

        let kern_msg = kern_emerg_msg(); // Kern, Emergency, dbserver01
        assert_eq!(cfg.matching_actions(&kern_msg).len(), 0);
    }
}
