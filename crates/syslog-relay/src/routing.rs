//! Management-driven routing table for selective output delivery.
//!
//! Uses [`syslog_mgmt::Selector`] to determine which outputs should
//! receive each message, enabling RFC 9742 action-based routing.

use syslog_mgmt::Selector;
use syslog_proto::SyslogMessage;

/// A single routing rule mapping a selector to output indices.
#[derive(Debug)]
pub struct RoutingRule {
    /// Selector determining which messages this rule applies to.
    pub selector: Selector,
    /// Indices into the pipeline's output list.
    pub output_indices: Vec<usize>,
    /// Optional description for logging/debugging.
    pub description: Option<String>,
}

/// A table of routing rules for selective message delivery.
///
/// When the routing table is present in the pipeline, messages are
/// sent only to the outputs whose indices appear in matching rules.
/// If no rules match, the message is not forwarded.
#[derive(Debug)]
pub struct RoutingTable {
    rules: Vec<RoutingRule>,
}

impl RoutingTable {
    /// Create a new routing table from the given rules.
    #[must_use]
    pub fn new(rules: Vec<RoutingRule>) -> Self {
        Self { rules }
    }

    /// Returns the deduplicated set of output indices for a given message.
    ///
    /// Each output index appears at most once, preserving the order of
    /// first occurrence.
    #[must_use]
    pub fn matching_output_indices(&self, msg: &SyslogMessage) -> Vec<usize> {
        let mut indices = Vec::new();
        for rule in &self.rules {
            if rule.selector.matches(msg) {
                for &idx in &rule.output_indices {
                    if !indices.contains(&idx) {
                        indices.push(idx);
                    }
                }
            }
        }
        indices
    }

    /// Returns `true` if the routing table has no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Returns the number of routing rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use compact_str::CompactString;
    use syslog_proto::{Facility, Severity, StructuredData, SyslogTimestamp};

    fn sample_msg(facility: Facility, severity: Severity) -> SyslogMessage {
        SyslogMessage {
            facility,
            severity,
            version: 1,
            timestamp: SyslogTimestamp::Nil,
            hostname: Some(CompactString::new("webserver01")),
            app_name: Some(CompactString::new("nginx")),
            proc_id: None,
            msg_id: None,
            structured_data: StructuredData::nil(),
            msg: Some(Bytes::from_static(b"test")),
            raw: None,
        }
    }

    #[test]
    fn empty_table_matches_nothing() {
        let table = RoutingTable::new(vec![]);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        let msg = sample_msg(Facility::User, Severity::Warning);
        assert!(table.matching_output_indices(&msg).is_empty());
    }

    #[test]
    fn single_rule_matches() {
        let rule = RoutingRule {
            selector: Selector::new().with_facilities(vec![Facility::User]),
            output_indices: vec![0],
            description: None,
        };
        let table = RoutingTable::new(vec![rule]);
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);

        let msg = sample_msg(Facility::User, Severity::Warning);
        assert_eq!(table.matching_output_indices(&msg), vec![0]);
    }

    #[test]
    fn single_rule_no_match() {
        let rule = RoutingRule {
            selector: Selector::new().with_facilities(vec![Facility::Kern]),
            output_indices: vec![0],
            description: None,
        };
        let table = RoutingTable::new(vec![rule]);
        let msg = sample_msg(Facility::User, Severity::Warning);
        assert!(table.matching_output_indices(&msg).is_empty());
    }

    #[test]
    fn multiple_rules_match() {
        let rules = vec![
            RoutingRule {
                selector: Selector::new().with_facilities(vec![Facility::User]),
                output_indices: vec![0],
                description: None,
            },
            RoutingRule {
                selector: Selector::new().with_min_severity(Severity::Warning),
                output_indices: vec![1],
                description: None,
            },
        ];
        let table = RoutingTable::new(rules);
        let msg = sample_msg(Facility::User, Severity::Warning);
        let indices = table.matching_output_indices(&msg);
        assert_eq!(indices, vec![0, 1]);
    }

    #[test]
    fn deduplication_of_indices() {
        let rules = vec![
            RoutingRule {
                selector: Selector::new(),
                output_indices: vec![0, 1],
                description: None,
            },
            RoutingRule {
                selector: Selector::new(),
                output_indices: vec![1, 2],
                description: None,
            },
        ];
        let table = RoutingTable::new(rules);
        let msg = sample_msg(Facility::User, Severity::Warning);
        let indices = table.matching_output_indices(&msg);
        assert_eq!(indices, vec![0, 1, 2]);
    }

    #[test]
    fn severity_based_routing() {
        let rules = vec![
            RoutingRule {
                selector: Selector::new().with_min_severity(Severity::Error),
                output_indices: vec![0],
                description: Some("errors to output 0".to_owned()),
            },
            RoutingRule {
                selector: Selector::new(),
                output_indices: vec![1],
                description: Some("all to output 1".to_owned()),
            },
        ];
        let table = RoutingTable::new(rules);

        // Error matches both rules
        let err_msg = sample_msg(Facility::User, Severity::Error);
        assert_eq!(table.matching_output_indices(&err_msg), vec![0, 1]);

        // Debug only matches the "all" rule
        let debug_msg = sample_msg(Facility::User, Severity::Debug);
        assert_eq!(table.matching_output_indices(&debug_msg), vec![1]);
    }

    #[test]
    fn hostname_pattern_routing() {
        let sel = match Selector::new().with_hostname_pattern(r"^web") {
            Ok(s) => s,
            Err(_) => return,
        };
        let rules = vec![RoutingRule {
            selector: sel,
            output_indices: vec![0, 1],
            description: None,
        }];
        let table = RoutingTable::new(rules);

        let web_msg = sample_msg(Facility::User, Severity::Warning);
        assert_eq!(table.matching_output_indices(&web_msg), vec![0, 1]);

        let mut db_msg = sample_msg(Facility::User, Severity::Warning);
        db_msg.hostname = Some(CompactString::new("dbserver01"));
        assert!(table.matching_output_indices(&db_msg).is_empty());
    }

    #[test]
    fn rule_with_description() {
        let rule = RoutingRule {
            selector: Selector::new(),
            output_indices: vec![0],
            description: Some("catch-all".to_owned()),
        };
        assert_eq!(rule.description.as_deref(), Some("catch-all"));
    }

    #[test]
    fn multiple_indices_per_rule() {
        let rule = RoutingRule {
            selector: Selector::new(),
            output_indices: vec![0, 1, 2],
            description: None,
        };
        let table = RoutingTable::new(vec![rule]);
        let msg = sample_msg(Facility::User, Severity::Warning);
        assert_eq!(table.matching_output_indices(&msg), vec![0, 1, 2]);
    }

    #[test]
    fn no_matching_rules_returns_empty() {
        let rules = vec![
            RoutingRule {
                selector: Selector::new().with_facilities(vec![Facility::Kern]),
                output_indices: vec![0],
                description: None,
            },
            RoutingRule {
                selector: Selector::new().with_facilities(vec![Facility::Mail]),
                output_indices: vec![1],
                description: None,
            },
        ];
        let table = RoutingTable::new(rules);
        let msg = sample_msg(Facility::User, Severity::Warning);
        assert!(table.matching_output_indices(&msg).is_empty());
    }
}
