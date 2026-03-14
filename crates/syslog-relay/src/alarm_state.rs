//! Alarm state table for tracking active alarms (RFC 5674).
//!
//! The [`AlarmStateTable`] maintains a bounded map of active alarms keyed by
//! resource and event type, enabling severity change detection and clear tracking.

use std::collections::HashMap;

use compact_str::CompactString;
use syslog_proto::{Alarm, ItuEventType, PerceivedSeverity};

/// Composite key for an alarm entry: (resource, event_type).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AlarmKey {
    /// The alarming resource identifier.
    pub resource: CompactString,
    /// The ITU event type classification.
    pub event_type: ItuEventType,
}

/// A single entry in the alarm state table.
#[derive(Debug, Clone)]
pub struct AlarmEntry {
    /// The key identifying this alarm.
    pub key: AlarmKey,
    /// Current perceived severity.
    pub perceived_severity: PerceivedSeverity,
    /// When this alarm was first raised.
    pub first_raised: std::time::Instant,
    /// When this alarm was last updated.
    pub last_updated: std::time::Instant,
    /// Number of times this alarm has been updated (including the initial raise).
    pub update_count: u64,
}

/// Describes what changed when an alarm was processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlarmStateChange {
    /// A new alarm was added to the table.
    NewAlarm,
    /// The severity of an existing alarm changed.
    SeverityChanged {
        /// Previous severity.
        from: PerceivedSeverity,
        /// New severity.
        to: PerceivedSeverity,
    },
    /// An alarm was cleared and removed from the active table.
    Cleared,
    /// An existing alarm was updated without a severity change.
    Updated,
    /// The table is full and the alarm could not be added.
    TableFull,
}

/// Bounded table of active alarms.
///
/// Tracks alarm lifecycle: raise, update, severity change, clear.
/// Enforces a maximum entry count to prevent unbounded memory growth.
#[derive(Debug)]
pub struct AlarmStateTable {
    active: HashMap<AlarmKey, AlarmEntry>,
    max_entries: usize,
}

impl AlarmStateTable {
    /// Create a new alarm state table with the given maximum entry count.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            active: HashMap::new(),
            max_entries,
        }
    }

    /// Process an incoming alarm, updating the state table.
    ///
    /// Returns the kind of state change that occurred.
    #[must_use]
    pub fn process_alarm(&mut self, alarm: &Alarm) -> AlarmStateChange {
        let key = AlarmKey {
            resource: alarm.resource.clone(),
            event_type: alarm.event_type,
        };

        // Handle cleared alarms: remove from active table
        if alarm.perceived_severity == PerceivedSeverity::Cleared {
            if self.active.remove(&key).is_some() {
                return AlarmStateChange::Cleared;
            }
            // Clearing an alarm that's not in the table is still a clear
            return AlarmStateChange::Cleared;
        }

        let now = std::time::Instant::now();

        // Update existing entry
        if let Some(entry) = self.active.get_mut(&key) {
            let old_severity = entry.perceived_severity;
            entry.perceived_severity = alarm.perceived_severity;
            entry.last_updated = now;
            entry.update_count = entry.update_count.saturating_add(1);

            if old_severity != alarm.perceived_severity {
                return AlarmStateChange::SeverityChanged {
                    from: old_severity,
                    to: alarm.perceived_severity,
                };
            }
            return AlarmStateChange::Updated;
        }

        // New alarm — check capacity
        if self.active.len() >= self.max_entries {
            return AlarmStateChange::TableFull;
        }

        let entry = AlarmEntry {
            key: key.clone(),
            perceived_severity: alarm.perceived_severity,
            first_raised: now,
            last_updated: now,
            update_count: 1,
        };
        self.active.insert(key, entry);
        AlarmStateChange::NewAlarm
    }

    /// Returns the number of currently active alarms.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Returns a map of perceived severity to count of active alarms at that severity.
    #[must_use]
    pub fn active_count_by_severity(&self) -> HashMap<PerceivedSeverity, usize> {
        let mut counts = HashMap::new();
        for entry in self.active.values() {
            *counts.entry(entry.perceived_severity).or_insert(0) += 1;
        }
        counts
    }

    /// Iterate over all active alarm entries.
    pub fn iter_active(&self) -> impl Iterator<Item = &AlarmEntry> {
        self.active.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compact_str::CompactString;
    use syslog_proto::{ItuEventType, PerceivedSeverity};

    fn make_alarm(resource: &str, severity: PerceivedSeverity, event_type: ItuEventType) -> Alarm {
        Alarm {
            resource: CompactString::new(resource),
            perceived_severity: severity,
            event_type,
            probable_cause: None,
            trend_indication: None,
        }
    }

    #[test]
    fn new_alarm_is_tracked() {
        let mut table = AlarmStateTable::new(100);
        let alarm = make_alarm(
            "eth0",
            PerceivedSeverity::Major,
            ItuEventType::CommunicationsAlarm,
        );
        let change = table.process_alarm(&alarm);
        assert_eq!(change, AlarmStateChange::NewAlarm);
        assert_eq!(table.active_count(), 1);
    }

    #[test]
    fn update_same_severity() {
        let mut table = AlarmStateTable::new(100);
        let alarm = make_alarm(
            "eth0",
            PerceivedSeverity::Major,
            ItuEventType::CommunicationsAlarm,
        );
        let _ = table.process_alarm(&alarm);
        let change = table.process_alarm(&alarm);
        assert_eq!(change, AlarmStateChange::Updated);
        assert_eq!(table.active_count(), 1);
    }

    #[test]
    fn severity_change_detected() {
        let mut table = AlarmStateTable::new(100);
        let alarm1 = make_alarm(
            "eth0",
            PerceivedSeverity::Minor,
            ItuEventType::CommunicationsAlarm,
        );
        let _ = table.process_alarm(&alarm1);

        let alarm2 = make_alarm(
            "eth0",
            PerceivedSeverity::Critical,
            ItuEventType::CommunicationsAlarm,
        );
        let change = table.process_alarm(&alarm2);
        assert_eq!(
            change,
            AlarmStateChange::SeverityChanged {
                from: PerceivedSeverity::Minor,
                to: PerceivedSeverity::Critical,
            }
        );
        assert_eq!(table.active_count(), 1);
    }

    #[test]
    fn clear_removes_alarm() {
        let mut table = AlarmStateTable::new(100);
        let alarm = make_alarm(
            "eth0",
            PerceivedSeverity::Major,
            ItuEventType::CommunicationsAlarm,
        );
        let _ = table.process_alarm(&alarm);
        assert_eq!(table.active_count(), 1);

        let clear = make_alarm(
            "eth0",
            PerceivedSeverity::Cleared,
            ItuEventType::CommunicationsAlarm,
        );
        let change = table.process_alarm(&clear);
        assert_eq!(change, AlarmStateChange::Cleared);
        assert_eq!(table.active_count(), 0);
    }

    #[test]
    fn clear_nonexistent_returns_cleared() {
        let mut table = AlarmStateTable::new(100);
        let clear = make_alarm(
            "eth0",
            PerceivedSeverity::Cleared,
            ItuEventType::CommunicationsAlarm,
        );
        let change = table.process_alarm(&clear);
        assert_eq!(change, AlarmStateChange::Cleared);
        assert_eq!(table.active_count(), 0);
    }

    #[test]
    fn table_full_rejects_new() {
        let mut table = AlarmStateTable::new(1);
        let alarm1 = make_alarm(
            "eth0",
            PerceivedSeverity::Major,
            ItuEventType::CommunicationsAlarm,
        );
        let _ = table.process_alarm(&alarm1);

        let alarm2 = make_alarm(
            "eth1",
            PerceivedSeverity::Minor,
            ItuEventType::EquipmentAlarm,
        );
        let change = table.process_alarm(&alarm2);
        assert_eq!(change, AlarmStateChange::TableFull);
        assert_eq!(table.active_count(), 1);
    }

    #[test]
    fn table_full_still_allows_updates() {
        let mut table = AlarmStateTable::new(1);
        let alarm = make_alarm(
            "eth0",
            PerceivedSeverity::Major,
            ItuEventType::CommunicationsAlarm,
        );
        let _ = table.process_alarm(&alarm);

        // Same key, different severity — should work even when full
        let update = make_alarm(
            "eth0",
            PerceivedSeverity::Critical,
            ItuEventType::CommunicationsAlarm,
        );
        let change = table.process_alarm(&update);
        assert_eq!(
            change,
            AlarmStateChange::SeverityChanged {
                from: PerceivedSeverity::Major,
                to: PerceivedSeverity::Critical,
            }
        );
    }

    #[test]
    fn active_count_by_severity() {
        let mut table = AlarmStateTable::new(100);
        let _ = table.process_alarm(&make_alarm(
            "eth0",
            PerceivedSeverity::Major,
            ItuEventType::CommunicationsAlarm,
        ));
        let _ = table.process_alarm(&make_alarm(
            "eth1",
            PerceivedSeverity::Major,
            ItuEventType::CommunicationsAlarm,
        ));
        let _ = table.process_alarm(&make_alarm(
            "cpu0",
            PerceivedSeverity::Minor,
            ItuEventType::ProcessingErrorAlarm,
        ));

        let counts = table.active_count_by_severity();
        assert_eq!(counts.get(&PerceivedSeverity::Major).copied(), Some(2));
        assert_eq!(counts.get(&PerceivedSeverity::Minor).copied(), Some(1));
        assert_eq!(counts.get(&PerceivedSeverity::Critical), None);
    }

    #[test]
    fn different_keys_tracked_separately() {
        let mut table = AlarmStateTable::new(100);
        let alarm1 = make_alarm(
            "eth0",
            PerceivedSeverity::Major,
            ItuEventType::CommunicationsAlarm,
        );
        let alarm2 = make_alarm(
            "eth0",
            PerceivedSeverity::Minor,
            ItuEventType::EquipmentAlarm,
        );
        let alarm3 = make_alarm(
            "eth1",
            PerceivedSeverity::Warning,
            ItuEventType::CommunicationsAlarm,
        );

        let _ = table.process_alarm(&alarm1);
        let _ = table.process_alarm(&alarm2);
        let _ = table.process_alarm(&alarm3);

        assert_eq!(table.active_count(), 3);
    }

    #[test]
    fn iter_active_returns_all() {
        let mut table = AlarmStateTable::new(100);
        let _ = table.process_alarm(&make_alarm(
            "a",
            PerceivedSeverity::Major,
            ItuEventType::Other,
        ));
        let _ = table.process_alarm(&make_alarm(
            "b",
            PerceivedSeverity::Minor,
            ItuEventType::Other,
        ));

        let entries: Vec<_> = table.iter_active().collect();
        assert_eq!(entries.len(), 2);
    }
}
