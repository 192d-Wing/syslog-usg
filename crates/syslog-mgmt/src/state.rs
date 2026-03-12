//! Runtime state tracking for the syslog management model.
//!
//! Provides counters and feature state for monitoring syslog operations,
//! aligned with RFC 9742 operational state reporting.

use crate::feature::SyslogFeatures;

/// Counters for tracking message processing statistics.
///
/// RFC 9742 §6 — operational counters for monitoring syslog health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageCounters {
    /// Total messages received.
    pub received: u64,
    /// Total messages successfully forwarded.
    pub forwarded: u64,
    /// Total messages dropped (e.g., queue full).
    pub dropped: u64,
    /// Total messages that failed to parse.
    pub malformed: u64,
}

impl MessageCounters {
    /// Create a new set of counters, all initialized to zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            received: 0,
            forwarded: 0,
            dropped: 0,
            malformed: 0,
        }
    }

    /// Increment the received counter by one.
    pub fn increment_received(&mut self) {
        self.received = self.received.saturating_add(1);
    }

    /// Increment the forwarded counter by one.
    pub fn increment_forwarded(&mut self) {
        self.forwarded = self.forwarded.saturating_add(1);
    }

    /// Increment the dropped counter by one.
    pub fn increment_dropped(&mut self) {
        self.dropped = self.dropped.saturating_add(1);
    }

    /// Increment the malformed counter by one.
    pub fn increment_malformed(&mut self) {
        self.malformed = self.malformed.saturating_add(1);
    }

    /// Returns the total number of messages processed (received).
    #[must_use]
    pub fn total_processed(&self) -> u64 {
        self.received
    }

    /// Returns the number of messages that were not forwarded (dropped + malformed).
    #[must_use]
    pub fn total_errors(&self) -> u64 {
        self.dropped.saturating_add(self.malformed)
    }
}

impl Default for MessageCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime state of the syslog system.
///
/// Combines feature capabilities with operational counters and timing.
#[derive(Debug)]
pub struct SyslogState {
    /// The set of features this instance supports.
    pub features: SyslogFeatures,
    /// When this instance was started.
    pub started_at: std::time::Instant,
    /// Message processing counters.
    pub message_counters: MessageCounters,
}

impl SyslogState {
    /// Create a new state with the given features, starting now.
    #[must_use]
    pub fn new(features: SyslogFeatures) -> Self {
        Self {
            features,
            started_at: std::time::Instant::now(),
            message_counters: MessageCounters::new(),
        }
    }

    /// Returns the uptime duration since this state was created.
    #[must_use]
    pub fn uptime(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_counters_are_zero() {
        let c = MessageCounters::new();
        assert_eq!(c.received, 0);
        assert_eq!(c.forwarded, 0);
        assert_eq!(c.dropped, 0);
        assert_eq!(c.malformed, 0);
    }

    #[test]
    fn default_counters_are_zero() {
        let c = MessageCounters::default();
        assert_eq!(c.received, 0);
        assert_eq!(c.forwarded, 0);
        assert_eq!(c.dropped, 0);
        assert_eq!(c.malformed, 0);
    }

    #[test]
    fn increment_received() {
        let mut c = MessageCounters::new();
        c.increment_received();
        assert_eq!(c.received, 1);
        c.increment_received();
        assert_eq!(c.received, 2);
    }

    #[test]
    fn increment_forwarded() {
        let mut c = MessageCounters::new();
        c.increment_forwarded();
        assert_eq!(c.forwarded, 1);
    }

    #[test]
    fn increment_dropped() {
        let mut c = MessageCounters::new();
        c.increment_dropped();
        assert_eq!(c.dropped, 1);
    }

    #[test]
    fn increment_malformed() {
        let mut c = MessageCounters::new();
        c.increment_malformed();
        assert_eq!(c.malformed, 1);
    }

    #[test]
    fn total_processed() {
        let mut c = MessageCounters::new();
        c.increment_received();
        c.increment_received();
        c.increment_received();
        assert_eq!(c.total_processed(), 3);
    }

    #[test]
    fn total_errors() {
        let mut c = MessageCounters::new();
        c.increment_dropped();
        c.increment_dropped();
        c.increment_malformed();
        assert_eq!(c.total_errors(), 3);
    }

    #[test]
    fn saturating_increment() {
        let mut c = MessageCounters::new();
        c.received = u64::MAX;
        c.increment_received();
        assert_eq!(c.received, u64::MAX);
    }

    #[test]
    fn state_construction() {
        let state = SyslogState::new(SyslogFeatures::default_relay());
        assert!(state.features.is_transport_capable());
        assert_eq!(state.message_counters.received, 0);
    }

    #[test]
    fn state_uptime_is_non_negative() {
        let state = SyslogState::new(SyslogFeatures::empty());
        let uptime = state.uptime();
        // Uptime should be very small but non-negative
        assert!(uptime.as_secs() < 1);
    }

    #[test]
    fn state_counters_are_mutable() {
        let mut state = SyslogState::new(SyslogFeatures::empty());
        state.message_counters.increment_received();
        state.message_counters.increment_forwarded();
        assert_eq!(state.message_counters.received, 1);
        assert_eq!(state.message_counters.forwarded, 1);
    }
}
