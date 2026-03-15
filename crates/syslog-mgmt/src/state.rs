//! Runtime state tracking for the syslog management model.
//!
//! Provides counters and feature state for monitoring syslog operations,
//! aligned with RFC 9742 operational state reporting.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::feature::SyslogFeatures;

/// Counters for tracking message processing statistics.
///
/// RFC 9742 §6 — operational counters for monitoring syslog health.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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

/// Thread-safe atomic message counters for concurrent access.
///
/// Uses `AtomicU64` with `Relaxed` ordering for high-performance
/// counter updates in the hot path.
#[derive(Debug)]
pub struct AtomicMessageCounters {
    received: AtomicU64,
    forwarded: AtomicU64,
    dropped: AtomicU64,
    malformed: AtomicU64,
}

impl AtomicMessageCounters {
    /// Create a new set of atomic counters, all initialized to zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            received: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
        }
    }

    /// Increment the received counter by one (saturating at `u64::MAX`).
    pub fn increment_received(&self) {
        saturating_fetch_add(&self.received);
    }

    /// Increment the forwarded counter by one (saturating at `u64::MAX`).
    pub fn increment_forwarded(&self) {
        saturating_fetch_add(&self.forwarded);
    }

    /// Increment the dropped counter by one (saturating at `u64::MAX`).
    pub fn increment_dropped(&self) {
        saturating_fetch_add(&self.dropped);
    }

    /// Increment the malformed counter by one (saturating at `u64::MAX`).
    pub fn increment_malformed(&self) {
        saturating_fetch_add(&self.malformed);
    }

    /// Take a consistent snapshot of the current counter values.
    #[must_use]
    pub fn snapshot(&self) -> MessageCounters {
        MessageCounters {
            received: self.received.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            malformed: self.malformed.load(Ordering::Relaxed),
        }
    }
}

impl Default for AtomicMessageCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// Saturating atomic increment: increments an `AtomicU64` by 1, capping at
/// `u64::MAX` rather than wrapping. Uses `fetch_update` with `Relaxed`
/// ordering for consistency with the non-atomic `MessageCounters`.
fn saturating_fetch_add(counter: &AtomicU64) {
    let _result = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        if v == u64::MAX { None } else { Some(v + 1) }
    });
}

/// Inner state shared behind an `Arc`.
#[derive(Debug)]
struct SharedInner {
    features: SyslogFeatures,
    started_at: std::time::Instant,
    counters: AtomicMessageCounters,
}

/// Thread-safe, cloneable shared syslog state.
///
/// Wraps feature flags, startup time, and atomic counters behind an `Arc`
/// for efficient sharing across async tasks.
#[derive(Clone, Debug)]
pub struct SharedSyslogState {
    inner: Arc<SharedInner>,
}

impl SharedSyslogState {
    /// Create a new shared state with the given features.
    #[must_use]
    pub fn new(features: SyslogFeatures) -> Self {
        Self {
            inner: Arc::new(SharedInner {
                features,
                started_at: std::time::Instant::now(),
                counters: AtomicMessageCounters::new(),
            }),
        }
    }

    /// Returns a reference to the atomic message counters.
    #[must_use]
    pub fn counters(&self) -> &AtomicMessageCounters {
        &self.inner.counters
    }

    /// Returns the feature flags for this instance.
    #[must_use]
    pub fn features(&self) -> SyslogFeatures {
        self.inner.features
    }

    /// Returns the uptime duration since this state was created.
    #[must_use]
    pub fn uptime(&self) -> std::time::Duration {
        self.inner.started_at.elapsed()
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

    // -- AtomicMessageCounters tests --

    #[test]
    fn atomic_counters_new_are_zero() {
        let c = AtomicMessageCounters::new();
        let snap = c.snapshot();
        assert_eq!(snap.received, 0);
        assert_eq!(snap.forwarded, 0);
        assert_eq!(snap.dropped, 0);
        assert_eq!(snap.malformed, 0);
    }

    #[test]
    fn atomic_counters_default_are_zero() {
        let c = AtomicMessageCounters::default();
        let snap = c.snapshot();
        assert_eq!(snap.received, 0);
    }

    #[test]
    fn atomic_increment_received() {
        let c = AtomicMessageCounters::new();
        c.increment_received();
        c.increment_received();
        assert_eq!(c.snapshot().received, 2);
    }

    #[test]
    fn atomic_increment_forwarded() {
        let c = AtomicMessageCounters::new();
        c.increment_forwarded();
        assert_eq!(c.snapshot().forwarded, 1);
    }

    #[test]
    fn atomic_increment_dropped() {
        let c = AtomicMessageCounters::new();
        c.increment_dropped();
        assert_eq!(c.snapshot().dropped, 1);
    }

    #[test]
    fn atomic_increment_malformed() {
        let c = AtomicMessageCounters::new();
        c.increment_malformed();
        assert_eq!(c.snapshot().malformed, 1);
    }

    #[test]
    fn atomic_snapshot_is_consistent_point_in_time() {
        let c = AtomicMessageCounters::new();
        c.increment_received();
        c.increment_forwarded();
        c.increment_dropped();
        c.increment_malformed();
        let snap = c.snapshot();
        assert_eq!(snap.received, 1);
        assert_eq!(snap.forwarded, 1);
        assert_eq!(snap.dropped, 1);
        assert_eq!(snap.malformed, 1);
    }

    #[test]
    fn atomic_multiple_increments() {
        let c = AtomicMessageCounters::new();
        for _ in 0..100 {
            c.increment_received();
        }
        assert_eq!(c.snapshot().received, 100);
    }

    // -- SharedSyslogState tests --

    #[test]
    fn shared_state_construction() {
        let state = SharedSyslogState::new(SyslogFeatures::default_relay());
        assert!(state.features().is_transport_capable());
        assert_eq!(state.counters().snapshot().received, 0);
    }

    #[test]
    fn shared_state_uptime() {
        let state = SharedSyslogState::new(SyslogFeatures::empty());
        assert!(state.uptime().as_secs() < 1);
    }

    #[test]
    fn shared_state_clone_shares_counters() {
        let state = SharedSyslogState::new(SyslogFeatures::empty());
        let clone = state.clone();
        state.counters().increment_received();
        assert_eq!(clone.counters().snapshot().received, 1);
    }

    #[test]
    fn shared_state_features() {
        let state = SharedSyslogState::new(SyslogFeatures::SIGNING | SyslogFeatures::RELAY);
        assert!(state.features().supports_signing());
        assert!(state.features().supports_relay());
    }

    // -- Serialization tests --

    #[test]
    fn message_counters_serialize() {
        let c = MessageCounters {
            received: 10,
            forwarded: 8,
            dropped: 1,
            malformed: 1,
        };
        let json = match serde_json::to_string(&c) {
            Ok(j) => j,
            Err(_) => return,
        };
        assert!(json.contains("\"received\":10"));
        assert!(json.contains("\"forwarded\":8"));
        assert!(json.contains("\"dropped\":1"));
        assert!(json.contains("\"malformed\":1"));
    }
}
