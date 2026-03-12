//! Counter management for RFC 5848 — GBC, FMN, and RSID.
//!
//! RFC 5848 §4.2: Global Block Counter (GBC), First Message Number (FMN),
//! and Reboot Session ID (RSID) are decimal counters with defined ranges.

use crate::error::SignError;
use crate::types::{MAX_GBC, MAX_RSID};

/// Global Block Counter — increments with each signature block emitted.
///
/// RFC 5848 §4.2.5: GBC is a decimal value 0–9999999999. Wraps around
/// at the maximum value (edge case documented in RFC).
#[derive(Debug, Clone)]
pub struct GlobalBlockCounter {
    value: u64,
}

impl GlobalBlockCounter {
    /// Create a new counter starting at 0.
    #[must_use]
    pub fn new() -> Self {
        Self { value: 0 }
    }

    /// Create a counter starting at a specific value.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::CounterOverflow`] if `value` exceeds [`MAX_GBC`].
    pub fn with_value(value: u64) -> Result<Self, SignError> {
        if value > MAX_GBC {
            return Err(SignError::CounterOverflow { name: "GBC", value });
        }
        Ok(Self { value })
    }

    /// Get the current counter value.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Increment and return the new value.
    ///
    /// Wraps around to 0 after [`MAX_GBC`].
    pub fn increment(&mut self) -> u64 {
        if self.value >= MAX_GBC {
            self.value = 0;
        } else {
            self.value += 1;
        }
        self.value
    }
}

impl Default for GlobalBlockCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Reboot Session ID — monotonically increasing across reboots.
///
/// RFC 5848 §4.2.4: RSID is a decimal value 0–9999999999.
/// MUST strictly monotonically increase across reboots.
/// If persistence cannot be guaranteed, MUST always be 0.
#[derive(Debug, Clone)]
pub struct RebootSessionId {
    value: u64,
}

impl RebootSessionId {
    /// Create with a specific RSID value.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::CounterOverflow`] if `value` exceeds [`MAX_RSID`].
    pub fn new(value: u64) -> Result<Self, SignError> {
        if value > MAX_RSID {
            return Err(SignError::CounterOverflow {
                name: "RSID",
                value,
            });
        }
        Ok(Self { value })
    }

    /// Create with RSID=0 (no persistence).
    ///
    /// RFC 5848 §4.2.4: If the implementation cannot guarantee
    /// persistence, RSID MUST always be 0.
    #[must_use]
    pub fn unpersisted() -> Self {
        Self { value: 0 }
    }

    /// Get the current RSID value.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.value
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gbc_starts_at_zero() {
        let gbc = GlobalBlockCounter::new();
        assert_eq!(gbc.value(), 0);
    }

    #[test]
    fn gbc_increments() {
        let mut gbc = GlobalBlockCounter::new();
        assert_eq!(gbc.increment(), 1);
        assert_eq!(gbc.increment(), 2);
        assert_eq!(gbc.increment(), 3);
    }

    #[test]
    fn gbc_wraps_at_max() {
        let mut gbc = GlobalBlockCounter::with_value(MAX_GBC);
        assert!(gbc.is_ok());
        if let Ok(ref mut gbc) = gbc {
            assert_eq!(gbc.value(), MAX_GBC);
            assert_eq!(gbc.increment(), 0);
        }
    }

    #[test]
    fn gbc_rejects_overflow() {
        assert!(GlobalBlockCounter::with_value(MAX_GBC + 1).is_err());
    }

    #[test]
    fn rsid_unpersisted() {
        let rsid = RebootSessionId::unpersisted();
        assert_eq!(rsid.value(), 0);
    }

    #[test]
    fn rsid_with_value() {
        let rsid = RebootSessionId::new(42);
        assert!(rsid.is_ok());
        if let Ok(rsid) = rsid {
            assert_eq!(rsid.value(), 42);
        }
    }

    #[test]
    fn rsid_rejects_overflow() {
        assert!(RebootSessionId::new(MAX_RSID + 1).is_err());
    }

    #[test]
    fn rsid_max_value_accepted() {
        let rsid = RebootSessionId::new(MAX_RSID);
        assert!(rsid.is_ok());
    }
}
