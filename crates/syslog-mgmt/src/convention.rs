//! RFC 5427 syslog MIB textual conventions.
//!
//! This module re-exports core protocol types with RFC 5427 §3 compliance
//! annotations and provides well-known constants for the management model.

use syslog_proto::{Facility, Severity};

/// RFC 5424 §6.1 SHOULD: Messages SHOULD be at most 2048 octets.
pub const MAX_MESSAGE_SIZE: usize = 2048;

/// Returns the RFC 5424 §6.1 recommended maximum message size (2048 octets).
#[must_use]
pub const fn max_message_size() -> usize {
    MAX_MESSAGE_SIZE
}

/// The total number of defined facility codes (RFC 5424 §6.2.1: 0-23).
pub const FACILITY_COUNT: usize = 24;

/// The total number of defined severity levels (RFC 5424 §6.2.1: 0-7).
pub const SEVERITY_COUNT: usize = 8;

/// RFC 5427 §3 — Returns the textual name for a facility value.
///
/// This is a convenience wrapper around [`Facility::name`].
#[must_use]
pub fn facility_name(facility: Facility) -> &'static str {
    facility.name()
}

/// RFC 5427 §3 — Returns the textual name for a severity value.
///
/// This is a convenience wrapper around [`Severity::name`].
#[must_use]
pub fn severity_name(severity: Severity) -> &'static str {
    severity.name()
}

/// RFC 5427 §3 — All defined facility values in numeric order.
#[must_use]
pub fn all_facilities() -> [Facility; 24] {
    [
        Facility::Kern,
        Facility::User,
        Facility::Mail,
        Facility::Daemon,
        Facility::Auth,
        Facility::Syslog,
        Facility::Lpr,
        Facility::News,
        Facility::Uucp,
        Facility::Cron,
        Facility::Authpriv,
        Facility::Ftp,
        Facility::Ntp,
        Facility::Audit,
        Facility::Alert,
        Facility::Clock,
        Facility::Local0,
        Facility::Local1,
        Facility::Local2,
        Facility::Local3,
        Facility::Local4,
        Facility::Local5,
        Facility::Local6,
        Facility::Local7,
    ]
}

/// OID prefix for syslog MIB objects (RFC 5427).
/// iso.org.dod.internet.private.enterprises.syslog = 1.3.6.1.2.1.192
pub const SYSLOG_MIB_OID_PREFIX: &str = "1.3.6.1.2.1.192";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_message_size_is_2048() {
        assert_eq!(max_message_size(), 2048);
        assert_eq!(MAX_MESSAGE_SIZE, 2048);
    }

    #[test]
    fn facility_count_is_24() {
        assert_eq!(FACILITY_COUNT, 24);
    }

    #[test]
    fn severity_count_is_8() {
        assert_eq!(SEVERITY_COUNT, 8);
    }

    #[test]
    fn facility_name_returns_rfc5427_names() {
        assert_eq!(facility_name(Facility::Kern), "kern");
        assert_eq!(facility_name(Facility::User), "user");
        assert_eq!(facility_name(Facility::Local7), "local7");
    }

    #[test]
    fn severity_name_returns_rfc5427_names() {
        assert_eq!(severity_name(Severity::Emergency), "emerg");
        assert_eq!(severity_name(Severity::Error), "err");
        assert_eq!(severity_name(Severity::Debug), "debug");
    }

    #[test]
    fn all_facilities_returns_24_entries() {
        let facilities = all_facilities();
        assert_eq!(facilities.len(), 24);
        assert_eq!(facilities.first().copied(), Some(Facility::Kern));
        assert_eq!(facilities.last().copied(), Some(Facility::Local7));
        // Verify first and last codes
        assert_eq!(Facility::Kern.code(), 0);
        assert_eq!(Facility::Local7.code(), 23);
    }

    #[test]
    fn syslog_mib_oid_prefix_is_correct() {
        assert!(SYSLOG_MIB_OID_PREFIX.starts_with("1.3.6.1.2.1.192"));
    }
}
