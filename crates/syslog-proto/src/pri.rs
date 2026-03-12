// RFC 5424 §6.2.1 — PRI (Priority) value
// PRI = Facility * 8 + Severity, range 0-191

use crate::facility::Facility;
use crate::severity::Severity;

/// The priority value of a syslog message, encoding both facility and severity.
///
/// PRI = Facility * 8 + Severity (RFC 5424 §6.2.1).
/// Valid range: 0-191.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pri(u8);

/// Error returned when a PRI value is out of the valid range (0-191).
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid PRI value: {0} (must be 0-191)")]
pub struct InvalidPri(pub u8);

impl Pri {
    // RFC 5424 §6.2.1 MUST: PRI values range from 0 to 191
    const MAX: u8 = 191;

    /// Construct a `Pri` from a facility and severity.
    #[must_use]
    pub const fn new(facility: Facility, severity: Severity) -> Self {
        Self(facility.code() * 8 + severity.code())
    }

    /// Decode the facility from this priority value.
    #[must_use]
    pub fn facility(self) -> Facility {
        // Safe: self.0 / 8 is always 0-23 for valid Pri (0-191)
        match Facility::try_from(self.0 / 8) {
            Ok(f) => f,
            Err(_) => {
                // This branch is unreachable for valid Pri values (0-191),
                // since 191 / 8 == 23 which is the max facility code.
                // Default to Kern as a safe fallback.
                Facility::Kern
            }
        }
    }

    /// Decode the severity from this priority value.
    #[must_use]
    pub fn severity(self) -> Severity {
        // Safe: self.0 % 8 is always 0-7
        match Severity::try_from(self.0 % 8) {
            Ok(s) => s,
            Err(_) => {
                // Unreachable for valid Pri values since % 8 is always 0-7
                Severity::Emergency
            }
        }
    }

    /// Returns the raw numeric PRI value.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for Pri {
    type Error = InvalidPri;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > Self::MAX {
            Err(InvalidPri(value))
        } else {
            Ok(Self(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_encodes_correctly() {
        // RFC 5424 §6.2.1: PRI = Facility * 8 + Severity
        let pri = Pri::new(Facility::Kern, Severity::Emergency);
        assert_eq!(pri.value(), 0);

        let pri = Pri::new(Facility::Local7, Severity::Debug);
        assert_eq!(pri.value(), 191);

        let pri = Pri::new(Facility::Mail, Severity::Critical);
        assert_eq!(pri.value(), 2 * 8 + 2);
    }

    #[test]
    fn decode_roundtrip() {
        for fac_code in 0u8..24 {
            for sev_code in 0u8..8 {
                let facility = Facility::try_from(fac_code);
                let severity = Severity::try_from(sev_code);
                assert!(facility.is_ok());
                assert!(severity.is_ok());
                if let (Ok(f), Ok(s)) = (facility, severity) {
                    let pri = Pri::new(f, s);
                    assert_eq!(pri.facility(), f);
                    assert_eq!(pri.severity(), s);
                }
            }
        }
    }

    #[test]
    fn try_from_u8_valid() {
        for val in 0u8..=191 {
            let pri = Pri::try_from(val);
            assert!(pri.is_ok());
            assert_eq!(pri.ok().map(|p| p.value()), Some(val));
        }
    }

    #[test]
    fn try_from_u8_invalid() {
        for val in 192u8..=255 {
            assert!(Pri::try_from(val).is_err());
        }
    }

    #[test]
    fn boundary_values() {
        // Min: kern.emerg
        let pri = Pri::try_from(0);
        assert!(pri.is_ok());
        if let Ok(p) = pri {
            assert_eq!(p.facility(), Facility::Kern);
            assert_eq!(p.severity(), Severity::Emergency);
        }

        // Max: local7.debug
        let pri = Pri::try_from(191);
        assert!(pri.is_ok());
        if let Ok(p) = pri {
            assert_eq!(p.facility(), Facility::Local7);
            assert_eq!(p.severity(), Severity::Debug);
        }

        // Just over max
        assert!(Pri::try_from(192).is_err());
    }
}
