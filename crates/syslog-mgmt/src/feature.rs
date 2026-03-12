//! Feature flags for syslog capabilities.
//!
//! Uses bitflags to represent the set of features supported by a syslog
//! implementation, aligned with RFC 9742 capability reporting.

use bitflags::bitflags;

bitflags! {
    /// Bitflag set of syslog features/capabilities.
    ///
    /// RFC 9742 §5 — implementations report which features they support.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SyslogFeatures: u32 {
        /// UDP transport (RFC 5426).
        const UDP_TRANSPORT  = 0b0000_0000_0001;
        /// TCP transport (RFC 6587).
        const TCP_TRANSPORT  = 0b0000_0000_0010;
        /// TLS transport (RFC 5425).
        const TLS_TRANSPORT  = 0b0000_0000_0100;
        /// DTLS transport (RFC 6012).
        const DTLS_TRANSPORT = 0b0000_0000_1000;
        /// RFC 5424 message format support.
        const RFC5424_FORMAT = 0b0000_0001_0000;
        /// RFC 3164 (BSD) message format support.
        const RFC3164_FORMAT = 0b0000_0010_0000;
        /// Structured data support (RFC 5424 §6.3).
        const STRUCTURED_DATA = 0b0000_0100_0000;
        /// Signed syslog messages (RFC 5848).
        const SIGNING         = 0b0000_1000_0000;
        /// Relay/forwarding capability.
        const RELAY           = 0b0001_0000_0000;
        /// Alarm/notification capability.
        const ALARM           = 0b0010_0000_0000;
    }
}

impl SyslogFeatures {
    /// Returns `true` if any transport capability is enabled.
    #[must_use]
    pub fn is_transport_capable(self) -> bool {
        self.intersects(
            Self::UDP_TRANSPORT | Self::TCP_TRANSPORT | Self::TLS_TRANSPORT | Self::DTLS_TRANSPORT,
        )
    }

    /// Returns `true` if message signing is supported.
    #[must_use]
    pub fn supports_signing(self) -> bool {
        self.contains(Self::SIGNING)
    }

    /// Returns `true` if relay/forwarding is supported.
    #[must_use]
    pub fn supports_relay(self) -> bool {
        self.contains(Self::RELAY)
    }

    /// Returns the default feature set for a typical syslog relay.
    #[must_use]
    pub fn default_relay() -> Self {
        Self::UDP_TRANSPORT
            | Self::TCP_TRANSPORT
            | Self::TLS_TRANSPORT
            | Self::RFC5424_FORMAT
            | Self::RFC3164_FORMAT
            | Self::STRUCTURED_DATA
            | Self::RELAY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_features() {
        let f = SyslogFeatures::empty();
        assert!(f.is_empty());
        assert!(!f.is_transport_capable());
        assert!(!f.supports_signing());
    }

    #[test]
    fn single_udp_transport() {
        let f = SyslogFeatures::UDP_TRANSPORT;
        assert!(f.is_transport_capable());
        assert!(!f.supports_signing());
    }

    #[test]
    fn single_tcp_transport() {
        let f = SyslogFeatures::TCP_TRANSPORT;
        assert!(f.is_transport_capable());
    }

    #[test]
    fn single_tls_transport() {
        let f = SyslogFeatures::TLS_TRANSPORT;
        assert!(f.is_transport_capable());
    }

    #[test]
    fn single_dtls_transport() {
        let f = SyslogFeatures::DTLS_TRANSPORT;
        assert!(f.is_transport_capable());
    }

    #[test]
    fn signing_flag() {
        let f = SyslogFeatures::SIGNING;
        assert!(f.supports_signing());
        assert!(!f.is_transport_capable());
    }

    #[test]
    fn relay_flag() {
        let f = SyslogFeatures::RELAY;
        assert!(f.supports_relay());
        assert!(!f.is_transport_capable());
    }

    #[test]
    fn combined_features() {
        let f =
            SyslogFeatures::UDP_TRANSPORT | SyslogFeatures::TLS_TRANSPORT | SyslogFeatures::SIGNING;
        assert!(f.is_transport_capable());
        assert!(f.supports_signing());
        assert!(f.contains(SyslogFeatures::UDP_TRANSPORT));
        assert!(f.contains(SyslogFeatures::TLS_TRANSPORT));
        assert!(!f.contains(SyslogFeatures::TCP_TRANSPORT));
    }

    #[test]
    fn default_relay_features() {
        let f = SyslogFeatures::default_relay();
        assert!(f.is_transport_capable());
        assert!(f.supports_relay());
        assert!(!f.supports_signing());
        assert!(f.contains(SyslogFeatures::UDP_TRANSPORT));
        assert!(f.contains(SyslogFeatures::TCP_TRANSPORT));
        assert!(f.contains(SyslogFeatures::TLS_TRANSPORT));
        assert!(f.contains(SyslogFeatures::RFC5424_FORMAT));
        assert!(f.contains(SyslogFeatures::RFC3164_FORMAT));
        assert!(f.contains(SyslogFeatures::STRUCTURED_DATA));
    }

    #[test]
    fn bitwise_intersection() {
        let a = SyslogFeatures::UDP_TRANSPORT | SyslogFeatures::TCP_TRANSPORT;
        let b = SyslogFeatures::TCP_TRANSPORT | SyslogFeatures::TLS_TRANSPORT;
        let intersection = a & b;
        assert_eq!(intersection, SyslogFeatures::TCP_TRANSPORT);
    }

    #[test]
    fn bitwise_union() {
        let a = SyslogFeatures::UDP_TRANSPORT;
        let b = SyslogFeatures::TLS_TRANSPORT;
        let union = a | b;
        assert!(union.contains(SyslogFeatures::UDP_TRANSPORT));
        assert!(union.contains(SyslogFeatures::TLS_TRANSPORT));
    }

    #[test]
    fn bitwise_difference() {
        let f = SyslogFeatures::UDP_TRANSPORT | SyslogFeatures::TCP_TRANSPORT;
        let removed = f - SyslogFeatures::UDP_TRANSPORT;
        assert!(!removed.contains(SyslogFeatures::UDP_TRANSPORT));
        assert!(removed.contains(SyslogFeatures::TCP_TRANSPORT));
    }
}
