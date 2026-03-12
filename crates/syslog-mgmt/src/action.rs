//! Action types for the syslog management model.
//!
//! An [`Action`] pairs a [`Selector`] with an [`ActionType`] to define
//! what should happen to matching syslog messages.

use crate::selector::Selector;
use std::path::PathBuf;

/// Transport protocol for remote syslog forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// UDP transport (RFC 5426).
    Udp,
    /// TCP transport (RFC 6587).
    Tcp,
    /// TLS transport (RFC 5425).
    Tls,
}

impl core::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Udp => f.write_str("udp"),
            Self::Tcp => f.write_str("tcp"),
            Self::Tls => f.write_str("tls"),
        }
    }
}

/// The type of action to take on matching messages.
#[derive(Debug, Clone)]
pub enum ActionType {
    /// Write to the system console / stdout.
    Console,
    /// Write to a file at the given path.
    File {
        /// Destination file path.
        path: PathBuf,
    },
    /// Forward to a remote syslog receiver.
    Remote {
        /// Remote host address.
        host: String,
        /// Remote port number.
        port: u16,
        /// Transport protocol to use.
        protocol: TransportProtocol,
    },
    /// Buffer messages in a named in-memory buffer.
    Buffer {
        /// Buffer name.
        name: String,
        /// Maximum number of messages to buffer.
        size: usize,
    },
    /// Discard matching messages (black hole).
    Discard,
}

/// An action pairs a selector (which messages) with an action type (what to do).
///
/// RFC 9742 §4 — actions are the primary configuration construct for
/// controlling syslog message disposition.
#[derive(Debug)]
pub struct Action {
    /// Selector determining which messages this action applies to.
    pub selector: Selector,
    /// The type of action to perform.
    pub action_type: ActionType,
    /// Optional human-readable description.
    pub description: Option<String>,
}

impl Action {
    /// Create a new action with the given selector and action type.
    #[must_use]
    pub fn new(selector: Selector, action_type: ActionType) -> Self {
        Self {
            selector,
            action_type,
            description: None,
        }
    }

    /// Set a description for this action.
    #[must_use]
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_action_construction() {
        let action = Action::new(Selector::new(), ActionType::Console);
        assert!(matches!(action.action_type, ActionType::Console));
        assert!(action.description.is_none());
    }

    #[test]
    fn file_action_construction() {
        let action = Action::new(
            Selector::new(),
            ActionType::File {
                path: PathBuf::from("/var/log/syslog"),
            },
        );
        assert!(matches!(action.action_type, ActionType::File { .. }));
        if let ActionType::File { ref path } = action.action_type {
            assert_eq!(path, &PathBuf::from("/var/log/syslog"));
        }
    }

    #[test]
    fn remote_action_construction() {
        let action = Action::new(
            Selector::new(),
            ActionType::Remote {
                host: "10.0.0.1".to_owned(),
                port: 514,
                protocol: TransportProtocol::Udp,
            },
        );
        assert!(matches!(action.action_type, ActionType::Remote { .. }));
        if let ActionType::Remote {
            ref host,
            port,
            protocol,
        } = action.action_type
        {
            assert_eq!(host, "10.0.0.1");
            assert_eq!(port, 514);
            assert_eq!(protocol, TransportProtocol::Udp);
        }
    }

    #[test]
    fn buffer_action_construction() {
        let action = Action::new(
            Selector::new(),
            ActionType::Buffer {
                name: "alerts".to_owned(),
                size: 1000,
            },
        );
        assert!(matches!(action.action_type, ActionType::Buffer { .. }));
        if let ActionType::Buffer { ref name, size } = action.action_type {
            assert_eq!(name, "alerts");
            assert_eq!(size, 1000);
        }
    }

    #[test]
    fn discard_action_construction() {
        let action = Action::new(Selector::new(), ActionType::Discard);
        assert!(matches!(action.action_type, ActionType::Discard));
    }

    #[test]
    fn action_with_description() {
        let action = Action::new(Selector::new(), ActionType::Console)
            .with_description("Log emergencies to console".to_owned());
        assert_eq!(
            action.description.as_deref(),
            Some("Log emergencies to console")
        );
    }

    #[test]
    fn transport_protocol_display() {
        assert_eq!(format!("{}", TransportProtocol::Udp), "udp");
        assert_eq!(format!("{}", TransportProtocol::Tcp), "tcp");
        assert_eq!(format!("{}", TransportProtocol::Tls), "tls");
    }

    #[test]
    fn transport_protocol_equality() {
        assert_eq!(TransportProtocol::Udp, TransportProtocol::Udp);
        assert_ne!(TransportProtocol::Udp, TransportProtocol::Tcp);
        assert_ne!(TransportProtocol::Tcp, TransportProtocol::Tls);
    }

    #[test]
    fn remote_tls_action() {
        let action = Action::new(
            Selector::new(),
            ActionType::Remote {
                host: "secure.example.com".to_owned(),
                port: 6514,
                protocol: TransportProtocol::Tls,
            },
        );
        assert!(matches!(action.action_type, ActionType::Remote { .. }));
        if let ActionType::Remote { protocol, .. } = action.action_type {
            assert_eq!(protocol, TransportProtocol::Tls);
        }
    }

    #[test]
    fn remote_tcp_action() {
        let action = Action::new(
            Selector::new(),
            ActionType::Remote {
                host: "relay.local".to_owned(),
                port: 1514,
                protocol: TransportProtocol::Tcp,
            },
        );
        assert!(matches!(action.action_type, ActionType::Remote { .. }));
        if let ActionType::Remote { protocol, port, .. } = action.action_type {
            assert_eq!(protocol, TransportProtocol::Tcp);
            assert_eq!(port, 1514);
        }
    }
}
