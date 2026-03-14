//! Conversion functions from config model types to management model types.
//!
//! Converts [`MgmtActionConfig`], [`SelectorConfig`], and [`ActionTypeConfig`]
//! from the TOML configuration into the runtime [`syslog_mgmt`] types.

use std::path::PathBuf;

use crate::error::ConfigError;
use crate::model::{ActionTypeConfig, MgmtActionConfig, SelectorConfig};

/// Convert a [`SelectorConfig`] into a [`syslog_mgmt::Selector`].
///
/// # Errors
///
/// Returns [`ConfigError::Validation`] if facility names, severity names,
/// or regex patterns are invalid.
pub fn convert_selector(cfg: &SelectorConfig) -> Result<syslog_mgmt::Selector, ConfigError> {
    let mut selector = syslog_mgmt::Selector::new();

    if let Some(ref facility_names) = cfg.facilities {
        let mut facilities = Vec::with_capacity(facility_names.len());
        for name in facility_names {
            let f = syslog_proto::Facility::try_from(name.as_str())
                .map_err(|_| ConfigError::Validation(format!("unknown facility: {name:?}")))?;
            facilities.push(f);
        }
        selector = selector.with_facilities(facilities);
    }

    if let Some(ref sev_name) = cfg.min_severity {
        let sev = syslog_proto::Severity::try_from(sev_name.as_str())
            .map_err(|_| ConfigError::Validation(format!("unknown severity: {sev_name:?}")))?;
        selector = selector.with_min_severity(sev);
    }

    if let Some(ref sev_name) = cfg.max_severity {
        let sev = syslog_proto::Severity::try_from(sev_name.as_str())
            .map_err(|_| ConfigError::Validation(format!("unknown severity: {sev_name:?}")))?;
        selector = selector.with_max_severity(sev);
    }

    if let Some(ref pat) = cfg.hostname_pattern {
        selector = selector
            .with_hostname_pattern(pat)
            .map_err(|e| ConfigError::Validation(format!("hostname pattern: {e}")))?;
    }

    if let Some(ref pat) = cfg.app_name_pattern {
        selector = selector
            .with_app_name_pattern(pat)
            .map_err(|e| ConfigError::Validation(format!("app_name pattern: {e}")))?;
    }

    Ok(selector)
}

/// Convert an [`ActionTypeConfig`] into a [`syslog_mgmt::ActionType`].
///
/// # Errors
///
/// Returns [`ConfigError::Validation`] if the protocol string is unknown.
pub fn convert_action_type(cfg: &ActionTypeConfig) -> Result<syslog_mgmt::ActionType, ConfigError> {
    match cfg {
        ActionTypeConfig::Console => Ok(syslog_mgmt::ActionType::Console),
        ActionTypeConfig::File { path } => Ok(syslog_mgmt::ActionType::File {
            path: PathBuf::from(path),
        }),
        ActionTypeConfig::Remote {
            host,
            port,
            protocol,
        } => {
            let proto = match protocol.as_str() {
                "udp" => syslog_mgmt::TransportProtocol::Udp,
                "tcp" => syslog_mgmt::TransportProtocol::Tcp,
                "tls" => syslog_mgmt::TransportProtocol::Tls,
                other => {
                    return Err(ConfigError::Validation(format!(
                        "unknown transport protocol: {other:?}"
                    )));
                }
            };
            Ok(syslog_mgmt::ActionType::Remote {
                host: host.clone(),
                port: *port,
                protocol: proto,
            })
        }
        ActionTypeConfig::Buffer { name, size } => Ok(syslog_mgmt::ActionType::Buffer {
            name: name.clone(),
            size: *size,
        }),
        ActionTypeConfig::Discard => Ok(syslog_mgmt::ActionType::Discard),
    }
}

/// Convert a [`MgmtActionConfig`] into a [`syslog_mgmt::Action`].
///
/// # Errors
///
/// Returns [`ConfigError`] if the selector or action type is invalid.
pub fn convert_action(cfg: &MgmtActionConfig) -> Result<syslog_mgmt::Action, ConfigError> {
    let selector = convert_selector(&cfg.selector)?;
    let action_type = convert_action_type(&cfg.action)?;
    let mut action = syslog_mgmt::Action::new(selector, action_type);
    if let Some(ref desc) = cfg.description {
        action = action.with_description(desc.clone());
    }
    Ok(action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_empty_selector() {
        let cfg = SelectorConfig::default();
        let sel = convert_selector(&cfg);
        assert!(sel.is_ok());
    }

    #[test]
    fn convert_selector_with_facilities() {
        let cfg = SelectorConfig {
            facilities: Some(vec!["kern".to_owned(), "user".to_owned()]),
            ..Default::default()
        };
        let sel = convert_selector(&cfg);
        assert!(sel.is_ok());
    }

    #[test]
    fn convert_selector_bad_facility() {
        let cfg = SelectorConfig {
            facilities: Some(vec!["bogus".to_owned()]),
            ..Default::default()
        };
        let sel = convert_selector(&cfg);
        assert!(sel.is_err());
    }

    #[test]
    fn convert_selector_with_severity() {
        let cfg = SelectorConfig {
            min_severity: Some("warning".to_owned()),
            max_severity: Some("emerg".to_owned()),
            ..Default::default()
        };
        let sel = convert_selector(&cfg);
        assert!(sel.is_ok());
    }

    #[test]
    fn convert_selector_bad_severity() {
        let cfg = SelectorConfig {
            min_severity: Some("bogus".to_owned()),
            ..Default::default()
        };
        let sel = convert_selector(&cfg);
        assert!(sel.is_err());
    }

    #[test]
    fn convert_action_type_console() {
        let cfg = ActionTypeConfig::Console;
        let at = convert_action_type(&cfg);
        assert!(at.is_ok());
        assert!(matches!(at.ok(), Some(syslog_mgmt::ActionType::Console)));
    }

    #[test]
    fn convert_action_type_remote_udp() {
        let cfg = ActionTypeConfig::Remote {
            host: "10.0.0.1".to_owned(),
            port: 514,
            protocol: "udp".to_owned(),
        };
        let at = convert_action_type(&cfg);
        assert!(at.is_ok());
    }

    #[test]
    fn convert_action_type_remote_bad_protocol() {
        let cfg = ActionTypeConfig::Remote {
            host: "10.0.0.1".to_owned(),
            port: 514,
            protocol: "dtls".to_owned(),
        };
        let at = convert_action_type(&cfg);
        assert!(at.is_err());
    }

    #[test]
    fn convert_full_action() {
        let cfg = MgmtActionConfig {
            description: Some("test action".to_owned()),
            selector: SelectorConfig {
                facilities: Some(vec!["user".to_owned()]),
                ..Default::default()
            },
            action: ActionTypeConfig::Console,
        };
        let action = convert_action(&cfg);
        assert!(action.is_ok());
        if let Ok(a) = action {
            assert_eq!(a.description.as_deref(), Some("test action"));
        }
    }

    #[test]
    fn convert_selector_with_hostname_pattern() {
        let cfg = SelectorConfig {
            hostname_pattern: Some(r"^web".to_owned()),
            ..Default::default()
        };
        let sel = convert_selector(&cfg);
        assert!(sel.is_ok());
    }

    #[test]
    fn convert_selector_bad_hostname_pattern() {
        let cfg = SelectorConfig {
            hostname_pattern: Some("[bad".to_owned()),
            ..Default::default()
        };
        let sel = convert_selector(&cfg);
        assert!(sel.is_err());
    }
}
