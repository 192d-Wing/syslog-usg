//! Configuration loading, validation, and environment variable substitution.
//!
//! Provides TOML-based configuration with `${VAR}` and `${VAR:-default}`
//! environment variable expansion.

pub mod convert;
pub mod error;
pub mod model;

use std::path::Path;

use crate::error::ConfigError;
use crate::model::{ActionTypeConfig, ListenerProtocol, OutputProtocol, ServerConfig};

/// Load a [`ServerConfig`] from a TOML file at `path`.
///
/// This function:
/// 1. Reads the file contents.
/// 2. Expands `${VAR}` and `${VAR:-default}` environment variable references.
/// 3. Parses the TOML into a [`ServerConfig`].
/// 4. Validates the resulting configuration.
pub fn load_config(path: &Path) -> Result<ServerConfig, ConfigError> {
    let raw = std::fs::read_to_string(path)?;
    let expanded = substitute_env_vars(&raw)?;
    let config: ServerConfig = toml::from_str(&expanded)?;
    validate(&config)?;
    Ok(config)
}

/// Load a [`ServerConfig`] directly from a TOML string (useful for testing).
///
/// Performs env-var substitution and validation just like [`load_config`].
pub fn load_config_str(toml_str: &str) -> Result<ServerConfig, ConfigError> {
    let expanded = substitute_env_vars(toml_str)?;
    let config: ServerConfig = toml::from_str(&expanded)?;
    validate(&config)?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// Environment variable substitution
// ---------------------------------------------------------------------------

/// Expand `${VAR}` and `${VAR:-default}` patterns in `input`.
///
/// - `${VAR}` is replaced by the value of the environment variable `VAR`.
///   If `VAR` is not set, an error is returned.
/// - `${VAR:-fallback}` is replaced by the value of `VAR` if set, otherwise
///   by `fallback`.
fn substitute_env_vars(input: &str) -> Result<String, ConfigError> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' {
            if chars.peek() == Some(&'{') {
                // consume '{'
                let _ = chars.next();
                // collect everything up to '}'
                let mut var_expr = String::new();
                let mut found_close = false;
                for c in chars.by_ref() {
                    if c == '}' {
                        found_close = true;
                        break;
                    }
                    var_expr.push(c);
                }
                if !found_close {
                    // Unterminated `${...` — treat literally.
                    result.push_str("${");
                    result.push_str(&var_expr);
                } else {
                    let resolved = resolve_var_expr(&var_expr)?;
                    result.push_str(&resolved);
                }
            } else {
                // Bare `$` not followed by `{` — keep as-is.
                result.push(ch);
            }
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

/// Resolve a single variable expression (the content between `${` and `}`).
///
/// Supports:
/// - `VAR`         — env var, error if not set
/// - `VAR:-default` — env var with fallback
fn resolve_var_expr(expr: &str) -> Result<String, ConfigError> {
    if let Some(sep_pos) = expr.find(":-") {
        let var_name = &expr[..sep_pos];
        let default_value = &expr[sep_pos + 2..];
        match std::env::var(var_name) {
            Ok(val) if !val.is_empty() => Ok(val),
            _ => Ok(default_value.to_owned()),
        }
    } else {
        std::env::var(expr).map_err(|_| ConfigError::EnvVarNotSet {
            name: expr.to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Check that a file path does not contain directory traversal sequences.
fn validate_path(path: &str, context: &str) -> Result<(), ConfigError> {
    if path.is_empty() {
        return Err(ConfigError::MissingField(context.to_owned()));
    }
    if path.contains("..") {
        return Err(ConfigError::Validation(format!(
            "{context}: path must not contain '..' (directory traversal)"
        )));
    }
    Ok(())
}

/// Validate a parsed [`ServerConfig`].
fn validate(config: &ServerConfig) -> Result<(), ConfigError> {
    // Validate listeners.
    for (i, listener) in config.listeners.iter().enumerate() {
        if listener.bind_address.is_empty() {
            return Err(ConfigError::MissingField(format!(
                "listeners[{i}].bind_address"
            )));
        }
        if listener.protocol == ListenerProtocol::Tls && listener.tls.is_none() {
            return Err(ConfigError::Validation(format!(
                "listeners[{i}]: TLS protocol requires a [tls] section"
            )));
        }
        if let Some(ref tls) = listener.tls {
            validate_path(&tls.cert_path, &format!("listeners[{i}].tls.cert_path"))?;
            validate_path(&tls.key_path, &format!("listeners[{i}].tls.key_path"))?;
            if let Some(ref ca) = tls.ca_path {
                validate_path(ca, &format!("listeners[{i}].tls.ca_path"))?;
            }
        }
        if listener.protocol == ListenerProtocol::Dtls && listener.tls.is_none() {
            return Err(ConfigError::Validation(format!(
                "listeners[{i}]: DTLS protocol requires a [tls] section"
            )));
        }
    }

    // Validate outputs.
    for (i, output) in config.outputs.iter().enumerate() {
        if output.name.is_empty() {
            return Err(ConfigError::MissingField(format!("outputs[{i}].name")));
        }
        if output.address.is_empty() {
            return Err(ConfigError::MissingField(format!("outputs[{i}].address")));
        }
        if output.protocol == OutputProtocol::Tls && output.tls.is_none() {
            return Err(ConfigError::Validation(format!(
                "outputs[{i}] ('{}'): TLS protocol requires a [tls] section",
                output.name
            )));
        }
        if let Some(ref tls) = output.tls {
            validate_path(&tls.cert_path, &format!("outputs[{i}].tls.cert_path"))?;
            validate_path(&tls.key_path, &format!("outputs[{i}].tls.key_path"))?;
            if let Some(ref ca) = tls.ca_path {
                validate_path(ca, &format!("outputs[{i}].tls.ca_path"))?;
            }
        }
        if output.protocol == OutputProtocol::Dtls && output.tls.is_none() {
            return Err(ConfigError::Validation(format!(
                "outputs[{i}] ('{}'): DTLS protocol requires a [tls] section",
                output.name
            )));
        }
    }

    // Pipeline sanity checks.
    if config.pipeline.channel_buffer_size == 0 {
        return Err(ConfigError::Validation(
            "pipeline.channel_buffer_size must be > 0".to_owned(),
        ));
    }
    if config.pipeline.channel_buffer_size > 1_000_000 {
        return Err(ConfigError::Validation(
            "pipeline.channel_buffer_size must be <= 1000000".to_owned(),
        ));
    }
    if config.pipeline.max_message_size == 0 {
        return Err(ConfigError::Validation(
            "pipeline.max_message_size must be > 0".to_owned(),
        ));
    }
    if config.pipeline.max_message_size > 2 * 1024 * 1024 {
        return Err(ConfigError::Validation(
            "pipeline.max_message_size must be <= 2097152 (2 MiB)".to_owned(),
        ));
    }

    // Listener connection limits.
    for (i, listener) in config.listeners.iter().enumerate() {
        if let Some(max) = listener.max_connections {
            if max > 100_000 {
                return Err(ConfigError::Validation(format!(
                    "listeners[{i}].max_connections must be <= 100000"
                )));
            }
        }
    }

    // Signing configuration validation (RFC 5848).
    if let Some(ref signing) = config.signing {
        if signing.enabled {
            if signing.key_path.is_empty() {
                return Err(ConfigError::MissingField("signing.key_path".to_owned()));
            }
            if let Some(ref algo) = signing.hash_algorithm {
                let valid = ["sha1", "sha256"];
                if !valid.contains(&algo.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "signing.hash_algorithm: unknown value {algo:?}, must be one of: {valid:?}"
                    )));
                }
            }
            if let Some(ref sg) = signing.signature_group {
                let valid = ["global", "per-pri", "pri-ranges", "custom"];
                if !valid.contains(&sg.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "signing.signature_group: unknown value {sg:?}, must be one of: {valid:?}"
                    )));
                }
            }
            if let Some(0) = signing.max_hashes_per_block {
                return Err(ConfigError::Validation(
                    "signing.max_hashes_per_block must be > 0".to_owned(),
                ));
            }
            if let Some(ref dir) = signing.state_dir {
                validate_path(dir, "signing.state_dir")?;
            }
        }
    }

    // Verification configuration validation (RFC 5848).
    if let Some(ref verification) = config.verification {
        if verification.enabled && verification.trusted_key_paths.is_empty() {
            return Err(ConfigError::Validation(
                "verification.trusted_key_paths must not be empty when verification is enabled"
                    .to_owned(),
            ));
        }
        if let Some(ref sp) = verification.state_path {
            validate_path(sp, "verification.state_path")?;
        }
    }

    // Management action validation (RFC 9742).
    for (i, action) in config.actions.iter().enumerate() {
        // Validate facility names if specified.
        if let Some(ref facilities) = action.selector.facilities {
            for f_name in facilities {
                if syslog_proto::Facility::try_from(f_name.as_str()).is_err() {
                    return Err(ConfigError::Validation(format!(
                        "actions[{i}].selector.facilities: unknown facility {f_name:?}"
                    )));
                }
            }
        }
        // Validate severity names.
        if let Some(ref sev) = action.selector.min_severity {
            if syslog_proto::Severity::try_from(sev.as_str()).is_err() {
                return Err(ConfigError::Validation(format!(
                    "actions[{i}].selector.min_severity: unknown severity {sev:?}"
                )));
            }
        }
        if let Some(ref sev) = action.selector.max_severity {
            if syslog_proto::Severity::try_from(sev.as_str()).is_err() {
                return Err(ConfigError::Validation(format!(
                    "actions[{i}].selector.max_severity: unknown severity {sev:?}"
                )));
            }
        }
        // Validate hostname/app_name patterns compile.
        if let Some(ref pat) = action.selector.hostname_pattern {
            if regex::Regex::new(pat).is_err() {
                return Err(ConfigError::Validation(format!(
                    "actions[{i}].selector.hostname_pattern: invalid regex {pat:?}"
                )));
            }
        }
        if let Some(ref pat) = action.selector.app_name_pattern {
            if regex::Regex::new(pat).is_err() {
                return Err(ConfigError::Validation(format!(
                    "actions[{i}].selector.app_name_pattern: invalid regex {pat:?}"
                )));
            }
        }
        // Validate action type specifics.
        match &action.action {
            ActionTypeConfig::Remote { protocol, .. } => {
                let valid = ["udp", "tcp", "tls"];
                if !valid.contains(&protocol.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "actions[{i}].action.protocol: must be one of {valid:?}, got {protocol:?}"
                    )));
                }
            }
            ActionTypeConfig::Buffer { size, .. } => {
                if *size == 0 {
                    return Err(ConfigError::Validation(format!(
                        "actions[{i}].action.size must be > 0"
                    )));
                }
            }
            ActionTypeConfig::File { path } => {
                validate_path(path, &format!("actions[{i}].action.path"))?;
            }
            ActionTypeConfig::Console | ActionTypeConfig::Discard => {}
        }
    }

    // Alarm filter validation (RFC 5674).
    if let Some(ref af) = config.pipeline.alarm_filter {
        if af.enabled {
            // Validate min_severity value if provided.
            if let Some(ref sev) = af.min_severity {
                let valid = [
                    "cleared",
                    "indeterminate",
                    "critical",
                    "major",
                    "minor",
                    "warning",
                ];
                if !valid.contains(&sev.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "pipeline.alarm_filter.min_severity: unknown value {sev:?}, \
                         must be one of: {valid:?}"
                    )));
                }
            }

            // Validate event type names.
            let valid_types = [
                "other",
                "communicationsAlarm",
                "qualityOfServiceAlarm",
                "processingErrorAlarm",
                "equipmentAlarm",
                "environmentalAlarm",
            ];
            for et in &af.event_types {
                if !valid_types.contains(&et.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "pipeline.alarm_filter.event_types: unknown type {et:?}, \
                         must be one of: {valid_types:?}"
                    )));
                }
            }

            // Validate non_alarm_policy.
            if let Some(ref policy) = af.non_alarm_policy {
                if policy != "pass" && policy != "drop" {
                    return Err(ConfigError::Validation(format!(
                        "pipeline.alarm_filter.non_alarm_policy: must be \"pass\" or \"drop\", \
                         got {policy:?}"
                    )));
                }
            }

            // Validate max_active_alarms.
            if let Some(0) = af.max_active_alarms {
                return Err(ConfigError::Validation(
                    "pipeline.alarm_filter.max_active_alarms must be > 0".to_owned(),
                ));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    // A variable name that is virtually guaranteed to never be set.
    const UNSET_VAR: &str = "_SYSLOG_CFG_TEST_GUARANTEED_UNSET_9f8a7b6c_";

    // -- env var substitution ------------------------------------------------

    #[test]
    fn test_substitute_known_var() {
        // HOME is always set on macOS / Linux.
        let home = match std::env::var("HOME") {
            Ok(v) => v,
            Err(_) => return, // skip if somehow unset
        };
        let input = "dir = \"${HOME}/logs\"";
        let out = match substitute_env_vars(input) {
            Ok(v) => v,
            Err(_) => return,
        };
        assert_eq!(out, format!("dir = \"{home}/logs\""));
    }

    #[test]
    fn test_substitute_var_with_default_when_set() {
        // HOME is set, so the default should be ignored.
        let home = match std::env::var("HOME") {
            Ok(v) => v,
            Err(_) => return,
        };
        let input = "dir = \"${HOME:-/fallback}\"";
        let out = match substitute_env_vars(input) {
            Ok(v) => v,
            Err(_) => return,
        };
        assert_eq!(out, format!("dir = \"{home}\""));
    }

    #[test]
    fn test_substitute_var_with_default_when_unset() {
        let input = format!("port = \"${{{UNSET_VAR}:-514}}\"");
        let out = match substitute_env_vars(&input) {
            Ok(v) => v,
            Err(_) => return,
        };
        assert_eq!(out, "port = \"514\"");
    }

    #[test]
    fn test_substitute_missing_var_errors() {
        let input = format!("host = \"${{{UNSET_VAR}}}\"");
        let result = substitute_env_vars(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_substitute_no_vars() {
        let input = "host = \"localhost\"";
        let out = substitute_env_vars(input).unwrap_or_default();
        assert_eq!(out, input);
    }

    #[test]
    fn test_substitute_bare_dollar() {
        let input = "price = $5";
        let out = substitute_env_vars(input).unwrap_or_default();
        assert_eq!(out, "price = $5");
    }

    #[test]
    fn test_substitute_unterminated_brace() {
        let input = "val = ${OPEN";
        let out = substitute_env_vars(input).unwrap_or_default();
        assert_eq!(out, "val = ${OPEN");
    }

    // -- full config parsing -------------------------------------------------

    #[test]
    fn test_minimal_config() {
        let toml = "";
        let cfg = load_config_str(toml);
        assert!(cfg.is_ok());
        let cfg = match cfg {
            Ok(v) => v,
            Err(_) => return,
        };
        assert_eq!(cfg.server.drain_timeout_seconds, 5);
        assert!(cfg.listeners.is_empty());
        assert!(cfg.outputs.is_empty());
        assert_eq!(cfg.pipeline.channel_buffer_size, 4096);
        assert_eq!(cfg.pipeline.max_message_size, 8192);
        assert_eq!(cfg.logging.level, "info");
        assert_eq!(cfg.logging.format, LogFormat::Text);
        assert!(!cfg.metrics.enabled);
        assert_eq!(cfg.metrics.bind_address, "127.0.0.1:9090");
    }

    #[test]
    fn test_full_config() {
        let toml = r#"
[server]
drain_timeout_seconds = 10

[[listeners]]
protocol = "udp"
bind_address = "0.0.0.0:514"

[[listeners]]
protocol = "tls"
bind_address = "0.0.0.0:6514"
[listeners.tls]
cert_path = "/etc/ssl/cert.pem"
key_path = "/etc/ssl/key.pem"
client_auth = true
ca_path = "/etc/ssl/ca.pem"

[[outputs]]
name = "central"
protocol = "tcp"
address = "10.0.0.2:514"

[[outputs]]
name = "secure"
protocol = "tls"
address = "10.0.0.3:6514"
[outputs.tls]
cert_path = "/etc/ssl/relay-cert.pem"
key_path = "/etc/ssl/relay-key.pem"

[pipeline]
channel_buffer_size = 8192
max_message_size = 16384

[logging]
level = "debug"
format = "json"

[metrics]
enabled = true
bind_address = "127.0.0.1:9091"
"#;
        let cfg = load_config_str(toml);
        assert!(cfg.is_ok());
        let cfg = match cfg {
            Ok(v) => v,
            Err(_) => return,
        };

        assert_eq!(cfg.server.drain_timeout_seconds, 10);
        assert_eq!(cfg.listeners.len(), 2);

        let udp = match cfg.listeners.first() {
            Some(v) => v,
            None => return,
        };
        assert_eq!(udp.protocol, ListenerProtocol::Udp);
        assert_eq!(udp.bind_address, "0.0.0.0:514");
        assert!(udp.tls.is_none());

        let tls = match cfg.listeners.get(1) {
            Some(v) => v,
            None => return,
        };
        assert_eq!(tls.protocol, ListenerProtocol::Tls);
        assert!(tls.tls.is_some());
        if let Some(ref tls_cfg) = tls.tls {
            assert_eq!(tls_cfg.cert_path, "/etc/ssl/cert.pem");
            assert!(tls_cfg.client_auth);
            assert_eq!(tls_cfg.ca_path.as_deref(), Some("/etc/ssl/ca.pem"));
        }

        assert_eq!(cfg.outputs.len(), 2);
        let out0 = match cfg.outputs.first() {
            Some(v) => v,
            None => return,
        };
        assert_eq!(out0.name, "central");
        assert_eq!(out0.protocol, OutputProtocol::Tcp);
        assert!(out0.tls.is_none());

        let out1 = match cfg.outputs.get(1) {
            Some(v) => v,
            None => return,
        };
        assert_eq!(out1.name, "secure");
        assert_eq!(out1.protocol, OutputProtocol::Tls);
        assert!(out1.tls.is_some());

        assert_eq!(cfg.pipeline.channel_buffer_size, 8192);
        assert_eq!(cfg.pipeline.max_message_size, 16384);
        assert_eq!(cfg.logging.level, "debug");
        assert_eq!(cfg.logging.format, LogFormat::Json);
        assert!(cfg.metrics.enabled);
        assert_eq!(cfg.metrics.bind_address, "127.0.0.1:9091");
    }

    // -- validation ----------------------------------------------------------

    #[test]
    fn test_tls_listener_without_tls_section_fails() {
        let toml = r#"
[[listeners]]
protocol = "tls"
bind_address = "0.0.0.0:6514"
"#;
        let result = load_config_str(toml);
        assert!(matches!(
            result,
            Err(ConfigError::Validation(ref msg)) if msg.contains("TLS protocol requires a [tls] section")
        ));
    }

    #[test]
    fn test_tls_output_without_tls_section_fails() {
        let toml = r#"
[[outputs]]
name = "broken"
protocol = "tls"
address = "10.0.0.1:6514"
"#;
        let result = load_config_str(toml);
        assert!(matches!(
            result,
            Err(ConfigError::Validation(ref msg)) if msg.contains("TLS protocol requires a [tls] section")
        ));
    }

    #[test]
    fn test_empty_bind_address_fails() {
        let toml = r#"
[[listeners]]
protocol = "udp"
bind_address = ""
"#;
        let result = load_config_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_output_name_fails() {
        let toml = r#"
[[outputs]]
name = ""
protocol = "tcp"
address = "10.0.0.1:514"
"#;
        let result = load_config_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_channel_buffer_fails() {
        let toml = r#"
[pipeline]
channel_buffer_size = 0
"#;
        let result = load_config_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_max_message_size_fails() {
        let toml = r#"
[pipeline]
max_message_size = 0
"#;
        let result = load_config_str(toml);
        assert!(result.is_err());
    }

    // -- env var integration in config loading --------------------------------

    #[test]
    fn test_env_var_default_in_config() {
        // Use a variable guaranteed not to be set, so the default kicks in.
        let toml = format!("[logging]\nlevel = \"${{{UNSET_VAR}:-warn}}\"\n");
        let cfg = match load_config_str(&toml) {
            Ok(v) => v,
            Err(_) => return,
        };
        assert_eq!(cfg.logging.level, "warn");
    }

    // -- load_config with file -----------------------------------------------

    #[test]
    fn test_load_config_file_not_found() {
        let result = load_config(Path::new("/tmp/__nonexistent_syslog_cfg__.toml"));
        assert!(result.is_err());
        assert!(matches!(result, Err(ConfigError::ReadFile(_))));
    }

    #[test]
    fn test_load_config_from_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("syslog_config_test.toml");
        let toml = r#"
[server]
drain_timeout_seconds = 3

[logging]
level = "trace"
format = "json"
"#;
        // Write test file — if this fails the test should just bail.
        if std::fs::write(&path, toml).is_err() {
            return;
        }
        let cfg = load_config(&path);
        // clean up
        let _ = std::fs::remove_file(&path);

        assert!(cfg.is_ok());
        let cfg = match cfg {
            Ok(v) => v,
            Err(_) => return,
        };
        assert_eq!(cfg.server.drain_timeout_seconds, 3);
        assert_eq!(cfg.logging.level, "trace");
        assert_eq!(cfg.logging.format, LogFormat::Json);
    }
}
