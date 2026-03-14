//! Configuration model structs.
//!
//! All config structs derive `Deserialize` for TOML loading.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Top-level
// ---------------------------------------------------------------------------

/// Top-level server configuration, representing the full TOML file.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ServerConfig {
    /// General server settings.
    #[serde(default)]
    pub server: ServerSettings,

    /// Listener definitions (UDP, TCP, TLS).
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,

    /// Relay / forwarding outputs.
    #[serde(default)]
    pub outputs: Vec<OutputConfig>,

    /// Internal pipeline tuning.
    #[serde(default)]
    pub pipeline: PipelineConfig,

    /// RFC 5848 message signing configuration.
    #[serde(default)]
    pub signing: Option<SigningConfig>,

    /// RFC 5848 message verification configuration.
    #[serde(default)]
    pub verification: Option<VerificationConfig>,

    /// Logging settings.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Prometheus metrics settings.
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Management actions (RFC 9742 selector + action pairs).
    #[serde(default)]
    pub actions: Vec<MgmtActionConfig>,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Server-wide operational settings.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ServerSettings {
    /// Graceful shutdown drain timeout in seconds.
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_seconds: u64,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            drain_timeout_seconds: default_drain_timeout(),
        }
    }
}

fn default_drain_timeout() -> u64 {
    5
}

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

/// The transport protocol a listener should use.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListenerProtocol {
    Udp,
    Tcp,
    Tls,
    Dtls,
}

/// Configuration for a single listener (inbound socket).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ListenerConfig {
    /// Transport protocol.
    pub protocol: ListenerProtocol,

    /// Bind address, e.g. `"0.0.0.0:514"`.
    pub bind_address: String,

    /// Optional TLS settings (required when `protocol` is `tls`).
    pub tls: Option<TlsConfig>,

    /// Maximum concurrent connections for TCP/TLS listeners.
    #[serde(default)]
    pub max_connections: Option<usize>,

    /// Per-frame read timeout in seconds for TCP/TLS listeners.
    #[serde(default)]
    pub read_timeout_secs: Option<u64>,
}

/// TLS configuration shared by listeners and outputs.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TlsConfig {
    /// Path to PEM certificate file.
    pub cert_path: String,

    /// Path to PEM private-key file.
    pub key_path: String,

    /// Whether to require and verify client certificates.
    #[serde(default)]
    pub client_auth: bool,

    /// Optional path to a CA bundle for verifying client certificates.
    pub ca_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Outputs (relay / forwarding)
// ---------------------------------------------------------------------------

/// The transport protocol for a relay output.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutputProtocol {
    Udp,
    Tcp,
    Tls,
    Dtls,
}

/// A single relay-forwarding destination.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OutputConfig {
    /// Friendly name for this output.
    pub name: String,

    /// Transport protocol.
    pub protocol: OutputProtocol,

    /// Destination address, e.g. `"10.0.0.2:514"`.
    pub address: String,

    /// Optional TLS settings (required when `protocol` is `tls`).
    pub tls: Option<TlsConfig>,
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/// Internal pipeline tuning knobs.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PipelineConfig {
    /// Capacity of the internal async channel between the listener and the
    /// processing pipeline.
    #[serde(default = "default_channel_buffer_size")]
    pub channel_buffer_size: usize,

    /// Maximum accepted syslog message size in bytes.
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,

    /// Optional alarm filter configuration (RFC 5674).
    #[serde(default)]
    pub alarm_filter: Option<AlarmFilterConfig>,

    /// When true, signing failures forward the original unsigned message
    /// (fail-open). When false, messages are dropped on signing failure
    /// (fail-closed). Defaults to true for backward compatibility.
    #[serde(default = "default_signing_fail_open")]
    pub signing_fail_open: bool,
}

/// RFC 5674 alarm-aware filter configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
pub struct AlarmFilterConfig {
    /// Whether the alarm filter is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Minimum perceived severity (e.g., "major", "critical").
    pub min_severity: Option<String>,

    /// Allowed ITU event type names (e.g., "communicationsAlarm").
    #[serde(default)]
    pub event_types: Vec<String>,

    /// Resource substring patterns for matching.
    #[serde(default)]
    pub resource_patterns: Vec<String>,

    /// Policy for non-alarm messages: "pass" (default) or "drop".
    pub non_alarm_policy: Option<String>,

    /// Maximum number of active alarms to track in the state table.
    pub max_active_alarms: Option<usize>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            channel_buffer_size: default_channel_buffer_size(),
            max_message_size: default_max_message_size(),
            alarm_filter: None,
            signing_fail_open: default_signing_fail_open(),
        }
    }
}

fn default_signing_fail_open() -> bool {
    true
}

fn default_channel_buffer_size() -> usize {
    4096
}

fn default_max_message_size() -> usize {
    8192
}

// ---------------------------------------------------------------------------
// Signing (RFC 5848)
// ---------------------------------------------------------------------------

/// RFC 5848 message signing configuration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SigningConfig {
    /// Whether signing is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Path to the PKCS#8 DER-encoded private key file.
    pub key_path: String,

    /// Path to the DER-encoded X.509 certificate file (optional).
    pub cert_path: Option<String>,

    /// Hash algorithm: "sha256" (default) or "sha1".
    pub hash_algorithm: Option<String>,

    /// Signature group mode: "global" (default), "per-pri", "pri-ranges", "custom".
    pub signature_group: Option<String>,

    /// Maximum number of message hashes per signature block.
    pub max_hashes_per_block: Option<usize>,

    /// How often (seconds) to emit certificate blocks.
    pub cert_emit_interval_secs: Option<u64>,
}

// ---------------------------------------------------------------------------
// Verification (RFC 5848)
// ---------------------------------------------------------------------------

/// RFC 5848 message verification configuration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct VerificationConfig {
    /// Whether verification is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Paths to trusted public key files (PKCS#8 DER-encoded).
    #[serde(default)]
    pub trusted_key_paths: Vec<String>,

    /// Whether to reject messages that cannot be verified.
    #[serde(default)]
    pub reject_unverified: bool,
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/// Log output format.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// Logging settings.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct LoggingConfig {
    /// Tracing filter level string, e.g. `"info"` or `"syslog_server=debug"`.
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Output format.
    #[serde(default)]
    pub format: LogFormat,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

fn default_log_level() -> String {
    String::from("info")
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Prometheus metrics exposition settings.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct MetricsConfig {
    /// Whether the metrics endpoint is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Bind address for the Prometheus HTTP endpoint.
    #[serde(default = "default_metrics_bind")]
    pub bind_address: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: default_metrics_bind(),
        }
    }
}

fn default_metrics_bind() -> String {
    String::from("127.0.0.1:9090")
}

// ---------------------------------------------------------------------------
// Management Actions (RFC 9742)
// ---------------------------------------------------------------------------

/// A management action from the RFC 9742 YANG model: selector + action type.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct MgmtActionConfig {
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Selector criteria for matching messages.
    #[serde(default)]
    pub selector: SelectorConfig,
    /// The action to take on matching messages.
    pub action: ActionTypeConfig,
}

/// Selector criteria for matching syslog messages.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
pub struct SelectorConfig {
    /// Facility names to match (e.g., ["kern", "user"]).
    pub facilities: Option<Vec<String>>,
    /// Minimum severity name (most urgent bound).
    pub min_severity: Option<String>,
    /// Maximum severity name (least urgent bound).
    pub max_severity: Option<String>,
    /// Regex pattern for hostname matching.
    pub hostname_pattern: Option<String>,
    /// Regex pattern for app_name matching.
    pub app_name_pattern: Option<String>,
}

/// The action type to take on matching messages.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ActionTypeConfig {
    /// Write to the system console / stdout.
    Console,
    /// Write to a file.
    File {
        /// Destination file path.
        path: String,
    },
    /// Forward to a remote syslog receiver.
    Remote {
        /// Remote host address.
        host: String,
        /// Remote port number.
        port: u16,
        /// Transport protocol: "udp", "tcp", or "tls".
        protocol: String,
    },
    /// Buffer messages in a named in-memory buffer.
    Buffer {
        /// Buffer name.
        name: String,
        /// Maximum number of messages to buffer.
        size: usize,
    },
    /// Discard matching messages.
    Discard,
}
