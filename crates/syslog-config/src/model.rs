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

    /// Logging settings.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Prometheus metrics settings.
    #[serde(default)]
    pub metrics: MetricsConfig,
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
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            channel_buffer_size: default_channel_buffer_size(),
            max_message_size: default_max_message_size(),
        }
    }
}

fn default_channel_buffer_size() -> usize {
    4096
}

fn default_max_message_size() -> usize {
    8192
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
    String::from("0.0.0.0:9090")
}
