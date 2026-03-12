//! Prometheus metrics initialization and metric name constants.
//!
//! All metric names follow the convention `syslog_<subsystem>_<name>_<unit>`
//! per Prometheus naming best practices.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

// ---------------------------------------------------------------------------
// Metric name constants
// ---------------------------------------------------------------------------

/// Counter: total syslog messages received (labels: transport, facility, severity).
pub const MESSAGES_RECEIVED_TOTAL: &str = "syslog_messages_received_total";

/// Counter: total messages parsed (labels: format = rfc5424 | rfc3164 | invalid).
pub const MESSAGES_PARSED_TOTAL: &str = "syslog_messages_parsed_total";

/// Counter: total messages forwarded (labels: output).
pub const MESSAGES_FORWARDED_TOTAL: &str = "syslog_messages_forwarded_total";

/// Counter: total messages dropped (labels: output, reason).
pub const MESSAGES_DROPPED_TOTAL: &str = "syslog_messages_dropped_total";

/// Histogram: parse duration in seconds.
pub const PARSE_DURATION_SECONDS: &str = "syslog_parse_duration_seconds";

/// Gauge: current queue depth per output (labels: output).
pub const QUEUE_DEPTH: &str = "syslog_queue_depth";

/// Gauge: active connections (labels: transport).
pub const CONNECTIONS_ACTIVE: &str = "syslog_connections_active";

// ---------------------------------------------------------------------------
// Label key constants
// ---------------------------------------------------------------------------

/// Label key for transport type (udp, tcp, tls).
pub const LABEL_TRANSPORT: &str = "transport";

/// Label key for syslog facility code.
pub const LABEL_FACILITY: &str = "facility";

/// Label key for syslog severity code.
pub const LABEL_SEVERITY: &str = "severity";

/// Label key for message format (rfc5424, rfc3164, invalid).
pub const LABEL_FORMAT: &str = "format";

/// Label key for output destination name.
pub const LABEL_OUTPUT: &str = "output";

/// Label key for drop reason.
pub const LABEL_REASON: &str = "reason";

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Error returned when metrics initialization fails.
#[derive(Debug, thiserror::Error)]
#[error("failed to install Prometheus metrics recorder: {0}")]
pub struct MetricsInitError(#[from] metrics_exporter_prometheus::BuildError);

/// Install the global Prometheus metrics recorder.
///
/// Returns a [`PrometheusHandle`] that can be used to render the metrics
/// scrape output (see [`crate::health`]).
///
/// # Errors
///
/// Returns [`MetricsInitError`] if the recorder has already been installed
/// or the builder configuration is invalid.
pub fn init_metrics() -> Result<PrometheusHandle, MetricsInitError> {
    let handle = PrometheusBuilder::new().install_recorder()?;
    Ok(handle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_name_constants_have_syslog_prefix() {
        let names = [
            MESSAGES_RECEIVED_TOTAL,
            MESSAGES_PARSED_TOTAL,
            MESSAGES_FORWARDED_TOTAL,
            MESSAGES_DROPPED_TOTAL,
            PARSE_DURATION_SECONDS,
            QUEUE_DEPTH,
            CONNECTIONS_ACTIVE,
        ];
        for name in &names {
            assert!(
                name.starts_with("syslog_"),
                "{name} should start with syslog_"
            );
        }
    }

    #[test]
    fn label_constants_are_non_empty() {
        let labels = [
            LABEL_TRANSPORT,
            LABEL_FACILITY,
            LABEL_SEVERITY,
            LABEL_FORMAT,
            LABEL_OUTPUT,
            LABEL_REASON,
        ];
        for label in &labels {
            assert!(!label.is_empty(), "label constant must not be empty");
        }
    }
}
