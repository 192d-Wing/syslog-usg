//! Relay pipeline error types.

use thiserror::Error;

/// Errors that can occur in the relay pipeline.
#[derive(Debug, Error)]
pub enum RelayError {
    /// The queue is full and a drop policy was applied.
    #[error("queue full for output {output}: {policy} policy applied")]
    QueueFull {
        /// Name of the output whose queue is full.
        output: String,
        /// The drop policy that was applied.
        policy: &'static str,
    },

    /// Sending a message to an output failed.
    #[error("output send failed for {output}: {reason}")]
    OutputSendFailed {
        /// Name of the output that failed.
        output: String,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// The pipeline has been shut down.
    #[error("pipeline shutdown")]
    Shutdown,

    /// A channel was closed unexpectedly.
    #[error("channel closed: {0}")]
    ChannelClosed(String),
}
