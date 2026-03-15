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
    ///
    /// Carries the serialized replay detector state (if a verification
    /// stage was configured) so the caller can persist it to disk.
    #[error("pipeline shutdown")]
    Shutdown {
        /// Serialized replay-detector state, or `None` when no verification
        /// stage is present.
        replay_state: Option<String>,
    },

    /// A channel was closed unexpectedly.
    #[error("channel closed: {0}")]
    ChannelClosed(String),
}
