//! Output trait and implementations for the relay pipeline.
//!
//! Outputs are the final stage of the pipeline, responsible for delivering
//! syslog messages to their destination (e.g., a remote syslog server,
//! a file, or a test collector).

use std::fmt;
use std::sync::Arc;

use syslog_proto::SyslogMessage;
use tokio::sync::Mutex;

use crate::error::RelayError;

/// Policy for handling queue overflow when the output queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropPolicy {
    /// Drop the newest incoming message when the queue is full.
    DropNewest,
    /// Drop the oldest message in the queue to make room for the new one.
    DropOldest,
    /// Block the sender until space becomes available.
    Block,
}

impl fmt::Display for DropPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DropNewest => f.write_str("drop_newest"),
            Self::DropOldest => f.write_str("drop_oldest"),
            Self::Block => f.write_str("block"),
        }
    }
}

/// Trait for pipeline outputs that consume syslog messages.
///
/// Implementations may forward messages over the network, write them to
/// disk, or collect them for testing purposes.
pub trait Output: Send + Sync + fmt::Debug {
    /// The name of this output, used for logging and error reporting.
    fn name(&self) -> &str;

    /// Send a message to this output.
    ///
    /// # Errors
    /// Returns `RelayError` if the message cannot be delivered.
    fn send(
        &self,
        message: SyslogMessage,
    ) -> impl std::future::Future<Output = Result<(), RelayError>> + Send;
}

/// A simple output that collects messages into a `Vec` for testing.
///
/// Thread-safe via an internal `Arc<Mutex<Vec<SyslogMessage>>>`.
#[derive(Debug, Clone)]
pub struct ForwardOutput {
    name: String,
    collected: Arc<Mutex<Vec<SyslogMessage>>>,
}

impl ForwardOutput {
    /// Create a new `ForwardOutput` with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            collected: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns a snapshot of all collected messages.
    pub async fn collected(&self) -> Vec<SyslogMessage> {
        self.collected.lock().await.clone()
    }

    /// Returns the number of collected messages.
    pub async fn len(&self) -> usize {
        self.collected.lock().await.len()
    }

    /// Returns `true` if no messages have been collected.
    pub async fn is_empty(&self) -> bool {
        self.collected.lock().await.is_empty()
    }

    /// Clears all collected messages.
    pub async fn clear(&self) {
        self.collected.lock().await.clear();
    }
}

impl Output for ForwardOutput {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, message: SyslogMessage) -> Result<(), RelayError> {
        self.collected.lock().await.push(message);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use compact_str::CompactString;
    use syslog_proto::{Facility, Severity, StructuredData, SyslogTimestamp};

    fn make_message(body: &'static [u8]) -> SyslogMessage {
        SyslogMessage {
            facility: Facility::User,
            severity: Severity::Notice,
            version: 1,
            timestamp: SyslogTimestamp::Nil,
            hostname: Some(CompactString::new("testhost")),
            app_name: Some(CompactString::new("testapp")),
            proc_id: None,
            msg_id: None,
            structured_data: StructuredData::nil(),
            msg: Some(Bytes::from_static(body)),
            raw: None,
        }
    }

    #[tokio::test]
    async fn forward_output_collects_messages() {
        let output = ForwardOutput::new("test");
        assert!(output.is_empty().await);

        let result = output.send(make_message(b"hello")).await;
        assert!(result.is_ok());

        assert_eq!(output.len().await, 1);
        assert!(!output.is_empty().await);

        let msgs = output.collected().await;
        assert_eq!(msgs.len(), 1);
    }

    #[tokio::test]
    async fn forward_output_clear() {
        let output = ForwardOutput::new("test");
        let _ = output.send(make_message(b"hello")).await;
        assert_eq!(output.len().await, 1);

        output.clear().await;
        assert!(output.is_empty().await);
    }

    #[tokio::test]
    async fn forward_output_name() {
        let output = ForwardOutput::new("my-output");
        assert_eq!(output.name(), "my-output");
    }

    #[test]
    fn drop_policy_display() {
        assert_eq!(DropPolicy::DropNewest.to_string(), "drop_newest");
        assert_eq!(DropPolicy::DropOldest.to_string(), "drop_oldest");
        assert_eq!(DropPolicy::Block.to_string(), "block");
    }
}
