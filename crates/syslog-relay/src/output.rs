//! Output trait and implementations for the relay pipeline.
//!
//! Outputs are the final stage of the pipeline, responsible for delivering
//! syslog messages to their destination (e.g., a remote syslog server,
//! a file, or a test collector).

use std::collections::VecDeque;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use syslog_proto::SyslogMessage;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::warn;

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

/// An output that writes serialized RFC 5424 syslog messages to a file.
///
/// The file is opened lazily on the first `send()` call in append mode,
/// creating it if it does not exist. Each message is followed by a newline.
#[derive(Debug, Clone)]
pub struct FileOutput {
    name: String,
    path: PathBuf,
    writer: Arc<Mutex<Option<tokio::fs::File>>>,
}

impl FileOutput {
    /// Create a new `FileOutput` with the given name and file path.
    ///
    /// The file is not opened until the first message is sent.
    #[must_use]
    pub fn new(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            writer: Arc::new(Mutex::new(None)),
        }
    }
}

impl Output for FileOutput {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, message: SyslogMessage) -> Result<(), RelayError> {
        let mut guard = self.writer.lock().await;

        // Lazily open the file in append mode, creating if needed.
        if guard.is_none() {
            let file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .await
                .map_err(|e| {
                    warn!(
                        output = %self.name,
                        path = %self.path.display(),
                        "failed to open file output: {e}"
                    );
                    RelayError::OutputSendFailed {
                        output: self.name.clone(),
                        reason: format!("open {}: {e}", self.path.display()),
                    }
                })?;
            *guard = Some(file);
        }

        // Serialize the message to RFC 5424 wire format.
        let mut wire = syslog_parse::rfc5424::serializer::serialize(&message);
        wire.push(b'\n');

        let file = guard.as_mut().ok_or_else(|| RelayError::OutputSendFailed {
            output: self.name.clone(),
            reason: "file not open".to_owned(),
        })?;

        file.write_all(&wire).await.map_err(|e| {
            warn!(
                output = %self.name,
                path = %self.path.display(),
                "failed to write to file output: {e}"
            );
            RelayError::OutputSendFailed {
                output: self.name.clone(),
                reason: format!("write to {}: {e}", self.path.display()),
            }
        })?;

        file.flush().await.map_err(|e| {
            warn!(
                output = %self.name,
                path = %self.path.display(),
                "failed to flush file output: {e}"
            );
            RelayError::OutputSendFailed {
                output: self.name.clone(),
                reason: format!("flush {}: {e}", self.path.display()),
            }
        })?;

        Ok(())
    }
}

/// A ring-buffer output that stores the last N messages in memory.
///
/// When the buffer reaches capacity, the oldest message is dropped
/// to make room for the new one (FIFO ring buffer). Thread-safe via
/// an internal `Arc<Mutex<VecDeque<SyslogMessage>>>`.
#[derive(Debug, Clone)]
pub struct BufferOutput {
    name: String,
    buffer: Arc<Mutex<VecDeque<SyslogMessage>>>,
    capacity: usize,
}

impl BufferOutput {
    /// Create a new `BufferOutput` with the given name and capacity.
    #[must_use]
    pub fn new(name: impl Into<String>, capacity: usize) -> Self {
        Self {
            name: name.into(),
            buffer: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    /// Returns a snapshot of the current buffer contents.
    pub async fn snapshot(&self) -> Vec<SyslogMessage> {
        self.buffer.lock().await.iter().cloned().collect()
    }

    /// Returns the number of messages currently in the buffer.
    pub async fn len(&self) -> usize {
        self.buffer.lock().await.len()
    }

    /// Returns `true` if the buffer is empty.
    pub async fn is_empty(&self) -> bool {
        self.buffer.lock().await.is_empty()
    }
}

impl Output for BufferOutput {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, message: SyslogMessage) -> Result<(), RelayError> {
        let mut guard = self.buffer.lock().await;
        if guard.len() >= self.capacity {
            guard.pop_front();
        }
        guard.push_back(message);
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

    #[tokio::test]
    async fn file_output_writes_message() {
        let dir = std::env::temp_dir().join("syslog-usg-test-file-output");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_write.log");
        // Clean up any previous run
        let _ = std::fs::remove_file(&path);

        let output = FileOutput::new("file-test", path.clone());
        assert_eq!(output.name(), "file-test");

        let msg = make_message(b"hello file");
        let result = output.send(msg).await;
        assert!(result.is_ok());

        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        // Should contain RFC 5424 serialized message followed by newline
        assert!(contents.contains("testhost"));
        assert!(contents.contains("testapp"));
        assert!(contents.contains("hello file"));
        assert!(contents.ends_with('\n'));

        // Clean up
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[tokio::test]
    async fn file_output_appends_multiple_messages() {
        let dir = std::env::temp_dir().join("syslog-usg-test-file-output");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_append.log");
        let _ = std::fs::remove_file(&path);

        let output = FileOutput::new("file-append", path.clone());

        let r1 = output.send(make_message(b"first")).await;
        assert!(r1.is_ok());

        let r2 = output.send(make_message(b"second")).await;
        assert!(r2.is_ok());

        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "expected two lines, got: {contents}");
        assert!(lines.first().is_some_and(|l| l.contains("first")));
        assert!(lines.get(1).is_some_and(|l| l.contains("second")));

        // Clean up
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[tokio::test]
    async fn file_output_name() {
        let output = FileOutput::new("my-file", "/tmp/dummy.log");
        assert_eq!(output.name(), "my-file");
    }

    #[tokio::test]
    async fn buffer_output_stores_messages() {
        let output = BufferOutput::new("buf", 3);
        assert!(output.is_empty().await);

        let _ = output.send(make_message(b"msg1")).await;
        let _ = output.send(make_message(b"msg2")).await;
        let _ = output.send(make_message(b"msg3")).await;

        assert_eq!(output.len().await, 3);

        let snap = output.snapshot().await;
        assert_eq!(snap.len(), 3);
        assert_eq!(
            snap.first().and_then(|m| m.msg.as_ref()).map(|b| b.as_ref()),
            Some(b"msg1".as_slice())
        );
        assert_eq!(
            snap.get(1).and_then(|m| m.msg.as_ref()).map(|b| b.as_ref()),
            Some(b"msg2".as_slice())
        );
        assert_eq!(
            snap.get(2).and_then(|m| m.msg.as_ref()).map(|b| b.as_ref()),
            Some(b"msg3".as_slice())
        );
    }

    #[tokio::test]
    async fn buffer_output_drops_oldest_when_full() {
        let output = BufferOutput::new("buf", 3);

        let _ = output.send(make_message(b"msg1")).await;
        let _ = output.send(make_message(b"msg2")).await;
        let _ = output.send(make_message(b"msg3")).await;
        let _ = output.send(make_message(b"msg4")).await;

        assert_eq!(output.len().await, 3);

        let snap = output.snapshot().await;
        assert_eq!(snap.len(), 3);
        // Oldest (msg1) should have been dropped
        assert_eq!(
            snap.first().and_then(|m| m.msg.as_ref()).map(|b| b.as_ref()),
            Some(b"msg2".as_slice())
        );
        assert_eq!(
            snap.get(1).and_then(|m| m.msg.as_ref()).map(|b| b.as_ref()),
            Some(b"msg3".as_slice())
        );
        assert_eq!(
            snap.get(2).and_then(|m| m.msg.as_ref()).map(|b| b.as_ref()),
            Some(b"msg4".as_slice())
        );
    }

    #[tokio::test]
    async fn buffer_output_name() {
        let output = BufferOutput::new("my-buffer", 10);
        assert_eq!(output.name(), "my-buffer");
    }
}
