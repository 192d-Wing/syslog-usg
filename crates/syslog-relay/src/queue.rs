//! Bounded async queue with configurable overflow policy.
//!
//! Wraps `tokio::sync::mpsc` with a [`DropPolicy`] that determines
//! what happens when the queue is full.

use syslog_proto::SyslogMessage;
use tokio::sync::mpsc;
use tracing::warn;

use crate::error::RelayError;
use crate::output::DropPolicy;

/// A bounded async message queue with configurable overflow behavior.
#[derive(Debug)]
pub struct BoundedQueue {
    /// The sending half of the channel.
    tx: mpsc::Sender<SyslogMessage>,
    /// The receiving half of the channel.
    rx: mpsc::Receiver<SyslogMessage>,
    /// Name used for logging and error reporting.
    name: String,
    /// What to do when the queue is full.
    policy: DropPolicy,
    /// Maximum capacity of the queue.
    capacity: usize,
}

impl BoundedQueue {
    /// Create a new bounded queue with the given capacity and overflow policy.
    ///
    /// # Arguments
    /// * `name` - A human-readable name for this queue (used in logs/errors).
    /// * `capacity` - Maximum number of messages the queue can hold.
    /// * `policy` - What to do when the queue is full.
    #[must_use]
    pub fn new(name: impl Into<String>, capacity: usize, policy: DropPolicy) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            tx,
            rx,
            name: name.into(),
            policy,
            capacity,
        }
    }

    /// Returns the name of this queue.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the configured capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the configured drop policy.
    #[must_use]
    pub fn policy(&self) -> DropPolicy {
        self.policy
    }

    /// Push a message onto the queue, applying the overflow policy if full.
    ///
    /// # Errors
    /// Returns `RelayError::QueueFull` if the queue is full and the policy
    /// is `DropNewest` (the incoming message is dropped).
    /// Returns `RelayError::ChannelClosed` if the receiver has been dropped.
    pub async fn push(&mut self, message: SyslogMessage) -> Result<(), RelayError> {
        match self.policy {
            DropPolicy::Block => self
                .tx
                .send(message)
                .await
                .map_err(|_| RelayError::ChannelClosed(self.name.clone())),
            DropPolicy::DropNewest => match self.tx.try_send(message) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(queue = %self.name, "queue full, dropping newest message");
                    metrics::counter!("relay_queue_dropped_total", "queue" => self.name.clone(), "policy" => "drop_newest").increment(1);
                    Err(RelayError::QueueFull {
                        output: self.name.clone(),
                        policy: "drop_newest",
                    })
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    Err(RelayError::ChannelClosed(self.name.clone()))
                }
            },
            DropPolicy::DropOldest => {
                match self.tx.try_send(message) {
                    Ok(()) => Ok(()),
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        Err(RelayError::ChannelClosed(self.name.clone()))
                    }
                    Err(mpsc::error::TrySendError::Full(returned_msg)) => {
                        // Queue is full — drain the oldest message and retry.
                        match self.rx.try_recv() {
                            Ok(_dropped) => {
                                warn!(queue = %self.name, "queue full, dropping oldest message");
                                metrics::counter!("relay_queue_dropped_total", "queue" => self.name.clone(), "policy" => "drop_oldest").increment(1);
                            }
                            Err(_) => {
                                // Queue was drained between try_send and try_recv;
                                // space is now available regardless.
                            }
                        }
                        // Retry the send with the recovered message.
                        match self.tx.try_send(returned_msg) {
                            Ok(()) => Ok(()),
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                Err(RelayError::ChannelClosed(self.name.clone()))
                            }
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                // Still full (unlikely race); report the drop.
                                Err(RelayError::QueueFull {
                                    output: self.name.clone(),
                                    policy: "drop_oldest",
                                })
                            }
                        }
                    }
                }
            }
        }
    }

    /// Receive the next message from the queue, waiting if empty.
    ///
    /// Returns `None` when the queue is closed (all senders dropped).
    pub async fn pop(&mut self) -> Option<SyslogMessage> {
        self.rx.recv().await
    }

    /// Try to receive a message without waiting.
    ///
    /// Returns `None` if the queue is empty or closed.
    pub fn try_pop(&mut self) -> Option<SyslogMessage> {
        self.rx.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use compact_str::CompactString;
    use syslog_proto::{Facility, Severity, StructuredData, SyslogTimestamp};

    fn make_message(body: &str) -> SyslogMessage {
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
            msg: Some(Bytes::from(body.to_owned())),
            raw: None,
        }
    }

    fn msg_body(msg: &SyslogMessage) -> String {
        msg.msg
            .as_ref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn basic_push_pop() {
        let mut queue = BoundedQueue::new("test", 8, DropPolicy::Block);
        let result = queue.push(make_message("hello")).await;
        assert!(result.is_ok());

        let msg = queue.pop().await;
        assert!(msg.is_some());
        if let Some(m) = msg {
            assert_eq!(msg_body(&m), "hello");
        }
    }

    #[tokio::test]
    async fn try_pop_empty() {
        let mut queue = BoundedQueue::new("test", 8, DropPolicy::Block);
        assert!(queue.try_pop().is_none());
    }

    #[tokio::test]
    async fn try_pop_after_push() {
        let mut queue = BoundedQueue::new("test", 8, DropPolicy::Block);
        let _ = queue.push(make_message("msg1")).await;
        let msg = queue.try_pop();
        assert!(msg.is_some());
    }

    #[tokio::test]
    async fn drop_newest_when_full() {
        // Capacity 2 queue with DropNewest policy
        let mut queue = BoundedQueue::new("test", 2, DropPolicy::DropNewest);

        let r1 = queue.push(make_message("first")).await;
        assert!(r1.is_ok());
        let r2 = queue.push(make_message("second")).await;
        assert!(r2.is_ok());

        // Third push should fail — queue is full
        let r3 = queue.push(make_message("third")).await;
        assert!(r3.is_err());

        // The two messages in the queue should be the original ones
        let m1 = queue.pop().await;
        assert!(m1.is_some());
        if let Some(m) = m1 {
            assert_eq!(msg_body(&m), "first");
        }

        let m2 = queue.pop().await;
        assert!(m2.is_some());
        if let Some(m) = m2 {
            assert_eq!(msg_body(&m), "second");
        }
    }

    #[tokio::test]
    async fn drop_oldest_when_full() {
        // Capacity 2 queue with DropOldest policy
        let mut queue = BoundedQueue::new("test", 2, DropPolicy::DropOldest);

        let r1 = queue.push(make_message("first")).await;
        assert!(r1.is_ok());
        let r2 = queue.push(make_message("second")).await;
        assert!(r2.is_ok());

        // Third push should succeed after dropping the oldest
        let r3 = queue.push(make_message("third")).await;
        assert!(r3.is_ok());

        // The oldest ("first") was dropped; "second" and "third" remain
        let m1 = queue.pop().await;
        assert!(m1.is_some());
        if let Some(m) = m1 {
            assert_eq!(msg_body(&m), "second");
        }

        let m2 = queue.pop().await;
        assert!(m2.is_some());
        if let Some(m) = m2 {
            assert_eq!(msg_body(&m), "third");
        }
    }

    #[tokio::test]
    async fn queue_accessors() {
        let queue = BoundedQueue::new("myqueue", 16, DropPolicy::Block);
        assert_eq!(queue.name(), "myqueue");
        assert_eq!(queue.capacity(), 16);
        assert_eq!(queue.policy(), DropPolicy::Block);
    }

    #[tokio::test]
    async fn block_policy_does_not_drop() {
        let mut queue = BoundedQueue::new("test", 4, DropPolicy::Block);
        for i in 0..4 {
            let body = format!("msg{i}");
            let result = queue.push(make_message(&body)).await;
            assert!(result.is_ok());
        }
        // All 4 messages should be present
        for i in 0..4 {
            let msg = queue.try_pop();
            assert!(msg.is_some());
            if let Some(m) = msg {
                let expected = format!("msg{i}");
                assert_eq!(msg_body(&m), expected);
            }
        }
    }
}
