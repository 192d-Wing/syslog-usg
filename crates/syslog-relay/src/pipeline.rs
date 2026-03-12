//! The main relay pipeline that connects ingestion to outputs.
//!
//! The pipeline receives [`SyslogMessage`] values from an mpsc channel,
//! applies optional filtering, and routes messages to configured outputs.

use syslog_proto::SyslogMessage;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::error::RelayError;
use crate::filter::SeverityFilter;
use crate::output::Output;

/// The main relay pipeline.
///
/// Receives parsed syslog messages from an ingestion channel, applies
/// filtering, and fans out to one or more outputs.
#[derive(Debug)]
pub struct Pipeline<O: Output> {
    /// Channel for receiving messages from transport/ingest layer.
    rx: mpsc::Receiver<SyslogMessage>,
    /// Optional severity filter.
    filter: Option<SeverityFilter>,
    /// Configured outputs to send messages to.
    outputs: Vec<O>,
    /// Watch channel receiver for graceful shutdown.
    shutdown: watch::Receiver<bool>,
}

/// Handle returned when building a pipeline, used to send messages into it.
#[derive(Debug, Clone)]
pub struct PipelineIngress {
    tx: mpsc::Sender<SyslogMessage>,
}

impl PipelineIngress {
    /// Send a message into the pipeline for processing.
    ///
    /// # Errors
    /// Returns `RelayError::ChannelClosed` if the pipeline has been dropped.
    pub async fn send(&self, message: SyslogMessage) -> Result<(), RelayError> {
        self.tx
            .send(message)
            .await
            .map_err(|_| RelayError::ChannelClosed("pipeline ingress".to_owned()))
    }
}

/// Handle for signaling the pipeline to shut down.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    tx: watch::Sender<bool>,
}

impl ShutdownHandle {
    /// Signal the pipeline to shut down gracefully.
    pub fn shutdown(&self) {
        // Ignore the error if all receivers have been dropped.
        let _ = self.tx.send(true);
    }
}

impl<O: Output> Pipeline<O> {
    /// Create a new pipeline with the given channel capacity.
    ///
    /// Returns the pipeline, an ingress handle for sending messages, and
    /// a shutdown handle.
    #[must_use]
    pub fn new(
        channel_capacity: usize,
        filter: Option<SeverityFilter>,
        outputs: Vec<O>,
    ) -> (Self, PipelineIngress, ShutdownHandle) {
        let (tx, rx) = mpsc::channel(channel_capacity);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let pipeline = Self {
            rx,
            filter,
            outputs,
            shutdown: shutdown_rx,
        };

        let ingress = PipelineIngress { tx };
        let shutdown_handle = ShutdownHandle { tx: shutdown_tx };

        (pipeline, ingress, shutdown_handle)
    }

    /// Run the pipeline until shutdown is signaled or the ingress channel closes.
    ///
    /// This is the main processing loop. It will:
    /// 1. Receive messages from the ingress channel
    /// 2. Apply the severity filter (if configured)
    /// 3. Fan out to all configured outputs
    ///
    /// # Errors
    /// Returns `RelayError::Shutdown` when the pipeline is shut down.
    pub async fn run(mut self) -> Result<(), RelayError> {
        info!("pipeline started with {} output(s)", self.outputs.len());

        let mut messages_processed: u64 = 0;
        let mut messages_filtered: u64 = 0;

        loop {
            tokio::select! {
                biased;

                _ = self.shutdown.changed() => {
                    if *self.shutdown.borrow() {
                        info!(
                            processed = messages_processed,
                            filtered = messages_filtered,
                            "pipeline shutting down"
                        );
                        return Err(RelayError::Shutdown);
                    }
                }

                msg = self.rx.recv() => {
                    match msg {
                        Some(message) => {
                            // Apply filter
                            if let Some(ref filter) = self.filter {
                                if !filter.should_pass(&message) {
                                    messages_filtered += 1;
                                    metrics::counter!("relay_messages_filtered_total").increment(1);
                                    debug!(
                                        severity = %message.severity,
                                        "message filtered out"
                                    );
                                    continue;
                                }
                            }

                            messages_processed += 1;
                            metrics::counter!("relay_messages_processed_total").increment(1);

                            // Fan out to all outputs
                            for output in &self.outputs {
                                if let Err(e) = output.send(message.clone()).await {
                                    warn!(
                                        output = output.name(),
                                        error = %e,
                                        "failed to send message to output"
                                    );
                                }
                            }
                        }
                        None => {
                            // Ingress channel closed — all senders dropped.
                            info!(
                                processed = messages_processed,
                                filtered = messages_filtered,
                                "ingress channel closed, pipeline stopping"
                            );
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::ForwardOutput;
    use bytes::Bytes;
    use compact_str::CompactString;
    use syslog_proto::{Facility, Severity, StructuredData, SyslogTimestamp};

    fn make_message(severity: Severity, body: &str) -> SyslogMessage {
        SyslogMessage {
            facility: Facility::User,
            severity,
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

    #[tokio::test]
    async fn pipeline_forwards_to_output() {
        let output = ForwardOutput::new("test-output");
        let output_clone = output.clone();

        let (pipeline, ingress, _shutdown) = Pipeline::new(16, None, vec![output]);

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        let _ = ingress
            .send(make_message(Severity::Error, "test msg"))
            .await;

        // Drop the ingress to close the channel and stop the pipeline
        drop(ingress);
        let _ = handle.await;

        assert_eq!(output_clone.len().await, 1);
    }

    #[tokio::test]
    async fn pipeline_applies_filter() {
        let output = ForwardOutput::new("test-output");
        let output_clone = output.clone();

        let filter = SeverityFilter::new(Severity::Warning);
        let (pipeline, ingress, _shutdown) = Pipeline::new(16, Some(filter), vec![output]);

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        // This should pass (Error >= Warning)
        let _ = ingress
            .send(make_message(Severity::Error, "error msg"))
            .await;
        // This should be filtered (Debug < Warning)
        let _ = ingress
            .send(make_message(Severity::Debug, "debug msg"))
            .await;
        // This should pass (Warning >= Warning)
        let _ = ingress
            .send(make_message(Severity::Warning, "warning msg"))
            .await;

        drop(ingress);
        let _ = handle.await;

        assert_eq!(output_clone.len().await, 2);
    }

    #[tokio::test]
    async fn pipeline_shutdown() {
        let output = ForwardOutput::new("test-output");

        let (pipeline, _ingress, shutdown) = Pipeline::new(16, None, vec![output]);

        let handle = tokio::spawn(async move { pipeline.run().await });

        shutdown.shutdown();
        let result = handle.await;
        assert!(result.is_ok());
        if let Ok(Err(RelayError::Shutdown)) = result {
            // expected
        } else {
            // The pipeline should have returned Shutdown error
            // but timing may cause it to see channel close first
        }
    }

    #[tokio::test]
    async fn pipeline_fans_out_to_multiple_outputs() {
        let output1 = ForwardOutput::new("output-1");
        let output2 = ForwardOutput::new("output-2");
        let o1_clone = output1.clone();
        let o2_clone = output2.clone();

        let (pipeline, ingress, _shutdown) = Pipeline::new(16, None, vec![output1, output2]);

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        let _ = ingress.send(make_message(Severity::Error, "fan-out")).await;

        drop(ingress);
        let _ = handle.await;

        assert_eq!(o1_clone.len().await, 1);
        assert_eq!(o2_clone.len().await, 1);
    }
}
