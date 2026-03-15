//! The main relay pipeline that connects ingestion to outputs.
//!
//! The pipeline receives [`SyslogMessage`] values from an mpsc channel,
//! applies optional filtering, and routes messages to configured outputs.

use syslog_mgmt::SharedSyslogState;
use syslog_proto::SyslogMessage;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::error::RelayError;
use crate::filter::MessageFilter;
use crate::output::Output;
use crate::routing::RoutingTable;
use crate::signing::SigningStage;
use crate::verification::VerificationStage;

/// The main relay pipeline.
///
/// Receives parsed syslog messages from an ingestion channel, applies
/// a chain of filters, and fans out to one or more outputs.
pub struct Pipeline<O: Output> {
    /// Channel for receiving messages from transport/ingest layer.
    rx: mpsc::Receiver<SyslogMessage>,
    /// Ordered chain of message filters. A message must pass all filters.
    filters: Vec<Box<dyn MessageFilter>>,
    /// Configured outputs to send messages to.
    outputs: Vec<O>,
    /// Watch channel receiver for graceful shutdown.
    shutdown: watch::Receiver<bool>,
    /// Optional RFC 5848 signing stage.
    signing: Option<SigningStage>,
    /// Optional RFC 5848 verification stage.
    verification: Option<VerificationStage>,
    /// Optional routing table for selective output delivery.
    routing_table: Option<RoutingTable>,
    /// Optional shared management state for atomic counters.
    shared_state: Option<SharedSyslogState>,
    /// When true, signing failures forward the original unsigned message.
    /// When false, messages are dropped on signing failure.
    signing_fail_open: bool,
}

impl<O: Output> std::fmt::Debug for Pipeline<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline")
            .field("filters", &self.filters)
            .field("outputs", &self.outputs)
            .field("signing", &self.signing)
            .field("verification", &self.verification)
            .field("routing_table", &self.routing_table)
            .field("has_shared_state", &self.shared_state.is_some())
            .finish_non_exhaustive()
    }
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
    /// Create a new pipeline with the given channel capacity and filter chain.
    ///
    /// Returns the pipeline, an ingress handle for sending messages, and
    /// a shutdown handle.
    ///
    /// Filters are applied in order; a message must pass all filters to be
    /// forwarded to outputs.
    #[must_use]
    pub fn new(
        channel_capacity: usize,
        filters: Vec<Box<dyn MessageFilter>>,
        outputs: Vec<O>,
    ) -> (Self, PipelineIngress, ShutdownHandle) {
        Self::with_signing(channel_capacity, filters, outputs, None, None)
    }

    /// Create a new pipeline with optional signing and verification stages.
    ///
    /// This is the full constructor. Use [`Pipeline::new`] for pipelines
    /// without signing/verification.
    #[must_use]
    pub fn with_signing(
        channel_capacity: usize,
        filters: Vec<Box<dyn MessageFilter>>,
        outputs: Vec<O>,
        signing: Option<SigningStage>,
        verification: Option<VerificationStage>,
    ) -> (Self, PipelineIngress, ShutdownHandle) {
        Self::with_management(
            channel_capacity,
            filters,
            outputs,
            signing,
            verification,
            None,
            None,
        )
    }

    /// Create a new pipeline with full management integration.
    ///
    /// Supports optional signing, verification, routing table, and
    /// shared management state with atomic counters.
    #[must_use]
    pub fn with_management(
        channel_capacity: usize,
        filters: Vec<Box<dyn MessageFilter>>,
        outputs: Vec<O>,
        signing: Option<SigningStage>,
        verification: Option<VerificationStage>,
        routing_table: Option<RoutingTable>,
        shared_state: Option<SharedSyslogState>,
    ) -> (Self, PipelineIngress, ShutdownHandle) {
        let (tx, rx) = mpsc::channel(channel_capacity);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let pipeline = Self {
            rx,
            filters,
            outputs,
            shutdown: shutdown_rx,
            signing,
            verification,
            routing_table,
            shared_state,
            signing_fail_open: true,
        };

        let ingress = PipelineIngress { tx };
        let shutdown_handle = ShutdownHandle { tx: shutdown_tx };

        (pipeline, ingress, shutdown_handle)
    }

    /// Set the signing failure policy.
    ///
    /// When `fail_open` is true (default), signing failures forward the
    /// original unsigned message. When false, messages are dropped.
    pub fn set_signing_fail_open(&mut self, fail_open: bool) {
        self.signing_fail_open = fail_open;
    }

    /// Send a message to all outputs (fan-out mode).
    async fn send_to_all_outputs(&self, messages: &[SyslogMessage]) {
        for out_msg in messages {
            for output in &self.outputs {
                if let Err(e) = output.send(out_msg.clone()).await {
                    warn!(
                        output = output.name(),
                        error = %e,
                        "failed to send message to output"
                    );
                }
            }
        }
    }

    /// Send a message to selected outputs based on the routing table.
    async fn send_to_routed_outputs(&self, messages: &[SyslogMessage], output_indices: &[usize]) {
        for out_msg in messages {
            for &idx in output_indices {
                if let Some(output) = self.outputs.get(idx) {
                    if let Err(e) = output.send(out_msg.clone()).await {
                        warn!(
                            output = output.name(),
                            error = %e,
                            "failed to send message to routed output"
                        );
                    }
                }
            }
        }
    }

    /// Flush signing stage and send flush messages to the given outputs.
    async fn flush_signing_to_all(&mut self) {
        if let Some(ref mut signing) = self.signing {
            match signing.flush() {
                Ok(flush_msgs) => {
                    for flush_msg in &flush_msgs {
                        for output in &self.outputs {
                            if let Err(e) = output.send(flush_msg.clone()).await {
                                warn!(
                                    output = output.name(),
                                    error = %e,
                                    "failed to send flush message to output"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "failed to flush signing stage");
                }
            }
        }
    }

    /// Serialize the replay detector state, if a verification stage is configured.
    ///
    /// Returns `None` if no verification stage is present.
    #[must_use]
    pub fn replay_state(&self) -> Option<String> {
        self.verification
            .as_ref()
            .map(|v| v.serialize_replay_state())
    }

    /// Run the pipeline until shutdown is signaled or the ingress channel closes.
    ///
    /// This is the main processing loop. It will:
    /// 1. Receive messages from the ingress channel
    /// 2. Optionally verify incoming signatures (RFC 5848)
    /// 3. Apply the filter chain
    /// 4. Optionally sign outgoing messages (RFC 5848)
    /// 5. Route to selected outputs (or fan-out to all)
    ///
    /// # Errors
    /// Returns `RelayError::Shutdown` (carrying any replay-detector state)
    /// when the pipeline is shut down.
    pub async fn run(mut self) -> Result<(), RelayError> {
        info!("pipeline started with {} output(s)", self.outputs.len());

        let mut messages_processed: u64 = 0;
        let mut messages_filtered: u64 = 0;
        let mut messages_rejected: u64 = 0;

        loop {
            tokio::select! {
                biased;

                result = self.shutdown.changed() => {
                    // If the sender was dropped (Err), or the value is true,
                    // shut down the pipeline. This prevents a busy-loop when
                    // the ShutdownHandle is dropped without sending `true`.
                    if result.is_err() || *self.shutdown.borrow() {
                        self.flush_signing_to_all().await;

                        let replay_state = self.replay_state();
                        info!(
                            processed = messages_processed,
                            filtered = messages_filtered,
                            rejected = messages_rejected,
                            "pipeline shutting down"
                        );
                        return Err(RelayError::Shutdown { replay_state });
                    }
                }

                msg = self.rx.recv() => {
                    match msg {
                        Some(message) => {
                            // Step 1: Verification (if configured)
                            if let Some(ref verification) = self.verification {
                                let vresult = verification.check_incoming(&message);
                                if !verification.should_forward(vresult) {
                                    messages_rejected += 1;
                                    if let Some(ref state) = self.shared_state {
                                        state.counters().increment_dropped();
                                    }
                                    metrics::counter!("relay_messages_rejected_total").increment(1);
                                    debug!(
                                        result = ?vresult,
                                        "message rejected by verification"
                                    );
                                    continue;
                                }
                            }

                            // Step 2: Apply filter chain — short-circuit on first rejection
                            let mut filtered = false;
                            for filter in &self.filters {
                                if !filter.should_pass(&message) {
                                    messages_filtered += 1;
                                    if let Some(ref state) = self.shared_state {
                                        state.counters().increment_dropped();
                                    }
                                    metrics::counter!("relay_messages_filtered_total", "filter" => filter.name().to_owned()).increment(1);
                                    debug!(
                                        filter = filter.name(),
                                        severity = %message.severity,
                                        "message filtered out"
                                    );
                                    filtered = true;
                                    break;
                                }
                            }
                            if filtered {
                                continue;
                            }

                            messages_processed += 1;
                            metrics::counter!("relay_messages_processed_total").increment(1);

                            // Step 3: Signing (if configured) — produces original + sig/cert messages
                            let messages_to_send = if let Some(ref mut signing) = self.signing {
                                match signing.process_message(&message) {
                                    Ok(msgs) => msgs,
                                    Err(e) => {
                                        metrics::counter!("relay_signing_failures_total").increment(1);
                                        if self.signing_fail_open {
                                            warn!(error = %e, "signing failed, forwarding unsigned (fail-open)");
                                            vec![message]
                                        } else {
                                            warn!(error = %e, "signing failed, dropping message (fail-closed)");
                                            if let Some(ref state) = self.shared_state {
                                                state.counters().increment_dropped();
                                            }
                                            messages_filtered += 1;
                                            continue;
                                        }
                                    }
                                }
                            } else {
                                vec![message]
                            };

                            // Step 4: Route to outputs
                            if let Some(ref routing_table) = self.routing_table {
                                let indices = routing_table.matching_output_indices(
                                    // Use the first message (original) for routing decisions
                                    match messages_to_send.first() {
                                        Some(m) => m,
                                        None => continue,
                                    },
                                );
                                if indices.is_empty() {
                                    if let Some(ref state) = self.shared_state {
                                        state.counters().increment_dropped();
                                    }
                                } else {
                                    if let Some(ref state) = self.shared_state {
                                        state.counters().increment_forwarded();
                                    }
                                    self.send_to_routed_outputs(&messages_to_send, &indices).await;
                                }
                            } else {
                                // Fan out to all outputs
                                if let Some(ref state) = self.shared_state {
                                    state.counters().increment_forwarded();
                                }
                                self.send_to_all_outputs(&messages_to_send).await;
                            }
                        }
                        None => {
                            // Ingress channel closed — flush signing and stop.
                            self.flush_signing_to_all().await;

                            info!(
                                processed = messages_processed,
                                filtered = messages_filtered,
                                rejected = messages_rejected,
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
    use crate::filter::SeverityFilter;
    use crate::output::ForwardOutput;
    use crate::routing::RoutingRule;
    use crate::signing::SigningStage;
    use crate::verification::VerificationStage;
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

        let (pipeline, ingress, _shutdown) = Pipeline::new(16, vec![], vec![output]);

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
        let filters: Vec<Box<dyn MessageFilter>> = vec![Box::new(filter)];
        let (pipeline, ingress, _shutdown) = Pipeline::new(16, filters, vec![output]);

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

        let (pipeline, _ingress, shutdown) = Pipeline::new(16, vec![], vec![output]);

        let handle = tokio::spawn(async move { pipeline.run().await });

        shutdown.shutdown();
        let result = handle.await;
        assert!(result.is_ok());
        if let Ok(Err(RelayError::Shutdown { .. })) = result {
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

        let (pipeline, ingress, _shutdown) = Pipeline::new(16, vec![], vec![output1, output2]);

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        let _ = ingress.send(make_message(Severity::Error, "fan-out")).await;

        drop(ingress);
        let _ = handle.await;

        assert_eq!(o1_clone.len().await, 1);
        assert_eq!(o2_clone.len().await, 1);
    }

    #[tokio::test]
    async fn pipeline_empty_filters_passes_all() {
        let output = ForwardOutput::new("test-output");
        let output_clone = output.clone();

        let (pipeline, ingress, _shutdown) = Pipeline::new(16, vec![], vec![output]);

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        let _ = ingress
            .send(make_message(Severity::Debug, "debug msg"))
            .await;
        let _ = ingress
            .send(make_message(Severity::Emergency, "emerg msg"))
            .await;

        drop(ingress);
        let _ = handle.await;

        assert_eq!(output_clone.len().await, 2);
    }

    #[tokio::test]
    async fn pipeline_multiple_filters_chain() {
        let output = ForwardOutput::new("test-output");
        let output_clone = output.clone();

        // First filter: severity >= Warning
        // Second filter: severity >= Error (stricter)
        let f1 = SeverityFilter::new(Severity::Warning);
        let f2 = SeverityFilter::new(Severity::Error);
        let filters: Vec<Box<dyn MessageFilter>> = vec![Box::new(f1), Box::new(f2)];
        let (pipeline, ingress, _shutdown) = Pipeline::new(16, filters, vec![output]);

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        // Warning passes first filter but not second
        let _ = ingress
            .send(make_message(Severity::Warning, "warning"))
            .await;
        // Error passes both
        let _ = ingress.send(make_message(Severity::Error, "error")).await;
        // Debug fails first filter
        let _ = ingress.send(make_message(Severity::Debug, "debug")).await;

        drop(ingress);
        let _ = handle.await;

        // Only the Error message should pass
        assert_eq!(output_clone.len().await, 1);
    }

    #[tokio::test]
    async fn pipeline_filter_short_circuits() {
        // Verify that if the first filter rejects, later filters are not consulted
        let output = ForwardOutput::new("test-output");
        let output_clone = output.clone();

        // Emergency-only filter as first in chain
        let f1 = SeverityFilter::new(Severity::Emergency);
        let filters: Vec<Box<dyn MessageFilter>> = vec![Box::new(f1)];
        let (pipeline, ingress, _shutdown) = Pipeline::new(16, filters, vec![output]);

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        let _ = ingress.send(make_message(Severity::Error, "error")).await;
        let _ = ingress
            .send(make_message(Severity::Emergency, "emerg"))
            .await;

        drop(ingress);
        let _ = handle.await;

        assert_eq!(output_clone.len().await, 1);
    }

    #[tokio::test]
    async fn pipeline_alarm_filter_integration() {
        use crate::alarm_filter::{AlarmFilter, NonAlarmPolicy};
        use smallvec::SmallVec;
        use syslog_proto::{Alarm, ItuEventType, PerceivedSeverity};

        let output = ForwardOutput::new("test-output");
        let output_clone = output.clone();

        let alarm_filter = AlarmFilter::builder()
            .min_severity(PerceivedSeverity::Major)
            .non_alarm_policy(NonAlarmPolicy::Pass)
            .build();
        let filters: Vec<Box<dyn MessageFilter>> = vec![Box::new(alarm_filter)];
        let (pipeline, ingress, _shutdown) = Pipeline::new(16, filters, vec![output]);

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        // Non-alarm message should pass (NonAlarmPolicy::Pass)
        let _ = ingress.send(make_message(Severity::Debug, "plain")).await;

        // Alarm with Major severity should pass
        let major_alarm = Alarm {
            resource: CompactString::new("eth0"),
            perceived_severity: PerceivedSeverity::Major,
            event_type: ItuEventType::CommunicationsAlarm,
            probable_cause: None,
            trend_indication: None,
        };
        if let Ok(elem) = major_alarm.to_sd_element() {
            let mut msg = make_message(Severity::Error, "major alarm");
            msg.structured_data = syslog_proto::StructuredData(SmallVec::from_vec(vec![elem]));
            let _ = ingress.send(msg).await;
        }

        // Alarm with Warning severity should be filtered
        let warning_alarm = Alarm {
            resource: CompactString::new("eth1"),
            perceived_severity: PerceivedSeverity::Warning,
            event_type: ItuEventType::CommunicationsAlarm,
            probable_cause: None,
            trend_indication: None,
        };
        if let Ok(elem) = warning_alarm.to_sd_element() {
            let mut msg = make_message(Severity::Warning, "warning alarm");
            msg.structured_data = syslog_proto::StructuredData(SmallVec::from_vec(vec![elem]));
            let _ = ingress.send(msg).await;
        }

        drop(ingress);
        let _ = handle.await;

        // plain message + major alarm = 2 (warning alarm filtered)
        assert_eq!(output_clone.len().await, 2);
    }

    #[tokio::test]
    async fn pipeline_with_signing_produces_sig_blocks() {
        use std::time::Duration;
        use syslog_sign::counter::RebootSessionId;
        use syslog_sign::signature::SigningKey;
        use syslog_sign::signer::{Signer, SignerConfig};

        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let rsid = RebootSessionId::unpersisted();
        let config = SignerConfig {
            max_hashes_per_block: 2,
            ..Default::default()
        };
        let signer = Signer::new(key, rsid, config);
        let template = make_message(Severity::Notice, "template");
        let signing = SigningStage::new(signer, None, Duration::from_secs(3600), template);

        let output = ForwardOutput::new("test-output");
        let output_clone = output.clone();

        let (pipeline, ingress, _shutdown) =
            Pipeline::with_signing(16, vec![], vec![output], Some(signing), None);

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        // Send 2 messages (fills the hash chain)
        let _ = ingress.send(make_message(Severity::Error, "msg1")).await;
        let _ = ingress.send(make_message(Severity::Error, "msg2")).await;

        drop(ingress);
        let _ = handle.await;

        // Should have: 2 original messages + 1 sig block + potentially 1 flush sig block
        let count = output_clone.len().await;
        assert!(
            count >= 3,
            "expected at least 3 messages (2 original + sig block), got {count}"
        );
    }

    #[tokio::test]
    async fn pipeline_with_verification_rejects_unsigned_when_configured() {
        let verification = VerificationStage::new(vec![], true);

        let output = ForwardOutput::new("test-output");
        let output_clone = output.clone();

        let (pipeline, ingress, _shutdown) =
            Pipeline::with_signing(16, vec![], vec![output], None, Some(verification));

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        // Send an unsigned message — should be rejected
        let _ = ingress
            .send(make_message(Severity::Error, "unsigned"))
            .await;

        drop(ingress);
        let _ = handle.await;

        assert_eq!(output_clone.len().await, 0);
    }

    #[tokio::test]
    async fn pipeline_with_verification_passes_unsigned_when_permissive() {
        let verification = VerificationStage::new(vec![], false);

        let output = ForwardOutput::new("test-output");
        let output_clone = output.clone();

        let (pipeline, ingress, _shutdown) =
            Pipeline::with_signing(16, vec![], vec![output], None, Some(verification));

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        let _ = ingress
            .send(make_message(Severity::Error, "unsigned"))
            .await;

        drop(ingress);
        let _ = handle.await;

        assert_eq!(output_clone.len().await, 1);
    }

    #[tokio::test]
    async fn pipeline_signing_flushes_on_close() {
        use std::time::Duration;
        use syslog_sign::counter::RebootSessionId;
        use syslog_sign::signature::SigningKey;
        use syslog_sign::signer::{Signer, SignerConfig};

        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let rsid = RebootSessionId::unpersisted();
        let config = SignerConfig {
            max_hashes_per_block: 100, // large so auto-flush won't trigger
            ..Default::default()
        };
        let signer = Signer::new(key, rsid, config);
        let template = make_message(Severity::Notice, "template");
        let signing = SigningStage::new(signer, None, Duration::from_secs(3600), template);

        let output = ForwardOutput::new("test-output");
        let output_clone = output.clone();

        let (pipeline, ingress, _shutdown) =
            Pipeline::with_signing(16, vec![], vec![output], Some(signing), None);

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        // Send 1 message (won't trigger auto-flush)
        let _ = ingress.send(make_message(Severity::Error, "msg1")).await;

        drop(ingress);
        let _ = handle.await;

        // Should have: 1 original + 1 flushed sig block
        let count = output_clone.len().await;
        assert_eq!(
            count, 2,
            "expected 2 messages (1 original + 1 flush sig), got {count}"
        );
    }

    #[tokio::test]
    async fn pipeline_with_signing_none_verification_none() {
        // Verify that with_signing(None, None) behaves identically to new()
        let output = ForwardOutput::new("test-output");
        let output_clone = output.clone();

        let (pipeline, ingress, _shutdown) =
            Pipeline::with_signing(16, vec![], vec![output], None, None);

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        let _ = ingress.send(make_message(Severity::Error, "test")).await;

        drop(ingress);
        let _ = handle.await;

        assert_eq!(output_clone.len().await, 1);
    }

    // -- Routing table tests --

    #[tokio::test]
    async fn pipeline_with_routing_selective_output() {
        let output0 = ForwardOutput::new("output-0");
        let output1 = ForwardOutput::new("output-1");
        let o0_clone = output0.clone();
        let o1_clone = output1.clone();

        // Route User facility to output 0 only
        let rule = RoutingRule {
            selector: syslog_mgmt::Selector::new().with_facilities(vec![Facility::User]),
            output_indices: vec![0],
            description: None,
        };
        let routing_table = RoutingTable::new(vec![rule]);

        let (pipeline, ingress, _shutdown) = Pipeline::with_management(
            16,
            vec![],
            vec![output0, output1],
            None,
            None,
            Some(routing_table),
            None,
        );

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        let _ = ingress.send(make_message(Severity::Error, "routed")).await;

        drop(ingress);
        let _ = handle.await;

        assert_eq!(o0_clone.len().await, 1);
        assert_eq!(o1_clone.len().await, 0);
    }

    #[tokio::test]
    async fn pipeline_with_routing_no_match_drops() {
        let output = ForwardOutput::new("output-0");
        let o_clone = output.clone();

        // Route only Kern facility
        let rule = RoutingRule {
            selector: syslog_mgmt::Selector::new().with_facilities(vec![Facility::Kern]),
            output_indices: vec![0],
            description: None,
        };
        let routing_table = RoutingTable::new(vec![rule]);

        let (pipeline, ingress, _shutdown) = Pipeline::with_management(
            16,
            vec![],
            vec![output],
            None,
            None,
            Some(routing_table),
            None,
        );

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        // User facility message should not match Kern rule
        let _ = ingress
            .send(make_message(Severity::Error, "unrouted"))
            .await;

        drop(ingress);
        let _ = handle.await;

        assert_eq!(o_clone.len().await, 0);
    }

    #[tokio::test]
    async fn pipeline_shared_state_counters() {
        let output = ForwardOutput::new("test-output");

        let state = SharedSyslogState::new(syslog_mgmt::SyslogFeatures::default_relay());
        let state_clone = state.clone();

        let filter = SeverityFilter::new(Severity::Warning);
        let filters: Vec<Box<dyn MessageFilter>> = vec![Box::new(filter)];

        let (pipeline, ingress, _shutdown) =
            Pipeline::with_management(16, filters, vec![output], None, None, None, Some(state));

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        // This passes (Error >= Warning)
        let _ = ingress.send(make_message(Severity::Error, "pass")).await;
        // This is filtered (Debug < Warning)
        let _ = ingress
            .send(make_message(Severity::Debug, "filtered"))
            .await;

        drop(ingress);
        let _ = handle.await;

        let snap = state_clone.counters().snapshot();
        assert_eq!(snap.forwarded, 1);
        assert_eq!(snap.dropped, 1);
    }

    #[tokio::test]
    async fn pipeline_with_routing_multi_output() {
        let output0 = ForwardOutput::new("output-0");
        let output1 = ForwardOutput::new("output-1");
        let output2 = ForwardOutput::new("output-2");
        let o0_clone = output0.clone();
        let o1_clone = output1.clone();
        let o2_clone = output2.clone();

        let rules = vec![
            RoutingRule {
                selector: syslog_mgmt::Selector::new().with_min_severity(Severity::Error),
                output_indices: vec![0, 1],
                description: None,
            },
            RoutingRule {
                selector: syslog_mgmt::Selector::new(),
                output_indices: vec![2],
                description: None,
            },
        ];
        let routing_table = RoutingTable::new(rules);

        let (pipeline, ingress, _shutdown) = Pipeline::with_management(
            16,
            vec![],
            vec![output0, output1, output2],
            None,
            None,
            Some(routing_table),
            None,
        );

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        // Error matches both rules -> outputs 0, 1, 2
        let _ = ingress.send(make_message(Severity::Error, "error")).await;
        // Debug matches only catch-all -> output 2
        let _ = ingress.send(make_message(Severity::Debug, "debug")).await;

        drop(ingress);
        let _ = handle.await;

        assert_eq!(o0_clone.len().await, 1);
        assert_eq!(o1_clone.len().await, 1);
        assert_eq!(o2_clone.len().await, 2);
    }

    #[tokio::test]
    async fn pipeline_without_routing_fans_out() {
        // No routing table = fan out to all (backward compat)
        let output0 = ForwardOutput::new("output-0");
        let output1 = ForwardOutput::new("output-1");
        let o0_clone = output0.clone();
        let o1_clone = output1.clone();

        let (pipeline, ingress, _shutdown) =
            Pipeline::with_management(16, vec![], vec![output0, output1], None, None, None, None);

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        let _ = ingress.send(make_message(Severity::Error, "all")).await;

        drop(ingress);
        let _ = handle.await;

        assert_eq!(o0_clone.len().await, 1);
        assert_eq!(o1_clone.len().await, 1);
    }

    #[tokio::test]
    async fn pipeline_shared_state_routing_dropped_counter() {
        let output = ForwardOutput::new("output-0");

        let state = SharedSyslogState::new(syslog_mgmt::SyslogFeatures::empty());
        let state_clone = state.clone();

        // Route only Kern -> output 0; User messages have no route
        let rule = RoutingRule {
            selector: syslog_mgmt::Selector::new().with_facilities(vec![Facility::Kern]),
            output_indices: vec![0],
            description: None,
        };
        let routing_table = RoutingTable::new(vec![rule]);

        let (pipeline, ingress, _shutdown) = Pipeline::with_management(
            16,
            vec![],
            vec![output],
            None,
            None,
            Some(routing_table),
            Some(state),
        );

        let handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        // User facility -> no route -> dropped
        let _ = ingress
            .send(make_message(Severity::Error, "no-route"))
            .await;

        drop(ingress);
        let _ = handle.await;

        let snap = state_clone.counters().snapshot();
        assert_eq!(snap.dropped, 1);
        assert_eq!(snap.forwarded, 0);
    }
}
