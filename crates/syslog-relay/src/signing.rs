//! Signing stage for the relay pipeline.
//!
//! Wraps the [`syslog_sign::Signer`] to integrate with the relay pipeline,
//! automatically producing signature and certificate block messages alongside
//! the original syslog messages.

use std::time::{Duration, Instant};

use syslog_proto::SyslogMessage;
use syslog_sign::error::SignError;
use syslog_sign::prepare::{
    build_certificate_message, build_signature_message, serialize_for_signing,
};
use syslog_sign::signer::Signer;
use tracing::debug;

/// A signing stage that wraps a [`Signer`] and produces signed messages
/// for the relay pipeline.
///
/// This stage:
/// 1. Serializes each message (stripping `ssign`/`ssign-cert` SD elements)
/// 2. Feeds the serialized bytes into the signer's hash chain
/// 3. When the chain fills, emits signature block messages
/// 4. Periodically emits certificate block messages
pub struct SigningStage {
    /// The underlying signer.
    signer: Signer,
    /// DER-encoded X.509 certificate for the signing key.
    certificate_der: Option<Vec<u8>>,
    /// How often to emit certificate blocks.
    cert_interval: Duration,
    /// When certificate blocks were last emitted.
    last_cert_emit: Instant,
    /// Template message for constructing signature/certificate messages.
    template: SyslogMessage,
}

impl std::fmt::Debug for SigningStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningStage")
            .field("signer", &self.signer)
            .field("has_certificate", &self.certificate_der.is_some())
            .field("cert_interval", &self.cert_interval)
            .finish_non_exhaustive()
    }
}

impl SigningStage {
    /// Create a new signing stage.
    ///
    /// - `signer`: The configured [`Signer`] with key and settings.
    /// - `certificate_der`: Optional DER-encoded X.509 certificate.
    /// - `cert_interval`: How often to emit certificate blocks.
    /// - `template`: Template message for header fields (hostname, etc.).
    #[must_use]
    pub fn new(
        signer: Signer,
        certificate_der: Option<Vec<u8>>,
        cert_interval: Duration,
        template: SyslogMessage,
    ) -> Self {
        Self {
            signer,
            certificate_der,
            cert_interval,
            last_cert_emit: Instant::now(),
            template,
        }
    }

    /// Process a message through the signing stage.
    ///
    /// Returns a list of messages to emit: the original message followed by
    /// any signature block and/or certificate block messages.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if signing fails.
    pub fn process_message(
        &mut self,
        msg: &SyslogMessage,
    ) -> Result<Vec<SyslogMessage>, SignError> {
        let mut result = vec![msg.clone()];

        // Serialize for signing (strips ssign/ssign-cert)
        let wire_bytes = serialize_for_signing(msg);

        // Feed to signer
        if let Some(sig_block) = self.signer.add_message(&wire_bytes)? {
            let sig_msg = build_signature_message(&sig_block, &self.template)?;
            debug!(
                gbc = sig_block.gbc,
                cnt = sig_block.cnt,
                "emitting signature block"
            );
            result.push(sig_msg);
        }

        // Emit certificate blocks periodically
        if self.last_cert_emit.elapsed() >= self.cert_interval {
            let cert_msgs = self.emit_certificate_blocks()?;
            result.extend(cert_msgs);
            self.last_cert_emit = Instant::now();
        }

        Ok(result)
    }

    /// Flush any pending hashes from the signer, producing a final
    /// signature block message if there are pending hashes.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if signing fails.
    pub fn flush(&mut self) -> Result<Vec<SyslogMessage>, SignError> {
        let mut result = Vec::new();

        if let Some(sig_block) = self.signer.flush()? {
            let sig_msg = build_signature_message(&sig_block, &self.template)?;
            debug!(
                gbc = sig_block.gbc,
                cnt = sig_block.cnt,
                "flushing final signature block"
            );
            result.push(sig_msg);
        }

        Ok(result)
    }

    /// Emit certificate blocks for the signing key's certificate.
    fn emit_certificate_blocks(&self) -> Result<Vec<SyslogMessage>, SignError> {
        let cert_der = match &self.certificate_der {
            Some(c) => c,
            None => return Ok(Vec::new()),
        };

        let cert_blocks = self.signer.certificate_blocks(cert_der)?;
        let mut msgs = Vec::with_capacity(cert_blocks.len());
        for block in &cert_blocks {
            let cert_msg = build_certificate_message(block, &self.template)?;
            msgs.push(cert_msg);
        }
        debug!(count = msgs.len(), "emitting certificate blocks");
        Ok(msgs)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use compact_str::CompactString;
    use syslog_proto::{Facility, Severity, StructuredData, SyslogTimestamp};
    use syslog_sign::counter::RebootSessionId;
    use syslog_sign::signature::SigningKey;
    use syslog_sign::signer::SignerConfig;
    use syslog_sign::types::SSIGN_SD_ID;

    fn make_template() -> SyslogMessage {
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
            msg: Some(Bytes::from_static(b"test")),
            raw: None,
        }
    }

    fn make_test_message(body: &str) -> SyslogMessage {
        SyslogMessage {
            facility: Facility::User,
            severity: Severity::Error,
            version: 1,
            timestamp: SyslogTimestamp::Nil,
            hostname: Some(CompactString::new("host")),
            app_name: Some(CompactString::new("app")),
            proc_id: None,
            msg_id: None,
            structured_data: StructuredData::nil(),
            msg: Some(Bytes::from(body.to_owned())),
            raw: None,
        }
    }

    fn make_signing_stage(max_hashes: usize) -> Option<SigningStage> {
        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let rsid = RebootSessionId::unpersisted();
        let config = SignerConfig {
            max_hashes_per_block: max_hashes,
            ..Default::default()
        };
        let signer = Signer::new(key, rsid, config);
        Some(SigningStage::new(
            signer,
            None,
            Duration::from_secs(3600),
            make_template(),
        ))
    }

    #[test]
    fn process_message_returns_original() {
        let mut stage = match make_signing_stage(10) {
            Some(s) => s,
            None => return,
        };

        let msg = make_test_message("hello");
        let result = stage.process_message(&msg);
        assert!(result.is_ok());
        if let Ok(msgs) = result {
            // At minimum, the original message should be returned
            assert!(!msgs.is_empty());
            if let Some(first) = msgs.first() {
                assert_eq!(first.msg.as_deref(), Some(b"hello".as_slice()));
            }
        }
    }

    #[test]
    fn process_produces_sig_block_when_full() {
        let mut stage = match make_signing_stage(2) {
            Some(s) => s,
            None => return,
        };

        let msg1 = make_test_message("msg1");
        let r1 = stage.process_message(&msg1);
        assert!(r1.is_ok());
        // First message: no sig block yet
        if let Ok(msgs) = r1 {
            assert_eq!(msgs.len(), 1);
        }

        let msg2 = make_test_message("msg2");
        let r2 = stage.process_message(&msg2);
        assert!(r2.is_ok());
        // Second message: chain is full, should emit sig block
        if let Ok(msgs) = r2 {
            assert_eq!(msgs.len(), 2);
            // Second message should be a signature block
            if let Some(sig_msg) = msgs.get(1) {
                assert_eq!(sig_msg.facility, Facility::Syslog);
                assert_eq!(sig_msg.app_name.as_deref(), Some("syslog-sign"));
                assert!(sig_msg.structured_data.find_by_id(SSIGN_SD_ID).is_some());
            }
        }
    }

    #[test]
    fn flush_produces_sig_block_for_pending() {
        let mut stage = match make_signing_stage(10) {
            Some(s) => s,
            None => return,
        };

        let msg = make_test_message("pending");
        let _ = stage.process_message(&msg);

        let result = stage.flush();
        assert!(result.is_ok());
        if let Ok(msgs) = result {
            assert_eq!(msgs.len(), 1);
            if let Some(sig_msg) = msgs.first() {
                assert!(sig_msg.structured_data.find_by_id(SSIGN_SD_ID).is_some());
            }
        }
    }

    #[test]
    fn flush_empty_produces_nothing() {
        let mut stage = match make_signing_stage(10) {
            Some(s) => s,
            None => return,
        };

        let result = stage.flush();
        assert!(result.is_ok());
        if let Ok(msgs) = result {
            assert!(msgs.is_empty());
        }
    }

    #[test]
    fn signing_stage_with_certificate() {
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
        let fake_cert = vec![0x30; 100];

        let mut stage = SigningStage::new(
            signer,
            Some(fake_cert),
            // Use zero duration so certs are always emitted
            Duration::from_secs(0),
            make_template(),
        );

        let msg = make_test_message("with cert");
        let result = stage.process_message(&msg);
        assert!(result.is_ok());
        if let Ok(msgs) = result {
            // Should have: original msg + at least one cert block
            assert!(msgs.len() >= 2);
        }
    }

    #[test]
    fn signing_stage_debug() {
        let stage = make_signing_stage(10);
        if let Some(s) = stage {
            let debug_str = format!("{s:?}");
            assert!(debug_str.contains("SigningStage"));
        }
    }

    #[test]
    fn sig_block_message_has_correct_hostname() {
        let mut stage = match make_signing_stage(1) {
            Some(s) => s,
            None => return,
        };

        let msg = make_test_message("test");
        let result = stage.process_message(&msg);
        assert!(result.is_ok());
        if let Ok(msgs) = result {
            if let Some(sig_msg) = msgs.get(1) {
                assert_eq!(sig_msg.hostname.as_deref(), Some("testhost"));
            }
        }
    }
}
