//! Verification stage for the relay pipeline.
//!
//! Checks incoming messages for RFC 5848 signature blocks and verifies
//! the cryptographic signature using configured trusted keys.

use syslog_proto::SyslogMessage;
use syslog_sign::blocks::{SignatureBlock, find_ssign};
use syslog_sign::verifier::Verifier;
use tracing::{debug, warn};

/// Result of signature verification for an incoming message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// The message has a valid signature.
    Pass,
    /// The message has an invalid signature and should be rejected.
    Reject,
    /// The message has no signature (or no matching verifier key).
    Unverified,
}

/// A verification stage that checks incoming messages for RFC 5848 signatures.
///
/// When `reject_unverified` is true, messages without valid signatures
/// are rejected. Otherwise, unsigned messages pass through unchanged.
pub struct VerificationStage {
    /// Configured verifiers (one per trusted public key).
    verifiers: Vec<Verifier>,
    /// Whether to reject messages that cannot be verified.
    reject_unverified: bool,
}

impl std::fmt::Debug for VerificationStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationStage")
            .field("verifier_count", &self.verifiers.len())
            .field("reject_unverified", &self.reject_unverified)
            .finish()
    }
}

impl VerificationStage {
    /// Create a new verification stage.
    ///
    /// - `verifiers`: List of verifiers, one per trusted public key.
    /// - `reject_unverified`: If true, messages without valid signatures are rejected.
    #[must_use]
    pub fn new(verifiers: Vec<Verifier>, reject_unverified: bool) -> Self {
        Self {
            verifiers,
            reject_unverified,
        }
    }

    /// Check an incoming message for a valid signature.
    ///
    /// Returns [`VerificationResult::Pass`] if the message has a valid
    /// `ssign` signature block that verifies against any trusted key.
    ///
    /// Returns [`VerificationResult::Reject`] if the message has an `ssign`
    /// block but it fails verification with all trusted keys.
    ///
    /// Returns [`VerificationResult::Unverified`] if the message has no
    /// `ssign` structured data element.
    #[must_use]
    pub fn check_incoming(&self, msg: &SyslogMessage) -> VerificationResult {
        let ssign_element = match find_ssign(&msg.structured_data) {
            Some(el) => el,
            None => {
                debug!("message has no ssign element");
                return VerificationResult::Unverified;
            }
        };

        let sig_block = match SignatureBlock::from_sd_element(ssign_element) {
            Ok(block) => block,
            Err(e) => {
                warn!(error = %e, "failed to parse ssign element");
                return VerificationResult::Reject;
            }
        };

        // Try each verifier
        for verifier in &self.verifiers {
            if verifier.verify_block(&sig_block).is_ok() {
                debug!(gbc = sig_block.gbc, "signature verification passed");
                return VerificationResult::Pass;
            }
        }

        warn!(
            gbc = sig_block.gbc,
            "signature verification failed with all trusted keys"
        );
        VerificationResult::Reject
    }

    /// Whether messages that are [`VerificationResult::Unverified`] should
    /// be treated as rejected.
    #[must_use]
    pub fn reject_unverified(&self) -> bool {
        self.reject_unverified
    }

    /// Determine if a message should be forwarded based on the verification result.
    ///
    /// Returns `true` if the message should be passed through.
    #[must_use]
    pub fn should_forward(&self, result: VerificationResult) -> bool {
        match result {
            VerificationResult::Pass => true,
            VerificationResult::Reject => false,
            VerificationResult::Unverified => !self.reject_unverified,
        }
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
    use smallvec::SmallVec;
    use syslog_proto::{Facility, Severity, StructuredData, SyslogTimestamp};
    use syslog_sign::counter::RebootSessionId;
    use syslog_sign::signature::{SigningKey, VerifyingKey};
    use syslog_sign::signer::{Signer, SignerConfig};

    fn make_message(body: &str) -> SyslogMessage {
        SyslogMessage {
            facility: Facility::User,
            severity: Severity::Notice,
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

    fn make_signed_message() -> Option<(SyslogMessage, Vec<u8>)> {
        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let pub_bytes = key.public_key_bytes().to_vec();
        let rsid = RebootSessionId::unpersisted();
        let config = SignerConfig {
            max_hashes_per_block: 1,
            ..Default::default()
        };
        let mut signer = Signer::new(key, rsid, config);

        // Feed a message to get a sig block
        let block = match signer.add_message(b"test data") {
            Ok(Some(b)) => b,
            _ => return None,
        };

        let sd_element = match block.to_sd_element() {
            Ok(e) => e,
            Err(_) => return None,
        };

        let mut msg = make_message("test");
        msg.structured_data = StructuredData(SmallVec::from_vec(vec![sd_element]));

        Some((msg, pub_bytes))
    }

    #[test]
    fn unverified_without_ssign() {
        let stage = VerificationStage::new(vec![], false);
        let msg = make_message("no sig");
        let result = stage.check_incoming(&msg);
        assert_eq!(result, VerificationResult::Unverified);
    }

    #[test]
    fn should_forward_unverified_when_not_rejecting() {
        let stage = VerificationStage::new(vec![], false);
        assert!(stage.should_forward(VerificationResult::Unverified));
        assert!(stage.should_forward(VerificationResult::Pass));
        assert!(!stage.should_forward(VerificationResult::Reject));
    }

    #[test]
    fn should_reject_unverified_when_configured() {
        let stage = VerificationStage::new(vec![], true);
        assert!(!stage.should_forward(VerificationResult::Unverified));
        assert!(stage.should_forward(VerificationResult::Pass));
        assert!(!stage.should_forward(VerificationResult::Reject));
    }

    #[test]
    fn pass_with_valid_signature() {
        let (msg, pub_bytes) = match make_signed_message() {
            Some(v) => v,
            None => return,
        };

        let verifier = Verifier::new(VerifyingKey::new(pub_bytes));
        let stage = VerificationStage::new(vec![verifier], false);
        let result = stage.check_incoming(&msg);
        assert_eq!(result, VerificationResult::Pass);
    }

    #[test]
    fn reject_with_wrong_key() {
        let (msg, _pub_bytes) = match make_signed_message() {
            Some(v) => v,
            None => return,
        };

        // Create a verifier with a different key
        let (other_key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let verifier = Verifier::new(VerifyingKey::new(other_key.public_key_bytes().to_vec()));
        let stage = VerificationStage::new(vec![verifier], false);
        let result = stage.check_incoming(&msg);
        assert_eq!(result, VerificationResult::Reject);
    }

    #[test]
    fn reject_unverified_flag() {
        let stage = VerificationStage::new(vec![], true);
        assert!(stage.reject_unverified());

        let stage2 = VerificationStage::new(vec![], false);
        assert!(!stage2.reject_unverified());
    }

    #[test]
    fn verification_stage_debug() {
        let stage = VerificationStage::new(vec![], false);
        let debug_str = format!("{stage:?}");
        assert!(debug_str.contains("VerificationStage"));
        assert!(debug_str.contains("verifier_count"));
    }
}
