//! Verification stage for the relay pipeline.
//!
//! Checks incoming messages for RFC 5848 signature blocks and verifies
//! the cryptographic signature using configured trusted keys.
//!
//! Includes replay protection via [`ReplayDetector`] to enforce GBC
//! monotonicity per RSID (RFC 5848 §5.3.2.2).

use std::sync::Mutex;

use syslog_proto::SyslogMessage;
use syslog_sign::blocks::{SignatureBlock, find_ssign};
use syslog_sign::types::SignatureScheme;
use syslog_sign::verifier::{ReplayDetector, Verifier};
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
    /// Replay detector — tracks GBC per RSID to reject replayed blocks.
    /// Uses a Mutex for interior mutability since check_incoming takes &self.
    replay_detector: Mutex<ReplayDetector>,
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
        Self::with_max_sessions(verifiers, reject_unverified, 4096)
    }

    /// Create a new verification stage with a custom replay detector session limit.
    ///
    /// - `max_sessions`: Maximum RSID sessions tracked for replay detection.
    ///   When full, the session with the lowest GBC is evicted.
    #[must_use]
    pub fn with_max_sessions(
        verifiers: Vec<Verifier>,
        reject_unverified: bool,
        max_sessions: usize,
    ) -> Self {
        if verifiers.is_empty() {
            warn!(
                "verification stage created with no trusted keys — all signatures will fail verification"
            );
        }
        Self {
            verifiers,
            reject_unverified,
            replay_detector: Mutex::new(ReplayDetector::with_max_sessions(max_sessions)),
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

        // RFC 5848 §4.2.2: warn if the incoming signature uses DSA (scheme=1),
        // which this implementation does not support — we use ECDSA P-256 instead.
        if sig_block.ver.signature_scheme == SignatureScheme::OpenPgpDsa {
            warn!(
                "RFC 5848 §4.2.2: incoming signature uses OpenPGP DSA (scheme=1), \
                 which this implementation cannot verify — only ECDSA P-256 (scheme=2) \
                 is supported (explicit deviation from RFC 5848)"
            );
        }

        // Try each verifier
        let mut sig_valid = false;
        for verifier in &self.verifiers {
            if verifier.verify_block(&sig_block).is_ok() {
                sig_valid = true;
                break;
            }
        }

        if !sig_valid {
            warn!(
                gbc = sig_block.gbc,
                "signature verification failed with all trusted keys"
            );
            return VerificationResult::Reject;
        }

        // RFC 5848 §5.3.2.2: check GBC monotonicity to detect replayed blocks
        match self.replay_detector.lock() {
            Ok(mut detector) => {
                if let Err(e) = detector.check(&sig_block) {
                    warn!(
                        gbc = sig_block.gbc,
                        rsid = sig_block.rsid,
                        error = %e,
                        "signature block rejected by replay detector"
                    );
                    return VerificationResult::Reject;
                }
            }
            Err(_) => {
                warn!("replay detector mutex poisoned, rejecting message for safety");
                return VerificationResult::Reject;
            }
        }

        debug!(gbc = sig_block.gbc, "signature verification passed");
        VerificationResult::Pass
    }

    /// Whether messages that are [`VerificationResult::Unverified`] should
    /// be treated as rejected.
    #[must_use]
    pub fn reject_unverified(&self) -> bool {
        self.reject_unverified
    }

    /// Returns the number of configured verifiers (trusted keys).
    #[must_use]
    pub fn verifier_count(&self) -> usize {
        self.verifiers.len()
    }

    /// Load persisted replay detector state from the serialized text format.
    ///
    /// See [`ReplayDetector::load_state`] for the format details.
    pub fn load_replay_state(&self, data: &str) {
        match self.replay_detector.lock() {
            Ok(mut detector) => {
                detector.load_state(data);
                debug!("loaded persisted replay detector state");
            }
            Err(_) => {
                warn!("replay detector mutex poisoned, cannot load persisted state");
            }
        }
    }

    /// Serialize the current replay detector state for persistence.
    ///
    /// See [`ReplayDetector::serialize_state`] for the format details.
    #[must_use]
    pub fn serialize_replay_state(&self) -> String {
        match self.replay_detector.lock() {
            Ok(detector) => detector.serialize_state(),
            Err(_) => {
                warn!("replay detector mutex poisoned, returning empty state");
                String::new()
            }
        }
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
        let block = match signer.add_message(b"test data", None) {
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
    fn reject_replayed_signature_block() {
        let (msg, pub_bytes) = match make_signed_message() {
            Some(v) => v,
            None => return,
        };

        let verifier = Verifier::new(VerifyingKey::new(pub_bytes));
        let stage = VerificationStage::new(vec![verifier], false);

        // First check should pass
        let result1 = stage.check_incoming(&msg);
        assert_eq!(result1, VerificationResult::Pass);

        // Same message again (same GBC) should be rejected as replay
        let result2 = stage.check_incoming(&msg);
        assert_eq!(result2, VerificationResult::Reject);
    }

    #[test]
    fn reject_dsa_scheme_signature() {
        // RFC 5848 §4.2.2: DSA (scheme=1) signatures cannot be verified
        // because this implementation only supports ECDSA P-256 (scheme=2).
        let sd_element = syslog_proto::SdElement {
            id: match syslog_proto::SdId::new("ssign") {
                Ok(id) => id,
                Err(_) => return,
            },
            params: SmallVec::from_vec(vec![
                syslog_proto::SdParam {
                    name: CompactString::new("VER"),
                    value: CompactString::new("0111"), // SHA-1 + DSA
                },
                syslog_proto::SdParam {
                    name: CompactString::new("RSID"),
                    value: CompactString::new("0"),
                },
                syslog_proto::SdParam {
                    name: CompactString::new("SG"),
                    value: CompactString::new("0"),
                },
                syslog_proto::SdParam {
                    name: CompactString::new("SPRI"),
                    value: CompactString::new("0"),
                },
                syslog_proto::SdParam {
                    name: CompactString::new("GBC"),
                    value: CompactString::new("1"),
                },
                syslog_proto::SdParam {
                    name: CompactString::new("FMN"),
                    value: CompactString::new("1"),
                },
                syslog_proto::SdParam {
                    name: CompactString::new("CNT"),
                    value: CompactString::new("1"),
                },
                syslog_proto::SdParam {
                    name: CompactString::new("HB"),
                    value: CompactString::new("dGVzdA=="), // base64 "test"
                },
                syslog_proto::SdParam {
                    name: CompactString::new("SIGN"),
                    value: CompactString::new("dGVzdA=="),
                },
            ]),
        };

        let mut msg = make_message("test");
        msg.structured_data = StructuredData(SmallVec::from_vec(vec![sd_element]));

        // Create a verifier with a real key (it won't matter — DSA scheme can't verify)
        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let verifier = Verifier::new(VerifyingKey::new(key.public_key_bytes().to_vec()));
        let stage = VerificationStage::new(vec![verifier], false);
        let result = stage.check_incoming(&msg);
        // Should reject because DSA signatures can't be verified with ECDSA keys
        assert_eq!(result, VerificationResult::Reject);
    }

    #[test]
    fn verification_stage_debug() {
        let stage = VerificationStage::new(vec![], false);
        let debug_str = format!("{stage:?}");
        assert!(debug_str.contains("VerificationStage"));
        assert!(debug_str.contains("verifier_count"));
    }
}
