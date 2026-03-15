//! High-level Verifier API for validating RFC 5848 signature blocks.
//!
//! The [`Verifier`] checks that signature blocks are correctly signed
//! and that the hash chain matches the original messages.
//!
//! # Replay Protection
//!
//! RFC 5848 §5.3.2.2 requires that verifiers track the Global Block Counter
//! (GBC) per Reboot Session ID (RSID) to detect replayed signature blocks.
//! Use [`ReplayDetector`] to enforce GBC monotonicity.

use std::collections::HashMap;

use rustls::RootCertStore;

use crate::blocks::SignatureBlock;
use crate::certificate;
use crate::encode::encode_hash_block;
use crate::error::SignError;
use crate::hash::hash_message;
use crate::signature::VerifyingKey;

/// Verifier for RFC 5848 signed syslog messages.
///
/// Validates signature blocks against a known public key and verifies
/// message hashes match the original message content.
#[derive(Debug)]
pub struct Verifier {
    key: VerifyingKey,
}

impl Verifier {
    /// Create a new verifier with the given public key.
    #[must_use]
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }

    /// Create a verifier from a DER-encoded X.509 certificate, validated
    /// against the provided trust anchors.
    ///
    /// RFC 5848 §4.2.6: Key blob type 'C' (PKIX) requires certificate path
    /// validation per RFC 5280 before using the public key.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::CertificateValidation`] if the certificate is
    /// invalid, expired, or not signed by a trusted CA.
    pub fn from_validated_certificate(
        cert_der: &[u8],
        intermediates: &[Vec<u8>],
        trust_anchors: &RootCertStore,
    ) -> Result<Self, SignError> {
        let spki_bytes = certificate::validate_certificate(cert_der, intermediates, trust_anchors)?;
        Ok(Self::new(VerifyingKey::new(spki_bytes)))
    }

    /// Verify that a signature block's signature is valid.
    ///
    /// This checks the cryptographic signature over the block's fields
    /// but does NOT verify individual message hashes (use [`verify_messages`]
    /// for that).
    ///
    /// # Errors
    ///
    /// Returns [`SignError::VerificationFailed`] if the signature is invalid.
    pub fn verify_block(&self, block: &SignatureBlock) -> Result<(), SignError> {
        // Reconstruct the signed data: VER + RSID + SG + SPRI + GBC + FMN + CNT + HB
        let hb_encoded = encode_hash_block(&block.hashes);
        let sign_data = format!(
            "{}{}{}{}{}{}{}{}",
            block.ver.encode(),
            block.rsid,
            block.sg.code(),
            block.spri,
            block.gbc,
            block.fmn,
            block.cnt,
            hb_encoded,
        );

        self.key.verify(sign_data.as_bytes(), &block.signature)
    }

    /// Verify that messages match the hashes in a signature block.
    ///
    /// `messages` should be the serialized RFC 5424 wire-format bytes of
    /// each message in the block (same order as when signed), with any
    /// `ssign`/`ssign-cert` SD elements removed.
    ///
    /// The number of messages must match `block.cnt`.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::HashChainMismatch`] if any hash doesn't match,
    /// or [`SignError::InvalidField`] if the message count is wrong.
    pub fn verify_messages(
        &self,
        block: &SignatureBlock,
        messages: &[&[u8]],
    ) -> Result<(), SignError> {
        if messages.len() != block.cnt {
            return Err(SignError::InvalidField {
                field: "CNT",
                reason: format!("expected {} messages, got {}", block.cnt, messages.len()),
            });
        }

        for (i, msg_data) in messages.iter().enumerate() {
            let computed = hash_message(block.ver.hash_algorithm, msg_data);
            let expected = block
                .hashes
                .get(i)
                .ok_or_else(|| SignError::HashChainMismatch {
                    index: i,
                    expected: String::from("<missing>"),
                    actual: hex_string(&computed),
                })?;

            // Use constant-time comparison to prevent timing side-channels
            if computed.len() != expected.len()
                || !bool::from(subtle::ConstantTimeEq::ct_eq(
                    computed.as_slice(),
                    expected.as_slice(),
                ))
            {
                return Err(SignError::HashChainMismatch {
                    index: i,
                    expected: hex_string(expected),
                    actual: hex_string(&computed),
                });
            }
        }

        Ok(())
    }

    /// Fully verify a signature block: check the signature AND verify
    /// messages match the hashes.
    ///
    /// This is a convenience method combining [`verify_block`] and
    /// [`verify_messages`].
    ///
    /// # Errors
    ///
    /// Returns the first error encountered.
    pub fn verify_full(&self, block: &SignatureBlock, messages: &[&[u8]]) -> Result<(), SignError> {
        self.verify_block(block)?;
        self.verify_messages(block, messages)
    }
}

/// Format bytes as hex string for error messages.
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Replay Detection
// ---------------------------------------------------------------------------

/// Tracks GBC values per RSID to detect replayed signature blocks.
///
/// RFC 5848 §5.3.2.2: The verifier MUST track the GBC per RSID and reject
/// signature blocks with a GBC that is not strictly monotonically increasing.
///
/// # Usage
///
/// Call [`check`](ReplayDetector::check) before accepting a signature block.
/// Returns `Ok(())` if the block's GBC is fresh (higher than any previously
/// seen GBC for that RSID), or `Err` if the block appears to be a replay.
#[derive(Debug, Default)]
pub struct ReplayDetector {
    /// Maps RSID → highest GBC seen for that session.
    seen: HashMap<u64, u64>,
    /// Maximum number of tracked RSIDs to bound memory usage.
    max_sessions: usize,
}

impl ReplayDetector {
    /// Create a new replay detector with a default session limit.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            max_sessions: 4096,
        }
    }

    /// Create a new replay detector with a custom maximum session count.
    #[must_use]
    pub fn with_max_sessions(max_sessions: usize) -> Self {
        Self {
            seen: HashMap::new(),
            max_sessions,
        }
    }

    /// Check whether a signature block's GBC is fresh for its RSID.
    ///
    /// If the GBC is higher than any previously seen value for the given RSID,
    /// the detector records it and returns `Ok(())`. Otherwise, returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::VerificationFailed`] if the block appears replayed
    /// (GBC is not strictly greater than the last seen value for this RSID).
    pub fn check(&mut self, block: &SignatureBlock) -> Result<(), SignError> {
        if let Some(&last_gbc) = self.seen.get(&block.rsid) {
            if block.gbc <= last_gbc {
                return Err(SignError::VerificationFailed(format!(
                    "replay detected: GBC {} for RSID {} is not greater than last seen {}",
                    block.gbc, block.rsid, last_gbc
                )));
            }
        }

        // Evict oldest session if at capacity (simple strategy: clear all)
        if self.seen.len() >= self.max_sessions && !self.seen.contains_key(&block.rsid) {
            self.seen.clear();
        }

        let _prev = self.seen.insert(block.rsid, block.gbc);
        Ok(())
    }

    /// Reset the detector, clearing all tracked state.
    pub fn reset(&mut self) {
        self.seen.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::counter::RebootSessionId;
    use crate::signature::SigningKey;
    use crate::signer::{Signer, SignerConfig};

    fn make_signer_and_verifier() -> Option<(Signer, Verifier)> {
        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let pub_bytes = key.public_key_bytes().to_vec();
        let rsid = RebootSessionId::unpersisted();
        let config = SignerConfig {
            max_hashes_per_block: 3,
            ..Default::default()
        };
        let signer = Signer::new(key, rsid, config);
        let verifier = Verifier::new(VerifyingKey::new(pub_bytes));
        Some((signer, verifier))
    }

    #[test]
    fn verify_valid_block() {
        let (mut signer, verifier) = match make_signer_and_verifier() {
            Some(v) => v,
            None => return,
        };
        signer.add_message(b"msg1").ok();
        signer.add_message(b"msg2").ok();
        let block = signer.add_message(b"msg3").ok().flatten();

        assert!(block.is_some());
        if let Some(block) = &block {
            // Verify signature
            assert!(verifier.verify_block(block).is_ok());
            // Verify message hashes
            let result = verifier.verify_messages(block, &[b"msg1", b"msg2", b"msg3"]);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn verify_full_valid() {
        let (mut signer, verifier) = match make_signer_and_verifier() {
            Some(v) => v,
            None => return,
        };
        signer.add_message(b"a").ok();
        signer.add_message(b"b").ok();
        let block = signer.add_message(b"c").ok().flatten();

        if let Some(block) = &block {
            let result = verifier.verify_full(block, &[b"a", b"b", b"c"]);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn verify_tampered_message_fails() {
        let (mut signer, verifier) = match make_signer_and_verifier() {
            Some(v) => v,
            None => return,
        };
        signer.add_message(b"original").ok();
        signer.add_message(b"also original").ok();
        let block = signer.add_message(b"third").ok().flatten();

        if let Some(block) = &block {
            let result = verifier.verify_messages(block, &[b"original", b"TAMPERED", b"third"]);
            assert!(result.is_err());
        }
    }

    #[test]
    fn verify_wrong_key_fails() {
        let (mut signer, _verifier) = match make_signer_and_verifier() {
            Some(v) => v,
            None => return,
        };
        signer.add_message(b"x").ok();
        signer.add_message(b"y").ok();
        let block = signer.add_message(b"z").ok().flatten();

        // Create a different verifier with a new key
        let (other_key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let wrong_verifier =
            Verifier::new(VerifyingKey::new(other_key.public_key_bytes().to_vec()));

        if let Some(block) = &block {
            assert!(wrong_verifier.verify_block(block).is_err());
        }
    }

    #[test]
    fn verify_wrong_message_count_fails() {
        let (mut signer, verifier) = match make_signer_and_verifier() {
            Some(v) => v,
            None => return,
        };
        signer.add_message(b"a").ok();
        signer.add_message(b"b").ok();
        let block = signer.add_message(b"c").ok().flatten();

        if let Some(block) = &block {
            // Too few messages
            let result = verifier.verify_messages(block, &[b"a", b"b"]);
            assert!(result.is_err());

            // Too many messages
            let result = verifier.verify_messages(block, &[b"a", b"b", b"c", b"d"]);
            assert!(result.is_err());
        }
    }

    #[test]
    fn verify_flushed_partial_block() {
        let (mut signer, verifier) = match make_signer_and_verifier() {
            Some(v) => v,
            None => return,
        };
        signer.add_message(b"only_one").ok();
        let block = signer.flush().ok().flatten();

        if let Some(block) = &block {
            assert_eq!(block.cnt, 1);
            assert!(verifier.verify_block(block).is_ok());
            assert!(verifier.verify_messages(block, &[b"only_one"]).is_ok());
        }
    }

    // -- ReplayDetector tests --

    #[test]
    fn replay_detector_accepts_increasing_gbc() {
        let mut detector = ReplayDetector::new();
        let mut block = make_test_block(1, 1);
        assert!(detector.check(&block).is_ok());

        block.gbc = 2;
        assert!(detector.check(&block).is_ok());

        block.gbc = 10;
        assert!(detector.check(&block).is_ok());
    }

    #[test]
    fn replay_detector_rejects_duplicate_gbc() {
        let mut detector = ReplayDetector::new();
        let block = make_test_block(1, 5);
        assert!(detector.check(&block).is_ok());

        // Same GBC again — replay
        assert!(detector.check(&block).is_err());
    }

    #[test]
    fn replay_detector_rejects_lower_gbc() {
        let mut detector = ReplayDetector::new();
        let mut block = make_test_block(1, 10);
        assert!(detector.check(&block).is_ok());

        block.gbc = 5; // Lower — replay
        assert!(detector.check(&block).is_err());
    }

    #[test]
    fn replay_detector_tracks_per_rsid() {
        let mut detector = ReplayDetector::new();
        let block_a = make_test_block(1, 5);
        let block_b = make_test_block(2, 3);
        assert!(detector.check(&block_a).is_ok());
        assert!(detector.check(&block_b).is_ok());

        // Advance RSID 1 — should work
        let block_a2 = make_test_block(1, 6);
        assert!(detector.check(&block_a2).is_ok());

        // Replay RSID 2 — should fail
        assert!(detector.check(&block_b).is_err());
    }

    #[test]
    fn replay_detector_reset() {
        let mut detector = ReplayDetector::new();
        let block = make_test_block(1, 5);
        assert!(detector.check(&block).is_ok());

        detector.reset();

        // After reset, same GBC should be accepted again
        assert!(detector.check(&block).is_ok());
    }

    fn make_test_block(rsid: u64, gbc: u64) -> SignatureBlock {
        use crate::types::{HashAlgorithm, SignatureScheme, Ver};
        SignatureBlock {
            ver: Ver::new(HashAlgorithm::Sha256, SignatureScheme::EcdsaP256),
            rsid,
            sg: crate::types::SignatureGroup::Global,
            spri: 0,
            gbc,
            fmn: 1,
            cnt: 0,
            hashes: vec![],
            signature: vec![],
        }
    }
}
