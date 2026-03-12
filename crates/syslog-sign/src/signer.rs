//! High-level Signer API for producing RFC 5848 signature blocks.
//!
//! The [`Signer`] accumulates messages, produces signature blocks when
//! the hash chain fills, and can emit certificate blocks on demand.

use crate::blocks::SignatureBlock;
use crate::certificate::fragment_certificate;
use crate::chain::HashChain;
use crate::counter::{GlobalBlockCounter, RebootSessionId};
use crate::encode::b64_encode;
use crate::error::SignError;
use crate::signature::SigningKey;
use crate::types::{DEFAULT_HASHES_PER_BLOCK, HashAlgorithm, SignatureGroup, SignatureScheme, Ver};

/// Configuration for a [`Signer`].
#[derive(Debug, Clone)]
pub struct SignerConfig {
    /// Hash algorithm (default: SHA-256).
    pub hash_algorithm: HashAlgorithm,
    /// Signature group mode (default: Global).
    pub signature_group: SignatureGroup,
    /// Signature priority (default: 0).
    pub signature_priority: u8,
    /// Maximum hashes per signature block (default: 25).
    pub max_hashes_per_block: usize,
}

impl Default for SignerConfig {
    fn default() -> Self {
        Self {
            hash_algorithm: HashAlgorithm::Sha256,
            signature_group: SignatureGroup::Global,
            signature_priority: 0,
            max_hashes_per_block: DEFAULT_HASHES_PER_BLOCK,
        }
    }
}

/// A syslog message signer implementing RFC 5848.
///
/// Accumulates message hashes in a chain and produces signed signature
/// blocks when the chain fills or when explicitly flushed.
///
/// # Usage
///
/// ```ignore
/// let (signing_key, _pkcs8) = SigningKey::generate()?;
/// let rsid = RebootSessionId::unpersisted();
/// let mut signer = Signer::new(signing_key, rsid, SignerConfig::default());
///
/// // Feed messages
/// for msg in messages {
///     let serialized = serialize_for_signing(&msg);
///     if let Some(sig_block) = signer.add_message(&serialized)? {
///         // Emit the signature block as a syslog message
///     }
/// }
///
/// // Flush remaining
/// if let Some(sig_block) = signer.flush()? {
///     // Emit final signature block
/// }
/// ```
pub struct Signer {
    key: SigningKey,
    ver: Ver,
    rsid: RebootSessionId,
    config: SignerConfig,
    chain: HashChain,
    gbc: GlobalBlockCounter,
}

impl Signer {
    /// Create a new signer.
    #[must_use]
    pub fn new(key: SigningKey, rsid: RebootSessionId, config: SignerConfig) -> Self {
        let ver = Ver::new(config.hash_algorithm, SignatureScheme::EcdsaP256);
        let chain = HashChain::new(config.hash_algorithm, config.max_hashes_per_block);

        Self {
            key,
            ver,
            rsid,
            config,
            chain,
            gbc: GlobalBlockCounter::new(),
        }
    }

    /// Add a serialized message to the hash chain.
    ///
    /// `data` should be the RFC 5424 wire-format bytes of the message,
    /// with any existing `ssign`/`ssign-cert` SD elements removed.
    ///
    /// Returns a [`SignatureBlock`] if the chain is full and was auto-flushed.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if signing the block fails.
    pub fn add_message(&mut self, data: &[u8]) -> Result<Option<SignatureBlock>, SignError> {
        let full = self.chain.add_message(data);
        if full { self.flush() } else { Ok(None) }
    }

    /// Flush the current hash chain, producing a signature block.
    ///
    /// Returns `None` if there are no pending hashes.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if signing fails.
    pub fn flush(&mut self) -> Result<Option<SignatureBlock>, SignError> {
        let hash_block = match self.chain.flush() {
            Some(hb) => hb,
            None => return Ok(None),
        };

        let gbc_val = self.gbc.value();
        self.gbc.increment();

        // Build the data to sign: VER + RSID + SG + SPRI + GBC + FMN + CNT + HB
        let hb_encoded = crate::encode::encode_hash_block(&hash_block.hashes);
        let sign_data = format!(
            "{}{}{}{}{}{}{}{}",
            self.ver.encode(),
            self.rsid.value(),
            self.config.signature_group.code(),
            self.config.signature_priority,
            gbc_val,
            hash_block.first_message_number,
            hash_block.count,
            hb_encoded,
        );

        let signature = self.key.sign(sign_data.as_bytes())?;

        Ok(Some(SignatureBlock {
            ver: self.ver,
            rsid: self.rsid.value(),
            sg: self.config.signature_group,
            spri: self.config.signature_priority,
            gbc: gbc_val,
            fmn: hash_block.first_message_number,
            cnt: hash_block.count,
            hashes: hash_block.hashes,
            signature,
        }))
    }

    /// Generate certificate blocks for the signer's public key.
    ///
    /// `certificate_der` should be the DER-encoded X.509 certificate
    /// corresponding to the signing key.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if fragmentation or signing fails.
    pub fn certificate_blocks(
        &self,
        certificate_der: &[u8],
    ) -> Result<Vec<crate::blocks::CertificateBlock>, SignError> {
        // Prepend key blob type 'C' (PKIX) + base64-encoded cert
        let payload = format!("C{}", b64_encode(certificate_der));

        fragment_certificate(
            payload.as_bytes(),
            self.ver,
            self.rsid.value(),
            self.config.signature_group,
            self.config.signature_priority,
            &self.key,
            None,
        )
    }

    /// Returns `true` if there are pending message hashes.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.chain.has_pending()
    }

    /// The VER field in use.
    #[must_use]
    pub fn ver(&self) -> Ver {
        self.ver
    }

    /// The public key bytes (for verification).
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key.public_key_bytes()
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("ver", &self.ver)
            .field("rsid", &self.rsid)
            .field("config", &self.config)
            .field("gbc", &self.gbc)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signer() -> Option<Signer> {
        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let rsid = RebootSessionId::unpersisted();
        let config = SignerConfig {
            max_hashes_per_block: 3,
            ..Default::default()
        };
        Some(Signer::new(key, rsid, config))
    }

    #[test]
    fn signer_produces_block_when_full() {
        let mut signer = match make_signer() {
            Some(s) => s,
            None => return,
        };

        let r1 = signer.add_message(b"msg1");
        assert!(r1.is_ok());
        assert!(r1.ok().flatten().is_none());

        let r2 = signer.add_message(b"msg2");
        assert!(r2.is_ok());
        assert!(r2.ok().flatten().is_none());

        let r3 = signer.add_message(b"msg3");
        assert!(r3.is_ok());
        let block = r3.ok().flatten();
        assert!(block.is_some());

        if let Some(block) = block {
            assert_eq!(block.cnt, 3);
            assert_eq!(block.fmn, 1);
            assert_eq!(block.gbc, 0);
            assert_eq!(block.hashes.len(), 3);
            assert!(!block.signature.is_empty());
        }
    }

    #[test]
    fn signer_flush_partial() {
        let mut signer = match make_signer() {
            Some(s) => s,
            None => return,
        };
        signer.add_message(b"msg1").ok();
        signer.add_message(b"msg2").ok();

        let block = signer.flush();
        assert!(block.is_ok());
        let block = block.ok().flatten();
        assert!(block.is_some());
        if let Some(block) = block {
            assert_eq!(block.cnt, 2);
        }
    }

    #[test]
    fn signer_flush_empty() {
        let mut signer = match make_signer() {
            Some(s) => s,
            None => return,
        };
        let block = signer.flush();
        assert!(block.is_ok());
        assert!(block.ok().flatten().is_none());
    }

    #[test]
    fn signer_gbc_increments() {
        let mut signer = match make_signer() {
            Some(s) => s,
            None => return,
        };

        // Fill and auto-flush first block
        signer.add_message(b"a").ok();
        signer.add_message(b"b").ok();
        let block1 = signer.add_message(b"c").ok().flatten();

        // Fill second block
        signer.add_message(b"d").ok();
        signer.add_message(b"e").ok();
        let block2 = signer.add_message(b"f").ok().flatten();

        if let (Some(b1), Some(b2)) = (block1, block2) {
            assert_eq!(b1.gbc, 0);
            assert_eq!(b2.gbc, 1);
            assert_eq!(b1.fmn, 1);
            assert_eq!(b2.fmn, 4);
        }
    }

    #[test]
    fn signer_certificate_blocks() {
        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let rsid = RebootSessionId::unpersisted();
        let signer = Signer::new(key, rsid, SignerConfig::default());

        // Fake certificate DER
        let fake_cert = vec![0x30; 800];
        let blocks = signer.certificate_blocks(&fake_cert);
        assert!(blocks.is_ok());
        let blocks = match blocks {
            Ok(b) => b,
            Err(_) => return,
        };
        assert!(!blocks.is_empty());

        // All blocks should have consistent TPBL
        let tpbl = blocks.first().map(|b| b.tpbl);
        for block in &blocks {
            assert_eq!(Some(block.tpbl), tpbl);
        }
    }

    #[test]
    fn signer_debug_safe() {
        let signer = make_signer();
        let debug = format!("{signer:?}");
        assert!(debug.contains("Signer"));
    }
}
