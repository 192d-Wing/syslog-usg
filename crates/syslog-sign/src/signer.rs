//! High-level Signer API for producing RFC 5848 signature blocks.
//!
//! The [`Signer`] accumulates messages, produces signature blocks when
//! the hash chain fills, and can emit certificate blocks on demand.

use std::collections::HashMap;

use crate::blocks::SignatureBlock;
use crate::certificate::fragment_certificate;
use crate::chain::HashChain;
use crate::counter::{GlobalBlockCounter, RebootSessionId};
use crate::encode::b64_encode;
use crate::error::SignError;
use crate::signature::SigningKey;
use crate::types::{DEFAULT_HASHES_PER_BLOCK, HashAlgorithm, SignatureGroup, SignatureScheme, Ver};

/// A contiguous range of PRI values mapped to a signature group ID.
///
/// RFC 5848 §4.2.3 SG=2: PRI values are partitioned into contiguous ranges,
/// each assigned to a distinct signature group.
#[derive(Debug, Clone)]
pub struct PriRange {
    /// Start of the PRI range (inclusive).
    pub start: u8,
    /// End of the PRI range (inclusive).
    pub end: u8,
    /// Group ID for this range.
    pub group_id: u8,
}

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
    /// PRI ranges for SG=2 mode. Each range maps a [start, end] PRI interval
    /// to a group ID. Ignored for other SG modes.
    pub pri_ranges: Vec<PriRange>,
}

impl Default for SignerConfig {
    fn default() -> Self {
        Self {
            hash_algorithm: HashAlgorithm::Sha256,
            signature_group: SignatureGroup::Global,
            signature_priority: 0,
            max_hashes_per_block: DEFAULT_HASHES_PER_BLOCK,
            pri_ranges: Vec::new(),
        }
    }
}

/// Manages hash chains for one or more signature groups.
///
/// RFC 5848 §4.2.3 defines four signature group modes. This enum
/// encapsulates the chain-management strategy for each mode.
enum ChainManager {
    /// SG=0: Single global chain for all messages.
    Global(HashChain),
    /// SG=1: One chain per unique PRI value.
    PerPri(HashMap<u8, HashChain>),
    /// SG=2: PRI values mapped to group IDs by configurable ranges.
    PriRanges {
        ranges: Vec<PriRange>,
        chains: HashMap<u8, HashChain>,
    },
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
/// // Feed messages (pass PRI for SG=1/SG=2 routing)
/// for msg in messages {
///     let serialized = serialize_for_signing(&msg);
///     let pri = msg.pri().value();
///     if let Some(sig_block) = signer.add_message(&serialized, Some(pri))? {
///         // Emit the signature block as a syslog message
///     }
/// }
///
/// // Flush remaining (may produce multiple blocks for multi-group modes)
/// for sig_block in signer.flush()? {
///     // Emit each signature block
/// }
/// ```
pub struct Signer {
    key: SigningKey,
    ver: Ver,
    rsid: RebootSessionId,
    config: SignerConfig,
    chain_mgr: ChainManager,
    gbc: GlobalBlockCounter,
}

impl Signer {
    /// Create a new signer.
    #[must_use]
    pub fn new(key: SigningKey, rsid: RebootSessionId, config: SignerConfig) -> Self {
        let ver = Ver::new(config.hash_algorithm, SignatureScheme::EcdsaP256);
        let chain_mgr = match config.signature_group {
            SignatureGroup::Global | SignatureGroup::Custom => ChainManager::Global(
                HashChain::new(config.hash_algorithm, config.max_hashes_per_block),
            ),
            SignatureGroup::PerPri => ChainManager::PerPri(HashMap::new()),
            SignatureGroup::PriRanges => ChainManager::PriRanges {
                ranges: config.pri_ranges.clone(),
                chains: HashMap::new(),
            },
        };

        Self {
            key,
            ver,
            rsid,
            config,
            chain_mgr,
            gbc: GlobalBlockCounter::new(),
        }
    }

    /// Add a serialized message to the hash chain.
    ///
    /// `data` should be the RFC 5424 wire-format bytes of the message,
    /// with any existing `ssign`/`ssign-cert` SD elements removed.
    ///
    /// `pri` is the PRI value (0-191) of the message. Used for SG=1 (PerPri)
    /// and SG=2 (PriRanges) modes to route messages to the correct chain.
    /// Ignored for SG=0 (Global) and SG=3 (Custom).
    ///
    /// Returns a [`SignatureBlock`] if the chain is full and was auto-flushed.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if signing the block fails.
    pub fn add_message(
        &mut self,
        data: &[u8],
        pri: Option<u8>,
    ) -> Result<Option<SignatureBlock>, SignError> {
        let hash_algo = self.config.hash_algorithm;
        let max_hashes = self.config.max_hashes_per_block;
        let chain = match &mut self.chain_mgr {
            ChainManager::Global(c) => c,
            ChainManager::PerPri(map) => {
                let pri_val = pri.unwrap_or(0);
                map.entry(pri_val)
                    .or_insert_with(|| HashChain::new(hash_algo, max_hashes))
            }
            ChainManager::PriRanges { ranges, chains } => {
                let pri_val = pri.unwrap_or(0);
                let group_id = ranges
                    .iter()
                    .find(|r| pri_val >= r.start && pri_val <= r.end)
                    .map(|r| r.group_id)
                    .unwrap_or(0);
                chains
                    .entry(group_id)
                    .or_insert_with(|| HashChain::new(hash_algo, max_hashes))
            }
        };
        let full = chain.add_message(data);
        if full {
            // Flush directly — we already hold &mut chain from chain_mgr,
            // so we use the hash_block + sign_hash_block pattern.
            match chain.flush() {
                Some(hb) => self.sign_hash_block(hb).map(Some),
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    /// Flush all hash chains, producing signature blocks for each chain
    /// that has pending hashes.
    ///
    /// Returns an empty `Vec` if there are no pending hashes in any chain.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if signing fails.
    pub fn flush(&mut self) -> Result<Vec<SignatureBlock>, SignError> {
        let mut blocks = Vec::new();
        // We must collect chain references carefully to satisfy the borrow
        // checker — we need `&mut self` for `flush_single_chain` but also
        // need to iterate over `self.chain_mgr`.
        //
        // Strategy: drain pending hashes from chains first, then sign them.
        let hash_blocks = match &mut self.chain_mgr {
            ChainManager::Global(chain) => {
                let mut v = Vec::new();
                if let Some(hb) = chain.flush() {
                    v.push(hb);
                }
                v
            }
            ChainManager::PerPri(map) => {
                let mut v = Vec::new();
                for chain in map.values_mut() {
                    if let Some(hb) = chain.flush() {
                        v.push(hb);
                    }
                }
                v
            }
            ChainManager::PriRanges { chains, .. } => {
                let mut v = Vec::new();
                for chain in chains.values_mut() {
                    if let Some(hb) = chain.flush() {
                        v.push(hb);
                    }
                }
                v
            }
        };

        for hash_block in hash_blocks {
            let block = self.sign_hash_block(hash_block)?;
            blocks.push(block);
        }
        Ok(blocks)
    }

    /// Build and sign a [`SignatureBlock`] from a flushed [`HashBlock`].
    fn sign_hash_block(
        &mut self,
        hash_block: crate::chain::HashBlock,
    ) -> Result<SignatureBlock, SignError> {
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

        Ok(SignatureBlock {
            ver: self.ver,
            rsid: self.rsid.value(),
            sg: self.config.signature_group,
            spri: self.config.signature_priority,
            gbc: gbc_val,
            fmn: hash_block.first_message_number,
            cnt: hash_block.count,
            hashes: hash_block.hashes,
            signature,
        })
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

    /// Returns `true` if there are pending message hashes in any chain.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        match &self.chain_mgr {
            ChainManager::Global(chain) => chain.has_pending(),
            ChainManager::PerPri(map) => map.values().any(HashChain::has_pending),
            ChainManager::PriRanges { chains, .. } => chains.values().any(HashChain::has_pending),
        }
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
        let chain_count = match &self.chain_mgr {
            ChainManager::Global(_) => 1,
            ChainManager::PerPri(map) => map.len(),
            ChainManager::PriRanges { chains, .. } => chains.len(),
        };
        f.debug_struct("Signer")
            .field("ver", &self.ver)
            .field("rsid", &self.rsid)
            .field("config", &self.config)
            .field("gbc", &self.gbc)
            .field("active_chains", &chain_count)
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

        let r1 = signer.add_message(b"msg1", None);
        assert!(r1.is_ok());
        assert!(r1.ok().flatten().is_none());

        let r2 = signer.add_message(b"msg2", None);
        assert!(r2.is_ok());
        assert!(r2.ok().flatten().is_none());

        let r3 = signer.add_message(b"msg3", None);
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
        signer.add_message(b"msg1", None).ok();
        signer.add_message(b"msg2", None).ok();

        let blocks = signer.flush();
        assert!(blocks.is_ok());
        let blocks = match blocks {
            Ok(b) => b,
            Err(_) => return,
        };
        assert_eq!(blocks.len(), 1);
        if let Some(block) = blocks.first() {
            assert_eq!(block.cnt, 2);
        }
    }

    #[test]
    fn signer_flush_empty() {
        let mut signer = match make_signer() {
            Some(s) => s,
            None => return,
        };
        let blocks = signer.flush();
        assert!(blocks.is_ok());
        if let Ok(b) = blocks {
            assert!(b.is_empty());
        }
    }

    #[test]
    fn signer_gbc_increments() {
        let mut signer = match make_signer() {
            Some(s) => s,
            None => return,
        };

        // Fill and auto-flush first block
        signer.add_message(b"a", None).ok();
        signer.add_message(b"b", None).ok();
        let block1 = signer.add_message(b"c", None).ok().flatten();

        // Fill second block
        signer.add_message(b"d", None).ok();
        signer.add_message(b"e", None).ok();
        let block2 = signer.add_message(b"f", None).ok().flatten();

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

    // -- SG=1 (PerPri) tests ------------------------------------------------

    fn make_per_pri_signer() -> Option<Signer> {
        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let rsid = RebootSessionId::unpersisted();
        let config = SignerConfig {
            max_hashes_per_block: 2,
            signature_group: SignatureGroup::PerPri,
            ..Default::default()
        };
        Some(Signer::new(key, rsid, config))
    }

    #[test]
    fn test_per_pri_creates_separate_chains() {
        let mut signer = match make_per_pri_signer() {
            Some(s) => s,
            None => return,
        };

        // Add messages with different PRI values (should go to separate chains)
        // PRI=11 (facility=1, severity=3)
        signer.add_message(b"msg_pri11_a", Some(11)).ok();
        signer.add_message(b"msg_pri11_b", Some(11)).ok();

        // PRI=42 (facility=5, severity=2)
        signer.add_message(b"msg_pri42_a", Some(42)).ok();
        signer.add_message(b"msg_pri42_b", Some(42)).ok();

        // PRI=100
        signer.add_message(b"msg_pri100_a", Some(100)).ok();

        // Flush all chains — should produce blocks for PRI 11, 42, and 100
        let blocks = signer.flush();
        assert!(blocks.is_ok());
        let blocks = match blocks {
            Ok(b) => b,
            Err(_) => return,
        };

        // PRI 11 and 42 auto-flushed when full (2 msgs each), so flush
        // should only pick up PRI 100 (1 pending message).
        // But auto-flush already produced blocks for 11 and 42 via add_message.
        // So flush() should produce 1 block (for PRI 100).
        assert_eq!(blocks.len(), 1);
        if let Some(block) = blocks.first() {
            assert_eq!(block.cnt, 1);
        }

        assert!(!signer.has_pending());
    }

    #[test]
    fn test_per_pri_auto_flushes_per_chain() {
        let mut signer = match make_per_pri_signer() {
            Some(s) => s,
            None => return,
        };

        // First message for PRI=10 — no block yet
        let r1 = signer.add_message(b"msg_pri10_a", Some(10));
        assert!(r1.is_ok());
        assert!(r1.ok().flatten().is_none());

        // Second message for PRI=10 — chain fills (max_hashes=2), block produced
        let r2 = signer.add_message(b"msg_pri10_b", Some(10));
        assert!(r2.is_ok());
        let block = r2.ok().flatten();
        assert!(block.is_some());
        if let Some(b) = block {
            assert_eq!(b.cnt, 2);
        }

        // First message for PRI=20 — no block (different chain)
        let r3 = signer.add_message(b"msg_pri20_a", Some(20));
        assert!(r3.is_ok());
        assert!(r3.ok().flatten().is_none());
    }

    // -- SG=2 (PriRanges) tests ----------------------------------------------

    fn make_pri_ranges_signer() -> Option<Signer> {
        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let rsid = RebootSessionId::unpersisted();
        let config = SignerConfig {
            max_hashes_per_block: 2,
            signature_group: SignatureGroup::PriRanges,
            pri_ranges: vec![
                PriRange {
                    start: 0,
                    end: 63,
                    group_id: 1,
                },
                PriRange {
                    start: 64,
                    end: 127,
                    group_id: 2,
                },
                PriRange {
                    start: 128,
                    end: 191,
                    group_id: 3,
                },
            ],
            ..Default::default()
        };
        Some(Signer::new(key, rsid, config))
    }

    #[test]
    fn test_pri_ranges_routes_correctly() {
        let mut signer = match make_pri_ranges_signer() {
            Some(s) => s,
            None => return,
        };

        // PRI=10 => group_id=1 (range 0-63)
        signer.add_message(b"msg_lo_a", Some(10)).ok();
        // PRI=50 => group_id=1 (same range)
        signer.add_message(b"msg_lo_b", Some(50)).ok();
        // Chain for group 1 is now full (2 msgs) and auto-flushed

        // PRI=80 => group_id=2 (range 64-127)
        signer.add_message(b"msg_mid_a", Some(80)).ok();

        // PRI=150 => group_id=3 (range 128-191)
        signer.add_message(b"msg_hi_a", Some(150)).ok();

        // Flush remaining — groups 2 and 3 each have 1 pending msg
        let blocks = signer.flush();
        assert!(blocks.is_ok());
        let blocks = match blocks {
            Ok(b) => b,
            Err(_) => return,
        };
        // Groups 2 and 3 each have 1 pending message
        assert_eq!(blocks.len(), 2);
        for block in &blocks {
            assert_eq!(block.cnt, 1);
        }
    }

    #[test]
    fn test_pri_ranges_unmapped_falls_to_default() {
        // Test that a PRI value not in any range falls to group_id=0
        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let rsid = RebootSessionId::unpersisted();
        let config = SignerConfig {
            max_hashes_per_block: 2,
            signature_group: SignatureGroup::PriRanges,
            pri_ranges: vec![
                // Only covers 0-10
                PriRange {
                    start: 0,
                    end: 10,
                    group_id: 1,
                },
            ],
            ..Default::default()
        };
        let mut signer = Signer::new(key, rsid, config);

        // PRI=5 => group_id=1
        signer.add_message(b"in_range", Some(5)).ok();
        // PRI=100 => no matching range, defaults to group_id=0
        signer.add_message(b"out_of_range", Some(100)).ok();

        let blocks = signer.flush();
        assert!(blocks.is_ok());
        let blocks = match blocks {
            Ok(b) => b,
            Err(_) => return,
        };
        // Two separate groups: group_id=1 and group_id=0
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn test_global_mode_unchanged() {
        // Verify that SG=0 (Global) still works exactly as before
        let mut signer = match make_signer() {
            Some(s) => s,
            None => return,
        };

        // All messages go to a single chain regardless of PRI
        signer.add_message(b"msg1", Some(10)).ok();
        signer.add_message(b"msg2", Some(100)).ok();
        let block = signer.add_message(b"msg3", Some(191)).ok().flatten();

        assert!(block.is_some());
        if let Some(b) = block {
            assert_eq!(b.cnt, 3);
            assert_eq!(b.fmn, 1);
            assert_eq!(b.sg, SignatureGroup::Global);
        }
    }

    #[test]
    fn test_per_pri_has_pending() {
        let mut signer = match make_per_pri_signer() {
            Some(s) => s,
            None => return,
        };

        assert!(!signer.has_pending());

        signer.add_message(b"msg", Some(42)).ok();
        assert!(signer.has_pending());

        let _ = signer.flush();
        assert!(!signer.has_pending());
    }
}
