//! Hash chain accumulation for signature groups.
//!
//! RFC 5848 §4.2.7: Messages within a signature group are accumulated
//! into blocks. Each block contains the hashes of up to CNT messages.
//! The signature covers the concatenation of all hashes in the block.

use crate::hash::hash_message;
use crate::types::{DEFAULT_HASHES_PER_BLOCK, HashAlgorithm, MAX_HASHES_PER_BLOCK};

/// Accumulates message hashes for a single signature group.
///
/// When the block reaches its configured capacity, it can be flushed
/// to produce a signature block.
#[derive(Debug)]
pub struct HashChain {
    algorithm: HashAlgorithm,
    max_per_block: usize,
    /// Accumulated hashes for the current block.
    pending: Vec<Vec<u8>>,
    /// First message number for the current pending block.
    first_message_number: u64,
    /// Total messages hashed since creation (used for FMN tracking).
    total_messages: u64,
}

/// A completed block of hashes ready for signing.
#[derive(Debug, Clone)]
pub struct HashBlock {
    /// The individual message hashes.
    pub hashes: Vec<Vec<u8>>,
    /// First message number in this block (1-based within the group).
    pub first_message_number: u64,
    /// Number of hashes in this block.
    pub count: usize,
}

impl HashChain {
    /// Create a new hash chain for the given algorithm.
    ///
    /// `max_per_block` controls how many hashes are accumulated before
    /// the chain signals a block is ready. Clamped to [`MAX_HASHES_PER_BLOCK`].
    #[must_use]
    pub fn new(algorithm: HashAlgorithm, max_per_block: usize) -> Self {
        let max_per_block = max_per_block.min(MAX_HASHES_PER_BLOCK);
        let max_per_block = if max_per_block == 0 {
            DEFAULT_HASHES_PER_BLOCK
        } else {
            max_per_block
        };
        Self {
            algorithm,
            max_per_block,
            pending: Vec::with_capacity(max_per_block),
            first_message_number: 1,
            total_messages: 0,
        }
    }

    /// Hash a message and add it to the current block.
    ///
    /// `data` should be the serialized RFC 5424 wire-format bytes,
    /// with any `ssign`/`ssign-cert` SD elements removed.
    ///
    /// Returns `true` if the block is now full and should be flushed.
    pub fn add_message(&mut self, data: &[u8]) -> bool {
        let hash = hash_message(self.algorithm, data);
        self.pending.push(hash);
        self.total_messages += 1;
        self.pending.len() >= self.max_per_block
    }

    /// Returns `true` if there are pending hashes that haven't been flushed.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Returns the number of pending hashes.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Flush the current block, returning the accumulated hashes.
    ///
    /// Returns `None` if there are no pending hashes.
    pub fn flush(&mut self) -> Option<HashBlock> {
        if self.pending.is_empty() {
            return None;
        }

        let hashes = std::mem::take(&mut self.pending);
        let count = hashes.len();
        let fmn = self.first_message_number;

        // Next block starts after these messages
        self.first_message_number += count as u64;
        self.pending.reserve(self.max_per_block);

        Some(HashBlock {
            hashes,
            first_message_number: fmn,
            count,
        })
    }

    /// The hash algorithm in use.
    #[must_use]
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Total number of messages hashed since creation.
    #[must_use]
    pub fn total_messages(&self) -> u64 {
        self.total_messages
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_accumulates_and_flushes() {
        let mut chain = HashChain::new(HashAlgorithm::Sha256, 3);
        assert!(!chain.has_pending());

        assert!(!chain.add_message(b"msg1"));
        assert!(!chain.add_message(b"msg2"));
        assert!(chain.add_message(b"msg3")); // full

        let block = chain.flush();
        assert!(block.is_some());
        let block = match block {
            Some(b) => b,
            Option::None => return,
        };
        assert_eq!(block.count, 3);
        assert_eq!(block.first_message_number, 1);
        assert_eq!(block.hashes.len(), 3);

        assert!(!chain.has_pending());
    }

    #[test]
    fn chain_partial_flush() {
        let mut chain = HashChain::new(HashAlgorithm::Sha256, 10);
        chain.add_message(b"msg1");
        chain.add_message(b"msg2");

        let block = chain.flush();
        assert!(block.is_some());
        let block = match block {
            Some(b) => b,
            Option::None => return,
        };
        assert_eq!(block.count, 2);
        assert_eq!(block.first_message_number, 1);
    }

    #[test]
    fn chain_empty_flush_returns_none() {
        let mut chain = HashChain::new(HashAlgorithm::Sha256, 10);
        assert!(chain.flush().is_none());
    }

    #[test]
    fn chain_fmn_advances() {
        let mut chain = HashChain::new(HashAlgorithm::Sha256, 2);
        chain.add_message(b"msg1");
        chain.add_message(b"msg2");
        let _ = chain.flush();

        chain.add_message(b"msg3");
        chain.add_message(b"msg4");
        let block2 = chain.flush();
        assert!(block2.is_some());
        if let Some(b) = block2 {
            assert_eq!(b.first_message_number, 3);
        }
    }

    #[test]
    fn chain_total_messages() {
        let mut chain = HashChain::new(HashAlgorithm::Sha256, 10);
        chain.add_message(b"a");
        chain.add_message(b"b");
        chain.add_message(b"c");
        assert_eq!(chain.total_messages(), 3);
    }

    #[test]
    fn chain_clamps_max_per_block() {
        let chain = HashChain::new(HashAlgorithm::Sha256, 200);
        // Should be clamped to MAX_HASHES_PER_BLOCK (99)
        assert_eq!(chain.max_per_block, MAX_HASHES_PER_BLOCK);
    }
}
