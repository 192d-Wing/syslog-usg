//! Message hashing for RFC 5848 signature blocks.
//!
//! RFC 5848 §4.2.7: Each message is hashed individually. The hash covers
//! the entire serialized RFC 5424 message (wire format), excluding any
//! existing `ssign` or `ssign-cert` structured data elements.

use ring::digest;

use crate::types::HashAlgorithm;

/// Compute the hash of a serialized syslog message.
///
/// The caller should pass the RFC 5424 wire-format bytes of the message,
/// with any `ssign`/`ssign-cert` SD elements stripped.
#[must_use]
pub fn hash_message(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    let algo = match algorithm {
        HashAlgorithm::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        HashAlgorithm::Sha256 => &digest::SHA256,
    };
    digest::digest(algo, data).as_ref().to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_produces_32_bytes() {
        let hash = hash_message(HashAlgorithm::Sha256, b"test message");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn sha1_produces_20_bytes() {
        let hash = hash_message(HashAlgorithm::Sha1, b"test message");
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn different_inputs_different_hashes() {
        let h1 = hash_message(HashAlgorithm::Sha256, b"message one");
        let h2 = hash_message(HashAlgorithm::Sha256, b"message two");
        assert_ne!(h1, h2);
    }

    #[test]
    fn same_input_same_hash() {
        let h1 = hash_message(HashAlgorithm::Sha256, b"deterministic");
        let h2 = hash_message(HashAlgorithm::Sha256, b"deterministic");
        assert_eq!(h1, h2);
    }
}
