//! Base64 encoding/decoding and SD parameter construction helpers.
//!
//! RFC 5848 uses base64 encoding (RFC 4648 §4, standard alphabet) for
//! hash blocks and signatures within structured data parameters.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::error::SignError;

/// Encode bytes to standard base64.
#[must_use]
pub fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode standard base64 to bytes.
///
/// # Errors
///
/// Returns [`SignError::Base64`] if the input is not valid base64.
pub fn b64_decode(data: &str) -> Result<Vec<u8>, SignError> {
    Ok(STANDARD.decode(data)?)
}

/// Encode a slice of hash digests as a space-separated base64 string.
///
/// RFC 5848 §4.2.7: HB = 1*(base64-hash SP)
/// Each hash is individually base64-encoded, then joined with spaces.
#[must_use]
pub fn encode_hash_block(hashes: &[Vec<u8>]) -> String {
    let mut result = String::new();
    for (i, hash) in hashes.iter().enumerate() {
        if i > 0 {
            result.push(' ');
        }
        result.push_str(&b64_encode(hash));
    }
    result
}

/// Decode a space-separated hash block back to individual hash digests.
///
/// # Errors
///
/// Returns [`SignError::Base64`] if any hash is not valid base64.
pub fn decode_hash_block(hb: &str) -> Result<Vec<Vec<u8>>, SignError> {
    if hb.is_empty() {
        return Ok(Vec::new());
    }
    hb.split(' ').map(b64_decode).collect::<Result<Vec<_>, _>>()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip() {
        let data = b"hello, syslog!";
        let encoded = b64_encode(data);
        let decoded = b64_decode(&encoded);
        assert!(decoded.is_ok());
        assert_eq!(decoded.ok().as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn b64_decode_invalid() {
        assert!(b64_decode("not valid base64!@#$").is_err());
    }

    #[test]
    fn hash_block_roundtrip() {
        let hashes = vec![vec![1u8, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let encoded = encode_hash_block(&hashes);
        assert!(encoded.contains(' '));
        let decoded = decode_hash_block(&encoded);
        assert!(decoded.is_ok());
        assert_eq!(decoded.ok(), Some(hashes));
    }

    #[test]
    fn hash_block_single() {
        let hashes = vec![vec![0xDE, 0xAD, 0xBE, 0xEF]];
        let encoded = encode_hash_block(&hashes);
        assert!(!encoded.contains(' '));
        let decoded = decode_hash_block(&encoded);
        assert!(decoded.is_ok());
        assert_eq!(decoded.ok(), Some(hashes));
    }

    #[test]
    fn hash_block_empty() {
        let decoded = decode_hash_block("");
        assert!(decoded.is_ok());
        assert_eq!(decoded.ok().as_deref(), Some([].as_slice()));
    }
}
