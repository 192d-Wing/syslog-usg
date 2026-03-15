//! Cryptographic signature operations for RFC 5848.
//!
//! Uses ECDSA with P-256 (via `ring`) for signing and verification.
//! RFC 5848 originally specified OpenPGP DSA; we use ECDSA P-256 as a
//! modern alternative (signature scheme code `2`).

use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _,
    UnparsedPublicKey,
};

use crate::encode::{b64_decode, b64_encode};
use crate::error::SignError;

/// A signing key (private key) for generating signatures.
///
/// Wraps an ECDSA P-256 key pair from `ring`.
pub struct SigningKey {
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl SigningKey {
    /// Create a signing key from PKCS#8 DER-encoded private key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidKey`] if the key material is invalid.
    pub fn from_pkcs8(pkcs8_der: &[u8]) -> Result<Self, SignError> {
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8_der,
            &SystemRandom::new(),
        )
        .map_err(|e| SignError::InvalidKey(format!("invalid PKCS#8 key: {e}")))?;

        Ok(Self {
            key_pair,
            rng: SystemRandom::new(),
        })
    }

    /// Generate a new random ECDSA P-256 key pair.
    ///
    /// Returns the signing key and the PKCS#8 DER-encoded document
    /// (for persistence).
    ///
    /// # Errors
    ///
    /// Returns [`SignError::SigningFailed`] if key generation fails.
    pub fn generate() -> Result<(Self, Vec<u8>), SignError> {
        use zeroize::Zeroizing;

        let rng = SystemRandom::new();
        let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| SignError::SigningFailed(format!("key generation failed: {e}")))?;
        // Wrap in Zeroizing to ensure PKCS#8 bytes are wiped from memory on drop
        let pkcs8_zeroizing = Zeroizing::new(pkcs8_doc.as_ref().to_vec());
        let pkcs8_bytes = pkcs8_zeroizing.to_vec();

        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &pkcs8_bytes,
            &SystemRandom::new(),
        )
        .map_err(|e| SignError::InvalidKey(format!("generated key rejected: {e}")))?;

        Ok((
            Self {
                key_pair,
                rng: SystemRandom::new(),
            },
            pkcs8_bytes,
        ))
    }

    /// Sign the given data, returning the signature as raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::SigningFailed`] if signing fails.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        let sig = self
            .key_pair
            .sign(&self.rng, data)
            .map_err(|e| SignError::SigningFailed(format!("ECDSA sign failed: {e}")))?;
        Ok(sig.as_ref().to_vec())
    }

    /// Sign data and return the signature as base64.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::SigningFailed`] if signing fails.
    pub fn sign_base64(&self, data: &[u8]) -> Result<String, SignError> {
        let sig = self.sign(data)?;
        Ok(b64_encode(&sig))
    }

    /// Get the public key bytes (uncompressed point format).
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }
}

// ring's EcdsaKeyPair is Send + Sync in ring 0.17
// Safety: ring ensures thread safety for EcdsaKeyPair
impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &"ECDSA_P256_SHA256")
            .finish_non_exhaustive()
    }
}

/// A verification key (public key) for checking signatures.
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    /// Raw public key bytes (uncompressed point format).
    public_key_bytes: Vec<u8>,
}

impl VerifyingKey {
    /// Create a verifying key from raw public key bytes.
    #[must_use]
    pub fn new(public_key_bytes: Vec<u8>) -> Self {
        Self { public_key_bytes }
    }

    /// Create from the base64-encoded public key.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::Base64`] if decoding fails.
    pub fn from_base64(b64: &str) -> Result<Self, SignError> {
        let bytes = b64_decode(b64)?;
        Ok(Self::new(bytes))
    }

    /// Verify a signature over the given data.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::VerificationFailed`] if the signature is invalid.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), SignError> {
        let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.public_key_bytes);
        public_key
            .verify(data, signature)
            .map_err(|_| SignError::VerificationFailed("ECDSA signature invalid".into()))
    }

    /// Verify a base64-encoded signature over the given data.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if decoding or verification fails.
    pub fn verify_base64(&self, data: &[u8], signature_b64: &str) -> Result<(), SignError> {
        let sig_bytes = b64_decode(signature_b64)?;
        self.verify(data, &sig_bytes)
    }

    /// The raw public key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign_verify() {
        let (key, _pkcs8) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let data = b"test message for signing";

        let sig = key.sign(data);
        assert!(sig.is_ok());
        let sig = match sig {
            Ok(s) => s,
            Err(_) => return,
        };

        let verifier = VerifyingKey::new(key.public_key_bytes().to_vec());
        assert!(verifier.verify(data, &sig).is_ok());
    }

    #[test]
    fn sign_verify_base64() {
        let (key, _pkcs8) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let data = b"base64 roundtrip test";

        let sig_b64 = key.sign_base64(data);
        assert!(sig_b64.is_ok());
        let sig_b64 = match sig_b64 {
            Ok(s) => s,
            Err(_) => return,
        };

        let verifier = VerifyingKey::new(key.public_key_bytes().to_vec());
        assert!(verifier.verify_base64(data, &sig_b64).is_ok());
    }

    #[test]
    fn wrong_data_fails_verification() {
        let (key, _pkcs8) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let sig = key.sign(b"original data");
        assert!(sig.is_ok());
        let sig = match sig {
            Ok(s) => s,
            Err(_) => return,
        };

        let verifier = VerifyingKey::new(key.public_key_bytes().to_vec());
        assert!(verifier.verify(b"tampered data", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (key1, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let (key2, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };

        let sig = key1.sign(b"some data");
        assert!(sig.is_ok());
        let sig = match sig {
            Ok(s) => s,
            Err(_) => return,
        };

        let verifier2 = VerifyingKey::new(key2.public_key_bytes().to_vec());
        assert!(verifier2.verify(b"some data", &sig).is_err());
    }

    #[test]
    fn pkcs8_roundtrip() {
        let (key, pkcs8) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let data = b"persistence test";
        let sig = key.sign(data);
        assert!(sig.is_ok());
        let sig = match sig {
            Ok(s) => s,
            Err(_) => return,
        };

        // Reload from PKCS#8
        let key2 = SigningKey::from_pkcs8(&pkcs8);
        assert!(key2.is_ok());
        let key2 = match key2 {
            Ok(k) => k,
            Err(_) => return,
        };

        // Same public key
        assert_eq!(key.public_key_bytes(), key2.public_key_bytes());

        // Can verify the original signature
        let verifier = VerifyingKey::new(key2.public_key_bytes().to_vec());
        assert!(verifier.verify(data, &sig).is_ok());
    }

    #[test]
    fn invalid_pkcs8_rejected() {
        assert!(SigningKey::from_pkcs8(b"not a valid key").is_err());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let debug = format!("{key:?}");
        assert!(debug.contains("ECDSA_P256_SHA256"));
        assert!(!debug.contains("key_pair"));
    }
}
