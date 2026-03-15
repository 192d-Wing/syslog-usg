//! Signed syslog messages (RFC 5848).
//!
//! This crate implements message signing and verification for syslog
//! messages as defined by RFC 5848. Signatures are carried in RFC 5424
//! structured data elements (`ssign` and `ssign-cert`).
//!
//! # Cryptographic Choices
//!
//! RFC 5848 originally specified OpenPGP DSA signatures. This implementation
//! uses ECDSA P-256 (via `ring`) as a modern alternative, identified by
//! signature scheme code `2` in the VER field.
//!
//! # Quick Start
//!
//! ```ignore
//! use syslog_sign::{Signer, SignerConfig, SigningKey, Verifier, VerifyingKey};
//! use syslog_sign::counter::RebootSessionId;
//!
//! // Generate a signing key
//! let (signing_key, pkcs8_bytes) = SigningKey::generate()?;
//! let pub_key_bytes = signing_key.public_key_bytes().to_vec();
//!
//! // Create signer
//! let rsid = RebootSessionId::unpersisted();
//! let mut signer = Signer::new(signing_key, rsid, SignerConfig::default());
//!
//! // Sign messages
//! let msg_bytes = b"<165>1 2023-10-11T22:14:15.003Z host app - - - msg";
//! if let Some(sig_block) = signer.add_message(msg_bytes)? {
//!     // Emit signature block
//! }
//!
//! // Verify
//! let verifier = Verifier::new(VerifyingKey::new(pub_key_bytes));
//! // verifier.verify_full(&sig_block, &[msg_bytes])?;
//! ```

pub mod blocks;
pub mod certificate;
pub mod chain;
pub mod counter;
pub mod encode;
pub mod error;
pub mod hash;
pub mod prepare;
pub mod signature;
pub mod signer;
pub mod types;
pub mod verifier;

// Re-export primary API types for convenience.
pub use blocks::{CertificateBlock, SignatureBlock};
pub use certificate::{build_root_store, mozilla_root_store, validate_certificate};
pub use error::SignError;
pub use signature::{SigningKey, VerifyingKey};
pub use signer::{Signer, SignerConfig};
pub use types::{HashAlgorithm, KeyBlobType, SignatureGroup, SignatureScheme, Ver};
pub use verifier::{ReplayDetector, Verifier};
