//! Error types for syslog message signing and verification.

/// Errors that can occur during signing or verification operations.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The VER field has an invalid format or unsupported version.
    #[error("invalid VER field: {0}")]
    InvalidVer(String),

    /// The hash algorithm is not supported.
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHashAlgorithm(u8),

    /// The signature scheme is not supported.
    #[error("unsupported signature scheme: {0}")]
    UnsupportedSignatureScheme(u8),

    /// The signature group mode is not supported.
    #[error("unsupported signature group mode: {0}")]
    UnsupportedSignatureGroup(u8),

    /// A required field is missing from the signature block.
    #[error("missing field in signature block: {0}")]
    MissingField(&'static str),

    /// A field value could not be parsed.
    #[error("invalid field value for {field}: {reason}")]
    InvalidField {
        /// The field name.
        field: &'static str,
        /// What went wrong.
        reason: String,
    },

    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Cryptographic signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// Signature verification failed.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// The certificate block is incomplete or has invalid fragments.
    #[error("certificate block error: {0}")]
    CertificateBlock(String),

    /// Hash chain verification failed — message integrity compromised.
    #[error("hash chain mismatch at message {index}: expected {expected}, got {actual}")]
    HashChainMismatch {
        /// Message index in the block.
        index: usize,
        /// Expected hash (hex).
        expected: String,
        /// Actual hash (hex).
        actual: String,
    },

    /// A counter value is out of range.
    #[error("{name} counter overflow: {value}")]
    CounterOverflow {
        /// Counter name (GBC, FMN, RSID).
        name: &'static str,
        /// The value that caused overflow.
        value: u64,
    },

    /// Message serialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// The key or certificate is invalid.
    #[error("invalid key material: {0}")]
    InvalidKey(String),

    /// X.509 certificate path validation failed.
    ///
    /// RFC 5848 §4.2.6 requires PKIX certificate validation (RFC 5280)
    /// before using a public key for signature verification.
    #[error("certificate validation failed: {0}")]
    CertificateValidation(String),
}
