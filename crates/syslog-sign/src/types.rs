//! Core types for RFC 5848 signed syslog messages.
//!
//! RFC 5848 §4.2: The VER field encodes protocol version, hash algorithm,
//! and signature scheme in 4 octets.

use crate::error::SignError;

// ---------------------------------------------------------------------------
// Hash algorithm
// ---------------------------------------------------------------------------

/// Hash algorithm used for message hashing.
///
/// RFC 5848 §4.2.1: Hash Algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashAlgorithm {
    /// SHA-1 (160-bit) — RFC 5848 SHOULD support.
    Sha1 = 1,
    /// SHA-256 (256-bit) — recommended.
    Sha256 = 2,
}

impl HashAlgorithm {
    /// Parse from the single-digit code in the VER field.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::UnsupportedHashAlgorithm`] for unknown codes.
    pub fn from_code(code: u8) -> Result<Self, SignError> {
        match code {
            1 => Ok(Self::Sha1),
            2 => Ok(Self::Sha256),
            other => Err(SignError::UnsupportedHashAlgorithm(other)),
        }
    }

    /// The single-digit code for the VER field.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Output digest length in bytes.
    #[must_use]
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

// ---------------------------------------------------------------------------
// Signature scheme
// ---------------------------------------------------------------------------

/// Signature scheme for signing hash blocks.
///
/// RFC 5848 §4.2.2 defines scheme `1` as OpenPGP DSA. We implement
/// ECDSA P-256 as scheme `2` for modern deployments while accepting
/// scheme `1` in parsing for interoperability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureScheme {
    /// OpenPGP DSA (RFC 5848 original). Parsed but not implemented for signing.
    OpenPgpDsa = 1,
    /// ECDSA with P-256 curve (modern extension).
    EcdsaP256 = 2,
}

impl SignatureScheme {
    /// Parse from the single-digit code in the VER field.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::UnsupportedSignatureScheme`] for unknown codes.
    pub fn from_code(code: u8) -> Result<Self, SignError> {
        match code {
            1 => Ok(Self::OpenPgpDsa),
            2 => Ok(Self::EcdsaP256),
            other => Err(SignError::UnsupportedSignatureScheme(other)),
        }
    }

    /// The single-digit code for the VER field.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Signature group mode
// ---------------------------------------------------------------------------

/// Signature group mode controlling how messages are partitioned for signing.
///
/// RFC 5848 §4.2.3: Signature Group (SG) field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureGroup {
    /// SG=0: All messages in a single group regardless of PRI.
    Global = 0,
    /// SG=1: One group per unique PRI value.
    PerPri = 1,
    /// SG=2: Contiguous PRI ranges with configured boundaries.
    PriRanges = 2,
    /// SG=3: Custom grouping (requires pre-arrangement).
    Custom = 3,
}

impl SignatureGroup {
    /// Parse from the single-digit code.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::UnsupportedSignatureGroup`] for unknown codes.
    pub fn from_code(code: u8) -> Result<Self, SignError> {
        match code {
            0 => Ok(Self::Global),
            1 => Ok(Self::PerPri),
            2 => Ok(Self::PriRanges),
            3 => Ok(Self::Custom),
            other => Err(SignError::UnsupportedSignatureGroup(other)),
        }
    }

    /// The single-digit code.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// VER field
// ---------------------------------------------------------------------------

/// The 4-octet VER field from an `ssign` or `ssign-cert` structured data element.
///
/// RFC 5848 §4.2: `VER = Protocol Version (2) + Hash Algorithm (1) + Signature Scheme (1)`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ver {
    /// Hash algorithm.
    pub hash_algorithm: HashAlgorithm,
    /// Signature scheme.
    pub signature_scheme: SignatureScheme,
}

/// RFC 5848 §4.2: Protocol version is always "01".
const PROTOCOL_VERSION: &str = "01";

impl Ver {
    /// Create a new VER with the given algorithm and scheme.
    #[must_use]
    pub fn new(hash_algorithm: HashAlgorithm, signature_scheme: SignatureScheme) -> Self {
        Self {
            hash_algorithm,
            signature_scheme,
        }
    }

    /// Parse a VER field string (4 characters: "PPHS").
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidVer`] if the format is wrong or the
    /// protocol version is unsupported.
    pub fn parse(s: &str) -> Result<Self, SignError> {
        if s.len() != 4 {
            return Err(SignError::InvalidVer(format!(
                "expected 4 characters, got {}",
                s.len()
            )));
        }

        let bytes = s.as_bytes();

        // First 2 chars must be "01"
        let proto = s.get(..2).ok_or_else(|| {
            SignError::InvalidVer("VER field too short for protocol version".into())
        })?;
        if proto != PROTOCOL_VERSION {
            return Err(SignError::InvalidVer(format!(
                "unsupported protocol version: {proto}"
            )));
        }

        let hash_byte = bytes.get(2).ok_or_else(|| {
            SignError::InvalidVer("VER field too short for hash algorithm".into())
        })?;
        let hash_code = hash_byte
            .checked_sub(b'0')
            .ok_or_else(|| SignError::InvalidVer("hash algorithm not a digit".into()))?;
        let hash_algorithm = HashAlgorithm::from_code(hash_code)?;

        let sig_byte = bytes.get(3).ok_or_else(|| {
            SignError::InvalidVer("VER field too short for signature scheme".into())
        })?;
        let sig_code = sig_byte
            .checked_sub(b'0')
            .ok_or_else(|| SignError::InvalidVer("signature scheme not a digit".into()))?;
        let signature_scheme = SignatureScheme::from_code(sig_code)?;

        Ok(Self {
            hash_algorithm,
            signature_scheme,
        })
    }

    /// Encode to the 4-character VER string.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{PROTOCOL_VERSION}{}{}",
            self.hash_algorithm.code(),
            self.signature_scheme.code()
        )
    }
}

// ---------------------------------------------------------------------------
// Key blob type
// ---------------------------------------------------------------------------

/// Key blob type for certificate blocks.
///
/// RFC 5848 §4.2.6: Key Blob Type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBlobType {
    /// 'C' — PKIX certificate (RFC 5280). MUST support.
    Pkix,
    /// 'P' — OpenPGP KeyID + certificate.
    OpenPgp,
    /// 'K' — Raw DSA public key.
    RawDsa,
    /// 'N' — No key (pre-distributed).
    None,
    /// 'U' — Vendor-specific.
    Vendor,
}

impl KeyBlobType {
    /// Parse from the single-character key blob type code.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidField`] for unknown codes.
    pub fn from_char(c: char) -> Result<Self, SignError> {
        match c {
            'C' => Ok(Self::Pkix),
            'P' => Ok(Self::OpenPgp),
            'K' => Ok(Self::RawDsa),
            'N' => Ok(Self::None),
            'U' => Ok(Self::Vendor),
            other => Err(SignError::InvalidField {
                field: "KeyBlobType",
                reason: format!("unknown key blob type: {other}"),
            }),
        }
    }

    /// The single-character code.
    #[must_use]
    pub fn as_char(self) -> char {
        match self {
            Self::Pkix => 'C',
            Self::OpenPgp => 'P',
            Self::RawDsa => 'K',
            Self::None => 'N',
            Self::Vendor => 'U',
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// SD-ID for signature blocks.
pub const SSIGN_SD_ID: &str = "ssign";

/// SD-ID for certificate blocks.
pub const SSIGN_CERT_SD_ID: &str = "ssign-cert";

/// Maximum value for Reboot Session ID (10 digits).
pub const MAX_RSID: u64 = 9_999_999_999;

/// Maximum value for Global Block Counter (10 digits).
pub const MAX_GBC: u64 = 9_999_999_999;

/// Maximum number of message hashes per signature block.
///
/// RFC 5848 §4.2.7: CNT is 1-2 digits (1-99).
pub const MAX_HASHES_PER_BLOCK: usize = 99;

/// Default number of hashes per block. Sized to keep signature blocks
/// within the 2048-octet MUST-accept size.
pub const DEFAULT_HASHES_PER_BLOCK: usize = 25;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_algorithm_roundtrip() {
        for &algo in &[HashAlgorithm::Sha1, HashAlgorithm::Sha256] {
            let code = algo.code();
            let parsed = HashAlgorithm::from_code(code);
            assert!(parsed.is_ok());
            assert_eq!(parsed.ok(), Some(algo));
        }
    }

    #[test]
    fn hash_algorithm_invalid() {
        assert!(HashAlgorithm::from_code(0).is_err());
        assert!(HashAlgorithm::from_code(3).is_err());
    }

    #[test]
    fn hash_algorithm_digest_len() {
        assert_eq!(HashAlgorithm::Sha1.digest_len(), 20);
        assert_eq!(HashAlgorithm::Sha256.digest_len(), 32);
    }

    #[test]
    fn signature_scheme_roundtrip() {
        for &scheme in &[SignatureScheme::OpenPgpDsa, SignatureScheme::EcdsaP256] {
            let code = scheme.code();
            let parsed = SignatureScheme::from_code(code);
            assert!(parsed.is_ok());
            assert_eq!(parsed.ok(), Some(scheme));
        }
    }

    #[test]
    fn signature_scheme_invalid() {
        assert!(SignatureScheme::from_code(0).is_err());
        assert!(SignatureScheme::from_code(3).is_err());
    }

    #[test]
    fn signature_group_roundtrip() {
        for code in 0..=3u8 {
            let parsed = SignatureGroup::from_code(code);
            assert!(parsed.is_ok());
            let sg = parsed.ok();
            assert!(sg.is_some());
            if let Some(sg) = sg {
                assert_eq!(sg.code(), code);
            }
        }
    }

    #[test]
    fn signature_group_invalid() {
        assert!(SignatureGroup::from_code(4).is_err());
    }

    #[test]
    fn ver_parse_valid() {
        // "0111" = protocol 01, hash SHA-1 (1), scheme DSA (1)
        let ver = Ver::parse("0111");
        assert!(ver.is_ok());
        let ver = match ver {
            Ok(v) => v,
            Err(_) => return,
        };
        assert_eq!(ver.hash_algorithm, HashAlgorithm::Sha1);
        assert_eq!(ver.signature_scheme, SignatureScheme::OpenPgpDsa);

        // "0122" = protocol 01, hash SHA-256 (2), scheme ECDSA (2)
        let ver2 = Ver::parse("0122");
        assert!(ver2.is_ok());
        let ver2 = match ver2 {
            Ok(v) => v,
            Err(_) => return,
        };
        assert_eq!(ver2.hash_algorithm, HashAlgorithm::Sha256);
        assert_eq!(ver2.signature_scheme, SignatureScheme::EcdsaP256);
    }

    #[test]
    fn ver_encode_roundtrip() {
        let ver = Ver::new(HashAlgorithm::Sha256, SignatureScheme::EcdsaP256);
        let encoded = ver.encode();
        assert_eq!(encoded, "0122");
        let parsed = Ver::parse(&encoded);
        assert!(parsed.is_ok());
        assert_eq!(parsed.ok(), Some(ver));
    }

    #[test]
    fn ver_parse_invalid_version() {
        assert!(Ver::parse("0221").is_err());
        assert!(Ver::parse("0021").is_err());
    }

    #[test]
    fn ver_parse_invalid_length() {
        assert!(Ver::parse("01").is_err());
        assert!(Ver::parse("01211").is_err());
    }

    #[test]
    fn key_blob_type_roundtrip() {
        for &(c, expected) in &[
            ('C', KeyBlobType::Pkix),
            ('P', KeyBlobType::OpenPgp),
            ('K', KeyBlobType::RawDsa),
            ('N', KeyBlobType::None),
            ('U', KeyBlobType::Vendor),
        ] {
            let parsed = KeyBlobType::from_char(c);
            assert!(parsed.is_ok());
            assert_eq!(parsed.ok(), Some(expected));
            assert_eq!(expected.as_char(), c);
        }
    }

    #[test]
    fn key_blob_type_invalid() {
        assert!(KeyBlobType::from_char('X').is_err());
    }
}
