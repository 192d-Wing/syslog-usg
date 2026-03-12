//! Signature and certificate block construction and parsing.
//!
//! RFC 5848 §4.2: Signature blocks use SD-ID `ssign` and certificate
//! blocks use SD-ID `ssign-cert`. Both are standard RFC 5424 structured
//! data elements.

use compact_str::CompactString;
use smallvec::SmallVec;

use syslog_proto::{SdElement, SdId, SdParam, StructuredData};

use crate::encode::{b64_encode, decode_hash_block, encode_hash_block};
use crate::error::SignError;
use crate::types::{SSIGN_CERT_SD_ID, SSIGN_SD_ID, SignatureGroup, Ver};

// ---------------------------------------------------------------------------
// Signature Block (ssign)
// ---------------------------------------------------------------------------

/// Parsed contents of an `ssign` signature block.
#[derive(Debug, Clone)]
pub struct SignatureBlock {
    /// VER field (protocol version + hash algo + sig scheme).
    pub ver: Ver,
    /// Reboot Session ID.
    pub rsid: u64,
    /// Signature Group mode.
    pub sg: SignatureGroup,
    /// Signature Priority.
    pub spri: u8,
    /// Global Block Counter.
    pub gbc: u64,
    /// First Message Number.
    pub fmn: u64,
    /// Count of message hashes.
    pub cnt: usize,
    /// Hash Block — individual message hashes.
    pub hashes: Vec<Vec<u8>>,
    /// Digital signature (raw bytes).
    pub signature: Vec<u8>,
}

impl SignatureBlock {
    /// Build an `ssign` structured data element from this block.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidField`] if the SD-ID cannot be created.
    pub fn to_sd_element(&self) -> Result<SdElement, SignError> {
        let sd_id = SdId::new(SSIGN_SD_ID).map_err(|e| SignError::InvalidField {
            field: "SD-ID",
            reason: format!("{e}"),
        })?;

        let params = SmallVec::from_vec(vec![
            sd_param("VER", &self.ver.encode()),
            sd_param("RSID", &self.rsid.to_string()),
            sd_param("SG", &self.sg.code().to_string()),
            sd_param("SPRI", &self.spri.to_string()),
            sd_param("GBC", &self.gbc.to_string()),
            sd_param("FMN", &self.fmn.to_string()),
            sd_param("CNT", &self.cnt.to_string()),
            sd_param("HB", &encode_hash_block(&self.hashes)),
            sd_param("SIGN", &b64_encode(&self.signature)),
        ]);

        Ok(SdElement { id: sd_id, params })
    }

    /// Parse a `SignatureBlock` from an `ssign` structured data element.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if required fields are missing or malformed.
    pub fn from_sd_element(element: &SdElement) -> Result<Self, SignError> {
        let ver_str = get_param(element, "VER")?;
        let ver = Ver::parse(ver_str)?;

        let rsid = parse_u64_param(element, "RSID")?;
        let sg_code = parse_u8_param(element, "SG")?;
        let sg = SignatureGroup::from_code(sg_code)?;
        let spri = parse_u8_param(element, "SPRI")?;
        let gbc = parse_u64_param(element, "GBC")?;
        let fmn = parse_u64_param(element, "FMN")?;
        let cnt_val = parse_u64_param(element, "CNT")?;
        let cnt = cnt_val as usize;

        let hb_str = get_param(element, "HB")?;
        let hashes = decode_hash_block(hb_str)?;

        let sign_str = get_param(element, "SIGN")?;
        let signature = crate::encode::b64_decode(sign_str)?;

        Ok(Self {
            ver,
            rsid,
            sg,
            spri,
            gbc,
            fmn,
            cnt,
            hashes,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// Certificate Block (ssign-cert)
// ---------------------------------------------------------------------------

/// Parsed contents of an `ssign-cert` certificate block.
#[derive(Debug, Clone)]
pub struct CertificateBlock {
    /// VER field.
    pub ver: Ver,
    /// Reboot Session ID.
    pub rsid: u64,
    /// Signature Group mode.
    pub sg: SignatureGroup,
    /// Signature Priority.
    pub spri: u8,
    /// Total Payload Block Length (of the complete certificate).
    pub tpbl: u64,
    /// Byte offset into the payload (1-based).
    pub index: u64,
    /// Fragment length.
    pub flen: u64,
    /// Payload fragment (raw bytes).
    pub fragment: Vec<u8>,
    /// Signature over the complete block (excluding SIGN itself).
    pub signature: Vec<u8>,
}

impl CertificateBlock {
    /// Build an `ssign-cert` structured data element.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::InvalidField`] if the SD-ID cannot be created.
    pub fn to_sd_element(&self) -> Result<SdElement, SignError> {
        let sd_id = SdId::new(SSIGN_CERT_SD_ID).map_err(|e| SignError::InvalidField {
            field: "SD-ID",
            reason: format!("{e}"),
        })?;

        let params = SmallVec::from_vec(vec![
            sd_param("VER", &self.ver.encode()),
            sd_param("RSID", &self.rsid.to_string()),
            sd_param("SG", &self.sg.code().to_string()),
            sd_param("SPRI", &self.spri.to_string()),
            sd_param("TPBL", &self.tpbl.to_string()),
            sd_param("INDEX", &self.index.to_string()),
            sd_param("FLEN", &self.flen.to_string()),
            sd_param("FRAG", &b64_encode(&self.fragment)),
            sd_param("SIGN", &b64_encode(&self.signature)),
        ]);

        Ok(SdElement { id: sd_id, params })
    }

    /// Parse from an `ssign-cert` structured data element.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`] if required fields are missing or malformed.
    pub fn from_sd_element(element: &SdElement) -> Result<Self, SignError> {
        let ver_str = get_param(element, "VER")?;
        let ver = Ver::parse(ver_str)?;

        let rsid = parse_u64_param(element, "RSID")?;
        let sg_code = parse_u8_param(element, "SG")?;
        let sg = SignatureGroup::from_code(sg_code)?;
        let spri = parse_u8_param(element, "SPRI")?;
        let tpbl = parse_u64_param(element, "TPBL")?;
        let index = parse_u64_param(element, "INDEX")?;
        let flen = parse_u64_param(element, "FLEN")?;

        let frag_str = get_param(element, "FRAG")?;
        let fragment = crate::encode::b64_decode(frag_str)?;

        let sign_str = get_param(element, "SIGN")?;
        let signature = crate::encode::b64_decode(sign_str)?;

        Ok(Self {
            ver,
            rsid,
            sg,
            spri,
            tpbl,
            index,
            flen,
            fragment,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers for SD element I/O
// ---------------------------------------------------------------------------

/// Find an `ssign` element in structured data.
#[must_use]
pub fn find_ssign(sd: &StructuredData) -> Option<&SdElement> {
    sd.find_by_id(SSIGN_SD_ID)
}

/// Find all `ssign-cert` elements in structured data.
#[must_use]
pub fn find_ssign_certs(sd: &StructuredData) -> Vec<&SdElement> {
    sd.iter()
        .filter(|el| el.id.as_str() == SSIGN_CERT_SD_ID)
        .collect()
}

fn sd_param(name: &str, value: &str) -> SdParam {
    SdParam {
        name: CompactString::new(name),
        value: CompactString::new(value),
    }
}

fn get_param<'a>(element: &'a SdElement, name: &'static str) -> Result<&'a str, SignError> {
    element
        .param_value(name)
        .ok_or(SignError::MissingField(name))
}

fn parse_u64_param(element: &SdElement, name: &'static str) -> Result<u64, SignError> {
    let s = get_param(element, name)?;
    s.parse::<u64>().map_err(|e| SignError::InvalidField {
        field: name,
        reason: format!("{e}"),
    })
}

fn parse_u8_param(element: &SdElement, name: &'static str) -> Result<u8, SignError> {
    let s = get_param(element, name)?;
    s.parse::<u8>().map_err(|e| SignError::InvalidField {
        field: name,
        reason: format!("{e}"),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HashAlgorithm, SignatureScheme};

    fn make_test_sig_block() -> SignatureBlock {
        SignatureBlock {
            ver: Ver::new(HashAlgorithm::Sha256, SignatureScheme::EcdsaP256),
            rsid: 1,
            sg: SignatureGroup::Global,
            spri: 0,
            gbc: 42,
            fmn: 1,
            cnt: 2,
            hashes: vec![vec![0xAA; 32], vec![0xBB; 32]],
            signature: vec![0xCC; 64],
        }
    }

    #[test]
    fn signature_block_to_sd_roundtrip() {
        let block = make_test_sig_block();
        let element = block.to_sd_element();
        assert!(element.is_ok());
        let element = match element {
            Ok(e) => e,
            Err(_) => return,
        };

        assert_eq!(element.id.as_str(), SSIGN_SD_ID);

        // Parse it back
        let parsed = SignatureBlock::from_sd_element(&element);
        assert!(parsed.is_ok());
        let parsed = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };

        assert_eq!(parsed.ver, block.ver);
        assert_eq!(parsed.rsid, block.rsid);
        assert_eq!(parsed.sg, block.sg);
        assert_eq!(parsed.spri, block.spri);
        assert_eq!(parsed.gbc, block.gbc);
        assert_eq!(parsed.fmn, block.fmn);
        assert_eq!(parsed.cnt, block.cnt);
        assert_eq!(parsed.hashes, block.hashes);
        assert_eq!(parsed.signature, block.signature);
    }

    #[test]
    fn certificate_block_to_sd_roundtrip() {
        let block = CertificateBlock {
            ver: Ver::new(HashAlgorithm::Sha256, SignatureScheme::EcdsaP256),
            rsid: 1,
            sg: SignatureGroup::Global,
            spri: 0,
            tpbl: 1024,
            index: 1,
            flen: 512,
            fragment: vec![0xDE; 512],
            signature: vec![0xEF; 64],
        };

        let element = block.to_sd_element();
        assert!(element.is_ok());
        let element = match element {
            Ok(e) => e,
            Err(_) => return,
        };

        assert_eq!(element.id.as_str(), SSIGN_CERT_SD_ID);

        let parsed = CertificateBlock::from_sd_element(&element);
        assert!(parsed.is_ok());
        let parsed = match parsed {
            Ok(p) => p,
            Err(_) => return,
        };

        assert_eq!(parsed.tpbl, 1024);
        assert_eq!(parsed.index, 1);
        assert_eq!(parsed.flen, 512);
        assert_eq!(parsed.fragment, block.fragment);
        assert_eq!(parsed.signature, block.signature);
    }

    #[test]
    fn missing_field_returns_error() {
        // Empty element — all fields missing
        let element = SdElement {
            id: match SdId::new(SSIGN_SD_ID) {
                Ok(id) => id,
                Err(_) => return,
            },
            params: SmallVec::new(),
        };
        let result = SignatureBlock::from_sd_element(&element);
        assert!(result.is_err());
    }

    #[test]
    fn find_ssign_in_structured_data() {
        let block = make_test_sig_block();
        let element = match block.to_sd_element() {
            Ok(e) => e,
            Err(_) => return,
        };
        let sd = StructuredData(SmallVec::from_elem(element, 1));
        assert!(find_ssign(&sd).is_some());
    }

    #[test]
    fn find_ssign_missing() {
        let sd = StructuredData::nil();
        assert!(find_ssign(&sd).is_none());
    }
}
