//! Signing preparation helpers for integrating RFC 5848 with the relay pipeline.
//!
//! These functions bridge between `SyslogMessage` (the parsed message model)
//! and the low-level signer/verifier API that operates on raw bytes.

use bytes::Bytes;
use compact_str::CompactString;

use syslog_parse::rfc5424::serializer::serialize;
use syslog_proto::{Facility, Severity, SyslogMessage};

use crate::blocks::{CertificateBlock, SignatureBlock};
use crate::error::SignError;
use crate::types::{SSIGN_CERT_SD_ID, SSIGN_SD_ID};

/// Serialize a `SyslogMessage` to RFC 5424 wire format for signing purposes.
///
/// Per RFC 5848 section 4.2.8, the message is serialized with any existing
/// `ssign` and `ssign-cert` structured data elements stripped, and the `raw`
/// field is cleared so the serializer reconstructs from parsed fields.
#[must_use]
pub fn serialize_for_signing(msg: &SyslogMessage) -> Vec<u8> {
    let mut signing_msg = msg.clone();
    signing_msg.structured_data = msg
        .structured_data
        .without_ids(&[SSIGN_SD_ID, SSIGN_CERT_SD_ID]);
    // Clear raw bytes so the serializer uses parsed fields
    signing_msg.raw = None;
    serialize(&signing_msg)
}

/// Build a syslog message carrying a signature block (`ssign` SD element).
///
/// RFC 5848 section 4.2.1: Signature blocks are emitted as syslog messages
/// with facility=syslog(5), severity=informational(6), app_name="syslog-sign".
///
/// The `template` message is used to derive hostname and other header fields.
///
/// # Errors
///
/// Returns [`SignError`] if the SD element cannot be constructed.
pub fn build_signature_message(
    block: &SignatureBlock,
    template: &SyslogMessage,
) -> Result<SyslogMessage, SignError> {
    let sd_element = block.to_sd_element()?;
    let mut sd = syslog_proto::StructuredData::nil();
    sd.push(sd_element);

    Ok(SyslogMessage {
        // RFC 5848: signature messages use facility=syslog(5), severity=informational(6)
        facility: Facility::Syslog,
        severity: Severity::Informational,
        version: 1,
        timestamp: template.timestamp.clone(),
        hostname: template.hostname.clone(),
        app_name: Some(CompactString::new("syslog-sign")),
        proc_id: None,
        msg_id: None,
        structured_data: sd,
        msg: Some(Bytes::from_static(b"")),
        raw: None,
    })
}

/// Build a syslog message carrying a certificate block (`ssign-cert` SD element).
///
/// Similar to [`build_signature_message`] but for certificate distribution.
///
/// # Errors
///
/// Returns [`SignError`] if the SD element cannot be constructed.
pub fn build_certificate_message(
    block: &CertificateBlock,
    template: &SyslogMessage,
) -> Result<SyslogMessage, SignError> {
    let sd_element = block.to_sd_element()?;
    let mut sd = syslog_proto::StructuredData::nil();
    sd.push(sd_element);

    Ok(SyslogMessage {
        facility: Facility::Syslog,
        severity: Severity::Informational,
        version: 1,
        timestamp: template.timestamp.clone(),
        hostname: template.hostname.clone(),
        app_name: Some(CompactString::new("syslog-sign")),
        proc_id: None,
        msg_id: None,
        structured_data: sd,
        msg: Some(Bytes::from_static(b"")),
        raw: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use compact_str::CompactString;
    use syslog_proto::{StructuredData, SyslogTimestamp};

    fn make_template() -> SyslogMessage {
        SyslogMessage {
            facility: Facility::User,
            severity: Severity::Notice,
            version: 1,
            timestamp: SyslogTimestamp::Nil,
            hostname: Some(CompactString::new("testhost")),
            app_name: Some(CompactString::new("testapp")),
            proc_id: None,
            msg_id: None,
            structured_data: StructuredData::nil(),
            msg: Some(Bytes::from_static(b"test message")),
            raw: None,
        }
    }

    #[test]
    fn serialize_for_signing_strips_ssign() {
        use smallvec::SmallVec;
        use syslog_proto::{SdElement, SdId, SdParam};

        let mut msg = make_template();

        // Add an ssign element to the message
        let ssign_id = match SdId::new(SSIGN_SD_ID) {
            Ok(id) => id,
            Err(_) => return,
        };
        let ssign_elem = SdElement {
            id: ssign_id,
            params: SmallVec::from_vec(vec![SdParam {
                name: CompactString::new("VER"),
                value: CompactString::new("0122"),
            }]),
        };

        // Also add a non-ssign element
        let origin_id = match SdId::new("origin") {
            Ok(id) => id,
            Err(_) => return,
        };
        let origin_elem = SdElement {
            id: origin_id,
            params: SmallVec::from_vec(vec![SdParam {
                name: CompactString::new("ip"),
                value: CompactString::new("10.0.0.1"),
            }]),
        };

        msg.structured_data = StructuredData(SmallVec::from_vec(vec![ssign_elem, origin_elem]));

        let wire = serialize_for_signing(&msg);
        let wire_str = String::from_utf8_lossy(&wire);

        // ssign should be stripped
        assert!(!wire_str.contains("ssign"));
        // origin should remain
        assert!(wire_str.contains("origin"));
    }

    #[test]
    fn serialize_for_signing_clears_raw() {
        let mut msg = make_template();
        msg.raw = Some(Bytes::from_static(b"<13>1 - testhost testapp - - - raw"));

        let wire = serialize_for_signing(&msg);
        let wire_str = String::from_utf8_lossy(&wire);

        // Should NOT use the raw bytes (they might contain ssign)
        assert!(!wire_str.contains("raw"));
        // Should contain the reconstructed message
        assert!(wire_str.contains("test message"));
    }

    #[test]
    fn build_signature_message_sets_fields() {
        use crate::types::{HashAlgorithm, SignatureGroup, SignatureScheme, Ver};

        let block = SignatureBlock {
            ver: Ver::new(HashAlgorithm::Sha256, SignatureScheme::EcdsaP256),
            rsid: 1,
            sg: SignatureGroup::Global,
            spri: 0,
            gbc: 0,
            fmn: 1,
            cnt: 1,
            hashes: vec![vec![0xAA; 32]],
            signature: vec![0xCC; 64],
        };

        let template = make_template();
        let result = build_signature_message(&block, &template);
        assert!(result.is_ok());
        if let Ok(msg) = result {
            assert_eq!(msg.facility, Facility::Syslog);
            assert_eq!(msg.severity, Severity::Informational);
            assert_eq!(msg.app_name.as_deref(), Some("syslog-sign"));
            assert_eq!(msg.hostname.as_deref(), Some("testhost"));
            assert!(msg.structured_data.find_by_id(SSIGN_SD_ID).is_some());
        }
    }

    #[test]
    fn build_certificate_message_sets_fields() {
        use crate::types::{HashAlgorithm, SignatureGroup, SignatureScheme, Ver};

        let block = CertificateBlock {
            ver: Ver::new(HashAlgorithm::Sha256, SignatureScheme::EcdsaP256),
            rsid: 1,
            sg: SignatureGroup::Global,
            spri: 0,
            tpbl: 512,
            index: 1,
            flen: 256,
            fragment: vec![0xDE; 256],
            signature: vec![0xEF; 64],
        };

        let template = make_template();
        let result = build_certificate_message(&block, &template);
        assert!(result.is_ok());
        if let Ok(msg) = result {
            assert_eq!(msg.facility, Facility::Syslog);
            assert_eq!(msg.severity, Severity::Informational);
            assert_eq!(msg.app_name.as_deref(), Some("syslog-sign"));
            assert!(msg.structured_data.find_by_id(SSIGN_CERT_SD_ID).is_some());
        }
    }

    #[test]
    fn build_signature_message_inherits_hostname() {
        use crate::types::{HashAlgorithm, SignatureGroup, SignatureScheme, Ver};

        let block = SignatureBlock {
            ver: Ver::new(HashAlgorithm::Sha256, SignatureScheme::EcdsaP256),
            rsid: 1,
            sg: SignatureGroup::Global,
            spri: 0,
            gbc: 0,
            fmn: 1,
            cnt: 0,
            hashes: vec![],
            signature: vec![0xCC; 64],
        };

        let mut template = make_template();
        template.hostname = Some(CompactString::new("relay.example.com"));

        let result = build_signature_message(&block, &template);
        assert!(result.is_ok());
        if let Ok(msg) = result {
            assert_eq!(msg.hostname.as_deref(), Some("relay.example.com"));
        }
    }

    #[test]
    fn serialize_for_signing_strips_ssign_cert() {
        use smallvec::SmallVec;
        use syslog_proto::{SdElement, SdId, SdParam};

        let mut msg = make_template();

        let cert_id = match SdId::new(SSIGN_CERT_SD_ID) {
            Ok(id) => id,
            Err(_) => return,
        };
        let cert_elem = SdElement {
            id: cert_id,
            params: SmallVec::from_vec(vec![SdParam {
                name: CompactString::new("VER"),
                value: CompactString::new("0122"),
            }]),
        };

        msg.structured_data = StructuredData(SmallVec::from_vec(vec![cert_elem]));

        let wire = serialize_for_signing(&msg);
        let wire_str = String::from_utf8_lossy(&wire);

        // ssign-cert should be stripped, leaving nil SD
        assert!(!wire_str.contains("ssign-cert"));
    }
}
