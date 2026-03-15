//! Certificate block fragmentation and reassembly.
//!
//! RFC 5848 §4.2.8: Large certificates are fragmented across multiple
//! `ssign-cert` syslog messages. Each fragment carries TPBL (total payload
//! length), INDEX (1-based byte offset), FLEN (fragment length), and FRAG
//! (the fragment data).

use crate::blocks::CertificateBlock;
use crate::error::SignError;
use crate::signature::SigningKey;
use crate::types::{SignatureGroup, Ver};

/// Default maximum fragment size in bytes (before base64 encoding).
/// Sized to keep certificate block messages under 2048 octets.
const DEFAULT_FRAGMENT_SIZE: usize = 512;

/// Maximum certificate payload size (1 MiB).
/// Prevents attacker-controlled TPBL from causing OOM.
const MAX_CERT_PAYLOAD: u64 = 1_048_576;

/// Maximum number of certificate fragments to reassemble.
/// Prevents CPU/memory exhaustion from millions of tiny fragments.
const MAX_CERT_FRAGMENTS: usize = 2048;

/// Fragment a certificate payload into multiple certificate blocks.
///
/// Each block is signed with the provided key. The `signing_data_fn`
/// constructs the data to sign for each block (typically the serialized
/// block excluding the SIGN field).
///
/// # Errors
///
/// Returns [`SignError`] if signing fails.
pub fn fragment_certificate(
    payload: &[u8],
    ver: Ver,
    rsid: u64,
    sg: SignatureGroup,
    spri: u8,
    signing_key: &SigningKey,
    fragment_size: Option<usize>,
) -> Result<Vec<CertificateBlock>, SignError> {
    let frag_size = fragment_size.unwrap_or(DEFAULT_FRAGMENT_SIZE);
    let tpbl = payload.len() as u64;
    let mut blocks = Vec::new();
    let mut offset = 0usize;

    while offset < payload.len() {
        let end = (offset + frag_size).min(payload.len());
        let fragment = payload
            .get(offset..end)
            .ok_or_else(|| SignError::CertificateBlock("fragment range out of bounds".into()))?;
        let flen = fragment.len() as u64;
        // RFC 5848: INDEX is 1-based byte offset
        let index = (offset as u64) + 1;

        // Build the block data to sign (all fields except SIGN)
        let sign_data = format!(
            "{ver}{rsid}{sg}{spri}{tpbl}{index}{flen}{frag}",
            ver = ver.encode(),
            rsid = rsid,
            sg = sg.code(),
            spri = spri,
            tpbl = tpbl,
            index = index,
            flen = flen,
            frag = crate::encode::b64_encode(fragment),
        );

        let signature = signing_key.sign(sign_data.as_bytes())?;

        blocks.push(CertificateBlock {
            ver,
            rsid,
            sg,
            spri,
            tpbl,
            index,
            flen,
            fragment: fragment.to_vec(),
            signature,
        });

        offset = end;
    }

    Ok(blocks)
}

/// Reassemble a certificate payload from a set of certificate blocks.
///
/// Blocks must cover the entire payload without gaps.
///
/// # Errors
///
/// Returns [`SignError::CertificateBlock`] if blocks are incomplete,
/// overlapping, or have inconsistent TPBL values.
pub fn reassemble_certificate(blocks: &[CertificateBlock]) -> Result<Vec<u8>, SignError> {
    if blocks.is_empty() {
        return Err(SignError::CertificateBlock("no certificate blocks".into()));
    }

    // Limit fragment count to prevent CPU exhaustion
    if blocks.len() > MAX_CERT_FRAGMENTS {
        return Err(SignError::CertificateBlock(format!(
            "too many certificate fragments: {} (max {MAX_CERT_FRAGMENTS})",
            blocks.len()
        )));
    }

    // All blocks should have the same TPBL
    let tpbl = blocks
        .first()
        .ok_or_else(|| SignError::CertificateBlock("empty blocks list".into()))?
        .tpbl;

    // Validate TPBL before allocating to prevent OOM from attacker-controlled values
    if tpbl > MAX_CERT_PAYLOAD {
        return Err(SignError::CertificateBlock(format!(
            "TPBL {tpbl} exceeds maximum certificate payload size ({MAX_CERT_PAYLOAD})"
        )));
    }

    for block in blocks {
        if block.tpbl != tpbl {
            return Err(SignError::CertificateBlock(format!(
                "inconsistent TPBL: expected {tpbl}, got {}",
                block.tpbl
            )));
        }
    }

    // Sort by INDEX and assemble
    let mut sorted: Vec<_> = blocks.to_vec();
    sorted.sort_by_key(|b| b.index);

    let mut payload = Vec::with_capacity(tpbl as usize);
    let mut expected_offset = 1u64; // 1-based

    for block in &sorted {
        if block.index != expected_offset {
            return Err(SignError::CertificateBlock(format!(
                "gap in certificate fragments: expected index {expected_offset}, got {}",
                block.index
            )));
        }
        payload.extend_from_slice(&block.fragment);
        expected_offset += block.flen;
    }

    if payload.len() as u64 != tpbl {
        return Err(SignError::CertificateBlock(format!(
            "reassembled size {} != TPBL {tpbl}",
            payload.len()
        )));
    }

    Ok(payload)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HashAlgorithm, SignatureScheme};

    fn test_ver() -> Ver {
        Ver::new(HashAlgorithm::Sha256, SignatureScheme::EcdsaP256)
    }

    #[test]
    fn fragment_and_reassemble() {
        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let payload = vec![0xAB; 1200]; // 1200 bytes → 3 fragments at 512 each

        let blocks = fragment_certificate(
            &payload,
            test_ver(),
            1,
            SignatureGroup::Global,
            0,
            &key,
            Some(512),
        );
        assert!(blocks.is_ok());
        let blocks = match blocks {
            Ok(b) => b,
            Err(_) => return,
        };

        assert_eq!(blocks.len(), 3); // 512 + 512 + 176

        // Check fragment sizes
        assert_eq!(blocks.first().map(|b| b.flen), Some(512));
        assert_eq!(blocks.get(1).map(|b| b.flen), Some(512));
        assert_eq!(blocks.get(2).map(|b| b.flen), Some(176));

        // Reassemble
        let reassembled = reassemble_certificate(&blocks);
        assert!(reassembled.is_ok());
        assert_eq!(reassembled.ok().as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn fragment_exact_size() {
        let (key, _) = match SigningKey::generate() {
            Ok(v) => v,
            Err(_) => return,
        };
        let payload = vec![0xCD; 512]; // Exactly one fragment

        let blocks = fragment_certificate(
            &payload,
            test_ver(),
            0,
            SignatureGroup::Global,
            0,
            &key,
            Some(512),
        );
        assert!(blocks.is_ok());
        let blocks = match blocks {
            Ok(b) => b,
            Err(_) => return,
        };
        assert_eq!(blocks.len(), 1);

        let reassembled = reassemble_certificate(&blocks);
        assert!(reassembled.is_ok());
        assert_eq!(reassembled.ok().as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn reassemble_empty_fails() {
        let result = reassemble_certificate(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn reassemble_inconsistent_tpbl_fails() {
        let b1 = CertificateBlock {
            ver: test_ver(),
            rsid: 0,
            sg: SignatureGroup::Global,
            spri: 0,
            tpbl: 100,
            index: 1,
            flen: 50,
            fragment: vec![0; 50],
            signature: vec![],
        };
        let mut b2 = b1.clone();
        b2.tpbl = 200; // Inconsistent
        b2.index = 51;

        let result = reassemble_certificate(&[b1.clone(), b2]);
        assert!(result.is_err());

        // Fix tpbl but create a gap
        let mut b2_gap = b1.clone();
        b2_gap.tpbl = 100;
        b2_gap.index = 60; // Gap: expected 51
        b2_gap.flen = 50;
        b2_gap.fragment = vec![0; 50];

        let result = reassemble_certificate(&[b1, b2_gap]);
        assert!(result.is_err());
    }

    #[test]
    fn reassemble_rejects_excessive_tpbl() {
        let block = CertificateBlock {
            ver: test_ver(),
            rsid: 0,
            sg: SignatureGroup::Global,
            spri: 0,
            tpbl: MAX_CERT_PAYLOAD + 1,
            index: 1,
            flen: 10,
            fragment: vec![0; 10],
            signature: vec![],
        };
        let result = reassemble_certificate(&[block]);
        assert!(result.is_err());
        if let Err(SignError::CertificateBlock(msg)) = &result {
            assert!(msg.contains("exceeds maximum"), "unexpected error: {msg}");
        }
    }

    #[test]
    fn reassemble_rejects_too_many_fragments() {
        let blocks: Vec<CertificateBlock> = (0..MAX_CERT_FRAGMENTS + 1)
            .map(|i| CertificateBlock {
                ver: test_ver(),
                rsid: 0,
                sg: SignatureGroup::Global,
                spri: 0,
                tpbl: 100,
                index: (i as u64) + 1,
                flen: 1,
                fragment: vec![0],
                signature: vec![],
            })
            .collect();
        let result = reassemble_certificate(&blocks);
        assert!(result.is_err());
        if let Err(SignError::CertificateBlock(msg)) = &result {
            assert!(msg.contains("too many"), "unexpected error: {msg}");
        }
    }
}
