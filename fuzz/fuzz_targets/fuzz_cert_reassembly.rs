#![no_main]
//! Fuzz certificate block reassembly (RFC 5848 §4.2.8).
//!
//! Exercises the TPBL/fragment count limits, gap detection, and
//! payload size validation added to prevent OOM (F-01, F-12).

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzCertInput {
    num_blocks: u8,
    tpbl: u64,
    fragments: Vec<Vec<u8>>,
}

fuzz_target!(|input: FuzzCertInput| {
    use syslog_sign::blocks::CertificateBlock;
    use syslog_sign::types::{HashAlgorithm, SignatureGroup, SignatureScheme, Ver};

    let ver = Ver::new(HashAlgorithm::Sha256, SignatureScheme::EcdsaP256);
    let num = (input.num_blocks as usize).min(input.fragments.len());

    let mut blocks = Vec::new();
    let mut offset = 1u64;

    for i in 0..num {
        let fragment = match input.fragments.get(i) {
            Some(f) => f.clone(),
            None => break,
        };
        let flen = fragment.len() as u64;
        blocks.push(CertificateBlock {
            ver,
            rsid: 0,
            sg: SignatureGroup::Global,
            spri: 0,
            tpbl: input.tpbl,
            index: offset,
            flen,
            fragment,
            signature: vec![],
        });
        offset = offset.saturating_add(flen);
    }

    // Should never panic — errors are returned via Result
    let _ = syslog_sign::certificate::reassemble_certificate(&blocks);
});
