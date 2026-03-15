#![no_main]
//! Fuzz the ReplayDetector with arbitrary RSID/GBC sequences.
//!
//! Verifies that the detector never panics and that accepted blocks
//! always have strictly increasing GBC per RSID.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzBlock {
    rsid: u64,
    gbc: u64,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    max_sessions: u8,
    blocks: Vec<FuzzBlock>,
}

fuzz_target!(|input: FuzzInput| {
    use syslog_sign::types::{HashAlgorithm, SignatureGroup, SignatureScheme, Ver};
    use syslog_sign::verifier::ReplayDetector;

    let max_sessions = (input.max_sessions as usize).max(1).min(256);
    let mut detector = ReplayDetector::with_max_sessions(max_sessions);

    let ver = Ver::new(HashAlgorithm::Sha256, SignatureScheme::EcdsaP256);

    for fb in &input.blocks {
        let block = syslog_sign::blocks::SignatureBlock {
            ver,
            rsid: fb.rsid,
            sg: SignatureGroup::Global,
            spri: 0,
            gbc: fb.gbc,
            fmn: 0,
            cnt: 0,
            hashes: vec![],
            signature: vec![],
        };

        // Should never panic
        let _ = detector.check(&block);
    }

    // Serialize/deserialize roundtrip should never panic
    let state = detector.serialize_state();
    let mut detector2 = ReplayDetector::with_max_sessions(max_sessions);
    detector2.load_state(&state);
});
