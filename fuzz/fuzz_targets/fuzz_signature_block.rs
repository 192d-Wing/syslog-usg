#![no_main]
//! Fuzz signature block parsing from structured data elements.
//!
//! Exercises SignatureBlock::from_sd_element() with arbitrary SD params
//! to verify no panics on malformed input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to interpret the input as a set of key=value pairs for an ssign element
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return,
    };

    // Build a fake SD element with arbitrary param values
    use compact_str::CompactString;
    use smallvec::SmallVec;
    use syslog_proto::{SdElement, SdId, SdParam};

    let sd_id = match SdId::new("ssign") {
        Ok(id) => id,
        Err(_) => return,
    };

    // Split input into chunks of ~20 chars for param values
    let param_names = ["VER", "RSID", "SG", "SPRI", "GBC", "FMN", "CNT", "HB", "SIGN"];
    let mut params = SmallVec::new();
    let chunks: Vec<&str> = text.splitn(param_names.len(), '|').collect();

    for (i, name) in param_names.iter().enumerate() {
        let value = chunks.get(i).copied().unwrap_or("");
        params.push(SdParam {
            name: CompactString::new(name),
            value: CompactString::new(value),
        });
    }

    let element = SdElement { id: sd_id, params };

    // Should never panic
    let _ = syslog_sign::blocks::SignatureBlock::from_sd_element(&element);
});
