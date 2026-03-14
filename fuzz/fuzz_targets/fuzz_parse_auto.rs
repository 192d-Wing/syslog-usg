#![no_main]
//! Fuzz the auto-detect parser (`syslog_parse::parse`).
//!
//! This exercises both RFC 5424 and RFC 3164 code paths, including format
//! detection, PRI parsing, timestamp parsing, header field extraction,
//! structured data parsing, and message body handling.
//!
//! Invariants checked:
//! - No panics on any input
//! - Successful parses produce a message with valid facility/severity

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic regardless of input
    let result = syslog_parse::parse(data);

    // If parsing succeeded, verify basic invariants
    if let Ok(msg) = result {
        // PRI value must be in range 0-191
        assert!(msg.pri().value() <= 191);

        // Version must be 0 (BSD) or 1 (RFC 5424)
        assert!(msg.version <= 1);

        // Raw bytes should be preserved
        assert!(msg.raw.is_some());
    }
});
