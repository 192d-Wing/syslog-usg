#![no_main]
//! Fuzz the RFC 3164 (BSD syslog) best-effort parser.
//!
//! The 3164 parser is intentionally lenient — it should never panic, even
//! on completely garbage input, as long as a PRI can be extracted.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let result = syslog_parse::rfc3164::parser::parse(data);

    if let Ok(msg) = result {
        assert!(msg.pri().value() <= 191);
        assert_eq!(msg.version, 0);
        assert!(msg.raw.is_some());
    }
});
