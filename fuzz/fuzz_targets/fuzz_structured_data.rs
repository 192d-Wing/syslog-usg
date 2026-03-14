#![no_main]
//! Fuzz the RFC 5424 §6.3 structured data parser directly.
//!
//! This targets the complex SD-ELEMENT / SD-PARAM / escape handling logic,
//! which is a high-risk area for parser bugs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut pos = 0;
    // Must not panic on any input
    let _ = syslog_parse::rfc5424::structured_data::parse_structured_data(data, &mut pos);
});
