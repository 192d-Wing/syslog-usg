#![no_main]
//! Fuzz the TOML configuration parser.
//!
//! Config deserialization and validation must handle arbitrary TOML strings
//! (and non-TOML garbage) without panicking.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Must not panic on any input string
        let _ = syslog_config::load_config_str(s);
    }
});
