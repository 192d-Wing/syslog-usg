#![no_main]
//! Fuzz the PRI field parser directly.
//!
//! PRI parsing is the first thing that happens for every syslog message.
//! It must handle malformed `<`, missing `>`, non-digit characters,
//! out-of-range values, and overflow attempts gracefully.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut pos = 0;
    let result = syslog_parse::rfc5424::header::parse_pri(data, &mut pos);

    if let Ok(pri) = result {
        // PRI value must be 0-191
        assert!(pri.value() <= 191);
        // Facility * 8 + Severity == PRI
        let recomputed = (pri.facility() as u8) * 8 + (pri.severity() as u8);
        assert_eq!(recomputed, pri.value());
    }
});
