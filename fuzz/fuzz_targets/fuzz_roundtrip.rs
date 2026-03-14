#![no_main]
//! Fuzz the parse-serialize-reparse roundtrip for RFC 5424 messages.
//!
//! For any input that parses successfully as RFC 5424, serializing it and
//! reparsing should produce an equivalent message (same facility, severity,
//! version, hostname, app_name, proc_id, msg_id). This catches serializer
//! bugs, field corruption, and inconsistent parse/serialize behavior.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(msg1) = syslog_parse::parse_strict(data) else {
        return;
    };

    // Clear raw bytes so the serializer reconstructs from fields
    let mut msg_no_raw = msg1.clone();
    msg_no_raw.raw = None;

    let serialized = syslog_parse::rfc5424::serializer::serialize(&msg_no_raw);

    let Ok(msg2) = syslog_parse::parse_strict(&serialized) else {
        // If the serializer produced output that doesn't reparse, that's a bug.
        // However, BSD-originated messages (version 0) won't round-trip through
        // the strict parser, so we only assert for version-1 messages.
        if msg1.version == 1 {
            panic!(
                "roundtrip failure: serialized output does not reparse as RFC 5424.\n\
                 Original input ({} bytes): {:?}\n\
                 Serialized ({} bytes): {:?}",
                data.len(),
                String::from_utf8_lossy(data),
                serialized.len(),
                String::from_utf8_lossy(&serialized),
            );
        }
        return;
    };

    // Verify semantic equivalence of key fields
    assert_eq!(msg1.facility, msg2.facility, "facility mismatch");
    assert_eq!(msg1.severity, msg2.severity, "severity mismatch");
    assert_eq!(msg1.version, msg2.version, "version mismatch");
    assert_eq!(msg1.hostname, msg2.hostname, "hostname mismatch");
    assert_eq!(msg1.app_name, msg2.app_name, "app_name mismatch");
    assert_eq!(msg1.proc_id, msg2.proc_id, "proc_id mismatch");
    assert_eq!(msg1.msg_id, msg2.msg_id, "msg_id mismatch");
});
