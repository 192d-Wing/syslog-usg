#![no_main]
//! Fuzz the strict RFC 5424 parser (`syslog_parse::parse_strict`).
//!
//! This exercises: PRI, VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID,
//! MSGID, STRUCTURED-DATA, and MSG parsing without RFC 3164 fallback.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let result = syslog_parse::parse_strict(data);

    if let Ok(msg) = result {
        assert!(msg.pri().value() <= 191);
        assert_eq!(msg.version, 1);
        assert!(msg.raw.is_some());

        // Header field length constraints (RFC 5424 §6.2)
        if let Some(ref h) = msg.hostname {
            assert!(h.len() <= 255);
        }
        if let Some(ref a) = msg.app_name {
            assert!(a.len() <= 48);
        }
        if let Some(ref p) = msg.proc_id {
            assert!(p.len() <= 128);
        }
        if let Some(ref m) = msg.msg_id {
            assert!(m.len() <= 32);
        }
    }
});
