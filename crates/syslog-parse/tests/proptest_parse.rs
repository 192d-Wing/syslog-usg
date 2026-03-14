#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Property-based tests for syslog-parse.
//!
//! Tests invariants like:
//! - No panics on arbitrary input
//! - Valid messages round-trip through serialize/reparse
//! - PRI values are always in range
//! - Field length constraints are enforced
//! - Parser behavior is deterministic

use proptest::prelude::*;

use syslog_parse::rfc5424::{header, serializer, structured_data};
use syslog_proto::{Facility, Severity, SyslogTimestamp};

// ---------------------------------------------------------------------------
// Custom strategies for generating valid and near-valid syslog components
// ---------------------------------------------------------------------------

/// Generate a valid PRI value (0-191).
fn arb_pri_value() -> impl Strategy<Value = u8> {
    0u8..=191
}

/// Generate a valid facility code (0-23).
fn arb_facility() -> impl Strategy<Value = Facility> {
    (0u8..24).prop_map(|code| Facility::try_from(code).unwrap_or(Facility::Kern))
}

/// Generate a valid severity code (0-7).
fn arb_severity() -> impl Strategy<Value = Severity> {
    (0u8..8).prop_map(|code| Severity::try_from(code).unwrap_or(Severity::Emergency))
}

/// Generate PRINTUSASCII characters (33-126) for header fields.
fn arb_printusascii_string(max_len: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(33u8..=126, 1..=max_len)
        .prop_map(|bytes| String::from_utf8(bytes).unwrap_or_default())
}

/// Generate a valid SD-NAME character (PRINTUSASCII except '=', SP, ']', '"').
fn arb_sd_name_char() -> impl Strategy<Value = u8> {
    (33u8..=126).prop_filter("SD-NAME excludes = ] \" SP", |&b| {
        b != b'=' && b != b']' && b != b'"' && b != b' '
    })
}

/// Generate a valid SD-ID string (1-32 SD-NAME chars).
fn arb_sd_id() -> impl Strategy<Value = String> {
    proptest::collection::vec(arb_sd_name_char(), 1..=32)
        .prop_map(|bytes| String::from_utf8(bytes).unwrap_or_default())
}

/// Generate a valid PARAM-NAME (1-32 SD-NAME chars).
fn arb_param_name() -> impl Strategy<Value = String> {
    proptest::collection::vec(arb_sd_name_char(), 1..=32)
        .prop_map(|bytes| String::from_utf8(bytes).unwrap_or_default())
}

/// Generate a PARAM-VALUE string (may contain any PRINTUSASCII + SP,
/// but we need to escape `"`, `\`, `]`).
fn arb_param_value() -> impl Strategy<Value = String> {
    proptest::collection::vec(32u8..=126, 0..=64)
        .prop_map(|bytes| bytes.iter().map(|&b| b as char).collect::<String>())
}

/// Build a complete valid RFC 5424 message string from components.
fn arb_rfc5424_message() -> impl Strategy<Value = Vec<u8>> {
    (
        arb_facility(),
        arb_severity(),
        proptest::option::of(arb_printusascii_string(255)), // hostname
        proptest::option::of(arb_printusascii_string(48)),  // app_name
        proptest::option::of(arb_printusascii_string(128)), // proc_id
        proptest::option::of(arb_printusascii_string(32)),  // msg_id
        proptest::option::of(prop::string::string_regex("[a-zA-Z0-9 .,!?-]{0,128}").unwrap()),
    )
        .prop_map(
            |(facility, severity, hostname, app_name, proc_id, msg_id, msg_body)| {
                let pri = (facility as u8) * 8 + (severity as u8);
                let mut out = format!("<{pri}>1 - "); // PRI VERSION SP TIMESTAMP SP

                // HOSTNAME
                match &hostname {
                    Some(h) => out.push_str(h),
                    None => out.push('-'),
                }
                out.push(' ');

                // APP-NAME
                match &app_name {
                    Some(a) => out.push_str(a),
                    None => out.push('-'),
                }
                out.push(' ');

                // PROCID
                match &proc_id {
                    Some(p) => out.push_str(p),
                    None => out.push('-'),
                }
                out.push(' ');

                // MSGID
                match &msg_id {
                    Some(m) => out.push_str(m),
                    None => out.push('-'),
                }
                out.push(' ');

                // STRUCTURED-DATA = NILVALUE
                out.push('-');

                // [SP MSG]
                if let Some(body) = &msg_body {
                    if !body.is_empty() {
                        out.push(' ');
                        out.push_str(body);
                    }
                }

                out.into_bytes()
            },
        )
}

/// Build a valid structured data string.
fn arb_structured_data_string() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        (
            arb_sd_id(),
            proptest::collection::vec((arb_param_name(), arb_param_value()), 0..=4),
        ),
        1..=4,
    )
    .prop_map(|elements| {
        let mut s = String::new();
        for (id, params) in elements {
            s.push('[');
            s.push_str(&id);
            for (name, value) in params {
                s.push(' ');
                s.push_str(&name);
                s.push_str("=\"");
                // Escape the value
                for ch in value.chars() {
                    match ch {
                        '"' => s.push_str("\\\""),
                        '\\' => s.push_str("\\\\"),
                        ']' => s.push_str("\\]"),
                        _ => s.push(ch),
                    }
                }
                s.push('"');
            }
            s.push(']');
        }
        s
    })
}

// ---------------------------------------------------------------------------
// Property: arbitrary bytes never panic the parser
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn parse_auto_never_panics(data in proptest::collection::vec(any::<u8>(), 0..=1024)) {
        let _ = syslog_parse::parse(&data);
    }

    #[test]
    fn parse_strict_never_panics(data in proptest::collection::vec(any::<u8>(), 0..=1024)) {
        let _ = syslog_parse::parse_strict(&data);
    }

    #[test]
    fn parse_rfc3164_never_panics(data in proptest::collection::vec(any::<u8>(), 0..=1024)) {
        let _ = syslog_parse::rfc3164::parser::parse(&data);
    }

    // ---------------------------------------------------------------------------
    // Property: valid RFC 5424 messages always parse successfully
    // ---------------------------------------------------------------------------

    #[test]
    fn valid_rfc5424_always_parses(msg_bytes in arb_rfc5424_message()) {
        let result = syslog_parse::parse_strict(&msg_bytes);
        prop_assert!(
            result.is_ok(),
            "valid RFC 5424 message failed to parse: {:?}\ninput: {:?}",
            result.err(),
            String::from_utf8_lossy(&msg_bytes)
        );
    }

    // ---------------------------------------------------------------------------
    // Property: PRI parsing invariants
    // ---------------------------------------------------------------------------

    #[test]
    fn pri_value_always_in_range(pri_val in arb_pri_value()) {
        let input = format!("<{pri_val}>").into_bytes();
        let mut pos = 0;
        let result = header::parse_pri(&input, &mut pos);
        prop_assert!(result.is_ok());
        if let Ok(pri) = result {
            prop_assert!(pri.value() <= 191);
            // Verify facility/severity decomposition
            let recomputed = (pri.facility() as u8) * 8 + (pri.severity() as u8);
            prop_assert_eq!(recomputed, pri.value());
        }
    }

    #[test]
    fn pri_out_of_range_rejected(pri_val in 192u16..=999) {
        let input = format!("<{pri_val}>").into_bytes();
        let mut pos = 0;
        let result = header::parse_pri(&input, &mut pos);
        prop_assert!(result.is_err());
    }

    // ---------------------------------------------------------------------------
    // Property: RFC 5424 roundtrip (parse -> serialize -> reparse)
    // ---------------------------------------------------------------------------

    #[test]
    fn rfc5424_roundtrip_preserves_fields(msg_bytes in arb_rfc5424_message()) {
        let Ok(msg1) = syslog_parse::parse_strict(&msg_bytes) else {
            // If generated message doesn't parse, skip (shouldn't happen)
            return Ok(());
        };

        // Clear raw so serializer rebuilds from fields
        let mut msg_no_raw = msg1.clone();
        msg_no_raw.raw = None;

        let serialized = serializer::serialize(&msg_no_raw);
        let result = syslog_parse::parse_strict(&serialized);

        prop_assert!(
            result.is_ok(),
            "roundtrip reparse failed: {:?}\nserialized: {:?}",
            result.err(),
            String::from_utf8_lossy(&serialized)
        );

        if let Ok(msg2) = result {
            prop_assert_eq!(msg1.facility, msg2.facility);
            prop_assert_eq!(msg1.severity, msg2.severity);
            prop_assert_eq!(msg1.version, msg2.version);
            prop_assert_eq!(msg1.hostname, msg2.hostname);
            prop_assert_eq!(msg1.app_name, msg2.app_name);
            prop_assert_eq!(msg1.proc_id, msg2.proc_id);
            prop_assert_eq!(msg1.msg_id, msg2.msg_id);
        }
    }

    // ---------------------------------------------------------------------------
    // Property: field length constraints enforced
    // ---------------------------------------------------------------------------

    #[test]
    fn hostname_too_long_rejected(len in 256usize..=512) {
        let hostname: String = (0..len).map(|_| 'a').collect();
        let input = format!("<13>1 - {hostname} - - - -").into_bytes();
        let result = syslog_parse::parse_strict(&input);
        prop_assert!(result.is_err());
    }

    #[test]
    fn app_name_too_long_rejected(len in 49usize..=128) {
        let app_name: String = (0..len).map(|_| 'a').collect();
        let input = format!("<13>1 - host {app_name} - - -").into_bytes();
        let result = syslog_parse::parse_strict(&input);
        prop_assert!(result.is_err());
    }

    #[test]
    fn proc_id_too_long_rejected(len in 129usize..=256) {
        let proc_id: String = (0..len).map(|_| 'a').collect();
        let input = format!("<13>1 - host app {proc_id} - -").into_bytes();
        let result = syslog_parse::parse_strict(&input);
        prop_assert!(result.is_err());
    }

    #[test]
    fn msg_id_too_long_rejected(len in 33usize..=64) {
        let msg_id: String = (0..len).map(|_| 'a').collect();
        let input = format!("<13>1 - host app pid {msg_id} -").into_bytes();
        let result = syslog_parse::parse_strict(&input);
        prop_assert!(result.is_err());
    }

    // ---------------------------------------------------------------------------
    // Property: structured data parsing
    // ---------------------------------------------------------------------------

    #[test]
    fn valid_structured_data_always_parses(sd_str in arb_structured_data_string()) {
        let input = sd_str.as_bytes();
        let mut pos = 0;
        let result = structured_data::parse_structured_data(input, &mut pos);
        prop_assert!(
            result.is_ok(),
            "valid SD failed to parse: {:?}\ninput: {:?}",
            result.err(),
            sd_str
        );
    }

    #[test]
    fn structured_data_arbitrary_bytes_no_panic(data in proptest::collection::vec(any::<u8>(), 0..=256)) {
        let mut pos = 0;
        let _ = structured_data::parse_structured_data(&data, &mut pos);
    }

    // ---------------------------------------------------------------------------
    // Property: parser determinism
    // ---------------------------------------------------------------------------

    #[test]
    fn parse_is_deterministic(data in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let result1 = syslog_parse::parse(&data);
        let result2 = syslog_parse::parse(&data);

        match (&result1, &result2) {
            (Ok(m1), Ok(m2)) => {
                prop_assert_eq!(m1.facility, m2.facility);
                prop_assert_eq!(m1.severity, m2.severity);
                prop_assert_eq!(m1.version, m2.version);
                prop_assert_eq!(m1.hostname.as_deref(), m2.hostname.as_deref());
                prop_assert_eq!(m1.app_name.as_deref(), m2.app_name.as_deref());
                prop_assert_eq!(m1.proc_id.as_deref(), m2.proc_id.as_deref());
                prop_assert_eq!(m1.msg_id.as_deref(), m2.msg_id.as_deref());
                prop_assert_eq!(m1.msg.as_deref(), m2.msg.as_deref());
            }
            (Err(_), Err(_)) => { /* both errors is fine */ }
            _ => prop_assert!(false, "non-deterministic parse result"),
        }
    }

    // ---------------------------------------------------------------------------
    // Property: BSD syslog PRI decomposition
    // ---------------------------------------------------------------------------

    #[test]
    fn bsd_parse_preserves_pri(pri_val in arb_pri_value()) {
        let input = format!("<{pri_val}>some message body").into_bytes();
        let result = syslog_parse::rfc3164::parser::parse(&input);
        prop_assert!(result.is_ok());
        if let Ok(msg) = result {
            prop_assert_eq!(msg.pri().value(), pri_val);
        }
    }

    // ---------------------------------------------------------------------------
    // Property: timestamp NIL roundtrip
    // ---------------------------------------------------------------------------

    #[test]
    fn nil_timestamp_roundtrips(
        facility in arb_facility(),
        severity in arb_severity(),
    ) {
        let pri = (facility as u8) * 8 + (severity as u8);
        let input = format!("<{pri}>1 - - - - - -").into_bytes();
        let msg = syslog_parse::parse_strict(&input);
        prop_assert!(msg.is_ok());
        if let Ok(msg) = msg {
            prop_assert!(matches!(msg.timestamp, SyslogTimestamp::Nil));

            // Serialize and reparse
            let mut msg_no_raw = msg.clone();
            msg_no_raw.raw = None;
            let serialized = serializer::serialize(&msg_no_raw);
            let msg2 = syslog_parse::parse_strict(&serialized);
            prop_assert!(msg2.is_ok());
            if let Ok(msg2) = msg2 {
                prop_assert!(matches!(msg2.timestamp, SyslogTimestamp::Nil));
            }
        }
    }
}
