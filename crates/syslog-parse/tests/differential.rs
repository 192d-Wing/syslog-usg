#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Differential tests comparing syslog-parse against reference implementations.
//!
//! Compares our parser's output against:
//! - `syslog_rfc5424` (strict RFC 5424 reference)
//! - `syslog_loose` (lenient multi-protocol reference)
//!
//! Any disagreement on valid input is flagged for investigation.

use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Helpers: map reference crate types to comparable values
// ---------------------------------------------------------------------------

/// Map our facility to a code for comparison.
fn our_facility_code(f: syslog_proto::Facility) -> u8 {
    f as u8
}

/// Map our severity to a code for comparison.
fn our_severity_code(s: syslog_proto::Severity) -> u8 {
    s as u8
}

/// Map syslog_rfc5424's facility to a code.
fn ref_facility_code(f: syslog_rfc5424::SyslogFacility) -> u8 {
    use syslog_rfc5424::SyslogFacility::*;
    match f {
        LOG_KERN => 0,
        LOG_USER => 1,
        LOG_MAIL => 2,
        LOG_DAEMON => 3,
        LOG_AUTH => 4,
        LOG_SYSLOG => 5,
        LOG_LPR => 6,
        LOG_NEWS => 7,
        LOG_UUCP => 8,
        LOG_CRON => 9,
        LOG_AUTHPRIV => 10,
        LOG_FTP => 11,
        LOG_NTP => 12,
        LOG_AUDIT => 13,
        LOG_ALERT => 14,
        LOG_CLOCKD => 15,
        LOG_LOCAL0 => 16,
        LOG_LOCAL1 => 17,
        LOG_LOCAL2 => 18,
        LOG_LOCAL3 => 19,
        LOG_LOCAL4 => 20,
        LOG_LOCAL5 => 21,
        LOG_LOCAL6 => 22,
        LOG_LOCAL7 => 23,
    }
}

/// Map syslog_rfc5424's severity to a code.
fn ref_severity_code(s: syslog_rfc5424::SyslogSeverity) -> u8 {
    use syslog_rfc5424::SyslogSeverity::*;
    match s {
        SEV_EMERG => 0,
        SEV_ALERT => 1,
        SEV_CRIT => 2,
        SEV_ERR => 3,
        SEV_WARNING => 4,
        SEV_NOTICE => 5,
        SEV_INFO => 6,
        SEV_DEBUG => 7,
    }
}

/// Map syslog_loose's facility to a code.
fn loose_facility_code(f: syslog_loose::SyslogFacility) -> u8 {
    use syslog_loose::SyslogFacility::*;
    match f {
        LOG_KERN => 0,
        LOG_USER => 1,
        LOG_MAIL => 2,
        LOG_DAEMON => 3,
        LOG_AUTH => 4,
        LOG_SYSLOG => 5,
        LOG_LPR => 6,
        LOG_NEWS => 7,
        LOG_UUCP => 8,
        LOG_CRON => 9,
        LOG_AUTHPRIV => 10,
        LOG_FTP => 11,
        LOG_NTP => 12,
        LOG_AUDIT => 13,
        LOG_ALERT => 14,
        LOG_CLOCKD => 15,
        LOG_LOCAL0 => 16,
        LOG_LOCAL1 => 17,
        LOG_LOCAL2 => 18,
        LOG_LOCAL3 => 19,
        LOG_LOCAL4 => 20,
        LOG_LOCAL5 => 21,
        LOG_LOCAL6 => 22,
        LOG_LOCAL7 => 23,
    }
}

/// Map syslog_loose's severity to a code.
fn loose_severity_code(s: syslog_loose::SyslogSeverity) -> u8 {
    use syslog_loose::SyslogSeverity::*;
    match s {
        SEV_EMERG => 0,
        SEV_ALERT => 1,
        SEV_CRIT => 2,
        SEV_ERR => 3,
        SEV_WARNING => 4,
        SEV_NOTICE => 5,
        SEV_INFO => 6,
        SEV_DEBUG => 7,
    }
}

// ---------------------------------------------------------------------------
// RFC 5424 test vectors — canonical messages both parsers should agree on
// ---------------------------------------------------------------------------

/// Well-known RFC 5424 examples that all parsers should handle identically.
const RFC5424_VECTORS: &[&str] = &[
    // RFC 5424 §6.5 Example 1
    "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8",
    // RFC 5424 §6.5 Example 2
    "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.",
    // RFC 5424 §6.5 Example 3
    "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] An application event log entry...",
    // RFC 5424 §6.5 Example 4
    "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]",
    // Minimal message
    "<0>1 - - - - - -",
    // All NIL fields with body
    "<13>1 - - - - - - hello world",
    // All fields populated
    "<34>1 2023-10-11T22:14:15Z myhost myapp 1234 ID47 - test message",
    // Structured data with escapes
    r#"<13>1 - - - - - [test key="val\"ue"] body"#,
    r#"<13>1 - - - - - [test key="val\\ue"] body"#,
    r#"<13>1 - - - - - [test key="val\]ue"] body"#,
    // Multiple SD elements
    "<13>1 - - - - - [id1 a=\"1\"][id2 b=\"2\"] body",
    // Edge-case PRI values
    "<0>1 - - - - - - emerg",
    "<191>1 - - - - - - debug",
    // Long hostname
    "<13>1 - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa - - - -",
];

// ---------------------------------------------------------------------------
// Roundtrip test vectors for parse → serialize → re-parse fidelity
// ---------------------------------------------------------------------------

const ROUNDTRIP_VECTORS: &[&str] = &[
    "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed",
    "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.",
    "<0>1 - - - - - -",
    "<13>1 2023-01-15T12:00:00Z myhost myapp 1234 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\"] hello",
];

// ---------------------------------------------------------------------------
// Differential test: syslog_parse vs syslog_rfc5424 on known vectors
// ---------------------------------------------------------------------------

#[test]
fn differential_rfc5424_known_vectors() {
    for (i, &input) in RFC5424_VECTORS.iter().enumerate() {
        let our_result = syslog_parse::parse_strict(input.as_bytes());
        let ref_result = syslog_rfc5424::parse_message(input);

        match (&our_result, &ref_result) {
            (Ok(ours), Ok(theirs)) => {
                // Facility must agree
                assert_eq!(
                    our_facility_code(ours.facility),
                    ref_facility_code(theirs.facility),
                    "vector {i}: facility mismatch for: {input}"
                );
                // Severity must agree
                assert_eq!(
                    our_severity_code(ours.severity),
                    ref_severity_code(theirs.severity),
                    "vector {i}: severity mismatch for: {input}"
                );
                // Hostname
                assert_eq!(
                    ours.hostname.as_deref(),
                    theirs.hostname.as_deref(),
                    "vector {i}: hostname mismatch for: {input}"
                );
                // App name
                assert_eq!(
                    ours.app_name.as_deref(),
                    theirs.appname.as_deref(),
                    "vector {i}: app_name mismatch for: {input}"
                );
                // Message ID
                assert_eq!(
                    ours.msg_id.as_deref(),
                    theirs.msgid.as_deref(),
                    "vector {i}: msg_id mismatch for: {input}"
                );
                // Structured data element count
                let our_sd_count = ours.structured_data.iter().count();
                let ref_sd_count = theirs.sd.len();
                assert_eq!(
                    our_sd_count, ref_sd_count,
                    "vector {i}: SD element count mismatch for: {input}"
                );
                // Compare SD element contents
                for el in ours.structured_data.iter() {
                    let sd_id = el.id.as_str();
                    let ref_el = theirs.sd.find_sdid(sd_id);
                    assert!(
                        ref_el.is_some(),
                        "vector {i}: SD-ID '{sd_id}' present in ours but missing in reference for: {input}"
                    );
                    if let Some(ref_params) = ref_el {
                        for param in &el.params {
                            let ref_val = ref_params.get(param.name.as_str());
                            assert_eq!(
                                Some(param.value.as_str()),
                                ref_val.map(|s| s.as_str()),
                                "vector {i}: SD param '{}.{}' value mismatch for: {input}",
                                sd_id,
                                param.name
                            );
                        }
                    }
                }
            }
            (Err(_), Err(_)) => {
                // Both reject — fine
            }
            (Ok(_), Err(ref_err)) => {
                // We accept but reference rejects — investigate
                // Some differences are expected (e.g. reference may reject valid edge cases)
                eprintln!(
                    "WARNING vector {i}: we accept but syslog_rfc5424 rejects: {ref_err:?}\n  input: {input}"
                );
            }
            (Err(our_err), Ok(_)) => {
                panic!(
                    "vector {i}: we reject but syslog_rfc5424 accepts!\n  our error: {our_err:?}\n  input: {input}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Differential test: syslog_parse vs syslog_loose on known vectors
// ---------------------------------------------------------------------------

#[test]
fn differential_loose_known_vectors() {
    for (i, &input) in RFC5424_VECTORS.iter().enumerate() {
        let our_result = syslog_parse::parse(input.as_bytes());
        let loose_result = syslog_loose::parse_message(input, syslog_loose::Variant::Either);

        if let Ok(ours) = &our_result {
            // Facility
            if let Some(loose_fac) = loose_result.facility {
                assert_eq!(
                    our_facility_code(ours.facility),
                    loose_facility_code(loose_fac),
                    "vector {i}: facility mismatch vs syslog_loose for: {input}"
                );
            }
            // Severity
            if let Some(loose_sev) = loose_result.severity {
                assert_eq!(
                    our_severity_code(ours.severity),
                    loose_severity_code(loose_sev),
                    "vector {i}: severity mismatch vs syslog_loose for: {input}"
                );
            }
            // Hostname
            assert_eq!(
                ours.hostname.as_deref(),
                loose_result.hostname,
                "vector {i}: hostname mismatch vs syslog_loose for: {input}"
            );
            // App name
            assert_eq!(
                ours.app_name.as_deref(),
                loose_result.appname,
                "vector {i}: app_name mismatch vs syslog_loose for: {input}"
            );
            // Message ID
            assert_eq!(
                ours.msg_id.as_deref(),
                loose_result.msgid,
                "vector {i}: msg_id mismatch vs syslog_loose for: {input}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Differential proptest: random RFC 5424 messages
// ---------------------------------------------------------------------------

/// Generate PRINTUSASCII characters (33-126) for header fields.
fn arb_printusascii_string(max_len: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(33u8..=126, 1..=max_len)
        .prop_map(|bytes| String::from_utf8(bytes).unwrap_or_default())
}

/// Generate a valid facility code (0-23).
fn arb_facility() -> impl Strategy<Value = u8> {
    0u8..24
}

/// Generate a valid severity code (0-7).
fn arb_severity() -> impl Strategy<Value = u8> {
    0u8..8
}

/// Build a valid RFC 5424 message string from random components.
fn arb_rfc5424_for_diff() -> impl Strategy<Value = String> {
    (
        arb_facility(),
        arb_severity(),
        proptest::option::of(arb_printusascii_string(64)),
        proptest::option::of(arb_printusascii_string(48)),
        proptest::option::of(arb_printusascii_string(32)),
        proptest::option::of(arb_printusascii_string(32)),
        proptest::option::of("[a-zA-Z0-9 .,!?]{0,64}"),
    )
        .prop_map(
            |(fac, sev, hostname, app_name, proc_id, msg_id, msg_body)| {
                let pri = fac * 8 + sev;
                let mut out = format!("<{pri}>1 2023-01-15T12:00:00Z ");

                match &hostname {
                    Some(h) => out.push_str(h),
                    None => out.push('-'),
                }
                out.push(' ');

                match &app_name {
                    Some(a) => out.push_str(a),
                    None => out.push('-'),
                }
                out.push(' ');

                match &proc_id {
                    Some(p) => out.push_str(p),
                    None => out.push('-'),
                }
                out.push(' ');

                match &msg_id {
                    Some(m) => out.push_str(m),
                    None => out.push('-'),
                }
                out.push_str(" -");

                if let Some(body) = &msg_body {
                    if !body.is_empty() {
                        out.push(' ');
                        out.push_str(body);
                    }
                }

                out
            },
        )
}

proptest! {
    /// For randomly generated valid RFC 5424 messages, both our parser and the
    /// reference parser must agree on facility, severity, hostname, app_name.
    #[test]
    fn differential_proptest_rfc5424_vs_reference(msg in arb_rfc5424_for_diff()) {
        let our_result = syslog_parse::parse_strict(msg.as_bytes());
        let ref_result = syslog_rfc5424::parse_message(&msg);

        match (&our_result, &ref_result) {
            (Ok(ours), Ok(theirs)) => {
                prop_assert_eq!(
                    our_facility_code(ours.facility),
                    ref_facility_code(theirs.facility),
                    "facility mismatch for: {}", msg
                );
                prop_assert_eq!(
                    our_severity_code(ours.severity),
                    ref_severity_code(theirs.severity),
                    "severity mismatch for: {}", msg
                );
                prop_assert_eq!(
                    ours.hostname.as_deref(),
                    theirs.hostname.as_deref(),
                    "hostname mismatch for: {}", msg
                );
                prop_assert_eq!(
                    ours.app_name.as_deref(),
                    theirs.appname.as_deref(),
                    "app_name mismatch for: {}", msg
                );
                prop_assert_eq!(
                    ours.msg_id.as_deref(),
                    theirs.msgid.as_deref(),
                    "msg_id mismatch for: {}", msg
                );
            }
            (Err(_), Err(_)) => {
                // Both reject — agreement
            }
            (Ok(_), Err(_)) => {
                // We're more lenient — acceptable but worth logging
            }
            (Err(our_err), Ok(_)) => {
                // We reject something the reference accepts — investigate
                prop_assert!(
                    false,
                    "we reject but reference accepts!\n  error: {:?}\n  input: {}",
                    our_err, msg
                );
            }
        }
    }

    /// Differential test vs syslog_loose on random messages.
    /// Note: syslog_loose has different hostname/app_name heuristics (e.g. it
    /// treats ":" as invalid hostname while RFC 5424 allows any PRINTUSASCII).
    /// We only compare facility/severity which are unambiguously encoded in PRI.
    #[test]
    fn differential_proptest_vs_loose(msg in arb_rfc5424_for_diff()) {
        let our_result = syslog_parse::parse(msg.as_bytes());
        let loose_result = syslog_loose::parse_message(&msg, syslog_loose::Variant::Either);

        if let Ok(ours) = &our_result {
            if let Some(loose_fac) = loose_result.facility {
                prop_assert_eq!(
                    our_facility_code(ours.facility),
                    loose_facility_code(loose_fac),
                    "facility mismatch vs syslog_loose for: {}", msg
                );
            }
            if let Some(loose_sev) = loose_result.severity {
                prop_assert_eq!(
                    our_severity_code(ours.severity),
                    loose_severity_code(loose_sev),
                    "severity mismatch vs syslog_loose for: {}", msg
                );
            }
        }
    }

    /// Feed arbitrary bytes to all three parsers. None should panic.
    /// We don't compare results since the parsers have different error handling,
    /// but we verify no crashes occur.
    #[test]
    fn all_parsers_no_panic_on_arbitrary_input(data in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let _ = syslog_parse::parse(&data);
        if let Ok(s) = std::str::from_utf8(&data) {
            let _ = syslog_rfc5424::parse_message(s);
            let _ = syslog_loose::parse_message(s, syslog_loose::Variant::Either);
        }
    }
}

// ---------------------------------------------------------------------------
// Structured data differential tests
// ---------------------------------------------------------------------------

#[test]
fn differential_structured_data_escapes() {
    // Test that escape sequences are handled identically
    let cases = [
        r#"<13>1 - - - - - [test key="val\"ue"] body"#,
        r#"<13>1 - - - - - [test key="val\\ue"] body"#,
        r#"<13>1 - - - - - [test key="val\]ue"] body"#,
        r#"<13>1 - - - - - [test key=""] body"#,
        r#"<13>1 - - - - - [test a="1" b="2" c="3"] body"#,
    ];

    for input in &cases {
        let our_result = syslog_parse::parse_strict(input.as_bytes());
        let ref_result = syslog_rfc5424::parse_message(input);

        match (&our_result, &ref_result) {
            (Ok(ours), Ok(theirs)) => {
                for el in ours.structured_data.iter() {
                    let sd_id = el.id.as_str();
                    let ref_el = theirs.sd.find_sdid(sd_id);
                    assert!(
                        ref_el.is_some(),
                        "SD-ID '{sd_id}' missing in reference for: {input}"
                    );
                    if let Some(ref_params) = ref_el {
                        for param in &el.params {
                            let ref_val = ref_params.get(param.name.as_str());
                            assert_eq!(
                                Some(param.value.as_str()),
                                ref_val.map(|s| s.as_str()),
                                "SD param '{}.{}' value mismatch for: {input}",
                                sd_id,
                                param.name
                            );
                        }
                    }
                }
            }
            (Ok(_), Err(e)) => {
                eprintln!("WARNING: we accept but reference rejects: {e:?}\n  input: {input}");
            }
            (Err(e), Ok(_)) => {
                panic!("we reject but reference accepts: {e:?}\n  input: {input}");
            }
            (Err(_), Err(_)) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// PRI boundary differential test
// ---------------------------------------------------------------------------

#[test]
fn differential_all_pri_values() {
    for pri in 0u8..=191 {
        let input = format!("<{pri}>1 - - - - - -");
        let our_result = syslog_parse::parse_strict(input.as_bytes());
        let ref_result = syslog_rfc5424::parse_message(&input);

        match (&our_result, &ref_result) {
            (Ok(ours), Ok(theirs)) => {
                assert_eq!(
                    our_facility_code(ours.facility),
                    ref_facility_code(theirs.facility),
                    "facility mismatch for PRI {pri}"
                );
                assert_eq!(
                    our_severity_code(ours.severity),
                    ref_severity_code(theirs.severity),
                    "severity mismatch for PRI {pri}"
                );
            }
            (Ok(_), Err(e)) => {
                panic!("PRI {pri}: we accept but reference rejects: {e:?}");
            }
            (Err(e), Ok(_)) => {
                panic!("PRI {pri}: we reject but reference accepts: {e:?}");
            }
            (Err(_), Err(_)) => {
                panic!("PRI {pri}: both reject — unexpected for valid PRI");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Parse-serialize roundtrip fidelity test
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_fidelity() {
    use syslog_proto::SyslogTimestamp;

    for (i, &input) in ROUNDTRIP_VECTORS.iter().enumerate() {
        // Step 1: Parse the original message
        let mut parsed1 = syslog_parse::parse_strict(input.as_bytes())
            .unwrap_or_else(|e| panic!("vector {i}: first parse failed: {e:?}\n  input: {input}"));

        // Step 2: Clear raw to force reconstruction
        parsed1.raw = None;

        // Step 3: Serialize
        let serialized = syslog_parse::rfc5424::serializer::serialize(&parsed1);

        // Step 4: Re-parse the serialized output
        let parsed2 = syslog_parse::parse_strict(&serialized).unwrap_or_else(|e| {
            panic!(
                "vector {i}: re-parse failed: {e:?}\n  serialized: {}",
                String::from_utf8_lossy(&serialized)
            )
        });

        // Step 5: Compare all fields
        assert_eq!(
            our_facility_code(parsed1.facility),
            our_facility_code(parsed2.facility),
            "vector {i}: facility mismatch after roundtrip"
        );
        assert_eq!(
            our_severity_code(parsed1.severity),
            our_severity_code(parsed2.severity),
            "vector {i}: severity mismatch after roundtrip"
        );
        assert_eq!(
            parsed1.version, parsed2.version,
            "vector {i}: version mismatch after roundtrip"
        );

        // Compare timestamps via Display (precision differences are acceptable in RFC 3339)
        match (&parsed1.timestamp, &parsed2.timestamp) {
            (SyslogTimestamp::Nil, SyslogTimestamp::Nil) => {}
            (SyslogTimestamp::Value(_), SyslogTimestamp::Value(_)) => {
                assert_eq!(
                    format!("{}", parsed1.timestamp),
                    format!("{}", parsed2.timestamp),
                    "vector {i}: timestamp mismatch after roundtrip"
                );
            }
            _ => panic!(
                "vector {i}: timestamp variant mismatch: {:?} vs {:?}",
                parsed1.timestamp, parsed2.timestamp
            ),
        }

        assert_eq!(
            parsed1.hostname, parsed2.hostname,
            "vector {i}: hostname mismatch after roundtrip"
        );
        assert_eq!(
            parsed1.app_name, parsed2.app_name,
            "vector {i}: app_name mismatch after roundtrip"
        );
        assert_eq!(
            parsed1.proc_id, parsed2.proc_id,
            "vector {i}: proc_id mismatch after roundtrip"
        );
        assert_eq!(
            parsed1.msg_id, parsed2.msg_id,
            "vector {i}: msg_id mismatch after roundtrip"
        );

        // Compare structured data
        let sd1_count = parsed1.structured_data.iter().count();
        let sd2_count = parsed2.structured_data.iter().count();
        assert_eq!(
            sd1_count, sd2_count,
            "vector {i}: SD element count mismatch after roundtrip"
        );
        for el1 in parsed1.structured_data.iter() {
            let sd_id = el1.id.as_str();
            let el2 = parsed2
                .structured_data
                .iter()
                .find(|e| e.id.as_str() == sd_id);
            assert!(
                el2.is_some(),
                "vector {i}: SD-ID '{sd_id}' missing after roundtrip"
            );
            let el2 = el2.unwrap();
            assert_eq!(
                el1.params.len(),
                el2.params.len(),
                "vector {i}: SD-ID '{sd_id}' param count mismatch after roundtrip"
            );
            for (p1, p2) in el1.params.iter().zip(el2.params.iter()) {
                assert_eq!(
                    p1.name, p2.name,
                    "vector {i}: SD param name mismatch in '{sd_id}'"
                );
                assert_eq!(
                    p1.value, p2.value,
                    "vector {i}: SD param value mismatch in '{sd_id}.{}'",
                    p1.name
                );
            }
        }

        // Compare message body
        assert_eq!(
            parsed1.msg, parsed2.msg,
            "vector {i}: msg body mismatch after roundtrip"
        );
    }
}

// ---------------------------------------------------------------------------
// Timestamp fractional-second edge case tests
// ---------------------------------------------------------------------------

#[test]
fn timestamp_fractional_seconds() {
    use syslog_proto::SyslogTimestamp;
    use time::Month;

    let fractional_cases = [
        "<0>1 2023-01-15T12:00:00Z - - - - -",
        "<0>1 2023-01-15T12:00:00.1Z - - - - -",
        "<0>1 2023-01-15T12:00:00.12Z - - - - -",
        "<0>1 2023-01-15T12:00:00.123Z - - - - -",
        "<0>1 2023-01-15T12:00:00.123456Z - - - - -",
        "<0>1 2023-01-15T12:00:00.123456789Z - - - - -",
    ];

    for input in &fractional_cases {
        let parsed = syslog_parse::parse_strict(input.as_bytes())
            .unwrap_or_else(|e| panic!("parse failed for: {input}\n  error: {e:?}"));

        match &parsed.timestamp {
            SyslogTimestamp::Nil => panic!("expected timestamp Value, got Nil for: {input}"),
            SyslogTimestamp::Value(dt) => {
                assert_eq!(dt.year(), 2023, "year mismatch for: {input}");
                assert_eq!(dt.month(), Month::January, "month mismatch for: {input}");
                assert_eq!(dt.day(), 15, "day mismatch for: {input}");
            }
        }
    }

    // Timezone variant tests
    let tz_cases = [
        "<0>1 2023-01-15T12:00:00+05:30 - - - - -",
        "<0>1 2023-01-15T12:00:00-07:00 - - - - -",
    ];

    for input in &tz_cases {
        let parsed = syslog_parse::parse_strict(input.as_bytes())
            .unwrap_or_else(|e| panic!("parse failed for: {input}\n  error: {e:?}"));

        match &parsed.timestamp {
            SyslogTimestamp::Nil => panic!("expected timestamp Value, got Nil for: {input}"),
            SyslogTimestamp::Value(dt) => {
                assert_eq!(dt.year(), 2023, "year mismatch for: {input}");
                assert_eq!(dt.month(), Month::January, "month mismatch for: {input}");
                assert_eq!(dt.day(), 15, "day mismatch for: {input}");
            }
        }
    }
}
