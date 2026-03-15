#![no_main]
//! Fuzz the PEM/DER auto-detection and base64 decoding logic.
//!
//! Verifies that load_pem_or_der-style logic never panics on
//! arbitrary input, including malformed PEM headers, truncated
//! base64, and binary garbage.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Simulate the PEM/DER detection logic from syslog-server
    let result = detect_and_decode(data);
    // Should never panic — just return Ok or Err
    let _ = result;
});

fn detect_and_decode(raw: &[u8]) -> Result<Vec<u8>, String> {
    use base64::Engine;

    if let Ok(text) = std::str::from_utf8(raw) {
        if text.starts_with("-----BEGIN") {
            let b64: String = text
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect();
            return base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|e| format!("PEM base64 decode: {e}"));
        }
    }

    Ok(raw.to_vec())
}
