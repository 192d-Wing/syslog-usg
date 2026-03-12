//! Heuristic helpers for RFC 3164 (BSD syslog) best-effort parsing.
//!
//! RFC 3164 is loosely specified. These heuristics attempt to extract
//! timestamp, hostname, and tag from the traditional BSD format:
//!   <PRI>TIMESTAMP HOSTNAME TAG: MSG

/// Month abbreviations as used in BSD syslog timestamps (Mmm).
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Try to parse a BSD-style month abbreviation, returning (month_number, bytes_consumed).
/// Month number is 1-based (Jan=1).
pub fn parse_bsd_month(s: &str) -> Option<(u8, usize)> {
    for (i, &m) in MONTHS.iter().enumerate() {
        if s.len() >= m.len() {
            if let Some(prefix) = s.get(..m.len()) {
                if prefix.eq_ignore_ascii_case(m) {
                    // month number is 1-indexed
                    return Some(((i as u8).saturating_add(1), m.len()));
                }
            }
        }
    }
    None
}

/// Check whether a byte slice looks like it starts with a BSD timestamp.
///
/// BSD timestamps have the format: `Mmm dd HH:MM:SS` (15 chars).
/// Returns `true` if the first 3 bytes look like a month abbreviation.
pub fn looks_like_bsd_timestamp(input: &[u8]) -> bool {
    if input.len() < 15 {
        return false;
    }
    let s = match core::str::from_utf8(input.get(..3).unwrap_or_default()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    parse_bsd_month(s).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_months() {
        assert_eq!(parse_bsd_month("Jan"), Some((1, 3)));
        assert_eq!(parse_bsd_month("Dec"), Some((12, 3)));
        assert_eq!(parse_bsd_month("feb"), Some((2, 3)));
        assert_eq!(parse_bsd_month("xyz"), None);
    }

    #[test]
    fn bsd_timestamp_detection() {
        assert!(looks_like_bsd_timestamp(b"Oct 11 22:14:15 rest"));
        assert!(!looks_like_bsd_timestamp(b"2003-10-11T22:14:15.003Z"));
        assert!(!looks_like_bsd_timestamp(b"short"));
    }
}
