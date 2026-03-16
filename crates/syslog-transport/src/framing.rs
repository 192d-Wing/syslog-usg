//! Syslog frame codecs for TCP/TLS transport.
//!
//! Supports two framing modes defined in RFC 6587:
//! - **Octet counting** (§3.4.1 / RFC 5425 §4.3): `MSG-LEN SP SYSLOG-MSG`
//! - **Non-transparent / LF-delimited** (§3.4.2): messages terminated by LF (0x0A)

use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::TransportError;

/// Maximum syslog message size (64 KiB, matching UDP maximum).
const MAX_FRAME_SIZE: usize = 64 * 1024;

/// Octet-counting codec for framing syslog messages over TCP/TLS.
///
/// Implements both `Decoder` (for receiving) and `Encoder<&[u8]>` (for sending).
#[derive(Debug, Default)]
pub struct OctetCountingCodec {
    /// Maximum allowed frame size in bytes.
    max_frame_size: usize,
    /// Cached decoded MSG-LEN from the current frame header, if known.
    pending_len: Option<usize>,
}

impl OctetCountingCodec {
    /// Create a new codec with the default maximum frame size (64 KiB).
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_frame_size: MAX_FRAME_SIZE,
            pending_len: None,
        }
    }

    /// Create a new codec with a custom maximum frame size.
    #[must_use]
    pub fn with_max_frame_size(max_frame_size: usize) -> Self {
        Self {
            max_frame_size,
            pending_len: None,
        }
    }
}

impl Decoder for OctetCountingCodec {
    type Item = BytesMut;
    type Error = TransportError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Phase 1: Parse the MSG-LEN header if we haven't yet
        let msg_len = match self.pending_len {
            Some(len) => len,
            None => {
                // Find the space delimiter separating MSG-LEN from SYSLOG-MSG
                let sp_pos = match src.iter().position(|&b| b == b' ') {
                    Some(pos) => pos,
                    None => {
                        // If we have more than 10 digits without a space, that's invalid
                        if src.len() > 10 {
                            return Err(TransportError::InvalidFrame(
                                "MSG-LEN exceeds maximum digit count".to_owned(),
                            ));
                        }
                        return Ok(None); // Need more data
                    }
                };

                if sp_pos == 0 {
                    return Err(TransportError::InvalidFrame("empty MSG-LEN".to_owned()));
                }

                // Validate all bytes before space are ASCII digits
                let len_bytes = src.get(..sp_pos).ok_or_else(|| {
                    TransportError::InvalidFrame("MSG-LEN slice error".to_owned())
                })?;
                for (i, &b) in len_bytes.iter().enumerate() {
                    if !b.is_ascii_digit() {
                        return Err(TransportError::InvalidFrame(format!(
                            "non-digit 0x{b:02X} in MSG-LEN at position {i}"
                        )));
                    }
                }

                let len_str = core::str::from_utf8(len_bytes)
                    .map_err(|_| TransportError::InvalidFrame("MSG-LEN is not ASCII".to_owned()))?;

                let msg_len: usize = len_str.parse().map_err(|_| {
                    TransportError::InvalidFrame(format!("MSG-LEN too large: {len_str}"))
                })?;

                // RFC 6587 §3.4.1: MSG-LEN = NONZERO-DIGIT *DIGIT — zero is invalid
                if msg_len == 0 {
                    return Err(TransportError::InvalidFrame(
                        "MSG-LEN must not be zero (RFC 6587 §3.4.1)".to_owned(),
                    ));
                }

                // RFC 6587 §3.4.1: MSG-LEN = NONZERO-DIGIT *DIGIT — leading zeros are invalid
                if len_bytes.first() == Some(&b'0') && sp_pos > 1 {
                    return Err(TransportError::InvalidFrame(
                        "MSG-LEN must not have leading zeros (RFC 6587 §3.4.1)".to_owned(),
                    ));
                }

                if msg_len > self.max_frame_size {
                    return Err(TransportError::FrameTooLarge {
                        size: msg_len,
                        max: self.max_frame_size,
                    });
                }

                // Consume the header (digits + space)
                let header_len = sp_pos.saturating_add(1);
                src.advance(header_len);

                self.pending_len = Some(msg_len);
                msg_len
            }
        };

        // Phase 2: Wait for the full message body
        if src.len() < msg_len {
            // Reserve space to avoid repeated allocations
            src.reserve(msg_len.saturating_sub(src.len()));
            return Ok(None);
        }

        // Extract the message
        let frame = src.split_to(msg_len);
        self.pending_len = None;

        Ok(Some(frame))
    }
}

impl Encoder<&[u8]> for OctetCountingCodec {
    type Error = TransportError;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.len() > self.max_frame_size {
            return Err(TransportError::FrameTooLarge {
                size: item.len(),
                max: self.max_frame_size,
            });
        }

        // Write MSG-LEN SP SYSLOG-MSG
        let len_str = item.len().to_string();
        dst.reserve(len_str.len().saturating_add(1).saturating_add(item.len()));
        dst.extend_from_slice(len_str.as_bytes());
        dst.extend_from_slice(b" ");
        dst.extend_from_slice(item);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LF-delimited codec (RFC 6587 §3.4.2)
// ---------------------------------------------------------------------------

/// LF-delimited codec for non-transparent framing (RFC 6587 §3.4.2).
///
/// Messages are terminated by LF (0x0A). CRLF sequences are also handled
/// (the CR is stripped). This is the "non-transparent-framing" method
/// described in RFC 6587.
#[derive(Debug)]
pub struct LfDelimitedCodec {
    max_frame_size: usize,
}

impl LfDelimitedCodec {
    /// Create a new codec with the default maximum frame size (64 KiB).
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_frame_size: MAX_FRAME_SIZE,
        }
    }

    /// Create a new codec with a custom maximum frame size.
    #[must_use]
    pub fn with_max_frame_size(max_frame_size: usize) -> Self {
        Self { max_frame_size }
    }
}

impl Default for LfDelimitedCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for LfDelimitedCodec {
    type Item = BytesMut;
    type Error = TransportError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Search for LF (0x0A) in the buffer.
        let lf_pos = match src.iter().position(|&b| b == b'\n') {
            Some(pos) => pos,
            None => {
                // No LF found — check if the buffer exceeds the maximum frame size.
                if src.len() > self.max_frame_size {
                    return Err(TransportError::FrameTooLarge {
                        size: src.len(),
                        max: self.max_frame_size,
                    });
                }
                return Ok(None); // Need more data.
            }
        };

        // Split the buffer: frame bytes before LF, then consume the LF itself.
        let mut frame = src.split_to(lf_pos);
        // Advance past the LF byte.
        src.advance(1);

        // Strip trailing CR if present (handles CRLF line endings).
        if frame.last() == Some(&b'\r') {
            frame.truncate(frame.len().saturating_sub(1));
        }

        Ok(Some(frame))
    }
}

impl Encoder<&[u8]> for LfDelimitedCodec {
    type Error = TransportError;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.len() > self.max_frame_size {
            return Err(TransportError::FrameTooLarge {
                size: item.len(),
                max: self.max_frame_size,
            });
        }

        dst.reserve(item.len().saturating_add(1));
        dst.extend_from_slice(item);
        dst.extend_from_slice(b"\n");

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unified codec enum
// ---------------------------------------------------------------------------

/// Unified syslog frame codec supporting both framing modes.
///
/// This enum dispatches to either [`OctetCountingCodec`] or [`LfDelimitedCodec`],
/// allowing TCP/TLS handlers to be generic over the framing mode.
#[derive(Debug)]
pub enum SyslogCodec {
    /// RFC 5425 §4.3 / RFC 6587 §3.4.1: octet-counting framing.
    OctetCounting(OctetCountingCodec),
    /// RFC 6587 §3.4.2: LF-delimited (non-transparent) framing.
    LfDelimited(LfDelimitedCodec),
}

impl Decoder for SyslogCodec {
    type Item = BytesMut;
    type Error = TransportError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            Self::OctetCounting(c) => c.decode(src),
            Self::LfDelimited(c) => c.decode(src),
        }
    }
}

impl Encoder<&[u8]> for SyslogCodec {
    type Error = TransportError;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            Self::OctetCounting(c) => c.encode(item, dst),
            Self::LfDelimited(c) => c.encode(item, dst),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn decode_single_frame() {
        let mut codec = OctetCountingCodec::new();
        let mut buf = BytesMut::from("11 hello world");
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        if let Ok(Some(frame)) = result {
            assert_eq!(&frame[..], b"hello world");
        }
    }

    #[test]
    fn decode_needs_more_data() {
        let mut codec = OctetCountingCodec::new();
        let mut buf = BytesMut::from("20 short");
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn decode_needs_header() {
        let mut codec = OctetCountingCodec::new();
        let mut buf = BytesMut::from("123");
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn decode_frame_too_large() {
        let mut codec = OctetCountingCodec::with_max_frame_size(10);
        let mut buf = BytesMut::from("100 data");
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn encode_frame() {
        let mut codec = OctetCountingCodec::new();
        let mut buf = BytesMut::new();
        let result = codec.encode(b"hello", &mut buf);
        assert!(result.is_ok());
        assert_eq!(&buf[..], b"5 hello");
    }

    #[test]
    fn encode_too_large() {
        let mut codec = OctetCountingCodec::with_max_frame_size(4);
        let mut buf = BytesMut::new();
        let result = codec.encode(b"hello", &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_zero_length_rejected() {
        let mut codec = OctetCountingCodec::new();
        let mut buf = BytesMut::from("0 ");
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn decode_leading_zeros_rejected() {
        let mut codec = OctetCountingCodec::new();
        let mut buf = BytesMut::from("011 hello world");
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip() {
        let mut codec = OctetCountingCodec::new();
        let msg = b"<13>1 - - - - - - test message";
        let mut encoded = BytesMut::new();
        codec.encode(msg.as_slice(), &mut encoded).ok();

        let mut decoder = OctetCountingCodec::new();
        let decoded = decoder.decode(&mut encoded);
        assert!(decoded.is_ok());
        if let Ok(Some(frame)) = decoded {
            assert_eq!(&frame[..], msg);
        }
    }

    // -- LF-delimited codec tests -------------------------------------------

    #[test]
    fn lf_decode_single_frame() {
        let mut codec = LfDelimitedCodec::new();
        let mut buf = BytesMut::from(&b"hello world\n"[..]);
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        if let Ok(Some(frame)) = result {
            assert_eq!(&frame[..], b"hello world");
        }
    }

    #[test]
    fn lf_decode_crlf() {
        let mut codec = LfDelimitedCodec::new();
        let mut buf = BytesMut::from(&b"hello\r\n"[..]);
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        if let Ok(Some(frame)) = result {
            assert_eq!(&frame[..], b"hello");
        }
    }

    #[test]
    fn lf_decode_needs_more_data() {
        let mut codec = LfDelimitedCodec::new();
        let mut buf = BytesMut::from(&b"partial"[..]);
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn lf_decode_frame_too_large() {
        let mut codec = LfDelimitedCodec::with_max_frame_size(5);
        let mut buf = BytesMut::from(&b"this is way too long without a newline"[..]);
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn lf_encode_frame() {
        let mut codec = LfDelimitedCodec::new();
        let mut buf = BytesMut::new();
        let result = codec.encode(b"hello", &mut buf);
        assert!(result.is_ok());
        assert_eq!(&buf[..], b"hello\n");
    }

    #[test]
    fn lf_decode_multiple_frames() {
        let mut codec = LfDelimitedCodec::new();
        let mut buf = BytesMut::from(&b"first\nsecond\n"[..]);

        let frame1 = codec.decode(&mut buf);
        assert!(frame1.is_ok());
        if let Ok(Some(f)) = frame1 {
            assert_eq!(&f[..], b"first");
        }

        let frame2 = codec.decode(&mut buf);
        assert!(frame2.is_ok());
        if let Ok(Some(f)) = frame2 {
            assert_eq!(&f[..], b"second");
        }
    }

    #[test]
    fn lf_decode_empty_line() {
        let mut codec = LfDelimitedCodec::new();
        let mut buf = BytesMut::from(&b"\n"[..]);
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        if let Ok(Some(frame)) = result {
            assert!(frame.is_empty(), "empty line should produce empty frame");
        }
    }

    #[test]
    fn lf_roundtrip() {
        let mut codec = LfDelimitedCodec::new();
        let msg = b"<13>1 - - - - - - test message";
        let mut encoded = BytesMut::new();
        codec.encode(msg.as_slice(), &mut encoded).ok();

        let mut decoder = LfDelimitedCodec::new();
        let decoded = decoder.decode(&mut encoded);
        assert!(decoded.is_ok());
        if let Ok(Some(frame)) = decoded {
            assert_eq!(&frame[..], msg);
        }
    }

    // -- SyslogCodec enum tests ---------------------------------------------

    #[test]
    fn syslog_codec_octet_counting() {
        let mut codec = SyslogCodec::OctetCounting(OctetCountingCodec::new());
        let mut buf = BytesMut::from("5 hello");
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        if let Ok(Some(frame)) = result {
            assert_eq!(&frame[..], b"hello");
        }
    }

    #[test]
    fn syslog_codec_lf_delimited() {
        let mut codec = SyslogCodec::LfDelimited(LfDelimitedCodec::new());
        let mut buf = BytesMut::from(&b"hello\n"[..]);
        let result = codec.decode(&mut buf);
        assert!(result.is_ok());
        if let Ok(Some(frame)) = result {
            assert_eq!(&frame[..], b"hello");
        }
    }
}
