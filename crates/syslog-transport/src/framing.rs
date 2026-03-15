//! Octet-counting frame codec for TCP/TLS syslog transport.
//!
//! RFC 5425 §4.3: `SYSLOG-FRAME = MSG-LEN SP SYSLOG-MSG`
//! where MSG-LEN is the number of octets in SYSLOG-MSG as ASCII decimal.

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
}
