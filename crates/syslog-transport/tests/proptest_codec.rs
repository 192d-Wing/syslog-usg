#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Property-based tests for the octet-counting codec (RFC 5425).
//!
//! Tests invariants like:
//! - Encode/decode roundtrip is lossless
//! - Arbitrary bytes never panic the decoder
//! - Multiple back-to-back frames decode correctly
//! - Frame size limits are enforced consistently

use bytes::BytesMut;
use proptest::prelude::*;
use syslog_transport::framing::OctetCountingCodec;
use tokio_util::codec::{Decoder, Encoder};

// ---------------------------------------------------------------------------
// Property: encode/decode roundtrip is lossless
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn codec_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..=4096)) {
        let mut encoder = OctetCountingCodec::new();
        let mut decoder = OctetCountingCodec::new();

        let mut encoded = BytesMut::new();
        let encode_result = encoder.encode(data.as_slice(), &mut encoded);
        prop_assert!(encode_result.is_ok());

        let decode_result = decoder.decode(&mut encoded);
        prop_assert!(decode_result.is_ok());
        if let Ok(Some(frame)) = decode_result {
            prop_assert_eq!(&frame[..], data.as_slice());
        } else {
            prop_assert!(false, "decode returned None after successful encode");
        }
    }

    // ---------------------------------------------------------------------------
    // Property: arbitrary bytes never panic the decoder
    // ---------------------------------------------------------------------------

    #[test]
    fn decoder_never_panics(data in proptest::collection::vec(any::<u8>(), 0..=1024)) {
        let mut codec = OctetCountingCodec::new();
        let mut buf = BytesMut::from(data.as_slice());

        // Drain as many frames as possible
        while let Ok(Some(_)) = codec.decode(&mut buf) {}
    }

    // ---------------------------------------------------------------------------
    // Property: multiple frames in a single buffer decode correctly
    // ---------------------------------------------------------------------------

    #[test]
    fn multi_frame_roundtrip(
        frames in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 1..=256),
            1..=8
        )
    ) {
        let mut encoder = OctetCountingCodec::new();
        let mut buf = BytesMut::new();

        // Encode all frames into one buffer
        for frame in &frames {
            let result = encoder.encode(frame.as_slice(), &mut buf);
            prop_assert!(result.is_ok());
        }

        // Decode all frames back
        let mut decoder = OctetCountingCodec::new();
        let mut decoded = Vec::new();

        loop {
            match decoder.decode(&mut buf) {
                Ok(Some(frame)) => decoded.push(frame.to_vec()),
                Ok(None) => break,
                Err(e) => prop_assert!(false, "unexpected decode error: {:?}", e),
            }
        }

        prop_assert_eq!(decoded.len(), frames.len(), "frame count mismatch");
        for (original, decoded_frame) in frames.iter().zip(decoded.iter()) {
            prop_assert_eq!(original, decoded_frame);
        }
    }

    // ---------------------------------------------------------------------------
    // Property: frame size limits are enforced for both encode and decode
    // ---------------------------------------------------------------------------

    #[test]
    fn oversized_frame_rejected_on_encode(
        data_len in 65u16..=1024,
    ) {
        let max_size = 64usize;
        let mut codec = OctetCountingCodec::with_max_frame_size(max_size);
        let data = vec![b'x'; data_len as usize];
        let mut buf = BytesMut::new();
        let result = codec.encode(data.as_slice(), &mut buf);
        prop_assert!(result.is_err());
    }

    #[test]
    fn oversized_frame_rejected_on_decode(
        data_len in 65u16..=1024,
    ) {
        let max_size = 64usize;
        let mut codec = OctetCountingCodec::with_max_frame_size(max_size);
        // Build a valid frame header claiming a size over the limit
        let header = format!("{} ", data_len);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(header.as_bytes());
        // Don't need to add the body — the header should trigger the error
        let result = codec.decode(&mut buf);
        prop_assert!(result.is_err());
    }

    // ---------------------------------------------------------------------------
    // Property: partial delivery still works (incremental feeding)
    // ---------------------------------------------------------------------------

    #[test]
    fn incremental_decode(data in proptest::collection::vec(any::<u8>(), 1..=256)) {
        let mut encoder = OctetCountingCodec::new();
        let mut encoded = BytesMut::new();
        let encode_result = encoder.encode(data.as_slice(), &mut encoded);
        prop_assert!(encode_result.is_ok());

        let full_encoded = encoded.to_vec();

        // Feed byte-by-byte
        let mut decoder = OctetCountingCodec::new();
        let mut buf = BytesMut::new();
        let mut decoded_frame = None;

        for &byte in &full_encoded {
            buf.extend_from_slice(&[byte]);
            match decoder.decode(&mut buf) {
                Ok(Some(frame)) => {
                    decoded_frame = Some(frame);
                    break;
                }
                Ok(None) => continue,
                Err(e) => {
                    prop_assert!(false, "decode error during incremental feed: {:?}", e);
                    break;
                }
            }
        }

        let decoded_frame = decoded_frame;
        prop_assert!(decoded_frame.is_some(), "no frame decoded after full input");
        if let Some(frame) = decoded_frame {
            prop_assert_eq!(&frame[..], data.as_slice());
        }
    }

    // ---------------------------------------------------------------------------
    // Property: empty frame (zero-length message) encodes/decodes correctly
    // ---------------------------------------------------------------------------

    #[test]
    fn empty_frame_roundtrip(_dummy in 0u8..1) {
        let mut encoder = OctetCountingCodec::new();
        let mut decoder = OctetCountingCodec::new();

        let mut encoded = BytesMut::new();
        let result = encoder.encode(b"".as_slice(), &mut encoded);
        prop_assert!(result.is_ok());
        prop_assert_eq!(&encoded[..], b"0 ");

        let decode_result = decoder.decode(&mut encoded);
        prop_assert!(decode_result.is_ok());
        if let Ok(Some(frame)) = decode_result {
            prop_assert_eq!(frame.len(), 0);
        }
    }
}
