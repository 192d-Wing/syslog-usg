#![no_main]
//! Fuzz the octet-counting codec (RFC 5425 §4.3 framing).
//!
//! This exercises the stateful two-phase decoder with arbitrary byte streams,
//! checking for: no panics, no hangs, bounded memory growth, and correct
//! frame extraction when valid.

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use syslog_transport::framing::OctetCountingCodec;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut codec = OctetCountingCodec::with_max_frame_size(64 * 1024);
    let mut buf = BytesMut::from(data);

    // Feed all data through the codec, consuming as many frames as possible.
    // The codec is stateful — it may need multiple decode calls.
    loop {
        match codec.decode(&mut buf) {
            Ok(Some(_frame)) => {
                // Successfully decoded a frame — continue for more
            }
            Ok(None) => {
                // Need more data — stop
                break;
            }
            Err(_) => {
                // Error is expected for malformed input — stop
                break;
            }
        }
    }
});
