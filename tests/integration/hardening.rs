//! Hardening integration tests — malformed input, edge cases, adversarial traffic.
//!
//! These tests exercise the system through its public interfaces with realistic
//! and adversarial inputs to verify resilience under production conditions.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio_util::codec::{Decoder, Encoder};

use syslog_parse::ParseError;
use syslog_relay::{ForwardOutput, Pipeline, SeverityFilter};
use syslog_transport::framing::OctetCountingCodec;
use syslog_transport::tcp::{TcpListenerConfig, TcpMessage, run_tcp_listener};
use syslog_transport::udp::{UdpDatagram, UdpListenerConfig, run_udp_listener};

// ==========================================================================
// Helper: spin up a UDP listener + pipeline + parser bridge
// ==========================================================================

struct UdpTestHarness {
    listen_addr: SocketAddr,
    output: ForwardOutput,
    _pipeline_handle: tokio::task::JoinHandle<()>,
    _listener_handle: tokio::task::JoinHandle<()>,
    _bridge_handle: tokio::task::JoinHandle<()>,
    _pipeline_shutdown: syslog_relay::ShutdownHandle,
    ingress: syslog_relay::PipelineIngress,
    shutdown_tx: watch::Sender<bool>,
}

impl UdpTestHarness {
    async fn new() -> Self {
        Self::with_filters(vec![]).await
    }

    async fn with_filters(filters: Vec<Box<dyn syslog_relay::MessageFilter>>) -> Self {
        let output = ForwardOutput::new("test");
        let output_clone = output.clone();
        let (pipeline, ingress, pipeline_shutdown) = Pipeline::new(256, filters, vec![output]);

        let pipeline_handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        let probe = UdpSocket::bind("127.0.0.1:0").await.expect("probe bind");
        let listen_addr = probe.local_addr().expect("probe addr");
        drop(probe);

        let udp_config = UdpListenerConfig {
            bind_addr: listen_addr,
            ..Default::default()
        };

        let (udp_tx, mut udp_rx) = mpsc::channel::<UdpDatagram>(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let listener_handle = tokio::spawn(async move {
            let _ = run_udp_listener(udp_config, udp_tx, shutdown_rx).await;
        });

        let bridge_ingress = ingress.clone();
        let bridge_handle = tokio::spawn(async move {
            while let Some(datagram) = udp_rx.recv().await {
                if let Ok(msg) = syslog_parse::parse(&datagram.data) {
                    let _ = bridge_ingress.send(msg).await;
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        Self {
            listen_addr,
            output: output_clone,
            _pipeline_handle: pipeline_handle,
            _listener_handle: listener_handle,
            _bridge_handle: bridge_handle,
            _pipeline_shutdown: pipeline_shutdown,
            ingress,
            shutdown_tx,
        }
    }

    async fn send(&self, data: &[u8]) {
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender bind");
        sender
            .send_to(data, self.listen_addr)
            .await
            .expect("send_to");
    }

    async fn message_count(&self) -> usize {
        self.output.len().await
    }

    fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        drop(self.ingress);
    }
}

// ==========================================================================
// Helper: spin up a TCP listener + pipeline + parser bridge
// ==========================================================================

struct TcpTestHarness {
    listen_addr: SocketAddr,
    output: ForwardOutput,
    _pipeline_handle: tokio::task::JoinHandle<()>,
    _listener_handle: tokio::task::JoinHandle<()>,
    _bridge_handle: tokio::task::JoinHandle<()>,
    _pipeline_shutdown: syslog_relay::ShutdownHandle,
    ingress: syslog_relay::PipelineIngress,
    shutdown_tx: watch::Sender<bool>,
}

impl TcpTestHarness {
    async fn new() -> Self {
        let output = ForwardOutput::new("test");
        let output_clone = output.clone();
        let (pipeline, ingress, pipeline_shutdown) = Pipeline::new(256, vec![], vec![output]);

        let pipeline_handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let listen_addr = probe.local_addr().expect("addr");
        drop(probe);

        let tcp_config = TcpListenerConfig {
            bind_addr: listen_addr,
            max_frame_size: 64 * 1024,
            tls_acceptor: None,
            max_connections: Some(16),
            max_connections_per_ip: None,
            read_timeout: Some(Duration::from_secs(5)),
            idle_timeout: Some(Duration::from_secs(10)),
            allowed_sources: std::collections::HashSet::new(),
            use_lf_framing: false,
        };

        let (tcp_tx, mut tcp_rx) = mpsc::channel::<TcpMessage>(256);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let listener_handle = tokio::spawn(async move {
            let _ = run_tcp_listener(tcp_config, tcp_tx, shutdown_rx).await;
        });

        let bridge_ingress = ingress.clone();
        let bridge_handle = tokio::spawn(async move {
            while let Some(frame) = tcp_rx.recv().await {
                if let Ok(msg) = syslog_parse::parse(&frame.data) {
                    let _ = bridge_ingress.send(msg).await;
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        Self {
            listen_addr,
            output: output_clone,
            _pipeline_handle: pipeline_handle,
            _listener_handle: listener_handle,
            _bridge_handle: bridge_handle,
            _pipeline_shutdown: pipeline_shutdown,
            ingress,
            shutdown_tx,
        }
    }

    async fn connect(&self) -> tokio::net::TcpStream {
        tokio::net::TcpStream::connect(self.listen_addr)
            .await
            .expect("TCP connect")
    }

    async fn send_framed(stream: &mut tokio::net::TcpStream, msg: &[u8]) {
        let header = format!("{} ", msg.len());
        stream.write_all(header.as_bytes()).await.expect("header");
        stream.write_all(msg).await.expect("body");
    }

    async fn message_count(&self) -> usize {
        self.output.len().await
    }

    fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        drop(self.ingress);
    }
}

// ==========================================================================
// Parser hardening: malformed input never panics
// ==========================================================================

#[test]
fn parse_empty_input() {
    assert!(matches!(
        syslog_parse::parse(b""),
        Err(ParseError::EmptyInput)
    ));
}

#[test]
fn parse_single_byte_inputs() {
    for b in 0u8..=255 {
        let _ = syslog_parse::parse(&[b]);
    }
}

#[test]
fn parse_no_pri() {
    assert!(syslog_parse::parse(b"no angle bracket").is_err());
    assert!(syslog_parse::parse(b"hello <13>1 - - - - - -").is_err());
}

#[test]
fn parse_truncated_pri() {
    assert!(syslog_parse::parse(b"<").is_err());
    assert!(syslog_parse::parse(b"<1").is_err());
    assert!(syslog_parse::parse(b"<13").is_err());
    assert!(syslog_parse::parse(b"<999").is_err());
}

#[test]
fn parse_pri_non_digits() {
    assert!(syslog_parse::parse(b"<abc>").is_err());
    assert!(syslog_parse::parse(b"<1a>").is_err());
    assert!(syslog_parse::parse(b"< 13>").is_err());
}

#[test]
fn parse_pri_out_of_range() {
    assert!(syslog_parse::parse(b"<192>1 - - - - - -").is_err());
    assert!(syslog_parse::parse(b"<255>1 - - - - - -").is_err());
    assert!(syslog_parse::parse(b"<999>1 - - - - - -").is_err());
}

#[test]
fn parse_truncated_header_fields() {
    // Missing fields after PRI
    assert!(syslog_parse::parse_strict(b"<13>1").is_err());
    assert!(syslog_parse::parse_strict(b"<13>1 ").is_err());
    assert!(syslog_parse::parse_strict(b"<13>1 -").is_err());
    assert!(syslog_parse::parse_strict(b"<13>1 - ").is_err());
    assert!(syslog_parse::parse_strict(b"<13>1 - -").is_err());
    assert!(syslog_parse::parse_strict(b"<13>1 - - -").is_err());
    assert!(syslog_parse::parse_strict(b"<13>1 - - - -").is_err());
    assert!(syslog_parse::parse_strict(b"<13>1 - - - - -").is_err());
    // This one should succeed (minimal valid message)
    assert!(syslog_parse::parse_strict(b"<13>1 - - - - - -").is_ok());
}

#[test]
fn parse_invalid_version() {
    assert!(syslog_parse::parse_strict(b"<13>0 - - - - - -").is_err());
    assert!(syslog_parse::parse_strict(b"<13>2 - - - - - -").is_err());
    assert!(syslog_parse::parse_strict(b"<13>9 - - - - - -").is_err());
}

#[test]
fn parse_control_chars_in_fields() {
    // Control characters (< 33) should be rejected in PRINTUSASCII fields
    assert!(syslog_parse::parse_strict(b"<13>1 - host\x00name - - - -").is_err());
    assert!(syslog_parse::parse_strict(b"<13>1 - host\x01name - - - -").is_err());
    assert!(syslog_parse::parse_strict(b"<13>1 - - app\nnm - - -").is_err());
}

#[test]
fn parse_malformed_structured_data() {
    // Unclosed bracket
    assert!(syslog_parse::parse_strict(b"<13>1 - - - - - [unclosed").is_err());
    // Missing SD-ID
    assert!(syslog_parse::parse_strict(b"<13>1 - - - - - []").is_err());
    // Invalid escape
    assert!(syslog_parse::parse_strict(b"<13>1 - - - - - [id key=\"\\x\"]").is_err());
    // Unclosed param value
    assert!(syslog_parse::parse_strict(b"<13>1 - - - - - [id key=\"unclosed]").is_err());
}

#[test]
fn parse_utf8_bom_in_message_body() {
    let mut input = b"<13>1 - - - - - - ".to_vec();
    input.extend_from_slice(&[0xEF, 0xBB, 0xBF]); // BOM
    input.extend_from_slice(b"hello after BOM");
    let result = syslog_parse::parse_strict(&input);
    assert!(result.is_ok());
    if let Ok(msg) = result {
        // BOM should be stripped
        if let Some(body) = &msg.msg {
            assert_eq!(&body[..], b"hello after BOM");
        }
    }
}

#[test]
fn parse_maximum_length_fields() {
    // Hostname at exactly 255 chars
    let hostname: String = (0..255).map(|_| 'a').collect();
    let input = format!("<13>1 - {hostname} - - - -");
    assert!(syslog_parse::parse_strict(input.as_bytes()).is_ok());

    // App name at exactly 48 chars
    let app_name: String = (0..48).map(|_| 'b').collect();
    let input = format!("<13>1 - host {app_name} - - -");
    assert!(syslog_parse::parse_strict(input.as_bytes()).is_ok());
}

#[test]
fn parse_rfc3164_edge_cases() {
    // Minimal BSD message
    assert!(syslog_parse::rfc3164::parser::parse(b"<0>x").is_ok());

    // BSD message with empty body after tag
    let result = syslog_parse::rfc3164::parser::parse(b"<13>Oct 11 22:14:15 host tag: ");
    assert!(result.is_ok());

    // Non-UTF8 content in BSD message
    let mut input = b"<13>Oct 11 22:14:15 host tag: ".to_vec();
    input.extend_from_slice(&[0xFF, 0xFE, 0x80]);
    // Should not panic — 3164 parser is best-effort
    let _ = syslog_parse::rfc3164::parser::parse(&input);
}

#[test]
fn parse_all_facilities_and_severities() {
    for fac in 0u8..24 {
        for sev in 0u8..8 {
            let pri = fac * 8 + sev;
            let input = format!("<{pri}>1 - - - - - -");
            let result = syslog_parse::parse_strict(input.as_bytes());
            assert!(result.is_ok(), "PRI {pri} (fac={fac}, sev={sev}) failed");
        }
    }
}

// ==========================================================================
// Octet-counting codec hardening
// ==========================================================================

#[test]
fn codec_empty_input() {
    let mut codec = OctetCountingCodec::new();
    let mut buf = BytesMut::new();
    let result = codec.decode(&mut buf);
    assert!(matches!(result, Ok(None)));
}

#[test]
fn codec_empty_frame_len() {
    let mut codec = OctetCountingCodec::new();
    let mut buf = BytesMut::from(" data");
    let result = codec.decode(&mut buf);
    assert!(result.is_err());
}

#[test]
fn codec_non_digit_in_length() {
    let mut codec = OctetCountingCodec::new();
    let mut buf = BytesMut::from("abc data");
    let result = codec.decode(&mut buf);
    assert!(result.is_err());
}

#[test]
fn codec_excessive_length_digits() {
    // More than 10 digits without a space
    let mut codec = OctetCountingCodec::new();
    let mut buf = BytesMut::from("12345678901");
    let result = codec.decode(&mut buf);
    assert!(result.is_err());
}

#[test]
fn codec_frame_too_large() {
    let mut codec = OctetCountingCodec::with_max_frame_size(100);
    let mut buf = BytesMut::from("10000 ");
    let result = codec.decode(&mut buf);
    assert!(result.is_err());
}

#[test]
fn codec_zero_length_frame() {
    // RFC 6587 §3.4.1: MSG-LEN = NONZERO-DIGIT *DIGIT — zero is invalid
    let mut codec = OctetCountingCodec::new();
    let mut buf = BytesMut::from("0 ");
    let result = codec.decode(&mut buf);
    assert!(result.is_err(), "MSG-LEN=0 should be rejected per RFC 6587");
}

#[test]
fn codec_back_to_back_frames() {
    let mut codec = OctetCountingCodec::new();
    let mut buf = BytesMut::from("5 hello5 world");
    let frame1 = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(&frame1[..], b"hello");
    let frame2 = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(&frame2[..], b"world");
}

#[test]
fn codec_encode_decode_large_frame() {
    let data = vec![b'X'; 60_000];
    let mut encoder = OctetCountingCodec::new();
    let mut encoded = BytesMut::new();
    encoder.encode(data.as_slice(), &mut encoded).unwrap();

    let mut decoder = OctetCountingCodec::new();
    let frame = decoder.decode(&mut encoded).unwrap().unwrap();
    assert_eq!(&frame[..], data.as_slice());
}

// ==========================================================================
// UDP: malformed packet handling
// ==========================================================================

#[tokio::test]
async fn udp_malformed_packets_dont_crash() {
    let harness = UdpTestHarness::new().await;

    // Send a mix of valid and invalid packets
    let packets: &[&[u8]] = &[
        b"<13>1 - - - - - - valid message",                       // valid
        b"",                                                      // empty
        b"not syslog at all",                                     // no PRI
        b"<999>1 - - - - - -",                                    // invalid PRI
        b"<13>1 - - - - - - second valid message",                // valid
        &[0xFF; 100],                                             // binary garbage
        b"<13>1 - - - - - [broken",                               // truncated SD
        b"<34>1 2023-10-11T22:14:15Z host app - - - third valid", // valid
    ];

    for pkt in packets {
        harness.send(pkt).await;
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Only the valid messages should arrive
    let count = harness.message_count().await;
    assert_eq!(count, 3, "expected 3 valid messages, got {count}");

    harness.shutdown();
}

#[tokio::test]
async fn udp_large_message() {
    let harness = UdpTestHarness::new().await;

    // Construct a large but valid syslog message within UDP datagram limits
    // macOS sendmsg limit is typically ~9216 bytes for loopback
    let body = "x".repeat(8000);
    let msg = format!("<13>1 - host app - - - {body}");
    harness.send(msg.as_bytes()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let count = harness.message_count().await;
    assert_eq!(count, 1, "large message should still parse");

    harness.shutdown();
}

#[tokio::test]
async fn udp_rapid_fire_messages() {
    let harness = UdpTestHarness::new().await;

    let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
    let count = 100;

    for i in 0..count {
        let msg = format!("<13>1 - host app - - - message {i}");
        sender
            .send_to(msg.as_bytes(), harness.listen_addr)
            .await
            .expect("send");
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    let received = harness.message_count().await;
    // UDP may drop packets under load; at least most should arrive
    assert!(
        received >= count / 2,
        "expected at least {}, got {received}",
        count / 2
    );

    harness.shutdown();
}

// ==========================================================================
// TCP: framing edge cases
// ==========================================================================

#[tokio::test]
async fn tcp_partial_frame_delivery() {
    let harness = TcpTestHarness::new().await;
    let mut stream = harness.connect().await;

    let msg = b"<13>1 - host app - - - test message";

    // Send the frame header in one write, body in another
    let header = format!("{} ", msg.len());
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send body in small chunks
    for chunk in msg.chunks(5) {
        stream.write_all(chunk).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let count = harness.message_count().await;
    assert_eq!(count, 1, "partial delivery should reassemble correctly");

    drop(stream);
    harness.shutdown();
}

#[tokio::test]
async fn tcp_back_to_back_frames_single_write() {
    let harness = TcpTestHarness::new().await;
    let mut stream = harness.connect().await;

    let messages = [
        b"<13>1 - h1 a1 - - - msg1" as &[u8],
        b"<14>1 - h2 a2 - - - msg2",
        b"<15>1 - h3 a3 - - - msg3",
    ];

    // Build all frames in a single buffer and write at once
    let mut buf = Vec::new();
    for msg in &messages {
        buf.extend_from_slice(format!("{} ", msg.len()).as_bytes());
        buf.extend_from_slice(msg);
    }
    stream.write_all(&buf).await.unwrap();
    stream.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let count = harness.message_count().await;
    assert_eq!(count, 3, "back-to-back frames should decode, got {count}");

    drop(stream);
    harness.shutdown();
}

#[tokio::test]
async fn tcp_invalid_frame_header() {
    let harness = TcpTestHarness::new().await;
    let mut stream = harness.connect().await;

    // Send invalid frame header (non-digit characters)
    stream.write_all(b"abc data").await.unwrap();
    stream.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    // The connection should be dropped; no messages should arrive
    let count = harness.message_count().await;
    assert_eq!(count, 0, "invalid frame should not produce messages");

    drop(stream);
    harness.shutdown();
}

#[tokio::test]
async fn tcp_oversized_frame_rejected() {
    let harness = TcpTestHarness::new().await;
    let mut stream = harness.connect().await;

    // Claim a frame size larger than max_frame_size (64KB)
    stream.write_all(b"100000 ").await.unwrap();
    stream.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let count = harness.message_count().await;
    assert_eq!(count, 0, "oversized frame should be rejected");

    drop(stream);
    harness.shutdown();
}

#[tokio::test]
async fn tcp_mixed_valid_invalid_messages() {
    let harness = TcpTestHarness::new().await;
    let mut stream = harness.connect().await;

    // Valid message
    let valid = b"<13>1 - host app - - - valid";
    TcpTestHarness::send_framed(&mut stream, valid).await;

    // Invalid syslog content (but valid framing)
    let invalid = b"this is not syslog";
    TcpTestHarness::send_framed(&mut stream, invalid).await;

    // Another valid message
    let valid2 = b"<14>1 - host2 app2 - - - valid2";
    TcpTestHarness::send_framed(&mut stream, valid2).await;

    stream.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    let count = harness.message_count().await;
    assert_eq!(
        count, 2,
        "only valid syslog messages should pass through, got {count}"
    );

    drop(stream);
    harness.shutdown();
}

#[tokio::test]
async fn tcp_connection_drop_mid_frame() {
    let harness = TcpTestHarness::new().await;

    {
        let mut stream = harness.connect().await;
        // Send a frame header promising 1000 bytes, then only send 10 and close
        stream.write_all(b"1000 ").await.unwrap();
        stream.write_all(b"short data").await.unwrap();
        stream.flush().await.unwrap();
        // Drop the stream (closes connection)
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    // No complete frames were delivered
    let count = harness.message_count().await;
    assert_eq!(count, 0, "truncated frame should not produce messages");

    harness.shutdown();
}

#[tokio::test]
async fn tcp_multiple_connections_concurrent() {
    let harness = TcpTestHarness::new().await;

    let mut handles = Vec::new();
    let addr = harness.listen_addr;

    // Spawn 5 concurrent connections, each sending 3 messages
    for conn_id in 0..5 {
        let handle = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            for msg_id in 0..3 {
                let msg = format!("<13>1 - host{conn_id} app - - - msg{msg_id}");
                let header = format!("{} ", msg.len());
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(msg.as_bytes()).await.unwrap();
            }
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(stream);
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    let count = harness.message_count().await;
    assert_eq!(count, 15, "expected 15 messages from 5x3, got {count}");

    harness.shutdown();
}

// ==========================================================================
// Pipeline: filter edge cases
// ==========================================================================

#[tokio::test]
async fn pipeline_filters_debug_passes_emergency() {
    use syslog_proto::Severity;

    let filter = SeverityFilter::new(Severity::Emergency);
    let filters: Vec<Box<dyn syslog_relay::MessageFilter>> = vec![Box::new(filter)];
    let harness = UdpTestHarness::with_filters(filters).await;

    // Emergency (0) should pass
    harness.send(b"<8>1 - host app - - - emergency").await; // User.Emergency = 1*8+0=8
    // Debug (7) should not pass
    harness.send(b"<15>1 - host app - - - debug").await; // User.Debug = 1*8+7=15
    // Alert (1) should not pass for Emergency-only filter
    harness.send(b"<9>1 - host app - - - alert").await; // User.Alert = 1*8+1=9

    tokio::time::sleep(Duration::from_millis(300)).await;

    let count = harness.message_count().await;
    // Only Emergency should pass
    assert_eq!(count, 1, "only Emergency should pass, got {count}");

    harness.shutdown();
}

// ==========================================================================
// Graceful shutdown under load
// ==========================================================================

#[tokio::test]
async fn graceful_shutdown_during_udp_traffic() {
    let harness = UdpTestHarness::new().await;

    let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
    let addr = harness.listen_addr;

    // Start sending messages
    let send_handle = tokio::spawn(async move {
        for i in 0..50 {
            let msg = format!("<13>1 - host app - - - msg{i}");
            let _ = sender.send_to(msg.as_bytes(), addr).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    // Shutdown after a short delay (while messages are still being sent)
    tokio::time::sleep(Duration::from_millis(50)).await;
    harness.shutdown();

    // This should not panic or hang
    let _ = send_handle.await;
}

// ==========================================================================
// Structured data: complex and adversarial cases
// ==========================================================================

#[test]
fn parse_deeply_nested_sd_params() {
    // Many params in a single SD element
    let mut sd = String::from("[id");
    for i in 0..60 {
        sd.push_str(&format!(" p{i}=\"v{i}\""));
    }
    sd.push(']');
    let input = format!("<13>1 - - - - - {sd}");
    let result = syslog_parse::parse_strict(input.as_bytes());
    assert!(result.is_ok());
}

#[test]
fn parse_many_sd_elements() {
    // 64 SD elements (within limit of 128)
    let mut sd = String::new();
    for i in 0..64 {
        sd.push_str(&format!("[id{i} key=\"val\"]"));
    }
    let input = format!("<13>1 - - - - - {sd}");
    let result = syslog_parse::parse_strict(input.as_bytes());
    assert!(result.is_ok());
}

#[test]
fn parse_too_many_sd_elements_rejected() {
    // 129 SD elements (over limit of 128)
    let mut sd = String::new();
    for i in 0..129 {
        sd.push_str(&format!("[id{i} key=\"val\"]"));
    }
    let input = format!("<13>1 - - - - - {sd}");
    let result = syslog_parse::parse_strict(input.as_bytes());
    assert!(result.is_err());
}

#[test]
fn parse_sd_with_all_escape_sequences() {
    let input = br#"<13>1 - - - - - [id key="quote\"backslash\\bracket\]end"]"#;
    let result = syslog_parse::parse_strict(input);
    assert!(result.is_ok());
    if let Ok(msg) = result {
        let el = msg.structured_data.iter().next();
        assert!(el.is_some());
        if let Some(el) = el {
            assert_eq!(el.param_value("key"), Some("quote\"backslash\\bracket]end"));
        }
    }
}

#[test]
fn parse_sd_empty_param_value() {
    let input = b"<13>1 - - - - - [id key=\"\"]";
    let result = syslog_parse::parse_strict(input);
    assert!(result.is_ok());
    if let Ok(msg) = result {
        let el = msg.structured_data.iter().next();
        assert!(el.is_some());
        if let Some(el) = el {
            assert_eq!(el.param_value("key"), Some(""));
        }
    }
}

// ==========================================================================
// Timestamp edge cases
// ==========================================================================

#[test]
fn parse_various_timestamp_formats() {
    // Full precision with offset
    assert!(
        syslog_parse::parse_strict(b"<13>1 2003-10-11T22:14:15.003000+05:30 - - - - -").is_ok()
    );

    // UTC with Z
    assert!(syslog_parse::parse_strict(b"<13>1 2003-10-11T22:14:15Z - - - - -").is_ok());

    // Nil timestamp
    assert!(syslog_parse::parse_strict(b"<13>1 - - - - - -").is_ok());
}

#[test]
fn parse_invalid_timestamps() {
    // Not RFC 3339
    assert!(syslog_parse::parse_strict(b"<13>1 Oct-11-2003 - - - - -").is_err());
    // Truncated
    assert!(syslog_parse::parse_strict(b"<13>1 2003-10-11 - - - - -").is_err());
}
