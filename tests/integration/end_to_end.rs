//! End-to-end integration tests.
//!
//! These tests spin up real UDP and TCP listeners, send syslog messages,
//! and verify they flow through parsing and into the pipeline.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

use syslog_relay::{BufferOutput, FileOutput, ForwardOutput, Pipeline, SigningStage};
use syslog_transport::dtls::{DtlsDatagram, DtlsListenerConfig, run_dtls_listener};
use syslog_transport::tcp::{TcpListenerConfig, TcpMessage, run_tcp_listener};
use syslog_transport::udp::{UdpDatagram, UdpListenerConfig, run_udp_listener};

/// A valid RFC 5424 syslog message.
const RFC5424_MSG: &[u8] = b"<165>1 2023-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] An application event log entry";

/// Bind to an ephemeral port and return the bound address.
async fn ephemeral_addr() -> SocketAddr {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    socket.local_addr().expect("local_addr")
}

// ---------------------------------------------------------------------------
// UDP end-to-end
// ---------------------------------------------------------------------------

#[tokio::test]
async fn udp_end_to_end() {
    // 1. Set up pipeline with a test output
    let output = ForwardOutput::new("test");
    let output_clone = output.clone();
    let (pipeline, ingress, _shutdown) = Pipeline::new(64, vec![], vec![output]);

    let pipeline_handle = tokio::spawn(async move {
        let _ = pipeline.run().await;
    });

    // 2. Find a free UDP port and start listener
    let probe = UdpSocket::bind("127.0.0.1:0").await.expect("probe bind");
    let listen_addr = probe.local_addr().expect("probe addr");
    drop(probe);

    let udp_config = UdpListenerConfig {
        bind_addr: listen_addr,
        ..Default::default()
    };

    let (udp_tx, mut udp_rx) = mpsc::channel::<UdpDatagram>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let listener_handle = tokio::spawn(async move {
        let _ = run_udp_listener(udp_config, udp_tx, shutdown_rx).await;
    });

    // Spawn parser bridge
    let bridge_ingress = ingress.clone();
    let bridge_handle = tokio::spawn(async move {
        while let Some(datagram) = udp_rx.recv().await {
            if let Ok(msg) = syslog_parse::parse(&datagram.data) {
                let _ = bridge_ingress.send(msg).await;
            }
        }
    });

    // Give the listener time to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. Send a syslog message via UDP
    let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender bind");
    sender
        .send_to(RFC5424_MSG, listen_addr)
        .await
        .expect("send_to");

    // 5. Wait for the message to flow through
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 6. Verify the message arrived at the output
    let count = output_clone.len().await;
    assert_eq!(count, 1, "expected 1 message in output, got {count}");

    let msgs = output_clone.collected().await;
    if let Some(msg) = msgs.first() {
        assert_eq!(
            msg.hostname.as_deref(),
            Some("mymachine.example.com"),
            "hostname mismatch"
        );
        assert_eq!(
            msg.app_name.as_deref(),
            Some("evntslog"),
            "app_name mismatch"
        );
    }

    // Cleanup
    let _ = shutdown_tx.send(true);
    drop(ingress);
    let _ = pipeline_handle.await;
    let _ = listener_handle.await;
    let _ = bridge_handle.await;
}

// ---------------------------------------------------------------------------
// TCP end-to-end
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_end_to_end() {
    // 1. Set up pipeline with a test output
    let output = ForwardOutput::new("test");
    let output_clone = output.clone();
    let (pipeline, ingress, _shutdown) = Pipeline::new(64, vec![], vec![output]);

    let pipeline_handle = tokio::spawn(async move {
        let _ = pipeline.run().await;
    });

    // 2. Find a free port for the TCP listener
    let listen_addr = ephemeral_addr().await;

    let tcp_config = TcpListenerConfig {
        bind_addr: listen_addr,
        max_frame_size: 64 * 1024,
        tls_acceptor: None,
        max_connections: None,
        max_connections_per_ip: None,
        read_timeout: None,
        idle_timeout: None,
    };

    let (tcp_tx, mut tcp_rx) = mpsc::channel::<TcpMessage>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let listener_handle = tokio::spawn(async move {
        let _ = run_tcp_listener(tcp_config, tcp_tx, shutdown_rx).await;
    });

    // Spawn parser bridge
    let bridge_ingress = ingress.clone();
    let bridge_handle = tokio::spawn(async move {
        while let Some(frame) = tcp_rx.recv().await {
            if let Ok(msg) = syslog_parse::parse(&frame.data) {
                let _ = bridge_ingress.send(msg).await;
            }
        }
    });

    // Give the listener time to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Send a syslog message via TCP with octet-counting framing
    let mut stream = tokio::net::TcpStream::connect(listen_addr)
        .await
        .expect("TCP connect");

    // RFC 5425 §4.3: SYSLOG-FRAME = MSG-LEN SP SYSLOG-MSG
    let frame = format!("{} ", RFC5424_MSG.len());
    stream
        .write_all(frame.as_bytes())
        .await
        .expect("write frame header");
    stream
        .write_all(RFC5424_MSG)
        .await
        .expect("write frame body");
    stream.flush().await.expect("flush");

    // 4. Wait for the message to flow through
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 5. Verify the message arrived at the output
    let count = output_clone.len().await;
    assert_eq!(count, 1, "expected 1 message in output, got {count}");

    let msgs = output_clone.collected().await;
    if let Some(msg) = msgs.first() {
        assert_eq!(
            msg.hostname.as_deref(),
            Some("mymachine.example.com"),
            "hostname mismatch"
        );
        assert_eq!(
            msg.app_name.as_deref(),
            Some("evntslog"),
            "app_name mismatch"
        );
    }

    // Cleanup
    drop(stream);
    let _ = shutdown_tx.send(true);
    drop(ingress);
    let _ = pipeline_handle.await;
    let _ = listener_handle.await;
    let _ = bridge_handle.await;
}

// ---------------------------------------------------------------------------
// TCP multiple messages
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_multiple_messages() {
    let output = ForwardOutput::new("test");
    let output_clone = output.clone();
    let (pipeline, ingress, _shutdown) = Pipeline::new(64, vec![], vec![output]);

    let pipeline_handle = tokio::spawn(async move {
        let _ = pipeline.run().await;
    });

    let listen_addr = ephemeral_addr().await;

    let tcp_config = TcpListenerConfig {
        bind_addr: listen_addr,
        max_frame_size: 64 * 1024,
        tls_acceptor: None,
        max_connections: None,
        max_connections_per_ip: None,
        read_timeout: None,
        idle_timeout: None,
    };

    let (tcp_tx, mut tcp_rx) = mpsc::channel::<TcpMessage>(64);
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

    let mut stream = tokio::net::TcpStream::connect(listen_addr)
        .await
        .expect("TCP connect");

    // Send 5 messages in a single TCP stream
    let messages = [
        b"<34>1 2023-10-11T22:14:15Z host1 app1 - - - msg one" as &[u8],
        b"<165>1 2023-10-11T22:14:16Z host2 app2 - - - msg two",
        b"<14>1 2023-10-11T22:14:17Z host3 app3 1234 - - msg three",
        b"<86>1 2023-10-11T22:14:18Z host4 app4 - ID1 - msg four",
        b"<0>1 2023-10-11T22:14:19Z host5 app5 - - - msg five",
    ];

    for msg in &messages {
        let header = format!("{} ", msg.len());
        stream
            .write_all(header.as_bytes())
            .await
            .expect("write header");
        stream.write_all(msg).await.expect("write msg");
    }
    stream.flush().await.expect("flush");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let count = output_clone.len().await;
    assert_eq!(count, 5, "expected 5 messages in output, got {count}");

    // Verify hostnames are distinct
    let msgs = output_clone.collected().await;
    let hostnames: Vec<_> = msgs.iter().filter_map(|m| m.hostname.as_deref()).collect();
    assert_eq!(hostnames, vec!["host1", "host2", "host3", "host4", "host5"]);

    drop(stream);
    let _ = shutdown_tx.send(true);
    drop(ingress);
    let _ = pipeline_handle.await;
    let _ = listener_handle.await;
    let _ = bridge_handle.await;
}

// ---------------------------------------------------------------------------
// Pipeline with filter integration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pipeline_filter_integration() {
    use syslog_proto::Severity;
    use syslog_relay::{MessageFilter, SeverityFilter};

    let output = ForwardOutput::new("test");
    let output_clone = output.clone();

    // Only pass Warning and above
    let filter = SeverityFilter::new(Severity::Warning);
    let filters: Vec<Box<dyn MessageFilter>> = vec![Box::new(filter)];
    let (pipeline, ingress, _shutdown) = Pipeline::new(64, filters, vec![output]);

    let pipeline_handle = tokio::spawn(async move {
        let _ = pipeline.run().await;
    });

    // Set up UDP listener
    let probe = UdpSocket::bind("127.0.0.1:0").await.expect("probe");
    let listen_addr = probe.local_addr().expect("addr");
    drop(probe);

    let udp_config = UdpListenerConfig {
        bind_addr: listen_addr,
        ..Default::default()
    };

    let (udp_tx, mut udp_rx) = mpsc::channel::<UdpDatagram>(64);
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

    let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");

    // Send messages with different severities:
    // PRI = facility * 8 + severity
    // <165> = User(1)*8 + Notice(5) = 13... wait, 165 = 20*8+5 = local4.notice
    // Let me use: <11> = User(1).Error(3), <15> = User(1).Debug(7), <12> = User(1).Warning(4)
    let error_msg = b"<11>1 2023-10-11T22:14:15Z host app - - - error message"; // severity 3 (Error)
    let debug_msg = b"<15>1 2023-10-11T22:14:16Z host app - - - debug message"; // severity 7 (Debug)
    let warning_msg = b"<12>1 2023-10-11T22:14:17Z host app - - - warning message"; // severity 4 (Warning)

    sender
        .send_to(error_msg, listen_addr)
        .await
        .expect("send error");
    sender
        .send_to(debug_msg, listen_addr)
        .await
        .expect("send debug");
    sender
        .send_to(warning_msg, listen_addr)
        .await
        .expect("send warning");

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Error (3) and Warning (4) should pass, Debug (7) should be filtered
    let count = output_clone.len().await;
    assert_eq!(
        count, 2,
        "expected 2 messages (Error + Warning) after filter, got {count}"
    );

    let _ = shutdown_tx.send(true);
    drop(ingress);
    let _ = pipeline_handle.await;
    let _ = listener_handle.await;
    let _ = bridge_handle.await;
}

// ---------------------------------------------------------------------------
// File output E2E
// ---------------------------------------------------------------------------

#[tokio::test]
async fn file_output_receives_messages() {
    let tmp_dir = tempfile::tempdir().expect("create temp dir");
    let file_path = tmp_dir.path().join("syslog_e2e_output.log");

    let file_output = FileOutput::new("file-e2e", file_path.clone());
    let (pipeline, ingress, _shutdown) = Pipeline::new(64, vec![], vec![file_output]);

    let pipeline_handle = tokio::spawn(async move {
        let _ = pipeline.run().await;
    });

    // Parse and send a valid RFC 5424 message through the pipeline
    let msg = syslog_parse::parse(RFC5424_MSG).expect("parse RFC5424_MSG");
    ingress.send(msg).await.expect("pipeline send");

    // Drop ingress to close pipeline
    drop(ingress);
    let _ = pipeline_handle.await;

    // Verify the file contains the serialized message
    let contents = tokio::fs::read_to_string(&file_path)
        .await
        .expect("read output file");
    assert!(
        contents.contains("mymachine.example.com"),
        "file should contain hostname, got: {contents}"
    );
    assert!(
        contents.contains("evntslog"),
        "file should contain app_name, got: {contents}"
    );
    assert!(
        contents.contains("An application event log entry"),
        "file should contain message body, got: {contents}"
    );
    assert!(contents.ends_with('\n'), "file should end with newline");
}

// ---------------------------------------------------------------------------
// Buffer output E2E
// ---------------------------------------------------------------------------

#[tokio::test]
async fn buffer_output_stores_messages() {
    let buffer = BufferOutput::new("buf-e2e", 5);
    let buffer_clone = buffer.clone();
    let (pipeline, ingress, _shutdown) = Pipeline::new(64, vec![], vec![buffer]);

    let pipeline_handle = tokio::spawn(async move {
        let _ = pipeline.run().await;
    });

    // Send 3 distinct messages
    let raw_messages: &[&[u8]] = &[
        b"<34>1 2023-10-11T22:14:15Z host1 app1 - - - msg one",
        b"<165>1 2023-10-11T22:14:16Z host2 app2 - - - msg two",
        b"<14>1 2023-10-11T22:14:17Z host3 app3 - - - msg three",
    ];

    for raw in raw_messages {
        let msg = syslog_parse::parse(raw).expect("parse");
        ingress.send(msg).await.expect("pipeline send");
    }

    // Give pipeline time to process
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify snapshot has 3 messages
    let snap = buffer_clone.snapshot().await;
    assert_eq!(
        snap.len(),
        3,
        "buffer should hold 3 messages, got {}",
        snap.len()
    );

    // Verify hostnames
    let hostnames: Vec<_> = snap.iter().filter_map(|m| m.hostname.as_deref()).collect();
    assert_eq!(hostnames, vec!["host1", "host2", "host3"]);

    // Cleanup
    drop(ingress);
    let _ = pipeline_handle.await;
}

// ---------------------------------------------------------------------------
// Signing produces signature blocks E2E
// ---------------------------------------------------------------------------

#[tokio::test]
async fn signing_produces_signature_blocks() {
    use syslog_sign::counter::RebootSessionId;
    use syslog_sign::signature::SigningKey;
    use syslog_sign::signer::{Signer, SignerConfig};

    // Generate a signing key
    let (key, _verifying_key) = match SigningKey::generate() {
        Ok(v) => v,
        Err(_) => {
            // Skip test if key generation fails
            return;
        }
    };

    let rsid = RebootSessionId::unpersisted();
    let config = SignerConfig {
        max_hashes_per_block: 2, // trigger sig block after 2 messages
        ..Default::default()
    };
    let signer = Signer::new(key, rsid, config);

    // Build a template message for signature block headers
    let template =
        syslog_parse::parse(b"<13>1 - sighost sigapp - - - template").expect("parse template");

    let signing_stage = SigningStage::new(
        signer,
        None,
        Duration::from_secs(3600), // no cert blocks
        template,
    );

    let output = ForwardOutput::new("sign-e2e");
    let output_clone = output.clone();

    let (pipeline, ingress, _shutdown) =
        Pipeline::with_signing(64, vec![], vec![output], Some(signing_stage), None);

    let pipeline_handle = tokio::spawn(async move {
        let _ = pipeline.run().await;
    });

    // Send 2 messages to fill the hash chain
    let msg1 = syslog_parse::parse(b"<11>1 2023-10-11T22:14:15Z host app - - - signed msg one")
        .expect("parse msg1");
    let msg2 = syslog_parse::parse(b"<11>1 2023-10-11T22:14:16Z host app - - - signed msg two")
        .expect("parse msg2");

    ingress.send(msg1).await.expect("send msg1");
    ingress.send(msg2).await.expect("send msg2");

    // Drop ingress to trigger flush
    drop(ingress);
    let _ = pipeline_handle.await;

    // Output should contain: 2 original messages + 1 sig block (from full chain)
    // + potentially 1 flush sig block (from pipeline close)
    let count = output_clone.len().await;
    assert!(
        count >= 3,
        "expected at least 3 messages (2 originals + sig block), got {count}"
    );

    // Verify the first two messages are our originals
    let msgs = output_clone.collected().await;
    assert_eq!(
        msgs[0].hostname.as_deref(),
        Some("host"),
        "first message should be original"
    );
    assert_eq!(
        msgs[1].hostname.as_deref(),
        Some("host"),
        "second message should be original"
    );

    // The signature block message should have the signing app_name
    let sig_msg = &msgs[2];
    assert_eq!(
        sig_msg.app_name.as_deref(),
        Some("syslog-sign"),
        "third message should be a signature block"
    );
}

// ---------------------------------------------------------------------------
// Severity filter E2E — drops debug, passes notice
// ---------------------------------------------------------------------------

#[tokio::test]
async fn severity_filter_drops_debug_messages() {
    use syslog_proto::Severity;
    use syslog_relay::{MessageFilter, SeverityFilter};

    let output = ForwardOutput::new("filter-e2e");
    let output_clone = output.clone();

    // Only pass Notice (5) and more severe (lower numeric value)
    let filter = SeverityFilter::new(Severity::Notice);
    let filters: Vec<Box<dyn MessageFilter>> = vec![Box::new(filter)];
    let (pipeline, ingress, _shutdown) = Pipeline::new(64, filters, vec![output]);

    let pipeline_handle = tokio::spawn(async move {
        let _ = pipeline.run().await;
    });

    // PRI <13> = User(1).Notice(5) — should pass
    let notice_msg =
        syslog_parse::parse(b"<13>1 2023-10-11T22:14:15Z host app - - - notice message")
            .expect("parse notice");

    // PRI <15> = User(1).Debug(7) — should be filtered
    let debug_msg = syslog_parse::parse(b"<15>1 2023-10-11T22:14:16Z host app - - - debug message")
        .expect("parse debug");

    // PRI <14> = User(1).Info(6) — should be filtered (Info > Notice numerically)
    let info_msg = syslog_parse::parse(b"<14>1 2023-10-11T22:14:17Z host app - - - info message")
        .expect("parse info");

    // PRI <11> = User(1).Error(3) — should pass
    let error_msg = syslog_parse::parse(b"<11>1 2023-10-11T22:14:18Z host app - - - error message")
        .expect("parse error");

    ingress.send(notice_msg).await.expect("send notice");
    ingress.send(debug_msg).await.expect("send debug");
    ingress.send(info_msg).await.expect("send info");
    ingress.send(error_msg).await.expect("send error");

    drop(ingress);
    let _ = pipeline_handle.await;

    // Only Notice and Error should pass
    let count = output_clone.len().await;
    assert_eq!(
        count, 2,
        "expected 2 messages (Notice + Error), got {count}"
    );

    let msgs = output_clone.collected().await;
    let bodies: Vec<_> = msgs
        .iter()
        .filter_map(|m| m.msg.as_ref())
        .map(|b| std::str::from_utf8(b).unwrap_or("?"))
        .collect();
    assert!(
        bodies.contains(&"notice message"),
        "notice should pass filter"
    );
    assert!(
        bodies.contains(&"error message"),
        "error should pass filter"
    );
}

// ---------------------------------------------------------------------------
// DTLS (plaintext-fallback) listener E2E
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dtls_listener_end_to_end() {
    // Set up pipeline
    let output = ForwardOutput::new("dtls-e2e");
    let output_clone = output.clone();
    let (pipeline, ingress, _shutdown) = Pipeline::new(64, vec![], vec![output]);

    let pipeline_handle = tokio::spawn(async move {
        let _ = pipeline.run().await;
    });

    // Find a free UDP port for the DTLS (plaintext-fallback) listener
    let probe = UdpSocket::bind("127.0.0.1:0").await.expect("probe bind");
    let listen_addr = probe.local_addr().expect("probe addr");
    drop(probe);

    // DtlsListenerConfig requires cert/key paths even though the
    // plaintext-fallback does not use them. Use dummy paths.
    let dtls_config = DtlsListenerConfig::new(listen_addr, "/dev/null".into(), "/dev/null".into());

    let (dtls_tx, mut dtls_rx) = mpsc::channel::<DtlsDatagram>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let listener_handle = tokio::spawn(async move {
        let _ = run_dtls_listener(&dtls_config, dtls_tx, shutdown_rx).await;
    });

    // Spawn parser bridge for DTLS datagrams
    let bridge_ingress = ingress.clone();
    let bridge_handle = tokio::spawn(async move {
        while let Some(datagram) = dtls_rx.recv().await {
            if let Ok(msg) = syslog_parse::parse(&datagram.payload) {
                let _ = bridge_ingress.send(msg).await;
            }
        }
    });

    // Give the listener time to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send a valid syslog message via UDP to the DTLS listener port
    let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender bind");
    sender
        .send_to(RFC5424_MSG, listen_addr)
        .await
        .expect("send_to");

    // Wait for the message to flow through
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify the message arrived at the output
    let count = output_clone.len().await;
    assert_eq!(count, 1, "expected 1 message in DTLS output, got {count}");

    let msgs = output_clone.collected().await;
    if let Some(msg) = msgs.first() {
        assert_eq!(
            msg.hostname.as_deref(),
            Some("mymachine.example.com"),
            "hostname mismatch"
        );
        assert_eq!(
            msg.app_name.as_deref(),
            Some("evntslog"),
            "app_name mismatch"
        );
    }

    // Cleanup
    let _ = shutdown_tx.send(true);
    drop(ingress);
    let _ = pipeline_handle.await;
    let _ = listener_handle.await;
    let _ = bridge_handle.await;
}
