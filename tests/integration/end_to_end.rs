//! End-to-end integration tests.
//!
//! These tests spin up real UDP and TCP listeners, send syslog messages,
//! and verify they flow through parsing and into the pipeline.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

use syslog_relay::{ForwardOutput, Pipeline};
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
