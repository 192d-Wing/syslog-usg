//! Lifecycle integration tests — graceful shutdown, drain timeout,
//! config reload, and signal handling behavior.
//!
//! These tests exercise the operational lifecycle of the syslog pipeline
//! under realistic conditions: shutdown during active ingestion, drain
//! timeout enforcement, config reload with valid and invalid configs,
//! and pipeline ingress draining.

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

use syslog_relay::{ForwardOutput, Pipeline, RelayError, ShutdownHandle};
use syslog_transport::tcp::{TcpListenerConfig, TcpMessage, run_tcp_listener};
use syslog_transport::udp::{UdpDatagram, UdpListenerConfig, run_udp_listener};

// ==========================================================================
// Helpers
// ==========================================================================

/// Send a test message through the pipeline ingress.
async fn send_msg(ingress: &syslog_relay::PipelineIngress, body: &str) {
    let raw = format!("<13>1 2023-10-11T22:14:15Z host app - - - {body}");
    let msg = syslog_parse::parse(raw.as_bytes()).expect("parse test message");
    ingress.send(msg).await.expect("pipeline send");
}

/// Build a pipeline with a ForwardOutput, returning (output, ingress, shutdown, handle).
fn build_pipeline(
    capacity: usize,
) -> (
    ForwardOutput,
    syslog_relay::PipelineIngress,
    ShutdownHandle,
    tokio::task::JoinHandle<Result<(), RelayError>>,
) {
    let output = ForwardOutput::new("lifecycle-test");
    let output_clone = output.clone();
    let (pipeline, ingress, shutdown) = Pipeline::new(capacity, vec![], vec![output]);
    let handle = tokio::spawn(async move { pipeline.run().await });
    (output_clone, ingress, shutdown, handle)
}

// ==========================================================================
// Pipeline ingress drain on shutdown: buffered messages are not lost
// ==========================================================================

#[tokio::test]
async fn pipeline_drains_buffered_messages_on_shutdown() {
    let (output, ingress, shutdown, handle) = build_pipeline(256);

    // Send several messages
    for i in 0..10 {
        send_msg(&ingress, &format!("msg-{i}")).await;
    }

    // Signal shutdown immediately — messages may still be in the channel
    shutdown.shutdown();

    // Wait for pipeline to finish
    let result = handle.await.expect("join pipeline");

    // Pipeline returns Shutdown on graceful shutdown
    assert!(
        matches!(result, Err(RelayError::Shutdown { .. })),
        "expected Shutdown error, got: {result:?}"
    );

    // All 10 messages should have been processed (drained from channel)
    let count = output.len().await;
    assert_eq!(
        count, 10,
        "expected all 10 messages to be drained on shutdown, got {count}"
    );
}

#[tokio::test]
async fn pipeline_drains_ingress_with_small_channel() {
    let (output, ingress, shutdown, handle) = build_pipeline(4);

    // Send messages rapidly to fill the channel
    for i in 0..4 {
        let raw = format!("<13>1 - host app - - - small-{i}");
        let msg = syslog_parse::parse(raw.as_bytes()).expect("parse");
        ingress.send(msg).await.expect("send");
    }

    // Brief yield to let some messages be consumed
    tokio::task::yield_now().await;

    // Signal shutdown
    shutdown.shutdown();

    let result = handle.await.expect("join");
    assert!(matches!(result, Err(RelayError::Shutdown { .. })));

    let count = output.len().await;
    assert_eq!(count, 4, "expected 4 messages after drain, got {count}");
}

// ==========================================================================
// Shutdown via ingress close (drop all senders)
// ==========================================================================

#[tokio::test]
async fn pipeline_stops_when_ingress_dropped() {
    let (output, ingress, _shutdown, handle) = build_pipeline(64);

    send_msg(&ingress, "before-close").await;

    // Drop ingress without signaling shutdown — pipeline should stop via channel close
    drop(ingress);

    let result = handle.await.expect("join pipeline");

    // Ingress close returns Ok, not Shutdown
    assert!(
        result.is_ok(),
        "expected Ok on ingress close, got: {result:?}"
    );

    let count = output.len().await;
    assert_eq!(count, 1, "message sent before close should be delivered");
}

// ==========================================================================
// Shutdown handle dropped without sending true
// ==========================================================================

#[tokio::test]
async fn pipeline_stops_when_shutdown_handle_dropped() {
    let (output, ingress, shutdown, handle) = build_pipeline(64);

    let raw = b"<13>1 - host app - - - test";
    let msg = syslog_parse::parse(raw).expect("parse");
    ingress.send(msg).await.expect("send");

    // Drop both shutdown handle and ingress — pipeline should stop.
    // The order matters: dropping shutdown first causes the watch channel
    // sender to be dropped, which the pipeline detects as a shutdown signal
    // (biased select picks shutdown.changed() Err before ingress close).
    // Dropping ingress first would cause the pipeline to stop via channel
    // close (Ok path). Either way, the pipeline must not hang.
    drop(shutdown);
    drop(ingress);

    let result = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("pipeline should stop within 5s")
        .expect("join");

    // Pipeline stops via either Shutdown (handle dropped) or Ok (ingress closed) —
    // both are valid depending on select ordering.
    assert!(
        result.is_ok() || matches!(result, Err(RelayError::Shutdown { .. })),
        "expected Ok or Shutdown, got: {result:?}"
    );
    assert_eq!(output.len().await, 1);
}

// ==========================================================================
// Drain timeout enforcement: pipeline completes within timeout
// ==========================================================================

#[tokio::test]
async fn drain_timeout_pipeline_completes_within_timeout() {
    let (output, ingress, shutdown, handle) = build_pipeline(64);

    for i in 0..5 {
        send_msg(&ingress, &format!("drain-{i}")).await;
    }

    shutdown.shutdown();

    // Pipeline should complete well within a 5s drain timeout
    let result = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("pipeline should complete within drain timeout")
        .expect("join");

    assert!(matches!(result, Err(RelayError::Shutdown { .. })));
    assert_eq!(output.len().await, 5);
}

// ==========================================================================
// Drain timeout: pipeline abort on stuck task
// ==========================================================================

#[tokio::test]
async fn drain_timeout_aborts_stuck_pipeline() {
    // Simulate a pipeline that blocks indefinitely by never closing ingress
    // and never signaling shutdown
    let output = ForwardOutput::new("stuck");
    let (pipeline, ingress, _shutdown) = Pipeline::new(64, vec![], vec![output]);

    let mut pipeline_handle = tokio::spawn(async move { pipeline.run().await });

    let raw = b"<13>1 - host app - - - test";
    let msg = syslog_parse::parse(raw).expect("parse");
    ingress.send(msg).await.expect("send");

    // Simulate a very short drain timeout (100ms)
    let result = tokio::select! {
        r = &mut pipeline_handle => {
            Some(r.expect("join"))
        }
        _ = tokio::time::sleep(Duration::from_millis(100)) => {
            // Drain timeout expired — abort
            pipeline_handle.abort();
            let _ = pipeline_handle.await;
            None
        }
    };

    // We should have hit the timeout and aborted
    assert!(
        result.is_none(),
        "pipeline should not have completed voluntarily"
    );
}

// ==========================================================================
// Shutdown during active UDP ingestion
// ==========================================================================

#[tokio::test]
async fn shutdown_during_active_udp_ingestion() {
    let output = ForwardOutput::new("udp-shutdown");
    let output_clone = output.clone();
    let (pipeline, ingress, pipeline_shutdown) = Pipeline::new(256, vec![], vec![output]);

    let pipeline_handle = tokio::spawn(async move {
        let _ = pipeline.run().await;
    });

    // Start UDP listener
    let probe = UdpSocket::bind("127.0.0.1:0").await.expect("probe");
    let listen_addr = probe.local_addr().expect("addr");
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

    // Start sending messages
    let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
    for i in 0..20 {
        let msg = format!("<13>1 - host app - - - udp-msg-{i}");
        let _ = sender.send_to(msg.as_bytes(), listen_addr).await;
    }

    // Brief delay to let some messages flow through
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Initiate shutdown while messages may still be in flight
    let _ = shutdown_tx.send(true);
    pipeline_shutdown.shutdown();
    drop(ingress);

    // All handles should complete within timeout (no hang)
    let timeout_result = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = pipeline_handle.await;
        let _ = listener_handle.await;
        let _ = bridge_handle.await;
    })
    .await;

    assert!(
        timeout_result.is_ok(),
        "shutdown should complete within 5 seconds"
    );

    // Some messages should have been processed (exact count depends on timing)
    let count = output_clone.len().await;
    assert!(count > 0, "at least some messages should be processed");
}

// ==========================================================================
// Shutdown during active TCP ingestion with open connections
// ==========================================================================

#[tokio::test]
async fn shutdown_during_active_tcp_ingestion() {
    let output = ForwardOutput::new("tcp-shutdown");
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
        max_connections: None,
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

    // Open a TCP connection and send messages
    let mut stream = tokio::net::TcpStream::connect(listen_addr)
        .await
        .expect("TCP connect");

    for i in 0..10 {
        let msg = format!("<13>1 - host app - - - tcp-msg-{i}");
        let header = format!("{} ", msg.len());
        stream.write_all(header.as_bytes()).await.expect("header");
        stream.write_all(msg.as_bytes()).await.expect("body");
    }
    stream.flush().await.expect("flush");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Shutdown while connection is still open
    let _ = shutdown_tx.send(true);
    pipeline_shutdown.shutdown();
    drop(ingress);
    drop(stream);

    // Should complete without hanging
    let timeout_result = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = pipeline_handle.await;
        let _ = listener_handle.await;
        let _ = bridge_handle.await;
    })
    .await;

    assert!(
        timeout_result.is_ok(),
        "TCP shutdown should complete within 5 seconds"
    );

    let count = output_clone.len().await;
    assert_eq!(
        count, 10,
        "all 10 TCP messages should be processed, got {count}"
    );
}

// ==========================================================================
// Multiple rapid shutdown signals (idempotent)
// ==========================================================================

#[tokio::test]
async fn rapid_shutdown_signals_are_idempotent() {
    let (output, ingress, shutdown, handle) = build_pipeline(64);

    send_msg(&ingress, "before-signals").await;

    // Send shutdown multiple times rapidly
    shutdown.shutdown();
    shutdown.shutdown();
    shutdown.shutdown();

    // Pipeline should still complete cleanly
    let result = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("pipeline should stop within 5s")
        .expect("join");

    assert!(matches!(result, Err(RelayError::Shutdown { .. })));
    assert_eq!(output.len().await, 1);
}

// ==========================================================================
// Shutdown with empty pipeline (no messages sent)
// ==========================================================================

#[tokio::test]
async fn shutdown_with_no_messages() {
    let (output, _ingress, shutdown, handle) = build_pipeline(64);

    shutdown.shutdown();

    let result = tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("pipeline should stop within 5s")
        .expect("join");

    assert!(matches!(result, Err(RelayError::Shutdown { .. })));
    assert_eq!(output.len().await, 0);
}

// ==========================================================================
// Config reload: valid config produces no error
// ==========================================================================

#[test]
fn reload_valid_config_from_string() {
    let toml = r#"
[server]
drain_timeout_seconds = 10

[logging]
level = "debug"

[metrics]
enabled = false
"#;
    let result = syslog_config::load_config_str(toml);
    assert!(result.is_ok(), "valid config should load: {result:?}");

    let config = result.expect("valid");
    assert_eq!(config.server.drain_timeout_seconds, 10);
    assert_eq!(config.logging.level, "debug");
}

// ==========================================================================
// Config reload: malformed TOML is rejected without crash
// ==========================================================================

#[test]
fn reload_malformed_toml_returns_error() {
    let bad_toml = r#"
[server
drain_timeout = invalid
"#;
    let result = syslog_config::load_config_str(bad_toml);
    assert!(result.is_err(), "malformed TOML should fail");
}

// ==========================================================================
// Config reload: semantically invalid config is rejected
// ==========================================================================

#[test]
fn reload_invalid_config_returns_error() {
    // TLS listener without required TLS config should fail validation
    let toml = r#"
[[listeners]]
protocol = "tls"
bind_address = "0.0.0.0:6514"
"#;
    let result = syslog_config::load_config_str(toml);
    assert!(
        result.is_err(),
        "TLS listener without TLS config should be rejected"
    );
}

// ==========================================================================
// Config reload: file not found is handled gracefully
// ==========================================================================

#[test]
fn reload_missing_config_file_returns_error() {
    let result = syslog_config::load_config(std::path::Path::new("/nonexistent/config.toml"));
    assert!(result.is_err(), "missing config file should return error");
}

// ==========================================================================
// Config reload: valid config with changed log level
// ==========================================================================

#[test]
fn config_detects_log_level_change() {
    let config_a = syslog_config::load_config_str(
        r#"
[logging]
level = "info"
"#,
    )
    .expect("config_a");

    let config_b = syslog_config::load_config_str(
        r#"
[logging]
level = "debug"
"#,
    )
    .expect("config_b");

    // Log level differs
    assert_ne!(config_a.logging.level, config_b.logging.level);

    // Other fields should be equal (defaults)
    assert_eq!(config_a.server, config_b.server);
    assert_eq!(config_a.listeners, config_b.listeners);
    assert_eq!(config_a.outputs, config_b.outputs);
}

// ==========================================================================
// Config reload: detect restart-required changes
// ==========================================================================

#[test]
fn config_detects_listener_changes() {
    let config_a = syslog_config::load_config_str(
        r#"
[[listeners]]
protocol = "udp"
bind_address = "0.0.0.0:514"
"#,
    )
    .expect("config_a");

    let config_b = syslog_config::load_config_str(
        r#"
[[listeners]]
protocol = "udp"
bind_address = "0.0.0.0:1514"
"#,
    )
    .expect("config_b");

    assert_ne!(
        config_a.listeners, config_b.listeners,
        "listener changes should be detected"
    );
}

// ==========================================================================
// Pipeline: concurrent ingress and shutdown (no deadlock)
// ==========================================================================

#[tokio::test]
async fn concurrent_ingress_and_shutdown_no_deadlock() {
    let output = ForwardOutput::new("concurrent");
    let output_clone = output.clone();
    let (pipeline, ingress, shutdown) = Pipeline::new(16, vec![], vec![output]);

    let pipeline_handle = tokio::spawn(async move { pipeline.run().await });

    // Spawn a task that continuously sends messages
    let sender_ingress = ingress.clone();
    let sender_handle = tokio::spawn(async move {
        for i in 0..100 {
            let raw = format!("<13>1 - host app - - - concurrent-{i}");
            let msg = match syslog_parse::parse(raw.as_bytes()) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if sender_ingress.send(msg).await.is_err() {
                break; // Pipeline closed
            }
            tokio::task::yield_now().await;
        }
    });

    // Let some messages flow
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Signal shutdown while sender is still active
    shutdown.shutdown();
    drop(ingress);

    // Everything should complete within 5 seconds (no deadlock)
    let timeout_result = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = sender_handle.await;
        let _ = pipeline_handle.await;
    })
    .await;

    assert!(
        timeout_result.is_ok(),
        "concurrent ingress + shutdown must not deadlock"
    );

    // At least some messages should have been processed
    let count = output_clone.len().await;
    assert!(
        count > 0,
        "at least some messages should be processed, got {count}"
    );
}

// ==========================================================================
// Listener shutdown: UDP listener stops accepting after shutdown signal
// ==========================================================================

#[tokio::test]
async fn udp_listener_stops_after_shutdown() {
    let probe = UdpSocket::bind("127.0.0.1:0").await.expect("probe");
    let listen_addr = probe.local_addr().expect("addr");
    drop(probe);

    let udp_config = UdpListenerConfig {
        bind_addr: listen_addr,
        ..Default::default()
    };

    let (udp_tx, _udp_rx) = mpsc::channel::<UdpDatagram>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let listener_handle = tokio::spawn(async move {
        let _ = run_udp_listener(udp_config, udp_tx, shutdown_rx).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send shutdown
    let _ = shutdown_tx.send(true);

    // Listener should stop within a reasonable time
    let result = tokio::time::timeout(Duration::from_secs(5), listener_handle).await;
    assert!(result.is_ok(), "UDP listener should stop within 5 seconds");
}

// ==========================================================================
// Listener shutdown: TCP listener stops accepting after shutdown signal
// ==========================================================================

#[tokio::test]
async fn tcp_listener_stops_after_shutdown() {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let listen_addr = probe.local_addr().expect("addr");
    drop(probe);

    let tcp_config = TcpListenerConfig {
        bind_addr: listen_addr,
        max_frame_size: 64 * 1024,
        tls_acceptor: None,
        max_connections: None,
        max_connections_per_ip: None,
        read_timeout: Some(Duration::from_secs(5)),
        idle_timeout: Some(Duration::from_secs(10)),
        allowed_sources: std::collections::HashSet::new(),
        use_lf_framing: false,
    };

    let (tcp_tx, _tcp_rx) = mpsc::channel::<TcpMessage>(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let listener_handle = tokio::spawn(async move {
        let _ = run_tcp_listener(tcp_config, tcp_tx, shutdown_rx).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send shutdown
    let _ = shutdown_tx.send(true);

    // Listener should stop within a reasonable time
    let result = tokio::time::timeout(Duration::from_secs(5), listener_handle).await;
    assert!(result.is_ok(), "TCP listener should stop within 5 seconds");
}

// ==========================================================================
// Full lifecycle: start → ingest → shutdown → drain → complete
// ==========================================================================

#[tokio::test]
async fn full_lifecycle_udp_start_ingest_shutdown_drain() {
    // 1. Build pipeline
    let output = ForwardOutput::new("lifecycle");
    let output_clone = output.clone();
    let (pipeline, ingress, pipeline_shutdown) = Pipeline::new(256, vec![], vec![output]);

    let pipeline_handle = tokio::spawn(async move { pipeline.run().await });

    // 2. Start UDP listener
    let probe = UdpSocket::bind("127.0.0.1:0").await.expect("probe");
    let listen_addr = probe.local_addr().expect("addr");
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

    // 3. Wait for listener to be ready
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. Send messages
    let sender = UdpSocket::bind("127.0.0.1:0").await.expect("sender");
    let msg_count = 15;
    for i in 0..msg_count {
        let msg = format!("<13>1 - host app - - - lifecycle-msg-{i}");
        sender
            .send_to(msg.as_bytes(), listen_addr)
            .await
            .expect("send");
    }

    // 5. Wait for messages to flow through
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 6. Initiate graceful shutdown (same sequence as main.rs)
    let _ = shutdown_tx.send(true);
    pipeline_shutdown.shutdown();
    drop(ingress);

    // 7. Wait for all handles with drain timeout
    let drain_timeout = Duration::from_secs(5);
    let drain_result = tokio::time::timeout(drain_timeout, async {
        let _ = pipeline_handle.await;
        let _ = listener_handle.await;
        let _ = bridge_handle.await;
    })
    .await;

    assert!(
        drain_result.is_ok(),
        "full lifecycle shutdown should complete within drain timeout"
    );

    // 8. Verify all messages were processed
    let count = output_clone.len().await;
    assert_eq!(
        count, msg_count,
        "expected {msg_count} messages after full lifecycle, got {count}"
    );
}

// ==========================================================================
// Full lifecycle: TCP start → ingest → shutdown → drain
// ==========================================================================

#[tokio::test]
async fn full_lifecycle_tcp_start_ingest_shutdown_drain() {
    let output = ForwardOutput::new("tcp-lifecycle");
    let output_clone = output.clone();
    let (pipeline, ingress, pipeline_shutdown) = Pipeline::new(256, vec![], vec![output]);

    let pipeline_handle = tokio::spawn(async move { pipeline.run().await });

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let listen_addr = probe.local_addr().expect("addr");
    drop(probe);

    let tcp_config = TcpListenerConfig {
        bind_addr: listen_addr,
        max_frame_size: 64 * 1024,
        tls_acceptor: None,
        max_connections: None,
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

    // Send 10 TCP messages
    let mut stream = tokio::net::TcpStream::connect(listen_addr)
        .await
        .expect("connect");

    let msg_count = 10;
    for i in 0..msg_count {
        let msg = format!("<13>1 - host app - - - tcp-lifecycle-{i}");
        let header = format!("{} ", msg.len());
        stream.write_all(header.as_bytes()).await.expect("header");
        stream.write_all(msg.as_bytes()).await.expect("body");
    }
    stream.flush().await.expect("flush");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Shutdown
    drop(stream);
    let _ = shutdown_tx.send(true);
    pipeline_shutdown.shutdown();
    drop(ingress);

    let drain_result = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = pipeline_handle.await;
        let _ = listener_handle.await;
        let _ = bridge_handle.await;
    })
    .await;

    assert!(
        drain_result.is_ok(),
        "TCP lifecycle should complete within drain timeout"
    );

    let count = output_clone.len().await;
    assert_eq!(
        count, msg_count,
        "expected {msg_count} TCP messages, got {count}"
    );
}

// ==========================================================================
// Pipeline with filter: filtered messages don't block shutdown
// ==========================================================================

#[tokio::test]
async fn filtered_messages_dont_block_shutdown() {
    use syslog_proto::Severity;
    use syslog_relay::{MessageFilter, SeverityFilter};

    let output = ForwardOutput::new("filter-shutdown");
    let output_clone = output.clone();

    // Only pass Warning and above
    let filter = SeverityFilter::new(Severity::Warning);
    let filters: Vec<Box<dyn MessageFilter>> = vec![Box::new(filter)];
    let (pipeline, ingress, shutdown) = Pipeline::new(64, filters, vec![output]);

    let pipeline_handle = tokio::spawn(async move { pipeline.run().await });

    // Send a mix of messages: some will be filtered, some won't
    for i in 0..5 {
        // Debug (7) — will be filtered
        let raw = format!("<15>1 - host app - - - debug-{i}");
        let msg = syslog_parse::parse(raw.as_bytes()).expect("parse");
        ingress.send(msg).await.expect("send");
    }
    for i in 0..3 {
        // Error (3) — will pass
        let raw = format!("<11>1 - host app - - - error-{i}");
        let msg = syslog_parse::parse(raw.as_bytes()).expect("parse");
        ingress.send(msg).await.expect("send");
    }

    shutdown.shutdown();

    let result = tokio::time::timeout(Duration::from_secs(5), pipeline_handle)
        .await
        .expect("should complete within 5s")
        .expect("join");

    assert!(matches!(result, Err(RelayError::Shutdown { .. })));
    assert_eq!(
        output_clone.len().await,
        3,
        "only 3 Error messages should pass the filter"
    );
}

// ==========================================================================
// Config reload: reload preserves defaults for missing fields
// ==========================================================================

#[test]
fn reload_minimal_config_uses_defaults() {
    let config = syslog_config::load_config_str("").expect("empty config should use defaults");

    assert_eq!(config.server.drain_timeout_seconds, 5);
    assert_eq!(config.logging.level, "info");
    assert!(config.listeners.is_empty());
    assert!(config.outputs.is_empty());
}

// ==========================================================================
// Config reload: drain_timeout_seconds is respected
// ==========================================================================

#[test]
fn reload_custom_drain_timeout() {
    let toml = r#"
[server]
drain_timeout_seconds = 30
"#;
    let config = syslog_config::load_config_str(toml).expect("valid config");
    assert_eq!(config.server.drain_timeout_seconds, 30);
}

// ==========================================================================
// SIGHUP: reload_config function test (unit-level, no actual signal)
// ==========================================================================

#[test]
fn reload_config_file_on_disk() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let config_path = dir.path().join("test-config.toml");

    // Write initial config
    std::fs::write(
        &config_path,
        r#"
[logging]
level = "info"

[server]
drain_timeout_seconds = 5
"#,
    )
    .expect("write initial config");

    let config = syslog_config::load_config(&config_path).expect("load initial");
    assert_eq!(config.logging.level, "info");

    // Write updated config (simulating what SIGHUP would re-read)
    std::fs::write(
        &config_path,
        r#"
[logging]
level = "debug"

[server]
drain_timeout_seconds = 10
"#,
    )
    .expect("write updated config");

    let updated = syslog_config::load_config(&config_path).expect("load updated");
    assert_eq!(updated.logging.level, "debug");
    assert_eq!(updated.server.drain_timeout_seconds, 10);

    // Verify change detection
    assert_ne!(config.logging.level, updated.logging.level);
    assert_ne!(config.server, updated.server);
}

#[test]
fn reload_config_invalid_file_on_disk() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let config_path = dir.path().join("bad-config.toml");

    // Write invalid TOML
    std::fs::write(&config_path, "this is not valid [[[toml").expect("write");

    let result = syslog_config::load_config(&config_path);
    assert!(result.is_err(), "invalid config file should return error");
}

// ==========================================================================
// Rapid config reloads: repeated valid loads don't accumulate errors
// ==========================================================================

#[test]
fn rapid_config_reloads_stable() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let config_path = dir.path().join("rapid-reload.toml");

    let levels = ["debug", "info", "warn", "error", "trace"];

    for (i, level) in levels.iter().enumerate() {
        std::fs::write(
            &config_path,
            format!(
                r#"
[logging]
level = "{level}"

[server]
drain_timeout_seconds = {drain}
"#,
                drain = 5 + i
            ),
        )
        .expect("write config");

        let config = syslog_config::load_config(&config_path).expect("load config");
        assert_eq!(config.logging.level, *level);
        assert_eq!(config.server.drain_timeout_seconds, (5 + i) as u64);
    }
}
