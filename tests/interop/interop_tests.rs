//! Interoperability tests with real syslog senders (rsyslog, syslog-ng).
//!
//! These tests launch Docker containers running real rsyslog or syslog-ng
//! instances, have them send syslog messages to the Rust server's listeners,
//! and verify that messages are correctly received, parsed, and processed.
//!
//! # Requirements
//! - Docker must be available on the test host
//! - Tests are skipped gracefully if Docker is unavailable
//!
//! # Running
//! ```sh
//! # Run all interop tests (requires Docker with host networking):
//! cargo test -p syslog-interop-tests -- --ignored
//!
//! # On Linux, set INTEROP_DOCKER_HOST=127.0.0.1 with --network=host containers.
//! # On macOS Docker Desktop, host.docker.internal is used by default.
//! ```

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

use syslog_proto::{Facility, Severity, SyslogMessage};
use syslog_relay::{ForwardOutput, Pipeline};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const RSYSLOG_IMAGE: &str = "syslog-interop-rsyslog";
const SYSLOG_NG_IMAGE: &str = "syslog-interop-syslog-ng";

/// How long to wait for the sender daemon to start and forward messages.
const SENDER_SETTLE_MS: u64 = 2000;

/// Docker host address that containers use to reach the host.
/// On macOS Docker Desktop this is `host.docker.internal`.
/// On Linux with `--network=host`, use `127.0.0.1`.
fn docker_host() -> String {
    std::env::var("INTEROP_DOCKER_HOST").unwrap_or_else(|_| "host.docker.internal".to_string())
}

// ---------------------------------------------------------------------------
// Docker helpers
// ---------------------------------------------------------------------------

/// Returns true if Docker is available and responsive.
fn docker_available() -> bool {
    Command::new("docker")
        .args(["info"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Build a Docker image from a Dockerfile path. Returns true on success.
fn build_image(name: &str, dockerfile_dir: &Path) -> bool {
    let status = Command::new("docker")
        .args(["build", "-t", name, "."])
        .current_dir(dockerfile_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status();
    match status {
        Ok(s) => s.success(),
        Err(_) => false,
    }
}

/// Run a sender container with a mounted config file.
/// Returns the container ID on success.
fn run_sender_container(image: &str, config_path: &Path, mount_target: &str) -> Option<String> {
    let output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "-v",
            &format!("{}:{}", config_path.display(), mount_target),
        ])
        .arg(image)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("Failed to start container: {stderr}");
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Execute `logger` inside a running container to inject a syslog message.
fn docker_exec_logger(container_id: &str, tag: &str, message: &str) -> bool {
    let status = Command::new("docker")
        .args([
            "exec",
            container_id,
            "logger",
            "-t",
            tag,
            "-p",
            "local0.info",
            message,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    matches!(status, Ok(s) if s.success())
}

/// Execute `logger` with a specific priority and structured data tag.
fn docker_exec_logger_full(container_id: &str, tag: &str, priority: &str, message: &str) -> bool {
    let status = Command::new("docker")
        .args([
            "exec",
            container_id,
            "logger",
            "-t",
            tag,
            "-p",
            priority,
            message,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    matches!(status, Ok(s) if s.success())
}

/// Stop and remove a container.
fn stop_container(container_id: &str) {
    let _ = Command::new("docker")
        .args(["stop", "-t", "2", container_id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Write a config template to a temp file, substituting __TARGET_HOST__ and __TARGET_PORT__.
fn render_config(template_path: &Path, host: &str, port: u16) -> tempfile::NamedTempFile {
    let template = std::fs::read_to_string(template_path)
        .unwrap_or_else(|e| panic!("read config template {}: {e}", template_path.display()));
    let rendered = template
        .replace("__TARGET_HOST__", host)
        .replace("__TARGET_PORT__", &port.to_string());
    let mut tmp = tempfile::Builder::new()
        .suffix(".conf")
        .tempfile()
        .expect("create temp config");
    tmp.write_all(rendered.as_bytes())
        .expect("write temp config");
    tmp.flush().expect("flush temp config");
    tmp
}

/// Fixtures directory for the given sender.
fn fixtures_dir(sender: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(sender)
}

// ---------------------------------------------------------------------------
// Test harness: shared listener + pipeline setup
// ---------------------------------------------------------------------------

struct UdpInteropHarness {
    listen_addr: SocketAddr,
    output: ForwardOutput,
    _pipeline_handle: tokio::task::JoinHandle<()>,
    _pipeline_shutdown: syslog_relay::ShutdownHandle,
    _recv_handle: tokio::task::JoinHandle<()>,
    _bridge_handle: tokio::task::JoinHandle<()>,
    shutdown_tx: watch::Sender<bool>,
}

impl UdpInteropHarness {
    async fn new() -> Self {
        let output = ForwardOutput::new("interop-test");
        let output_clone = output.clone();
        let (pipeline, ingress, pipeline_shutdown) = Pipeline::new(256, vec![], vec![output]);

        let pipeline_handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        // Bind directly — no probe-drop-rebind. This socket stays open.
        let socket = std::sync::Arc::new(UdpSocket::bind("0.0.0.0:0").await.expect("bind UDP"));
        let listen_addr = socket.local_addr().expect("local_addr");

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        // Simple receive loop (replaces run_udp_listener for interop tests)
        let recv_socket = socket.clone();
        let (msg_tx, mut msg_rx) = mpsc::channel::<bytes::Bytes>(256);
        let recv_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    result = recv_socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, _src)) => {
                                let data = bytes::Bytes::copy_from_slice(&buf[..len]);
                                if msg_tx.send(data).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        break;
                    }
                }
            }
        });

        // Parser bridge
        let bridge_ingress = ingress.clone();
        let bridge_handle = tokio::spawn(async move {
            while let Some(data) = msg_rx.recv().await {
                if let Ok(msg) = syslog_parse::parse(&data) {
                    let _ = bridge_ingress.send(msg).await;
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        Self {
            listen_addr,
            output: output_clone,
            _pipeline_handle: pipeline_handle,
            _pipeline_shutdown: pipeline_shutdown,
            _recv_handle: recv_handle,
            _bridge_handle: bridge_handle,
            shutdown_tx,
        }
    }

    async fn collected(&self) -> Vec<SyslogMessage> {
        self.output.collected().await
    }

    async fn message_count(&self) -> usize {
        self.output.len().await
    }

    fn port(&self) -> u16 {
        self.listen_addr.port()
    }

    fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
    }
}

struct TcpInteropHarness {
    listen_addr: SocketAddr,
    output: ForwardOutput,
    _pipeline_handle: tokio::task::JoinHandle<()>,
    _pipeline_shutdown: syslog_relay::ShutdownHandle,
    _listener_handle: tokio::task::JoinHandle<()>,
    _bridge_handle: tokio::task::JoinHandle<()>,
    shutdown_tx: watch::Sender<bool>,
}

impl TcpInteropHarness {
    async fn new(use_lf_framing: bool) -> Self {
        let output = ForwardOutput::new("interop-test");
        let output_clone = output.clone();
        let (pipeline, ingress, pipeline_shutdown) = Pipeline::new(256, vec![], vec![output]);

        let pipeline_handle = tokio::spawn(async move {
            let _ = pipeline.run().await;
        });

        // Bind directly — no probe-drop-rebind. Keep the listener open.
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
            .await
            .expect("bind TCP");
        let listen_addr = listener.local_addr().expect("local_addr");

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let (frame_tx, mut frame_rx) = mpsc::channel::<bytes::Bytes>(256);

        // Accept connections and decode frames with the appropriate codec
        let listener_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _peer)) => {
                                let tx = frame_tx.clone();
                                let lf = use_lf_framing;
                                tokio::spawn(async move {
                                    use tokio_util::codec::FramedRead;
                                    use syslog_transport::{OctetCountingCodec, LfDelimitedCodec, SyslogCodec};
                                    use tokio_stream::StreamExt;
                                    let codec = if lf {
                                        SyslogCodec::LfDelimited(LfDelimitedCodec::with_max_frame_size(64 * 1024))
                                    } else {
                                        SyslogCodec::OctetCounting(OctetCountingCodec::with_max_frame_size(64 * 1024))
                                    };
                                    let mut framed = FramedRead::new(stream, codec);
                                    while let Some(Ok(frame)) = StreamExt::next(&mut framed).await {
                                        let data: bytes::Bytes = frame.freeze();
                                        if tx.send(data).await.is_err() {
                                            break;
                                        }
                                    }
                                });
                            }
                            Err(_) => break,
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        break;
                    }
                }
            }
        });

        // Parser bridge
        let bridge_ingress = ingress.clone();
        let bridge_handle = tokio::spawn(async move {
            while let Some(data) = frame_rx.recv().await {
                if let Ok(msg) = syslog_parse::parse(&data) {
                    let _ = bridge_ingress.send(msg).await;
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        Self {
            listen_addr,
            output: output_clone,
            _pipeline_handle: pipeline_handle,
            _pipeline_shutdown: pipeline_shutdown,
            _listener_handle: listener_handle,
            _bridge_handle: bridge_handle,
            shutdown_tx,
        }
    }

    async fn collected(&self) -> Vec<SyslogMessage> {
        self.output.collected().await
    }

    async fn message_count(&self) -> usize {
        self.output.len().await
    }

    fn port(&self) -> u16 {
        self.listen_addr.port()
    }

    fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
    }
}

// ---------------------------------------------------------------------------
// Docker image build guard — build once, reuse across tests
// ---------------------------------------------------------------------------

use std::sync::Once;

static BUILD_RSYSLOG: Once = Once::new();
static BUILD_SYSLOG_NG: Once = Once::new();

fn ensure_rsyslog_image() -> bool {
    let mut ok = false;
    BUILD_RSYSLOG.call_once(|| {
        ok = build_image(RSYSLOG_IMAGE, &fixtures_dir("rsyslog"));
        if !ok {
            eprintln!("WARNING: failed to build rsyslog Docker image");
        }
    });
    // After Once::call_once, check if image exists
    if !ok {
        // The image may have been built in a previous call_once
        let output = Command::new("docker")
            .args(["image", "inspect", RSYSLOG_IMAGE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        return matches!(output, Ok(s) if s.success());
    }
    ok
}

fn ensure_syslog_ng_image() -> bool {
    let mut ok = false;
    BUILD_SYSLOG_NG.call_once(|| {
        ok = build_image(SYSLOG_NG_IMAGE, &fixtures_dir("syslog-ng"));
        if !ok {
            eprintln!("WARNING: failed to build syslog-ng Docker image");
        }
    });
    if !ok {
        let output = Command::new("docker")
            .args(["image", "inspect", SYSLOG_NG_IMAGE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        return matches!(output, Ok(s) if s.success());
    }
    ok
}

/// Skip the test if Docker is not available.
macro_rules! require_docker {
    () => {
        if !docker_available() {
            eprintln!("SKIPPED: Docker is not available");
            return;
        }
    };
}

/// Skip if the rsyslog image can't be built.
macro_rules! require_rsyslog {
    () => {
        require_docker!();
        if !ensure_rsyslog_image() {
            eprintln!("SKIPPED: rsyslog Docker image could not be built");
            return;
        }
    };
}

/// Skip if the syslog-ng image can't be built.
macro_rules! require_syslog_ng {
    () => {
        require_docker!();
        if !ensure_syslog_ng_image() {
            eprintln!("SKIPPED: syslog-ng Docker image could not be built");
            return;
        }
    };
}

/// RAII guard that stops a container on drop.
struct ContainerGuard {
    id: String,
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        stop_container(&self.id);
    }
}

/// Wait for messages to arrive, with a bounded retry loop.
async fn wait_for_messages(output: &ForwardOutput, expected: usize, timeout_ms: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    while tokio::time::Instant::now() < deadline {
        if output.len().await >= expected {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

// ===========================================================================
// rsyslog interop tests
// ===========================================================================

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn rsyslog_rfc5424_over_udp() {
    require_rsyslog!();
    let harness = UdpInteropHarness::new().await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("rsyslog").join("rsyslog-udp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(RSYSLOG_IMAGE, config.path(), "/etc/rsyslog.conf")
        .expect("start rsyslog container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    // Let rsyslog start (it sends startup messages we don't care about)
    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    // Inject test messages via logger
    assert!(docker_exec_logger(
        &container_id,
        "interop-test",
        "rsyslog UDP RFC5424 test message"
    ));
    assert!(docker_exec_logger_full(
        &container_id,
        "auth-test",
        "auth.warning",
        "authentication warning from rsyslog"
    ));

    // Wait for 2 NEW messages beyond the startup baseline
    let received = wait_for_messages(&harness.output, baseline + 2, 5000).await;
    assert!(
        received,
        "expected at least {} messages, got {}",
        baseline + 2,
        harness.message_count().await
    );

    let msgs = harness.collected().await;

    // Verify at least one message has expected properties
    let test_msg = msgs.iter().find(|m| {
        m.msg.as_ref().is_some_and(|b| {
            String::from_utf8_lossy(b).contains("rsyslog UDP RFC5424 test message")
        })
    });
    assert!(
        test_msg.is_some(),
        "test message not found in collected messages"
    );
    let msg = test_msg.unwrap();

    // rsyslog sends RFC 5424 version 1
    assert_eq!(msg.version, 1, "expected RFC 5424 version 1");
    // Facility local0 = 16
    assert_eq!(msg.facility, Facility::Local0, "expected local0 facility");
    // Severity info = 6
    assert_eq!(
        msg.severity,
        Severity::Informational,
        "expected info severity"
    );
    // Hostname should be set
    assert!(msg.hostname.is_some(), "hostname should be present");
    // App-name should match the logger tag
    assert_eq!(
        msg.app_name.as_deref(),
        Some("interop-test"),
        "app_name should match logger tag"
    );

    // Check the auth.warning message
    let auth_msg = msgs.iter().find(|m| {
        m.msg.as_ref().is_some_and(|b| {
            String::from_utf8_lossy(b).contains("authentication warning from rsyslog")
        })
    });
    assert!(auth_msg.is_some(), "auth warning message not found");
    let auth = auth_msg.unwrap();
    assert_eq!(auth.facility, Facility::Auth, "expected auth facility");
    assert_eq!(
        auth.severity,
        Severity::Warning,
        "expected warning severity"
    );
    assert_eq!(auth.app_name.as_deref(), Some("auth-test"));

    harness.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn rsyslog_rfc5424_over_tcp() {
    require_rsyslog!();
    // rsyslog with TCP_Framing="octet-counted" uses octet-counting
    let harness = TcpInteropHarness::new(false).await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("rsyslog").join("rsyslog-tcp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(RSYSLOG_IMAGE, config.path(), "/etc/rsyslog.conf")
        .expect("start rsyslog container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    // Send messages
    assert!(docker_exec_logger(
        &container_id,
        "tcp-test",
        "rsyslog TCP octet-counted message 1"
    ));
    assert!(docker_exec_logger(
        &container_id,
        "tcp-test",
        "rsyslog TCP octet-counted message 2"
    ));
    assert!(docker_exec_logger(
        &container_id,
        "tcp-test",
        "rsyslog TCP octet-counted message 3"
    ));

    let received = wait_for_messages(&harness.output, baseline + 3, 5000).await;
    assert!(
        received,
        "expected at least {} messages, got {}",
        baseline + 3,
        harness.message_count().await
    );

    let msgs = harness.collected().await;

    // Verify all messages arrived and were parsed as RFC 5424
    for msg in &msgs {
        if msg.app_name.as_deref() == Some("tcp-test") {
            assert_eq!(msg.version, 1, "RFC 5424 version");
            assert_eq!(msg.facility, Facility::Local0);
            assert!(msg.hostname.is_some());
            assert!(msg.msg.is_some());
        }
    }

    // Verify ordering — messages from a single TCP stream should be in order
    let tcp_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.app_name.as_deref() == Some("tcp-test"))
        .collect();
    assert!(tcp_msgs.len() >= 3, "expected at least 3 tcp-test messages");

    // Check message bodies are in order
    let bodies: Vec<String> = tcp_msgs
        .iter()
        .filter_map(|m| {
            m.msg
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).to_string())
        })
        .collect();
    for (i, body) in bodies.iter().enumerate() {
        assert!(
            body.contains(&format!("message {}", i + 1)),
            "message {i} out of order or missing: {body}"
        );
    }

    harness.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn rsyslog_rfc3164_over_tcp() {
    require_rsyslog!();
    // RFC 3164 traditional format — rsyslog sends with octet-counting framing
    let harness = TcpInteropHarness::new(false).await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("rsyslog").join("rsyslog-tcp-3164.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(RSYSLOG_IMAGE, config.path(), "/etc/rsyslog.conf")
        .expect("start rsyslog container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    assert!(docker_exec_logger(
        &container_id,
        "legacy-test",
        "rsyslog RFC3164 legacy message"
    ));

    let received = wait_for_messages(&harness.output, baseline + 1, 5000).await;
    assert!(
        received,
        "expected at least {} messages, got {}",
        baseline + 1,
        harness.message_count().await
    );

    let msgs = harness.collected().await;
    let legacy_msg = msgs.iter().find(|m| {
        m.msg
            .as_ref()
            .is_some_and(|b| String::from_utf8_lossy(b).contains("rsyslog RFC3164 legacy message"))
    });
    assert!(legacy_msg.is_some(), "legacy message not found");

    // RFC 3164 messages parsed via auto-detect should still have basic fields
    let msg = legacy_msg.unwrap();
    assert!(
        msg.hostname.is_some(),
        "hostname should be extracted from 3164 header"
    );
    // The parser may set version to 0 for 3164 messages
    // Facility and severity should still be correct
    assert_eq!(msg.facility, Facility::Local0);
    assert_eq!(msg.severity, Severity::Informational);

    harness.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn rsyslog_burst_traffic() {
    require_rsyslog!();
    let harness = UdpInteropHarness::new().await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("rsyslog").join("rsyslog-udp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(RSYSLOG_IMAGE, config.path(), "/etc/rsyslog.conf")
        .expect("start rsyslog container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    // Send 20 messages in rapid succession
    let msg_count = 20;
    for i in 0..msg_count {
        assert!(docker_exec_logger(
            &container_id,
            "burst-test",
            &format!("burst message {i:03}"),
        ));
    }

    // Wait for all messages — UDP may lose some, so we accept a threshold
    let received = wait_for_messages(&harness.output, baseline + msg_count / 2, 10000).await;
    let actual = harness.message_count().await;
    assert!(
        received,
        "expected at least {} messages, got {actual}",
        baseline + msg_count / 2
    );

    // Verify the ones we did get are well-formed
    let msgs = harness.collected().await;
    let burst_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.app_name.as_deref() == Some("burst-test"))
        .collect();

    for msg in &burst_msgs {
        assert_eq!(msg.version, 1);
        assert_eq!(msg.facility, Facility::Local0);
        assert_eq!(msg.severity, Severity::Informational);
        assert!(msg.hostname.is_some());
        assert!(msg.msg.is_some());
    }

    eprintln!(
        "rsyslog burst: sent {msg_count}, received {} ({:.0}% delivery)",
        burst_msgs.len(),
        (burst_msgs.len() as f64 / msg_count as f64) * 100.0
    );

    harness.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn rsyslog_large_message() {
    require_rsyslog!();
    let harness = UdpInteropHarness::new().await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("rsyslog").join("rsyslog-udp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(RSYSLOG_IMAGE, config.path(), "/etc/rsyslog.conf")
        .expect("start rsyslog container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    // Send a large message (close to UDP max for typical syslog ~4KB payload)
    let large_payload = "X".repeat(4000);
    assert!(docker_exec_logger(
        &container_id,
        "large-test",
        &large_payload
    ));

    let received = wait_for_messages(&harness.output, baseline + 1, 5000).await;
    assert!(received, "expected at least {} messages", baseline + 1);

    let msgs = harness.collected().await;
    let large_msg = msgs
        .iter()
        .find(|m| m.app_name.as_deref() == Some("large-test"));
    assert!(large_msg.is_some(), "large message not found");

    let msg = large_msg.unwrap();
    let body = msg
        .msg
        .as_ref()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .unwrap_or_default();
    // The message should contain a substantial portion of our payload
    // (rsyslog may have a max message size limit, but 4KB should be within range)
    assert!(
        body.len() > 500,
        "large message body too short: {} bytes",
        body.len()
    );

    harness.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn rsyslog_multiple_facilities_and_severities() {
    require_rsyslog!();
    let harness = UdpInteropHarness::new().await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("rsyslog").join("rsyslog-udp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(RSYSLOG_IMAGE, config.path(), "/etc/rsyslog.conf")
        .expect("start rsyslog container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    // Send messages with different facility.severity combinations
    let cases = [
        (
            "kern.emerg",
            "kern-test",
            Facility::Kern,
            Severity::Emergency,
        ),
        ("user.err", "user-test", Facility::User, Severity::Error),
        (
            "mail.warning",
            "mail-test",
            Facility::Mail,
            Severity::Warning,
        ),
        (
            "daemon.notice",
            "daemon-test",
            Facility::Daemon,
            Severity::Notice,
        ),
        (
            "local7.debug",
            "local7-test",
            Facility::Local7,
            Severity::Debug,
        ),
    ];

    for (priority, tag, _, _) in &cases {
        assert!(docker_exec_logger_full(
            &container_id,
            tag,
            priority,
            &format!("facility-severity test for {priority}"),
        ));
    }

    let received = wait_for_messages(&harness.output, baseline + cases.len(), 5000).await;
    assert!(
        received,
        "expected {} messages, got {}",
        baseline + cases.len(),
        harness.message_count().await
    );

    let msgs = harness.collected().await;

    for (_, tag, expected_facility, expected_severity) in &cases {
        let found = msgs.iter().find(|m| m.app_name.as_deref() == Some(*tag));
        assert!(found.is_some(), "message with tag '{tag}' not found");
        let msg = found.unwrap();
        assert_eq!(
            msg.facility, *expected_facility,
            "facility mismatch for tag '{tag}'"
        );
        assert_eq!(
            msg.severity, *expected_severity,
            "severity mismatch for tag '{tag}'"
        );
    }

    harness.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn rsyslog_tcp_reconnect_behavior() {
    require_rsyslog!();
    // Start TCP listener, send messages, restart listener, verify rsyslog reconnects
    let harness = TcpInteropHarness::new(false).await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("rsyslog").join("rsyslog-tcp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(RSYSLOG_IMAGE, config.path(), "/etc/rsyslog.conf")
        .expect("start rsyslog container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    // Send initial message
    assert!(docker_exec_logger(
        &container_id,
        "reconnect-test",
        "before restart"
    ));
    let received = wait_for_messages(&harness.output, baseline + 1, 5000).await;
    assert!(received, "expected message before restart");

    // Send more messages — rsyslog should have an established connection
    assert!(docker_exec_logger(
        &container_id,
        "reconnect-test",
        "after initial"
    ));
    let received = wait_for_messages(&harness.output, baseline + 2, 5000).await;
    assert!(received, "expected messages after initial send");

    let msgs = harness.collected().await;
    let reconnect_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.app_name.as_deref() == Some("reconnect-test"))
        .collect();
    assert!(
        reconnect_msgs.len() >= 2,
        "expected at least 2 reconnect-test messages"
    );

    harness.shutdown();
}

// ===========================================================================
// syslog-ng interop tests
// ===========================================================================

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn syslog_ng_rfc5424_over_udp() {
    require_syslog_ng!();
    let harness = UdpInteropHarness::new().await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("syslog-ng").join("syslog-ng-udp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(
        SYSLOG_NG_IMAGE,
        config.path(),
        "/etc/syslog-ng/syslog-ng.conf",
    )
    .expect("start syslog-ng container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    assert!(docker_exec_logger(
        &container_id,
        "sng-udp-test",
        "syslog-ng UDP RFC5424 message"
    ));
    assert!(docker_exec_logger_full(
        &container_id,
        "sng-auth",
        "auth.crit",
        "critical auth event from syslog-ng"
    ));

    let received = wait_for_messages(&harness.output, baseline + 2, 5000).await;
    assert!(
        received,
        "expected at least {} messages, got {}",
        baseline + 2,
        harness.message_count().await
    );

    let msgs = harness.collected().await;

    let test_msg = msgs.iter().find(|m| {
        m.msg
            .as_ref()
            .is_some_and(|b| String::from_utf8_lossy(b).contains("syslog-ng UDP RFC5424 message"))
    });
    assert!(test_msg.is_some(), "syslog-ng test message not found");
    let msg = test_msg.unwrap();

    // syslog-ng's syslog() destination sends RFC 5424
    assert_eq!(msg.version, 1, "expected RFC 5424 version 1");
    assert_eq!(msg.facility, Facility::Local0);
    assert_eq!(msg.severity, Severity::Informational);
    assert!(msg.hostname.is_some());

    // Check auth.crit message
    let auth_msg = msgs.iter().find(|m| {
        m.msg.as_ref().is_some_and(|b| {
            String::from_utf8_lossy(b).contains("critical auth event from syslog-ng")
        })
    });
    assert!(auth_msg.is_some(), "auth message not found");
    let auth = auth_msg.unwrap();
    assert_eq!(auth.facility, Facility::Auth);
    assert_eq!(auth.severity, Severity::Critical);

    harness.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn syslog_ng_rfc5424_over_tcp() {
    require_syslog_ng!();
    // syslog-ng's syslog() destination uses octet-counting by default
    let harness = TcpInteropHarness::new(false).await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("syslog-ng").join("syslog-ng-tcp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(
        SYSLOG_NG_IMAGE,
        config.path(),
        "/etc/syslog-ng/syslog-ng.conf",
    )
    .expect("start syslog-ng container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    assert!(docker_exec_logger(
        &container_id,
        "sng-tcp-test",
        "syslog-ng TCP message 1"
    ));
    assert!(docker_exec_logger(
        &container_id,
        "sng-tcp-test",
        "syslog-ng TCP message 2"
    ));
    assert!(docker_exec_logger(
        &container_id,
        "sng-tcp-test",
        "syslog-ng TCP message 3"
    ));

    let received = wait_for_messages(&harness.output, baseline + 3, 5000).await;
    assert!(
        received,
        "expected at least {} messages, got {}",
        baseline + 3,
        harness.message_count().await
    );

    let msgs = harness.collected().await;
    let sng_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.app_name.as_deref() == Some("sng-tcp-test"))
        .collect();
    assert!(
        sng_msgs.len() >= 3,
        "expected at least 3 syslog-ng TCP messages"
    );

    // Verify message ordering over TCP
    let bodies: Vec<String> = sng_msgs
        .iter()
        .filter_map(|m| {
            m.msg
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).to_string())
        })
        .collect();
    for (i, body) in bodies.iter().enumerate() {
        assert!(
            body.contains(&format!("message {}", i + 1)),
            "syslog-ng TCP message {i} out of order: {body}"
        );
    }

    for msg in &sng_msgs {
        assert_eq!(msg.version, 1);
        assert!(msg.hostname.is_some());
    }

    harness.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn syslog_ng_rfc3164_over_tcp() {
    require_syslog_ng!();
    // syslog-ng network() destination sends legacy format with LF framing
    let harness = TcpInteropHarness::new(true).await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("syslog-ng").join("syslog-ng-tcp-3164.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(
        SYSLOG_NG_IMAGE,
        config.path(),
        "/etc/syslog-ng/syslog-ng.conf",
    )
    .expect("start syslog-ng container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    assert!(docker_exec_logger(
        &container_id,
        "sng-legacy",
        "syslog-ng legacy format test"
    ));

    let received = wait_for_messages(&harness.output, baseline + 1, 5000).await;
    assert!(
        received,
        "expected at least {} messages, got {}",
        baseline + 1,
        harness.message_count().await
    );

    let msgs = harness.collected().await;
    let legacy_msg = msgs.iter().find(|m| {
        m.msg
            .as_ref()
            .is_some_and(|b| String::from_utf8_lossy(b).contains("syslog-ng legacy format test"))
    });
    assert!(legacy_msg.is_some(), "syslog-ng legacy message not found");

    let msg = legacy_msg.unwrap();
    assert_eq!(msg.facility, Facility::Local0);
    assert_eq!(msg.severity, Severity::Informational);
    assert!(
        msg.hostname.is_some(),
        "hostname should be parsed from 3164 header"
    );

    harness.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn syslog_ng_burst_traffic() {
    require_syslog_ng!();
    let harness = UdpInteropHarness::new().await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("syslog-ng").join("syslog-ng-udp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(
        SYSLOG_NG_IMAGE,
        config.path(),
        "/etc/syslog-ng/syslog-ng.conf",
    )
    .expect("start syslog-ng container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    let msg_count = 20;
    for i in 0..msg_count {
        assert!(docker_exec_logger(
            &container_id,
            "sng-burst",
            &format!("syslog-ng burst {i:03}"),
        ));
    }

    let received = wait_for_messages(&harness.output, baseline + msg_count / 2, 10000).await;
    let actual = harness.message_count().await;
    assert!(
        received,
        "expected at least {} messages, got {actual}",
        baseline + msg_count / 2
    );

    let msgs = harness.collected().await;
    let burst_msgs: Vec<_> = msgs
        .iter()
        .filter(|m| m.app_name.as_deref() == Some("sng-burst"))
        .collect();

    for msg in &burst_msgs {
        assert_eq!(msg.facility, Facility::Local0);
        assert_eq!(msg.severity, Severity::Informational);
        assert!(msg.hostname.is_some());
    }

    eprintln!(
        "syslog-ng burst: sent {msg_count}, received {} ({:.0}% delivery)",
        burst_msgs.len(),
        (burst_msgs.len() as f64 / msg_count as f64) * 100.0
    );

    harness.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn syslog_ng_large_message() {
    require_syslog_ng!();
    let harness = UdpInteropHarness::new().await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("syslog-ng").join("syslog-ng-udp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(
        SYSLOG_NG_IMAGE,
        config.path(),
        "/etc/syslog-ng/syslog-ng.conf",
    )
    .expect("start syslog-ng container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    let large_payload = "Y".repeat(4000);
    assert!(docker_exec_logger(
        &container_id,
        "sng-large",
        &large_payload
    ));

    let received = wait_for_messages(&harness.output, baseline + 1, 5000).await;
    assert!(received, "expected at least {} messages", baseline + 1);

    let msgs = harness.collected().await;
    let large_msg = msgs
        .iter()
        .find(|m| m.app_name.as_deref() == Some("sng-large"));
    assert!(large_msg.is_some(), "syslog-ng large message not found");

    let body_len = large_msg
        .unwrap()
        .msg
        .as_ref()
        .map(|b| b.len())
        .unwrap_or(0);
    assert!(
        body_len > 500,
        "syslog-ng large message too short: {body_len} bytes"
    );

    harness.shutdown();
}

// ===========================================================================
// Cross-sender tests
// ===========================================================================

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn parallel_rsyslog_and_syslog_ng_udp() {
    require_rsyslog!();
    require_syslog_ng!();

    let harness = UdpInteropHarness::new().await;
    let host = docker_host();
    let port = harness.port();

    // Start both senders pointing at the same listener
    let rsyslog_config = render_config(
        &fixtures_dir("rsyslog").join("rsyslog-udp-5424.conf"),
        &host,
        port,
    );
    let syslog_ng_config = render_config(
        &fixtures_dir("syslog-ng").join("syslog-ng-udp-5424.conf"),
        &host,
        port,
    );

    let rsyslog_id =
        run_sender_container(RSYSLOG_IMAGE, rsyslog_config.path(), "/etc/rsyslog.conf")
            .expect("start rsyslog container");
    let _rsyslog_guard = ContainerGuard {
        id: rsyslog_id.clone(),
    };

    let syslog_ng_id = run_sender_container(
        SYSLOG_NG_IMAGE,
        syslog_ng_config.path(),
        "/etc/syslog-ng/syslog-ng.conf",
    )
    .expect("start syslog-ng container");
    let _syslog_ng_guard = ContainerGuard {
        id: syslog_ng_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    // Send messages from both senders
    assert!(docker_exec_logger(
        &rsyslog_id,
        "rsyslog-parallel",
        "from rsyslog"
    ));
    assert!(docker_exec_logger(
        &syslog_ng_id,
        "syslog-ng-parallel",
        "from syslog-ng"
    ));

    let received = wait_for_messages(&harness.output, baseline + 2, 8000).await;
    assert!(
        received,
        "expected at least {} messages from parallel senders",
        baseline + 2
    );

    let msgs = harness.collected().await;

    let from_rsyslog = msgs.iter().any(|m| {
        m.msg
            .as_ref()
            .is_some_and(|b| String::from_utf8_lossy(b).contains("from rsyslog"))
    });
    let from_syslog_ng = msgs.iter().any(|m| {
        m.msg
            .as_ref()
            .is_some_and(|b| String::from_utf8_lossy(b).contains("from syslog-ng"))
    });

    assert!(from_rsyslog, "message from rsyslog not found");
    assert!(from_syslog_ng, "message from syslog-ng not found");

    // Both should be valid RFC 5424
    for msg in &msgs {
        if msg.app_name.as_deref() == Some("rsyslog-parallel")
            || msg.app_name.as_deref() == Some("syslog-ng-parallel")
        {
            assert_eq!(msg.version, 1);
            assert!(msg.hostname.is_some());
            assert_eq!(msg.facility, Facility::Local0);
        }
    }

    harness.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn parallel_rsyslog_and_syslog_ng_tcp() {
    require_rsyslog!();
    require_syslog_ng!();

    let harness = TcpInteropHarness::new(false).await;
    let host = docker_host();
    let port = harness.port();

    let rsyslog_config = render_config(
        &fixtures_dir("rsyslog").join("rsyslog-tcp-5424.conf"),
        &host,
        port,
    );
    let syslog_ng_config = render_config(
        &fixtures_dir("syslog-ng").join("syslog-ng-tcp-5424.conf"),
        &host,
        port,
    );

    let rsyslog_id =
        run_sender_container(RSYSLOG_IMAGE, rsyslog_config.path(), "/etc/rsyslog.conf")
            .expect("start rsyslog container");
    let _rsyslog_guard = ContainerGuard {
        id: rsyslog_id.clone(),
    };

    let syslog_ng_id = run_sender_container(
        SYSLOG_NG_IMAGE,
        syslog_ng_config.path(),
        "/etc/syslog-ng/syslog-ng.conf",
    )
    .expect("start syslog-ng container");
    let _syslog_ng_guard = ContainerGuard {
        id: syslog_ng_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    // Send from both over TCP (both should use octet-counting)
    for i in 0..3 {
        assert!(docker_exec_logger(
            &rsyslog_id,
            "rs-tcp-par",
            &format!("rsyslog tcp parallel {i}")
        ));
        assert!(docker_exec_logger(
            &syslog_ng_id,
            "sng-tcp-par",
            &format!("syslog-ng tcp parallel {i}")
        ));
    }

    let received = wait_for_messages(&harness.output, baseline + 6, 8000).await;
    assert!(
        received,
        "expected at least {} messages from parallel TCP senders, got {}",
        baseline + 6,
        harness.message_count().await
    );

    let msgs = harness.collected().await;
    let rs_count = msgs
        .iter()
        .filter(|m| m.app_name.as_deref() == Some("rs-tcp-par"))
        .count();
    let sng_count = msgs
        .iter()
        .filter(|m| m.app_name.as_deref() == Some("sng-tcp-par"))
        .count();

    assert!(
        rs_count >= 3,
        "expected 3 rsyslog TCP parallel messages, got {rs_count}"
    );
    assert!(
        sng_count >= 3,
        "expected 3 syslog-ng TCP parallel messages, got {sng_count}"
    );

    harness.shutdown();
}

// ===========================================================================
// UTF-8 and special character tests
// ===========================================================================

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn rsyslog_utf8_message() {
    require_rsyslog!();
    let harness = UdpInteropHarness::new().await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("rsyslog").join("rsyslog-udp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(RSYSLOG_IMAGE, config.path(), "/etc/rsyslog.conf")
        .expect("start rsyslog container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    // UTF-8 message with various scripts
    let utf8_msg = "Héllo wörld — 日本語テスト — Привет мир — 🔒 security event";
    assert!(docker_exec_logger(&container_id, "utf8-test", utf8_msg));

    let received = wait_for_messages(&harness.output, baseline + 1, 5000).await;
    assert!(received, "expected at least {} messages", baseline + 1);

    let msgs = harness.collected().await;
    let utf8_found = msgs
        .iter()
        .find(|m| m.app_name.as_deref() == Some("utf8-test"));
    assert!(utf8_found.is_some(), "UTF-8 message not found");

    let body = utf8_found
        .unwrap()
        .msg
        .as_ref()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .unwrap_or_default();

    // Verify key UTF-8 sequences survived the roundtrip
    assert!(body.contains("Héllo"), "Latin extended chars lost");
    assert!(body.contains("日本語"), "CJK chars lost");
    assert!(body.contains("Привет"), "Cyrillic chars lost");

    harness.shutdown();
}

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn syslog_ng_utf8_message() {
    require_syslog_ng!();
    let harness = UdpInteropHarness::new().await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("syslog-ng").join("syslog-ng-udp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(
        SYSLOG_NG_IMAGE,
        config.path(),
        "/etc/syslog-ng/syslog-ng.conf",
    )
    .expect("start syslog-ng container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    let utf8_msg = "Ünïcödé tëst — 中文测试 — العربية — Ελληνικά";
    assert!(docker_exec_logger(&container_id, "sng-utf8", utf8_msg));

    let received = wait_for_messages(&harness.output, baseline + 1, 5000).await;
    assert!(received, "expected at least {} messages", baseline + 1);

    let msgs = harness.collected().await;
    let utf8_found = msgs
        .iter()
        .find(|m| m.app_name.as_deref() == Some("sng-utf8"));
    assert!(utf8_found.is_some(), "syslog-ng UTF-8 message not found");

    let body = utf8_found
        .unwrap()
        .msg
        .as_ref()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .unwrap_or_default();

    assert!(body.contains("Ünïcödé"), "extended Latin chars lost");
    assert!(body.contains("中文测试"), "CJK chars lost");

    harness.shutdown();
}

// ===========================================================================
// Timestamp validation
// ===========================================================================

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn rsyslog_timestamp_precision() {
    require_rsyslog!();
    let harness = UdpInteropHarness::new().await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("rsyslog").join("rsyslog-udp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(RSYSLOG_IMAGE, config.path(), "/etc/rsyslog.conf")
        .expect("start rsyslog container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    assert!(docker_exec_logger(
        &container_id,
        "ts-test",
        "timestamp precision test"
    ));

    let received = wait_for_messages(&harness.output, baseline + 1, 5000).await;
    assert!(received, "expected at least {} messages", baseline + 1);

    let msgs = harness.collected().await;
    let ts_msg = msgs
        .iter()
        .find(|m| m.app_name.as_deref() == Some("ts-test"));
    assert!(ts_msg.is_some());

    let msg = ts_msg.unwrap();
    // rsyslog should produce a valid RFC 3339 timestamp that our parser accepts
    use syslog_proto::SyslogTimestamp;
    match &msg.timestamp {
        SyslogTimestamp::Value(dt) => {
            // Basic sanity: year should be current or recent
            assert!(dt.year() >= 2024, "timestamp year too old: {}", dt.year());
            assert!(
                (1..=12).contains(&u8::from(dt.month())),
                "invalid month: {}",
                dt.month()
            );
            assert!((1..=31).contains(&dt.day()), "invalid day: {}", dt.day());
            assert!(dt.hour() <= 23, "invalid hour: {}", dt.hour());
            assert!(dt.minute() <= 59, "invalid minute: {}", dt.minute());
            assert!(
                dt.second() <= 60,
                "invalid second (allowing leap): {}",
                dt.second()
            );
        }
        SyslogTimestamp::Nil => {
            panic!("expected RFC 3339 timestamp, got Nil");
        }
    }

    harness.shutdown();
}

// ===========================================================================
// Hostname / app-name edge cases
// ===========================================================================

#[tokio::test]
#[ignore = "requires Docker with container-to-host networking"]
async fn rsyslog_various_app_names() {
    require_rsyslog!();
    let harness = UdpInteropHarness::new().await;
    let host = docker_host();
    let port = harness.port();

    let config = render_config(
        &fixtures_dir("rsyslog").join("rsyslog-udp-5424.conf"),
        &host,
        port,
    );

    let container_id = run_sender_container(RSYSLOG_IMAGE, config.path(), "/etc/rsyslog.conf")
        .expect("start rsyslog container");
    let _guard = ContainerGuard {
        id: container_id.clone(),
    };

    tokio::time::sleep(Duration::from_millis(SENDER_SETTLE_MS)).await;
    let baseline = harness.message_count().await;

    // Test various app-name patterns that real systems produce
    let tags = ["sshd", "CRON", "systemd-resolved", "kernel", "my.app.v2"];

    for tag in &tags {
        assert!(docker_exec_logger(
            &container_id,
            tag,
            &format!("app-name test for {tag}")
        ));
    }

    let received = wait_for_messages(&harness.output, baseline + tags.len(), 5000).await;
    assert!(received, "expected {} messages", baseline + tags.len());

    let msgs = harness.collected().await;
    for tag in &tags {
        let found = msgs.iter().any(|m| m.app_name.as_deref() == Some(*tag));
        assert!(found, "message with app_name '{tag}' not found");
    }

    harness.shutdown();
}
