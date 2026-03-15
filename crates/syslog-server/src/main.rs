//! syslog-usg — Production-grade syslog server and relay.
//!
//! This binary wires together all crates:
//! - Transport listeners (UDP, TCP/TLS)
//! - Message parsing (RFC 5424, RFC 3164)
//! - Relay pipeline (filter, route, fan-out)
//! - Management state (RFC 9742 counters, features)
//! - Observability (metrics, health endpoints, structured logging)
//! - Configuration loading (TOML with env var substitution)

mod network_output;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use syslog_config::model::{ListenerProtocol, OutputProtocol, ServerConfig};
use syslog_mgmt::{SharedSyslogState, SyslogFeatures};
use syslog_observe::{
    HealthState, LogReloadHandle, health_router_with_token, init_logging, init_metrics,
};
use syslog_relay::output::Output;
use syslog_relay::{
    AlarmFilter, BufferOutput, FileOutput, MessageFilter, NonAlarmPolicy, Pipeline,
    PipelineIngress, RelayError, RoutingRule, RoutingTable,
};
use syslog_transport::dtls::{DtlsDatagram, DtlsListenerConfig, run_dtls_listener};
use syslog_transport::tcp::{TcpListenerConfig, TcpMessage, run_tcp_listener};
use syslog_transport::tls::load_certs;
use syslog_transport::udp::{UdpDatagram, UdpListenerConfig, run_udp_listener};

use crate::network_output::NetworkOutput;

/// Unified output type for the server pipeline, wrapping both network
/// and file-based outputs behind a common [`Output`] implementation.
#[derive(Debug, Clone)]
enum ServerOutput {
    Network(NetworkOutput),
    File(FileOutput),
    Buffer(BufferOutput),
}

impl Output for ServerOutput {
    fn name(&self) -> &str {
        match self {
            Self::Network(o) => o.name(),
            Self::File(o) => o.name(),
            Self::Buffer(o) => o.name(),
        }
    }

    async fn send(&self, message: syslog_proto::SyslogMessage) -> Result<(), RelayError> {
        match self {
            Self::Network(o) => o.send(message).await,
            Self::File(o) => o.send(message).await,
            Self::Buffer(o) => o.send(message).await,
        }
    }
}

/// syslog-usg: Production-grade syslog server and relay.
#[derive(Parser, Debug)]
#[command(name = "syslog-usg", version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/syslog-usg/config.toml")]
    config: PathBuf,

    /// Override the log level (e.g., debug, info, warn, error).
    #[arg(long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Load configuration
    let config = match syslog_config::load_config(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to load config from {:?}: {e}", cli.config);
            std::process::exit(1);
        }
    };

    // Initialize logging (returns a handle for runtime reload)
    let log_level = cli.log_level.as_deref().unwrap_or(&config.logging.level);
    let log_reload = match init_logging(log_level) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: failed to initialize logging: {e}");
            std::process::exit(1);
        }
    };

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %cli.config.display(),
        "syslog-usg starting"
    );

    // Initialize metrics
    let metrics_handle = match init_metrics() {
        Ok(h) => h,
        Err(e) => {
            error!("failed to initialize metrics: {e}");
            std::process::exit(1);
        }
    };

    // Detect features and build shared management state
    let features = detect_features(&config);
    let shared_state = SharedSyslogState::new(features);
    info!(features = ?features.flag_names(), "detected features");

    // Shutdown coordination
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Build outputs from config (network outputs + file outputs from actions)
    let mut outputs = build_outputs(&config);
    let network_output_count = outputs.len();

    // Add file outputs from management actions and build routing table
    let routing_table = build_routing_table(&config, network_output_count, &mut outputs);

    if outputs.is_empty() {
        warn!("no outputs configured — messages will be received but not forwarded");
    }
    let channel_capacity = config.pipeline.channel_buffer_size;

    // Build filter chain
    let filters = build_filters(&config);

    // Build optional signing/verification stages (RFC 5848)
    let signing = build_signing_stage(&config);
    let verification = build_verification_stage(&config);

    let (mut pipeline, ingress, pipeline_shutdown) = Pipeline::with_management(
        channel_capacity,
        filters,
        outputs,
        signing,
        verification,
        routing_table,
        Some(shared_state.clone()),
    );
    pipeline.set_signing_fail_open(config.pipeline.signing_fail_open);

    // Start the relay pipeline
    let pipeline_handle = tokio::spawn(async move {
        if let Err(e) = pipeline.run().await {
            info!("pipeline stopped: {e}");
        }
    });

    // Start listeners
    let mut listener_handles = Vec::new();
    start_listeners(
        &config,
        &ingress,
        &shared_state,
        shutdown_rx.clone(),
        &mut listener_handles,
    );

    // Start health/metrics HTTP server (with management state)
    let health_state = HealthState::with_management(metrics_handle, shared_state.clone());
    let health_addr: SocketAddr = match config.metrics.bind_address.parse() {
        Ok(a) => a,
        Err(e) => {
            error!(
                address = %config.metrics.bind_address,
                "invalid metrics bind address: {e} — defaulting to 127.0.0.1:9090"
            );
            ([127, 0, 0, 1], 9090).into()
        }
    };

    // Warn if management/metrics endpoints are unauthenticated on non-loopback
    if config.metrics.bearer_token.is_none() && !health_addr.ip().is_loopback() {
        warn!(
            addr = %health_addr,
            "metrics/management endpoints are unauthenticated on a non-loopback address — \
             set metrics.bearer_token in config for production use"
        );
    }

    let health_state_clone = health_state.clone();
    let bearer_token = config.metrics.bearer_token.clone();
    let health_handle = tokio::spawn(async move {
        let app = health_router_with_token(health_state_clone, bearer_token);
        let listener = match tokio::net::TcpListener::bind(health_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(addr = %health_addr, "failed to bind health server: {e}");
                return;
            }
        };
        info!(addr = %health_addr, "health/metrics server started");
        if let Err(e) = axum::serve(listener, app).await {
            error!("health server error: {e}");
        }
    });

    // Mark as ready
    health_state.set_ready(true);
    info!("syslog-usg ready");

    // Wait for shutdown or reload signals
    wait_for_signals(&cli.config, &log_reload, &config).await;

    // Initiate graceful shutdown
    info!("initiating graceful shutdown");
    health_state.set_ready(false);
    let _ = shutdown_tx.send(true);
    pipeline_shutdown.shutdown();

    // Wait for drain timeout
    let drain_timeout = std::time::Duration::from_secs(config.server.drain_timeout_seconds);
    let _ = tokio::time::timeout(drain_timeout, async {
        let _ = pipeline_handle.await;
        for handle in listener_handles {
            let _ = handle.await;
        }
    })
    .await;

    // Health server doesn't need graceful shutdown
    health_handle.abort();

    info!("syslog-usg stopped");
}

/// Detect which features are enabled based on configuration.
fn detect_features(config: &ServerConfig) -> SyslogFeatures {
    let mut features = SyslogFeatures::RFC5424_FORMAT | SyslogFeatures::RFC3164_FORMAT;

    for listener in &config.listeners {
        match listener.protocol {
            ListenerProtocol::Udp => features |= SyslogFeatures::UDP_TRANSPORT,
            ListenerProtocol::Tcp => features |= SyslogFeatures::TCP_TRANSPORT,
            ListenerProtocol::Tls => features |= SyslogFeatures::TLS_TRANSPORT,
            ListenerProtocol::Dtls => features |= SyslogFeatures::DTLS_TRANSPORT,
        }
    }

    for output in &config.outputs {
        match output.protocol {
            OutputProtocol::Udp => features |= SyslogFeatures::UDP_TRANSPORT,
            OutputProtocol::Tcp => features |= SyslogFeatures::TCP_TRANSPORT,
            OutputProtocol::Tls => features |= SyslogFeatures::TLS_TRANSPORT,
            OutputProtocol::Dtls => features |= SyslogFeatures::DTLS_TRANSPORT,
        }
    }

    if !config.outputs.is_empty() {
        features |= SyslogFeatures::RELAY;
    }

    if config.signing.as_ref().is_some_and(|s| s.enabled) {
        features |= SyslogFeatures::SIGNING;
    }

    features |= SyslogFeatures::STRUCTURED_DATA;

    if config
        .pipeline
        .alarm_filter
        .as_ref()
        .is_some_and(|af| af.enabled)
    {
        features |= SyslogFeatures::ALARM;
    }

    features
}

/// Build the routing table from management action configurations.
///
/// File actions create `FileOutput` entries appended to `outputs` and are
/// routed to the corresponding index.
fn build_routing_table(
    config: &ServerConfig,
    network_output_count: usize,
    outputs: &mut Vec<ServerOutput>,
) -> Option<RoutingTable> {
    if config.actions.is_empty() {
        return None;
    }

    let mut rules = Vec::new();
    for (i, action_cfg) in config.actions.iter().enumerate() {
        let selector = match syslog_config::convert::convert_selector(&action_cfg.selector) {
            Ok(s) => s,
            Err(e) => {
                error!(action_index = i, "failed to convert action selector: {e}");
                continue;
            }
        };

        // Map action type to output indices.
        let output_indices: Vec<usize> = match &action_cfg.action {
            syslog_config::model::ActionTypeConfig::Remote { .. } => {
                (0..network_output_count).collect()
            }
            syslog_config::model::ActionTypeConfig::Console => (0..network_output_count).collect(),
            syslog_config::model::ActionTypeConfig::Discard => {
                vec![]
            }
            syslog_config::model::ActionTypeConfig::File { path } => {
                let file_output = FileOutput::new(format!("file-action-{i}"), path.as_str());
                let idx = outputs.len();
                outputs.push(ServerOutput::File(file_output));
                info!(
                    action_index = i,
                    path = %path,
                    output_index = idx,
                    "file output configured from management action"
                );
                vec![idx]
            }
            syslog_config::model::ActionTypeConfig::Buffer { name, size } => {
                let buffer_output =
                    BufferOutput::new(format!("buffer-action-{i}-{name}"), *size);
                let idx = outputs.len();
                outputs.push(ServerOutput::Buffer(buffer_output));
                info!(
                    action_index = i,
                    name = %name,
                    size = size,
                    output_index = idx,
                    "buffer output configured from management action"
                );
                vec![idx]
            }
        };

        rules.push(RoutingRule {
            selector,
            output_indices,
            description: action_cfg.description.clone(),
        });
    }

    if rules.is_empty() {
        None
    } else {
        info!(
            rules = rules.len(),
            "routing table built from management actions"
        );
        Some(RoutingTable::new(rules))
    }
}

/// Start transport listeners based on configuration.
fn start_listeners(
    config: &ServerConfig,
    ingress: &PipelineIngress,
    shared_state: &SharedSyslogState,
    shutdown_rx: watch::Receiver<bool>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    for listener_cfg in &config.listeners {
        let addr_str = &listener_cfg.bind_address;
        let addr: SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                error!(address = %addr_str, "invalid listener address: {e}");
                continue;
            }
        };

        match listener_cfg.protocol {
            ListenerProtocol::Udp => {
                let udp_config = UdpListenerConfig {
                    bind_addr: addr,
                    ..Default::default()
                };

                let (udp_tx, mut udp_rx) =
                    mpsc::channel::<UdpDatagram>(config.pipeline.channel_buffer_size);
                let shutdown = shutdown_rx.clone();
                let ingress = ingress.clone();
                let state = shared_state.clone();

                // Spawn the UDP listener
                handles.push(tokio::spawn(async move {
                    if let Err(e) = run_udp_listener(udp_config, udp_tx, shutdown).await {
                        error!("UDP listener error: {e}");
                    }
                }));

                // Spawn the parser bridge (UDP datagrams -> parsed messages -> pipeline)
                handles.push(tokio::spawn(async move {
                    while let Some(datagram) = udp_rx.recv().await {
                        state.counters().increment_received();
                        match syslog_parse::parse(&datagram.data) {
                            Ok(msg) => {
                                if let Err(e) = ingress.send(msg).await {
                                    warn!("pipeline send error: {e}");
                                    return;
                                }
                            }
                            Err(e) => {
                                state.counters().increment_malformed();
                                warn!(
                                    source = %datagram.source,
                                    "parse error: {}",
                                    sanitize_log_msg(&e.to_string())
                                );
                                metrics::counter!("syslog_messages_parsed_total", "format" => "invalid")
                                    .increment(1);
                            }
                        }
                    }
                }));

                info!(addr = %addr, "UDP listener configured");
            }
            ListenerProtocol::Dtls => {
                let dtls_config = DtlsListenerConfig::new(
                    addr,
                    listener_cfg
                        .tls
                        .as_ref()
                        .map(|t| t.cert_path.clone().into())
                        .unwrap_or_default(),
                    listener_cfg
                        .tls
                        .as_ref()
                        .map(|t| t.key_path.clone().into())
                        .unwrap_or_default(),
                );

                let (dtls_tx, mut dtls_rx) =
                    mpsc::channel::<DtlsDatagram>(config.pipeline.channel_buffer_size);
                let shutdown = shutdown_rx.clone();
                let ingress = ingress.clone();
                let state = shared_state.clone();

                // Spawn the DTLS (plaintext-fallback) listener
                handles.push(tokio::spawn(async move {
                    if let Err(e) = run_dtls_listener(&dtls_config, dtls_tx, shutdown).await {
                        error!("DTLS listener error: {e}");
                    }
                }));

                // Spawn the parser bridge (DTLS datagrams -> parsed messages -> pipeline)
                handles.push(tokio::spawn(async move {
                    while let Some(datagram) = dtls_rx.recv().await {
                        state.counters().increment_received();
                        match syslog_parse::parse(&datagram.payload) {
                            Ok(msg) => {
                                if let Err(e) = ingress.send(msg).await {
                                    warn!("pipeline send error: {e}");
                                    return;
                                }
                            }
                            Err(e) => {
                                state.counters().increment_malformed();
                                warn!(
                                    source = %datagram.peer,
                                    "parse error: {}",
                                    sanitize_log_msg(&e.to_string())
                                );
                                metrics::counter!("syslog_messages_parsed_total", "format" => "invalid")
                                    .increment(1);
                            }
                        }
                    }
                }));

                info!(addr = %addr, "DTLS (plaintext-fallback) listener configured");
            }
            ListenerProtocol::Tcp | ListenerProtocol::Tls => {
                let tls_acceptor = if listener_cfg.protocol == ListenerProtocol::Tls {
                    let tls_cfg = match &listener_cfg.tls {
                        Some(t) => t,
                        None => {
                            error!(addr = %addr, "TLS listener missing [tls] config section");
                            continue;
                        }
                    };

                    check_key_file_permissions(&tls_cfg.key_path);

                    let transport_tls = syslog_transport::tls::TlsConfig {
                        cert_path: tls_cfg.cert_path.clone(),
                        key_path: tls_cfg.key_path.clone(),
                        client_auth: tls_cfg.client_auth,
                        client_ca_path: tls_cfg.ca_path.clone(),
                    };

                    match syslog_transport::tls::build_server_config(&transport_tls) {
                        Ok(c) => Some(Arc::new(tokio_rustls::TlsAcceptor::from(c))),
                        Err(e) => {
                            error!(addr = %addr, "failed to build TLS config: {e}");
                            continue;
                        }
                    }
                } else {
                    None
                };

                let proto_label = if tls_acceptor.is_some() { "TLS" } else { "TCP" };

                let tcp_config = TcpListenerConfig {
                    bind_addr: addr,
                    max_frame_size: config.pipeline.max_message_size,
                    tls_acceptor,
                    max_connections: listener_cfg.max_connections,
                    read_timeout: listener_cfg
                        .read_timeout_secs
                        .map(std::time::Duration::from_secs),
                    idle_timeout: None,
                };

                let (tcp_tx, mut tcp_rx) =
                    mpsc::channel::<TcpMessage>(config.pipeline.channel_buffer_size);
                let shutdown = shutdown_rx.clone();
                let ingress = ingress.clone();
                let state = shared_state.clone();

                // Spawn the TCP/TLS listener
                handles.push(tokio::spawn(async move {
                    if let Err(e) = run_tcp_listener(tcp_config, tcp_tx, shutdown).await {
                        error!("{proto_label} listener error: {e}");
                    }
                }));

                // Spawn the parser bridge (TCP frames -> parsed messages -> pipeline)
                handles.push(tokio::spawn(async move {
                    while let Some(frame) = tcp_rx.recv().await {
                        state.counters().increment_received();
                        match syslog_parse::parse(&frame.data) {
                            Ok(msg) => {
                                if let Err(e) = ingress.send(msg).await {
                                    warn!("pipeline send error: {e}");
                                    return;
                                }
                            }
                            Err(e) => {
                                state.counters().increment_malformed();
                                warn!(
                                    source = %frame.peer,
                                    tls = frame.tls,
                                    "parse error: {}",
                                    sanitize_log_msg(&e.to_string())
                                );
                                metrics::counter!("syslog_messages_parsed_total", "format" => "invalid")
                                    .increment(1);
                            }
                        }
                    }
                }));

                info!(addr = %addr, proto = proto_label, "listener configured");
            }
        }
    }
}

/// Build the pipeline filter chain from configuration.
fn build_filters(config: &ServerConfig) -> Vec<Box<dyn MessageFilter>> {
    let mut filters: Vec<Box<dyn MessageFilter>> = Vec::new();

    // Build alarm filter if configured and enabled (RFC 5674).
    if let Some(ref af_cfg) = config.pipeline.alarm_filter {
        if af_cfg.enabled {
            let mut builder = AlarmFilter::builder();

            // Min severity
            if let Some(ref sev_str) = af_cfg.min_severity {
                if let Ok(sev) = sev_str.parse::<syslog_proto::PerceivedSeverity>() {
                    builder = builder.min_severity(sev);
                }
            }

            // Event types
            let mut event_types = Vec::new();
            for et_str in &af_cfg.event_types {
                if let Ok(et) = et_str.parse::<syslog_proto::ItuEventType>() {
                    event_types.push(et);
                }
            }
            if !event_types.is_empty() {
                builder = builder.event_types(event_types);
            }

            // Resource patterns
            if !af_cfg.resource_patterns.is_empty() {
                builder = builder.resource_patterns(af_cfg.resource_patterns.clone());
            }

            // Non-alarm policy
            if let Some(ref policy_str) = af_cfg.non_alarm_policy {
                let policy = match policy_str.as_str() {
                    "drop" => NonAlarmPolicy::Drop,
                    _ => NonAlarmPolicy::Pass,
                };
                builder = builder.non_alarm_policy(policy);
            }

            let alarm_filter = builder.build();
            info!(
                min_severity = ?af_cfg.min_severity,
                event_types = ?af_cfg.event_types,
                non_alarm_policy = ?af_cfg.non_alarm_policy,
                "alarm filter enabled"
            );
            filters.push(Box::new(alarm_filter));
        }
    }

    filters
}

/// Build the optional RFC 5848 signing stage from configuration.
///
/// Loads the PKCS#8 signing key and optional X.509 certificate from disk,
/// then constructs a [`SigningStage`] for the relay pipeline.
fn build_signing_stage(config: &ServerConfig) -> Option<syslog_relay::SigningStage> {
    use bytes::Bytes;
    use compact_str::CompactString;
    use syslog_proto::{Facility, Severity, StructuredData, SyslogMessage, SyslogTimestamp};
    use syslog_sign::SigningKey;
    use syslog_sign::counter::RebootSessionId;
    use syslog_sign::signer::{Signer, SignerConfig};
    use syslog_sign::types::{HashAlgorithm, SignatureGroup};

    let signing_cfg = config.signing.as_ref()?;
    if !signing_cfg.enabled {
        return None;
    }

    // Load PKCS#8 DER-encoded private key
    check_key_file_permissions(&signing_cfg.key_path);
    let key_bytes = match std::fs::read(&signing_cfg.key_path) {
        Ok(b) => b,
        Err(e) => {
            error!(path = %signing_cfg.key_path, "failed to read signing key: {e}");
            return None;
        }
    };

    let signing_key = match SigningKey::from_pkcs8(&key_bytes) {
        Ok(k) => k,
        Err(e) => {
            error!("failed to parse signing key: {e}");
            return None;
        }
    };

    // Load optional DER-encoded X.509 certificate
    let cert_der =
        signing_cfg
            .cert_path
            .as_ref()
            .and_then(|cert_path| match std::fs::read(cert_path) {
                Ok(b) => {
                    info!(path = %cert_path, "loaded signing certificate");
                    Some(b)
                }
                Err(e) => {
                    warn!(path = %cert_path, "failed to read signing certificate: {e}");
                    None
                }
            });

    // Parse config options
    let hash_algorithm = match signing_cfg.hash_algorithm.as_deref() {
        Some("sha1") => HashAlgorithm::Sha1,
        _ => HashAlgorithm::Sha256,
    };

    let signature_group = match signing_cfg.signature_group.as_deref() {
        Some("per-pri") => SignatureGroup::PerPri,
        Some("pri-ranges") => SignatureGroup::PriRanges,
        Some("custom") => SignatureGroup::Custom,
        _ => SignatureGroup::Global,
    };

    let signer_config = SignerConfig {
        hash_algorithm,
        signature_group,
        max_hashes_per_block: signing_cfg.max_hashes_per_block.unwrap_or(25),
        ..Default::default()
    };

    let rsid = match &signing_cfg.state_dir {
        Some(dir) => load_or_increment_rsid(dir),
        None => RebootSessionId::unpersisted(),
    };
    let signer = Signer::new(signing_key, rsid, signer_config);

    let cert_interval =
        std::time::Duration::from_secs(signing_cfg.cert_emit_interval_secs.unwrap_or(3600));

    // Build a template message for signature/certificate block messages
    let hostname = gethostname().unwrap_or_else(|| "syslog-usg".to_owned());
    let template = SyslogMessage {
        facility: Facility::Syslog,
        severity: Severity::Informational,
        version: 1,
        timestamp: SyslogTimestamp::Nil,
        hostname: Some(CompactString::new(&hostname)),
        app_name: Some(CompactString::new("syslog-sign")),
        proc_id: None,
        msg_id: None,
        structured_data: StructuredData::nil(),
        msg: Some(Bytes::from_static(b"")),
        raw: None,
    };

    let stage = syslog_relay::SigningStage::new(signer, cert_der, cert_interval, template);

    info!(
        hash = ?hash_algorithm,
        sg = ?signature_group,
        "RFC 5848 signing stage enabled"
    );

    Some(stage)
}

/// Build the optional RFC 5848 verification stage from configuration.
///
/// Loads trusted public key files from disk and constructs a
/// [`VerificationStage`] for the relay pipeline.
fn build_verification_stage(config: &ServerConfig) -> Option<syslog_relay::VerificationStage> {
    use syslog_sign::signature::VerifyingKey;
    use syslog_sign::verifier::Verifier;

    let verif_cfg = config.verification.as_ref()?;
    if !verif_cfg.enabled {
        return None;
    }

    let mut verifiers = Vec::new();

    for key_path in &verif_cfg.trusted_key_paths {
        let key_bytes = match std::fs::read(key_path) {
            Ok(b) => b,
            Err(e) => {
                error!(path = %key_path, "failed to read trusted key: {e}");
                continue;
            }
        };

        let verifying_key = VerifyingKey::new(key_bytes);
        verifiers.push(Verifier::new(verifying_key));
        info!(path = %key_path, "loaded trusted verification key");
    }

    if verifiers.is_empty() {
        error!(
            "verification enabled but no trusted keys were loaded — \
             all signed messages will fail verification"
        );
    }

    let stage = syslog_relay::VerificationStage::new(verifiers, verif_cfg.reject_unverified);

    // Load persisted replay detector state if configured.
    if let Some(ref state_path) = verif_cfg.state_path {
        match std::fs::read_to_string(state_path) {
            Ok(data) => {
                stage.load_replay_state(&data);
                info!(
                    path = %state_path,
                    "loaded persisted replay detector state"
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(
                    path = %state_path,
                    "no persisted replay detector state file found, starting fresh"
                );
            }
            Err(e) => {
                warn!(
                    path = %state_path,
                    error = %e,
                    "failed to read replay detector state file, starting fresh"
                );
            }
        }
    }

    info!(
        keys = stage.verifier_count(),
        reject_unverified = verif_cfg.reject_unverified,
        "RFC 5848 verification stage enabled"
    );

    Some(stage)
}

/// Load the persisted RSID from `<state_dir>/rsid`, increment it, and write back.
/// If the file doesn't exist, starts at 1.
/// Returns `RebootSessionId::unpersisted()` on any error (with a warning log).
fn load_or_increment_rsid(state_dir: &str) -> syslog_sign::counter::RebootSessionId {
    use syslog_sign::counter::RebootSessionId;

    let dir = std::path::Path::new(state_dir);
    let rsid_path = dir.join("rsid");
    let tmp_path = dir.join("rsid.tmp");

    // Validate no directory traversal
    if state_dir.contains("..") {
        warn!(path = %state_dir, "state_dir contains '..' — using unpersisted RSID");
        return RebootSessionId::unpersisted();
    }

    // Read existing value (or default to 0)
    let current: u64 = match std::fs::read_to_string(&rsid_path) {
        Ok(contents) => match contents.trim().parse::<u64>() {
            Ok(v) => v,
            Err(e) => {
                warn!(path = %rsid_path.display(), "failed to parse RSID file: {e} — using unpersisted RSID");
                return RebootSessionId::unpersisted();
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => {
            warn!(path = %rsid_path.display(), "failed to read RSID file: {e} — using unpersisted RSID");
            return RebootSessionId::unpersisted();
        }
    };

    let next = current.saturating_add(1);

    // Ensure the directory exists
    if let Err(e) = std::fs::create_dir_all(dir) {
        warn!(path = %state_dir, "failed to create state directory: {e} — using unpersisted RSID");
        return RebootSessionId::unpersisted();
    }

    // Atomic write: write to tmp, then rename
    if let Err(e) = std::fs::write(&tmp_path, next.to_string()) {
        warn!(path = %tmp_path.display(), "failed to write RSID tmp file: {e} — using unpersisted RSID");
        return RebootSessionId::unpersisted();
    }
    if let Err(e) = std::fs::rename(&tmp_path, &rsid_path) {
        warn!(
            src = %tmp_path.display(),
            dst = %rsid_path.display(),
            "failed to rename RSID file: {e} — using unpersisted RSID"
        );
        return RebootSessionId::unpersisted();
    }

    match RebootSessionId::new(next) {
        Ok(rsid) => {
            info!(rsid = next, path = %rsid_path.display(), "persisted RSID loaded and incremented");
            rsid
        }
        Err(e) => {
            warn!(
                value = next,
                "RSID value out of range: {e} — using unpersisted RSID"
            );
            RebootSessionId::unpersisted()
        }
    }
}

/// Get the system hostname from the `HOSTNAME` environment variable.
///
/// Returns `None` if the variable is not set or empty.
fn gethostname() -> Option<String> {
    std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty())
}

/// Check that a private key file is not group/world readable.
///
/// On Unix, warns if the file mode allows group or other read access.
/// On non-Unix platforms this is a no-op.
fn check_key_file_permissions(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions().mode();
                // Check if group (0o040) or other (0o004) read bits are set
                if mode & 0o044 != 0 {
                    warn!(
                        path = %path,
                        mode = format!("{mode:04o}"),
                        "private key file is readable by group/other — \
                         recommend chmod 0600 for production use"
                    );
                }
            }
            Err(e) => {
                debug!(path = %path, "could not check key file permissions: {e}");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Build network outputs from configuration.
fn build_outputs(config: &ServerConfig) -> Vec<ServerOutput> {
    let mut outputs = Vec::new();

    for output_cfg in &config.outputs {
        let addr: SocketAddr = match output_cfg.address.parse() {
            Ok(a) => a,
            Err(e) => {
                error!(
                    name = %output_cfg.name,
                    address = %output_cfg.address,
                    "invalid output address: {e}"
                );
                continue;
            }
        };

        match output_cfg.protocol {
            OutputProtocol::Tcp | OutputProtocol::Udp => {
                // UDP outputs use the same TCP framing for simplicity in MVP;
                // a dedicated UDP sender can be added later.
                let proto_label = match output_cfg.protocol {
                    OutputProtocol::Udp => "udp",
                    OutputProtocol::Tcp => "tcp",
                    OutputProtocol::Tls => "tls",
                    OutputProtocol::Dtls => "dtls",
                };
                let output = NetworkOutput::tcp(&output_cfg.name, addr);
                info!(
                    name = %output_cfg.name,
                    addr = %addr,
                    proto = proto_label,
                    "output configured"
                );
                outputs.push(ServerOutput::Network(output));
            }
            OutputProtocol::Tls => {
                let tls_cfg = match &output_cfg.tls {
                    Some(t) => t,
                    None => {
                        error!(
                            name = %output_cfg.name,
                            "TLS output missing [tls] config section"
                        );
                        continue;
                    }
                };

                // Build client TLS config
                let mut root_store = rustls::RootCertStore::empty();

                // F-06: Load custom CA certificates if configured, otherwise
                // fall back to system/webpki default roots.
                if let Some(ca_path) = &tls_cfg.ca_path {
                    match load_certs(ca_path) {
                        Ok(ca_certs) => {
                            for cert in &ca_certs {
                                if let Err(e) = root_store.add(cert.clone()) {
                                    error!(
                                        name = %output_cfg.name,
                                        ca = %ca_path,
                                        err = %e,
                                        "failed to add custom CA cert to root store"
                                    );
                                }
                            }
                            info!(
                                name = %output_cfg.name,
                                ca = %ca_path,
                                count = ca_certs.len(),
                                "loaded custom CA certificates for output"
                            );
                        }
                        Err(e) => {
                            error!(
                                name = %output_cfg.name,
                                ca = %ca_path,
                                err = %e,
                                "failed to load custom CA certs, falling back to system roots"
                            );
                            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                        }
                    }
                } else {
                    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                }

                let client_config = rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                let connector = Arc::new(tokio_rustls::TlsConnector::from(Arc::new(client_config)));

                // Derive server name from address, handling IPv6 brackets
                let server_name = extract_host(&output_cfg.address);

                let output = NetworkOutput::tls(&output_cfg.name, addr, connector, server_name);
                info!(
                    name = %output_cfg.name,
                    addr = %addr,
                    "TLS output configured"
                );
                debug!(
                    name = %output_cfg.name,
                    cert = %tls_cfg.cert_path,
                    "TLS output certificate path"
                );
                outputs.push(ServerOutput::Network(output));
            }
            OutputProtocol::Dtls => {
                warn!(
                    name = %output_cfg.name,
                    "DTLS output not yet implemented (RFC 6012), skipping"
                );
                continue;
            }
        }
    }

    outputs
}

/// Wait for shutdown (SIGINT/SIGTERM) or reload (SIGHUP) signals.
///
/// On SIGHUP: re-reads the config file and applies runtime-reloadable
/// settings (log level). Changes to listeners, outputs, pipeline, signing,
/// verification, metrics, and management actions are detected and logged
/// but require a full restart to take effect.
///
/// On SIGINT/SIGTERM: returns so the caller can proceed with graceful shutdown.
#[cfg(unix)]
async fn wait_for_signals(
    config_path: &std::path::Path,
    log_reload: &LogReloadHandle,
    current_config: &ServerConfig,
) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            error!("failed to register SIGHUP handler: {e}");
            // Fall back to just waiting for ctrl-c
            match tokio::signal::ctrl_c().await {
                Ok(()) => info!("received shutdown signal"),
                Err(e) => error!("failed to listen for shutdown signal: {e}"),
            }
            return;
        }
    };

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("received shutdown signal");
                return;
            }
            _ = sighup.recv() => {
                info!("received SIGHUP — reloading configuration");
                reload_config(config_path, log_reload, current_config);
            }
        }
    }
}

/// Fallback for non-Unix platforms: just wait for ctrl-c.
#[cfg(not(unix))]
async fn wait_for_signals(
    _config_path: &std::path::Path,
    _log_reload: &LogReloadHandle,
    _current_config: &ServerConfig,
) {
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("received shutdown signal"),
        Err(e) => error!("failed to listen for shutdown signal: {e}"),
    }
}

/// Re-read the config file and apply runtime-reloadable settings.
///
/// Currently reloadable without restart:
/// - `logging.level`
///
/// All other configuration changes are detected and logged with a warning
/// indicating that a restart is required.
fn reload_config(
    config_path: &std::path::Path,
    log_reload: &LogReloadHandle,
    current_config: &ServerConfig,
) {
    let new_config = match syslog_config::load_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(path = %config_path.display(), "config reload failed: {e}");
            return;
        }
    };

    // Reload log level (hot-reloadable)
    if new_config.logging.level != current_config.logging.level {
        match log_reload.reload_level(&new_config.logging.level) {
            Ok(()) => info!(level = %new_config.logging.level, "log level reloaded"),
            Err(e) => error!("failed to reload log level: {e}"),
        }
    }

    // Detect changes that require a restart
    if new_config.listeners != current_config.listeners {
        warn!("listener configuration changed — restart required to apply");
    }
    if new_config.outputs != current_config.outputs {
        warn!("output configuration changed — restart required to apply");
    }
    if new_config.pipeline != current_config.pipeline {
        warn!("pipeline configuration changed — restart required to apply");
    }
    if new_config.signing != current_config.signing {
        warn!("signing configuration changed — restart required to apply");
    }
    if new_config.verification != current_config.verification {
        warn!("verification configuration changed — restart required to apply");
    }
    if new_config.metrics.bearer_token != current_config.metrics.bearer_token {
        warn!("metrics.bearer_token changed — restart required to apply");
    }
    if new_config.metrics.bind_address != current_config.metrics.bind_address {
        warn!("metrics.bind_address changed — restart required to apply");
    }
    if new_config.metrics.enabled != current_config.metrics.enabled {
        warn!("metrics.enabled changed — restart required to apply");
    }
    if new_config.server != current_config.server {
        warn!("server configuration changed — restart required to apply");
    }
    if new_config.actions != current_config.actions {
        warn!("actions configuration changed — restart required to apply");
    }
    if new_config.logging.format != current_config.logging.format {
        warn!("logging.format changed — restart required to apply");
    }

    info!("configuration reloaded successfully");
}

/// Sanitize an error message for logging: truncate to 200 chars and
/// replace control characters to prevent log injection.
fn sanitize_log_msg(msg: &str) -> String {
    msg.chars()
        .take(200)
        .map(|c| if c.is_control() && c != ' ' { '?' } else { c })
        .collect()
}

/// Extract the host portion from an address string.
/// Handles `host:port`, `[ipv6]:port`, and bare addresses.
fn extract_host(address: &str) -> &str {
    // Handle [ipv6]:port — strip brackets
    if let Some(rest) = address.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host;
        }
    }

    // Handle host:port — use rsplit_once to handle IPv6 without brackets
    if let Some((host, _port)) = address.rsplit_once(':') {
        return host;
    }

    address
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_truncates_long_messages() {
        let long = "a".repeat(300);
        let result = sanitize_log_msg(&long);
        assert_eq!(result.chars().count(), 200);
    }

    #[test]
    fn sanitize_replaces_control_chars() {
        let msg = "hello\nworld\x00bad";
        let result = sanitize_log_msg(msg);
        assert!(!result.contains('\n'));
        assert!(!result.contains('\x00'));
        assert!(result.contains("hello"));
    }

    #[test]
    fn extract_host_ipv4() {
        assert_eq!(extract_host("10.0.0.1:514"), "10.0.0.1");
    }

    #[test]
    fn extract_host_ipv6_bracketed() {
        assert_eq!(extract_host("[::1]:514"), "::1");
    }

    #[test]
    fn extract_host_hostname() {
        assert_eq!(extract_host("syslog.example.com:514"), "syslog.example.com");
    }

    #[test]
    fn extract_host_bare() {
        assert_eq!(extract_host("localhost"), "localhost");
    }

    #[test]
    fn load_or_increment_rsid_persists_and_increments() {
        let dir = std::env::temp_dir().join("syslog_rsid_test");
        // Clean up from any previous run
        let _ = std::fs::remove_dir_all(&dir);

        let dir_str = match dir.to_str() {
            Some(s) => s.to_owned(),
            None => return,
        };

        // First call: file doesn't exist, should start at 1
        let rsid1 = load_or_increment_rsid(&dir_str);
        assert_eq!(rsid1.value(), 1);

        // Second call: file contains "1", should increment to 2
        let rsid2 = load_or_increment_rsid(&dir_str);
        assert_eq!(rsid2.value(), 2);

        // Verify the file contains "2"
        let contents = match std::fs::read_to_string(dir.join("rsid")) {
            Ok(c) => c,
            Err(_) => return,
        };
        assert_eq!(contents, "2");

        // Clean up
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_increment_rsid_rejects_traversal() {
        let rsid = load_or_increment_rsid("/tmp/../etc/evil");
        assert_eq!(rsid.value(), 0);
    }
}
