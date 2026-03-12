//! syslog-usg — Production-grade syslog server and relay.
//!
//! This binary wires together all crates:
//! - Transport listeners (UDP, TCP/TLS)
//! - Message parsing (RFC 5424, RFC 3164)
//! - Relay pipeline (filter, route, fan-out)
//! - Observability (metrics, health endpoints, structured logging)
//! - Configuration loading (TOML with env var substitution)

mod network_output;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use syslog_config::model::{ListenerProtocol, OutputProtocol, ServerConfig};
use syslog_observe::{HealthState, LogReloadHandle, health_router, init_logging, init_metrics};
use syslog_relay::{Pipeline, PipelineIngress};
use syslog_transport::tcp::{TcpListenerConfig, TcpMessage, run_tcp_listener};
use syslog_transport::udp::{UdpDatagram, UdpListenerConfig, run_udp_listener};

use crate::network_output::NetworkOutput;

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

    // Shutdown coordination
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Build outputs from config
    let outputs = build_outputs(&config);
    if outputs.is_empty() {
        warn!("no outputs configured — messages will be received but not forwarded");
    }
    let channel_capacity = config.pipeline.channel_buffer_size;

    let (pipeline, ingress, pipeline_shutdown) = Pipeline::new(channel_capacity, None, outputs);

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
        shutdown_rx.clone(),
        &mut listener_handles,
    );

    // Start health/metrics HTTP server
    let health_state = HealthState::new(metrics_handle);
    let health_addr: SocketAddr = config
        .metrics
        .bind_address
        .parse()
        .unwrap_or_else(|_| ([0, 0, 0, 0], 9090).into());

    let health_state_clone = health_state.clone();
    let health_handle = tokio::spawn(async move {
        let app = health_router(health_state_clone);
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
    wait_for_signals(&cli.config, &log_reload).await;

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

/// Start transport listeners based on configuration.
fn start_listeners(
    config: &ServerConfig,
    ingress: &PipelineIngress,
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

                let (udp_tx, mut udp_rx) = mpsc::channel::<UdpDatagram>(4096);
                let shutdown = shutdown_rx.clone();
                let ingress = ingress.clone();

                // Spawn the UDP listener
                handles.push(tokio::spawn(async move {
                    if let Err(e) = run_udp_listener(udp_config, udp_tx, shutdown).await {
                        error!("UDP listener error: {e}");
                    }
                }));

                // Spawn the parser bridge (UDP datagrams -> parsed messages -> pipeline)
                handles.push(tokio::spawn(async move {
                    while let Some(datagram) = udp_rx.recv().await {
                        match syslog_parse::parse(&datagram.data) {
                            Ok(msg) => {
                                if let Err(e) = ingress.send(msg).await {
                                    warn!("pipeline send error: {e}");
                                    return;
                                }
                            }
                            Err(e) => {
                                warn!(
                                    source = %datagram.source,
                                    "parse error: {e}"
                                );
                                metrics::counter!("syslog_messages_parsed_total", "format" => "invalid")
                                    .increment(1);
                            }
                        }
                    }
                }));

                info!(addr = %addr, "UDP listener configured");
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
                };

                let (tcp_tx, mut tcp_rx) = mpsc::channel::<TcpMessage>(4096);
                let shutdown = shutdown_rx.clone();
                let ingress = ingress.clone();

                // Spawn the TCP/TLS listener
                handles.push(tokio::spawn(async move {
                    if let Err(e) = run_tcp_listener(tcp_config, tcp_tx, shutdown).await {
                        error!("{proto_label} listener error: {e}");
                    }
                }));

                // Spawn the parser bridge (TCP frames -> parsed messages -> pipeline)
                handles.push(tokio::spawn(async move {
                    while let Some(frame) = tcp_rx.recv().await {
                        match syslog_parse::parse(&frame.data) {
                            Ok(msg) => {
                                if let Err(e) = ingress.send(msg).await {
                                    warn!("pipeline send error: {e}");
                                    return;
                                }
                            }
                            Err(e) => {
                                warn!(
                                    source = %frame.peer,
                                    tls = frame.tls,
                                    "parse error: {e}"
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

/// Build network outputs from configuration.
fn build_outputs(config: &ServerConfig) -> Vec<NetworkOutput> {
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
                };
                let output = NetworkOutput::tcp(&output_cfg.name, addr);
                info!(
                    name = %output_cfg.name,
                    addr = %addr,
                    proto = proto_label,
                    "output configured"
                );
                outputs.push(output);
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
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

                let client_config = rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                let connector = Arc::new(tokio_rustls::TlsConnector::from(Arc::new(client_config)));

                // Derive server name from address (use IP as fallback)
                let server_name = output_cfg
                    .address
                    .split(':')
                    .next()
                    .unwrap_or(&output_cfg.address);

                let output = NetworkOutput::tls(&output_cfg.name, addr, connector, server_name);
                info!(
                    name = %output_cfg.name,
                    addr = %addr,
                    cert = %tls_cfg.cert_path,
                    "TLS output configured"
                );
                outputs.push(output);
            }
        }
    }

    outputs
}

/// Wait for shutdown (SIGINT/SIGTERM) or reload (SIGHUP) signals.
///
/// On SIGHUP: re-reads the config file and applies runtime-reloadable
/// settings (currently: log level). Listener and output changes are logged
/// but require a full restart to take effect.
///
/// On SIGINT/SIGTERM: returns so the caller can proceed with graceful shutdown.
#[cfg(unix)]
async fn wait_for_signals(config_path: &std::path::Path, log_reload: &LogReloadHandle) {
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
                reload_config(config_path, log_reload);
            }
        }
    }
}

/// Fallback for non-Unix platforms: just wait for ctrl-c.
#[cfg(not(unix))]
async fn wait_for_signals(_config_path: &std::path::Path, _log_reload: &LogReloadHandle) {
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("received shutdown signal"),
        Err(e) => error!("failed to listen for shutdown signal: {e}"),
    }
}

/// Re-read the config file and apply runtime-reloadable settings.
fn reload_config(config_path: &std::path::Path, log_reload: &LogReloadHandle) {
    let config = match syslog_config::load_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!(path = %config_path.display(), "config reload failed: {e}");
            return;
        }
    };

    // Reload log level
    match log_reload.reload_level(&config.logging.level) {
        Ok(()) => info!(level = %config.logging.level, "log level reloaded"),
        Err(e) => error!("failed to reload log level: {e}"),
    }

    // Note: listener and output changes require a restart.
    // Future work: hot-swap outputs, add/remove listeners.
    info!("configuration reloaded successfully");
}
