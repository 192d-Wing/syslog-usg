//! syslog-usg — Production-grade syslog server and relay.
//!
//! This binary wires together all crates:
//! - Transport listeners (UDP, TCP/TLS)
//! - Message parsing (RFC 5424, RFC 3164)
//! - Relay pipeline (filter, route, fan-out)
//! - Observability (metrics, health endpoints, structured logging)
//! - Configuration loading (TOML with env var substitution)

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use syslog_config::model::{ListenerProtocol, ServerConfig};
use syslog_observe::{HealthState, health_router, init_logging, init_metrics};
use syslog_relay::{ForwardOutput, Pipeline, PipelineIngress};
use syslog_transport::udp::{UdpDatagram, UdpListenerConfig, run_udp_listener};

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

    // Initialize logging
    let log_level = cli.log_level.as_deref().unwrap_or(&config.logging.level);
    if let Err(e) = init_logging(log_level) {
        eprintln!("error: failed to initialize logging: {e}");
        std::process::exit(1);
    }

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

    // Build the relay pipeline
    let output = ForwardOutput::new("default");
    let channel_capacity = config.pipeline.channel_buffer_size;

    let (pipeline, ingress, pipeline_shutdown) =
        Pipeline::new(channel_capacity, None, vec![output]);

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

    // Wait for shutdown signal (SIGTERM / SIGINT)
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("received shutdown signal"),
        Err(e) => error!("failed to listen for shutdown signal: {e}"),
    }

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
            ListenerProtocol::Tcp => {
                info!(addr = %addr, "TCP listener configured (not yet wired)");
            }
            ListenerProtocol::Tls => {
                info!(addr = %addr, "TLS listener configured (not yet wired)");
            }
        }
    }
}
