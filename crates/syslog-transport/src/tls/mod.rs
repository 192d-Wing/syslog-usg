//! TLS transport (RFC 5425 + RFC 9662).
//!
//! RFC 5425: TLS transport mapping for syslog using octet-counting framing.
//! RFC 9662: Updates to TLS cipher suites — requires TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tracing::info;

use crate::error::TransportError;

/// TLS configuration for a syslog server.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to the PEM-encoded certificate chain file.
    pub cert_path: String,
    /// Path to the PEM-encoded private key file.
    pub key_path: String,
    /// Whether to require client certificates (mutual TLS).
    pub client_auth: bool,
    /// Optional path to the CA certificate for client verification.
    pub client_ca_path: Option<String>,
}

/// Build a `rustls::ServerConfig` from the provided TLS configuration.
///
/// This configures TLS per RFC 9662 requirements:
/// - TLS 1.2 and TLS 1.3 are supported
/// - 0-RTT is disabled (not supported by rustls ServerConfig by default)
///
/// # Errors
/// Returns `TransportError` if certificates or keys cannot be loaded.
pub fn build_server_config(config: &TlsConfig) -> Result<Arc<ServerConfig>, TransportError> {
    let cert_chain = load_certs(&config.cert_path)?;
    let private_key = load_private_key(&config.key_path)?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(TransportError::Tls)?;

    // RFC 5425 §5.2: ALPN is not defined for syslog-over-TLS
    // RFC 9662: 0-RTT MUST be disabled — rustls doesn't support 0-RTT on server by default

    info!("TLS server configuration loaded");

    Ok(Arc::new(server_config))
}

/// Load PEM-encoded certificates from a file.
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    let file = std::fs::File::open(Path::new(path)).map_err(|e| {
        TransportError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("cert file {path}: {e}"),
        ))
    })?;
    let mut reader = io::BufReader::new(file);
    let certs_result: Result<Vec<_>, _> = certs(&mut reader).collect();
    let certs = certs_result.map_err(|e| {
        TransportError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid cert: {e}"),
        ))
    })?;
    if certs.is_empty() {
        return Err(TransportError::InvalidFrame(
            "no certificates found in file".to_owned(),
        ));
    }
    Ok(certs)
}

/// Load a PEM-encoded private key from a file. Tries PKCS#8 first, then RSA.
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, TransportError> {
    let file = std::fs::File::open(Path::new(path)).map_err(|e| {
        TransportError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("key file {path}: {e}"),
        ))
    })?;
    let mut reader = io::BufReader::new(file);

    // Try PKCS#8 first
    let pkcs8_keys: Result<Vec<_>, _> = pkcs8_private_keys(&mut reader).collect();
    if let Ok(keys) = pkcs8_keys {
        if let Some(key) = keys.into_iter().next() {
            return Ok(PrivateKeyDer::Pkcs8(key));
        }
    }

    // Rewind and try RSA
    let file = std::fs::File::open(Path::new(path)).map_err(|e| {
        TransportError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("key file {path}: {e}"),
        ))
    })?;
    let mut reader = io::BufReader::new(file);
    let rsa_keys: Result<Vec<_>, _> = rsa_private_keys(&mut reader).collect();
    if let Ok(keys) = rsa_keys {
        if let Some(key) = keys.into_iter().next() {
            return Ok(PrivateKeyDer::Pkcs1(key));
        }
    }

    Err(TransportError::InvalidFrame(
        "no private key found in file".to_owned(),
    ))
}
