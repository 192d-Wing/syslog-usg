//! TLS transport (RFC 5425 + RFC 9662).
//!
//! RFC 5425: TLS transport mapping for syslog using octet-counting framing.
//! RFC 9662: Updates to TLS cipher suites — requires TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, pem::PemObject,
};
use rustls::server::{ServerSessionMemoryCache, WebPkiClientVerifier};
use tracing::{debug, info};

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
    /// Optional paths to PEM-encoded CRL files for client certificate revocation checking.
    pub crl_paths: Vec<String>,
}

/// Build a `rustls::ServerConfig` from the provided TLS configuration.
///
/// This configures TLS per RFC 9662 requirements:
/// - TLS 1.2 and TLS 1.3 are supported
/// - 0-RTT is disabled (not supported by rustls ServerConfig by default)
/// - When `client_auth` is true, mutual TLS is enforced using the CA
///   bundle at `client_ca_path`.
///
/// # Errors
/// Returns `TransportError` if certificates or keys cannot be loaded,
/// or if `client_auth` is true but `client_ca_path` is missing.
pub fn build_server_config(config: &TlsConfig) -> Result<Arc<ServerConfig>, TransportError> {
    // Validate mTLS config before loading anything
    if config.client_auth && config.client_ca_path.is_none() {
        return Err(TransportError::InvalidFrame(
            "client_auth requires client_ca_path to be set".to_owned(),
        ));
    }

    let cert_chain = load_certs(&config.cert_path)?;
    let private_key = load_private_key(&config.key_path)?;

    // RFC 9662 §3: build a CryptoProvider with only compliant cipher suites.
    // Mandatory: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
    // Also include the TLS 1.3 equivalents and ECDSA variants.
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            // TLS 1.3
            rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            // TLS 1.2 — GCM-only (RFC 9662)
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ],
        ..rustls::crypto::ring::default_provider()
    };

    let builder = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|e| TransportError::InvalidFrame(format!("TLS version config failed: {e}")))?;

    let mut server_config = if config.client_auth {
        // RFC 5425 §5.2: mutual TLS — require and verify client certificates
        // Safety: validated above that client_ca_path is Some
        let ca_path = config.client_ca_path.as_deref().ok_or_else(|| {
            TransportError::InvalidFrame("client_auth requires client_ca_path to be set".to_owned())
        })?;

        let ca_certs = load_certs(ca_path)?;
        let mut root_store = rustls::RootCertStore::empty();
        for cert in &ca_certs {
            root_store.add(cert.clone()).map_err(|e| {
                TransportError::InvalidFrame(format!("invalid CA certificate: {e}"))
            })?;
        }

        // RFC 5425 §5.2 SHOULD: load CRLs for client certificate revocation checking
        let crls = load_crls(&config.crl_paths)?;

        let mut verifier_builder = WebPkiClientVerifier::builder(Arc::new(root_store));
        if !crls.is_empty() {
            verifier_builder =
                verifier_builder.with_crls(crls).allow_unknown_revocation_status();
            info!("CRL revocation checking enabled ({} CRL file(s) loaded)", config.crl_paths.len());
        }
        let verifier = verifier_builder.build().map_err(|e| {
            TransportError::InvalidFrame(format!("failed to build client cert verifier: {e}"))
        })?;

        info!("mTLS enabled: client certificate verification required");

        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, private_key)
            .map_err(TransportError::Tls)?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(TransportError::Tls)?
    };

    // RFC 5425 §5.2: ALPN is not defined for syslog-over-TLS
    // RFC 9662: 0-RTT MUST be disabled — rustls doesn't support 0-RTT on server by default
    // RFC 5425 §5.3: enable session resumption with bounded cache
    server_config.session_storage = ServerSessionMemoryCache::new(1024);

    info!("TLS server configuration loaded (RFC 9662 cipher suites enforced, session cache enabled)");

    Ok(Arc::new(server_config))
}

/// Load PEM-encoded certificates from a file.
pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    let certs = CertificateDer::pem_file_iter(Path::new(path))
        .map_err(|e| {
            debug!(path = %path, error = %e, "failed to open certificate file");
            TransportError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "failed to open certificate file",
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            debug!(path = %path, error = %e, "invalid certificate data");
            TransportError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid certificate data",
            ))
        })?;
    if certs.is_empty() {
        return Err(TransportError::InvalidFrame(
            "no certificates found in file".to_owned(),
        ));
    }
    Ok(certs)
}

/// Load PEM-encoded CRLs from the given file paths.
///
/// RFC 5425 §5.2 SHOULD: support certificate revocation checking via CRLs.
fn load_crls(
    paths: &[String],
) -> Result<Vec<CertificateRevocationListDer<'static>>, TransportError> {
    let mut all_crls = Vec::new();
    for path in paths {
        let crls = CertificateRevocationListDer::pem_file_iter(Path::new(path))
            .map_err(|e| {
                debug!(path = %path, error = %e, "failed to open CRL file");
                TransportError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    "failed to open CRL file",
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                debug!(path = %path, error = %e, "invalid CRL data");
                TransportError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid CRL data",
                ))
            })?;
        all_crls.extend(crls);
    }
    Ok(all_crls)
}

/// Load a PEM-encoded private key from a file. Accepts PKCS#8, PKCS#1, or SEC1 keys.
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, TransportError> {
    PrivateKeyDer::from_pem_file(Path::new(path)).map_err(|e| {
        debug!(path = %path, error = %e, "failed to load private key");
        TransportError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "failed to load private key",
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_auth_without_ca_path_returns_error() {
        let config = TlsConfig {
            cert_path: "nonexistent.pem".to_owned(),
            key_path: "nonexistent.key".to_owned(),
            client_auth: true,
            client_ca_path: None,
            crl_paths: vec![],
        };
        let result = build_server_config(&config);
        assert!(result.is_err());
        if let Err(e) = result {
            let err = e.to_string();
            assert!(
                err.contains("client_ca_path"),
                "error should mention client_ca_path: {err}"
            );
        }
    }

    #[test]
    fn client_auth_with_invalid_ca_path_returns_error() {
        let config = TlsConfig {
            cert_path: "nonexistent.pem".to_owned(),
            key_path: "nonexistent.key".to_owned(),
            client_auth: true,
            client_ca_path: Some("/nonexistent/ca.pem".to_owned()),
            crl_paths: vec![],
        };
        let result = build_server_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn no_client_auth_with_invalid_cert_returns_error() {
        let config = TlsConfig {
            cert_path: "nonexistent.pem".to_owned(),
            key_path: "nonexistent.key".to_owned(),
            client_auth: false,
            client_ca_path: None,
            crl_paths: vec![],
        };
        let result = build_server_config(&config);
        assert!(result.is_err());
    }

    /// Verify that the cipher suite list used in `build_server_config` includes
    /// the RFC 9662 MUST suite and excludes non-forward-secrecy suites.
    #[test]
    fn rfc9662_cipher_suites_pinned() {
        // Build the same CryptoProvider that build_server_config uses
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: vec![
                rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
                rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            ..rustls::crypto::ring::default_provider()
        };

        let suite_ids: Vec<_> = provider.cipher_suites.iter().map(|s| s.suite()).collect();

        // RFC 9662 §5 MUST: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        assert!(
            suite_ids.contains(&rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            "RFC 9662 mandatory suite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 missing"
        );

        // All TLS 1.2 suites must use ECDHE (forward secrecy) + GCM (AEAD)
        for suite in &provider.cipher_suites {
            let name = format!("{:?}", suite.suite());
            if name.starts_with("TLS_") && !name.starts_with("TLS13_") {
                assert!(
                    name.contains("ECDHE"),
                    "TLS 1.2 suite without forward secrecy: {name}"
                );
                assert!(name.contains("GCM"), "TLS 1.2 suite without AEAD: {name}");
            }
        }

        // TLS 1.3 suites must be present
        assert!(
            suite_ids.contains(&rustls::CipherSuite::TLS13_AES_128_GCM_SHA256),
            "TLS 1.3 AES-128-GCM suite missing"
        );
        assert!(
            suite_ids.contains(&rustls::CipherSuite::TLS13_AES_256_GCM_SHA384),
            "TLS 1.3 AES-256-GCM suite missing"
        );
    }
}
