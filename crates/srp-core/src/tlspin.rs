//! TLS configuration for the QUIC and WSS transports.
//!
//! There is no CA in the picture: the server presents its persisted
//! self-signed certificate, and the client accepts it only when its SHA-256
//! fingerprint matches the pinned value. This is the same pinning model the
//! `client-config` command bakes into `server_cert_fingerprint`.

use std::sync::{Arc, Once};

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, ServerConfig, SignatureScheme,
};

use crate::identity::cert_fingerprint_from_der;

static PROVIDER: Once = Once::new();

/// Install the ring crypto provider as the process default exactly once.
fn ensure_provider() {
    PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Build a rustls server config presenting the self-signed certificate.
pub fn server_config(cert_pem: &str, key_pem: &str) -> Result<ServerConfig> {
    ensure_provider();
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<std::result::Result<_, _>>()
        .context("parsing certificate PEM")?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("parsing private key PEM")?
        .context("no private key found in PEM")?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building rustls server config")
}

/// Build a rustls client config that accepts exactly the certificate whose
/// SHA-256 fingerprint equals `pinned` (formatted `sha256:<hex>`).
pub fn pinned_client_config(pinned: &str) -> ClientConfig {
    ensure_provider();
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
            pinned: pinned.to_string(),
        }))
        .with_no_client_auth()
}

/// A `ServerCertVerifier` that trusts one certificate, identified by its
/// SHA-256 fingerprint. Hostname and CA chain are intentionally irrelevant —
/// the pinned fingerprint is the whole identity check.
#[derive(Debug)]
struct PinnedVerifier {
    pinned: String,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        let actual = cert_fingerprint_from_der(end_entity.as_ref());
        if actual == self.pinned {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "server certificate fingerprint {actual} does not match pinned {}",
                self.pinned
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}
