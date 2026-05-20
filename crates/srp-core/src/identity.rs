//! Server identity: a self-signed TLS certificate (shared by the QUIC and WSS
//! transports) and a Noise static keypair (used by the `NKpsk0` handshake on
//! every transport).
//!
//! Both artifacts are generated once and then persisted under the server's
//! state directory, so the fingerprints a client pins stay stable across
//! restarts.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Noise parameters rs_srp uses. The keypair generated here is X25519.
const NOISE_PARAMS: &str = "Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s";

const TLS_CERT_FILE: &str = "tls_cert.pem";
const TLS_KEY_FILE: &str = "tls_key.pem";
const NOISE_PRIV_FILE: &str = "noise_static_priv.bin";
const NOISE_PUB_FILE: &str = "noise_static_pub.bin";

/// The server's long-lived cryptographic identity.
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    tls_cert_pem: String,
    tls_key_pem: String,
    noise_private: Vec<u8>,
    noise_public: Vec<u8>,
}

impl ServerIdentity {
    /// Load the identity from `state_dir`, generating and persisting any
    /// artifact that is missing. The directory is created if absent.
    ///
    /// The TLS keypair and the Noise keypair are handled independently, so a
    /// missing file is regenerated without rotating the other (already-pinned)
    /// artifact.
    pub fn load_or_create(state_dir: &Path) -> Result<ServerIdentity> {
        fs::create_dir_all(state_dir)
            .with_context(|| format!("creating state dir {}", state_dir.display()))?;

        let (tls_cert_pem, tls_key_pem) = load_or_create_tls(state_dir)?;
        let (noise_private, noise_public) = load_or_create_noise(state_dir)?;

        Ok(ServerIdentity {
            tls_cert_pem,
            tls_key_pem,
            noise_private,
            noise_public,
        })
    }

    /// PEM-encoded self-signed certificate (QUIC + WSS).
    pub fn tls_cert_pem(&self) -> &str {
        &self.tls_cert_pem
    }

    /// PEM-encoded private key for [`Self::tls_cert_pem`].
    pub fn tls_key_pem(&self) -> &str {
        &self.tls_key_pem
    }

    /// Raw 32-byte Noise static private key.
    pub fn noise_private_key(&self) -> &[u8] {
        &self.noise_private
    }

    /// Raw 32-byte Noise static public key.
    pub fn noise_public_key(&self) -> &[u8] {
        &self.noise_public
    }

    /// Base64 (standard alphabet) of the Noise static public key. This is the
    /// value a client pins as `server_noise_pubkey`.
    pub fn noise_public_key_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.noise_public)
    }

    /// SHA-256 fingerprint of the TLS certificate, formatted `sha256:<hex>`.
    /// This is the value a client pins as `server_cert_fingerprint`.
    pub fn cert_fingerprint(&self) -> Result<String> {
        let der = pem_to_der(&self.tls_cert_pem).context("decoding the stored TLS certificate")?;
        Ok(cert_fingerprint_from_der(&der))
    }
}

/// Format the `sha256:<hex>` fingerprint of a DER-encoded certificate. Both the
/// server (when reporting) and the client (when verifying a pinned cert) must
/// use this so the strings compare equal.
pub fn cert_fingerprint_from_der(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Decode a base64-encoded Noise public key — the `server_noise_pubkey` value
/// a client pins in its config.
pub fn decode_noise_public_key(b64: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("base64-decoding Noise public key")
}

fn load_or_create_tls(state_dir: &Path) -> Result<(String, String)> {
    let cert_path = state_dir.join(TLS_CERT_FILE);
    let key_path = state_dir.join(TLS_KEY_FILE);

    if cert_path.exists() && key_path.exists() {
        let cert = fs::read_to_string(&cert_path)
            .with_context(|| format!("reading {}", cert_path.display()))?;
        let key = fs::read_to_string(&key_path)
            .with_context(|| format!("reading {}", key_path.display()))?;
        return Ok((cert, key));
    }

    let certified = rcgen::generate_simple_self_signed(vec!["rs_srp".to_string()])
        .context("generating self-signed certificate")?;
    let cert_pem = certified.cert.pem();
    let key_pem = certified.signing_key.serialize_pem();

    write_public(&cert_path, cert_pem.as_bytes())?;
    write_secret(&key_path, key_pem.as_bytes())?;
    Ok((cert_pem, key_pem))
}

fn load_or_create_noise(state_dir: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let priv_path = state_dir.join(NOISE_PRIV_FILE);
    let pub_path = state_dir.join(NOISE_PUB_FILE);

    if priv_path.exists() && pub_path.exists() {
        let private =
            fs::read(&priv_path).with_context(|| format!("reading {}", priv_path.display()))?;
        let public =
            fs::read(&pub_path).with_context(|| format!("reading {}", pub_path.display()))?;
        return Ok((private, public));
    }

    let params = NOISE_PARAMS.parse().context("parsing Noise parameters")?;
    let keypair = snow::Builder::new(params)
        .generate_keypair()
        .context("generating Noise static keypair")?;

    write_secret(&priv_path, &keypair.private)?;
    write_public(&pub_path, &keypair.public)?;
    Ok((keypair.private, keypair.public))
}

/// Write a non-sensitive file.
fn write_public(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

/// Write a secret file with `0600` permissions on Unix.
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Extract the DER bytes of the first PEM block in `pem`.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut body = String::new();
    let mut inside = false;
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN ") {
            inside = true;
        } else if line.starts_with("-----END ") {
            break;
        } else if inside {
            body.push_str(line);
        }
    }
    anyhow::ensure!(!body.is_empty(), "no PEM block found");
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .context("base64-decoding PEM body")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_across_reload() {
        let dir = std::env::temp_dir().join(format!("rs_srp_id_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let first = ServerIdentity::load_or_create(&dir).unwrap();
        let second = ServerIdentity::load_or_create(&dir).unwrap();

        assert_eq!(
            first.cert_fingerprint().unwrap(),
            second.cert_fingerprint().unwrap(),
            "cert fingerprint must survive a reload",
        );
        assert_eq!(first.noise_public_key_b64(), second.noise_public_key_b64());
        assert!(first.cert_fingerprint().unwrap().starts_with("sha256:"));
        assert_eq!(first.noise_public_key().len(), 32);
        assert_eq!(first.noise_private_key().len(), 32);

        fs::remove_dir_all(&dir).unwrap();
    }
}
