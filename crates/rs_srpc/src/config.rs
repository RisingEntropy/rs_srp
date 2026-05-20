//! Configuration types and validation for `rs_srpc`.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use srp_core::types::{ProxyKind, TransportKind};

// ── Top-level config ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub client: ClientSection,
    pub security: ClientSecurity,
    #[serde(default)]
    pub proxies: Vec<ProxyRule>,
}

// ── [client] section ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSection {
    pub server_host: String,
    pub transport_priority: Vec<TransportKind>,
    pub server_noise_pubkey: String,
    pub server_cert_fingerprint: String,
    pub transports: ClientTransports,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTransports {
    pub tcp: Option<ClientTcp>,
    pub quic: Option<ClientQuic>,
    pub wss: Option<ClientWss>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTcp {
    pub port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientQuic {
    pub port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientWss {
    pub port: u16,
    #[serde(default = "default_wss_path")]
    pub path: String,
}

fn default_wss_path() -> String {
    "/srp-tunnel".to_owned()
}

// ── [security] section ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSecurity {
    pub server_secret: String,
    pub username: String,
    pub token: String,
}

// ── [[proxies]] entries ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRule {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ProxyKind,
    pub local_addr: SocketAddr,
    pub remote_port: u16,
}

// ── Loading and validation ────────────────────────────────────────────────────

/// Load and validate a [`ClientConfig`] from the file at `path`.
pub fn load(path: &Path) -> anyhow::Result<ClientConfig> {
    // 1. File existence
    if !path.exists() {
        bail!("config file not found: {}", path.display());
    }

    // 2. Parse TOML
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file: {}", path.display()))?;
    let cfg: ClientConfig =
        toml::from_str(&raw).with_context(|| format!("parsing config file: {}", path.display()))?;

    // 3. Validate
    validate(&cfg)?;

    Ok(cfg)
}

fn validate(cfg: &ClientConfig) -> anyhow::Result<()> {
    let c = &cfg.client;

    // transport_priority must be non-empty
    if c.transport_priority.is_empty() {
        bail!("client.transport_priority must not be empty");
    }

    // Every transport listed in priority must have a matching [client.transports.X] block
    for kind in &c.transport_priority {
        let has_block = match kind {
            TransportKind::Tcp => c.transports.tcp.is_some(),
            TransportKind::Quic => c.transports.quic.is_some(),
            TransportKind::Wss => c.transports.wss.is_some(),
        };
        if !has_block {
            bail!(
                "transport '{}' is listed in transport_priority but has no \
                 [client.transports.{}] block",
                kind,
                kind
            );
        }
    }

    // server_host, server_noise_pubkey, server_cert_fingerprint must be non-empty
    if c.server_host.trim().is_empty() {
        bail!("client.server_host must not be empty");
    }
    if c.server_noise_pubkey.trim().is_empty() {
        bail!("client.server_noise_pubkey must not be empty");
    }
    if c.server_cert_fingerprint.trim().is_empty() {
        bail!("client.server_cert_fingerprint must not be empty");
    }

    // Proxy names must be unique
    let mut seen: HashSet<&str> = HashSet::new();
    for proxy in &cfg.proxies {
        if !seen.insert(proxy.name.as_str()) {
            bail!("duplicate proxy name: '{}'", proxy.name);
        }
    }

    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL_TOML: &str = r#"
[client]
server_host = "srp.example.com"
transport_priority = ["quic", "wss", "tcp"]
server_noise_pubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
server_cert_fingerprint = "sha256:0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd"

[client.transports.quic]
port = 7101

[client.transports.wss]
port = 7102
path = "/srp-tunnel"

[client.transports.tcp]
port = 7100

[security]
server_secret = "change-me-service-psk"
username = "alice"
token = "alice-secret-token"

[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 20022
"#;

    #[test]
    fn parse_canonical_config_succeeds() {
        let cfg: ClientConfig = toml::from_str(CANONICAL_TOML).expect("parse failed");
        assert_eq!(cfg.client.server_host, "srp.example.com");
        assert_eq!(
            cfg.client.transport_priority,
            vec![TransportKind::Quic, TransportKind::Wss, TransportKind::Tcp]
        );
        assert!(cfg.client.transports.quic.is_some());
        assert!(cfg.client.transports.wss.is_some());
        assert!(cfg.client.transports.tcp.is_some());
        assert_eq!(
            cfg.client.transports.wss.as_ref().unwrap().path,
            "/srp-tunnel"
        );
        assert_eq!(cfg.security.username, "alice");
        assert_eq!(cfg.proxies.len(), 1);
        assert_eq!(cfg.proxies[0].name, "ssh");
        assert_eq!(cfg.proxies[0].kind, ProxyKind::Tcp);
        assert_eq!(cfg.proxies[0].remote_port, 20022);
        // validate should also pass
        validate(&cfg).expect("validation failed");
    }

    #[test]
    fn missing_transport_block_is_rejected() {
        // Lists "tcp" in priority but has no [client.transports.tcp] block
        let bad_toml = r#"
[client]
server_host = "srp.example.com"
transport_priority = ["tcp"]
server_noise_pubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
server_cert_fingerprint = "sha256:0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd"

[client.transports.quic]
port = 7101

[security]
server_secret = "change-me-service-psk"
username = "alice"
token = "alice-secret-token"
"#;
        let cfg: ClientConfig = toml::from_str(bad_toml).expect("parse should succeed");
        let err = validate(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("tcp"),
            "error should mention tcp: {err}"
        );
    }

    #[test]
    fn empty_transport_priority_is_rejected() {
        let bad_toml = r#"
[client]
server_host = "srp.example.com"
transport_priority = []
server_noise_pubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
server_cert_fingerprint = "sha256:0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd"

[client.transports.tcp]
port = 7100

[security]
server_secret = "change-me-service-psk"
username = "alice"
token = "alice-secret-token"
"#;
        let cfg: ClientConfig = toml::from_str(bad_toml).expect("parse should succeed");
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("transport_priority"));
    }

    #[test]
    fn duplicate_proxy_names_rejected() {
        let bad_toml = r#"
[client]
server_host = "srp.example.com"
transport_priority = ["tcp"]
server_noise_pubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
server_cert_fingerprint = "sha256:0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd"

[client.transports.tcp]
port = 7100

[security]
server_secret = "change-me-service-psk"
username = "alice"
token = "alice-secret-token"

[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:22"
remote_port = 20022

[[proxies]]
name = "ssh"
type = "tcp"
local_addr = "127.0.0.1:8080"
remote_port = 20080
"#;
        let cfg: ClientConfig = toml::from_str(bad_toml).expect("parse should succeed");
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("ssh"));
    }

    #[test]
    fn wss_path_defaults_when_omitted() {
        let toml_no_path = r#"
[client]
server_host = "srp.example.com"
transport_priority = ["wss"]
server_noise_pubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
server_cert_fingerprint = "sha256:0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd"

[client.transports.wss]
port = 7102

[security]
server_secret = "change-me-service-psk"
username = "alice"
token = "alice-secret-token"
"#;
        let cfg: ClientConfig = toml::from_str(toml_no_path).expect("parse failed");
        assert_eq!(
            cfg.client.transports.wss.as_ref().unwrap().path,
            "/srp-tunnel"
        );
    }
}
