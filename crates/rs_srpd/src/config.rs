//! Server configuration: TOML schema, parsing, and validation.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Hostname advertised to clients via `client-config`. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_host: Option<String>,
    /// Directory where the server's cryptographic identity is persisted.
    pub state_dir: PathBuf,
    pub transports: Transports,
    pub security: Security,
    #[serde(default)]
    pub users: Vec<User>,
    /// Operations dashboard. Defaults to enabled on 127.0.0.1:1564.
    #[serde(default)]
    pub dashboard: DashboardConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Transports {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<TransportListener>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic: Option<TransportListener>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wss: Option<WssListener>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransportListener {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub bind: SocketAddr,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WssListener {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub bind: SocketAddr,
    #[serde(default = "default_wss_path")]
    pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Security {
    pub server_secret: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    pub token: String,
    #[serde(default)]
    pub allow_remote_ports: Vec<String>,
}

/// Operations dashboard configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Address the dashboard HTTP server binds. Default 127.0.0.1:1564 —
    /// loopback-only, so remote access goes through an SSH tunnel.
    #[serde(default = "default_dashboard_bind")]
    pub bind: SocketAddr,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        DashboardConfig {
            enabled: true,
            bind: default_dashboard_bind(),
        }
    }
}

fn default_dashboard_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 1564))
}

fn default_true() -> bool {
    true
}

fn default_wss_path() -> String {
    "/srp-tunnel".to_string()
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load and validate a [`ServerConfig`] from a TOML file.
pub fn load(path: &Path) -> Result<ServerConfig> {
    anyhow::ensure!(path.exists(), "config file not found: {}", path.display());

    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {}", path.display()))?;

    let config: ServerConfig =
        toml::from_str(&raw).with_context(|| format!("parsing config file {}", path.display()))?;

    validate(&config)?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate(cfg: &ServerConfig) -> Result<()> {
    // At least one transport must be present and enabled.
    let any_enabled = cfg
        .transports
        .tcp
        .as_ref()
        .map(|t| t.enabled)
        .unwrap_or(false)
        || cfg
            .transports
            .quic
            .as_ref()
            .map(|t| t.enabled)
            .unwrap_or(false)
        || cfg
            .transports
            .wss
            .as_ref()
            .map(|t| t.enabled)
            .unwrap_or(false);
    if !any_enabled {
        bail!("at least one transport ([transports.tcp], [transports.quic], or [transports.wss]) must be present and enabled");
    }

    // server_secret must be non-empty.
    if cfg.security.server_secret.is_empty() {
        bail!("security.server_secret must not be empty");
    }

    // User names must be unique.
    let mut seen_names = std::collections::HashSet::new();
    for user in &cfg.users {
        if !seen_names.insert(&user.name) {
            bail!("duplicate user name: {:?}", user.name);
        }
    }

    // Validate allow_remote_ports entries for every user.
    for user in &cfg.users {
        for entry in &user.allow_remote_ports {
            parse_port_range(entry).with_context(|| {
                format!(
                    "invalid allow_remote_ports entry {:?} for user {:?}",
                    entry, user.name
                )
            })?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Port-range parser
// ---------------------------------------------------------------------------

/// A validated port range. `lo == hi` for a single port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

/// Parse a single port-range string: either `"N"` or `"N-M"` (N ≤ M, both
/// valid u16 values). Returns an error with a helpful message on failure.
pub fn parse_port_range(s: &str) -> Result<PortRange> {
    if let Some((lo_str, hi_str)) = s.split_once('-') {
        let lo: u16 = lo_str
            .parse()
            .with_context(|| format!("low port {lo_str:?} is not a valid u16"))?;
        let hi: u16 = hi_str
            .parse()
            .with_context(|| format!("high port {hi_str:?} is not a valid u16"))?;
        if lo > hi {
            bail!("port range {s:?}: low port {lo} must be <= high port {hi}");
        }
        Ok(PortRange { lo, hi })
    } else {
        let port: u16 = s
            .parse()
            .with_context(|| format!("{s:?} is not a valid port number (u16)"))?;
        Ok(PortRange { lo: port, hi: port })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
public_host = "srp.example.com"
state_dir = "./srpd-state"

[transports.tcp]
enabled = true
bind = "0.0.0.0:7100"

[transports.quic]
enabled = true
bind = "0.0.0.0:7101"

[transports.wss]
enabled = true
bind = "0.0.0.0:7102"
path = "/srp-tunnel"

[security]
server_secret = "change-me-service-psk"

[[users]]
name = "alice"
token = "alice-secret-token"
allow_remote_ports = ["20000-21000"]

[[users]]
name = "bob"
token = "bob-secret-token"
allow_remote_ports = ["8080", "22000"]
"#;

    #[test]
    fn parses_valid_sample() {
        let cfg: ServerConfig = toml::from_str(SAMPLE_TOML).expect("should parse");
        validate(&cfg).expect("should be valid");

        assert_eq!(cfg.public_host.as_deref(), Some("srp.example.com"));
        assert_eq!(cfg.state_dir, PathBuf::from("./srpd-state"));
        assert_eq!(cfg.security.server_secret, "change-me-service-psk");

        let tcp = cfg.transports.tcp.as_ref().unwrap();
        assert!(tcp.enabled);
        assert_eq!(tcp.bind.port(), 7100);

        let quic = cfg.transports.quic.as_ref().unwrap();
        assert!(quic.enabled);
        assert_eq!(quic.bind.port(), 7101);

        let wss = cfg.transports.wss.as_ref().unwrap();
        assert!(wss.enabled);
        assert_eq!(wss.bind.port(), 7102);
        assert_eq!(wss.path, "/srp-tunnel");

        assert_eq!(cfg.users.len(), 2);
        assert_eq!(cfg.users[0].name, "alice");
        assert_eq!(cfg.users[1].name, "bob");
    }

    #[test]
    fn rejects_no_enabled_transports() {
        let bad = r#"
state_dir = "./state"

[security]
server_secret = "s3cret"

[transports.tcp]
enabled = false
bind = "0.0.0.0:7100"
"#;
        let cfg: ServerConfig = toml::from_str(bad).expect("should parse");
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_empty_server_secret() {
        let bad = r#"
state_dir = "./state"

[transports.tcp]
bind = "0.0.0.0:7100"

[security]
server_secret = ""
"#;
        let cfg: ServerConfig = toml::from_str(bad).expect("should parse");
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_duplicate_user_names() {
        let bad = r#"
state_dir = "./state"

[transports.tcp]
bind = "0.0.0.0:7100"

[security]
server_secret = "s3cret"

[[users]]
name = "alice"
token = "tok1"

[[users]]
name = "alice"
token = "tok2"
"#;
        let cfg: ServerConfig = toml::from_str(bad).expect("should parse");
        assert!(validate(&cfg).is_err());
    }

    // ----- port range parser -------------------------------------------------

    #[test]
    fn port_range_single() {
        let r = parse_port_range("8080").unwrap();
        assert_eq!(r, PortRange { lo: 8080, hi: 8080 });
    }

    #[test]
    fn port_range_range() {
        let r = parse_port_range("20000-21000").unwrap();
        assert_eq!(
            r,
            PortRange {
                lo: 20000,
                hi: 21000
            }
        );
    }

    #[test]
    fn port_range_inverted_is_error() {
        assert!(parse_port_range("21000-20000").is_err());
    }

    #[test]
    fn port_range_overflow_is_error() {
        assert!(parse_port_range("70000").is_err());
        assert!(parse_port_range("1-70000").is_err());
    }

    #[test]
    fn port_range_not_a_number_is_error() {
        assert!(parse_port_range("abc").is_err());
        assert!(parse_port_range("80-abc").is_err());
    }
}
