//! Implementation of the `client-config` subcommand.

use anyhow::{bail, Result};
use srp_core::identity::ServerIdentity;

use crate::config::ServerConfig;

/// Run `client-config` with an optional `--user` and optional `--host`.
///
/// - With `--user`: prints a full `srpc.toml` ready to save.
/// - Without `--user`: prints a human-readable identity card.
pub fn run(cfg: &ServerConfig, user_name: Option<&str>, host_override: Option<&str>) -> Result<()> {
    let identity = ServerIdentity::load_or_create(&cfg.state_dir)
        .map_err(|e| e.context("loading/creating server identity"))?;

    match user_name {
        Some(name) => print_srpc_toml(cfg, &identity, name, host_override),
        None => print_identity_card(cfg, &identity),
    }
}

// ---------------------------------------------------------------------------
// Full srpc.toml output
// ---------------------------------------------------------------------------

fn print_srpc_toml(
    cfg: &ServerConfig,
    identity: &ServerIdentity,
    user_name: &str,
    host_override: Option<&str>,
) -> Result<()> {
    // Find user entry.
    let user = cfg.users.iter().find(|u| u.name == user_name);
    let user = match user {
        Some(u) => u,
        None => {
            let names: Vec<&str> = cfg.users.iter().map(|u| u.name.as_str()).collect();
            bail!(
                "user {:?} not found; available users: {}",
                user_name,
                if names.is_empty() {
                    "(none configured)".to_string()
                } else {
                    names.join(", ")
                }
            );
        }
    };

    let server_host = resolve_host(cfg, host_override);
    let host_placeholder = host_override.is_none() && cfg.public_host.is_none();

    let noise_pubkey = identity.noise_public_key_b64();
    let cert_fingerprint = identity.cert_fingerprint()?;

    // Collect enabled transports in priority order: quic, wss, tcp.
    let has_quic = cfg
        .transports
        .quic
        .as_ref()
        .map(|t| t.enabled)
        .unwrap_or(false);
    let has_wss = cfg
        .transports
        .wss
        .as_ref()
        .map(|t| t.enabled)
        .unwrap_or(false);
    let has_tcp = cfg
        .transports
        .tcp
        .as_ref()
        .map(|t| t.enabled)
        .unwrap_or(false);

    let mut priority = Vec::new();
    if has_quic {
        priority.push("quic");
    }
    if has_wss {
        priority.push("wss");
    }
    if has_tcp {
        priority.push("tcp");
    }
    let priority_str = priority
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let mut out = String::new();

    // Header comment block.
    out.push_str("# srpc.toml — client configuration for rs_srpc\n");
    out.push_str("#\n");
    out.push_str("# WARNING: this file contains secrets (token, server_secret).\n");
    out.push_str("# Save it as srpc.toml and restrict its permissions (chmod 600).\n");
    out.push_str("#\n");
    if host_placeholder {
        out.push_str(
            "# NOTE: server_host is a placeholder — fill in the server's public address.\n",
        );
        out.push_str("#\n");
    }

    // [client]
    out.push_str("[client]\n");
    out.push_str(&format!("server_host = \"{server_host}\"\n"));
    out.push_str(&format!("transport_priority = [{priority_str}]\n"));
    out.push_str(&format!("server_noise_pubkey = \"{noise_pubkey}\"\n"));
    out.push_str(&format!(
        "server_cert_fingerprint = \"{cert_fingerprint}\"\n"
    ));
    out.push('\n');

    // [client.transports.*] — one block per enabled transport.
    if has_quic {
        let quic = cfg.transports.quic.as_ref().unwrap();
        out.push_str("[client.transports.quic]\n");
        out.push_str(&format!("port = {}\n", quic.bind.port()));
        out.push('\n');
    }
    if has_wss {
        let wss = cfg.transports.wss.as_ref().unwrap();
        out.push_str("[client.transports.wss]\n");
        out.push_str(&format!("port = {}\n", wss.bind.port()));
        out.push_str(&format!("path = \"{}\"\n", wss.path));
        out.push('\n');
    }
    if has_tcp {
        let tcp = cfg.transports.tcp.as_ref().unwrap();
        out.push_str("[client.transports.tcp]\n");
        out.push_str(&format!("port = {}\n", tcp.bind.port()));
        out.push('\n');
    }

    // [security]
    out.push_str("[security]\n");
    out.push_str(&format!(
        "server_secret = \"{}\"\n",
        cfg.security.server_secret
    ));
    out.push_str(&format!("username = \"{}\"\n", user.name));
    out.push_str(&format!("token = \"{}\"\n", user.token));
    out.push('\n');

    // Example [[proxies]] block.
    out.push_str("# Edit the proxy entries below to match your services.\n");
    out.push_str("# Each [[proxies]] block forwards one local port to the server.\n");
    out.push_str("[[proxies]]\n");
    out.push_str("name = \"ssh\"\n");
    out.push_str("type = \"tcp\"\n");
    out.push_str("local_addr = \"127.0.0.1:22\"\n");
    out.push_str("remote_port = 20022\n");

    print!("{out}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Identity card output (no --user)
// ---------------------------------------------------------------------------

fn print_identity_card(cfg: &ServerConfig, identity: &ServerIdentity) -> Result<()> {
    let cert_fingerprint = identity.cert_fingerprint()?;
    let noise_pubkey = identity.noise_public_key_b64();

    println!("=== rs_srpd server identity ===");
    println!();

    match &cfg.public_host {
        Some(h) => println!("  public_host          : {h}"),
        None => println!("  public_host          : (not configured)"),
    }
    println!("  noise_public_key     : {noise_pubkey}");
    println!("  cert_fingerprint     : {cert_fingerprint}");
    println!();

    println!("  Enabled transports:");
    if let Some(quic) = &cfg.transports.quic {
        if quic.enabled {
            println!("    quic   bind={}", quic.bind);
        }
    }
    if let Some(wss) = &cfg.transports.wss {
        if wss.enabled {
            println!("    wss    bind={}  path={}", wss.bind, wss.path);
        }
    }
    if let Some(tcp) = &cfg.transports.tcp {
        if tcp.enabled {
            println!("    tcp    bind={}", tcp.bind);
        }
    }
    println!();

    let user_names: Vec<&str> = cfg.users.iter().map(|u| u.name.as_str()).collect();
    if user_names.is_empty() {
        println!("  Configured users     : (none)");
    } else {
        println!("  Configured users     : {}", user_names.join(", "));
    }
    println!();
    println!("Hint: re-run with `--user <name>` to generate a full srpc.toml.");

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Determine the server_host value for the client config.
fn resolve_host<'a>(cfg: &'a ServerConfig, host_override: Option<&'a str>) -> &'a str {
    if let Some(h) = host_override {
        return h;
    }
    if let Some(ref h) = cfg.public_host {
        return h.as_str();
    }
    "<server-public-host>"
}
