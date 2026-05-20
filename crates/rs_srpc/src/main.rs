mod cli;
mod config;

use anyhow::Context;
use clap::Parser;
use tracing::{info, warn};

use cli::{Cli, Commands};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            config: config_path,
        } => {
            // Load and validate config before initialising logging so that
            // TOML parse errors are printed without noise.
            let cfg = config::load(&config_path)
                .with_context(|| format!("failed to load config: {}", config_path.display()))?;

            // Initialise the global tracing subscriber.
            srp_core::logging::init(cli.verbose);

            // ── Startup banner ────────────────────────────────────────────────

            info!("rs_srpc starting (milestone M0)");
            info!(server_host = %cfg.client.server_host, "server host");

            let priority_str: Vec<String> = cfg
                .client
                .transport_priority
                .iter()
                .map(|t| t.to_string())
                .collect();
            info!(
                transport_priority = %priority_str.join(", "),
                "transport priority order"
            );

            // Per-transport endpoint details
            if let Some(tcp) = &cfg.client.transports.tcp {
                info!(
                    transport = "tcp",
                    host = %cfg.client.server_host,
                    port = tcp.port,
                    "transport endpoint"
                );
            }
            if let Some(quic) = &cfg.client.transports.quic {
                info!(
                    transport = "quic",
                    host = %cfg.client.server_host,
                    port = quic.port,
                    "transport endpoint"
                );
            }
            if let Some(wss) = &cfg.client.transports.wss {
                info!(
                    transport = "wss",
                    host = %cfg.client.server_host,
                    port = wss.port,
                    path = %wss.path,
                    "transport endpoint"
                );
            }

            // Pinned keys
            info!(
                server_noise_pubkey = %cfg.client.server_noise_pubkey,
                "pinned server Noise public key"
            );
            info!(
                server_cert_fingerprint = %cfg.client.server_cert_fingerprint,
                "pinned server TLS certificate fingerprint"
            );

            // Proxy rules
            if cfg.proxies.is_empty() {
                info!("no proxy rules configured");
            } else {
                for proxy in &cfg.proxies {
                    info!(
                        name = %proxy.name,
                        kind = %proxy.kind,
                        local_addr = %proxy.local_addr,
                        remote_port = proxy.remote_port,
                        "proxy rule"
                    );
                }
            }

            warn!("networking is not implemented in milestone M0 — exiting");
        }
    }

    Ok(())
}
