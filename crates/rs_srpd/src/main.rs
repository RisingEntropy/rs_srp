//! rs_srpd — the SRP relay server binary.
//!
//! Milestone M0: CLI, config parsing/validation, logging wiring, and the
//! `client-config` helper command.  No networking is implemented yet.

mod cli;
mod client_config;
mod config;

use anyhow::Result;
use clap::Parser as _;
use tracing::{info, warn};

use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => {
            // Init logging first so all subsequent output is structured.
            srp_core::logging::init(cli.verbose);
            cmd_run(&args, cli.verbose)?;
        }
        Commands::ClientConfig(args) => {
            // client-config is a tooling command; use plain logging.
            srp_core::logging::init(cli.verbose);
            let cfg = config::load(&args.config)?;
            client_config::run(&cfg, args.user.as_deref(), args.host.as_deref())?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// `run` subcommand
// ---------------------------------------------------------------------------

fn cmd_run(args: &cli::RunArgs, _verbose: bool) -> Result<()> {
    // Load + validate config.
    let cfg = config::load(&args.config)?;

    // Load (or create) the server identity.
    let identity = srp_core::identity::ServerIdentity::load_or_create(&cfg.state_dir)
        .map_err(|e| e.context("loading/creating server identity"))?;

    let noise_pubkey = identity.noise_public_key_b64();
    let cert_fingerprint = identity.cert_fingerprint()?;

    // Startup banner.
    info!("=== rs_srpd M0 startup ===");
    info!(noise_pubkey = %noise_pubkey, "server noise public key");
    info!(cert_fingerprint = %cert_fingerprint, "server TLS cert fingerprint");

    // Log each enabled transport.
    if let Some(quic) = &cfg.transports.quic {
        if quic.enabled {
            info!(transport = "quic", bind = %quic.bind, "transport enabled");
        }
    }
    if let Some(wss) = &cfg.transports.wss {
        if wss.enabled {
            info!(
                transport = "wss",
                bind = %wss.bind,
                path = %wss.path,
                "transport enabled"
            );
        }
    }
    if let Some(tcp) = &cfg.transports.tcp {
        if tcp.enabled {
            info!(transport = "tcp", bind = %tcp.bind, "transport enabled");
        }
    }

    info!(user_count = cfg.users.len(), "configured users");

    warn!("networking is not implemented in milestone M0 — exiting");
    Ok(())
}
