//! rs_srpd — the SRP relay server binary.
//!
//! Subcommands: `run` (start the relay + dashboard) and `client-config` (emit
//! a client configuration). See the `cli` module for argument definitions.

mod cli;
mod client_config;
mod config;
mod dashboard;
mod metrics;
mod server;

use anyhow::Result;
use clap::Parser as _;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    srp_core::logging::init(cli.verbose);

    match cli.command {
        Commands::Run(args) => server::run(&args.config).await?,
        Commands::ClientConfig(args) => {
            let cfg = config::load(&args.config)?;
            client_config::run(&cfg, args.user.as_deref(), args.host.as_deref())?;
        }
    }
    Ok(())
}
