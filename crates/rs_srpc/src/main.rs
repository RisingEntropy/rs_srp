//! rs_srpc — the SRP relay client binary.

mod cli;
mod client;
mod config;

use anyhow::Result;
use clap::Parser as _;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    srp_core::logging::init(cli.verbose);

    match cli.command {
        Commands::Run { config } => client::run(&config).await?,
    }
    Ok(())
}
