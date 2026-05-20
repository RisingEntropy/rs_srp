//! CLI definition using `clap` derive.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// rs_srpd — the SRP relay server.
#[derive(Debug, Parser)]
#[command(name = "rs_srpd", about = "SRP relay server (milestone M0)")]
pub struct Cli {
    /// Enable verbose (debug-level) logging.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start the relay server.
    Run(RunArgs),
    /// Print client configuration (srpc.toml).
    ClientConfig(ClientConfigArgs),
}

/// Arguments for the `run` subcommand.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Path to the server configuration file.
    #[arg(short, long, default_value = "srpd.toml")]
    pub config: PathBuf,
}

/// Arguments for the `client-config` subcommand.
#[derive(Debug, clap::Args)]
pub struct ClientConfigArgs {
    /// Path to the server configuration file.
    #[arg(short, long, default_value = "srpd.toml")]
    pub config: PathBuf,

    /// Generate a full srpc.toml for this user.
    #[arg(long)]
    pub user: Option<String>,

    /// Override the server host advertised in the client config.
    #[arg(long)]
    pub host: Option<String>,
}
