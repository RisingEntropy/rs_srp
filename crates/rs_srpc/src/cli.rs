//! CLI definition for `rs_srpc`.

use clap::{Parser, Subcommand};

/// rs_srpc — NAT-traversal reverse proxy client (FRP-style relay model).
#[derive(Debug, Parser)]
#[command(name = "rs_srpc", version)]
pub struct Cli {
    /// Enable verbose (debug-level) logging.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start the client using a configuration file.
    Run {
        /// Path to the client configuration file.
        #[arg(short, long, default_value = "srpc.toml")]
        config: std::path::PathBuf,
    },
}
