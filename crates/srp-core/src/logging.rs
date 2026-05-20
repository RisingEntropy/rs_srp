//! Process-wide logging setup.

use tracing_subscriber::EnvFilter;

/// Install the global tracing subscriber.
///
/// The level defaults to `info`, or `debug` when `verbose` is set; the
/// `RUST_LOG` environment variable, when present, overrides both.
pub fn init(verbose: bool) {
    let fallback = if verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(fallback));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
