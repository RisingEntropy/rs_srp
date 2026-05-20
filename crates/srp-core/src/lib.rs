//! Shared core for rs_srp (rust secure reverse proxy).
//!
//! The encrypted tunnel is a stack of layers, innermost last:
//! - [`transport`] — a raw byte stream (TCP for now).
//! - [`session`] — a Noise `NKpsk0` session encrypting everything above it.
//! - [`mux`] — yamux multiplexing, so many connections share one tunnel.
//! - [`proto`] — the control-plane messages exchanged over a mux substream.
//!
//! [`identity`] holds the server's persisted keys and [`crypto`] derives the
//! Noise PSK from the shared password.

pub mod crypto;
pub mod identity;
pub mod logging;
pub mod mux;
pub mod proto;
pub mod session;
pub mod transport;
pub mod types;
