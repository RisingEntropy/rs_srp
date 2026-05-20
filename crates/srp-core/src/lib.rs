//! Shared core for rs_srp (rust secure reverse proxy).
//!
//! The encrypted tunnel is a stack of layers, innermost last:
//! - [`transport`] / [`quic`] / [`wss`] — a raw byte stream over TCP, QUIC, or
//!   WSS.
//! - [`session`] — a Noise `NKpsk0` session encrypting everything above it.
//! - [`mux`] — yamux multiplexing, so many connections share one tunnel.
//! - [`proto`] — the control-plane messages exchanged over a mux substream.
//!
//! [`identity`] holds the server's persisted keys, [`crypto`] derives the
//! Noise PSK from the shared password, and [`tlspin`] supplies the pinned TLS
//! configuration QUIC and WSS share.

pub mod crypto;
pub mod identity;
pub mod logging;
pub mod mux;
pub mod proto;
pub mod quic;
pub mod session;
pub mod tlspin;
pub mod transport;
pub mod types;
pub mod wss;
