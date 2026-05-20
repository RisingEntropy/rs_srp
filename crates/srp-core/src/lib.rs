//! Shared core for rs_srp (rust secure reverse proxy).
//!
//! As of milestone M0 this crate provides:
//! - [`identity`]: the server's persisted TLS certificate and Noise static
//!   keypair, plus certificate-fingerprint helpers used for pinning.
//! - [`logging`]: tracing setup shared by both binaries.
//! - [`types`]: protocol-level enums shared across the workspace.

pub mod identity;
pub mod logging;
pub mod types;
