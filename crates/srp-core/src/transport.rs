//! Raw transport layer — the byte stream the encrypted tunnel runs over.
//!
//! M1 ships only TCP. QUIC and WSS arrive in M3; this module is where they
//! will plug in.

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};

/// Dial a TCP tunnel transport.
pub async fn tcp_connect(addr: &str) -> Result<TcpStream> {
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting TCP transport to {addr}"))?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

/// Bind a TCP tunnel listener.
pub async fn tcp_listen(addr: &str) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding TCP transport listener on {addr}"))
}
