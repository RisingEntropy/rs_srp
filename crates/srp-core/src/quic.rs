//! QUIC tunnel transport.
//!
//! Each QUIC connection carries one bidirectional stream, which — joined into a
//! single `AsyncRead + AsyncWrite` — is the byte stream the Noise session runs
//! over. QUIC supplies its own TLS 1.3; the certificate is pinned exactly as
//! for WSS.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskCtx, Poll};

use anyhow::{anyhow, Context, Result};
use tokio::io::{join, AsyncRead, AsyncWrite, Join, ReadBuf};

/// ALPN protocol identifier for rs_srp QUIC tunnels.
const ALPN: &[u8] = b"rs-srp/1";

/// A QUIC tunnel: one bidirectional stream presented as a byte stream. The
/// connection and endpoint are held alive for as long as the stream is used.
pub struct QuicStream {
    inner: Join<quinn::RecvStream, quinn::SendStream>,
    _conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Dial a QUIC server and open the tunnel's bidirectional stream.
pub async fn quic_connect(
    addr: SocketAddr,
    server_name: &str,
    cert_fingerprint: &str,
) -> Result<QuicStream> {
    let mut tls = crate::tlspin::pinned_client_config(cert_fingerprint);
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .context("building QUIC client crypto config")?;
    let client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut endpoint = quinn::Endpoint::client(bind).context("creating QUIC client endpoint")?;
    endpoint.set_default_client_config(client_cfg);

    let conn = endpoint
        .connect(addr, server_name)
        .context("starting QUIC connection")?
        .await
        .context("QUIC handshake")?;
    let (send, recv) = conn.open_bi().await.context("opening QUIC stream")?;

    Ok(QuicStream {
        inner: join(recv, send),
        _conn: conn,
        _endpoint: endpoint,
    })
}

/// A QUIC listener for inbound tunnels.
pub struct QuicListener {
    endpoint: quinn::Endpoint,
}

impl QuicListener {
    /// Bind a QUIC endpoint presenting the server's self-signed certificate.
    pub fn bind(addr: SocketAddr, cert_pem: &str, key_pem: &str) -> Result<QuicListener> {
        let mut tls = crate::tlspin::server_config(cert_pem, key_pem)?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .context("building QUIC server crypto config")?;
        let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        let endpoint =
            quinn::Endpoint::server(server_cfg, addr).context("creating QUIC server endpoint")?;
        Ok(QuicListener { endpoint })
    }

    /// Accept the next inbound QUIC tunnel.
    pub async fn accept(&self) -> Result<(QuicStream, SocketAddr)> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("QUIC endpoint closed"))?;
        let conn = incoming.await.context("QUIC handshake")?;
        let peer = conn.remote_address();
        let (send, recv) = conn.accept_bi().await.context("accepting QUIC stream")?;
        Ok((
            QuicStream {
                inner: join(recv, send),
                _conn: conn,
                _endpoint: self.endpoint.clone(),
            },
            peer,
        ))
    }
}
