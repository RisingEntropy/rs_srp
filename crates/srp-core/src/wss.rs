//! WSS (WebSocket-over-TLS) tunnel transport.
//!
//! The stack is TCP → TLS → WebSocket. Each tunnel payload chunk travels as one
//! binary WebSocket message; [`WsStream`] adapts that message stream back into
//! an `AsyncRead + AsyncWrite` byte stream for the Noise session. The TLS
//! certificate is pinned exactly as for QUIC.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskCtx, Poll};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// A WebSocket connection presented as a byte stream.
pub struct WsStream<S> {
    ws: WebSocketStream<S>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl<S> WsStream<S> {
    fn new(ws: WebSocketStream<S>) -> Self {
        WsStream {
            ws,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.read_pos < me.read_buf.len() {
                let n = (me.read_buf.len() - me.read_pos).min(dst.remaining());
                dst.put_slice(&me.read_buf[me.read_pos..me.read_pos + n]);
                me.read_pos += n;
                return Poll::Ready(Ok(()));
            }
            match me.ws.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::other(e))),
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        me.read_buf = data.to_vec();
                        me.read_pos = 0;
                    }
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    // Ping/Pong are handled by tungstenite; Text is unexpected.
                    _ => continue,
                },
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        match me.ws.poll_ready_unpin(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(Ok(())) => {}
        }
        match me.ws.start_send_unpin(Message::binary(buf.to_vec())) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(io::Error::other(e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().ws.poll_flush_unpin(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().ws.poll_close_unpin(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Dial a WSS server: TCP, then a pinned TLS handshake, then the WebSocket
/// upgrade on `path`.
pub async fn wss_connect(
    addr: SocketAddr,
    server_name: &str,
    path: &str,
    cert_fingerprint: &str,
) -> Result<WsStream<tokio_rustls::client::TlsStream<TcpStream>>> {
    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting WSS transport to {addr}"))?;
    tcp.set_nodelay(true).ok();

    let tls_cfg = crate::tlspin::pinned_client_config(cert_fingerprint);
    let connector = TlsConnector::from(Arc::new(tls_cfg));
    let dns = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .context("invalid server name")?;
    let tls = connector
        .connect(dns, tcp)
        .await
        .context("WSS TLS handshake")?;

    let request = format!("ws://{server_name}{path}");
    let (ws, _resp) = tokio_tungstenite::client_async(request, tls)
        .await
        .context("WebSocket handshake")?;
    Ok(WsStream::new(ws))
}

/// A WSS listener for inbound tunnels.
pub struct WssListener {
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
}

impl WssListener {
    /// Bind a WSS listener presenting the server's self-signed certificate.
    pub async fn bind(addr: SocketAddr, cert_pem: &str, key_pem: &str) -> Result<WssListener> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding WSS listener on {addr}"))?;
        let tls = crate::tlspin::server_config(cert_pem, key_pem)?;
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        Ok(WssListener { listener, acceptor })
    }

    /// Accept the next inbound WSS tunnel.
    pub async fn accept(
        &self,
    ) -> Result<(
        WsStream<tokio_rustls::server::TlsStream<TcpStream>>,
        SocketAddr,
    )> {
        let (tcp, peer) = self.listener.accept().await.context("WSS TCP accept")?;
        tcp.set_nodelay(true).ok();
        let tls = self
            .acceptor
            .accept(tcp)
            .await
            .context("WSS TLS handshake")?;
        let ws = tokio_tungstenite::accept_async(tls)
            .await
            .context("WebSocket handshake")?;
        Ok((WsStream::new(ws), peer))
    }
}
