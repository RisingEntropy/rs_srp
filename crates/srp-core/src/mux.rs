//! Stream multiplexing over a single encrypted session, backed by yamux.
//!
//! Many proxied connections share one Noise tunnel: the control plane and every
//! data connection are yamux substreams. yamux framing therefore lives *inside*
//! the encryption and is invisible on the wire.
//!
//! yamux 0.13's `Connection` must be driven from one place, so a background
//! task owns it; [`Mux`] is a cheap handle that talks to that task.

use std::future::poll_fn;
use std::io;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// A multiplexed substream — a tokio `AsyncRead + AsyncWrite` byte stream.
pub type Substream = Compat<yamux::Stream>;

type OpenReq = oneshot::Sender<io::Result<Substream>>;

/// Handle to a running yamux connection.
pub struct Mux {
    open_tx: mpsc::UnboundedSender<OpenReq>,
    inbound_rx: mpsc::UnboundedReceiver<Substream>,
}

impl Mux {
    /// Multiplex `io` as the yamux client (the dialing peer).
    pub fn client<T>(io: T) -> Mux
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::spawn(io, yamux::Mode::Client)
    }

    /// Multiplex `io` as the yamux server (the accepting peer).
    pub fn server<T>(io: T) -> Mux
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::spawn(io, yamux::Mode::Server)
    }

    fn spawn<T>(io: T, mode: yamux::Mode) -> Mux
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let conn = yamux::Connection::new(io.compat(), yamux::Config::default(), mode);
        let (open_tx, open_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        tokio::spawn(drive(conn, open_rx, inbound_tx));
        Mux {
            open_tx,
            inbound_rx,
        }
    }

    /// Open a new outbound substream.
    pub async fn open(&self) -> io::Result<Substream> {
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .send(tx)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux connection closed"))?;
        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux connection closed"))?
    }

    /// Accept the next inbound substream, or `None` once the connection ends.
    pub async fn accept(&mut self) -> Option<Substream> {
        self.inbound_rx.recv().await
    }
}

/// Background task that owns the yamux connection: it accepts inbound
/// substreams and services outbound-open requests, one at a time.
async fn drive<T>(
    mut conn: yamux::Connection<Compat<T>>,
    mut open_rx: mpsc::UnboundedReceiver<OpenReq>,
    inbound_tx: mpsc::UnboundedSender<Substream>,
) where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut pending: Option<OpenReq> = None;

    poll_fn(|cx| {
        loop {
            // Service an in-flight open request.
            if let Some(reply) = pending.take() {
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(Ok(s)) => {
                        let _ = reply.send(Ok(s.compat()));
                    }
                    Poll::Ready(Err(e)) => {
                        let _ = reply.send(Err(io::Error::other(e.to_string())));
                    }
                    Poll::Pending => pending = Some(reply),
                }
            }

            // Pick up the next open request when not already busy with one.
            if pending.is_none() {
                match open_rx.poll_recv(cx) {
                    Poll::Ready(Some(reply)) => {
                        pending = Some(reply);
                        continue;
                    }
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
            }

            // Drive inbound substreams (this also pumps all substream I/O).
            match conn.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(s))) => {
                    if inbound_tx.send(s.compat()).is_err() {
                        return Poll::Ready(());
                    }
                    continue;
                }
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => return Poll::Ready(()),
                Poll::Pending => return Poll::Pending,
            }
        }
    })
    .await;

    let _ = poll_fn(|cx| conn.poll_close(cx)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn open_and_accept_roundtrip() {
        let (a, b) = tokio::io::duplex(8192);
        let client = Mux::client(a);
        let mut server = Mux::server(b);

        let srv = tokio::spawn(async move {
            let mut s = server.accept().await.expect("inbound substream");
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(b"pong").await.unwrap();
            s.flush().await.unwrap();
            buf
        });

        let mut s = client.open().await.unwrap();
        s.write_all(b"ping").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf, b"pong");
        assert_eq!(&srv.await.unwrap(), b"ping");
    }

    #[tokio::test]
    async fn many_concurrent_substreams() {
        let (a, b) = tokio::io::duplex(8192);
        let client = Mux::client(a);
        let mut server = Mux::server(b);

        tokio::spawn(async move {
            while let Some(mut s) = server.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4];
                    if s.read_exact(&mut buf).await.is_ok() {
                        let _ = s.write_all(&buf).await;
                        let _ = s.flush().await;
                    }
                });
            }
        });

        for i in 0u32..16 {
            let mut s = client.open().await.unwrap();
            let msg = i.to_be_bytes();
            s.write_all(&msg).await.unwrap();
            s.flush().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, msg);
        }
    }
}
