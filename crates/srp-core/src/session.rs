//! Noise-encrypted session layer.
//!
//! Wraps any byte stream in a `Noise_NKpsk0` session: the client authenticates
//! the server by its pinned static key, both prove the shared PSK, and all
//! subsequent traffic is encrypted with ChaCha20-Poly1305. The result is itself
//! an `AsyncRead + AsyncWrite` stream, so higher layers are oblivious to it.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context as TaskCtx, Poll};

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Noise pattern: NK (server static key pinned by the client) + psk0.
const NOISE_PARAMS: &str = "Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s";

/// A Noise message is at most 65535 bytes; 16 of them are the AEAD tag.
const MAX_PLAINTEXT: usize = 65535 - 16;

/// Run the handshake as the initiator (client side).
///
/// `server_static_pub` is the server's pinned Noise public key.
pub async fn connect<T>(
    mut io: T,
    server_static_pub: &[u8],
    psk: &[u8; 32],
) -> Result<NoiseStream<T>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let params = NOISE_PARAMS.parse().context("parsing noise params")?;
    let mut hs = snow::Builder::new(params)
        .remote_public_key(server_static_pub)
        .context("setting server static key")?
        .psk(0, psk)
        .context("setting psk")?
        .build_initiator()
        .context("building noise initiator")?;

    let mut scratch = [0u8; 65535];
    // -> psk, e, es
    let n = hs
        .write_message(&[], &mut scratch)
        .context("noise message 1")?;
    write_hs(&mut io, &scratch[..n]).await?;
    // <- e, ee
    let msg = read_hs(&mut io).await?;
    hs.read_message(&msg, &mut scratch)
        .context("noise message 2")?;

    let transport = hs
        .into_transport_mode()
        .context("entering transport mode")?;
    Ok(NoiseStream::new(io, transport))
}

/// Run the handshake as the responder (server side).
pub async fn accept<T>(
    mut io: T,
    server_static_priv: &[u8],
    psk: &[u8; 32],
) -> Result<NoiseStream<T>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let params = NOISE_PARAMS.parse().context("parsing noise params")?;
    let mut hs = snow::Builder::new(params)
        .local_private_key(server_static_priv)
        .context("setting server static key")?
        .psk(0, psk)
        .context("setting psk")?
        .build_responder()
        .context("building noise responder")?;

    let mut scratch = [0u8; 65535];
    // -> psk, e, es
    let msg = read_hs(&mut io).await?;
    hs.read_message(&msg, &mut scratch)
        .context("noise message 1")?;
    // <- e, ee
    let n = hs
        .write_message(&[], &mut scratch)
        .context("noise message 2")?;
    write_hs(&mut io, &scratch[..n]).await?;

    let transport = hs
        .into_transport_mode()
        .context("entering transport mode")?;
    Ok(NoiseStream::new(io, transport))
}

/// A handshake message, length-prefixed with a big-endian `u16`.
async fn write_hs<T: AsyncWrite + Unpin>(io: &mut T, msg: &[u8]) -> Result<()> {
    io.write_all(&(msg.len() as u16).to_be_bytes()).await?;
    io.write_all(msg).await?;
    io.flush().await?;
    Ok(())
}

async fn read_hs<T: AsyncRead + Unpin>(io: &mut T) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    io.read_exact(&mut len).await?;
    let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
    io.read_exact(&mut msg).await?;
    Ok(msg)
}

/// Read side of the record framer.
enum ReadState {
    /// Reading the 2-byte length prefix of the next record.
    Len { buf: [u8; 2], filled: usize },
    /// Reading the ciphertext body of a record.
    Body { buf: Vec<u8>, filled: usize },
}

/// A byte stream encrypted by an established Noise session.
///
/// Records are framed on the wire as a big-endian `u16` length followed by the
/// Noise ciphertext.
pub struct NoiseStream<T> {
    io: T,
    transport: snow::TransportState,
    read_state: ReadState,
    plaintext: Vec<u8>,
    plaintext_pos: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
}

impl<T> NoiseStream<T> {
    fn new(io: T, transport: snow::TransportState) -> Self {
        NoiseStream {
            io,
            transport,
            read_state: ReadState::Len {
                buf: [0; 2],
                filled: 0,
            },
            plaintext: Vec::new(),
            plaintext_pos: 0,
            write_buf: Vec::new(),
            write_pos: 0,
        }
    }
}

impl<T: AsyncWrite + Unpin> NoiseStream<T> {
    /// Flush any framed ciphertext still pending on the inner stream.
    fn poll_drain(&mut self, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let n =
                ready!(Pin::new(&mut self.io).poll_write(cx, &self.write_buf[self.write_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_pos += n;
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for NoiseStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            // Deliver buffered plaintext first.
            if me.plaintext_pos < me.plaintext.len() {
                let n = (me.plaintext.len() - me.plaintext_pos).min(dst.remaining());
                dst.put_slice(&me.plaintext[me.plaintext_pos..me.plaintext_pos + n]);
                me.plaintext_pos += n;
                return Poll::Ready(Ok(()));
            }

            let mut state = std::mem::replace(
                &mut me.read_state,
                ReadState::Len {
                    buf: [0; 2],
                    filled: 0,
                },
            );
            match &mut state {
                ReadState::Len { buf, filled } => {
                    let mut rb = ReadBuf::new(&mut buf[*filled..]);
                    match Pin::new(&mut me.io).poll_read(cx, &mut rb) {
                        Poll::Pending => {
                            me.read_state = state;
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            me.read_state = state;
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(())) => {
                            let got = rb.filled().len();
                            if got == 0 {
                                return if *filled == 0 {
                                    Poll::Ready(Ok(())) // clean EOF on a record boundary
                                } else {
                                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                                };
                            }
                            *filled += got;
                            if *filled == 2 {
                                let len = u16::from_be_bytes(*buf) as usize;
                                me.read_state = ReadState::Body {
                                    buf: vec![0u8; len],
                                    filled: 0,
                                };
                            } else {
                                me.read_state = state;
                            }
                        }
                    }
                }
                ReadState::Body { buf, filled } => {
                    if *filled < buf.len() {
                        let mut rb = ReadBuf::new(&mut buf[*filled..]);
                        match Pin::new(&mut me.io).poll_read(cx, &mut rb) {
                            Poll::Pending => {
                                me.read_state = state;
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => {
                                me.read_state = state;
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(())) => {
                                if rb.filled().is_empty() {
                                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                                }
                                *filled += rb.filled().len();
                            }
                        }
                    }
                    if *filled == buf.len() {
                        // `me.read_state` is already the fresh `Len` placeholder.
                        let ciphertext = std::mem::take(buf);
                        let mut out = vec![0u8; ciphertext.len().max(1)];
                        let n = me
                            .transport
                            .read_message(&ciphertext, &mut out)
                            .map_err(|e| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("noise decrypt: {e}"),
                                )
                            })?;
                        out.truncate(n);
                        me.plaintext = out;
                        me.plaintext_pos = 0;
                    } else {
                        me.read_state = state;
                    }
                }
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for NoiseStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // One record in flight at a time: drain the previous one first.
        ready!(me.poll_drain(cx))?;
        if src.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk = &src[..src.len().min(MAX_PLAINTEXT)];
        let mut frame = vec![0u8; 2 + chunk.len() + 16];
        let n = me
            .transport
            .write_message(chunk, &mut frame[2..])
            .map_err(|e| io::Error::other(format!("noise encrypt: {e}")))?;
        frame[..2].copy_from_slice(&(n as u16).to_be_bytes());
        frame.truncate(2 + n);
        me.write_buf = frame;
        me.write_pos = 0;

        // Best effort: the bytes are accepted regardless of whether the inner
        // stream takes them now, since they are buffered in `write_buf`.
        if let Poll::Ready(Err(e)) = me.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.poll_drain(cx))?;
        Pin::new(&mut me.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.poll_drain(cx))?;
        Pin::new(&mut me.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
        let kp = snow::Builder::new(params).generate_keypair().unwrap();
        (kp.private, kp.public)
    }

    #[tokio::test]
    async fn noise_roundtrip_over_duplex() {
        let (priv_key, pub_key) = keypair();
        let psk = [0x5a; 32];
        let (a, b) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let mut s = accept(b, &priv_key, &psk).await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(b"world").await.unwrap();
            s.flush().await.unwrap();
            buf
        });

        let mut client = connect(a, &pub_key, &psk).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0u8; 5];
        client.read_exact(&mut reply).await.unwrap();

        assert_eq!(&reply, b"world");
        assert_eq!(&server.await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn wrong_psk_fails_handshake() {
        let (priv_key, pub_key) = keypair();
        let (a, b) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move { accept(b, &priv_key, &[1u8; 32]).await.is_err() });
        let client_err = connect(a, &pub_key, &[2u8; 32]).await.is_err();

        assert!(
            client_err || server.await.unwrap(),
            "mismatched PSK must fail"
        );
    }

    #[tokio::test]
    async fn large_payload_spans_multiple_records() {
        let (priv_key, pub_key) = keypair();
        let psk = [0x11; 32];
        let (a, b) = tokio::io::duplex(4096);
        let payload: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let expected = payload.clone();

        let server = tokio::spawn(async move {
            let mut s = accept(b, &priv_key, &psk).await.unwrap();
            let mut buf = vec![0u8; expected.len()];
            s.read_exact(&mut buf).await.unwrap();
            buf == expected
        });

        let mut client = connect(a, &pub_key, &psk).await.unwrap();
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        assert!(server.await.unwrap(), "payload must survive record framing");
    }
}
