//! Control-plane protocol exchanged over multiplexed substreams.
//!
//! Frames are a 4-byte big-endian length prefix followed by a postcard-encoded
//! message. They travel inside the encrypted, multiplexed tunnel.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::types::ProxyKind;

/// Upper bound on a control frame. Messages are tiny; this only guards against
/// a corrupt or hostile length prefix.
const MAX_FRAME: usize = 64 * 1024;

/// Messages exchanged on the control substream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMsg {
    /// Client → server: authenticate as a configured user.
    Login {
        username: String,
        token: String,
    },
    /// Server → client: authentication accepted.
    LoginOk,
    /// Server → client: authentication rejected.
    LoginErr {
        reason: String,
    },
    /// Client → server: request a public port forwarding a local service.
    RegisterProxy {
        name: String,
        kind: ProxyKind,
        remote_port: u16,
    },
    /// Server → client: the proxy is live on `remote_port`.
    RegisterOk {
        name: String,
        remote_port: u16,
    },
    /// Server → client: the proxy could not be registered.
    RegisterErr {
        name: String,
        reason: String,
    },
    /// Keep-alive request / response.
    Ping,
    Pong,
}

/// First frame on every data substream: which proxy the substream serves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataHead {
    pub proxy: String,
}

/// Write one length-prefixed, postcard-encoded message.
pub async fn write_frame<W, M>(w: &mut W, msg: &M) -> Result<()>
where
    W: AsyncWrite + Unpin,
    M: Serialize,
{
    let bytes = postcard::to_stdvec(msg).context("serializing control frame")?;
    if bytes.len() > MAX_FRAME {
        bail!("control frame too large: {} bytes", bytes.len());
    }
    w.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed, postcard-encoded message.
pub async fn read_frame<R, M>(r: &mut R) -> Result<M>
where
    R: AsyncRead + Unpin,
    M: for<'de> Deserialize<'de>,
{
    let mut len = [0u8; 4];
    r.read_exact(&mut len)
        .await
        .context("reading frame length")?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("control frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.context("reading frame body")?;
    postcard::from_bytes(&buf).context("deserializing control frame")
}

/// Largest datagram payload that may be framed. UDP datagrams stay well under
/// this; the limit only guards against a corrupt length prefix.
const MAX_DATAGRAM: usize = 64 * 1024;

/// Write a raw datagram, length-prefixed with a big-endian `u32`.
///
/// A data substream serving a UDP proxy carries one framed datagram per call,
/// so packet boundaries survive the byte-stream tunnel.
pub async fn write_datagram<W>(w: &mut W, data: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if data.len() > MAX_DATAGRAM {
        bail!("datagram too large: {} bytes", data.len());
    }
    w.write_all(&(data.len() as u32).to_be_bytes()).await?;
    w.write_all(data).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed datagram written by [`write_datagram`].
pub async fn read_datagram<R>(r: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len = [0u8; 4];
    r.read_exact(&mut len)
        .await
        .context("reading datagram length")?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_DATAGRAM {
        bail!("datagram too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .await
        .context("reading datagram body")?;
    Ok(buf)
}
