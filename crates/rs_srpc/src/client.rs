//! Relay client: dial the server, register proxies, forward connections.
//!
//! The client runs the Noise initiator handshake, wraps the session in yamux,
//! authenticates on the control substream, and registers each configured
//! proxy. The server then drives traffic by opening data substreams, which the
//! client relays to the matching local TCP or UDP service.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{copy_bidirectional, split, ReadHalf, WriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

use srp_core::identity;
use srp_core::mux::{Mux, Substream};
use srp_core::proto::{
    read_datagram, read_frame, write_datagram, write_frame, ControlMsg, DataHead,
};
use srp_core::session;
use srp_core::types::{ProxyKind, TransportKind};

use crate::config::{self, ClientConfig};

/// A UDP session with no traffic from the local service for this long is
/// dropped (the server enforces the same).
const UDP_IDLE: Duration = Duration::from_secs(60);

/// Run the client until the tunnel closes.
pub async fn run(config_path: &Path) -> Result<()> {
    let config = Arc::new(config::load(config_path)?);

    let psk = srp_core::crypto::derive_psk(&config.security.server_secret)?;
    let server_pub = identity::decode_noise_public_key(&config.client.server_noise_pubkey)?;

    // M1/M2 support only the tcp transport.
    if !config
        .client
        .transport_priority
        .contains(&TransportKind::Tcp)
    {
        bail!("only the tcp transport is supported so far; add \"tcp\" to transport_priority");
    }
    let tcp = config
        .client
        .transports
        .tcp
        .as_ref()
        .ok_or_else(|| anyhow!("a [client.transports.tcp] block is required"))?;
    let addr = format!("{}:{}", config.client.server_host, tcp.port);

    info!(server = %addr, "connecting to the relay server over the tcp transport");
    let stream = srp_core::transport::tcp_connect(&addr).await?;
    let noise = session::connect(stream, &server_pub, &psk)
        .await
        .context("noise handshake")?;
    info!("Noise session established");

    let mux = Mux::client(noise);
    let mut control = mux.open().await.context("opening control stream")?;

    // ---- authenticate ----
    write_frame(
        &mut control,
        &ControlMsg::Login {
            username: config.security.username.clone(),
            token: config.security.token.clone(),
        },
    )
    .await
    .context("sending login")?;
    match read_frame(&mut control)
        .await
        .context("reading login reply")?
    {
        ControlMsg::LoginOk => {
            info!(user = %config.security.username, "authenticated with the server")
        }
        ControlMsg::LoginErr { reason } => bail!("login rejected by server: {reason}"),
        other => bail!("unexpected reply to login: {other:?}"),
    }

    // ---- register proxies ----
    let mut active = 0usize;
    for proxy in &config.proxies {
        write_frame(
            &mut control,
            &ControlMsg::RegisterProxy {
                name: proxy.name.clone(),
                kind: proxy.kind,
                remote_port: proxy.remote_port,
            },
        )
        .await
        .context("sending proxy registration")?;
        match read_frame(&mut control)
            .await
            .context("reading registration reply")?
        {
            ControlMsg::RegisterOk { name, remote_port } => {
                active += 1;
                info!(proxy = %name, kind = %proxy.kind, remote_port, local = %proxy.local_addr, "proxy active");
            }
            ControlMsg::RegisterErr { name, reason } => {
                warn!(proxy = %name, reason = %reason, "proxy rejected by server")
            }
            other => bail!("unexpected reply to proxy registration: {other:?}"),
        }
    }
    info!(
        active,
        total = config.proxies.len(),
        "proxy registration complete"
    );

    // ---- keep the control stream drained (answer keep-alive pings) ----
    tokio::spawn(async move {
        loop {
            let msg: Result<ControlMsg> = read_frame(&mut control).await;
            match msg {
                Ok(ControlMsg::Ping) => {
                    if write_frame(&mut control, &ControlMsg::Pong).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => {
                    debug!("control stream closed");
                    break;
                }
            }
        }
    });

    // ---- relay data substreams opened by the server ----
    let mut mux = mux;
    info!("ready — waiting for proxied connections");
    while let Some(sub) = mux.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_data(sub, config).await {
                debug!(error = %format!("{e:#}"), "data connection ended");
            }
        });
    }

    info!("tunnel closed by the server");
    Ok(())
}

/// Relay one server-opened data substream to its local service.
async fn handle_data(mut sub: Substream, config: Arc<ClientConfig>) -> Result<()> {
    let head: DataHead = read_frame(&mut sub).await.context("reading data head")?;
    let proxy = config
        .proxies
        .iter()
        .find(|p| p.name == head.proxy)
        .ok_or_else(|| anyhow!("server referenced unknown proxy {:?}", head.proxy))?;
    let (kind, local_addr) = (proxy.kind, proxy.local_addr);

    match kind {
        ProxyKind::Tcp => {
            let mut local = TcpStream::connect(local_addr)
                .await
                .with_context(|| format!("connecting to local service {local_addr}"))?;
            local.set_nodelay(true).ok();
            debug!(proxy = %head.proxy, local = %local_addr, "tcp data connection established");
            copy_bidirectional(&mut local, &mut sub)
                .await
                .context("relaying tcp data")?;
        }
        ProxyKind::Udp => {
            debug!(proxy = %head.proxy, local = %local_addr, "udp session established");
            relay_udp(sub, local_addr).await?;
        }
    }
    Ok(())
}

/// Relay one UDP data substream to a local UDP service.
async fn relay_udp(sub: Substream, local_addr: SocketAddr) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("binding a local udp socket")?;
    socket
        .connect(local_addr)
        .await
        .with_context(|| format!("connecting udp socket to {local_addr}"))?;
    let socket = Arc::new(socket);

    let (reader, writer) = split(sub);
    let mut to_local = tokio::spawn(udp_tunnel_to_local(reader, socket.clone()));
    let mut to_tunnel = tokio::spawn(udp_local_to_tunnel(writer, socket));
    tokio::select! {
        _ = &mut to_local => to_tunnel.abort(),
        _ = &mut to_tunnel => to_local.abort(),
    }
    Ok(())
}

/// Substream → local UDP service.
async fn udp_tunnel_to_local(mut reader: ReadHalf<Substream>, socket: Arc<UdpSocket>) {
    while let Ok(dg) = read_datagram(&mut reader).await {
        if socket.send(&dg).await.is_err() {
            break;
        }
    }
}

/// Local UDP service → substream. An idle stretch ends the session.
async fn udp_local_to_tunnel(mut writer: WriteHalf<Substream>, socket: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 64 * 1024];
    while let Ok(Ok(n)) = timeout(UDP_IDLE, socket.recv(&mut buf)).await {
        if write_datagram(&mut writer, &buf[..n]).await.is_err() {
            break;
        }
    }
}
