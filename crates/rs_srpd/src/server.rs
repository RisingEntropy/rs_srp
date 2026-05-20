//! Relay server: accept encrypted tunnels and forward TCP and UDP traffic.
//!
//! For each client tunnel the server runs the Noise responder handshake, wraps
//! the session in yamux, authenticates the client on the control substream,
//! and binds a public port for every registered proxy. A TCP proxy gets a
//! `TcpListener`; a UDP proxy gets a `UdpSocket` whose datagrams are demuxed by
//! source address. Either way, traffic flows over per-connection data
//! substreams back to the client.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{copy_bidirectional, split, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

use srp_core::identity::ServerIdentity;
use srp_core::mux::{Mux, Substream};
use srp_core::proto::{
    read_datagram, read_frame, write_datagram, write_frame, ControlMsg, DataHead,
};
use srp_core::session;
use srp_core::types::ProxyKind;

use crate::config::{self, ServerConfig, User};

/// A UDP session with no traffic for this long is torn down.
const UDP_IDLE: Duration = Duration::from_secs(60);

/// Receive buffer large enough for any UDP datagram.
const UDP_BUF: usize = 64 * 1024;

/// Run the relay server until interrupted.
pub async fn run(config_path: &Path) -> Result<()> {
    let config = Arc::new(config::load(config_path)?);
    let identity = Arc::new(ServerIdentity::load_or_create(&config.state_dir)?);
    let psk = srp_core::crypto::derive_psk(&config.security.server_secret)?;

    info!(
        noise_pubkey = %identity.noise_public_key_b64(),
        users = config.users.len(),
        "server identity ready"
    );

    let tcp = config
        .transports
        .tcp
        .as_ref()
        .filter(|t| t.enabled)
        .ok_or_else(|| anyhow!("M1 requires the [transports.tcp] transport to be enabled"))?;

    let listener = srp_core::transport::tcp_listen(&tcp.bind.to_string()).await?;
    info!(bind = %tcp.bind, "listening for tunnels on the tcp transport");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "accepting a tunnel connection failed");
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        let config = config.clone();
        let identity = identity.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tunnel(stream, peer, config, identity, psk).await {
                warn!(%peer, error = %format!("{e:#}"), "tunnel ended with error");
            }
        });
    }
}

/// Handle one client tunnel for its whole lifetime.
async fn handle_tunnel(
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<ServerConfig>,
    identity: Arc<ServerIdentity>,
    psk: [u8; 32],
) -> Result<()> {
    info!(%peer, "tunnel connecting — starting Noise handshake");
    let noise = session::accept(stream, identity.noise_private_key(), &psk)
        .await
        .context("noise handshake")?;

    let mut mux = Mux::server(noise);
    let mut control = mux
        .accept()
        .await
        .ok_or_else(|| anyhow!("client opened no control stream"))?;
    let mux = Arc::new(mux);

    // ---- authenticate ----
    let (username, token) = match read_frame(&mut control).await.context("reading login")? {
        ControlMsg::Login { username, token } => (username, token),
        other => bail!("expected a Login message, got {other:?}"),
    };
    let user = match config
        .users
        .iter()
        .find(|u| u.name == username && u.token == token)
    {
        Some(u) => u.clone(),
        None => {
            warn!(%peer, user = %username, "authentication failed");
            write_frame(
                &mut control,
                &ControlMsg::LoginErr {
                    reason: "invalid username or token".to_string(),
                },
            )
            .await?;
            return Ok(());
        }
    };
    write_frame(&mut control, &ControlMsg::LoginOk).await?;
    info!(%peer, user = %user.name, "client authenticated");

    // ---- control loop ----
    let mut proxy_tasks: Vec<JoinHandle<()>> = Vec::new();
    loop {
        let msg: ControlMsg = match read_frame(&mut control).await {
            Ok(m) => m,
            Err(_) => {
                info!(%peer, user = %user.name, "control stream closed");
                break;
            }
        };
        match msg {
            ControlMsg::RegisterProxy {
                name,
                kind,
                remote_port,
            } => match register_proxy(&user, &name, kind, remote_port, &mux).await {
                Ok(handle) => {
                    proxy_tasks.push(handle);
                    info!(%peer, proxy = %name, kind = %kind, port = remote_port, "proxy registered");
                    write_frame(
                        &mut control,
                        &ControlMsg::RegisterOk {
                            name: name.clone(),
                            remote_port,
                        },
                    )
                    .await?;
                }
                Err(e) => {
                    warn!(%peer, proxy = %name, error = %e, "proxy registration rejected");
                    write_frame(
                        &mut control,
                        &ControlMsg::RegisterErr {
                            name,
                            reason: format!("{e}"),
                        },
                    )
                    .await?;
                }
            },
            ControlMsg::Ping => write_frame(&mut control, &ControlMsg::Pong).await?,
            other => debug!(?other, "ignoring unexpected control message"),
        }
    }

    // Tear down the public listeners bound for this tunnel.
    for handle in proxy_tasks {
        handle.abort();
    }
    Ok(())
}

/// Validate a proxy registration and bind its public port.
async fn register_proxy(
    user: &User,
    name: &str,
    kind: ProxyKind,
    remote_port: u16,
    mux: &Arc<Mux>,
) -> Result<JoinHandle<()>> {
    if !port_allowed(user, remote_port) {
        bail!(
            "remote port {remote_port} is not permitted for user {:?}",
            user.name
        );
    }
    match kind {
        ProxyKind::Tcp => {
            let listener = TcpListener::bind(("0.0.0.0", remote_port))
                .await
                .with_context(|| format!("binding public TCP port {remote_port}"))?;
            Ok(tokio::spawn(tcp_proxy_loop(
                listener,
                mux.clone(),
                name.to_string(),
            )))
        }
        ProxyKind::Udp => {
            let socket = UdpSocket::bind(("0.0.0.0", remote_port))
                .await
                .with_context(|| format!("binding public UDP port {remote_port}"))?;
            Ok(tokio::spawn(udp_proxy_loop(
                Arc::new(socket),
                mux.clone(),
                name.to_string(),
            )))
        }
    }
}

/// Whether `port` falls inside any of the user's permitted ranges. An empty
/// permit list denies everything.
fn port_allowed(user: &User, port: u16) -> bool {
    user.allow_remote_ports.iter().any(|entry| {
        config::parse_port_range(entry)
            .map(|r| port >= r.lo && port <= r.hi)
            .unwrap_or(false)
    })
}

// ── TCP proxy ──────────────────────────────────────────────────────────────

/// Accept public TCP connections for one proxy, one data substream per peer.
async fn tcp_proxy_loop(listener: TcpListener, mux: Arc<Mux>, proxy: String) {
    loop {
        let (user_stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(proxy = %proxy, error = %e, "public accept failed");
                break;
            }
        };
        user_stream.set_nodelay(true).ok();
        let mux = mux.clone();
        let proxy = proxy.clone();
        tokio::spawn(async move {
            debug!(proxy = %proxy, %peer, "public tcp connection accepted");
            if let Err(e) = serve_tcp_conn(user_stream, mux, &proxy).await {
                debug!(proxy = %proxy, %peer, error = %format!("{e:#}"), "tcp connection ended");
            }
        });
    }
}

/// Relay one public TCP connection to the client over a fresh data substream.
async fn serve_tcp_conn(mut user_stream: TcpStream, mux: Arc<Mux>, proxy: &str) -> Result<()> {
    let mut sub = mux.open().await.context("opening data substream")?;
    write_frame(
        &mut sub,
        &DataHead {
            proxy: proxy.to_string(),
        },
    )
    .await
    .context("sending data head")?;
    copy_bidirectional(&mut user_stream, &mut sub)
        .await
        .context("relaying data")?;
    Ok(())
}

// ── UDP proxy ──────────────────────────────────────────────────────────────

/// Receive UDP datagrams on a public port; demultiplex by source address into
/// one data substream (one logical session) per peer.
async fn udp_proxy_loop(socket: Arc<UdpSocket>, mux: Arc<Mux>, proxy: String) {
    let mut sessions: HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(proxy = %proxy, error = %e, "udp recv failed");
                break;
            }
        };
        let datagram = buf[..n].to_vec();

        // Route to an existing session; recover the datagram if it has exited.
        let datagram = match sessions.get(&src) {
            Some(tx) => match tx.send(datagram) {
                Ok(()) => continue,
                Err(e) => e.0,
            },
            None => datagram,
        };

        sessions.remove(&src);
        let sub = match mux.open().await {
            Ok(s) => s,
            Err(e) => {
                warn!(proxy = %proxy, error = %e, "opening udp substream failed");
                continue;
            }
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let _ = tx.send(datagram);
        sessions.insert(src, tx);
        debug!(proxy = %proxy, %src, "new udp session");
        tokio::spawn(udp_session(sub, proxy.clone(), rx, socket.clone(), src));
    }
}

/// Relay one UDP session: external datagrams ⇄ a data substream.
async fn udp_session(
    sub: Substream,
    proxy: String,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    socket: Arc<UdpSocket>,
    src: SocketAddr,
) {
    let (reader, writer) = split(sub);
    let mut to_peer = tokio::spawn(udp_tunnel_to_peer(reader, socket, src));
    let mut to_tunnel = tokio::spawn(udp_peer_to_tunnel(writer, proxy, rx));
    tokio::select! {
        _ = &mut to_peer => to_tunnel.abort(),
        _ = &mut to_tunnel => to_peer.abort(),
    }
    debug!(%src, "udp session ended");
}

/// Substream → external peer. An idle stretch ends the session.
async fn udp_tunnel_to_peer(
    mut reader: ReadHalf<Substream>,
    socket: Arc<UdpSocket>,
    src: SocketAddr,
) {
    while let Ok(Ok(dg)) = timeout(UDP_IDLE, read_datagram(&mut reader)).await {
        if socket.send_to(&dg, src).await.is_err() {
            break;
        }
    }
}

/// External peer → substream. The first frame is the `DataHead`.
async fn udp_peer_to_tunnel(
    mut writer: WriteHalf<Substream>,
    proxy: String,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    if write_frame(&mut writer, &DataHead { proxy }).await.is_err() {
        return;
    }
    while let Some(dg) = rx.recv().await {
        if write_datagram(&mut writer, &dg).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_with(ports: &[&str]) -> User {
        User {
            name: "u".to_string(),
            token: "t".to_string(),
            allow_remote_ports: ports.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn port_permission_respects_ranges() {
        let u = user_with(&["20000-21000", "8080"]);
        assert!(port_allowed(&u, 20000));
        assert!(port_allowed(&u, 20500));
        assert!(port_allowed(&u, 21000));
        assert!(port_allowed(&u, 8080));
        assert!(!port_allowed(&u, 19999));
        assert!(!port_allowed(&u, 9090));
    }

    #[test]
    fn empty_permit_list_denies_all() {
        assert!(!port_allowed(&user_with(&[]), 8080));
    }
}
