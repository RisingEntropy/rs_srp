//! Relay server: accept encrypted tunnels over TCP / QUIC / WSS and forward
//! TCP and UDP traffic.
//!
//! Every enabled transport gets its own accept loop; each accepted byte stream
//! runs the same Noise + yamux + control-protocol stack. Traffic flows over
//! per-connection data substreams, counted into the shared [`Metrics`] that the
//! dashboard reads. The server config is held behind a lock so the dashboard
//! can hot-reload user changes.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{copy_bidirectional, split, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout, Duration};
use tracing::{debug, info, warn};

use srp_core::identity::ServerIdentity;
use srp_core::mux::{Mux, Substream};
use srp_core::proto::{
    read_datagram, read_frame, write_datagram, write_frame, ControlMsg, DataHead,
};
use srp_core::quic::QuicListener;
use srp_core::session;
use srp_core::types::ProxyKind;
use srp_core::wss::WssListener;

use crate::config::{self, ServerConfig, User};
use crate::metrics::{ConnGuard, Counters, CountingStream, Metrics};

/// The server config, swappable so the dashboard can hot-reload edits. New
/// tunnels read the current snapshot; in-flight tunnels keep their own.
pub type SharedConfig = Arc<RwLock<Arc<ServerConfig>>>;

/// A UDP session with no traffic for this long is torn down.
const UDP_IDLE: Duration = Duration::from_secs(60);
/// Receive buffer large enough for any UDP datagram.
const UDP_BUF: usize = 64 * 1024;
/// No control-stream activity for this long means the client is gone. Clients
/// send a keep-alive `Ping` every 15s, so this is a generous 3× margin.
const CONTROL_IDLE: Duration = Duration::from_secs(45);

/// Run the relay server until interrupted.
pub async fn run(config_path: &Path) -> Result<()> {
    let initial = config::load(config_path)?;
    let identity = Arc::new(ServerIdentity::load_or_create(&initial.state_dir)?);
    let psk = srp_core::crypto::derive_psk(&initial.security.server_secret)?;
    let metrics = Metrics::new(&initial.state_dir);
    let shared: SharedConfig = Arc::new(RwLock::new(Arc::new(initial)));
    let cfg = shared.read().unwrap().clone();

    info!(
        noise_pubkey = %identity.noise_public_key_b64(),
        users = cfg.users.len(),
        "server identity ready"
    );

    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    // History sampler: snapshot traffic every 10s, persist every minute.
    {
        let metrics = metrics.clone();
        tasks.push(tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(10));
            let mut n = 0u64;
            loop {
                tick.tick().await;
                metrics.sample();
                n += 1;
                if n.is_multiple_of(6) {
                    metrics.persist();
                }
            }
        }));
    }

    // Dashboard.
    if cfg.dashboard.enabled {
        let bind = cfg.dashboard.bind;
        let fut = crate::dashboard::serve(
            bind,
            metrics.clone(),
            shared.clone(),
            identity.clone(),
            config_path.to_path_buf(),
        );
        info!(%bind, "operations dashboard listening");
        tasks.push(tokio::spawn(async move {
            if let Err(e) = fut.await {
                warn!(error = %format!("{e:#}"), "dashboard server stopped");
            }
        }));
    }

    // Transport accept loops.
    if let Some(t) = cfg.transports.tcp.as_ref().filter(|t| t.enabled) {
        let listener = srp_core::transport::tcp_listen(&t.bind.to_string()).await?;
        info!(bind = %t.bind, "listening on the tcp transport");
        tasks.push(tokio::spawn(tcp_accept_loop(
            listener,
            shared.clone(),
            identity.clone(),
            psk,
            metrics.clone(),
        )));
    }
    if let Some(t) = cfg.transports.quic.as_ref().filter(|t| t.enabled) {
        let listener = QuicListener::bind(t.bind, identity.tls_cert_pem(), identity.tls_key_pem())?;
        info!(bind = %t.bind, "listening on the quic transport");
        tasks.push(tokio::spawn(quic_accept_loop(
            listener,
            shared.clone(),
            identity.clone(),
            psk,
            metrics.clone(),
        )));
    }
    if let Some(t) = cfg.transports.wss.as_ref().filter(|t| t.enabled) {
        let listener =
            WssListener::bind(t.bind, identity.tls_cert_pem(), identity.tls_key_pem()).await?;
        info!(bind = %t.bind, path = %t.path, "listening on the wss transport");
        tasks.push(tokio::spawn(wss_accept_loop(
            listener,
            shared.clone(),
            identity.clone(),
            psk,
            metrics.clone(),
        )));
    }

    let transports = tasks.len() - if cfg.dashboard.enabled { 2 } else { 1 };
    if transports == 0 {
        bail!("no transport is enabled — enable at least one of [transports.tcp/quic/wss]");
    }
    for task in tasks {
        let _ = task.await;
    }
    Ok(())
}

// ── Per-transport accept loops ─────────────────────────────────────────────

async fn tcp_accept_loop(
    listener: TcpListener,
    config: SharedConfig,
    identity: Arc<ServerIdentity>,
    psk: [u8; 32],
    metrics: Arc<Metrics>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                stream.set_nodelay(true).ok();
                spawn_tunnel(
                    "tcp",
                    stream,
                    peer,
                    config.clone(),
                    identity.clone(),
                    psk,
                    metrics.clone(),
                );
            }
            Err(e) => warn!(error = %e, "tcp accept failed"),
        }
    }
}

async fn quic_accept_loop(
    listener: QuicListener,
    config: SharedConfig,
    identity: Arc<ServerIdentity>,
    psk: [u8; 32],
    metrics: Arc<Metrics>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => spawn_tunnel(
                "quic",
                stream,
                peer,
                config.clone(),
                identity.clone(),
                psk,
                metrics.clone(),
            ),
            Err(e) => debug!(error = %format!("{e:#}"), "quic accept failed"),
        }
    }
}

async fn wss_accept_loop(
    listener: WssListener,
    config: SharedConfig,
    identity: Arc<ServerIdentity>,
    psk: [u8; 32],
    metrics: Arc<Metrics>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => spawn_tunnel(
                "wss",
                stream,
                peer,
                config.clone(),
                identity.clone(),
                psk,
                metrics.clone(),
            ),
            Err(e) => debug!(error = %format!("{e:#}"), "wss accept failed"),
        }
    }
}

/// Spawn a tunnel handler for an accepted byte stream of any transport.
#[allow(clippy::too_many_arguments)]
fn spawn_tunnel<S>(
    transport: &'static str,
    stream: S,
    peer: SocketAddr,
    config: SharedConfig,
    identity: Arc<ServerIdentity>,
    psk: [u8; 32],
    metrics: Arc<Metrics>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        if let Err(e) = handle_tunnel(stream, transport, peer, config, identity, psk, metrics).await
        {
            warn!(transport, %peer, error = %format!("{e:#}"), "tunnel ended with error");
        }
    });
}

/// Unregister a tunnel from the metrics registry on drop.
struct TunnelReg {
    metrics: Arc<Metrics>,
    id: u64,
}

impl Drop for TunnelReg {
    fn drop(&mut self) {
        self.metrics.unregister_tunnel(self.id);
    }
}

/// Handle one client tunnel for its whole lifetime.
#[allow(clippy::too_many_arguments)]
async fn handle_tunnel<S>(
    stream: S,
    transport: &'static str,
    peer: SocketAddr,
    config: SharedConfig,
    identity: Arc<ServerIdentity>,
    psk: [u8; 32],
    metrics: Arc<Metrics>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    info!(transport, %peer, "tunnel connecting — starting Noise handshake");
    let noise = session::accept(stream, identity.noise_private_key(), &psk)
        .await
        .context("noise handshake")?;

    let mut mux = Mux::server(noise);
    let mut control = mux
        .accept()
        .await
        .ok_or_else(|| anyhow!("client opened no control stream"))?;
    let mux = Arc::new(mux);

    // ---- authenticate against the current config snapshot ----
    let snapshot = config.read().unwrap().clone();
    let (username, token) = match read_frame(&mut control).await.context("reading login")? {
        ControlMsg::Login { username, token } => (username, token),
        other => bail!("expected a Login message, got {other:?}"),
    };
    let user = match snapshot
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
    info!(transport, %peer, user = %user.name, "client authenticated");

    let tunnel_id = metrics.register_tunnel(&user.name, transport, peer.to_string());
    let _reg = TunnelReg {
        metrics: metrics.clone(),
        id: tunnel_id,
    };

    // ---- control loop ----
    let mut proxy_tasks: Vec<JoinHandle<()>> = Vec::new();
    loop {
        let msg: ControlMsg = match timeout(CONTROL_IDLE, read_frame(&mut control)).await {
            Ok(Ok(m)) => m,
            Ok(Err(_)) => {
                info!(%peer, user = %user.name, "control stream closed");
                break;
            }
            Err(_) => {
                warn!(%peer, user = %user.name, "client heartbeat timed out");
                break;
            }
        };
        match msg {
            ControlMsg::RegisterProxy {
                name,
                kind,
                remote_port,
            } => {
                let counters = metrics.register_proxy(tunnel_id, &name, kind, remote_port);
                match register_proxy(&user, &name, kind, remote_port, &mux, counters).await {
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
                }
            }
            ControlMsg::Ping => write_frame(&mut control, &ControlMsg::Pong).await?,
            other => debug!(?other, "ignoring unexpected control message"),
        }
    }

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
    counters: Arc<Counters>,
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
                counters,
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
                counters,
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
async fn tcp_proxy_loop(
    listener: TcpListener,
    mux: Arc<Mux>,
    proxy: String,
    counters: Arc<Counters>,
) {
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
        let counters = counters.clone();
        tokio::spawn(async move {
            debug!(proxy = %proxy, %peer, "public tcp connection accepted");
            if let Err(e) = serve_tcp_conn(user_stream, mux, &proxy, counters).await {
                debug!(proxy = %proxy, %peer, error = %format!("{e:#}"), "tcp connection ended");
            }
        });
    }
}

/// Relay one public TCP connection to the client over a fresh data substream.
async fn serve_tcp_conn(
    user_stream: TcpStream,
    mux: Arc<Mux>,
    proxy: &str,
    counters: Arc<Counters>,
) -> Result<()> {
    let _guard = ConnGuard::new(counters.clone());
    let mut sub = mux.open().await.context("opening data substream")?;
    write_frame(
        &mut sub,
        &DataHead {
            proxy: proxy.to_string(),
        },
    )
    .await
    .context("sending data head")?;
    let mut counted = CountingStream::new(user_stream, counters);
    copy_bidirectional(&mut counted, &mut sub)
        .await
        .context("relaying data")?;
    Ok(())
}

// ── UDP proxy ──────────────────────────────────────────────────────────────

/// Receive UDP datagrams on a public port; demultiplex by source address into
/// one data substream (one logical session) per peer.
async fn udp_proxy_loop(
    socket: Arc<UdpSocket>,
    mux: Arc<Mux>,
    proxy: String,
    counters: Arc<Counters>,
) {
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
        counters.add_in(n as u64);
        let datagram = buf[..n].to_vec();

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
        let guard = ConnGuard::new(counters.clone());
        tokio::spawn(udp_session(
            sub,
            proxy.clone(),
            rx,
            socket.clone(),
            src,
            counters.clone(),
            guard,
        ));
    }
}

/// Relay one UDP session: external datagrams ⇄ a data substream.
#[allow(clippy::too_many_arguments)]
async fn udp_session(
    sub: Substream,
    proxy: String,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    counters: Arc<Counters>,
    guard: ConnGuard,
) {
    let (reader, writer) = split(sub);
    let mut to_peer = tokio::spawn(udp_tunnel_to_peer(reader, socket, src, counters));
    let mut to_tunnel = tokio::spawn(udp_peer_to_tunnel(writer, proxy, rx));
    tokio::select! {
        _ = &mut to_peer => to_tunnel.abort(),
        _ = &mut to_tunnel => to_peer.abort(),
    }
    drop(guard);
    debug!(%src, "udp session ended");
}

/// Substream → external peer. An idle stretch ends the session.
async fn udp_tunnel_to_peer(
    mut reader: ReadHalf<Substream>,
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    counters: Arc<Counters>,
) {
    while let Ok(Ok(dg)) = timeout(UDP_IDLE, read_datagram(&mut reader)).await {
        match socket.send_to(&dg, src).await {
            Ok(_) => counters.add_out(dg.len() as u64),
            Err(_) => break,
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
