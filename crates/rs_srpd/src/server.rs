//! M1 relay server: accept encrypted tunnels and forward TCP traffic.
//!
//! For each client tunnel the server runs the Noise responder handshake, wraps
//! the session in yamux, authenticates the client on the control substream,
//! and binds a public TCP port for every registered proxy. An inbound public
//! connection becomes a fresh data substream back to the client.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use srp_core::identity::ServerIdentity;
use srp_core::mux::Mux;
use srp_core::proto::{read_frame, write_frame, ControlMsg, DataHead};
use srp_core::session;
use srp_core::types::ProxyKind;

use crate::config::{self, ServerConfig, User};

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
                    info!(%peer, proxy = %name, port = remote_port, "proxy registered");
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

/// Validate and bind a single proxy registration request.
async fn register_proxy(
    user: &User,
    name: &str,
    kind: ProxyKind,
    remote_port: u16,
    mux: &Arc<Mux>,
) -> Result<JoinHandle<()>> {
    if kind != ProxyKind::Tcp {
        bail!("only tcp proxies are supported in M1");
    }
    if !port_allowed(user, remote_port) {
        bail!(
            "remote port {remote_port} is not permitted for user {:?}",
            user.name
        );
    }
    let listener = TcpListener::bind(("0.0.0.0", remote_port))
        .await
        .with_context(|| format!("binding public port {remote_port}"))?;

    Ok(tokio::spawn(proxy_accept_loop(
        listener,
        mux.clone(),
        name.to_string(),
    )))
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

/// Accept public connections for one proxy, opening a data substream per peer.
async fn proxy_accept_loop(listener: TcpListener, mux: Arc<Mux>, proxy: String) {
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
            debug!(proxy = %proxy, %peer, "public connection accepted");
            if let Err(e) = serve_data_conn(user_stream, mux, &proxy).await {
                debug!(proxy = %proxy, %peer, error = %format!("{e:#}"), "data connection ended");
            }
        });
    }
}

/// Relay one public connection to the client over a fresh data substream.
async fn serve_data_conn(mut user_stream: TcpStream, mux: Arc<Mux>, proxy: &str) -> Result<()> {
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
