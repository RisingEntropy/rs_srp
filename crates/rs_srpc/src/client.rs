//! M1 relay client: dial the server, register proxies, forward connections.
//!
//! The client runs the Noise initiator handshake, wraps the session in yamux,
//! authenticates on the control substream, and registers each configured
//! proxy. The server then drives traffic by opening data substreams, which the
//! client relays to the matching local service.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use srp_core::identity;
use srp_core::mux::{Mux, Substream};
use srp_core::proto::{read_frame, write_frame, ControlMsg, DataHead};
use srp_core::session;
use srp_core::types::TransportKind;

use crate::config::{self, ClientConfig};

/// Run the client until the tunnel closes.
pub async fn run(config_path: &Path) -> Result<()> {
    let config = Arc::new(config::load(config_path)?);

    let psk = srp_core::crypto::derive_psk(&config.security.server_secret)?;
    let server_pub = identity::decode_noise_public_key(&config.client.server_noise_pubkey)?;

    // M1 supports only the tcp transport.
    if !config
        .client
        .transport_priority
        .contains(&TransportKind::Tcp)
    {
        bail!("M1 supports only the tcp transport; add \"tcp\" to transport_priority");
    }
    let tcp = config
        .client
        .transports
        .tcp
        .as_ref()
        .ok_or_else(|| anyhow!("M1 requires a [client.transports.tcp] block"))?;
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
                info!(proxy = %name, remote_port, local = %proxy.local_addr, "proxy active");
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

    let mut local = TcpStream::connect(proxy.local_addr)
        .await
        .with_context(|| format!("connecting to local service {}", proxy.local_addr))?;
    local.set_nodelay(true).ok();
    debug!(proxy = %head.proxy, local = %proxy.local_addr, "data connection established");

    copy_bidirectional(&mut local, &mut sub)
        .await
        .context("relaying data")?;
    Ok(())
}
