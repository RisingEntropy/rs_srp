//! Operations dashboard: an HTTP server (default `127.0.0.1:1564`) exposing
//! live metrics and user management.
//!
//! The single-page UI is embedded in the binary. The JSON API serves an
//! overview (server identity, transports, live tunnels), traffic history, and
//! user CRUD — edits are written back to the config file and hot-reloaded.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Path as AxPath, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::info;

use srp_core::identity::ServerIdentity;

use crate::config::{self, ServerConfig, User};
use crate::metrics::{Metrics, TunnelView};
use crate::server::SharedConfig;

/// The dashboard single-page app, baked into the binary.
const PAGE: &str = include_str!("dashboard.html");

/// Shared state handed to every request handler.
#[derive(Clone)]
struct DashState {
    metrics: Arc<Metrics>,
    config: SharedConfig,
    identity: Arc<ServerIdentity>,
    config_path: PathBuf,
}

/// Serve the dashboard until the process exits.
pub async fn serve(
    bind: SocketAddr,
    metrics: Arc<Metrics>,
    config: SharedConfig,
    identity: Arc<ServerIdentity>,
    config_path: PathBuf,
) -> Result<()> {
    let state = DashState {
        metrics,
        config,
        identity,
        config_path,
    };
    let app = Router::new()
        .route("/", get(|| async { Html(PAGE) }))
        .route("/api/overview", get(overview))
        .route("/api/history", get(history))
        .route("/api/users", get(list_users).post(upsert_user))
        .route("/api/users/{name}", delete(delete_user))
        .route("/api/client-config", get(client_config))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding the dashboard on {bind}"))?;
    axum::serve(listener, app)
        .await
        .context("running the dashboard server")
}

// ── API response types ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct TransportInfo {
    kind: String,
    bind: String,
}

#[derive(Serialize)]
struct Overview {
    public_host: Option<String>,
    noise_pubkey: String,
    cert_fingerprint: String,
    transports: Vec<TransportInfo>,
    user_count: usize,
    tunnels: Vec<TunnelView>,
}

#[derive(Serialize)]
struct UserView {
    name: String,
    token: String,
    allow_remote_ports: Vec<String>,
}

#[derive(Deserialize)]
struct UserPayload {
    name: String,
    token: String,
    #[serde(default)]
    allow_remote_ports: Vec<String>,
}

#[derive(Deserialize)]
struct CcQuery {
    user: String,
    host: Option<String>,
}

// ── Handlers ───────────────────────────────────────────────────────────────

async fn overview(State(s): State<DashState>) -> impl IntoResponse {
    let cfg = s.config.read().unwrap().clone();
    let mut transports = Vec::new();
    if let Some(t) = cfg.transports.tcp.as_ref().filter(|t| t.enabled) {
        transports.push(TransportInfo {
            kind: "tcp".into(),
            bind: t.bind.to_string(),
        });
    }
    if let Some(t) = cfg.transports.quic.as_ref().filter(|t| t.enabled) {
        transports.push(TransportInfo {
            kind: "quic".into(),
            bind: t.bind.to_string(),
        });
    }
    if let Some(t) = cfg.transports.wss.as_ref().filter(|t| t.enabled) {
        transports.push(TransportInfo {
            kind: "wss".into(),
            bind: format!("{} {}", t.bind, t.path),
        });
    }
    Json(Overview {
        public_host: cfg.public_host.clone(),
        noise_pubkey: s.identity.noise_public_key_b64(),
        cert_fingerprint: s.identity.cert_fingerprint().unwrap_or_default(),
        transports,
        user_count: cfg.users.len(),
        tunnels: s.metrics.tunnels(),
    })
}

async fn history(State(s): State<DashState>) -> impl IntoResponse {
    Json(s.metrics.history())
}

async fn list_users(State(s): State<DashState>) -> impl IntoResponse {
    let cfg = s.config.read().unwrap().clone();
    let users: Vec<UserView> = cfg
        .users
        .iter()
        .map(|u| UserView {
            name: u.name.clone(),
            token: u.token.clone(),
            allow_remote_ports: u.allow_remote_ports.clone(),
        })
        .collect();
    Json(users)
}

async fn upsert_user(State(s): State<DashState>, Json(p): Json<UserPayload>) -> Response {
    if p.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "user name is required").into_response();
    }
    if p.token.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "token is required").into_response();
    }
    for entry in &p.allow_remote_ports {
        if config::parse_port_range(entry).is_err() {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid port range: {entry:?}"),
            )
                .into_response();
        }
    }
    let mut cfg: ServerConfig = s.config.read().unwrap().as_ref().clone();
    cfg.users.retain(|u| u.name != p.name);
    cfg.users.push(User {
        name: p.name,
        token: p.token,
        allow_remote_ports: p.allow_remote_ports,
    });
    apply(&s, cfg)
}

async fn delete_user(State(s): State<DashState>, AxPath(name): AxPath<String>) -> Response {
    let mut cfg: ServerConfig = s.config.read().unwrap().as_ref().clone();
    let before = cfg.users.len();
    cfg.users.retain(|u| u.name != name);
    if cfg.users.len() == before {
        return (StatusCode::NOT_FOUND, format!("user {name:?} not found")).into_response();
    }
    apply(&s, cfg)
}

async fn client_config(State(s): State<DashState>, Query(q): Query<CcQuery>) -> Response {
    let cfg = s.config.read().unwrap().clone();
    match crate::client_config::render_srpc_toml(&cfg, &s.identity, &q.user, q.host.as_deref()) {
        Ok(toml) => (StatusCode::OK, toml).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("{e}")).into_response(),
    }
}

/// Write the updated config to disk and hot-swap it for new tunnels.
fn apply(s: &DashState, cfg: ServerConfig) -> Response {
    let toml = match toml::to_string_pretty(&cfg) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("serializing config: {e}"),
            )
                .into_response()
        }
    };
    if let Err(e) = std::fs::write(&s.config_path, &toml) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("writing config file: {e}"),
        )
            .into_response();
    }
    *s.config.write().unwrap() = Arc::new(cfg);
    info!("dashboard updated the configuration and hot-reloaded it");
    (StatusCode::OK, "ok").into_response()
}
