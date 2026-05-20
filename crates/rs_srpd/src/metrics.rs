//! Live metrics and traffic history powering the dashboard.
//!
//! [`Metrics`] is a shared registry: tunnels register on connect, proxies
//! register on `RegisterProxy`, and a [`CountingStream`] bumps per-proxy byte
//! counters as traffic flows. A background sampler snapshots cumulative totals
//! into a capped, disk-persisted history for the dashboard's charts.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use srp_core::types::ProxyKind;

/// How many history samples to keep (≈5.5h at one sample per 10s).
const HISTORY_CAP: usize = 2048;

/// Byte and connection counters for one registered proxy.
#[derive(Default)]
pub struct Counters {
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub conns: AtomicU64,
    pub active: AtomicU64,
}

impl Counters {
    /// Record `n` bytes flowing in (from the public side).
    pub fn add_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    /// Record `n` bytes flowing out (to the public side).
    pub fn add_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }
}

struct Proxy {
    name: String,
    kind: ProxyKind,
    remote_port: u16,
    counters: Arc<Counters>,
}

struct Tunnel {
    user: String,
    transport: &'static str,
    peer: String,
    since: Instant,
    proxies: Vec<Proxy>,
}

struct State {
    next_id: u64,
    tunnels: BTreeMap<u64, Tunnel>,
    /// Bytes from tunnels that have since disconnected, so cumulative totals
    /// stay monotonic.
    retired_in: u64,
    retired_out: u64,
}

/// One traffic-history data point.
#[derive(Clone, Serialize, Deserialize)]
pub struct Sample {
    /// Unix timestamp (seconds).
    pub t: u64,
    /// Cumulative bytes since the history began.
    pub total_in: u64,
    pub total_out: u64,
}

/// Serializable view of a proxy for the dashboard API.
#[derive(Serialize)]
pub struct ProxyView {
    pub name: String,
    pub kind: String,
    pub remote_port: u16,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub conns: u64,
    pub active: u64,
}

/// Serializable view of a tunnel for the dashboard API.
#[derive(Serialize)]
pub struct TunnelView {
    pub id: u64,
    pub user: String,
    pub transport: String,
    pub peer: String,
    pub uptime_secs: u64,
    pub proxies: Vec<ProxyView>,
}

/// The shared metrics registry.
pub struct Metrics {
    state: Mutex<State>,
    history: Mutex<VecDeque<Sample>>,
    history_path: PathBuf,
}

impl Metrics {
    /// Create the registry, loading any persisted history from `state_dir`.
    pub fn new(state_dir: &Path) -> Arc<Metrics> {
        let history_path = state_dir.join("dashboard-history.json");
        let history = std::fs::read_to_string(&history_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<VecDeque<Sample>>(&raw).ok())
            .unwrap_or_default();
        Arc::new(Metrics {
            state: Mutex::new(State {
                next_id: 1,
                tunnels: BTreeMap::new(),
                retired_in: 0,
                retired_out: 0,
            }),
            history: Mutex::new(history),
            history_path,
        })
    }

    /// Register a newly connected tunnel; returns its id.
    pub fn register_tunnel(&self, user: &str, transport: &'static str, peer: String) -> u64 {
        let mut state = self.state.lock().unwrap();
        let id = state.next_id;
        state.next_id += 1;
        state.tunnels.insert(
            id,
            Tunnel {
                user: user.to_string(),
                transport,
                peer,
                since: Instant::now(),
                proxies: Vec::new(),
            },
        );
        id
    }

    /// Remove a tunnel, rolling its traffic into the retired totals.
    pub fn unregister_tunnel(&self, id: u64) {
        let mut state = self.state.lock().unwrap();
        if let Some(tunnel) = state.tunnels.remove(&id) {
            let (mut ri, mut ro) = (0u64, 0u64);
            for p in &tunnel.proxies {
                ri += p.counters.bytes_in.load(Ordering::Relaxed);
                ro += p.counters.bytes_out.load(Ordering::Relaxed);
            }
            state.retired_in += ri;
            state.retired_out += ro;
        }
    }

    /// Register a proxy under a tunnel; returns its shared counters.
    pub fn register_proxy(
        &self,
        tunnel_id: u64,
        name: &str,
        kind: ProxyKind,
        remote_port: u16,
    ) -> Arc<Counters> {
        let counters = Arc::new(Counters::default());
        let mut state = self.state.lock().unwrap();
        if let Some(tunnel) = state.tunnels.get_mut(&tunnel_id) {
            tunnel.proxies.push(Proxy {
                name: name.to_string(),
                kind,
                remote_port,
                counters: counters.clone(),
            });
        }
        counters
    }

    /// Cumulative (retired + live) byte totals.
    fn totals(&self) -> (u64, u64) {
        let state = self.state.lock().unwrap();
        let (mut ti, mut to) = (state.retired_in, state.retired_out);
        for tunnel in state.tunnels.values() {
            for p in &tunnel.proxies {
                ti += p.counters.bytes_in.load(Ordering::Relaxed);
                to += p.counters.bytes_out.load(Ordering::Relaxed);
            }
        }
        (ti, to)
    }

    /// Snapshot of all live tunnels for the dashboard API.
    pub fn tunnels(&self) -> Vec<TunnelView> {
        let state = self.state.lock().unwrap();
        state
            .tunnels
            .iter()
            .map(|(&id, t)| TunnelView {
                id,
                user: t.user.clone(),
                transport: t.transport.to_string(),
                peer: t.peer.clone(),
                uptime_secs: t.since.elapsed().as_secs(),
                proxies: t
                    .proxies
                    .iter()
                    .map(|p| ProxyView {
                        name: p.name.clone(),
                        kind: p.kind.to_string(),
                        remote_port: p.remote_port,
                        bytes_in: p.counters.bytes_in.load(Ordering::Relaxed),
                        bytes_out: p.counters.bytes_out.load(Ordering::Relaxed),
                        conns: p.counters.conns.load(Ordering::Relaxed),
                        active: p.counters.active.load(Ordering::Relaxed),
                    })
                    .collect(),
            })
            .collect()
    }

    /// Append a history sample from the current totals.
    pub fn sample(&self) {
        let (total_in, total_out) = self.totals();
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut history = self.history.lock().unwrap();
        history.push_back(Sample {
            t,
            total_in,
            total_out,
        });
        while history.len() > HISTORY_CAP {
            history.pop_front();
        }
    }

    /// The traffic history for the dashboard charts.
    pub fn history(&self) -> Vec<Sample> {
        self.history.lock().unwrap().iter().cloned().collect()
    }

    /// Persist the history to disk.
    pub fn persist(&self) {
        let history = self.history.lock().unwrap();
        match serde_json::to_string(&*history) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.history_path, json) {
                    debug!(error = %e, "persisting dashboard history failed");
                }
            }
            Err(e) => debug!(error = %e, "serializing dashboard history failed"),
        }
    }
}

/// RAII guard counting one active connection on a proxy.
pub struct ConnGuard(Arc<Counters>);

impl ConnGuard {
    pub fn new(counters: Arc<Counters>) -> ConnGuard {
        counters.conns.fetch_add(1, Ordering::Relaxed);
        counters.active.fetch_add(1, Ordering::Relaxed);
        ConnGuard(counters)
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Wraps a byte stream, counting bytes read (`bytes_in`) and written
/// (`bytes_out`) into shared [`Counters`].
pub struct CountingStream<S> {
    inner: S,
    counters: Arc<Counters>,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S, counters: Arc<Counters>) -> CountingStream<S> {
        CountingStream { inner, counters }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut me.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = buf.filled().len() - before;
            me.counters
                .bytes_in
                .fetch_add(read as u64, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let result = Pin::new(&mut me.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            me.counters
                .bytes_out
                .fetch_add(*n as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
