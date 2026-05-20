<div align="center">

# 🛡️ rs_srp

**rust secure reverse proxy** — a NAT-traversal reverse proxy.
Think of it as **FRP, levelled up.**

[![CI](https://github.com/RisingEntropy/rs_srp/actions/workflows/ci.yml/badge.svg)](https://github.com/RisingEntropy/rs_srp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org)

*Expose any service behind NAT on a public address — through a tunnel that is
**encrypted end-to-end**, **multiplexed**, and **switches transport
automatically** when one is blocked.*

</div>

---

rs_srp keeps the FRP relay model you already know — a public-IP server fronts
your services behind NAT — but rebuilds the wire protocol from scratch: every
byte is sealed inside a Noise session, the tunnel rides TCP **/** QUIC **/**
WebSocket-over-TLS interchangeably, and a blocked path is routed around without
you lifting a finger.

```
        NAT boundary
                    │
   your service     │                public internet
   127.0.0.1:8000   │
        ▲           │
        │           │
     rs_srpc ───────┼─── encrypted tunnel ───►  rs_srpd ───► 0.0.0.0:20022
     (client,       │     TCP / QUIC / WSS      (server,           ▲
      behind NAT)   │                            public IP)        │
                    │                                       external users
```

## ✨ Why rs_srp — the FRP upgrade

If you've outgrown FRP because a firewall keeps killing your tunnel, or you want
encryption that isn't an afterthought, rs_srp is the drop-in upgrade.

| | FRP | **rs_srp** |
|---|---|---|
| Tunnel encryption | optional, per-proxy | **always on**, every tunnel end-to-end |
| Transports | mainly TCP | **TCP · QUIC · WSS, with automatic fallback** |
| Blocked transport | reconfigure by hand | **routed around automatically** |
| Key material | plaintext token in config | **password-derived key** (Argon2id → Noise PSK) |
| Server trust | — | **certificate + static-key pinning, no CA** |
| Operations | config files / admin API | **built-in web dashboard** — live stats + hot-reload |

## 🚀 Features

- 🌐 **NAT traversal, relay model** — a public-IP server relays traffic for
  clients behind NAT. Expose any local **TCP or UDP** service on a public port.
- 🔒 **Encrypted end-to-end** — every tunnel runs a Noise `NKpsk0` session
  sealed with ChaCha20-Poly1305. The key is derived from your password — no
  plaintext secret on the wire, no CA to manage.
- 🔀 **Three transports, automatic fallback** — the tunnel runs over TCP, QUIC,
  or WSS. The client tries them in priority order and keeps the first that
  connects, so a blocked transport is routed around for you.
- 🧵 **Multiplexed** — many proxied connections share one tunnel via yamux,
  living *inside* the encryption.
- 👥 **Multi-user** — each user gets a token and a set of permitted public port
  ranges.
- ♻️ **Resilient** — a heartbeat detects a dead tunnel; the client reconnects
  with exponential backoff, re-running the transport fallback each time.
- 📊 **Operations dashboard** — a built-in web UI for live tunnels, per-proxy
  traffic, a traffic chart, and user management with config hot-reload.

## ⚡ Quick start

### 1. Install

Grab pre-built `rs_srpd` (server) and `rs_srpc` (client) binaries for Linux,
macOS, and Windows from the [Releases](../../releases) page — or build from
source:

```sh
cargo build --release      # → target/release/rs_srpd, rs_srpc
```

### 2. Server — on a host with a public IP

Copy `crates/rs_srpd/srpd.example.toml` to `srpd.toml`, set a strong
`server_secret`, define `[[users]]`, then:

```sh
rs_srpd run -c srpd.toml
```

On first start the server generates and persists its identity (a self-signed
TLS certificate and a Noise keypair) under `state_dir`.

### 3. Hand a client its config

On the server:

```sh
rs_srpd client-config -c srpd.toml --user alice --host your.server.example
```

This prints a ready-to-use `srpc.toml` — pinned server identity and the user's
credentials already filled in.

### 4. Client — behind NAT

Save that output as `srpc.toml`, add a `[[proxies]]` entry per local service:

```toml
[[proxies]]
name = "ssh"
type = "tcp"               # or "udp"
local_addr = "127.0.0.1:22"
remote_port = 20022        # must fall within the user's allowed range
```

```sh
rs_srpc run -c srpc.toml
```

External users can now reach the service at `your.server.example:20022`. Done.

## 📊 Dashboard

The server runs an operations dashboard, by default on `127.0.0.1:1564`
(loopback only — reach it remotely via an SSH tunnel):

```sh
ssh -L 1564:127.0.0.1:1564 user@your.server.example
# then open http://localhost:1564
```

It shows live tunnels, per-proxy traffic counters and a traffic chart, and lets
you add, edit, and remove users — changes are written back to the config file
and hot-reloaded, no restart.

## 🔧 Configuration

Annotated examples of every field:

- Server — [`crates/rs_srpd/srpd.example.toml`](crates/rs_srpd/srpd.example.toml)
- Client — [`crates/rs_srpc/srpc.example.toml`](crates/rs_srpc/srpc.example.toml)

The client's `transport_priority` (e.g. `["quic", "wss", "tcp"]`) sets the order
transports are tried.

To cross-compile every platform at once, see [`build/`](build/README.md):

```sh
./build/build.sh        # artifacts land in build/dist/
```

---

## 🧩 How it works

The tunnel is a layered stack — many logical streams share one encrypted
connection over whichever transport is available:

```
  control protocol   +   data streams        ← yamux substreams
  └──────────────── yamux multiplexing ────────────────┘
  └──────────── Noise NKpsk0 / ChaCha20-Poly1305 ───────┘   ← encryption
  └────────────────  TCP  /  QUIC  /  WSS  ─────────────┘   ← transport
```

A client opens one control stream to log in and register proxies. When an
external user connects to a public port, the server opens a fresh data
substream back to the client, which forwards it to the matching local service.
QUIC and WSS carry their own pinned TLS 1.3 underneath; the inner Noise session
authenticates and encrypts regardless of which transport is in use.

### Security model

- **No CA.** The server holds a self-signed certificate and a Noise static
  keypair. Clients pin both by fingerprint, baked into the config by
  `client-config` — verification matches the fingerprint and ignores hostname.
- **Password-derived key.** The shared `server_secret` is stretched with
  Argon2id into the Noise PSK, making a captured handshake expensive to
  brute-force.
- **Defense in depth.** QUIC and WSS additionally carry their own TLS 1.3; the
  inner Noise session authenticates and encrypts regardless of transport.
- The dashboard is loopback-bound by default — do not expose it directly.

### Project layout

| Crate      | Role                                                       |
|------------|------------------------------------------------------------|
| `srp-core` | Shared library: identity, transports, Noise session, mux.  |
| `rs_srpd`  | Server binary (`run`, `client-config`) + dashboard.        |
| `rs_srpc`  | Client binary (`run`).                                     |

### Roadmap

Implemented: encrypted multiplexed tunnels, TCP & UDP forwarding, multi-user
auth, the TCP/QUIC/WSS transports with priority fallback, heartbeat-driven
auto-reconnect, and the operations dashboard.

Planned: native QUIC-stream multiplexing and a raw-UDP (KCP) transport.

## 📄 License

Licensed under the [MIT License](LICENSE).
