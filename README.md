# rs_srp

[![CI](https://github.com/RisingEntropy/rs_srp/actions/workflows/ci.yml/badge.svg)](https://github.com/RisingEntropy/rs_srp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**rs_srp** (*rust secure reverse proxy*) is a NAT-traversal reverse proxy. It
publishes a service running behind NAT on a public address, by relaying it
through an encrypted, multiplexed tunnel to a server with a public IP.

It follows the FRP-style relay model but is built from scratch with its own
protocol: every tunnel is encrypted end-to-end and can ride TCP, QUIC, or
WebSocket-over-TLS, switching transport automatically when one is blocked.

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

## Features

- **NAT traversal, relay model** — a public-IP server relays traffic for
  clients behind NAT. Expose any local **TCP or UDP** service on a public port.
- **Encrypted end-to-end** — every tunnel runs a Noise `NKpsk0` session: the
  client pins the server's static key, both sides prove a password-derived PSK
  (Argon2id), and traffic is sealed with ChaCha20-Poly1305. No CA required.
- **Multiple transports with fallback** — the tunnel runs over TCP, QUIC, or
  WSS. The client tries them in priority order and keeps the first that
  connects, so a blocked transport is routed around automatically. QUIC and
  WSS carry their own pinned TLS 1.3.
- **Multiplexed** — many proxied connections share one tunnel via yamux, which
  lives *inside* the encryption.
- **Multi-user** — the server defines users, each with a token and a set of
  permitted public port ranges.
- **Resilient** — a heartbeat detects a dead tunnel; the client reconnects with
  exponential backoff, re-running the transport fallback each time.
- **Operations dashboard** — a built-in web UI shows live tunnels, per-proxy
  traffic and a traffic chart, and manages users with config hot-reload.

## How it works

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

## Install

### Pre-built binaries

Download `rs_srpd` (server) and `rs_srpc` (client) for Linux, macOS, and
Windows from the [Releases](../../releases) page.

### From source

```sh
cargo build --release
# → target/release/rs_srpd, target/release/rs_srpc
```

To cross-compile every platform at once, see [`build/`](build/README.md):

```sh
./build/build.sh        # artifacts land in build/dist/
```

## Quick start

### 1. Server — on a host with a public IP

Copy `crates/rs_srpd/srpd.example.toml` to `srpd.toml`, set a strong
`server_secret`, and define `[[users]]`. Then:

```sh
rs_srpd run -c srpd.toml
```

On first start the server generates and persists its identity (a self-signed
TLS certificate and a Noise keypair) under `state_dir`.

### 2. Generate a client configuration

On the server:

```sh
rs_srpd client-config -c srpd.toml --user alice --host your.server.example
```

This prints a ready-to-use `srpc.toml` with the pinned server identity and the
user's credentials.

### 3. Client — behind NAT

Save that output as `srpc.toml`, add a `[[proxies]]` entry for each local
service to expose, then:

```sh
rs_srpc run -c srpc.toml
```

```toml
[[proxies]]
name = "ssh"
type = "tcp"               # or "udp"
local_addr = "127.0.0.1:22"
remote_port = 20022        # must fall within the user's allowed range
```

External users can now reach the service at `your.server.example:20022`.

## Configuration

Annotated examples of every field:

- Server — [`crates/rs_srpd/srpd.example.toml`](crates/rs_srpd/srpd.example.toml)
- Client — [`crates/rs_srpc/srpc.example.toml`](crates/rs_srpc/srpc.example.toml)

The client's `transport_priority` (e.g. `["quic", "wss", "tcp"]`) sets the
order transports are tried.

## Dashboard

The server runs an operations dashboard, by default on `127.0.0.1:1564`
(loopback only — reach it remotely via an SSH tunnel):

```sh
ssh -L 1564:127.0.0.1:1564 user@your.server.example
# then open http://localhost:1564
```

It shows live tunnels, per-proxy traffic counters and a traffic chart, and lets
you add, edit, and remove users — changes are written back to the config file
and hot-reloaded.

## Security model

- **No CA.** The server holds a self-signed certificate and a Noise static
  keypair. Clients pin both by fingerprint, baked into the config by
  `client-config`.
- **Password-derived key.** The shared `server_secret` is stretched with
  Argon2id into the Noise PSK, making a captured handshake expensive to
  brute-force.
- **Defense in depth.** QUIC and WSS additionally carry their own TLS 1.3; the
  inner Noise session authenticates and encrypts regardless of transport.
- The dashboard is loopback-bound by default; do not expose it directly.

## Project layout

| Crate      | Role                                                       |
|------------|------------------------------------------------------------|
| `srp-core` | Shared library: identity, transports, Noise session, mux.  |
| `rs_srpd`  | Server binary (`run`, `client-config`) + dashboard.        |
| `rs_srpc`  | Client binary (`run`).                                     |

## Roadmap

Implemented: encrypted multiplexed tunnels, TCP & UDP forwarding, multi-user
auth, the TCP/QUIC/WSS transports with priority fallback, heartbeat-driven
auto-reconnect, and the operations dashboard.

Planned: native QUIC-stream multiplexing and a raw-UDP (KCP) transport.

## License

Licensed under the [MIT License](LICENSE).
