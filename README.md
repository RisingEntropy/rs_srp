# rs_srp — rust secure reverse proxy

A NAT-traversal reverse proxy (FRP-style relay model) written in Rust. A server
with a public IP relays traffic for clients behind NAT; every tunnel is
encrypted, multiplexed, and can ride one of several transports.

## Features

- **Relay model** — one public-IP server, clients behind NAT, traffic relayed.
- **TCP and UDP forwarding** — expose any local TCP or UDP service on a public
  port.
- **Encrypted everywhere** — every tunnel runs a Noise `NKpsk0` session:
  the client pins the server's static key, both prove a password-derived PSK
  (Argon2id), and traffic is sealed with ChaCha20-Poly1305.
- **Multiple transports** — the tunnel runs over TCP, QUIC, or WSS. The client
  tries them in priority order and keeps the first that connects; QUIC and WSS
  carry their own TLS 1.3 with a pinned self-signed certificate.
- **Multiplexed** — many proxied connections share one tunnel via yamux, which
  lives *inside* the encryption.
- **Multi-user** — the server config defines users, each with a token and a set
  of permitted public port ranges.
- **Resilient** — a heartbeat detects a dead tunnel; the client reconnects with
  exponential backoff, re-running the transport fallback each time.

## Workspace layout

| Crate      | Role                                                          |
|------------|---------------------------------------------------------------|
| `srp-core` | Shared library: identity, transports, Noise session, mux.     |
| `rs_srpd`  | Server binary (`rs_srpd run`, `rs_srpd client-config`).       |
| `rs_srpc`  | Client binary (`rs_srpc run`).                                |

## Build

```sh
cargo build --release
```

## Quick start

1. **Server** — copy `crates/rs_srpd/srpd.example.toml` to `srpd.toml`, set a
   strong `server_secret`, and define `[[users]]`. Then:

   ```sh
   rs_srpd run -c srpd.toml
   ```

   On first start the server generates and persists its identity (a self-signed
   TLS certificate and a Noise keypair) under `state_dir`.

2. **Hand a client its config** — on the server:

   ```sh
   rs_srpd client-config -c srpd.toml --user alice --host your.server.example
   ```

   This prints a ready-to-use `srpc.toml` with the pinned server identity and
   the user's credentials.

3. **Client** — save that as `srpc.toml`, add `[[proxies]]` entries for the
   local services to expose, and run:

   ```sh
   rs_srpc run -c srpc.toml
   ```

## Configuration

See `crates/rs_srpd/srpd.example.toml` and `crates/rs_srpc/srpc.example.toml`
for annotated examples of every field.

## Status

Milestones M0–M4 are complete: encrypted multiplexed tunnels, TCP and UDP
forwarding, multi-user authentication, the TCP/QUIC/WSS transports with
priority fallback, and heartbeat-driven auto-reconnect — all verified
end-to-end. Possible future work: native QUIC-stream multiplexing, a raw-UDP
(KCP) transport, and an observability dashboard.
