# rs_srp — rust secure reverse proxy

A NAT-traversal reverse proxy (FRP-style relay model) written in Rust.

- **Relay model**: a server with a public IP relays traffic for clients behind NAT.
- **Multiple transports**: the encrypted tunnel runs over TCP, QUIC, or WSS,
  trying them by priority and keeping the first that works.
- **Encryption everywhere**: every transport is wrapped in a Noise (`NKpsk0`)
  session keyed from a password (Argon2id-derived PSK) and the server's pinned
  Noise static key. QUIC/WSS additionally carry their own TLS.
- **Multiplexing**: many proxied connections share one tunnel via a mux layer
  that lives *inside* the encryption.

## Workspace layout

| Crate      | Role                                                          |
|------------|---------------------------------------------------------------|
| `srp-core` | Shared library: identity, transports, secure session, mux.    |
| `rs_srpd`  | Server binary (`rs_srpd run`, `rs_srpd client-config`).       |
| `rs_srpc`  | Client binary (`rs_srpc run`).                                |

## Status

Milestone **M1** complete: a working TCP-transport tunnel. The client dials the
server, both run a Noise `NKpsk0` handshake, multiplex with yamux, authenticate
on a control substream, and forward TCP services end-to-end through the
encrypted tunnel.

Next: M2 (multi-user enforcement, UDP forwarding), M3 (QUIC + WSS transports
with priority fallback), M4 (heartbeat, reconnect, polish).
