//! Protocol-level enums shared by the server and client.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Transport that carries the encrypted tunnel between client and server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Tcp,
    Quic,
    Wss,
}

impl fmt::Display for TransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TransportKind::Tcp => "tcp",
            TransportKind::Quic => "quic",
            TransportKind::Wss => "wss",
        })
    }
}

/// L4 protocol of a forwarded service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Tcp,
    Udp,
}

impl fmt::Display for ProxyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProxyKind::Tcp => "tcp",
            ProxyKind::Udp => "udp",
        })
    }
}
