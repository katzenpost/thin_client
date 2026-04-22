// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! TCP transport for the Rust thin-client.

use std::io;

use serde::Deserialize;
use tokio::net::TcpStream;

use crate::core::{ReadHalf, WriteHalf};

use super::{DialedHalves, Dialer};

/// Configures a TCP dialer. `address` is host:port form (e.g.
/// `localhost:64331` or `[::1]:64331`). `network` is optionally one
/// of `"tcp"`, `"tcp4"`, `"tcp6"`; when absent it defaults to
/// `"tcp"` (dual-stack where supported).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpDialConfig {
    #[serde(rename = "Address")]
    pub address: String,
    #[serde(rename = "Network", default)]
    pub network: Option<String>,
}

#[async_trait::async_trait]
impl Dialer for TcpDialConfig {
    async fn dial(&self) -> io::Result<DialedHalves> {
        let network = self.network.as_deref().unwrap_or("tcp");
        match network {
            "tcp" | "tcp4" | "tcp6" => {}
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "transport: TcpDialConfig.Network {other:?} is not one of tcp, tcp4, tcp6"
                    ),
                ));
            }
        }

        // tokio's `TcpStream::connect` resolves host:port and picks
        // a family automatically. For "tcp4" / "tcp6" we defer to
        // tokio's default address-family behaviour; a caller wanting
        // to force v4 or v6 can spell that in the address itself
        // (e.g. "127.0.0.1:..." or "[::1]:...").
        let socket = TcpStream::connect(&self.address).await?;
        let (read_half, write_half) = socket.into_split();
        Ok((ReadHalf::Tcp(read_half), WriteHalf::Tcp(write_half)))
    }
}
