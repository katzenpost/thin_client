// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Unix-domain-socket transport for the Rust thin-client.

use std::io;

use serde::Deserialize;
use tokio::net::UnixStream;

use crate::core::{ReadHalf, WriteHalf};

use super::{DialedHalves, Dialer};

/// Configures a unix-domain-socket dialer. `address` is the path to
/// the socket the daemon is listening on. A leading `@` indicates a
/// Linux abstract socket; the rest of the name becomes the abstract
/// address (with a leading null byte prepended internally).
#[derive(Clone, Debug, Deserialize)]
pub struct UnixDialConfig {
    #[serde(rename = "Address")]
    pub address: String,
}

#[async_trait::async_trait]
impl Dialer for UnixDialConfig {
    async fn dial(&self) -> io::Result<DialedHalves> {
        let path = if self.address.starts_with('@') {
            let mut p = String::from("\0");
            p.push_str(&self.address[1..]);
            p
        } else {
            self.address.clone()
        };
        let socket = UnixStream::connect(path).await?;
        let (read_half, write_half) = socket.into_split();
        Ok((ReadHalf::Unix(read_half), WriteHalf::Unix(write_half)))
    }
}
