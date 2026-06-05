// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! High-level Pigeonhole API with database persistence.
//!
//! This module provides a simplified API for the Pigeonhole protocol,
//! automatically managing state (capabilities, indices) via SQLite.
//!
//! # Overview
//!
//! The low-level pigeonhole API in [`crate::pigeonhole`] requires manual
//! management of write/read capabilities and message box indices. This
//! module wraps that API with automatic state persistence, making it
//! much easier to build applications.
//!
//! # Features
//!
//! - **Automatic index management**: Write and read indices are automatically
//!   persisted and incremented after each operation.
//! - **Channel persistence**: Channels (with their capabilities) are stored in
//!   SQLite and can be recovered after application restart.
//! - **Tombstone support**: Delete messages by overwriting them with zeros.
//! - **Copy command support**: Send large payloads that span multiple boxes
//!   using the Copy command with automatic chunking.
//! - **Message history**: Received messages are stored for later retrieval.
//!
//! # Example
//!
//! ```rust,ignore
//! use katzenpost_thin_client::persistent::{PigeonholeClient, Database};
//!
//! // Open database and create client
//! let db = Database::open("pigeonhole.db")?;
//! let pigeonhole = PigeonholeClient::new(thin_client, db);
//!
//! // Generate a fresh capability pair via the thin client
//! let mut seed = [0u8; 32];
//! rand::thread_rng().fill_bytes(&mut seed);
//! let kp = thin_client.new_keypair(&seed).await?;
//!
//! // Sender loads a write channel
//! let mut writer = pigeonhole
//!     .load_write_channel("alice-to-bob", &kp.write_cap, &kp.write_cap)?;
//! writer.send(b"Hello, world!").await?;
//!
//! // Receiver (possibly on another machine, with their own PigeonholeClient)
//! let mut reader = pigeonhole
//!     .load_read_channel("from-alice", &kp.read_cap, &kp.read_cap)?;
//! let message = reader.receive().await?;
//! ```
//!
//! # Plaintext Size Constraints
//!
//! Single messages sent via [`WriteChannel::send`] must not exceed
//! `PigeonholeGeometry.max_plaintext_payload_length` bytes.
//!
//! # Database Schema
//!
//! The module creates four tables:
//! - `write_channels`: write capabilities and write-side `next_index`
//! - `read_channels`: read capabilities and read-side `next_index`
//! - `pending_messages`: messages waiting to be sent or acknowledged
//! - `received_messages`: messages received from read channels

pub mod channel;
pub mod db;
pub mod error;
pub mod models;

pub use channel::{CopyStreamBuilder, PigeonholeClient, ReadChannel, WriteChannel};
pub use db::Database;
pub use error::{PigeonholeDbError, Result};
pub use models::{
    PendingMessage, ReadChannel as ReadChannelModel, ReceivedMessage,
    WriteChannel as WriteChannelModel,
};
