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
//! # Example
//!
//! ```rust,ignore
//! use katzenpost_thin_client::pigeonhole_db::{PigeonholeClient, Database};
//!
//! // Open database and create client
//! let db = Database::open("pigeonhole.db")?;
//! let pigeonhole = PigeonholeClient::new(thin_client, db);
//!
//! // Create a channel (generates keypair automatically)
//! let mut channel = pigeonhole.create_channel("my-channel").await?;
//!
//! // Send a message (indices managed automatically)
//! channel.send(b"Hello, world!").await?;
//!
//! // Share read capability with someone else
//! let read_cap = channel.share_read_capability();
//! let read_cap_bytes = read_cap.to_bytes();
//!
//! // On the receiver side:
//! let read_cap = ReadCapability::from_bytes(&read_cap_bytes)?;
//! let mut their_channel = pigeonhole.import_channel("from-alice", &read_cap)?;
//! let message = their_channel.receive().await?;
//! ```
//!
//! # Database Schema
//!
//! The module creates three tables:
//! - `channels`: Stores channel metadata (name, capabilities, indices)
//! - `pending_messages`: Messages waiting to be sent or acknowledged
//! - `received_messages`: Messages received from channels

pub mod channel;
pub mod db;
pub mod error;
pub mod models;

pub use channel::{ChannelHandle, PigeonholeClient};
pub use db::Database;
pub use error::{PigeonholeDbError, Result};
pub use models::{Channel, PendingMessage, ReadCapability, ReceivedMessage};

