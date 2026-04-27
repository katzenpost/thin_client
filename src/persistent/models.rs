// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Database models for the persistent pigeonhole module.

use serde::{Deserialize, Serialize};

/// A pigeonhole write channel stored in the database.
///
/// A write channel carries the write capability and the next message box
/// index to be used for the next write. The cap is immutable; `next_index`
/// advances with each successful write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteChannel {
    /// Unique database ID.
    pub id: i64,
    /// Human-readable name for the channel.
    pub name: String,
    /// Write capability bytes.
    pub write_cap: Vec<u8>,
    /// The next message box index to use for the next write.
    pub next_index: Vec<u8>,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: i64,
    /// Last activity timestamp (Unix epoch seconds).
    pub updated_at: i64,
}

/// A pigeonhole read channel stored in the database.
///
/// A read channel carries the read capability and the next message box
/// index to be used for the next read. The cap is immutable; `next_index`
/// advances with each successful read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadChannel {
    /// Unique database ID.
    pub id: i64,
    /// Human-readable name for the channel.
    pub name: String,
    /// Read capability bytes.
    pub read_cap: Vec<u8>,
    /// The next message box index to use for the next read.
    pub next_index: Vec<u8>,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: i64,
    /// Last activity timestamp (Unix epoch seconds).
    pub updated_at: i64,
}

/// A pending outgoing message waiting to be sent or acknowledged.
///
/// `write_channel_id` references a row in the `write_channels` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMessage {
    /// Unique database ID.
    pub id: i64,
    /// Write channel ID this message belongs to.
    pub write_channel_id: i64,
    /// The plaintext message content.
    pub plaintext: Vec<u8>,
    /// The encrypted message ciphertext.
    pub message_ciphertext: Vec<u8>,
    /// Envelope descriptor for decryption.
    pub envelope_descriptor: Vec<u8>,
    /// Envelope hash for cancellation/tracking.
    pub envelope_hash: Vec<u8>,
    /// The message box index this was sent to.
    pub box_index: Vec<u8>,
    /// Number of send attempts.
    pub attempts: i32,
    /// Current status: "pending", "sending", "sent", "failed".
    pub status: String,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: i64,
    /// Last attempt timestamp (Unix epoch seconds).
    pub last_attempt_at: Option<i64>,
}

/// A received message from a read channel.
///
/// `read_channel_id` references a row in the `read_channels` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedMessage {
    /// Unique database ID.
    pub id: i64,
    /// Read channel ID this message was received from.
    pub read_channel_id: i64,
    /// The decrypted plaintext message content.
    pub plaintext: Vec<u8>,
    /// The message box index this was read from.
    pub box_index: Vec<u8>,
    /// Reception timestamp (Unix epoch seconds).
    pub received_at: i64,
    /// Whether the message has been read/processed by the application.
    pub is_read: bool,
}
