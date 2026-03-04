// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Database models for the pigeonhole_db module.

use serde::{Deserialize, Serialize};

/// A pigeonhole channel stored in the database.
///
/// Channels represent a communication endpoint with write and/or read capabilities.
/// The owner of a channel has the write_cap and can send messages.
/// They can share the read_cap with others to allow reading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    /// Unique database ID.
    pub id: i64,
    /// Human-readable name for the channel.
    pub name: String,
    /// Write capability (only present if we own the channel).
    pub write_cap: Option<Vec<u8>>,
    /// Read capability (always present).
    pub read_cap: Vec<u8>,
    /// Current write index (for sending messages).
    pub write_index: Vec<u8>,
    /// Current read index (for receiving messages).
    pub read_index: Vec<u8>,
    /// Whether this is an owned channel (we have write_cap) or imported (read-only).
    pub is_owned: bool,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: i64,
    /// Last activity timestamp (Unix epoch seconds).
    pub updated_at: i64,
}

/// A pending outgoing message waiting to be sent or acknowledged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMessage {
    /// Unique database ID.
    pub id: i64,
    /// Channel ID this message belongs to.
    pub channel_id: i64,
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

/// A received message from a channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedMessage {
    /// Unique database ID.
    pub id: i64,
    /// Channel ID this message was received from.
    pub channel_id: i64,
    /// The decrypted plaintext message content.
    pub plaintext: Vec<u8>,
    /// The message box index this was read from.
    pub box_index: Vec<u8>,
    /// Reception timestamp (Unix epoch seconds).
    pub received_at: i64,
    /// Whether the message has been read/processed by the application.
    pub is_read: bool,
}

/// Read capability that can be shared with others.
///
/// This is a serializable structure containing all information
/// needed to import and read from a channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadCapability {
    /// The read capability bytes.
    pub read_cap: Vec<u8>,
    /// The starting message index for reading.
    pub start_index: Vec<u8>,
    /// Optional human-readable name/description.
    pub name: Option<String>,
}

impl ReadCapability {
    /// Serialize to bytes for sharing (e.g., as a QR code or file).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).expect("Failed to serialize ReadCapability")
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_cbor::Error> {
        serde_cbor::from_slice(bytes)
    }
}

