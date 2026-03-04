// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! High-level Channel API for simplified pigeonhole operations.

use std::sync::Arc;

use rand::RngCore;

use crate::core::ThinClient;
use super::db::Database;
use super::error::{PigeonholeDbError, Result};
use super::models::{Channel as ChannelModel, ReadCapability, ReceivedMessage};

/// High-level pigeonhole client with database persistence.
///
/// This struct provides a simplified API for pigeonhole operations,
/// automatically managing state (indices, capabilities) via SQLite.
pub struct PigeonholeClient {
    /// The underlying thin client for network operations.
    client: Arc<ThinClient>,
    /// Database for state persistence.
    db: Database,
}

impl PigeonholeClient {
    /// Create a new PigeonholeClient.
    ///
    /// # Arguments
    /// * `client` - The underlying ThinClient for network operations.
    /// * `db` - Database handle for state persistence.
    pub fn new(client: Arc<ThinClient>, db: Database) -> Self {
        Self { client, db }
    }

    /// Create a new PigeonholeClient with an in-memory database (for testing).
    pub fn new_in_memory(client: Arc<ThinClient>) -> Result<Self> {
        let db = Database::open_in_memory()?;
        Ok(Self { client, db })
    }

    /// Get a reference to the database.
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Get a reference to the underlying thin client.
    pub fn thin_client(&self) -> &Arc<ThinClient> {
        &self.client
    }

    /// Create a new owned channel.
    ///
    /// This generates a new keypair and creates a channel that you own
    /// (can both send and receive messages).
    ///
    /// # Arguments
    /// * `name` - Human-readable name for the channel.
    ///
    /// # Returns
    /// A `ChannelHandle` for interacting with the channel.
    pub async fn create_channel(&self, name: &str) -> Result<ChannelHandle> {
        // Generate random seed
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);

        // Create keypair via thin client
        let (write_cap, read_cap, first_index) = self.client.new_keypair(&seed).await?;

        // Store in database
        let channel = self.db.create_channel(name, &write_cap, &read_cap, &first_index)?;

        Ok(ChannelHandle {
            channel,
            client: self.client.clone(),
            db: self.db.clone(),
        })
    }

    /// Import a channel from a shared read capability.
    ///
    /// This creates a read-only channel that you can receive messages from
    /// but cannot send to.
    ///
    /// # Arguments
    /// * `name` - Human-readable name for the channel.
    /// * `read_capability` - The shared read capability.
    ///
    /// # Returns
    /// A `ChannelHandle` for interacting with the channel.
    pub fn import_channel(&self, name: &str, read_capability: &ReadCapability) -> Result<ChannelHandle> {
        let channel = self.db.import_channel(name, &read_capability.read_cap, &read_capability.start_index)?;

        Ok(ChannelHandle {
            channel,
            client: self.client.clone(),
            db: self.db.clone(),
        })
    }

    /// Get an existing channel by name.
    pub fn get_channel(&self, name: &str) -> Result<ChannelHandle> {
        let channel = self.db.get_channel(name)?;

        Ok(ChannelHandle {
            channel,
            client: self.client.clone(),
            db: self.db.clone(),
        })
    }

    /// List all channels.
    pub fn list_channels(&self) -> Result<Vec<ChannelModel>> {
        self.db.list_channels()
    }

    /// Delete a channel and all its messages.
    pub fn delete_channel(&self, name: &str) -> Result<()> {
        self.db.delete_channel(name)
    }
}

/// Handle for interacting with a specific channel.
///
/// This provides the main send/receive API with automatic state management.
pub struct ChannelHandle {
    channel: ChannelModel,
    client: Arc<ThinClient>,
    db: Database,
}

impl ChannelHandle {
    /// Get the channel model.
    pub fn channel(&self) -> &ChannelModel {
        &self.channel
    }

    /// Get the channel name.
    pub fn name(&self) -> &str {
        &self.channel.name
    }

    /// Check if this is an owned channel (can send messages).
    pub fn is_owned(&self) -> bool {
        self.channel.is_owned
    }

    /// Refresh the channel data from the database.
    pub fn refresh(&mut self) -> Result<()> {
        self.channel = self.db.get_channel_by_id(self.channel.id)?;
        Ok(())
    }

    /// Get the read capability for sharing with others.
    ///
    /// Share this with someone to allow them to read messages from this channel.
    pub fn share_read_capability(&self) -> ReadCapability {
        ReadCapability {
            read_cap: self.channel.read_cap.clone(),
            start_index: self.channel.read_index.clone(),
            name: Some(self.channel.name.clone()),
        }
    }

    /// Send a message on this channel.
    ///
    /// This method:
    /// 1. Encrypts the message using the current write index
    /// 2. Stores it as a pending message in the database
    /// 3. Sends it via ARQ (automatic repeat request)
    /// 4. Updates the write index on success
    /// 5. Removes the pending message on success
    ///
    /// # Plaintext Size Constraint
    ///
    /// The `plaintext` must not exceed `PigeonholeGeometry.max_plaintext_payload_length` bytes.
    /// The daemon internally adds a 4-byte big-endian length prefix before padding and
    /// encryption. If the plaintext exceeds the maximum size, the operation will fail
    /// with an error.
    ///
    /// To send larger payloads, use the copy stream API which chunks the data across
    /// multiple boxes.
    ///
    /// # Arguments
    /// * `plaintext` - The message to send. Must be at most
    ///   `PigeonholeGeometry.max_plaintext_payload_length` bytes.
    ///
    /// # Errors
    /// Returns an error if:
    /// - This is a read-only channel (imported, no write capability)
    /// - The plaintext exceeds the maximum payload size
    /// - The underlying send operation fails
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let write_cap = self.channel.write_cap.as_ref().ok_or_else(|| {
            PigeonholeDbError::Other("Cannot send on a read-only channel".to_string())
        })?;

        // Encrypt the message
        let (message_ciphertext, envelope_descriptor, envelope_hash) = self
            .client
            .encrypt_write(plaintext, write_cap, &self.channel.write_index)
            .await?;

        // Store as pending message
        let pending = self.db.create_pending_message(
            self.channel.id,
            plaintext,
            &message_ciphertext,
            &envelope_descriptor,
            &envelope_hash,
            &self.channel.write_index,
        )?;

        // Update status to sending
        self.db.update_pending_message_status(pending.id, "sending")?;

        // Send via ARQ
        let result = self
            .client
            .start_resending_encrypted_message(
                None,                      // read_cap (None for writes)
                Some(write_cap),           // write_cap
                None,                      // next_message_index (not needed for writes)
                Some(0),                   // reply_index
                &envelope_descriptor,
                &message_ciphertext,
                &envelope_hash,
            )
            .await;

        match result {
            Ok(_) => {
                // Success - update write index and remove pending message
                let next_index = self.client.next_message_box_index(&self.channel.write_index).await?;
                self.db.update_write_index(self.channel.id, &next_index)?;
                self.db.delete_pending_message(pending.id)?;
                self.channel.write_index = next_index;
                Ok(())
            }
            Err(e) => {
                // Failed - update pending message status
                self.db.update_pending_message_status(pending.id, "failed")?;
                Err(e.into())
            }
        }
    }

    /// Receive the next message from this channel.
    ///
    /// This method:
    /// 1. Encrypts a read request for the current read index
    /// 2. Sends it via ARQ
    /// 3. Stores the received message in the database
    /// 4. Updates the read index
    /// 5. Returns the plaintext
    ///
    /// # Returns
    /// The decrypted message plaintext (at most `PigeonholeGeometry.max_plaintext_payload_length`
    /// bytes). The length prefix and padding are automatically removed by the daemon.
    ///
    /// # Errors
    /// Returns an error if the read operation fails or times out.
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        // Encrypt read request
        let (message_ciphertext, next_message_index, envelope_descriptor, envelope_hash) = self
            .client
            .encrypt_read(&self.channel.read_cap, &self.channel.read_index)
            .await?;

        // Send via ARQ and get plaintext
        let plaintext = self
            .client
            .start_resending_encrypted_message(
                Some(&self.channel.read_cap), // read_cap
                None,                          // write_cap (None for reads)
                Some(&next_message_index),     // next_message_index
                Some(0),                       // reply_index
                &envelope_descriptor,
                &message_ciphertext,
                &envelope_hash,
            )
            .await?;

        // Store received message
        self.db.create_received_message(
            self.channel.id,
            &plaintext,
            &self.channel.read_index,
        )?;

        // Update read index
        let next_index = self.client.next_message_box_index(&self.channel.read_index).await?;
        self.db.update_read_index(self.channel.id, &next_index)?;
        self.channel.read_index = next_index;

        Ok(plaintext)
    }

    /// Get unread messages from the database (already received).
    pub fn get_unread_messages(&self) -> Result<Vec<ReceivedMessage>> {
        self.db.get_unread_messages(self.channel.id)
    }

    /// Get all received messages from the database.
    pub fn get_all_messages(&self) -> Result<Vec<ReceivedMessage>> {
        self.db.get_all_messages(self.channel.id)
    }

    /// Mark a message as read.
    pub fn mark_message_read(&self, message_id: i64) -> Result<()> {
        self.db.mark_message_read(message_id)
    }
}

