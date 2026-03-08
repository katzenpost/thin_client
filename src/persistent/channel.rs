// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! High-level Channel API for simplified pigeonhole operations.

use std::sync::Arc;

use rand::RngCore;

use crate::core::ThinClient;
use crate::pigeonhole::TombstoneRangeResult;
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

    /// Get the write capability for this channel.
    ///
    /// Returns the write capability if this is an owned channel, or `None` if
    /// this is an imported read-only channel.
    ///
    /// The write capability is needed for operations like:
    /// - The Copy command, which copies data from a temporary channel to a destination
    /// - Resuming write operations after a restart
    /// - Advanced ARQ scenarios
    ///
    /// # Security Note
    /// The write capability grants full write access to the channel. Only share
    /// it with trusted parties or use it in secure contexts like the Copy command.
    pub fn write_cap(&self) -> Option<&[u8]> {
        self.channel.write_cap.as_deref()
    }

    /// Get the read capability bytes for this channel.
    ///
    /// This returns the raw read capability bytes, which can be used for
    /// low-level operations or when you need the capability without the
    /// additional metadata included in [`share_read_capability`].
    pub fn read_cap(&self) -> &[u8] {
        &self.channel.read_cap
    }

    /// Get the current write index for this channel.
    ///
    /// This is the next message box index that will be used when sending.
    /// Returns `None` if this is a read-only channel.
    pub fn write_index(&self) -> Option<&[u8]> {
        if self.channel.is_owned {
            Some(&self.channel.write_index)
        } else {
            None
        }
    }

    /// Get the current read index for this channel.
    ///
    /// This is the next message box index that will be read from.
    pub fn read_index(&self) -> &[u8] {
        &self.channel.read_index
    }

    // ========================================================================
    // Low-Level Box Operations (single box, no state management)
    // ========================================================================

    /// Write a single box payload at a specific index (low-level).
    ///
    /// This is the low-level primitive for writing to a pigeonhole box.
    /// It does NOT update the channel's write index - use this when you need
    /// precise control over box indices.
    ///
    /// # Arguments
    /// * `plaintext` - The payload to write. Must be at most
    ///   `PigeonholeGeometry.max_plaintext_payload_length` bytes.
    /// * `box_index` - The specific box index to write to.
    ///
    /// # Returns
    /// The next box index after this write.
    ///
    /// # Errors
    /// Returns an error if this is a read-only channel or the operation fails.
    pub async fn write_box(&self, plaintext: &[u8], box_index: &[u8]) -> Result<Vec<u8>> {
        let write_cap = self.channel.write_cap.as_ref().ok_or_else(|| {
            PigeonholeDbError::Other("Cannot write on a read-only channel".to_string())
        })?;

        let (message_ciphertext, envelope_descriptor, envelope_hash) = self
            .client
            .encrypt_write(plaintext, write_cap, box_index)
            .await?;

        self.client
            .start_resending_encrypted_message(
                None,
                Some(write_cap),
                None,
                Some(0),
                &envelope_descriptor,
                &message_ciphertext,
                &envelope_hash,
            )
            .await?;

        let next_index = self.client.next_message_box_index(box_index).await?;
        Ok(next_index)
    }

    /// Write a single box payload at a specific index, returning BoxAlreadyExists as error.
    ///
    /// Like `write_box`, but returns `BoxAlreadyExistsError` if the box already
    /// contains data, instead of treating it as an idempotent success.
    ///
    /// # Arguments
    /// * `plaintext` - The payload to write.
    /// * `box_index` - The specific box index to write to.
    ///
    /// # Returns
    /// The next box index after this write.
    ///
    /// # Errors
    /// Returns `BoxAlreadyExistsError` if the box is already written.
    pub async fn write_box_return_box_exists(&self, plaintext: &[u8], box_index: &[u8]) -> Result<Vec<u8>> {
        let write_cap = self.channel.write_cap.as_ref().ok_or_else(|| {
            PigeonholeDbError::Other("Cannot write on a read-only channel".to_string())
        })?;

        let (message_ciphertext, envelope_descriptor, envelope_hash) = self
            .client
            .encrypt_write(plaintext, write_cap, box_index)
            .await?;

        self.client
            .start_resending_encrypted_message_return_box_exists(
                None,
                Some(write_cap),
                None,
                Some(0),
                &envelope_descriptor,
                &message_ciphertext,
                &envelope_hash,
            )
            .await?;

        let next_index = self.client.next_message_box_index(box_index).await?;
        Ok(next_index)
    }

    /// Read a single box payload at a specific index (low-level).
    ///
    /// This is the low-level primitive for reading from a pigeonhole box.
    /// It does NOT update the channel's read index - use this when you need
    /// precise control over box indices.
    ///
    /// # Arguments
    /// * `box_index` - The specific box index to read from.
    ///
    /// # Returns
    /// A tuple of (plaintext, next_box_index).
    ///
    /// # Errors
    /// Returns an error if the read operation fails.
    pub async fn read_box(&self, box_index: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (message_ciphertext, next_message_index, envelope_descriptor, envelope_hash) = self
            .client
            .encrypt_read(&self.channel.read_cap, box_index)
            .await?;

        let plaintext = self
            .client
            .start_resending_encrypted_message(
                Some(&self.channel.read_cap),
                None,
                Some(&next_message_index),
                Some(0),
                &envelope_descriptor,
                &message_ciphertext,
                &envelope_hash,
            )
            .await?;

        let next_index = self.client.next_message_box_index(box_index).await?;
        Ok((plaintext, next_index))
    }

    /// Read a single box without automatic retries on BoxIDNotFound.
    ///
    /// Like `read_box`, but returns `BoxIDNotFoundError` immediately instead
    /// of retrying (which normally accounts for mixnet replication lag).
    ///
    /// Use this when you need to quickly check if a box exists without waiting
    /// for potential retries.
    ///
    /// # Arguments
    /// * `box_index` - The specific box index to read from.
    ///
    /// # Returns
    /// A tuple of (plaintext, next_box_index).
    ///
    /// # Errors
    /// Returns `BoxIDNotFoundError` immediately if box doesn't exist.
    pub async fn read_box_no_retry(&self, box_index: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (message_ciphertext, next_message_index, envelope_descriptor, envelope_hash) = self
            .client
            .encrypt_read(&self.channel.read_cap, box_index)
            .await?;

        let plaintext = self
            .client
            .start_resending_encrypted_message_no_retry(
                Some(&self.channel.read_cap),
                None,
                Some(&next_message_index),
                Some(0),
                &envelope_descriptor,
                &message_ciphertext,
                &envelope_hash,
            )
            .await?;

        let next_index = self.client.next_message_box_index(box_index).await?;
        Ok((plaintext, next_index))
    }

    // ========================================================================
    // High-Level Send/Receive (with state management)
    // ========================================================================

    /// Send a message on this channel (high-level).
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
    /// For larger payloads, use the copy stream API via `CopyStreamBuilder`.
    ///
    /// # Arguments
    /// * `plaintext` - The message to send.
    ///
    /// # Errors
    /// Returns an error if this is a read-only channel or the operation fails.
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let write_cap = self.channel.write_cap.as_ref().ok_or_else(|| {
            PigeonholeDbError::Other("Cannot send on a read-only channel".to_string())
        })?;

        let (message_ciphertext, envelope_descriptor, envelope_hash) = self
            .client
            .encrypt_write(plaintext, write_cap, &self.channel.write_index)
            .await?;

        let pending = self.db.create_pending_message(
            self.channel.id,
            plaintext,
            &message_ciphertext,
            &envelope_descriptor,
            &envelope_hash,
            &self.channel.write_index,
        )?;

        self.db.update_pending_message_status(pending.id, "sending")?;

        let result = self
            .client
            .start_resending_encrypted_message(
                None,
                Some(write_cap),
                None,
                Some(0),
                &envelope_descriptor,
                &message_ciphertext,
                &envelope_hash,
            )
            .await;

        match result {
            Ok(_) => {
                let next_index = self.client.next_message_box_index(&self.channel.write_index).await?;
                self.db.update_write_index(self.channel.id, &next_index)?;
                self.db.delete_pending_message(pending.id)?;
                self.channel.write_index = next_index;
                Ok(())
            }
            Err(e) => {
                self.db.update_pending_message_status(pending.id, "failed")?;
                Err(e.into())
            }
        }
    }

    /// Send a message, returning BoxAlreadyExists as error if box is occupied.
    ///
    /// Like `send`, but returns `BoxAlreadyExistsError` if the box already
    /// contains data, instead of treating it as an idempotent success.
    ///
    /// # Arguments
    /// * `plaintext` - The message to send.
    ///
    /// # Errors
    /// Returns `BoxAlreadyExistsError` if the box is already written.
    pub async fn send_return_box_exists(&mut self, plaintext: &[u8]) -> Result<()> {
        let write_cap = self.channel.write_cap.as_ref().ok_or_else(|| {
            PigeonholeDbError::Other("Cannot send on a read-only channel".to_string())
        })?;

        let (message_ciphertext, envelope_descriptor, envelope_hash) = self
            .client
            .encrypt_write(plaintext, write_cap, &self.channel.write_index)
            .await?;

        let pending = self.db.create_pending_message(
            self.channel.id,
            plaintext,
            &message_ciphertext,
            &envelope_descriptor,
            &envelope_hash,
            &self.channel.write_index,
        )?;

        self.db.update_pending_message_status(pending.id, "sending")?;

        let result = self
            .client
            .start_resending_encrypted_message_return_box_exists(
                None,
                Some(write_cap),
                None,
                Some(0),
                &envelope_descriptor,
                &message_ciphertext,
                &envelope_hash,
            )
            .await;

        match result {
            Ok(_) => {
                let next_index = self.client.next_message_box_index(&self.channel.write_index).await?;
                self.db.update_write_index(self.channel.id, &next_index)?;
                self.db.delete_pending_message(pending.id)?;
                self.channel.write_index = next_index;
                Ok(())
            }
            Err(e) => {
                self.db.update_pending_message_status(pending.id, "failed")?;
                Err(e.into())
            }
        }
    }

    /// Receive the next message from this channel (high-level).
    ///
    /// This method reads from the current read index, stores the message,
    /// and advances the read index.
    ///
    /// # Returns
    /// The decrypted message plaintext.
    ///
    /// # Errors
    /// Returns an error if the read operation fails.
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        let (message_ciphertext, next_message_index, envelope_descriptor, envelope_hash) = self
            .client
            .encrypt_read(&self.channel.read_cap, &self.channel.read_index)
            .await?;

        let plaintext = self
            .client
            .start_resending_encrypted_message(
                Some(&self.channel.read_cap),
                None,
                Some(&next_message_index),
                Some(0),
                &envelope_descriptor,
                &message_ciphertext,
                &envelope_hash,
            )
            .await?;

        self.db.create_received_message(
            self.channel.id,
            &plaintext,
            &self.channel.read_index,
        )?;

        let next_index = self.client.next_message_box_index(&self.channel.read_index).await?;
        self.db.update_read_index(self.channel.id, &next_index)?;
        self.channel.read_index = next_index;

        Ok(plaintext)
    }

    /// Receive the next message without automatic retries on BoxIDNotFound.
    ///
    /// Like `receive`, but returns `BoxIDNotFoundError` immediately instead
    /// of retrying (which normally accounts for mixnet replication lag).
    ///
    /// Use this when you need to quickly check if a message exists without
    /// waiting for potential retries.
    ///
    /// # Returns
    /// The decrypted message plaintext.
    ///
    /// # Errors
    /// Returns `BoxIDNotFoundError` immediately if no message exists.
    pub async fn receive_no_retry(&mut self) -> Result<Vec<u8>> {
        let (message_ciphertext, next_message_index, envelope_descriptor, envelope_hash) = self
            .client
            .encrypt_read(&self.channel.read_cap, &self.channel.read_index)
            .await?;

        let plaintext = self
            .client
            .start_resending_encrypted_message_no_retry(
                Some(&self.channel.read_cap),
                None,
                Some(&next_message_index),
                Some(0),
                &envelope_descriptor,
                &message_ciphertext,
                &envelope_hash,
            )
            .await?;

        self.db.create_received_message(
            self.channel.id,
            &plaintext,
            &self.channel.read_index,
        )?;

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

    // ========================================================================
    // Tombstone Operations
    // ========================================================================

    /// Tombstone (delete) the current write position.
    ///
    /// This writes an empty payload to the current write index, effectively
    /// deleting the message at that position. The write index is then advanced.
    ///
    /// # Errors
    /// Returns an error if this is a read-only channel or the operation fails.
    pub async fn tombstone_current(&mut self) -> Result<()> {
        let write_cap = self.channel.write_cap.as_ref().ok_or_else(|| {
            PigeonholeDbError::Other("Cannot tombstone on a read-only channel".to_string())
        })?;

        // Create and send the tombstone
        let (ciphertext, env_desc, env_hash) = self
            .client
            .tombstone_box(write_cap, &self.channel.write_index)
            .await?;

        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&env_hash);

        self.client
            .start_resending_encrypted_message(
                None,
                Some(write_cap),
                None,
                None, // No reply expected for tombstone
                &env_desc,
                &ciphertext,
                &hash_arr,
            )
            .await?;

        // Update write index
        let next_index = self.client.next_message_box_index(&self.channel.write_index).await?;
        self.db.update_write_index(self.channel.id, &next_index)?;
        self.channel.write_index = next_index;

        Ok(())
    }

    /// Tombstone a range of boxes starting from the current write position.
    ///
    /// This creates tombstones for up to `count` boxes and sends them all.
    /// The write index is advanced past all tombstoned boxes.
    ///
    /// # Arguments
    /// * `count` - Maximum number of boxes to tombstone.
    ///
    /// # Returns
    /// The number of boxes successfully tombstoned.
    ///
    /// # Errors
    /// Returns an error if this is a read-only channel.
    pub async fn tombstone_range(&mut self, count: u32) -> Result<u32> {
        let write_cap = self.channel.write_cap.as_ref().ok_or_else(|| {
            PigeonholeDbError::Other("Cannot tombstone on a read-only channel".to_string())
        })?;

        let result: TombstoneRangeResult = self
            .client
            .tombstone_range(write_cap, &self.channel.write_index, count)
            .await;

        let mut sent_count = 0u32;

        // Send all the tombstone envelopes
        for envelope in &result.envelopes {
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(&envelope.envelope_hash);

            match self.client.start_resending_encrypted_message(
                None,
                Some(write_cap),
                None,
                None,
                &envelope.envelope_descriptor,
                &envelope.message_ciphertext,
                &hash_arr,
            ).await {
                Ok(_) => sent_count += 1,
                Err(e) => {
                    // Update write index to where we got to
                    if sent_count > 0 {
                        self.db.update_write_index(self.channel.id, &envelope.box_index)?;
                        self.channel.write_index = envelope.box_index.clone();
                    }
                    return Err(e.into());
                }
            }
        }

        // Update write index to the final position
        if sent_count > 0 {
            self.db.update_write_index(self.channel.id, &result.next)?;
            self.channel.write_index = result.next;
        }

        Ok(sent_count)
    }

    /// Tombstone (delete) a specific box by its index.
    ///
    /// This writes an empty payload to the specified box index, effectively
    /// deleting the message at that position. This does NOT update the channel's
    /// write index - use this when you need to delete a specific previously-written box.
    ///
    /// # Arguments
    /// * `box_index` - The specific box index to tombstone.
    ///
    /// # Errors
    /// Returns an error if this is a read-only channel or the operation fails.
    pub async fn tombstone_at(&self, box_index: &[u8]) -> Result<()> {
        let write_cap = self.channel.write_cap.as_ref().ok_or_else(|| {
            PigeonholeDbError::Other("Cannot tombstone on a read-only channel".to_string())
        })?;

        // Create and send the tombstone
        let (ciphertext, env_desc, env_hash) = self
            .client
            .tombstone_box(write_cap, box_index)
            .await?;

        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&env_hash);

        self.client
            .start_resending_encrypted_message(
                None,
                Some(write_cap),
                None,
                None, // No reply expected for tombstone
                &env_desc,
                &ciphertext,
                &hash_arr,
            )
            .await?;

        Ok(())
    }

    /// Tombstone a range of boxes starting from a specific index.
    ///
    /// This creates tombstones for up to `count` boxes starting from `start_index`
    /// and sends them all. This does NOT update the channel's write index - use this
    /// when you need to delete specific previously-written boxes.
    ///
    /// # Arguments
    /// * `start_index` - The box index to start tombstoning from.
    /// * `count` - Maximum number of boxes to tombstone.
    ///
    /// # Returns
    /// The number of boxes successfully tombstoned.
    ///
    /// # Errors
    /// Returns an error if this is a read-only channel.
    pub async fn tombstone_from(&self, start_index: &[u8], count: u32) -> Result<u32> {
        let write_cap = self.channel.write_cap.as_ref().ok_or_else(|| {
            PigeonholeDbError::Other("Cannot tombstone on a read-only channel".to_string())
        })?;

        let result: TombstoneRangeResult = self
            .client
            .tombstone_range(write_cap, start_index, count)
            .await;

        let mut sent_count = 0u32;

        // Send all the tombstone envelopes
        for envelope in &result.envelopes {
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(&envelope.envelope_hash);

            match self.client.start_resending_encrypted_message(
                None,
                Some(write_cap),
                None,
                None,
                &envelope.envelope_descriptor,
                &envelope.message_ciphertext,
                &hash_arr,
            ).await {
                Ok(_) => sent_count += 1,
                Err(e) => {
                    return Err(e.into());
                }
            }
        }

        Ok(sent_count)
    }

    // ========================================================================
    // Copy Stream Operations
    // ========================================================================

    /// Create a new CopyStreamBuilder for streaming large payloads.
    ///
    /// Use this for payloads of any size. The builder allows you to add
    /// payloads incrementally (streaming from disk, network, etc.) without
    /// loading everything into memory at once.
    ///
    /// # Example
    /// ```ignore
    /// let mut builder = channel.copy_stream_builder().await?;
    ///
    /// // Stream data in chunks (e.g., reading from a file)
    /// while let Some(chunk) = file.read_chunk() {
    ///     builder.add_payload(&chunk, dest_write_cap, dest_start_index, false).await?;
    /// }
    ///
    /// // Finalize and execute the copy
    /// builder.finish().await?;
    /// ```
    pub async fn copy_stream_builder(&self) -> Result<CopyStreamBuilder> {
        CopyStreamBuilder::new(self.client.clone()).await
    }

    /// Execute a Copy command using this channel's write capability as the source.
    ///
    /// This is useful when this channel has been used as a temporary copy stream
    /// and you want to trigger the courier to copy from it to the destination(s)
    /// encoded in the stream.
    ///
    /// # Arguments
    /// * `courier_identity_hash` - Optional specific courier to use.
    /// * `courier_queue_id` - Optional queue ID for the specific courier.
    ///
    /// # Errors
    /// Returns an error if this is a read-only channel or the operation fails.
    pub async fn execute_copy(
        &self,
        courier_identity_hash: Option<&[u8]>,
        courier_queue_id: Option<&[u8]>,
    ) -> Result<()> {
        let write_cap = self.channel.write_cap.as_ref().ok_or_else(|| {
            PigeonholeDbError::Other("Cannot execute copy on a read-only channel".to_string())
        })?;

        self.client
            .start_resending_copy_command(write_cap, courier_identity_hash, courier_queue_id)
            .await?;

        Ok(())
    }

    /// Cancel a Copy command in progress.
    ///
    /// This stops the automatic repeat request (ARQ) for a previously started
    /// copy command.
    ///
    /// # Arguments
    /// * `write_cap_hash` - 32-byte hash of the WriteCap used in execute_copy.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn cancel_copy(&self, write_cap_hash: &[u8; 32]) -> Result<()> {
        self.client
            .cancel_resending_copy_command(write_cap_hash)
            .await?;

        Ok(())
    }
}

/// Builder for creating copy streams that can handle arbitrarily large payloads.
///
/// This builder uses the daemon's internal buffer (correlated by stream ID) to
/// efficiently pack data into the temporary channel. You can call `add_payload`
/// multiple times with chunks of data, and the daemon handles the packing.
///
/// # Memory Efficiency
/// Unlike passing large buffers, this approach:
/// - Uses stream ID correlation to maintain state in the daemon
/// - Allows streaming data from disk/network without loading everything into memory
/// - Packs multiple payloads efficiently into copy stream boxes
///
/// # Crash Recovery
/// When `is_last=false` is passed to `add_payload` or `add_multi_payload`, partial
/// data may be buffered by the daemon. The buffer is saved after each call and can
/// be accessed via `buffer()`. To recover after a crash, persist the buffer and
/// restore it via `ThinClient::set_stream_buffer` before continuing the stream.
///
/// # Example
/// ```ignore
/// let mut builder = channel.copy_stream_builder().await?;
///
/// // Add multiple payloads to different destinations
/// builder.add_payload(payload1, dest1_write_cap, dest1_index, false).await?;
/// builder.add_payload(payload2, dest2_write_cap, dest2_index, false).await?;
///
/// // Finalize and send the copy command
/// let boxes_written = builder.finish().await?;
/// ```
pub struct CopyStreamBuilder {
    client: Arc<ThinClient>,
    stream_id: [u8; 16],
    temp_write_cap: Vec<u8>,
    temp_index: Vec<u8>,
    total_boxes: usize,
    /// Buffer containing data that hasn't been output yet.
    /// This can be persisted for crash recovery.
    buffer: Vec<u8>,
}

impl CopyStreamBuilder {
    /// Create a new CopyStreamBuilder.
    async fn new(client: Arc<ThinClient>) -> Result<Self> {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let (temp_write_cap, _temp_read_cap, temp_first_index) =
            client.new_keypair(&seed).await?;

        Ok(Self {
            client,
            stream_id: ThinClient::new_stream_id(),
            temp_write_cap,
            temp_index: temp_first_index,
            total_boxes: 0,
            buffer: Vec::new(),
        })
    }

    /// Add a payload to the copy stream.
    ///
    /// This can be called multiple times to stream data incrementally.
    /// Each call creates courier envelopes and writes them to the temporary
    /// channel immediately.
    ///
    /// # Arguments
    /// * `payload` - The payload chunk to add (max 10MB per call).
    /// * `dest_write_cap` - Write capability for the destination.
    /// * `dest_start_index` - Starting index in the destination.
    /// * `is_last` - True if this is the final payload for this destination.
    ///
    /// # Returns
    /// The number of boxes written for this payload.
    pub async fn add_payload(
        &mut self,
        payload: &[u8],
        dest_write_cap: &[u8],
        dest_start_index: &[u8],
        is_last: bool,
    ) -> Result<usize> {
        let result = self.client.create_courier_envelopes_from_payload(
            &self.stream_id,
            payload,
            dest_write_cap,
            dest_start_index,
            is_last,
        ).await?;

        let chunk_count = result.envelopes.len();

        // Save the buffer for crash recovery
        self.buffer = result.buffer;

        for chunk in result.envelopes {
            let (ciphertext, env_desc, env_hash) = self
                .client
                .encrypt_write(&chunk, &self.temp_write_cap, &self.temp_index)
                .await?;

            self.client
                .start_resending_encrypted_message(
                    None,
                    Some(&self.temp_write_cap),
                    None,
                    Some(0),
                    &env_desc,
                    &ciphertext,
                    &env_hash,
                )
                .await?;

            self.temp_index = self.client.next_message_box_index(&self.temp_index).await?;
        }

        self.total_boxes += chunk_count;
        Ok(chunk_count)
    }

    /// Add multiple payloads to different destinations efficiently.
    ///
    /// This packs all payloads together, which is more space-efficient than
    /// calling `add_payload` multiple times because envelopes from different
    /// destinations are packed together without wasting space.
    ///
    /// # Arguments
    /// * `destinations` - List of (payload, dest_write_cap, dest_start_index) tuples.
    /// * `is_last` - True if this is the final set of payloads.
    ///
    /// # Returns
    /// The number of boxes written.
    pub async fn add_multi_payload(
        &mut self,
        destinations: Vec<(&[u8], &[u8], &[u8])>,
        is_last: bool,
    ) -> Result<usize> {
        if destinations.is_empty() {
            return Ok(0);
        }

        let result = self.client.create_courier_envelopes_from_multi_payload(
            &self.stream_id,
            destinations,
            is_last,
        ).await?;

        let chunk_count = result.envelopes.len();

        // Save the buffer for crash recovery
        self.buffer = result.buffer;

        for chunk in result.envelopes {
            let (ciphertext, env_desc, env_hash) = self
                .client
                .encrypt_write(&chunk, &self.temp_write_cap, &self.temp_index)
                .await?;

            self.client
                .start_resending_encrypted_message(
                    None,
                    Some(&self.temp_write_cap),
                    None,
                    Some(0),
                    &env_desc,
                    &ciphertext,
                    &env_hash,
                )
                .await?;

            self.temp_index = self.client.next_message_box_index(&self.temp_index).await?;
        }

        self.total_boxes += chunk_count;
        Ok(chunk_count)
    }

    /// Finalize the copy stream and execute the Copy command.
    ///
    /// This sends the Copy command to the courier, which will read the
    /// temporary channel and execute all the write operations atomically.
    ///
    /// # Returns
    /// The total number of boxes written to the temporary channel.
    pub async fn finish(self) -> Result<usize> {
        self.client
            .start_resending_copy_command(&self.temp_write_cap, None, None)
            .await?;

        Ok(self.total_boxes)
    }

    /// Finalize with a specific courier.
    ///
    /// # Arguments
    /// * `courier_identity_hash` - Identity hash of the courier to use.
    /// * `courier_queue_id` - Queue ID for the courier.
    pub async fn finish_with_courier(
        self,
        courier_identity_hash: &[u8],
        courier_queue_id: &[u8],
    ) -> Result<usize> {
        self.client
            .start_resending_copy_command(
                &self.temp_write_cap,
                Some(courier_identity_hash),
                Some(courier_queue_id),
            )
            .await?;

        Ok(self.total_boxes)
    }

    /// Get the temporary channel's write capability.
    ///
    /// This can be used to cancel the copy operation if needed.
    pub fn temp_write_cap(&self) -> &[u8] {
        &self.temp_write_cap
    }

    /// Get the stream ID for this copy stream.
    pub fn stream_id(&self) -> &[u8; 16] {
        &self.stream_id
    }

    /// Get the current buffer contents for crash recovery.
    ///
    /// When `is_last=false` is passed to `add_payload` or `add_multi_payload`,
    /// partial data may be buffered. This buffer can be persisted and restored
    /// via `ThinClient::set_stream_buffer` on restart to continue the stream.
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }
}

