// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed channel handles for simplified pigeonhole operations.
//!
//! A `WriteChannel` carries the write capability and tracks the next
//! message box index for sending. A `ReadChannel` carries the read
//! capability and tracks the next message box index for receiving.
//! Capabilities themselves are immutable; only `next_index` advances.

use std::sync::Arc;

use rand::RngCore;

use crate::core::ThinClient;
use crate::pigeonhole::{KeypairResult, TombstoneRangeResult};
use super::db::Database;
use super::error::{PigeonholeDbError, Result};
use super::models::{
    ReadChannel as ReadChannelModel, ReceivedMessage, WriteChannel as WriteChannelModel,
};

/// High-level pigeonhole client with database persistence.
pub struct PigeonholeClient {
    client: Arc<ThinClient>,
    db: Database,
}

impl PigeonholeClient {
    pub fn new(client: Arc<ThinClient>, db: Database) -> Self {
        Self { client, db }
    }

    pub fn new_in_memory(client: Arc<ThinClient>) -> Result<Self> {
        let db = Database::open_in_memory()?;
        Ok(Self { client, db })
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn thin_client(&self) -> &Arc<ThinClient> {
        &self.client
    }

    // ========================================================================
    // Write Channel Constructors
    // ========================================================================

    /// Load an owned write channel from previously-issued capability material.
    ///
    /// `next_index` is the message box index to use for the next write —
    /// either `first_message_index` from `new_keypair` for a fresh channel,
    /// or a saved cursor from a prior session for resume.
    pub fn load_write_channel(
        &self,
        name: &str,
        write_cap: &[u8],
        next_index: &[u8],
    ) -> Result<WriteChannel> {
        let model = self.db.create_write_channel(name, write_cap, next_index)?;
        Ok(WriteChannel { model, client: self.client.clone(), db: self.db.clone() })
    }

    /// Get an existing write channel by name.
    pub fn get_write_channel(&self, name: &str) -> Result<WriteChannel> {
        let model = self.db.get_write_channel(name)?;
        Ok(WriteChannel { model, client: self.client.clone(), db: self.db.clone() })
    }

    /// List all stored write channels.
    pub fn list_write_channels(&self) -> Result<Vec<WriteChannelModel>> {
        self.db.list_write_channels()
    }

    /// Delete a write channel and all its pending messages.
    pub fn delete_write_channel(&self, name: &str) -> Result<()> {
        self.db.delete_write_channel(name)
    }

    // ========================================================================
    // Read Channel Constructors
    // ========================================================================

    /// Load a read channel from previously-issued capability material.
    ///
    /// `next_index` is the message box index to use for the next read —
    /// either `first_message_index` from `new_keypair` for a fresh channel,
    /// or a saved cursor from a prior session for resume.
    pub fn load_read_channel(
        &self,
        name: &str,
        read_cap: &[u8],
        next_index: &[u8],
    ) -> Result<ReadChannel> {
        let model = self.db.create_read_channel(name, read_cap, next_index)?;
        Ok(ReadChannel { model, client: self.client.clone(), db: self.db.clone() })
    }

    /// Get an existing read channel by name.
    pub fn get_read_channel(&self, name: &str) -> Result<ReadChannel> {
        let model = self.db.get_read_channel(name)?;
        Ok(ReadChannel { model, client: self.client.clone(), db: self.db.clone() })
    }

    /// List all stored read channels.
    pub fn list_read_channels(&self) -> Result<Vec<ReadChannelModel>> {
        self.db.list_read_channels()
    }

    /// Delete a read channel and all its received messages.
    pub fn delete_read_channel(&self, name: &str) -> Result<()> {
        self.db.delete_read_channel(name)
    }
}

// ============================================================================
// WriteChannel
// ============================================================================

/// Handle for sending on a pigeonhole channel.
pub struct WriteChannel {
    model: WriteChannelModel,
    client: Arc<ThinClient>,
    db: Database,
}

impl WriteChannel {
    pub fn name(&self) -> &str {
        &self.model.name
    }

    pub fn write_cap(&self) -> &[u8] {
        &self.model.write_cap
    }

    /// The message box index that will be used for the next write.
    pub fn next_index(&self) -> &[u8] {
        &self.model.next_index
    }

    /// Refresh the in-memory model from the database.
    pub fn refresh(&mut self) -> Result<()> {
        self.model = self.db.get_write_channel_by_id(self.model.id)?;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Low-Level Box Operations (caller-supplied index, no state advancement)
    // ------------------------------------------------------------------------

    /// Write a single box at a specific index. Does NOT advance `next_index`.
    pub async fn write_box(&self, plaintext: &[u8], box_index: &[u8]) -> Result<Vec<u8>> {
        let result = self
            .client
            .encrypt_write(plaintext, &self.model.write_cap, box_index)
            .await?;

        self.client
            .start_resending_encrypted_message(
                None,
                Some(&self.model.write_cap),
                None,
                Some(0),
                &result.envelope_descriptor,
                &result.message_ciphertext,
                &result.envelope_hash,
            )
            .await?;

        Ok(result.next_message_box_index)
    }

    /// Write a single box, returning `BoxAlreadyExists` rather than treating
    /// re-writes as idempotent successes.
    pub async fn write_box_return_box_exists(
        &self,
        plaintext: &[u8],
        box_index: &[u8],
    ) -> Result<Vec<u8>> {
        let result = self
            .client
            .encrypt_write(plaintext, &self.model.write_cap, box_index)
            .await?;

        self.client
            .start_resending_encrypted_message_return_box_exists(
                None,
                Some(&self.model.write_cap),
                None,
                Some(0),
                &result.envelope_descriptor,
                &result.message_ciphertext,
                &result.envelope_hash,
            )
            .await?;

        Ok(result.next_message_box_index)
    }

    // ------------------------------------------------------------------------
    // High-Level Send (advances state in the database)
    // ------------------------------------------------------------------------

    /// Send a message at the channel's `next_index`, advancing state on success.
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let encrypt_result = self
            .client
            .encrypt_write(plaintext, &self.model.write_cap, &self.model.next_index)
            .await?;

        let pending = self.db.create_pending_message(
            self.model.id,
            plaintext,
            &encrypt_result.message_ciphertext,
            &encrypt_result.envelope_descriptor,
            &encrypt_result.envelope_hash,
            &self.model.next_index,
        )?;

        self.db.update_pending_message_status(pending.id, "sending")?;

        let result = self
            .client
            .start_resending_encrypted_message(
                None,
                Some(&self.model.write_cap),
                None,
                Some(0),
                &encrypt_result.envelope_descriptor,
                &encrypt_result.message_ciphertext,
                &encrypt_result.envelope_hash,
            )
            .await;

        match result {
            Ok(_) => {
                let next = encrypt_result.next_message_box_index;
                self.db.update_write_next_index(self.model.id, &next)?;
                self.db.delete_pending_message(pending.id)?;
                self.model.next_index = next;
                Ok(())
            }
            Err(e) => {
                self.db.update_pending_message_status(pending.id, "failed")?;
                Err(e.into())
            }
        }
    }

    /// Like `send`, but returns `BoxAlreadyExists` rather than treating
    /// re-writes as idempotent successes.
    pub async fn send_return_box_exists(&mut self, plaintext: &[u8]) -> Result<()> {
        let encrypt_result = self
            .client
            .encrypt_write(plaintext, &self.model.write_cap, &self.model.next_index)
            .await?;

        let pending = self.db.create_pending_message(
            self.model.id,
            plaintext,
            &encrypt_result.message_ciphertext,
            &encrypt_result.envelope_descriptor,
            &encrypt_result.envelope_hash,
            &self.model.next_index,
        )?;

        self.db.update_pending_message_status(pending.id, "sending")?;

        let result = self
            .client
            .start_resending_encrypted_message_return_box_exists(
                None,
                Some(&self.model.write_cap),
                None,
                Some(0),
                &encrypt_result.envelope_descriptor,
                &encrypt_result.message_ciphertext,
                &encrypt_result.envelope_hash,
            )
            .await;

        match result {
            Ok(_) => {
                let next = encrypt_result.next_message_box_index;
                self.db.update_write_next_index(self.model.id, &next)?;
                self.db.delete_pending_message(pending.id)?;
                self.model.next_index = next;
                Ok(())
            }
            Err(e) => {
                self.db.update_pending_message_status(pending.id, "failed")?;
                Err(e.into())
            }
        }
    }

    // ------------------------------------------------------------------------
    // Tombstone Operations
    // ------------------------------------------------------------------------

    /// Tombstone the box at `next_index`, advancing state on success.
    pub async fn tombstone_current(&mut self) -> Result<()> {
        let encrypt_result = self
            .client
            .encrypt_write(&[], &self.model.write_cap, &self.model.next_index)
            .await?;

        self.client
            .start_resending_encrypted_message(
                None,
                Some(&self.model.write_cap),
                None,
                None,
                &encrypt_result.envelope_descriptor,
                &encrypt_result.message_ciphertext,
                &encrypt_result.envelope_hash,
            )
            .await?;

        let next = encrypt_result.next_message_box_index;
        self.db.update_write_next_index(self.model.id, &next)?;
        self.model.next_index = next;
        Ok(())
    }

    /// Tombstone up to `count` boxes starting from the channel's `next_index`,
    /// advancing state past the tombstoned range.
    pub async fn tombstone_range(&mut self, count: u32) -> Result<u32> {
        let result: TombstoneRangeResult = self
            .client
            .tombstone_range(&self.model.write_cap, &self.model.next_index, count)
            .await;

        let mut sent = 0u32;
        for envelope in &result.envelopes {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&envelope.envelope_hash);

            match self
                .client
                .start_resending_encrypted_message(
                    None,
                    Some(&self.model.write_cap),
                    None,
                    None,
                    &envelope.envelope_descriptor,
                    &envelope.message_ciphertext,
                    &hash,
                )
                .await
            {
                Ok(_) => sent += 1,
                Err(e) => {
                    if sent > 0 {
                        self.db
                            .update_write_next_index(self.model.id, &envelope.box_index)?;
                        self.model.next_index = envelope.box_index.clone();
                    }
                    return Err(e.into());
                }
            }
        }

        if sent > 0 {
            self.db.update_write_next_index(self.model.id, &result.next)?;
            self.model.next_index = result.next;
        }
        Ok(sent)
    }

    /// Tombstone a specific box without affecting the channel's `next_index`.
    pub async fn tombstone_at(&self, box_index: &[u8]) -> Result<()> {
        let encrypt_result = self
            .client
            .encrypt_write(&[], &self.model.write_cap, box_index)
            .await?;

        self.client
            .start_resending_encrypted_message(
                None,
                Some(&self.model.write_cap),
                None,
                None,
                &encrypt_result.envelope_descriptor,
                &encrypt_result.message_ciphertext,
                &encrypt_result.envelope_hash,
            )
            .await?;

        Ok(())
    }

    /// Tombstone up to `count` boxes from `start_index` without affecting
    /// the channel's `next_index`.
    pub async fn tombstone_from(&self, start_index: &[u8], count: u32) -> Result<u32> {
        let result: TombstoneRangeResult = self
            .client
            .tombstone_range(&self.model.write_cap, start_index, count)
            .await;

        let mut sent = 0u32;
        for envelope in &result.envelopes {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&envelope.envelope_hash);

            match self
                .client
                .start_resending_encrypted_message(
                    None,
                    Some(&self.model.write_cap),
                    None,
                    None,
                    &envelope.envelope_descriptor,
                    &envelope.message_ciphertext,
                    &hash,
                )
                .await
            {
                Ok(_) => sent += 1,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(sent)
    }

    // ------------------------------------------------------------------------
    // Copy Stream Operations
    // ------------------------------------------------------------------------

    /// Create a `CopyStreamBuilder` rooted at this channel's thin client.
    pub async fn copy_stream_builder(&self) -> Result<CopyStreamBuilder> {
        CopyStreamBuilder::new(self.client.clone()).await
    }

    /// Execute a Copy command using this channel's write capability as the source.
    pub async fn execute_copy(
        &self,
        courier_identity_hash: Option<&[u8]>,
        courier_queue_id: Option<&[u8]>,
    ) -> Result<()> {
        self.client
            .start_resending_copy_command(&self.model.write_cap, courier_identity_hash, courier_queue_id)
            .await?;
        Ok(())
    }

    /// Cancel a Copy command in progress by write-cap hash.
    pub async fn cancel_copy(&self, write_cap_hash: &[u8; 32]) -> Result<()> {
        self.client.cancel_resending_copy_command(write_cap_hash).await?;
        Ok(())
    }
}

// ============================================================================
// ReadChannel
// ============================================================================

/// Handle for receiving on a pigeonhole channel.
pub struct ReadChannel {
    model: ReadChannelModel,
    client: Arc<ThinClient>,
    db: Database,
}

impl ReadChannel {
    pub fn name(&self) -> &str {
        &self.model.name
    }

    pub fn read_cap(&self) -> &[u8] {
        &self.model.read_cap
    }

    /// The message box index that will be used for the next read.
    pub fn next_index(&self) -> &[u8] {
        &self.model.next_index
    }

    /// Refresh the in-memory model from the database.
    pub fn refresh(&mut self) -> Result<()> {
        self.model = self.db.get_read_channel_by_id(self.model.id)?;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Low-Level Box Operations (caller-supplied index, no state advancement)
    // ------------------------------------------------------------------------

    /// Read a single box at a specific index. Does NOT advance `next_index`.
    pub async fn read_box(&self, box_index: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let encrypt_result = self
            .client
            .encrypt_read(&self.model.read_cap, box_index)
            .await?;

        let result = self
            .client
            .start_resending_encrypted_message(
                Some(&self.model.read_cap),
                None,
                Some(box_index),
                Some(0),
                &encrypt_result.envelope_descriptor,
                &encrypt_result.message_ciphertext,
                &encrypt_result.envelope_hash,
            )
            .await?;

        Ok((result.plaintext, encrypt_result.next_message_box_index))
    }

    /// Like `read_box`, but returns `BoxIDNotFound` immediately rather than
    /// retrying through replication lag.
    pub async fn read_box_no_retry(&self, box_index: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let encrypt_result = self
            .client
            .encrypt_read(&self.model.read_cap, box_index)
            .await?;

        let result = self
            .client
            .start_resending_encrypted_message_no_retry(
                Some(&self.model.read_cap),
                None,
                Some(box_index),
                Some(0),
                &encrypt_result.envelope_descriptor,
                &encrypt_result.message_ciphertext,
                &encrypt_result.envelope_hash,
            )
            .await?;

        Ok((result.plaintext, encrypt_result.next_message_box_index))
    }

    // ------------------------------------------------------------------------
    // High-Level Receive (advances state in the database)
    // ------------------------------------------------------------------------

    /// Receive the next message from the channel's `next_index`, advancing state on success.
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        let encrypt_result = self
            .client
            .encrypt_read(&self.model.read_cap, &self.model.next_index)
            .await?;

        let current_index = self.model.next_index.clone();
        let result = self
            .client
            .start_resending_encrypted_message(
                Some(&self.model.read_cap),
                None,
                Some(&current_index),
                Some(0),
                &encrypt_result.envelope_descriptor,
                &encrypt_result.message_ciphertext,
                &encrypt_result.envelope_hash,
            )
            .await?;

        self.db
            .create_received_message(self.model.id, &result.plaintext, &current_index)?;

        let next = encrypt_result.next_message_box_index;
        self.db.update_read_next_index(self.model.id, &next)?;
        self.model.next_index = next;

        Ok(result.plaintext)
    }

    /// Like `receive`, but returns `BoxIDNotFound` immediately rather than
    /// retrying through replication lag.
    pub async fn receive_no_retry(&mut self) -> Result<Vec<u8>> {
        let encrypt_result = self
            .client
            .encrypt_read(&self.model.read_cap, &self.model.next_index)
            .await?;

        let current_index = self.model.next_index.clone();
        let result = self
            .client
            .start_resending_encrypted_message_no_retry(
                Some(&self.model.read_cap),
                None,
                Some(&current_index),
                Some(0),
                &encrypt_result.envelope_descriptor,
                &encrypt_result.message_ciphertext,
                &encrypt_result.envelope_hash,
            )
            .await?;

        self.db
            .create_received_message(self.model.id, &result.plaintext, &current_index)?;

        let next = encrypt_result.next_message_box_index;
        self.db.update_read_next_index(self.model.id, &next)?;
        self.model.next_index = next;

        Ok(result.plaintext)
    }

    pub fn get_unread_messages(&self) -> Result<Vec<ReceivedMessage>> {
        self.db.get_unread_messages(self.model.id)
    }

    pub fn get_all_messages(&self) -> Result<Vec<ReceivedMessage>> {
        self.db.get_all_messages(self.model.id)
    }

    pub fn mark_message_read(&self, message_id: i64) -> Result<()> {
        self.db.mark_message_read(message_id)
    }
}

// ============================================================================
// CopyStreamBuilder
// ============================================================================

/// Builder for streaming arbitrarily large payloads through a temporary
/// pigeonhole channel into one or more destination channels via the courier
/// Copy command.
pub struct CopyStreamBuilder {
    client: Arc<ThinClient>,
    temp_write_cap: Vec<u8>,
    temp_index: Vec<u8>,
    total_boxes: usize,
    buffer: Vec<u8>,
}

impl CopyStreamBuilder {
    async fn new(client: Arc<ThinClient>) -> Result<Self> {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let KeypairResult { write_cap: temp_write_cap, read_cap: _, first_message_index: temp_first_index } =
            client.new_keypair(&seed).await?;

        Ok(Self {
            client,
            temp_write_cap,
            temp_index: temp_first_index,
            total_boxes: 0,
            buffer: Vec::new(),
        })
    }

    pub async fn add_payload(
        &mut self,
        payload: &[u8],
        dest_write_cap: &[u8],
        dest_start_index: &[u8],
        is_last: bool,
    ) -> Result<usize> {
        let is_start = self.total_boxes == 0;
        let result = self
            .client
            .create_courier_envelopes_from_payload(payload, dest_write_cap, dest_start_index, is_start, is_last)
            .await?;

        let chunk_count = result.envelopes.len();

        for chunk in result.envelopes {
            let encrypt_result = self
                .client
                .encrypt_write(&chunk, &self.temp_write_cap, &self.temp_index)
                .await?;

            self.client
                .start_resending_encrypted_message(
                    None,
                    Some(&self.temp_write_cap),
                    None,
                    Some(0),
                    &encrypt_result.envelope_descriptor,
                    &encrypt_result.message_ciphertext,
                    &encrypt_result.envelope_hash,
                )
                .await?;

            self.temp_index = encrypt_result.next_message_box_index;
        }

        self.total_boxes += chunk_count;
        Ok(chunk_count)
    }

    pub async fn add_multi_payload(
        &mut self,
        destinations: Vec<(&[u8], &[u8], &[u8])>,
        is_last: bool,
    ) -> Result<usize> {
        if destinations.is_empty() {
            return Ok(0);
        }

        let is_start = self.total_boxes == 0;
        let buf = if self.buffer.is_empty() { None } else { Some(self.buffer.clone()) };
        let result = self
            .client
            .create_courier_envelopes_from_multi_payload(destinations, is_start, is_last, buf)
            .await?;

        let chunk_count = result.envelopes.len();
        self.buffer = result.buffer;

        for chunk in result.envelopes {
            let encrypt_result = self
                .client
                .encrypt_write(&chunk, &self.temp_write_cap, &self.temp_index)
                .await?;

            self.client
                .start_resending_encrypted_message(
                    None,
                    Some(&self.temp_write_cap),
                    None,
                    Some(0),
                    &encrypt_result.envelope_descriptor,
                    &encrypt_result.message_ciphertext,
                    &encrypt_result.envelope_hash,
                )
                .await?;

            self.temp_index = encrypt_result.next_message_box_index;
        }

        self.total_boxes += chunk_count;
        Ok(chunk_count)
    }

    pub async fn finish(self) -> Result<usize> {
        self.client
            .start_resending_copy_command(&self.temp_write_cap, None, None)
            .await?;
        Ok(self.total_boxes)
    }

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

    pub fn temp_write_cap(&self) -> &[u8] {
        &self.temp_write_cap
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }
}

// `PigeonholeDbError` is referenced indirectly through `Result`; suppress unused warning.
#[allow(dead_code)]
fn _ensure_error_in_scope(_e: PigeonholeDbError) {}
