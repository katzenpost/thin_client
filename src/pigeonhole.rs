// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Pigeonhole protocol API for the thin client.
//!
//! This module provides methods for interacting with the Pigeonhole protocol,
//! including key generation, encryption, and ARQ (Automatic Repeat Request)
//! for reliable message delivery to the courier.

use std::collections::BTreeMap;
use serde_cbor::Value;
use rand::RngCore;
use log::debug;
use blake2::{Blake2b, Digest, digest::consts::U32};

use crate::error::{ThinClientError, error_code_to_error};
use crate::core::ThinClient;

// ========================================================================
// Helper module for serializing Option<Vec<u8>> as CBOR byte strings
// ========================================================================

mod optional_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes, serializer),
            None => Option::<&[u8]>::None.serialize(serializer),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

// ========================================================================
// NEW Pigeonhole API Protocol Message Structs
// ========================================================================

/// Request to create a new keypair for the Pigeonhole protocol.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NewKeypairRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    seed: Vec<u8>,
}

/// Reply containing the generated keypair and first message index.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NewKeypairReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(default, with = "optional_bytes")]
    write_cap: Option<Vec<u8>>,
    #[serde(default, with = "optional_bytes")]
    read_cap: Option<Vec<u8>>,
    #[serde(default, with = "optional_bytes")]
    first_message_index: Option<Vec<u8>>,
    #[serde(default)]
    error_code: u8,
}

/// Request to encrypt a read operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct EncryptReadRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    read_cap: Vec<u8>,
    #[serde(with = "serde_bytes")]
    message_box_index: Vec<u8>,
}

/// Reply containing the encrypted read operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct EncryptReadReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(default, with = "optional_bytes")]
    message_ciphertext: Option<Vec<u8>>,
    #[serde(default, with = "optional_bytes")]
    envelope_descriptor: Option<Vec<u8>>,
    #[serde(default, with = "optional_bytes")]
    envelope_hash: Option<Vec<u8>>,
    #[serde(default, with = "optional_bytes")]
    next_message_box_index: Option<Vec<u8>>,
    #[serde(default)]
    error_code: u8,
}

/// Request to encrypt a write operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct EncryptWriteRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    plaintext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    write_cap: Vec<u8>,
    #[serde(with = "serde_bytes")]
    message_box_index: Vec<u8>,
}

/// Reply containing the encrypted write operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct EncryptWriteReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(default, with = "optional_bytes")]
    message_ciphertext: Option<Vec<u8>>,
    #[serde(default, with = "optional_bytes")]
    envelope_descriptor: Option<Vec<u8>>,
    #[serde(default, with = "optional_bytes")]
    envelope_hash: Option<Vec<u8>>,
    #[serde(default, with = "optional_bytes")]
    next_message_box_index: Option<Vec<u8>>,
    #[serde(default)]
    error_code: u8,
}

/// Request to start resending an encrypted message via ARQ.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StartResendingEncryptedMessageRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none", with = "optional_bytes")]
    read_cap: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "optional_bytes")]
    write_cap: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "optional_bytes")]
    message_box_index: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_index: Option<u8>,
    #[serde(with = "serde_bytes")]
    envelope_descriptor: Vec<u8>,
    #[serde(with = "serde_bytes")]
    message_ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    envelope_hash: Vec<u8>,
    /// If true, BoxIDNotFound errors on reads trigger immediate error instead of automatic retries.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    no_retry_on_box_id_not_found: bool,
    /// If true, BoxAlreadyExists errors on writes are returned as errors instead of idempotent success.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    no_idempotent_box_already_exists: bool,
}

/// Reply containing the plaintext from a resent encrypted message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StartResendingEncryptedMessageReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(default, with = "optional_bytes")]
    plaintext: Option<Vec<u8>>,
    error_code: u8,
    #[serde(default, with = "optional_bytes")]
    courier_identity_hash: Option<Vec<u8>>,
    #[serde(default, with = "optional_bytes")]
    courier_queue_id: Option<Vec<u8>>,
}

/// Result returned by `start_resending_encrypted_message` and its variants.
///
/// Contains the decrypted plaintext (for reads) along with the courier identity
/// that was selected to handle the message. Callers can watch PKI document updates
/// and cancel+re-encrypt if the courier disappears from consensus.
#[derive(Debug, Clone)]
pub struct StartResendingResult {
    pub plaintext: Vec<u8>,
    pub courier_identity_hash: Option<Vec<u8>>,
    pub courier_queue_id: Option<Vec<u8>>,
}

/// Request to cancel resending an encrypted message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CancelResendingEncryptedMessageRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    envelope_hash: Vec<u8>,
}

/// Reply confirming cancellation of resending.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CancelResendingEncryptedMessageReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    error_code: u8,
}

/// Request to increment a MessageBoxIndex.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NextMessageBoxIndexRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    message_box_index: Vec<u8>,
}

/// Reply containing the incremented MessageBoxIndex.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NextMessageBoxIndexReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(default, with = "optional_bytes")]
    next_message_box_index: Option<Vec<u8>>,
    #[serde(default)]
    error_code: u8,
}

/// Request to start resending a copy command.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StartResendingCopyCommandRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    write_cap: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "optional_bytes")]
    courier_identity_hash: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", default, with = "optional_bytes")]
    courier_queue_id: Option<Vec<u8>>,
}

/// Reply confirming start of copy command resending.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StartResendingCopyCommandReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    error_code: u8,
}

/// Request to cancel resending a copy command.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CancelResendingCopyCommandRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    write_cap_hash: Vec<u8>,
}

/// Reply confirming cancellation of copy command resending.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CancelResendingCopyCommandReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    error_code: u8,
}

/// Request to create courier envelopes from a payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CreateCourierEnvelopesFromPayloadRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    #[serde(with = "serde_bytes")]
    dest_write_cap: Vec<u8>,
    #[serde(with = "serde_bytes")]
    dest_start_index: Vec<u8>,
    is_start: bool,
    is_last: bool,
}

/// Reply containing the created courier envelopes and next destination index.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CreateCourierEnvelopesFromPayloadReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    /// Envelopes is None when the daemon returns an error.
    envelopes: Option<Vec<serde_bytes::ByteBuf>>,
    /// Next destination message box index after all boxes consumed by this call.
    #[serde(default, with = "optional_bytes")]
    next_dest_index: Option<Vec<u8>>,
    #[serde(default)]
    error_code: u8,
}

/// A destination for creating courier envelopes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct EnvelopeDestination {
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    #[serde(with = "serde_bytes")]
    write_cap: Vec<u8>,
    #[serde(with = "serde_bytes")]
    start_index: Vec<u8>,
}

/// Request to create courier envelopes from multiple payloads.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CreateCourierEnvelopesFromPayloadsRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    stream_id: Vec<u8>,
    destinations: Vec<EnvelopeDestination>,
    is_last: bool,
}

/// Reply containing the created courier envelopes from multiple payloads and buffer state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CreateCourierEnvelopesFromPayloadsReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    /// Envelopes is None when the daemon returns an error.
    envelopes: Option<Vec<serde_bytes::ByteBuf>>,
    /// Buffer contains any data buffered by the encoder that hasn't been output yet.
    /// None when the daemon returns an error.
    #[serde(default, with = "optional_bytes")]
    buffer: Option<Vec<u8>>,
    /// Next destination indices for each destination, in request order.
    #[serde(default)]
    next_dest_indices: Option<Vec<serde_bytes::ByteBuf>>,
    #[serde(default)]
    error_code: u8,
}

/// Request to set/restore the buffered state for a stream (for crash recovery).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SetStreamBufferRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    stream_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    buffer: Vec<u8>,
}

/// Reply confirming the buffer state has been restored.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SetStreamBufferReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    error_code: u8,
}

/// Result from new_keypair containing the generated capabilities.
#[derive(Debug, Clone)]
pub struct KeypairResult {
    pub write_cap: Vec<u8>,
    pub read_cap: Vec<u8>,
    pub first_message_index: Vec<u8>,
}

/// Result from encrypt_read containing the encrypted read request.
#[derive(Debug, Clone)]
pub struct EncryptReadResult {
    pub message_ciphertext: Vec<u8>,
    pub envelope_descriptor: Vec<u8>,
    pub envelope_hash: [u8; 32],
    pub next_message_box_index: Vec<u8>,
}

/// Result from encrypt_write containing the encrypted write request.
#[derive(Debug, Clone)]
pub struct EncryptWriteResult {
    pub message_ciphertext: Vec<u8>,
    pub envelope_descriptor: Vec<u8>,
    pub envelope_hash: [u8; 32],
    pub next_message_box_index: Vec<u8>,
}

/// Result of creating courier envelopes.
#[derive(Debug, Clone)]
pub struct CreateEnvelopesResult {
    /// The serialized CopyStreamElements to send to the network.
    pub envelopes: Vec<Vec<u8>>,
    /// The buffered data that hasn't been output yet. Persist this for crash recovery.
    /// Only populated by create_courier_envelopes_from_multi_payload.
    pub buffer: Vec<u8>,
    /// The next destination message box index after all boxes consumed by this call.
    /// Only populated by create_courier_envelopes_from_payload.
    pub next_dest_index: Option<Vec<u8>>,
    /// The next destination indices for each destination, in request order.
    /// Only populated by create_courier_envelopes_from_multi_payload.
    pub next_dest_indices: Option<Vec<Vec<u8>>>,
}

// ========================================================================
// NEW Pigeonhole API Methods
// ========================================================================

impl ThinClient {
    /// Creates a new keypair for use with the Pigeonhole protocol.
    ///
    /// This method generates a WriteCap and ReadCap from the provided seed using
    /// the BACAP (Blinding-and-Capability) protocol. The WriteCap should be stored
    /// securely for writing messages, while the ReadCap can be shared with others
    /// to allow them to read messages.
    ///
    /// # Arguments
    /// * `seed` - 32-byte seed used to derive the keypair
    ///
    /// # Returns
    /// * `Ok((write_cap, read_cap, first_message_index))` on success
    /// * `Err(ThinClientError)` on failure
    pub async fn new_keypair(&self, seed: &[u8; 32]) -> Result<KeypairResult, ThinClientError> {
        let query_id = Self::new_query_id();

        let request_inner = NewKeypairRequest {
            query_id: query_id.clone(),
            seed: seed.to_vec(),
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("new_keypair".to_string()), request_value);

        let reply_map = self.send_and_wait_direct(query_id, request).await?;

        let reply: NewKeypairReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("new_keypair failed with error code: {}", reply.error_code)));
        }

        let write_cap = reply.write_cap.ok_or_else(|| ThinClientError::Other("new_keypair: write_cap is None".to_string()))?;
        let read_cap = reply.read_cap.ok_or_else(|| ThinClientError::Other("new_keypair: read_cap is None".to_string()))?;
        let first_message_index = reply.first_message_index.ok_or_else(|| ThinClientError::Other("new_keypair: first_message_index is None".to_string()))?;

        Ok(KeypairResult { write_cap, read_cap, first_message_index })
    }

    /// Encrypts a read operation for a given read capability.
    ///
    /// This method prepares an encrypted read request that can be sent to the
    /// courier service to retrieve a message from a pigeonhole box.
    ///
    /// # Arguments
    /// * `read_cap` - Read capability that grants access to the channel
    /// * `message_box_index` - Starting read position for the channel
    ///
    /// # Returns
    /// * `Ok(EncryptReadResult)` on success
    /// * `Err(ThinClientError)` on failure
    pub async fn encrypt_read(
        &self,
        read_cap: &[u8],
        message_box_index: &[u8]
    ) -> Result<EncryptReadResult, ThinClientError> {
        let query_id = Self::new_query_id();

        let request_inner = EncryptReadRequest {
            query_id: query_id.clone(),
            read_cap: read_cap.to_vec(),
            message_box_index: message_box_index.to_vec(),
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("encrypt_read".to_string()), request_value);

        let reply_map = self.send_and_wait_direct(query_id, request).await?;

        let reply: EncryptReadReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("encrypt_read failed with error code: {}", reply.error_code)));
        }

        let message_ciphertext = reply.message_ciphertext.ok_or_else(|| ThinClientError::Other("encrypt_read: message_ciphertext is None".to_string()))?;
        let envelope_descriptor = reply.envelope_descriptor.ok_or_else(|| ThinClientError::Other("encrypt_read: envelope_descriptor is None".to_string()))?;
        let envelope_hash_vec = reply.envelope_hash.ok_or_else(|| ThinClientError::Other("encrypt_read: envelope_hash is None".to_string()))?;
        let next_message_box_index = reply.next_message_box_index.ok_or_else(|| ThinClientError::Other("encrypt_read: next_message_box_index is None".to_string()))?;

        let mut envelope_hash = [0u8; 32];
        envelope_hash.copy_from_slice(&envelope_hash_vec[..32]);

        Ok(EncryptReadResult {
            message_ciphertext,
            envelope_descriptor,
            envelope_hash,
            next_message_box_index,
        })
    }

    /// Encrypts a write operation for a given write capability.
    ///
    /// This method prepares an encrypted write request that can be sent to the
    /// courier service to store a message in a pigeonhole box.
    ///
    /// # Plaintext Size Constraint
    ///
    /// The `plaintext` must not exceed `PigeonholeGeometry.max_plaintext_payload_length` bytes.
    /// The daemon internally adds a 4-byte big-endian length prefix before padding and
    /// encryption, so the actual wire format is `[4-byte length][plaintext][zero padding]`.
    ///
    /// If the plaintext exceeds the maximum size, the daemon will return
    /// `ThinClientErrorInvalidRequest`.
    ///
    /// # Arguments
    /// * `plaintext` - The plaintext message to encrypt. Must be at most
    ///   `PigeonholeGeometry.max_plaintext_payload_length` bytes.
    /// * `write_cap` - Write capability that grants access to the channel.
    /// * `message_box_index` - The message box index for this write operation.
    ///
    /// # Returns
    /// * `Ok((message_ciphertext, envelope_descriptor, envelope_hash))` on success
    /// * `Err(ThinClientError)` on failure (including if plaintext is too large)
    pub async fn encrypt_write(
        &self,
        plaintext: &[u8],
        write_cap: &[u8],
        message_box_index: &[u8]
    ) -> Result<EncryptWriteResult, ThinClientError> {
        let query_id = Self::new_query_id();

        let request_inner = EncryptWriteRequest {
            query_id: query_id.clone(),
            plaintext: plaintext.to_vec(),
            write_cap: write_cap.to_vec(),
            message_box_index: message_box_index.to_vec(),
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("encrypt_write".to_string()), request_value);

        let reply_map = self.send_and_wait_direct(query_id, request).await?;

        let reply: EncryptWriteReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("encrypt_write failed with error code: {}", reply.error_code)));
        }

        let message_ciphertext = reply.message_ciphertext.ok_or_else(|| ThinClientError::Other("encrypt_write: message_ciphertext is None".to_string()))?;
        let envelope_descriptor = reply.envelope_descriptor.ok_or_else(|| ThinClientError::Other("encrypt_write: envelope_descriptor is None".to_string()))?;
        let envelope_hash_vec = reply.envelope_hash.ok_or_else(|| ThinClientError::Other("encrypt_write: envelope_hash is None".to_string()))?;
        let next_message_box_index = reply.next_message_box_index.ok_or_else(|| ThinClientError::Other("encrypt_write: next_message_box_index is None".to_string()))?;

        let mut envelope_hash = [0u8; 32];
        envelope_hash.copy_from_slice(&envelope_hash_vec[..32]);

        Ok(EncryptWriteResult {
            message_ciphertext,
            envelope_descriptor,
            envelope_hash,
            next_message_box_index,
        })
    }

    /// Sends an encrypted message via ARQ (Automatic Repeat Request) and blocks until completion.
    ///
    /// This method BLOCKS until a reply is received from the daemon.
    /// The message will be resent periodically until either:
    /// - A successful response is received
    /// - An error response is received from the daemon
    /// - The operation is cancelled via cancel_resending_encrypted_message
    ///
    /// The daemon implements a finite state machine for the stop-and-wait ARQ protocol:
    /// - **Default writes** (write_cap set, no_idempotent_box_already_exists false):
    ///   Returns success after a single round-trip. The courier ACK confirms the
    ///   envelope was received and will be dispatched to both shard replicas.
    /// - **BoxAlreadyExists-aware writes** (no_idempotent_box_already_exists true):
    ///   Requires two round-trips — one for the courier ACK, and a second to
    ///   retrieve the replica's error code.
    /// - **Reads** (read_cap set): Requires two round-trips — one for the courier
    ///   ACK, and a second to retrieve the decrypted payload from the replica.
    ///
    /// # Arguments
    /// * `read_cap` - Optional read capability (for read operations)
    /// * `write_cap` - Optional write capability (for write operations)
    /// * `message_box_index` - Current message box index being operated on (for read operations)
    /// * `reply_index` - Reply index for the operation (None for tombstone writes)
    /// * `envelope_descriptor` - Envelope descriptor from encrypt_read/encrypt_write
    /// * `message_ciphertext` - Encrypted message from encrypt_read/encrypt_write
    /// * `envelope_hash` - Envelope hash from encrypt_read/encrypt_write
    ///
    /// # Returns
    /// * `Ok(plaintext)` - For read operations, the decrypted plaintext message
    ///   (at most `PigeonholeGeometry.max_plaintext_payload_length` bytes).
    ///   For write operations, returns an empty vector on success.
    /// * `Err(ThinClientError)` on failure
    pub async fn start_resending_encrypted_message(
        &self,
        read_cap: Option<&[u8]>,
        write_cap: Option<&[u8]>,
        message_box_index: Option<&[u8]>,
        reply_index: Option<u8>,
        envelope_descriptor: &[u8],
        message_ciphertext: &[u8],
        envelope_hash: &[u8; 32]
    ) -> Result<StartResendingResult, ThinClientError> {
        self.start_resending_encrypted_message_with_options(
            read_cap,
            write_cap,
            message_box_index,
            reply_index,
            envelope_descriptor,
            message_ciphertext,
            envelope_hash,
            false,
            false,
        ).await
    }

    /// Like `start_resending_encrypted_message` but returns BoxAlreadyExists errors.
    ///
    /// Use this when you want to detect whether a write was actually performed
    /// or if the box already existed.
    ///
    /// # Arguments
    /// Same as `start_resending_encrypted_message`
    ///
    /// # Returns
    /// * `Ok(plaintext)` on success
    /// * `Err(ThinClientError::BoxAlreadyExists)` if the box already contains data
    /// * `Err(ThinClientError)` on other failures
    pub async fn start_resending_encrypted_message_return_box_exists(
        &self,
        read_cap: Option<&[u8]>,
        write_cap: Option<&[u8]>,
        message_box_index: Option<&[u8]>,
        reply_index: Option<u8>,
        envelope_descriptor: &[u8],
        message_ciphertext: &[u8],
        envelope_hash: &[u8; 32]
    ) -> Result<StartResendingResult, ThinClientError> {
        self.start_resending_encrypted_message_with_options(
            read_cap,
            write_cap,
            message_box_index,
            reply_index,
            envelope_descriptor,
            message_ciphertext,
            envelope_hash,
            false,
            true,  // no_idempotent_box_already_exists
        ).await
    }

    /// Like `start_resending_encrypted_message` but disables automatic retries on BoxIDNotFound.
    ///
    /// Use this when you want immediate error feedback rather than waiting for
    /// potential replication lag to resolve.
    ///
    /// # Arguments
    /// Same as `start_resending_encrypted_message`
    ///
    /// # Returns
    /// * `Ok(plaintext)` on success
    /// * `Err(ThinClientError::BoxIdNotFound)` if the box does not exist (no automatic retries)
    /// * `Err(ThinClientError)` on other failures
    pub async fn start_resending_encrypted_message_no_retry(
        &self,
        read_cap: Option<&[u8]>,
        write_cap: Option<&[u8]>,
        message_box_index: Option<&[u8]>,
        reply_index: Option<u8>,
        envelope_descriptor: &[u8],
        message_ciphertext: &[u8],
        envelope_hash: &[u8; 32]
    ) -> Result<StartResendingResult, ThinClientError> {
        self.start_resending_encrypted_message_with_options(
            read_cap,
            write_cap,
            message_box_index,
            reply_index,
            envelope_descriptor,
            message_ciphertext,
            envelope_hash,
            true,  // no_retry_on_box_id_not_found
            false,
        ).await
    }

    /// Internal method with all options for start_resending_encrypted_message.
    async fn start_resending_encrypted_message_with_options(
        &self,
        read_cap: Option<&[u8]>,
        write_cap: Option<&[u8]>,
        message_box_index: Option<&[u8]>,
        reply_index: Option<u8>,
        envelope_descriptor: &[u8],
        message_ciphertext: &[u8],
        envelope_hash: &[u8; 32],
        no_retry_on_box_id_not_found: bool,
        no_idempotent_box_already_exists: bool,
    ) -> Result<StartResendingResult, ThinClientError> {
        let query_id = Self::new_query_id();

        let request_inner = StartResendingEncryptedMessageRequest {
            query_id: query_id.clone(),
            read_cap: read_cap.map(|rc| rc.to_vec()),
            write_cap: write_cap.map(|wc| wc.to_vec()),
            message_box_index: message_box_index.map(|mbi| mbi.to_vec()),
            reply_index,
            envelope_descriptor: envelope_descriptor.to_vec(),
            message_ciphertext: message_ciphertext.to_vec(),
            envelope_hash: envelope_hash.to_vec(),
            no_retry_on_box_id_not_found,
            no_idempotent_box_already_exists,
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("start_resending_encrypted_message".to_string()), request_value);

        // Track in-flight request for replay on reconnect to new daemon instance
        let tracking_key = envelope_hash.to_vec();
        self.in_flight_resends.lock().await.insert(tracking_key.clone(), request.clone());

        // Use direct response routing (like Python's _send_and_wait)
        // This blocks until the daemon sends a reply with matching query_id
        let reply_map = match self.send_and_wait_direct(query_id, request).await {
            Ok(reply) => {
                self.in_flight_resends.lock().await.remove(&tracking_key);
                reply
            }
            Err(e) => {
                self.in_flight_resends.lock().await.remove(&tracking_key);
                return Err(e);
            }
        };

        // Parse the reply
        let reply: StartResendingEncryptedMessageReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        debug!("start_resending_encrypted_message: received reply, error_code={}, plaintext_len={}",
               reply.error_code, reply.plaintext.as_ref().map(|p| p.len()).unwrap_or(0));

        if reply.error_code != 0 {
            return Err(error_code_to_error(reply.error_code));
        }

        Ok(StartResendingResult {
            plaintext: reply.plaintext.unwrap_or_default(),
            courier_identity_hash: reply.courier_identity_hash,
            courier_queue_id: reply.courier_queue_id,
        })
    }

    /// Cancels ARQ resending for an encrypted message.
    ///
    /// This method stops the automatic repeat request for a previously started
    /// encrypted message transmission.
    ///
    /// # Arguments
    /// * `envelope_hash` - Hash of the courier envelope to cancel
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(ThinClientError)` on failure
    pub async fn cancel_resending_encrypted_message(&self, envelope_hash: &[u8; 32]) -> Result<(), ThinClientError> {
        // Remove from in-flight tracking so it won't be replayed on reconnect
        self.in_flight_resends.lock().await.remove(&envelope_hash.to_vec());

        // If disconnected, just remove from tracking — daemon has no state to cancel
        if !self.is_connected() {
            return Ok(());
        }

        let query_id = Self::new_query_id();

        let request_inner = CancelResendingEncryptedMessageRequest {
            query_id: query_id.clone(),
            envelope_hash: envelope_hash.to_vec(),
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("cancel_resending_encrypted_message".to_string()), request_value);

        let reply_map = self.send_and_wait_direct(query_id, request).await?;

        let reply: CancelResendingEncryptedMessageReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("cancel_resending_encrypted_message failed with error code: {}", reply.error_code)));
        }

        Ok(())
    }

    /// Increments a MessageBoxIndex using the BACAP NextIndex method.
    ///
    /// This method is used when sending multiple messages to different mailboxes using
    /// the same WriteCap or ReadCap. It properly advances the cryptographic state by:
    /// - Incrementing the Idx64 counter
    /// - Deriving new encryption and blinding keys using HKDF
    /// - Updating the HKDF state for the next iteration
    ///
    /// # Arguments
    /// * `message_box_index` - Current message box index to increment
    ///
    /// # Returns
    /// * `Ok(next_message_box_index)` - The incremented message box index
    /// * `Err(ThinClientError)` on failure
    pub async fn next_message_box_index(&self, message_box_index: &[u8]) -> Result<Vec<u8>, ThinClientError> {
        let query_id = Self::new_query_id();

        let request_inner = NextMessageBoxIndexRequest {
            query_id: query_id.clone(),
            message_box_index: message_box_index.to_vec(),
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("next_message_box_index".to_string()), request_value);

        let reply_map = self.send_and_wait_direct(query_id, request).await?;

        let reply: NextMessageBoxIndexReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("next_message_box_index failed with error code: {}", reply.error_code)));
        }

        let next_index = reply.next_message_box_index.ok_or_else(|| ThinClientError::Other("next_message_box_index: next_message_box_index is None".to_string()))?;
        Ok(next_index)
    }

    /// Starts resending a copy command to a courier via ARQ.
    ///
    /// This method instructs a courier to read data from a temporary channel
    /// (identified by the write_cap) and write it to the destination channel.
    /// The command is automatically retransmitted until acknowledged.
    ///
    /// If courier_identity_hash and courier_queue_id are both provided,
    /// the copy command is sent to that specific courier. Otherwise, a
    /// random courier is selected.
    ///
    /// # Arguments
    /// * `write_cap` - Write capability for the temporary channel containing the data
    /// * `courier_identity_hash` - Optional identity hash of a specific courier to use
    /// * `courier_queue_id` - Optional queue ID for the specified courier
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(ThinClientError)` on failure
    pub async fn start_resending_copy_command(
        &self,
        write_cap: &[u8],
        courier_identity_hash: Option<&[u8]>,
        courier_queue_id: Option<&[u8]>
    ) -> Result<(), ThinClientError> {
        // Compute write cap hash for in-flight tracking (matches daemon-side hash)
        let tracking_key = Blake2b::<U32>::digest(write_cap).to_vec();

        let query_id = Self::new_query_id();

        let request_inner = StartResendingCopyCommandRequest {
            query_id: query_id.clone(),
            write_cap: write_cap.to_vec(),
            courier_identity_hash: courier_identity_hash.map(|h| h.to_vec()),
            courier_queue_id: courier_queue_id.map(|q| q.to_vec()),
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("start_resending_copy_command".to_string()), request_value);

        // Track in-flight request for replay on reconnect to new daemon instance
        self.in_flight_resends.lock().await.insert(tracking_key.clone(), request.clone());

        let reply_map = match self.send_and_wait_direct(query_id, request).await {
            Ok(reply) => {
                self.in_flight_resends.lock().await.remove(&tracking_key);
                reply
            }
            Err(e) => {
                self.in_flight_resends.lock().await.remove(&tracking_key);
                return Err(e);
            }
        };

        let reply: StartResendingCopyCommandReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("start_resending_copy_command failed with error code: {}", reply.error_code)));
        }

        Ok(())
    }

    /// Cancels ARQ resending for a copy command.
    ///
    /// This method stops the automatic repeat request (ARQ) for a previously started
    /// copy command.
    ///
    /// # Arguments
    /// * `write_cap_hash` - Hash of the WriteCap used in start_resending_copy_command
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(ThinClientError)` on failure
    pub async fn cancel_resending_copy_command(&self, write_cap_hash: &[u8; 32]) -> Result<(), ThinClientError> {
        // Remove from in-flight tracking so it won't be replayed on reconnect
        self.in_flight_resends.lock().await.remove(&write_cap_hash.to_vec());

        // If disconnected, just remove from tracking — daemon has no state to cancel
        if !self.is_connected() {
            return Ok(());
        }

        let query_id = Self::new_query_id();

        let request_inner = CancelResendingCopyCommandRequest {
            query_id: query_id.clone(),
            write_cap_hash: write_cap_hash.to_vec(),
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("cancel_resending_copy_command".to_string()), request_value);

        let reply_map = self.send_and_wait_direct(query_id, request).await?;

        let reply: CancelResendingCopyCommandReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("cancel_resending_copy_command failed with error code: {}", reply.error_code)));
        }

        Ok(())
    }

    /// Creates multiple CourierEnvelopes from a payload of any size.
    ///
    /// The payload is automatically chunked and each chunk is wrapped in a
    /// CourierEnvelope. Each returned chunk is a serialized CopyStreamElement
    /// ready to be written to a box.
    ///
    /// Multiple calls can be made with the same stream_id to build up a stream
    /// incrementally. The first call creates a new encoder (first element gets
    /// IsStart=true). The final call should have is_last=true (last element
    /// gets IsFinal=true).
    ///
    /// # Crash Recovery
    ///
    /// When `is_last=false`, the daemon buffers the last partial box's payload
    /// internally so that subsequent writes can be packed efficiently. The
    /// `buffer` in the result contains this buffered data which you should
    /// persist for crash recovery. On restart, use `set_stream_buffer` to restore
    /// the state before continuing the stream.
    ///
    /// # Arguments
    /// * `stream_id` - 16-byte identifier for the encoder instance
    /// * `payload` - The data to be encoded into courier envelopes
    /// * `dest_write_cap` - Write capability for the destination channel
    /// * `dest_start_index` - Starting index in the destination channel
    /// * `is_last` - Whether this is the last payload in the sequence
    ///
    /// # Returns
    /// * `Ok(CreateEnvelopesResult)` - Contains envelopes and buffer state for crash recovery
    /// * `Err(ThinClientError)` on failure
    pub async fn create_courier_envelopes_from_payload(
        &self,
        payload: &[u8],
        dest_write_cap: &[u8],
        dest_start_index: &[u8],
        is_start: bool,
        is_last: bool
    ) -> Result<CreateEnvelopesResult, ThinClientError> {
        let query_id = Self::new_query_id();

        let request_inner = CreateCourierEnvelopesFromPayloadRequest {
            query_id: query_id.clone(),
            payload: payload.to_vec(),
            dest_write_cap: dest_write_cap.to_vec(),
            dest_start_index: dest_start_index.to_vec(),
            is_start,
            is_last,
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("create_courier_envelopes_from_payload".to_string()), request_value);

        let reply_map = self.send_and_wait_direct(query_id, request).await?;

        let reply: CreateCourierEnvelopesFromPayloadReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("create_courier_envelopes_from_payload failed with error code: {}", reply.error_code)));
        }

        Ok(CreateEnvelopesResult {
            envelopes: reply.envelopes.unwrap_or_default().into_iter().map(|b| b.into_vec()).collect(),
            buffer: Vec::new(),
            next_dest_index: reply.next_dest_index,
            next_dest_indices: None,
        })
    }

    /// Creates CourierEnvelopes from multiple payloads going to different destinations.
    ///
    /// This is more space-efficient than calling create_courier_envelopes_from_payload
    /// multiple times because envelopes from different destinations are packed
    /// together in the copy stream without wasting space.
    ///
    /// # Crash Recovery
    ///
    /// When `is_last=false`, the daemon buffers the last partial box's payload
    /// internally so that subsequent writes can be packed efficiently. The
    /// `buffer` in the result contains this buffered data which you should
    /// persist for crash recovery. On restart, use `set_stream_buffer` to restore
    /// the state before continuing the stream.
    ///
    /// # Arguments
    /// * `stream_id` - 16-byte identifier for the encoder instance
    /// * `destinations` - List of (payload, write_cap, start_index) tuples
    /// * `is_last` - Whether this is the last set of payloads in the sequence
    ///
    /// # Returns
    /// * `Ok(CreateEnvelopesResult)` - Contains envelopes and buffer state for crash recovery
    /// * `Err(ThinClientError)` on failure
    pub async fn create_courier_envelopes_from_multi_payload(
        &self,
        stream_id: &[u8; 16],
        destinations: Vec<(&[u8], &[u8], &[u8])>,
        is_last: bool
    ) -> Result<CreateEnvelopesResult, ThinClientError> {
        let query_id = Self::new_query_id();

        let destinations_inner: Vec<EnvelopeDestination> = destinations
            .into_iter()
            .map(|(payload, write_cap, start_index)| EnvelopeDestination {
                payload: payload.to_vec(),
                write_cap: write_cap.to_vec(),
                start_index: start_index.to_vec(),
            })
            .collect();

        let request_inner = CreateCourierEnvelopesFromPayloadsRequest {
            query_id: query_id.clone(),
            stream_id: stream_id.to_vec(),
            destinations: destinations_inner,
            is_last,
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("create_courier_envelopes_from_multi_payload".to_string()), request_value);

        let reply_map = self.send_and_wait_direct(query_id, request).await?;

        let reply: CreateCourierEnvelopesFromPayloadsReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("create_courier_envelopes_from_multi_payload failed with error code: {}", reply.error_code)));
        }

        Ok(CreateEnvelopesResult {
            envelopes: reply.envelopes.unwrap_or_default().into_iter().map(|b| b.into_vec()).collect(),
            buffer: reply.buffer.unwrap_or_default(),
            next_dest_index: None,
            next_dest_indices: reply.next_dest_indices.map(|v| v.into_iter().map(|b| b.into_vec()).collect()),
        })
    }

    /// Generates a new random 16-byte stream ID.
    pub fn new_stream_id() -> [u8; 16] {
        let mut stream_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut stream_id);
        stream_id
    }

    /// Restores the buffered state for a given stream ID.
    ///
    /// This is useful for crash recovery: after restart, call this method with the
    /// buffer that was returned by `create_courier_envelopes_from_payload` or
    /// `create_courier_envelopes_from_multi_payload` before the crash/shutdown.
    ///
    /// Note: This will create a new encoder if one doesn't exist for this stream_id,
    /// or replace the buffer contents if one already exists.
    ///
    /// # Arguments
    /// * `stream_id` - 16-byte identifier for the encoder instance
    /// * `buffer` - The buffered data to restore (from `CreateEnvelopesResult.buffer`)
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(ThinClientError)` on failure
    ///
    /// # Example
    /// ```ignore
    /// // During streaming, save the buffer from each call
    /// let result = client.create_courier_envelopes_from_payload(&stream_id, data, ..., false).await?;
    /// save_to_disk(&stream_id, &result.buffer)?;
    ///
    /// // On restart, restore the stream state
    /// let buffer = load_from_disk(&stream_id)?;
    /// client.set_stream_buffer(&stream_id, buffer).await?;
    /// // Now continue streaming from where we left off
    /// client.create_courier_envelopes_from_payload(&stream_id, more_data, ..., true).await?;
    /// ```
    pub async fn set_stream_buffer(
        &self,
        stream_id: &[u8; 16],
        buffer: Vec<u8>,
    ) -> Result<(), ThinClientError> {
        let query_id = Self::new_query_id();

        let request_inner = SetStreamBufferRequest {
            query_id: query_id.clone(),
            stream_id: stream_id.to_vec(),
            buffer,
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("set_stream_buffer".to_string()), request_value);

        let reply_map = self.send_and_wait_direct(query_id, request).await?;

        let reply: SetStreamBufferReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!(
                "set_stream_buffer failed with error code: {}", reply.error_code
            )));
        }

        Ok(())
    }

}

/// A single tombstone envelope ready to be sent.
#[derive(Debug, Clone)]
pub struct TombstoneEnvelope {
    /// The encrypted tombstone payload.
    pub message_ciphertext: Vec<u8>,
    /// The envelope descriptor.
    pub envelope_descriptor: Vec<u8>,
    /// The envelope hash for cancellation.
    pub envelope_hash: Vec<u8>,
    /// The box index this envelope is for.
    pub box_index: Vec<u8>,
}

/// Result of a tombstone_range operation.
#[derive(Debug)]
pub struct TombstoneRangeResult {
    /// List of tombstone envelopes ready to be sent.
    pub envelopes: Vec<TombstoneEnvelope>,
    /// The next MessageBoxIndex after the last processed.
    pub next: Vec<u8>,
    /// Error message if the operation failed partway through.
    pub error: Option<String>,
}

impl ThinClient {
    /// Create tombstones for a range of pigeonhole boxes.
    ///
    /// This method creates tombstones for up to max_count boxes,
    /// starting from the specified box index and advancing through consecutive
    /// indices. The caller must send each envelope via start_resending_encrypted_message
    /// to complete the tombstone operations.
    ///
    /// If an error occurs during the operation, a partial result is returned
    /// containing the envelopes created so far and the next index.
    ///
    /// # Arguments
    /// * `write_cap` - Write capability for the boxes
    /// * `start` - Starting MessageBoxIndex
    /// * `max_count` - Maximum number of boxes to tombstone
    ///
    /// # Returns
    /// * `TombstoneRangeResult` containing the envelopes and next index
    pub async fn tombstone_range(
        &self,
        write_cap: &[u8],
        start: &[u8],
        max_count: u32
    ) -> TombstoneRangeResult {
        if max_count == 0 {
            return TombstoneRangeResult {
                envelopes: Vec::new(),
                next: start.to_vec(),
                error: None,
            };
        }

        let mut cur = start.to_vec();
        let mut envelopes: Vec<TombstoneEnvelope> = Vec::with_capacity(max_count as usize);

        while (envelopes.len() as u32) < max_count {
            match self.encrypt_write(&[], write_cap, &cur).await {
                Ok(result) => {
                    envelopes.push(TombstoneEnvelope {
                        message_ciphertext: result.message_ciphertext,
                        envelope_descriptor: result.envelope_descriptor,
                        envelope_hash: result.envelope_hash.to_vec(),
                        box_index: cur.clone(),
                    });
                    cur = result.next_message_box_index;
                }
                Err(e) => {
                    let count = envelopes.len();
                    return TombstoneRangeResult {
                        envelopes,
                        next: cur,
                        error: Some(format!("Error creating tombstone at index {}: {:?}", count, e)),
                    };
                }
            }
        }

        TombstoneRangeResult {
            envelopes,
            next: cur,
            error: None,
        }
    }
}