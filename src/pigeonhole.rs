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

use crate::error::ThinClientError;
use crate::core::ThinClient;
use crate::PigeonholeGeometry;

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
    #[serde(with = "serde_bytes")]
    write_cap: Vec<u8>,
    #[serde(with = "serde_bytes")]
    read_cap: Vec<u8>,
    #[serde(with = "serde_bytes")]
    first_message_index: Vec<u8>,
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
    #[serde(with = "serde_bytes")]
    message_ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    next_message_index: Vec<u8>,
    #[serde(with = "serde_bytes")]
    envelope_descriptor: Vec<u8>,
    #[serde(with = "serde_bytes")]
    envelope_hash: Vec<u8>,
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
    #[serde(with = "serde_bytes")]
    message_ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    envelope_descriptor: Vec<u8>,
    #[serde(with = "serde_bytes")]
    envelope_hash: Vec<u8>,
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
    next_message_index: Option<Vec<u8>>,
    reply_index: u8,
    #[serde(with = "serde_bytes")]
    envelope_descriptor: Vec<u8>,
    #[serde(with = "serde_bytes")]
    message_ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    envelope_hash: Vec<u8>,
}

/// Reply containing the plaintext from a resent encrypted message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StartResendingEncryptedMessageReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(default, with = "optional_bytes")]
    plaintext: Option<Vec<u8>>,
    error_code: u8,
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
    #[serde(with = "serde_bytes")]
    next_message_box_index: Vec<u8>,
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
    stream_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    #[serde(with = "serde_bytes")]
    dest_write_cap: Vec<u8>,
    #[serde(with = "serde_bytes")]
    dest_start_index: Vec<u8>,
    is_last: bool,
}

/// Reply containing the created courier envelopes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CreateCourierEnvelopesFromPayloadReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    envelopes: Vec<serde_bytes::ByteBuf>,
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

/// Reply containing the created courier envelopes from multiple payloads.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CreateCourierEnvelopesFromPayloadsReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    envelopes: Vec<serde_bytes::ByteBuf>,
    error_code: u8,
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
    pub async fn new_keypair(&self, seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ThinClientError> {
        let query_id = Self::new_query_id();

        let request_inner = NewKeypairRequest {
            query_id: query_id.clone(),
            seed: seed.to_vec(),
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("new_keypair".to_string()), request_value);

        let reply_map = self.send_and_wait(&query_id, request).await?;

        let reply: NewKeypairReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("new_keypair failed with error code: {}", reply.error_code)));
        }

        Ok((reply.write_cap, reply.read_cap, reply.first_message_index))
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
    /// * `Ok((message_ciphertext, next_message_index, envelope_descriptor, envelope_hash))` on success
    /// * `Err(ThinClientError)` on failure
    pub async fn encrypt_read(
        &self,
        read_cap: &[u8],
        message_box_index: &[u8]
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32]), ThinClientError> {
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

        let reply_map = self.send_and_wait(&query_id, request).await?;

        let reply: EncryptReadReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("encrypt_read failed with error code: {}", reply.error_code)));
        }

        let mut envelope_hash = [0u8; 32];
        envelope_hash.copy_from_slice(&reply.envelope_hash[..32]);

        Ok((
            reply.message_ciphertext,
            reply.next_message_index,
            reply.envelope_descriptor,
            envelope_hash
        ))
    }

    /// Encrypts a write operation for a given write capability.
    ///
    /// This method prepares an encrypted write request that can be sent to the
    /// courier service to store a message in a pigeonhole box.
    ///
    /// # Arguments
    /// * `plaintext` - The plaintext message to encrypt
    /// * `write_cap` - Write capability that grants access to the channel
    /// * `message_box_index` - Starting write position for the channel
    ///
    /// # Returns
    /// * `Ok((message_ciphertext, envelope_descriptor, envelope_hash))` on success
    /// * `Err(ThinClientError)` on failure
    pub async fn encrypt_write(
        &self,
        plaintext: &[u8],
        write_cap: &[u8],
        message_box_index: &[u8]
    ) -> Result<(Vec<u8>, Vec<u8>, [u8; 32]), ThinClientError> {
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

        let reply_map = self.send_and_wait(&query_id, request).await?;

        let reply: EncryptWriteReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("encrypt_write failed with error code: {}", reply.error_code)));
        }

        let mut envelope_hash = [0u8; 32];
        envelope_hash.copy_from_slice(&reply.envelope_hash[..32]);

        Ok((
            reply.message_ciphertext,
            reply.envelope_descriptor,
            envelope_hash
        ))
    }

    /// Starts resending an encrypted message via ARQ (Automatic Repeat Request).
    ///
    /// This method initiates automatic repeat request for an encrypted message,
    /// which will be resent periodically until either a reply is received or
    /// the operation is cancelled.
    ///
    /// # Arguments
    /// * `read_cap` - Optional read capability (for read operations)
    /// * `write_cap` - Optional write capability (for write operations)
    /// * `next_message_index` - Optional next message index (for read operations)
    /// * `reply_index` - Reply index for the operation
    /// * `envelope_descriptor` - Envelope descriptor from encrypt_read/encrypt_write
    /// * `message_ciphertext` - Encrypted message from encrypt_read/encrypt_write
    /// * `envelope_hash` - Envelope hash from encrypt_read/encrypt_write
    ///
    /// # Returns
    /// * `Ok(plaintext)` - The plaintext reply received
    /// * `Err(ThinClientError)` on failure
    pub async fn start_resending_encrypted_message(
        &self,
        read_cap: Option<&[u8]>,
        write_cap: Option<&[u8]>,
        next_message_index: Option<&[u8]>,
        reply_index: u8,
        envelope_descriptor: &[u8],
        message_ciphertext: &[u8],
        envelope_hash: &[u8; 32]
    ) -> Result<Vec<u8>, ThinClientError> {
        let query_id = Self::new_query_id();

        let request_inner = StartResendingEncryptedMessageRequest {
            query_id: query_id.clone(),
            read_cap: read_cap.map(|rc| rc.to_vec()),
            write_cap: write_cap.map(|wc| wc.to_vec()),
            next_message_index: next_message_index.map(|nmi| nmi.to_vec()),
            reply_index,
            envelope_descriptor: envelope_descriptor.to_vec(),
            message_ciphertext: message_ciphertext.to_vec(),
            envelope_hash: envelope_hash.to_vec(),
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("start_resending_encrypted_message".to_string()), request_value);

        let reply_map = self.send_and_wait(&query_id, request).await?;

        let reply: StartResendingEncryptedMessageReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("start_resending_encrypted_message failed with error code: {}", reply.error_code)));
        }

        Ok(reply.plaintext.unwrap_or_default())
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
        let query_id = Self::new_query_id();

        let request_inner = CancelResendingEncryptedMessageRequest {
            query_id: query_id.clone(),
            envelope_hash: envelope_hash.to_vec(),
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("cancel_resending_encrypted_message".to_string()), request_value);

        let reply_map = self.send_and_wait(&query_id, request).await?;

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

        let reply_map = self.send_and_wait(&query_id, request).await?;

        let reply: NextMessageBoxIndexReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("next_message_box_index failed with error code: {}", reply.error_code)));
        }

        Ok(reply.next_message_box_index)
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

        let reply_map = self.send_and_wait(&query_id, request).await?;

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
        let query_id = Self::new_query_id();

        let request_inner = CancelResendingCopyCommandRequest {
            query_id: query_id.clone(),
            write_cap_hash: write_cap_hash.to_vec(),
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("cancel_resending_copy_command".to_string()), request_value);

        let reply_map = self.send_and_wait(&query_id, request).await?;

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
    /// # Arguments
    /// * `stream_id` - 16-byte identifier for the encoder instance
    /// * `payload` - The data to be encoded into courier envelopes
    /// * `dest_write_cap` - Write capability for the destination channel
    /// * `dest_start_index` - Starting index in the destination channel
    /// * `is_last` - Whether this is the last payload in the sequence
    ///
    /// # Returns
    /// * `Ok(Vec<Vec<u8>>)` - List of serialized CopyStreamElements
    /// * `Err(ThinClientError)` on failure
    pub async fn create_courier_envelopes_from_payload(
        &self,
        stream_id: &[u8; 16],
        payload: &[u8],
        dest_write_cap: &[u8],
        dest_start_index: &[u8],
        is_last: bool
    ) -> Result<Vec<Vec<u8>>, ThinClientError> {
        let query_id = Self::new_query_id();

        let request_inner = CreateCourierEnvelopesFromPayloadRequest {
            query_id: query_id.clone(),
            stream_id: stream_id.to_vec(),
            payload: payload.to_vec(),
            dest_write_cap: dest_write_cap.to_vec(),
            dest_start_index: dest_start_index.to_vec(),
            is_last,
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(|e| ThinClientError::CborError(e))?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("create_courier_envelopes_from_payload".to_string()), request_value);

        let reply_map = self.send_and_wait(&query_id, request).await?;

        let reply: CreateCourierEnvelopesFromPayloadReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("create_courier_envelopes_from_payload failed with error code: {}", reply.error_code)));
        }

        Ok(reply.envelopes.into_iter().map(|b| b.into_vec()).collect())
    }

    /// Creates CourierEnvelopes from multiple payloads going to different destinations.
    ///
    /// This is more space-efficient than calling create_courier_envelopes_from_payload
    /// multiple times because envelopes from different destinations are packed
    /// together in the copy stream without wasting space.
    ///
    /// # Arguments
    /// * `stream_id` - 16-byte identifier for the encoder instance
    /// * `destinations` - List of (payload, write_cap, start_index) tuples
    /// * `is_last` - Whether this is the last set of payloads in the sequence
    ///
    /// # Returns
    /// * `Ok(Vec<Vec<u8>>)` - List of serialized CopyStreamElements
    /// * `Err(ThinClientError)` on failure
    pub async fn create_courier_envelopes_from_payloads(
        &self,
        stream_id: &[u8; 16],
        destinations: Vec<(&[u8], &[u8], &[u8])>,
        is_last: bool
    ) -> Result<Vec<Vec<u8>>, ThinClientError> {
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
        request.insert(Value::Text("create_courier_envelopes_from_payloads".to_string()), request_value);

        let reply_map = self.send_and_wait(&query_id, request).await?;

        let reply: CreateCourierEnvelopesFromPayloadsReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(|e| ThinClientError::CborError(e))?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!("create_courier_envelopes_from_payloads failed with error code: {}", reply.error_code)));
        }

        Ok(reply.envelopes.into_iter().map(|b| b.into_vec()).collect())
    }

    /// Generates a new random 16-byte stream ID.
    pub fn new_stream_id() -> [u8; 16] {
        let mut stream_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut stream_id);
        stream_id
    }

    /// Tombstone a single pigeonhole box by overwriting it with zeros.
    ///
    /// This method overwrites the specified box with a zero-filled payload,
    /// effectively deleting its contents. The tombstone is sent via ARQ
    /// for reliable delivery.
    ///
    /// # Arguments
    /// * `geometry` - Pigeonhole geometry defining payload size
    /// * `write_cap` - Write capability for the box
    /// * `box_index` - Index of the box to tombstone
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(ThinClientError)` on failure
    pub async fn tombstone_box(
        &self,
        geometry: &PigeonholeGeometry,
        write_cap: &[u8],
        box_index: &[u8]
    ) -> Result<(), ThinClientError> {
        geometry.validate().map_err(|e| ThinClientError::Other(e.to_string()))?;

        // Create zero-filled tombstone payload
        let tomb = vec![0u8; geometry.max_plaintext_payload_length];

        // Encrypt the tombstone for the target box
        let (ciphertext, env_desc, env_hash) = self
            .encrypt_write(&tomb, write_cap, box_index).await?;

        // Send via ARQ for reliable delivery
        let _ = self.start_resending_encrypted_message(
            None,
            Some(write_cap),
            None,
            0,
            &env_desc,
            &ciphertext,
            &env_hash
        ).await?;

        Ok(())
    }
}

/// Result of a tombstone_range operation.
#[derive(Debug)]
pub struct TombstoneRangeResult {
    /// Number of boxes successfully tombstoned.
    pub tombstoned: u32,
    /// The next MessageBoxIndex after the last processed.
    pub next: Vec<u8>,
    /// Error message if the operation failed partway through.
    pub error: Option<String>,
}

impl ThinClient {
    /// Tombstone a range of pigeonhole boxes starting from a given index.
    ///
    /// This method tombstones up to max_count boxes, starting from the
    /// specified box index and advancing through consecutive indices.
    ///
    /// If an error occurs during the operation, a partial result is returned
    /// containing the number of boxes successfully tombstoned and the next
    /// index that was being processed.
    ///
    /// # Arguments
    /// * `geometry` - Pigeonhole geometry defining payload size
    /// * `write_cap` - Write capability for the boxes
    /// * `start` - Starting MessageBoxIndex
    /// * `max_count` - Maximum number of boxes to tombstone
    ///
    /// # Returns
    /// * `TombstoneRangeResult` containing the count and next index
    pub async fn tombstone_range(
        &self,
        geometry: &PigeonholeGeometry,
        write_cap: &[u8],
        start: &[u8],
        max_count: u32
    ) -> TombstoneRangeResult {
        if max_count == 0 {
            return TombstoneRangeResult {
                tombstoned: 0,
                next: start.to_vec(),
                error: None,
            };
        }

        if let Err(e) = geometry.validate() {
            return TombstoneRangeResult {
                tombstoned: 0,
                next: start.to_vec(),
                error: Some(e.to_string()),
            };
        }

        let mut cur = start.to_vec();
        let mut done: u32 = 0;

        while done < max_count {
            if let Err(e) = self.tombstone_box(geometry, write_cap, &cur).await {
                return TombstoneRangeResult {
                    tombstoned: done,
                    next: cur,
                    error: Some(format!("Error tombstoning box at index {}: {:?}", done, e)),
                };
            }

            done += 1;

            match self.next_message_box_index(&cur).await {
                Ok(next) => cur = next,
                Err(e) => {
                    return TombstoneRangeResult {
                        tombstoned: done,
                        next: cur,
                        error: Some(format!("Error getting next index after tombstoning: {:?}", e)),
                    };
                }
            }
        }

        TombstoneRangeResult {
            tombstoned: done,
            next: cur,
            error: None,
        }
    }
}