// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! A thin client for sending and receiving messages via a Katzenpost
//! mix network.
//!
//! This crate provides a thin client library for interacting with a
//! Katzenpost mixnet, suitable for desktop and mobile applications.
//!
//! A mix network is a type of anonymous communications network.
//! What's a thin client library? It's code you can use as a
//! depencency in your application so that it can interact with
//! services on the mix network. The Katzenpost client daemon is a
//! multiplexing client; many applications on the same device can use
//! their thin client libraries to connect to the daemon and interact
//! with mixnet services concurrently.
//!
//! This example can be found here: https://github.com/katzenpost/thin_client/blob/main/examples/echo_ping.rs
//! Thin client example usage::
//!
//!
//! ```rust,no_run
//! use std::env;
//! use std::collections::BTreeMap;
//! use std::sync::{Arc, Mutex};
//! use std::process;
//!
//! use tokio::time::{timeout, Duration};
//! use tokio::runtime::Runtime;
//!
//! use serde_cbor::Value;
//!
//! use katzenpost_thin_client::{ThinClient, Config, pretty_print_pki_doc};
//!
//! struct ClientState {
//!     reply_message: Arc<Mutex<Option<BTreeMap<Value, Value>>>>,
//!     pki_received: Arc<Mutex<bool>>,
//! }
//!
//! impl ClientState {
//!     fn new() -> Self {
//!         Self {
//!             reply_message: Arc::new(Mutex::new(None)),
//!             pki_received: Arc::new(Mutex::new(false)),
//!         }
//!     }
//!
//!     fn save_reply(&self, reply: &BTreeMap<Value, Value>) {
//!         let mut stored_reply = self.reply_message.lock().unwrap();
//!         *stored_reply = Some(reply.clone());
//!     }
//!
//!     fn set_pki_received(&self) {
//!         let mut pki_flag = self.pki_received.lock().unwrap();
//!         *pki_flag = true;
//!     }
//!
//!     fn is_pki_received(&self) -> bool {
//!         *self.pki_received.lock().unwrap()
//!     }
//!
//!     fn await_message_reply(&self) -> Option<BTreeMap<Value, Value>> {
//!         let stored_reply = self.reply_message.lock().unwrap();
//!         stored_reply.clone()
//!     }
//! }
//!
//! fn main() {
//!     let args: Vec<String> = env::args().collect();
//!     if args.len() != 2 {
//!         eprintln!("Usage: {} <config_path>", args[0]);
//!         process::exit(1);
//!     }
//!     let config_path = &args[1];
//!
//!     let rt = Runtime::new().unwrap();
//!     rt.block_on(run_client(config_path)).unwrap();
//! }
//!
//! async fn run_client(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
//!     let state = Arc::new(ClientState::new());
//!     let state_for_reply = Arc::clone(&state);
//!     let state_for_pki = Arc::clone(&state);
//!
//!     let mut cfg = Config::new(config_path)?;
//!     cfg.on_new_pki_document = Some(Arc::new(move |_pki_doc| {
//!         println!("✅ PKI document received.");
//!         state_for_pki.set_pki_received();
//!     }));
//!     cfg.on_message_reply = Some(Arc::new(move |reply| {
//!         println!("📩 Received a reply!");
//!         state_for_reply.save_reply(reply);
//!     }));
//!
//!     println!("🚀 Initializing ThinClient...");
//!     let client = ThinClient::new(cfg).await?;
//!
//!     println!("⏳ Waiting for PKI document...");
//!     let result = timeout(Duration::from_secs(5), async {
//!         loop {
//!             if state.is_pki_received() {
//!                 break;
//!             }
//!             tokio::task::yield_now().await;
//!         }
//!     })
//!     .await;
//!
//!     if result.is_err() {
//!         return Err("❌ PKI document not received in time.".into());
//!     }
//!
//!     println!("✅ Pretty printing PKI document:");
//!     let doc = client.pki_document().await;
//!     pretty_print_pki_doc(&doc);
//!     println!("AFTER Pretty printing PKI document");
//!
//!     let service_desc = client.get_service("echo").await?;
//!     println!("got service descriptor for echo service");
//!
//!     let surb_id = ThinClient::new_surb_id();
//!     let payload = b"hello".to_vec();
//!     let (dest_node, dest_queue) = service_desc.to_destination();
//!
//!     println!("before calling send_message");
//!     client.send_message(surb_id, &payload, dest_node, dest_queue).await?;
//!     println!("after calling send_message");
//!
//!     println!("⏳ Waiting for message reply...");
//!     let state_for_reply_wait = Arc::clone(&state);
//!
//!     let result = timeout(Duration::from_secs(5), async move {
//!         loop {
//!             if let Some(reply) = state_for_reply_wait.await_message_reply() {
//!                 if let Some(Value::Bytes(payload2)) = reply.get(&Value::Text("payload".to_string())) {
//!                     let payload2 = &payload2[..payload.len()];
//!                     assert_eq!(payload, payload2, "Reply does not match payload!");
//!                     println!("✅ Received valid reply, stopping client.");
//!                     return Ok::<(), Box<dyn std::error::Error>>(());
//!                 }
//!             }
//!             tokio::task::yield_now().await;
//!         }
//!     }).await;
//!
//!     result.map_err(|e| Box::new(e))??;
//!     client.stop().await;
//!     println!("✅ Client stopped successfully.");
//!     Ok(())
//! }
//! ```
//!
//!
//! # See Also
//!
//! - [katzenpost thin client rust docs](https://docs.rs/katzenpost_thin_client/latest/katzenpost_thin_client/)
//! - [katzenpost website](https://katzenpost.mixnetworks.org/)
//! - [katzepost client integration guide](https://katzenpost.network/docs/client_integration/)
//! - [katzenpost thin client protocol specification](https://katzenpost.network/docs/specs/connector.html)

pub mod error;

// Thin client error codes provide standardized error reporting across the protocol.
// These codes are used in response messages to indicate the success or failure
// of operations, allowing applications to handle errors consistently.

/// ThinClientSuccess indicates that the operation completed successfully
/// with no errors. This is the default success state.
pub const THIN_CLIENT_SUCCESS: u8 = 0;

/// ThinClientErrorConnectionLost indicates that the connection to the daemon
/// was lost during the operation. The client should attempt to reconnect.
pub const THIN_CLIENT_ERROR_CONNECTION_LOST: u8 = 1;

/// ThinClientErrorTimeout indicates that the operation timed out before
/// completion. This may occur during network operations or when waiting
/// for responses from the mixnet.
pub const THIN_CLIENT_ERROR_TIMEOUT: u8 = 2;

/// ThinClientErrorInvalidRequest indicates that the request format was
/// invalid or contained malformed data that could not be processed.
pub const THIN_CLIENT_ERROR_INVALID_REQUEST: u8 = 3;

/// ThinClientErrorInternalError indicates an internal error occurred within
/// the client daemon or thin client that prevented operation completion.
pub const THIN_CLIENT_ERROR_INTERNAL_ERROR: u8 = 4;

/// ThinClientErrorMaxRetries indicates that the maximum number of retry
/// attempts was exceeded for a reliable operation (such as ARQ).
pub const THIN_CLIENT_ERROR_MAX_RETRIES: u8 = 5;

/// ThinClientErrorInvalidChannel indicates that the specified channel ID
/// is invalid or malformed.
pub const THIN_CLIENT_ERROR_INVALID_CHANNEL: u8 = 6;

/// ThinClientErrorChannelNotFound indicates that the specified channel
/// does not exist or has been garbage collected.
pub const THIN_CLIENT_ERROR_CHANNEL_NOT_FOUND: u8 = 7;

/// ThinClientErrorPermissionDenied indicates that the operation was denied
/// due to insufficient permissions or capability restrictions.
pub const THIN_CLIENT_ERROR_PERMISSION_DENIED: u8 = 8;

/// ThinClientErrorInvalidPayload indicates that the message payload was
/// invalid, too large, or otherwise could not be processed.
pub const THIN_CLIENT_ERROR_INVALID_PAYLOAD: u8 = 9;

/// ThinClientErrorServiceUnavailable indicates that the requested service
/// or functionality is currently unavailable.
pub const THIN_CLIENT_ERROR_SERVICE_UNAVAILABLE: u8 = 10;

/// ThinClientErrorDuplicateCapability indicates that the provided capability
/// (read or write cap) has already been used and is considered a duplicate.
pub const THIN_CLIENT_ERROR_DUPLICATE_CAPABILITY: u8 = 11;

/// ThinClientErrorCourierCacheCorruption indicates that the courier's cache
/// has detected corruption.
pub const THIN_CLIENT_ERROR_COURIER_CACHE_CORRUPTION: u8 = 12;

/// ThinClientPropagationError indicates that the request could not be
/// propagated to replicas.
pub const THIN_CLIENT_PROPAGATION_ERROR: u8 = 13;

/// Converts a thin client error code to a human-readable string.
/// This function provides consistent error message formatting across the thin client
/// protocol and is used for logging and error reporting.
pub fn thin_client_error_to_string(error_code: u8) -> &'static str {
    match error_code {
        THIN_CLIENT_SUCCESS => "Success",
        THIN_CLIENT_ERROR_CONNECTION_LOST => "Connection lost",
        THIN_CLIENT_ERROR_TIMEOUT => "Timeout",
        THIN_CLIENT_ERROR_INVALID_REQUEST => "Invalid request",
        THIN_CLIENT_ERROR_INTERNAL_ERROR => "Internal error",
        THIN_CLIENT_ERROR_MAX_RETRIES => "Maximum retries exceeded",
        THIN_CLIENT_ERROR_INVALID_CHANNEL => "Invalid channel",
        THIN_CLIENT_ERROR_CHANNEL_NOT_FOUND => "Channel not found",
        THIN_CLIENT_ERROR_PERMISSION_DENIED => "Permission denied",
        THIN_CLIENT_ERROR_INVALID_PAYLOAD => "Invalid payload",
        THIN_CLIENT_ERROR_SERVICE_UNAVAILABLE => "Service unavailable",
        THIN_CLIENT_ERROR_DUPLICATE_CAPABILITY => "Duplicate capability",
        THIN_CLIENT_ERROR_COURIER_CACHE_CORRUPTION => "Courier cache corruption",
        THIN_CLIENT_PROPAGATION_ERROR => "Propagation error",
        _ => "Unknown thin client error code",
    }
}

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::fs;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;
use serde_cbor::{from_slice, Value};

use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::task::JoinHandle;
use tokio::net::{TcpStream, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf as TcpReadHalf, OwnedWriteHalf as TcpWriteHalf};
use tokio::net::unix::{OwnedReadHalf as UnixReadHalf, OwnedWriteHalf as UnixWriteHalf};

use blake2::{Blake2b, Digest};
use generic_array::typenum::U32;
use rand::RngCore;
use log::{debug, error};

use crate::error::ThinClientError;

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
    replica_epoch: u64,
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
    replica_epoch: u64,
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
    replica_epoch: u64,
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

/// The size in bytes of a SURB (Single-Use Reply Block) identifier.
///
/// SURB IDs are used to correlate replies with the original message sender.
/// Each SURB ID must be unique and is typically randomly generated.
const SURB_ID_SIZE: usize = 16;

/// The size in bytes of a message identifier.
///
/// Message IDs are used to track outbound messages and correlate them with replies.
/// Like SURB IDs, these are expected to be randomly generated and unique.
const MESSAGE_ID_SIZE: usize = 16;

/// The size in bytes of a query identifier.
///
/// Query IDs are used to correlate channel operation requests with their responses.
/// Each query should have a unique ID.
const QUERY_ID_SIZE: usize = 16;

/// ServiceDescriptor is used when we are searching the PKI
/// document for a specific service.
#[derive(Debug, Clone)]
pub struct ServiceDescriptor {
    pub recipient_queue_id: Vec<u8>,
    pub mix_descriptor: BTreeMap<Value, Value>,
}

impl ServiceDescriptor {
    /// Here we convert the given descriptor into a destination
    /// that we can use to send a message on the mixnet.
    pub fn to_destination(&self) -> (Vec<u8>, Vec<u8>) {
        let identity_key = self
            .mix_descriptor
            .get(&Value::Text("IdentityKey".to_string()))
            .and_then(|v| match v {
                Value::Bytes(b) => Some(b),
                _ => None,
            })
            .cloned()
            .unwrap_or_else(Vec::new);

        let mut hasher = Blake2b::<U32>::new();
        hasher.update(&identity_key);
        let provider_id_hash = hasher.finalize().to_vec();
        (provider_id_hash, self.recipient_queue_id.clone())
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Geometry {
    #[serde(rename = "PacketLength")]
    pub packet_length: usize,

    #[serde(rename = "NrHops")]
    pub nr_hops: usize,

    #[serde(rename = "HeaderLength")]
    pub header_length: usize,

    #[serde(rename = "RoutingInfoLength")]
    pub routing_info_length: usize,

    #[serde(rename = "PerHopRoutingInfoLength")]
    pub per_hop_routing_info_length: usize,

    #[serde(rename = "SURBLength")]
    pub surb_length: usize,

    #[serde(rename = "SphinxPlaintextHeaderLength")]
    pub sphinx_plaintext_header_length: usize,

    #[serde(rename = "PayloadTagLength")]
    pub payload_tag_length: usize,

    #[serde(rename = "ForwardPayloadLength")]
    pub forward_payload_length: usize,

    #[serde(rename = "UserForwardPayloadLength")]
    pub user_forward_payload_length: usize,

    #[serde(rename = "NextNodeHopLength")]
    pub next_node_hop_length: usize,

    #[serde(rename = "SPRPKeyMaterialLength")]
    pub sprp_key_material_length: usize,

    #[serde(rename = "NIKEName")]
    pub nike_name: String,

    #[serde(rename = "KEMName")]
    pub kem_name: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    #[serde(rename = "SphinxGeometry")]
    pub sphinx_geometry: Geometry,

    #[serde(rename = "Network")]
    pub network: String,

    #[serde(rename = "Address")]
    pub address: String,
}

impl ConfigFile {
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: ConfigFile = toml::from_str(&contents)?;
        Ok(config)
    }
}


/// Our configuration defines some callbacks which the thin client will envoke
/// when it receives the corresponding event from the client daemon.
#[derive(Clone)]
pub struct Config {
    pub network: String,
    pub address: String,
    pub sphinx_geometry: Geometry,

    pub on_connection_status: Option<Arc<dyn Fn(&BTreeMap<Value, Value>) + Send + Sync>>,
    pub on_new_pki_document: Option<Arc<dyn Fn(&BTreeMap<Value, Value>) + Send + Sync>>,
    pub on_message_sent: Option<Arc<dyn Fn(&BTreeMap<Value, Value>) + Send + Sync>>,
    pub on_message_reply: Option<Arc<dyn Fn(&BTreeMap<Value, Value>) + Send + Sync>>,
}

impl Config {
    pub fn new(filepath: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(filepath)?;
        let parsed: ConfigFile = toml::from_str(&contents)?;

        Ok(Self {
            network: parsed.network,
            address: parsed.address,
            sphinx_geometry: parsed.sphinx_geometry,
            on_connection_status: None,
            on_new_pki_document: None,
            on_message_sent: None,
            on_message_reply: None,
        })
    }
}

/// This represent the read half of our network socket.
pub enum ReadHalf {
    Tcp(TcpReadHalf),
    Unix(UnixReadHalf),
}

/// This represent the write half of our network socket.
pub enum WriteHalf {
    Tcp(TcpWriteHalf),
    Unix(UnixWriteHalf),
}

/// Wrapper for event sink receiver that automatically removes the drain when dropped
pub struct EventSinkReceiver {
    receiver: mpsc::UnboundedReceiver<BTreeMap<Value, Value>>,
    sender: mpsc::UnboundedSender<BTreeMap<Value, Value>>,
    drain_remove: mpsc::UnboundedSender<mpsc::UnboundedSender<BTreeMap<Value, Value>>>,
}

impl EventSinkReceiver {
    /// Receive the next event from the sink
    pub async fn recv(&mut self) -> Option<BTreeMap<Value, Value>> {
        self.receiver.recv().await
    }
}

impl Drop for EventSinkReceiver {
    fn drop(&mut self) {
        // Remove the drain when the receiver is dropped
        if let Err(_) = self.drain_remove.send(self.sender.clone()) {
            debug!("Failed to remove drain channel - event sink worker may be stopped");
        }
    }
}

/// This is our ThinClient type which encapsulates our thin client
/// connection management and message processing.
pub struct ThinClient {
    read_half: Mutex<ReadHalf>,
    write_half: Mutex<WriteHalf>,
    config: Config,
    pki_doc: Arc<RwLock<Option<BTreeMap<Value, Value>>>>,
    worker_task: Mutex<Option<JoinHandle<()>>>,
    event_sink_task: Mutex<Option<JoinHandle<()>>>,
    shutdown: Arc<AtomicBool>,
    is_connected: Arc<AtomicBool>,
    // Event system like Go implementation
    event_sink: mpsc::UnboundedSender<BTreeMap<Value, Value>>,
    drain_add: mpsc::UnboundedSender<mpsc::UnboundedSender<BTreeMap<Value, Value>>>,
    drain_remove: mpsc::UnboundedSender<mpsc::UnboundedSender<BTreeMap<Value, Value>>>,
}

impl ThinClient {

    /// Create a new thin cilent and connect it to the client daemon.
    pub async fn new(config: Config) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        // Create event system channels like Go implementation
        let (event_sink_tx, event_sink_rx) = mpsc::unbounded_channel();
        let (drain_add_tx, drain_add_rx) = mpsc::unbounded_channel();
        let (drain_remove_tx, drain_remove_rx) = mpsc::unbounded_channel();

	let client = match config.network.to_uppercase().as_str() {
            "TCP" => {
		let socket = TcpStream::connect(&config.address).await?;
		let (read_half, write_half) = socket.into_split();
		Arc::new(Self {
                    read_half: Mutex::new(ReadHalf::Tcp(read_half)),
                    write_half: Mutex::new(WriteHalf::Tcp(write_half)),
                    config,
                    pki_doc: Arc::new(RwLock::new(None)),
                    worker_task: Mutex::new(None),
                    event_sink_task: Mutex::new(None),
                    shutdown: Arc::new(AtomicBool::new(false)),
                    is_connected: Arc::new(AtomicBool::new(false)),
                    event_sink: event_sink_tx.clone(),
                    drain_add: drain_add_tx.clone(),
                    drain_remove: drain_remove_tx.clone(),
		})
            }
            "UNIX" => {
		let path = if config.address.starts_with('@') {
                    let mut p = String::from("\0");
                    p.push_str(&config.address[1..]);
                    p
		} else {
                    config.address.clone()
		};
		let socket = UnixStream::connect(path).await?;
		let (read_half, write_half) = socket.into_split();
		Arc::new(Self {
                    read_half: Mutex::new(ReadHalf::Unix(read_half)),
                    write_half: Mutex::new(WriteHalf::Unix(write_half)),
                    config,
                    pki_doc: Arc::new(RwLock::new(None)),
                    worker_task: Mutex::new(None),
                    event_sink_task: Mutex::new(None),
                    shutdown: Arc::new(AtomicBool::new(false)),
                    is_connected: Arc::new(AtomicBool::new(false)),
                    event_sink: event_sink_tx,
                    drain_add: drain_add_tx,
                    drain_remove: drain_remove_tx,
		})
            }
	    _ => {
		return Err(format!("Unknown network type: {}", config.network).into());
            }
        };

        // Start worker loop
        let client_clone = Arc::clone(&client);
        let task = tokio::spawn(async move { client_clone.worker_loop().await });
        *client.worker_task.lock().await = Some(task);

        // Start event sink worker
        let client_clone2 = Arc::clone(&client);
        let event_sink_task = tokio::spawn(async move {
            client_clone2.event_sink_worker(event_sink_rx, drain_add_rx, drain_remove_rx).await
        });
        *client.event_sink_task.lock().await = Some(event_sink_task);

        debug!("✅ ThinClient initialized with worker loop and event sink started.");
        Ok(client)
        }

        /// Stop our async worker task and disconnect the thin client.
        pub async fn stop(&self) {
        debug!("Stopping ThinClient...");

        self.shutdown.store(true, Ordering::Relaxed);

        let mut write_half = self.write_half.lock().await;

        let _ = match &mut *write_half {
                WriteHalf::Tcp(wh) => wh.shutdown().await,
                WriteHalf::Unix(wh) => wh.shutdown().await,
        };

        if let Some(worker) = self.worker_task.lock().await.take() {
                worker.abort();
        }

        debug!("✅ ThinClient stopped.");
    }

    /// Returns true if the daemon is connected to the mixnet.
    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::Relaxed)
    }

    /// Creates a new event channel that receives all events from the thin client
    /// This mirrors the Go implementation's EventSink method
    pub fn event_sink(&self) -> EventSinkReceiver {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Err(_) = self.drain_add.send(tx.clone()) {
            debug!("Failed to add drain channel - event sink worker may be stopped");
        }
        EventSinkReceiver {
            receiver: rx,
            sender: tx,
            drain_remove: self.drain_remove.clone(),
        }
    }

    /// Generates a new message ID.
    pub fn new_message_id() -> Vec<u8> {
        let mut id = vec![0; MESSAGE_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    /// Generates a new SURB ID.
    pub fn new_surb_id() -> Vec<u8> {
        let mut id = vec![0; SURB_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    /// Generates a new query ID.
    pub fn new_query_id() -> Vec<u8> {
        let mut id = vec![0; QUERY_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    async fn update_pki_document(&self, new_pki_doc: BTreeMap<Value, Value>) {
        let mut pki_doc_lock = self.pki_doc.write().await;
        *pki_doc_lock = Some(new_pki_doc);
        debug!("PKI document updated.");
    }

    /// Returns our latest retrieved PKI document.
    pub async fn pki_document(&self) -> BTreeMap<Value, Value> {
        self.pki_doc.read().await.clone().expect("❌ PKI document is missing!")
    }

    /// Given a service name this returns a ServiceDescriptor if the service exists
    /// in the current PKI document.
    pub async fn get_service(&self, service_name: &str) -> Result<ServiceDescriptor, ThinClientError> {
        let doc = self.pki_doc.read().await.clone().ok_or(ThinClientError::MissingPkiDocument)?;
        let services = find_services(service_name, &doc);
        services.into_iter().next().ok_or(ThinClientError::ServiceNotFound)
    }

    /// Returns a courier service destination for the current epoch.
    /// This method finds and randomly selects a courier service from the current
    /// PKI document. The returned destination information is used with SendChannelQuery
    /// and SendChannelQueryAwaitReply to transmit prepared channel operations.
    /// Returns (dest_node, dest_queue) on success.
    pub async fn get_courier_destination(&self) -> Result<(Vec<u8>, Vec<u8>), ThinClientError> {
        let courier_service = self.get_service("courier").await?;
        let (dest_node, dest_queue) = courier_service.to_destination();
        Ok((dest_node, dest_queue))
    }

    async fn recv(&self) -> Result<BTreeMap<Value, Value>, ThinClientError> {
        let mut length_prefix = [0; 4];
        {
                let mut read_half = self.read_half.lock().await;
                match &mut *read_half {
            ReadHalf::Tcp(rh) => rh.read_exact(&mut length_prefix).await.map_err(ThinClientError::IoError)?,
            ReadHalf::Unix(rh) => rh.read_exact(&mut length_prefix).await.map_err(ThinClientError::IoError)?,
                };
        }
        let message_length = u32::from_be_bytes(length_prefix) as usize;
        let mut buffer = vec![0; message_length];
        {
                let mut read_half = self.read_half.lock().await;
                match &mut *read_half {
            ReadHalf::Tcp(rh) => rh.read_exact(&mut buffer).await.map_err(ThinClientError::IoError)?,
            ReadHalf::Unix(rh) => rh.read_exact(&mut buffer).await.map_err(ThinClientError::IoError)?,
                };
        }
        let response: BTreeMap<Value, Value> = match from_slice(&buffer) {
                Ok(parsed) => {
            parsed
                }
                Err(err) => {
            error!("❌ Failed to parse CBOR: {:?}", err);
            return Err(ThinClientError::CborError(err));
                }
        };
        Ok(response)
    }
    
    fn parse_status(&self, event: &BTreeMap<Value, Value>) {
        let is_connected = event.get(&Value::Text("is_connected".to_string()))
            .and_then(|v| match v {
                Value::Bool(b) => Some(*b),
                _ => None,
            })
            .unwrap_or(false);

        // Update connection state
        self.is_connected.store(is_connected, Ordering::Relaxed);

        if is_connected {
            debug!("✅ Daemon is connected to mixnet - full functionality available.");
        } else {
            debug!("📴 Daemon is not connected to mixnet - entering offline mode (channel operations will work).");
        }
    }

    async fn parse_pki_doc(&self, event: &BTreeMap<Value, Value>) {
        if let Some(Value::Bytes(payload)) = event.get(&Value::Text("payload".to_string())) {
            match serde_cbor::from_slice::<BTreeMap<Value, Value>>(payload) {
                Ok(raw_pki_doc) => {
                    self.update_pki_document(raw_pki_doc).await;
                    debug!("✅ PKI document successfully parsed.");
                }
                Err(err) => {
                    error!("❌ Failed to parse PKI document: {:?}", err);
                }
            }
        } else {
            error!("❌ Missing 'payload' field in PKI document event.");
        }
    }

    async fn handle_response(&self, response: BTreeMap<Value, Value>) {
        assert!(!response.is_empty(), "❌ Received an empty response!");

        if let Some(Value::Map(event)) = response.get(&Value::Text("connection_status_event".to_string())) {
            debug!("🔄 Connection status event received.");
            self.parse_status(event);
            if let Some(cb) = self.config.on_connection_status.as_ref() {
                cb(event);
            }
            return;
        }

        if let Some(Value::Map(event)) = response.get(&Value::Text("new_pki_document_event".to_string())) {
            debug!("📜 New PKI document event received.");
            self.parse_pki_doc(event).await;
            if let Some(cb) = self.config.on_new_pki_document.as_ref() {
                cb(event);
            }
            return;
        }

        if let Some(Value::Map(event)) = response.get(&Value::Text("message_sent_event".to_string())) {
            debug!("📨 Message sent event received.");
            if let Some(cb) = self.config.on_message_sent.as_ref() {
                cb(event);
            }
            return;
        }

        if let Some(Value::Map(event)) = response.get(&Value::Text("message_reply_event".to_string())) {
            debug!("📩 Message reply event received.");
            if let Some(cb) = self.config.on_message_reply.as_ref() {
                cb(event);
            }
            return;
        }

        error!("❌ Unknown event type received: {:?}", response);
    }

    async fn worker_loop(&self) {
        debug!("Worker loop started");
        while !self.shutdown.load(Ordering::Relaxed) {
            match self.recv().await {
                Ok(response) => {
                    // Send all responses to event sink for distribution
                    if let Err(_) = self.event_sink.send(response.clone()) {
                        debug!("Event sink channel closed, stopping worker loop");
                        break;
                    }
                    self.handle_response(response).await;
                },
                Err(_) if self.shutdown.load(Ordering::Relaxed) => break,
                Err(err) => error!("Error in recv: {}", err),
            }
        }
        debug!("Worker loop exited.");
    }

    /// Event sink worker that distributes events to multiple drain channels
    /// This mirrors the Go implementation's eventSinkWorker
    async fn event_sink_worker(
        &self,
        mut event_sink_rx: mpsc::UnboundedReceiver<BTreeMap<Value, Value>>,
        mut drain_add_rx: mpsc::UnboundedReceiver<mpsc::UnboundedSender<BTreeMap<Value, Value>>>,
        mut drain_remove_rx: mpsc::UnboundedReceiver<mpsc::UnboundedSender<BTreeMap<Value, Value>>>,
    ) {
        debug!("Event sink worker started");
        let mut drains: HashMap<usize, mpsc::UnboundedSender<BTreeMap<Value, Value>>> = HashMap::new();
        let mut next_id = 0usize;

        loop {
            tokio::select! {
                // Handle shutdown
                _ = async { while !self.shutdown.load(Ordering::Relaxed) { tokio::time::sleep(std::time::Duration::from_millis(100)).await; } } => {
                    debug!("Event sink worker shutting down");
                    break;
                }

                // Add new drain channel
                Some(drain) = drain_add_rx.recv() => {
                    drains.insert(next_id, drain);
                    next_id += 1;
                    debug!("Added new drain channel, total drains: {}", drains.len());
                }

                // Remove drain channel when EventSinkReceiver is dropped
                Some(drain_to_remove) = drain_remove_rx.recv() => {
                    drains.retain(|_, drain| !std::ptr::addr_eq(drain, &drain_to_remove));
                    debug!("Removed drain channel, total drains: {}", drains.len());
                }

                // Distribute events to all drain channels
                Some(event) = event_sink_rx.recv() => {
                    let mut bad_drains = Vec::new();

                    for (id, drain) in &drains {
                        if let Err(_) = drain.send(event.clone()) {
                            // Channel is closed, mark for removal
                            bad_drains.push(*id);
                        }
                    }

                    // Remove closed channels
                    for id in bad_drains {
                        drains.remove(&id);
                    }
                }
            }
        }
        debug!("Event sink worker exited.");
    }

    async fn send_cbor_request(&self, request: BTreeMap<Value, Value>) -> Result<(), ThinClientError> {
        let encoded_request = serde_cbor::to_vec(&serde_cbor::Value::Map(request))?;
        let length_prefix = (encoded_request.len() as u32).to_be_bytes();

        let mut write_half = self.write_half.lock().await;

        match &mut *write_half {
                WriteHalf::Tcp(wh) => {
            wh.write_all(&length_prefix).await?;
            wh.write_all(&encoded_request).await?;
                }
                WriteHalf::Unix(wh) => {
            wh.write_all(&length_prefix).await?;
            wh.write_all(&encoded_request).await?;
                }
        }

        debug!("✅ Request sent successfully.");
        Ok(())
    }

    /// Send a CBOR request and wait for a reply with the matching query_id
    async fn send_and_wait(&self, query_id: &[u8], request: BTreeMap<Value, Value>) -> Result<BTreeMap<Value, Value>, ThinClientError> {
        // Create an event sink to receive the reply
        let mut event_rx = self.event_sink();

        // Small delay to ensure the event sink drain is registered before sending the request
        // This prevents a race condition where a fast daemon response arrives before the drain is ready
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Send the request
        self.send_cbor_request(request).await?;

        // Wait for the reply with matching query_id (with timeout)
        // Mixnets are slow due to mixing delays, cover traffic, etc.
        // Use a generous timeout for integration tests and real-world usage
        let timeout_duration = Duration::from_secs(600);
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > timeout_duration {
                return Err(ThinClientError::Other("Timeout waiting for reply".to_string()));
            }

            // Try to receive with a short timeout to allow checking the overall timeout
            match tokio::time::timeout(Duration::from_millis(100), event_rx.recv()).await {
                Ok(Some(reply)) => {
                    let reply_types = vec![
                        "new_keypair_reply",
                        "encrypt_read_reply",
                        "encrypt_write_reply",
                        "start_resending_encrypted_message_reply",
                        "cancel_resending_encrypted_message_reply",
                        "next_message_box_index_reply",
                    ];

                    for reply_type in reply_types {
                        if let Some(Value::Map(inner_reply)) = reply.get(&Value::Text(reply_type.to_string())) {
                            // Check if this inner reply has the matching query_id
                            if let Some(Value::Bytes(reply_query_id)) = inner_reply.get(&Value::Text("query_id".to_string())) {
                                if reply_query_id == query_id {
                                    // Found our reply! Return the inner map
                                    return Ok(inner_reply.clone());
                                }
                            }
                        }
                    }
                    // Not our reply, continue waiting
                }
                Ok(None) => {
                    return Err(ThinClientError::Other("Event channel closed".to_string()));
                }
                Err(_) => {
                    // Timeout on this receive, continue loop to check overall timeout
                    continue;
                }
            }
        }
    }

    /// Sends a message encapsulated in a Sphinx packet without any SURB.
    /// No reply will be possible. This method requires mixnet connectivity.
    pub async fn send_message_without_reply(
	&self,
	payload: &[u8],
	dest_node: Vec<u8>,
	dest_queue: Vec<u8>
    ) -> Result<(), ThinClientError> {
        // Check if we're in offline mode
        if !self.is_connected() {
            return Err(ThinClientError::OfflineMode("cannot send message in offline mode - daemon not connected to mixnet".to_string()));
        }
        // Create the SendMessage structure
        let mut send_message = BTreeMap::new();
        send_message.insert(Value::Text("id".to_string()), Value::Null); // No ID for fire-and-forget messages
        send_message.insert(Value::Text("with_surb".to_string()), Value::Bool(false));
        send_message.insert(Value::Text("surbid".to_string()), Value::Null); // No SURB ID for fire-and-forget messages
        send_message.insert(Value::Text("destination_id_hash".to_string()), Value::Bytes(dest_node));
        send_message.insert(Value::Text("recipient_queue_id".to_string()), Value::Bytes(dest_queue));
        send_message.insert(Value::Text("payload".to_string()), Value::Bytes(payload.to_vec()));

        // Wrap in the new Request structure
        let mut request = BTreeMap::new();
        request.insert(Value::Text("send_message".to_string()), Value::Map(send_message));

        self.send_cbor_request(request).await
    }

    /// This method takes a message payload, a destination node,
    /// destination queue ID and a SURB ID and sends a message along
    /// with a SURB so that you can later receive the reply along with
    /// the SURBID you choose.  This method of sending messages should
    /// be considered to be asynchronous because it does NOT actually
    /// wait until the client daemon sends the message. Nor does it
    /// wait for a reply. The only blocking aspect to it's behavior is
    /// merely blocking until the client daemon receives our request
    /// to send a message. This method requires mixnet connectivity.
    pub async fn send_message(
	&self,
	surb_id: Vec<u8>,
	payload: &[u8],
	dest_node: Vec<u8>,
	dest_queue: Vec<u8>
    ) -> Result<(), ThinClientError> {
        // Check if we're in offline mode
        if !self.is_connected() {
            return Err(ThinClientError::OfflineMode("cannot send message in offline mode - daemon not connected to mixnet".to_string()));
        }
        // Create the SendMessage structure
        let mut send_message = BTreeMap::new();
        send_message.insert(Value::Text("id".to_string()), Value::Null); // No ID for regular messages
        send_message.insert(Value::Text("with_surb".to_string()), Value::Bool(true));
        send_message.insert(Value::Text("surbid".to_string()), Value::Bytes(surb_id));
        send_message.insert(Value::Text("destination_id_hash".to_string()), Value::Bytes(dest_node));
        send_message.insert(Value::Text("recipient_queue_id".to_string()), Value::Bytes(dest_queue));
        send_message.insert(Value::Text("payload".to_string()), Value::Bytes(payload.to_vec()));

        // Wrap in the new Request structure
        let mut request = BTreeMap::new();
        request.insert(Value::Text("send_message".to_string()), Value::Map(send_message));

        self.send_cbor_request(request).await
    }

    /// This method takes a message payload, a destination node,
    /// destination queue ID and a message ID and reliably sends a message.
    /// This uses a simple ARQ to resend the message if a reply wasn't received.
    /// The given message ID will be used to identify the reply since a SURB ID
    /// can only be used once. This method requires mixnet connectivity.
    pub async fn send_reliable_message(
	&self,
	message_id: Vec<u8>,
	payload: &[u8],
	dest_node: Vec<u8>,
	dest_queue: Vec<u8>
    ) -> Result<(), ThinClientError> {
        // Check if we're in offline mode
        if !self.is_connected() {
            return Err(ThinClientError::OfflineMode("cannot send reliable message in offline mode - daemon not connected to mixnet".to_string()));
        }
        // Create the SendARQMessage structure
        let mut send_arq_message = BTreeMap::new();
        send_arq_message.insert(Value::Text("id".to_string()), Value::Bytes(message_id));
        send_arq_message.insert(Value::Text("with_surb".to_string()), Value::Bool(true));
        send_arq_message.insert(Value::Text("surbid".to_string()), Value::Null); // ARQ messages don't use SURB IDs directly
        send_arq_message.insert(Value::Text("destination_id_hash".to_string()), Value::Bytes(dest_node));
        send_arq_message.insert(Value::Text("recipient_queue_id".to_string()), Value::Bytes(dest_queue));
        send_arq_message.insert(Value::Text("payload".to_string()), Value::Bytes(payload.to_vec()));

        // Wrap in the new Request structure
        let mut request = BTreeMap::new();
        request.insert(Value::Text("send_arq_message".to_string()), Value::Map(send_arq_message));

        self.send_cbor_request(request).await
    }

    // ========================================================================
    // NEW Pigeonhole API Methods
    // ========================================================================

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
    /// * `Ok((message_ciphertext, next_message_index, envelope_descriptor, envelope_hash, replica_epoch))` on success
    /// * `Err(ThinClientError)` on failure
    pub async fn encrypt_read(
        &self,
        read_cap: &[u8],
        message_box_index: &[u8]
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32], u64), ThinClientError> {
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
            envelope_hash,
            reply.replica_epoch
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
    /// * `Ok((message_ciphertext, envelope_descriptor, envelope_hash, replica_epoch))` on success
    /// * `Err(ThinClientError)` on failure
    pub async fn encrypt_write(
        &self,
        plaintext: &[u8],
        write_cap: &[u8],
        message_box_index: &[u8]
    ) -> Result<(Vec<u8>, Vec<u8>, [u8; 32], u64), ThinClientError> {
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
            envelope_hash,
            reply.replica_epoch
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
    /// * `replica_epoch` - Replica epoch from encrypt_read/encrypt_write
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
        envelope_hash: &[u8; 32],
        replica_epoch: u64
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
            replica_epoch,
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
}

/// Find a specific mixnet service if it exists.
pub fn find_services(capability: &str, doc: &BTreeMap<Value, Value>) -> Vec<ServiceDescriptor> {
    let mut services = Vec::new();

    let Some(Value::Array(nodes)) = doc.get(&Value::Text("ServiceNodes".to_string())) else {
        println!("❌ No 'ServiceNodes' found in PKI document.");
        return services;
    };

    for node in nodes {
        let Value::Bytes(node_bytes) = node else { continue };
        let Ok(mynode) = from_slice::<BTreeMap<Value, Value>>(node_bytes) else { continue };

        // 🔍 Print available capabilities in each node
        if let Some(Value::Map(details)) = mynode.get(&Value::Text("Kaetzchen".to_string())) {
            println!("🔍 Available Capabilities: {:?}", details.keys());
        }

        let Some(Value::Map(details)) = mynode.get(&Value::Text("Kaetzchen".to_string())) else { continue };
        let Some(Value::Map(service)) = details.get(&Value::Text(capability.to_string())) else { continue };
        let Some(Value::Text(endpoint)) = service.get(&Value::Text("endpoint".to_string())) else { continue };

	println!("returning a service descriptor!");
	    
        services.push(ServiceDescriptor {
            recipient_queue_id: endpoint.as_bytes().to_vec(),
            mix_descriptor: mynode,
        });
    }

    services
}

fn convert_to_pretty_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Text(s) => serde_json::Value::String(s.clone()),
        Value::Integer(i) => json!(*i),
        Value::Bytes(b) => json!(hex::encode(b)), // Encode byte arrays as hex strings
        Value::Array(arr) => serde_json::Value::Array(arr.iter().map(convert_to_pretty_json).collect()),
        Value::Map(map) => {
            let converted_map: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(key, value)| {
                    let key_str = match key {
                        Value::Text(s) => s.clone(),
                        _ => format!("{:?}", key),
                    };
                    (key_str, convert_to_pretty_json(value))
                })
                .collect();
            serde_json::Value::Object(converted_map)
        }
        _ => serde_json::Value::Null, // Handle unexpected CBOR types
    }
}

fn decode_cbor_nodes(nodes: &[Value]) -> Vec<Value> {
    nodes
        .iter()
        .filter_map(|node| match node {
            Value::Bytes(blob) => serde_cbor::from_slice::<BTreeMap<Value, Value>>(blob)
                .ok()
                .map(Value::Map),
            _ => Some(node.clone()), // Preserve non-CBOR values as they are
        })
        .collect()
}

/// Pretty prints a PKI document which you can gather from the client
/// with it's `pki_document` method, documented above.
pub fn pretty_print_pki_doc(doc: &BTreeMap<Value, Value>) {
    let mut new_doc = BTreeMap::new();

    // Decode "GatewayNodes"
    if let Some(Value::Array(gateway_nodes)) = doc.get(&Value::Text("GatewayNodes".to_string())) {
        new_doc.insert(Value::Text("GatewayNodes".to_string()), Value::Array(decode_cbor_nodes(gateway_nodes)));
    }

    // Decode "ServiceNodes"
    if let Some(Value::Array(service_nodes)) = doc.get(&Value::Text("ServiceNodes".to_string())) {
        new_doc.insert(Value::Text("ServiceNodes".to_string()), Value::Array(decode_cbor_nodes(service_nodes)));
    }

    // Decode "Topology" (flatten nested arrays of CBOR blobs)
    if let Some(Value::Array(topology_layers)) = doc.get(&Value::Text("Topology".to_string())) {
        let decoded_topology: Vec<Value> = topology_layers
            .iter()
            .flat_map(|layer| match layer {
                Value::Array(layer_nodes) => decode_cbor_nodes(layer_nodes),
                _ => vec![],
            })
            .collect();

        new_doc.insert(Value::Text("Topology".to_string()), Value::Array(decoded_topology));
    }

    // Copy and decode all other fields that might contain CBOR blobs
    for (key, value) in doc.iter() {
        if !matches!(key, Value::Text(s) if ["GatewayNodes", "ServiceNodes", "Topology"].contains(&s.as_str())) {
            let key_str = key.clone();
            let decoded_value = match value {
                Value::Bytes(blob) => serde_cbor::from_slice::<BTreeMap<Value, Value>>(blob)
                    .ok()
                    .map(Value::Map)
                    .unwrap_or(value.clone()), // Fallback to original if not CBOR
                _ => value.clone(),
            };

            new_doc.insert(key_str, decoded_value);
        }
    }

    // Convert to pretty JSON format right before printing
    let pretty_json = convert_to_pretty_json(&Value::Map(new_doc));
    println!("{}", serde_json::to_string_pretty(&pretty_json).unwrap());
}
