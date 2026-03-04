// SPDX-FileCopyrightText: Copyright (C) 2025, 2026 David Stainton
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
//!
//! # See Also
//!
//! - [katzenpost thin client rust docs](https://docs.rs/katzenpost_thin_client/latest/katzenpost_thin_client/)
//! - [katzenpost website](https://katzenpost.mixnetworks.org/)
//! - [katzepost client integration guide](https://katzenpost.network/docs/client_integration/)
//! - [katzenpost thin client protocol specification](https://katzenpost.network/docs/specs/connector.html)

// ========================================================================
// Module declarations
// ========================================================================

pub mod error;
pub mod core;
pub mod pigeonhole;
pub mod pigeonhole_db;
pub mod helpers;

// ========================================================================
// Re-exports for public API
// ========================================================================

pub use crate::core::{ThinClient, EventSinkReceiver};
pub use crate::helpers::{find_services, pretty_print_pki_doc};
pub use crate::pigeonhole::TombstoneRangeResult;

// ========================================================================
// Imports for types defined in this file
// ========================================================================

use std::collections::BTreeMap;
use std::sync::Arc;
use std::fs;

use serde::Deserialize;
use serde_cbor::Value;

use blake2::{Blake2b, Digest};
use generic_array::typenum::U32;

// ========================================================================
// Error codes
// ========================================================================

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

/// ThinClientErrorInvalidWriteCapability indicates that the provided write
/// capability is invalid.
pub const THIN_CLIENT_ERROR_INVALID_WRITE_CAPABILITY: u8 = 14;

/// ThinClientErrorInvalidReadCapability indicates that the provided read
/// capability is invalid.
pub const THIN_CLIENT_ERROR_INVALID_READ_CAPABILITY: u8 = 15;

/// ThinClientErrorInvalidResumeWriteChannelRequest indicates that the provided
/// ResumeWriteChannel request is invalid.
pub const THIN_CLIENT_ERROR_INVALID_RESUME_WRITE_CHANNEL_REQUEST: u8 = 16;

/// ThinClientErrorInvalidResumeReadChannelRequest indicates that the provided
/// ResumeReadChannel request is invalid.
pub const THIN_CLIENT_ERROR_INVALID_RESUME_READ_CHANNEL_REQUEST: u8 = 17;

/// ThinClientImpossibleHashError indicates that the provided hash is impossible
/// to compute, such as when the hash of a write capability is provided but
/// the write capability itself is not provided.
pub const THIN_CLIENT_IMPOSSIBLE_HASH_ERROR: u8 = 18;

/// ThinClientImpossibleNewWriteCapError indicates that the daemon was unable
/// to create a new write capability.
pub const THIN_CLIENT_IMPOSSIBLE_NEW_WRITE_CAP_ERROR: u8 = 19;

/// ThinClientImpossibleNewStatefulWriterError indicates that the daemon was unable
/// to create a new stateful writer.
pub const THIN_CLIENT_IMPOSSIBLE_NEW_STATEFUL_WRITER_ERROR: u8 = 20;

/// ThinClientCapabilityAlreadyInUse indicates that the provided capability
/// is already in use.
pub const THIN_CLIENT_CAPABILITY_ALREADY_IN_USE: u8 = 21;

/// ThinClientErrorMKEMDecryptionFailed indicates that MKEM decryption failed.
/// This occurs when the MKEM envelope cannot be decrypted with any of the replica keys.
pub const THIN_CLIENT_ERROR_MKEM_DECRYPTION_FAILED: u8 = 22;

/// ThinClientErrorBACAPDecryptionFailed indicates that BACAP decryption failed.
/// This occurs when the BACAP payload cannot be decrypted or signature verification fails.
pub const THIN_CLIENT_ERROR_BACAP_DECRYPTION_FAILED: u8 = 23;

/// ThinClientErrorStartResendingCancelled indicates that a StartResendingEncryptedMessage
/// or StartResendingCopyCommand operation was cancelled before completion.
pub const THIN_CLIENT_ERROR_START_RESENDING_CANCELLED: u8 = 24;

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
        THIN_CLIENT_ERROR_INVALID_WRITE_CAPABILITY => "Invalid write capability",
        THIN_CLIENT_ERROR_INVALID_READ_CAPABILITY => "Invalid read capability",
        THIN_CLIENT_ERROR_INVALID_RESUME_WRITE_CHANNEL_REQUEST => "Invalid resume write channel request",
        THIN_CLIENT_ERROR_INVALID_RESUME_READ_CHANNEL_REQUEST => "Invalid resume read channel request",
        THIN_CLIENT_IMPOSSIBLE_HASH_ERROR => "Impossible hash error",
        THIN_CLIENT_IMPOSSIBLE_NEW_WRITE_CAP_ERROR => "Failed to create new write capability",
        THIN_CLIENT_IMPOSSIBLE_NEW_STATEFUL_WRITER_ERROR => "Failed to create new stateful writer",
        THIN_CLIENT_CAPABILITY_ALREADY_IN_USE => "Capability already in use",
        THIN_CLIENT_ERROR_MKEM_DECRYPTION_FAILED => "MKEM decryption failed",
        THIN_CLIENT_ERROR_BACAP_DECRYPTION_FAILED => "BACAP decryption failed",
        THIN_CLIENT_ERROR_START_RESENDING_CANCELLED => "Start resending cancelled",
        _ => "Unknown thin client error code",
    }
}

// ========================================================================
// Public types
// ========================================================================

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

/// PigeonholeGeometry describes the geometry of a Pigeonhole envelope.
///
/// This provides mathematically precise geometry calculations using trunnel's
/// fixed binary format.
///
/// It supports 3 distinct use cases:
/// 1. Given MaxPlaintextPayloadLength → compute all envelope sizes
/// 2. Given precomputed Pigeonhole Geometry → derive accommodating Sphinx Geometry
/// 3. Given Sphinx Geometry constraint → derive optimal Pigeonhole Geometry
#[derive(Debug, Clone, Deserialize)]
pub struct PigeonholeGeometry {
    /// The maximum usable plaintext payload size within a Box.
    #[serde(rename = "MaxPlaintextPayloadLength")]
    pub max_plaintext_payload_length: usize,

    /// The size of a CourierQuery containing a ReplicaRead.
    #[serde(rename = "CourierQueryReadLength")]
    pub courier_query_read_length: usize,

    /// The size of a CourierQuery containing a ReplicaWrite.
    #[serde(rename = "CourierQueryWriteLength")]
    pub courier_query_write_length: usize,

    /// The size of a CourierQueryReply containing a ReplicaReadReply.
    #[serde(rename = "CourierQueryReplyReadLength")]
    pub courier_query_reply_read_length: usize,

    /// The size of a CourierQueryReply containing a ReplicaWriteReply.
    #[serde(rename = "CourierQueryReplyWriteLength")]
    pub courier_query_reply_write_length: usize,

    /// The NIKE scheme name used in MKEM for encrypting to multiple storage replicas.
    #[serde(rename = "NIKEName")]
    pub nike_name: String,

    /// The signature scheme used for BACAP (always "Ed25519").
    #[serde(rename = "SignatureSchemeName")]
    pub signature_scheme_name: String,
}

impl PigeonholeGeometry {
    /// Creates a new PigeonholeGeometry with the given parameters.
    ///
    /// Note: In a real application, the courier query lengths would be computed
    /// from the max_plaintext_payload_length using the geometry calculations.
    /// This constructor is primarily for testing where those values may be
    /// provided directly or defaulted to 0.
    pub fn new(max_plaintext_payload_length: usize, nike_name: &str) -> Self {
        Self {
            max_plaintext_payload_length,
            courier_query_read_length: 0,
            courier_query_write_length: 0,
            courier_query_reply_read_length: 0,
            courier_query_reply_write_length: 0,
            nike_name: nike_name.to_string(),
            signature_scheme_name: "Ed25519".to_string(),
        }
    }

    /// Validates that the geometry has valid parameters.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_plaintext_payload_length == 0 {
            return Err("MaxPlaintextPayloadLength must be positive");
        }
        if self.nike_name.is_empty() {
            return Err("NIKEName must be set");
        }
        if self.signature_scheme_name != "Ed25519" {
            return Err("SignatureSchemeName must be Ed25519");
        }
        Ok(())
    }
}

/// Creates a tombstone plaintext (all zeros) for the given geometry.
///
/// A tombstone is used to overwrite/delete a pigeonhole box by filling it
/// with zeros.
pub fn tombstone_plaintext(geometry: &PigeonholeGeometry) -> Result<Vec<u8>, &'static str> {
    geometry.validate()?;
    Ok(vec![0u8; geometry.max_plaintext_payload_length])
}

/// Checks if a plaintext is a tombstone (all zeros of the correct length).
pub fn is_tombstone_plaintext(geometry: &PigeonholeGeometry, plaintext: &[u8]) -> bool {
    if plaintext.len() != geometry.max_plaintext_payload_length {
        return false;
    }
    plaintext.iter().all(|&b| b == 0)
}

#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    #[serde(rename = "SphinxGeometry")]
    pub sphinx_geometry: Geometry,

    #[serde(rename = "PigeonholeGeometry")]
    pub pigeonhole_geometry: PigeonholeGeometry,

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
    pub pigeonhole_geometry: PigeonholeGeometry,

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
            pigeonhole_geometry: parsed.pigeonhole_geometry,
            on_connection_status: None,
            on_new_pki_document: None,
            on_message_sent: None,
            on_message_reply: None,
        })
    }
}





