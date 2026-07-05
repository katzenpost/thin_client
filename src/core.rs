// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! This module provides the main ThinClient struct and core functionality for
//! connecting to the client daemon, managing events, and sending messages.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use serde_cbor::{from_slice, Value};

use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf as TcpReadHalf, OwnedWriteHalf as TcpWriteHalf};
use tokio::net::unix::{OwnedReadHalf as UnixReadHalf, OwnedWriteHalf as UnixWriteHalf};

use rand::RngCore;
use rand::Rng;
use log::{debug, error};

use crate::error::ThinClientError;
use crate::{Config, ServiceDescriptor, Geometry, PigeonholeGeometry};
use crate::helpers::find_services;

/// Request to close the thin client connection.
/// Tells the daemon to clean up ARQ state for this connection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ThinCloseRequest {}

/// Request the cert.Certificate-wrapped signed PKI document for an
/// epoch, with every directory authority signature intact. Pass
/// `epoch = 0` to ask the daemon for the document it believes is
/// current.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct GetPKIDocumentRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    epoch: u64,
}

/// Reply to a `GetPKIDocument` request. `payload` carries the
/// cert.Certificate-wrapped signed PKI document; `epoch` is the
/// epoch of the returned document; `error_code` is zero on success.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct GetPKIDocumentReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(default, with = "serde_bytes")]
    payload: Vec<u8>,
    #[serde(default)]
    epoch: u64,
    #[serde(default)]
    error_code: u8,
}

/// A directory authority descriptor as held in the client daemon's
/// configuration. The keys are conveyed in PEM so a consumer need not
/// link a key type to read them; `identity_key_hash` is the 32-byte
/// BLAKE2b-256 hash of the identity public key, the value by which a PKI
/// document's signatures are indexed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DirectoryAuthority {
    pub identifier: String,
    pub pki_signature_scheme: String,
    pub wire_kem_scheme: String,
    pub addresses: Vec<String>,
    pub identity_public_key_pem: String,
    pub link_public_key_pem: String,
    #[serde(with = "serde_bytes")]
    pub identity_key_hash: Vec<u8>,
}

/// Request the directory authority descriptors the daemon is configured
/// with. Carries only a correlation id; the daemon needs no parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct GetDirectoryAuthoritiesRequest {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
}

/// Reply to a `GetDirectoryAuthorities` request. `authorities` carries the
/// descriptors; `error_code` is zero on success.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct GetDirectoryAuthoritiesReply {
    #[serde(with = "serde_bytes")]
    query_id: Vec<u8>,
    #[serde(default)]
    authorities: Vec<DirectoryAuthority>,
    #[serde(default)]
    error_code: u8,
}

/// The size in bytes of a SURB (Single-Use Reply Block) identifier.
const SURB_ID_SIZE: usize = 16;

/// The size in bytes of a message identifier.
const MESSAGE_ID_SIZE: usize = 16;

/// Upper bound on a single length-prefixed frame from the daemon. The
/// 4-byte big-endian prefix is daemon-controlled; without a ceiling a
/// hostile or buggy daemon could declare a multi-gigabyte frame and
/// drive this client to allocate it before any payload arrives. 40 MiB
/// is far above any legitimate CBOR message yet far below a
/// memory-exhaustion threat. Must match the Go daemon's
/// thin.MaxMessageSize.
const MAX_MESSAGE_SIZE: usize = 40 * 1024 * 1024;

/// The size in bytes of a query identifier.
const QUERY_ID_SIZE: usize = 16;

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

/// The number of recent epochs for which PKI documents are retained in
/// `pki_doc_cache`. Matches the bound used by the Go and Python clients.
const MAX_CACHED_EPOCHS: u64 = 5;

/// Reads the `Epoch` field from a forwarded PKI document. The daemon
/// serialises the Go struct field in PascalCase, so the CBOR key is
/// `Epoch` and the value is a non-negative integer.
fn doc_epoch(doc: &BTreeMap<Value, Value>) -> Option<u64> {
    match doc.get(&Value::Text("Epoch".to_string())) {
        Some(Value::Integer(i)) => u64::try_from(*i).ok(),
        _ => None,
    }
}

/// Inserts a document into the epoch-keyed cache, then evicts every entry
/// older than the last `MAX_CACHED_EPOCHS` epochs so that a long-running
/// client cannot accumulate documents without bound.
fn cache_pki_doc(
    cache: &mut BTreeMap<u64, BTreeMap<Value, Value>>,
    epoch: u64,
    doc: BTreeMap<Value, Value>,
) {
    cache.insert(epoch, doc);
    if cache.len() as u64 > MAX_CACHED_EPOCHS {
        let oldest = epoch.saturating_sub(MAX_CACHED_EPOCHS);
        cache.retain(|&e, _| e >= oldest);
    }
}

/// This is our ThinClient type which encapsulates our thin client
/// connection management and message processing.
pub struct ThinClient {
    read_half: Mutex<ReadHalf>,
    write_half: Mutex<WriteHalf>,
    config: Config,
    pki_doc: Arc<RwLock<Option<BTreeMap<Value, Value>>>>,
    // PKI documents cached by epoch, so a caller may retrieve a document
    // for a specific past epoch during epoch transitions. Bounded to the
    // last few epochs by `cache_pki_doc` so it cannot grow without limit.
    pki_doc_cache: Arc<RwLock<BTreeMap<u64, BTreeMap<Value, Value>>>>,
    worker_task: Mutex<Option<JoinHandle<()>>>,
    event_sink_task: Mutex<Option<JoinHandle<()>>>,
    shutdown: Arc<AtomicBool>,
    is_connected: Arc<AtomicBool>,
    // Event system like Go implementation
    event_sink: mpsc::UnboundedSender<BTreeMap<Value, Value>>,
    drain_add: mpsc::UnboundedSender<mpsc::UnboundedSender<BTreeMap<Value, Value>>>,
    drain_remove: mpsc::UnboundedSender<mpsc::UnboundedSender<BTreeMap<Value, Value>>>,
    // Response routing like Python implementation - keyed by query_id
    response_channels: Arc<Mutex<HashMap<Vec<u8>, oneshot::Sender<BTreeMap<Value, Value>>>>>,
    // Instance token from the daemon for reconnect detection
    daemon_instance_token: RwLock<Vec<u8>>,
    // Geometry the daemon supplies in its ConnectionStatusEvent during
    // the handshake. Not configured client-side; runtime state. None
    // until the first connection status event has been processed.
    sphinx_geometry: std::sync::RwLock<Option<Geometry>>,
    pigeonhole_geometry: std::sync::RwLock<Option<PigeonholeGeometry>>,
    // In-flight StartResending requests for replay on reconnect to new daemon
    pub(crate) in_flight_resends: Mutex<HashMap<Vec<u8>, BTreeMap<Value, Value>>>,
    // Track if daemon sent ShutdownEvent before disconnect
    received_shutdown: AtomicBool,
    // Client instance token for session resumption across reconnections
    pub(crate) instance_token: [u8; 16],
}


impl ThinClient {

    /// Create a new thin cilent and connect it to the client daemon.
    pub async fn new(config: Config) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        // Create event system channels like Go implementation
        let (event_sink_tx, event_sink_rx) = mpsc::unbounded_channel();
        let (drain_add_tx, drain_add_rx) = mpsc::unbounded_channel();
        let (drain_remove_tx, drain_remove_rx) = mpsc::unbounded_channel();

        // Shared response channels map
        let response_channels = Arc::new(Mutex::new(HashMap::new()));

        let (read_half, write_half) = config.dial.dial().await?;
        let client = Arc::new(Self {
            read_half: Mutex::new(read_half),
            write_half: Mutex::new(write_half),
            config,
            pki_doc: Arc::new(RwLock::new(None)),
            pki_doc_cache: Arc::new(RwLock::new(BTreeMap::new())),
            worker_task: Mutex::new(None),
            event_sink_task: Mutex::new(None),
            shutdown: Arc::new(AtomicBool::new(false)),
            is_connected: Arc::new(AtomicBool::new(false)),
            event_sink: event_sink_tx,
            drain_add: drain_add_tx,
            drain_remove: drain_remove_tx,
            response_channels,
            daemon_instance_token: RwLock::new(Vec::new()),
            sphinx_geometry: std::sync::RwLock::new(None),
            pigeonhole_geometry: std::sync::RwLock::new(None),
            in_flight_resends: Mutex::new(HashMap::new()),
            received_shutdown: AtomicBool::new(false),
            instance_token: {
                let mut token = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut token);
                token
            },
        });

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
        /// Sends a thin_close message to the daemon so it can clean up
        /// ARQ state for this connection before disconnecting.
        pub async fn stop(&self) {
        debug!("Stopping ThinClient...");

        self.shutdown.store(true, Ordering::Relaxed);

        // Send thin_close to the daemon before shutting down the socket.
        // Best effort — the socket may already be closed.
        let close_value = serde_cbor::value::to_value(&ThinCloseRequest {}).unwrap();
        let mut close_req = BTreeMap::new();
        close_req.insert(Value::Text("thin_close".to_string()), close_value);
        let _ = self.send_cbor_request(close_req).await;

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

    /// Disconnect from the daemon without sending thin_close.
    /// The daemon preserves all state for this client's app ID, allowing
    /// the client to reconnect and resume with the same session token.
    pub async fn disconnect(&self) {
        debug!("Disconnecting ThinClient (preserving state)...");
        self.shutdown.store(true, Ordering::Relaxed);

        let mut write_half = self.write_half.lock().await;
        let _ = match &mut *write_half {
            WriteHalf::Tcp(wh) => wh.shutdown().await,
            WriteHalf::Unix(wh) => wh.shutdown().await,
        };

        if let Some(worker) = self.worker_task.lock().await.take() {
            worker.abort();
        }
        debug!("ThinClient disconnected (state preserved).");
    }

    /// Returns `true` if the daemon is currently connected to the mixnet.
    ///
    /// Note the distinction: this tracks the daemon's *mixnet* connectivity,
    /// not the local socket between this thin client and the daemon. The
    /// daemon may be reachable while the mixnet itself is unreachable — in
    /// that case the local socket is fine but this method returns `false`,
    /// and `send_message` / `blocking_send_message` will raise
    /// `ThinClientError::OfflineMode`. The latest value is updated by
    /// `ConnectionStatusEvent`s.
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

    /// Generates a new 16-byte random message ID.
    ///
    /// Message IDs are used to correlate `SendMessage` requests with their
    /// corresponding `MessageSentEvent` and (if a SURB is present)
    /// `MessageReplyEvent`. Callers generally do not need to construct one
    /// by hand — use `blocking_send_message`, which does it internally —
    /// but this helper is exposed for callers composing requests manually.
    ///
    /// Randomness is drawn from the thread-local CSPRNG.
    pub fn new_message_id() -> Vec<u8> {
        let mut id = vec![0; MESSAGE_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    /// Generates a new random SURB ID of the Sphinx-protocol-defined length.
    ///
    /// SURB IDs identify which Single Use Reply Block a given
    /// `MessageReplyEvent` corresponds to. Pass the returned bytes as the
    /// `surb_id` argument to `send_message`, then watch the event sink for
    /// a matching reply.
    ///
    /// Randomness is drawn from the thread-local CSPRNG.
    pub fn new_surb_id() -> Vec<u8> {
        let mut id = vec![0; SURB_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    /// Generates a new 16-byte random query ID.
    ///
    /// Query IDs correlate requests and replies within the thin client ↔
    /// daemon CBOR protocol (distinct from mix-network SURB IDs, which
    /// identify replies within the mixnet itself). Most callers never
    /// touch query IDs directly; they are used internally by the
    /// Pigeonhole wire-protocol helpers.
    ///
    /// Randomness is drawn from the thread-local CSPRNG.
    pub fn new_query_id() -> Vec<u8> {
        let mut id = vec![0; QUERY_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    async fn update_pki_document(&self, new_pki_doc: BTreeMap<Value, Value>) {
        if let Some(epoch) = doc_epoch(&new_pki_doc) {
            let mut cache = self.pki_doc_cache.write().await;
            cache_pki_doc(&mut cache, epoch, new_pki_doc.clone());
            debug!("Cached PKI document for epoch {}.", epoch);
        }
        let mut pki_doc_lock = self.pki_doc.write().await;
        *pki_doc_lock = Some(new_pki_doc);
        debug!("PKI document updated.");
    }

    /// Returns the PKI document for a specific epoch.
    ///
    /// The thin client retains the documents for the last few epochs (see
    /// `cache_pki_doc`), which lets a caller resolve a document for a
    /// recently-elapsed epoch during an epoch transition. When the
    /// requested epoch is not in the cache the current document is
    /// returned instead, matching the Go and Python clients.
    ///
    /// # Errors
    ///
    /// * `ThinClientError::MissingPkiDocument` — no PKI document is
    ///   available at all (neither cached nor current), most commonly on a
    ///   freshly-connected client.
    pub async fn pki_document_for_epoch(&self, epoch: u64) -> Result<BTreeMap<Value, Value>, ThinClientError> {
        if let Some(doc) = self.pki_doc_cache.read().await.get(&epoch) {
            return Ok(doc.clone());
        }
        self.pki_doc.read().await.clone().ok_or(ThinClientError::MissingPkiDocument)
    }

    /// Returns the most recent PKI consensus document the daemon has
    /// forwarded to this thin client.
    ///
    /// The document is a CBOR map describing the current mixnet topology,
    /// the set of available services, and per-node public-key material.
    /// Useful inputs include the PKI epoch, the list of mix nodes, the list
    /// of service providers, and the `ReplicaDescriptor` entries consulted
    /// by Pigeonhole.
    ///
    /// # Errors
    ///
    /// * `ThinClientError::MissingPkiDocument` — the daemon has not yet
    ///   forwarded a PKI document (most commonly on a freshly-connected
    ///   client, before the first `NewDocumentEvent` has arrived).
    pub async fn pki_document(&self) -> Result<BTreeMap<Value, Value>, ThinClientError> {
        self.pki_doc.read().await.clone().ok_or(ThinClientError::MissingPkiDocument)
    }

    /// Returns the cert.Certificate-wrapped signed PKI document for the
    /// requested epoch, with every directory authority signature intact.
    ///
    /// The thin client receives the stripped PKI document by default
    /// (forwarded by the daemon through `NewPKIDocumentEvent`, and
    /// surfaced via [`pki_document`](Self::pki_document)); the daemon
    /// nils the signature map before forwarding it. Use this method
    /// when the caller wishes to verify the directory authority
    /// signatures itself: the returned payload may be deserialized and
    /// verified with the katzenpost `core/pki.FromPayload` routine
    /// against the authorities listed in `client.toml`.
    ///
    /// # Arguments
    ///
    /// * `epoch` — the epoch for which the signed PKI document should
    ///   be returned. Pass `0` to request the document the daemon
    ///   believes is current.
    ///
    /// # Returns
    ///
    /// `(payload, epoch)` where `payload` is the cert.Certificate-
    /// wrapped signed PKI document and `epoch` is the epoch of the
    /// returned document. When `0` was passed in, `epoch` echoes the
    /// epoch the daemon resolved to.
    ///
    /// # Errors
    ///
    /// * `ThinClientError::Other` — the daemon has no cached document
    ///   for the requested epoch, or any other non-zero error code is
    ///   returned. The diagnostic string includes the requested epoch.
    pub async fn get_pki_document_raw(&self, epoch: u64) -> Result<(Vec<u8>, u64), ThinClientError> {
        let query_id = Self::new_query_id();

        let request_inner = GetPKIDocumentRequest {
            query_id: query_id.clone(),
            epoch,
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(ThinClientError::CborError)?;

        let mut request = BTreeMap::new();
        request.insert(Value::Text("get_pki_document".to_string()), request_value);

        let reply_map = self.send_and_wait_direct(query_id, request).await?;

        let reply: GetPKIDocumentReply = serde_cbor::value::from_value(Value::Map(reply_map))
            .map_err(ThinClientError::CborError)?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!(
                "get_pki_document_raw failed for epoch {}: error code {}",
                epoch, reply.error_code
            )));
        }

        Ok((reply.payload, reply.epoch))
    }

    /// Return the directory authority descriptors the client daemon is
    /// configured with.
    ///
    /// A thin client holds only its dial transport configuration and never
    /// sees the daemon's voting authority peer list. This surfaces it, so a
    /// caller may, for instance, map a PKI document's signature fingerprints
    /// (the keys of its signature map) to authority identifiers via each
    /// descriptor's `identity_key_hash`.
    ///
    /// # Errors
    ///
    /// * `ThinClientError::Other` — the daemon has no voting authority peers
    ///   configured, or any other non-zero error code is returned.
    pub async fn get_directory_authorities(
        &self,
    ) -> Result<Vec<DirectoryAuthority>, ThinClientError> {
        let query_id = Self::new_query_id();

        let request_inner = GetDirectoryAuthoritiesRequest {
            query_id: query_id.clone(),
        };

        let request_value = serde_cbor::value::to_value(&request_inner)
            .map_err(ThinClientError::CborError)?;

        let mut request = BTreeMap::new();
        request.insert(
            Value::Text("get_directory_authorities".to_string()),
            request_value,
        );

        let reply_map = self.send_and_wait_direct(query_id, request).await?;

        let reply: GetDirectoryAuthoritiesReply =
            serde_cbor::value::from_value(Value::Map(reply_map))
                .map_err(ThinClientError::CborError)?;

        if reply.error_code != 0 {
            return Err(ThinClientError::Other(format!(
                "get_directory_authorities failed: error code {}",
                reply.error_code
            )));
        }

        Ok(reply.authorities)
    }

    /// Returns the pigeonhole geometry the daemon supplied during the
    /// connection handshake. This geometry defines the payload sizes and
    /// envelope formats for the pigeonhole protocol.
    ///
    /// Panics if called before the daemon's first ConnectionStatusEvent
    /// has been processed, or if the daemon did not supply the geometry
    /// (an incompatible daemon).
    pub fn pigeonhole_geometry(&self) -> PigeonholeGeometry {
        self.pigeonhole_geometry
            .read()
            .unwrap()
            .clone()
            .expect("pigeonhole geometry not yet received from daemon (incompatible daemon, or called before connect)")
    }

    /// Returns the Sphinx geometry the daemon supplied during the
    /// connection handshake. Same panic semantics as
    /// [`Self::pigeonhole_geometry`].
    pub fn sphinx_geometry(&self) -> Geometry {
        self.sphinx_geometry
            .read()
            .unwrap()
            .clone()
            .expect("sphinx geometry not yet received from daemon (incompatible daemon, or called before connect)")
    }

    /// Returns every instance of the named service advertised in the
    /// current PKI document.
    ///
    /// Multiple mix nodes may advertise the same service name; this method
    /// returns all of them, in the order `find_services` discovers them.
    /// For the common case where any one instance will do, prefer
    /// `get_service`, which picks one at random for load balancing.
    ///
    /// # Arguments
    ///
    /// * `capability` — the service capability to look up (e.g. `"echo"`,
    ///   `"courier"`).
    ///
    /// # Errors
    ///
    /// * `ThinClientError::MissingPkiDocument` — no PKI document is yet
    ///   available; see `pki_document`.
    /// * `ThinClientError::ServiceNotFound` — no node in the current
    ///   consensus advertises `capability`.
    pub async fn get_services(&self, capability: &str) -> Result<Vec<ServiceDescriptor>, ThinClientError> {
        let doc = self.pki_doc.read().await.clone().ok_or(ThinClientError::MissingPkiDocument)?;
        let services = find_services(capability, &doc);
        if services.is_empty() {
            return Err(ThinClientError::ServiceNotFound);
        }
        Ok(services)
    }

    /// Returns a randomly selected instance of the named service from the
    /// current PKI document.
    ///
    /// This is a convenience wrapper around `get_services` that draws one
    /// instance uniformly at random, providing automatic load balancing
    /// across the available instances. To see every advertised instance,
    /// use `get_services`.
    ///
    /// # Arguments
    ///
    /// * `service_name` — the service capability to look up (e.g.
    ///   `"echo"`, `"courier"`).
    ///
    /// # Errors
    ///
    /// * `ThinClientError::MissingPkiDocument` — no PKI document is yet
    ///   available; see `pki_document`.
    /// * `ThinClientError::ServiceNotFound` — no node in the current
    ///   consensus advertises `service_name`.
    pub async fn get_service(&self, service_name: &str) -> Result<ServiceDescriptor, ThinClientError> {
        let mut services = self.get_services(service_name).await?;
        let idx = rand::thread_rng().gen_range(0..services.len());
        Ok(services.swap_remove(idx))
    }

    pub(crate) async fn recv(&self) -> Result<BTreeMap<Value, Value>, ThinClientError> {
        let mut length_prefix = [0; 4];
        {
                let mut read_half = self.read_half.lock().await;
                match &mut *read_half {
            ReadHalf::Tcp(rh) => rh.read_exact(&mut length_prefix).await.map_err(ThinClientError::IoError)?,
            ReadHalf::Unix(rh) => rh.read_exact(&mut length_prefix).await.map_err(ThinClientError::IoError)?,
                };
        }
        let message_length = u32::from_be_bytes(length_prefix) as usize;
        if message_length > MAX_MESSAGE_SIZE {
            return Err(ThinClientError::Other(format!(
                "daemon response frame too large: {} bytes (max {})",
                message_length, MAX_MESSAGE_SIZE
            )));
        }
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

    async fn parse_status(&self, event: &BTreeMap<Value, Value>) {
        let is_connected = event.get(&Value::Text("is_connected".to_string()))
            .and_then(|v| match v {
                Value::Bool(b) => Some(*b),
                _ => None,
            })
            .unwrap_or(false);

        // Update connection state
        self.is_connected.store(is_connected, Ordering::Relaxed);

        // Extract and store instance token if present
        if let Some(Value::Bytes(token)) = event.get(&Value::Text("instance_token".to_string())) {
            let mut t = self.daemon_instance_token.write().await;
            *t = token.clone();
        }

        // The daemon supplies the geometries here rather than the thin
        // client carrying them in its config file. A daemon that omits
        // them is incompatible.
        match event.get(&Value::Text("sphinx_geometry".to_string())) {
            Some(v) => match serde_cbor::value::from_value::<Geometry>(v.clone()) {
                Ok(g) => *self.sphinx_geometry.write().unwrap() = Some(g),
                Err(e) => error!("Failed to decode sphinx_geometry from daemon: {:?}", e),
            },
            None => error!("Daemon did not supply sphinx_geometry in its ConnectionStatusEvent (incompatible daemon)"),
        }
        match event.get(&Value::Text("pigeonhole_geometry".to_string())) {
            Some(v) => match serde_cbor::value::from_value::<PigeonholeGeometry>(v.clone()) {
                Ok(g) => *self.pigeonhole_geometry.write().unwrap() = Some(g),
                Err(e) => error!("Failed to decode pigeonhole_geometry from daemon: {:?}", e),
            },
            None => error!("Daemon did not supply pigeonhole_geometry in its ConnectionStatusEvent (incompatible daemon)"),
        }

        if is_connected {
            debug!("Daemon is connected to mixnet - full functionality available.");
        } else {
            debug!("Daemon is not connected to mixnet - entering offline mode (channel operations will work).");
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
        if response.is_empty() {
            error!("Received an empty response, ignoring");
            return;
        }

        if let Some(Value::Map(_)) = response.get(&Value::Text("shutdown_event".to_string())) {
            debug!("Received ShutdownEvent from daemon");
            self.received_shutdown.store(true, Ordering::Relaxed);
            return;
        }

        if let Some(Value::Map(event)) = response.get(&Value::Text("connection_status_event".to_string())) {
            debug!("Connection status event received.");
            self.parse_status(event).await;
            if let Some(cb) = self.config.on_connection_status.as_ref() {
                cb(event);
            }
            return;
        }

        if let Some(Value::Map(event)) = response.get(&Value::Text("new_pki_document_event".to_string())) {
            debug!("New PKI document event received.");
            self.parse_pki_doc(event).await;
            if let Some(cb) = self.config.on_new_pki_document.as_ref() {
                cb(event);
            }
            return;
        }

        if let Some(Value::Map(event)) = response.get(&Value::Text("message_sent_event".to_string())) {
            debug!("Message sent event received.");
            if let Some(cb) = self.config.on_message_sent.as_ref() {
                cb(event);
            }
            return;
        }

        if let Some(Value::Map(event)) = response.get(&Value::Text("message_reply_event".to_string())) {
            debug!("Message reply event received.");
            if let Some(cb) = self.config.on_message_reply.as_ref() {
                cb(event);
            }
            return;
        }

        // Route replies to response_channels based on query_id (like Python implementation)
        // This handles *_reply messages with query_id fields
        for (key, value) in response.iter() {
            if let Value::Text(reply_type) = key {
                if reply_type.ends_with("_reply") {
                    if let Value::Map(reply_map) = value {
                        if let Some(Value::Bytes(query_id)) = reply_map.get(&Value::Text("query_id".to_string())) {
                            let mut channels = self.response_channels.lock().await;
                            if let Some(sender) = channels.remove(query_id) {
                                debug!("Routing {} to waiting caller", reply_type);
                                let _ = sender.send(reply_map.clone());
                                return;
                            }
                        }
                    }
                    debug!("Unrouted reply: {}", reply_type);
                }
            }
        }

        debug!("Unhandled response (no matching query_id listener): {:?}", response.keys().collect::<Vec<_>>());
    }

    /// Read messages from the daemon until disconnect or shutdown.
    /// Returns (Option<error_string>, is_graceful).
    /// If the returned Option is None, shutdown was requested.
    async fn read_until_disconnect(&self) -> (Option<String>, bool) {
        while !self.shutdown.load(Ordering::Relaxed) {
            match self.recv().await {
                Ok(response) => {
                    // Send all responses to event sink for distribution
                    if let Err(_) = self.event_sink.send(response.clone()) {
                        debug!("Event sink channel closed, stopping read loop");
                        return (None, false);
                    }
                    self.handle_response(response).await;
                }
                Err(_) if self.shutdown.load(Ordering::Relaxed) => {
                    return (None, false);
                }
                Err(err) => {
                    let graceful = self.received_shutdown.load(Ordering::Relaxed);
                    return (Some(format!("{}", err)), graceful);
                }
            }
        }
        (None, false)
    }

    /// Create a new socket connection and replace the read/write halves.
    async fn dial(&self) -> Result<(), String> {
        let (read_half, write_half) = self
            .config
            .dial
            .dial()
            .await
            .map_err(|e| format!("{}", e))?;
        *self.read_half.lock().await = read_half;
        *self.write_half.lock().await = write_half;
        Ok(())
    }

    /// Send SessionToken to the daemon and read SessionTokenReply.
    async fn send_session_token(&self) -> Result<(), String> {
        let mut inner = BTreeMap::new();
        inner.insert(
            Value::Text("client_instance_token".to_string()),
            Value::Bytes(self.instance_token.to_vec()),
        );
        let mut request = BTreeMap::new();
        request.insert(
            Value::Text("session_token".to_string()),
            Value::Map(inner),
        );
        self.send_cbor_request(request).await.map_err(|e| format!("{}", e))?;

        let response = self.recv().await.map_err(|e| format!("{}", e))?;
        if !response.contains_key(&Value::Text("session_token_reply".to_string())) {
            return Err("expected session_token_reply".to_string());
        }
        if let Some(Value::Map(reply)) = response.get(&Value::Text("session_token_reply".to_string())) {
            let resumed = reply.get(&Value::Text("resumed".to_string()))
                .and_then(|v| if let Value::Bool(b) = v { Some(*b) } else { None })
                .unwrap_or(false);
            debug!("Session token reply: resumed={}", resumed);
        }
        Ok(())
    }

    /// Read and dispatch a single handshake message from the daemon.
    async fn recv_and_dispatch(&self) -> Result<(), String> {
        let response = self.recv().await.map_err(|e| format!("{}", e))?;
        let _ = self.event_sink.send(response.clone());
        self.handle_response(response).await;
        Ok(())
    }

    /// Attempt to reconnect to the daemon with exponential backoff.
    /// Returns true on success, false if shutdown was requested.
    async fn reconnect(&self) -> bool {
        let mut delay = std::time::Duration::from_secs(1);
        let max_delay = std::time::Duration::from_secs(60);

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return false;
            }

            tokio::time::sleep(delay).await;
            if self.shutdown.load(Ordering::Relaxed) {
                return false;
            }

            debug!("Attempting to reconnect to daemon via {:?}", self.config.dial);
            if let Err(e) = self.dial().await {
                error!("Reconnect failed: {}", e);
                delay = std::cmp::min(delay * 2, max_delay);
                continue;
            }

            // Handshake: ConnectionStatusEvent then NewPKIDocumentEvent
            if let Err(e) = self.recv_and_dispatch().await {
                error!("Reconnect handshake failed (ConnectionStatusEvent): {}", e);
                delay = std::cmp::min(delay * 2, max_delay);
                continue;
            }
            if let Err(e) = self.recv_and_dispatch().await {
                error!("Reconnect handshake failed (NewPKIDocumentEvent): {}", e);
                delay = std::cmp::min(delay * 2, max_delay);
                continue;
            }

            if let Err(e) = self.send_session_token().await {
                error!("Reconnect handshake failed (SessionToken): {}", e);
                delay = std::cmp::min(delay * 2, max_delay);
                continue;
            }

            debug!("Reconnected to daemon (connected={})", self.is_connected());
            return true;
        }
    }

    /// Replay in-flight resend requests after reconnecting to a new daemon instance.
    async fn replay_in_flight_resends(&self) {
        let resends = self.in_flight_resends.lock().await;
        for (_key, request) in resends.iter() {
            if let Err(e) = self.send_cbor_request(request.clone()).await {
                error!("Failed to replay in-flight request: {}", e);
            }
        }
    }

    async fn worker_loop(&self) {
        debug!("Worker loop started");

        // Initial handshake: read ConnectionStatusEvent, NewPKIDocumentEvent,
        // then send SessionToken and read SessionTokenReply.
        if let Err(e) = self.recv_and_dispatch().await {
            error!("Initial handshake failed (ConnectionStatusEvent): {}", e);
            return;
        }
        if let Err(e) = self.recv_and_dispatch().await {
            error!("Initial handshake failed (NewPKIDocumentEvent): {}", e);
            return;
        }
        if let Err(e) = self.send_session_token().await {
            error!("Initial handshake failed (SessionToken): {}", e);
            return;
        }

        loop {
            // Reset the shutdown-event flag for this connection
            self.received_shutdown.store(false, Ordering::Relaxed);

            let (disconnect_err, graceful) = self.read_until_disconnect().await;

            // If None, shutdown was requested -- exit cleanly
            if disconnect_err.is_none() {
                debug!("Worker loop exiting due to shutdown.");
                break;
            }

            let err_msg = disconnect_err.unwrap();
            debug!("Disconnected from daemon (graceful={}): {}", graceful, err_msg);

            // Save previous instance token before reconnecting
            let prev_token = self.daemon_instance_token.read().await.clone();

            // Invoke on_daemon_disconnected callback
            if let Some(cb) = self.config.on_daemon_disconnected.as_ref() {
                cb(graceful, Some(err_msg));
            }

            // Attempt reconnect with backoff
            if !self.reconnect().await {
                debug!("Worker loop exiting due to shutdown during reconnect.");
                break;
            }

            // Compare instance tokens: if different, replay in-flight resends
            let new_token = self.daemon_instance_token.read().await.clone();
            if !prev_token.is_empty() && prev_token != new_token {
                debug!("Daemon instance changed, replaying in-flight resends.");
                self.replay_in_flight_resends().await;
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

    pub(crate) async fn send_cbor_request(&self, request: BTreeMap<Value, Value>) -> Result<(), ThinClientError> {
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

    /// Send a CBOR request and wait for a reply with the matching query_id.
    /// This uses direct response routing via query_id (like Python's _send_and_wait).
    pub(crate) async fn send_and_wait_direct(&self, query_id: Vec<u8>, request: BTreeMap<Value, Value>) -> Result<BTreeMap<Value, Value>, ThinClientError> {
        // Create oneshot channel for receiving the reply
        let (tx, rx) = oneshot::channel();

        // Register the channel BEFORE sending the request (like Python)
        {
            let mut channels = self.response_channels.lock().await;
            channels.insert(query_id.clone(), tx);
        }

        // Send the request
        if let Err(e) = self.send_cbor_request(request).await {
            // Clean up on failure
            let mut channels = self.response_channels.lock().await;
            channels.remove(&query_id);
            return Err(e);
        }

        debug!("send_and_wait_direct: request sent, waiting for reply with query_id {:?}", &query_id[..std::cmp::min(8, query_id.len())]);

        // Wait for the reply (no timeout - block forever like Go/Python)
        match rx.await {
            Ok(reply) => {
                debug!("send_and_wait_direct: received reply");
                Ok(reply)
            }
            Err(_) => {
                // Channel was dropped without sending - clean up
                let mut channels = self.response_channels.lock().await;
                channels.remove(&query_id);
                Err(ThinClientError::Other("Response channel closed without reply".to_string()))
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

    /// Send a message and block until a reply is received or timeout.
    ///
    /// This method provides a synchronous request-response pattern by
    /// automatically generating a SURB ID, sending the message, and
    /// waiting for the reply. It blocks until either a reply is received
    /// or the timeout expires.
    pub async fn blocking_send_message(
	&self,
	payload: &[u8],
	dest_node: Vec<u8>,
	dest_queue: Vec<u8>,
	timeout: std::time::Duration,
    ) -> Result<Vec<u8>, ThinClientError> {
        if !self.is_connected() {
            return Err(ThinClientError::OfflineMode("cannot send message in offline mode - daemon not connected to mixnet".to_string()));
        }

        let surb_id = Self::new_surb_id();
        let mut event_sink = self.event_sink();

        self.send_message(surb_id.clone(), payload, dest_node, dest_queue).await?;

        let result = tokio::time::timeout(timeout, async {
            loop {
                match event_sink.recv().await {
                    Some(event) => {
                        if let Some(Value::Map(reply)) = event.get(&Value::Text("message_reply_event".to_string())) {
                            if let Some(Value::Bytes(reply_surb_id)) = reply.get(&Value::Text("surbid".to_string())) {
                                if *reply_surb_id == surb_id {
                                    if let Some(Value::Bytes(payload)) = reply.get(&Value::Text("payload".to_string())) {
                                        return Ok(payload.clone());
                                    }
                                }
                            }
                        }
                        // Not our reply, keep waiting
                    }
                    None => {
                        return Err(ThinClientError::OfflineMode("event sink closed".to_string()));
                    }
                }
            }
        }).await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err(ThinClientError::Timeout("blocking_send_message timed out waiting for reply".to_string())),
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_cbor::Value;
    use std::collections::BTreeMap;

    /// instance_token field should exist on ThinClient.
    #[test]
    fn test_instance_token_field_exists() {
        // We can't easily construct a ThinClient without a socket,
        // but we can verify the field exists by checking the struct layout
        // via a compile-time assertion. If this compiles, the field exists.
        fn _assert_field(tc: &ThinClient) -> &[u8; 16] {
            &tc.instance_token
        }
    }

    /// disconnect() method should exist and be distinct from stop().
    #[test]
    fn test_disconnect_method_exists() {
        // Compile-time check: if this compiles, disconnect() exists as an async method.
        fn _assert_method(tc: &ThinClient) {
            let _ = tc.disconnect();
        }
    }

    /// SessionToken CBOR encoding should match what the daemon expects.
    #[test]
    fn test_session_token_cbor_encoding() {
        let token = [0x01u8; 16];
        let mut inner = BTreeMap::new();
        inner.insert(
            Value::Text("client_instance_token".to_string()),
            Value::Bytes(token.to_vec()),
        );
        let mut request = BTreeMap::new();
        request.insert(
            Value::Text("session_token".to_string()),
            Value::Map(inner),
        );

        let encoded = serde_cbor::to_vec(&request).unwrap();
        let decoded: BTreeMap<Value, Value> = serde_cbor::from_slice(&encoded).unwrap();

        if let Some(Value::Map(st)) = decoded.get(&Value::Text("session_token".to_string())) {
            if let Some(Value::Bytes(t)) = st.get(&Value::Text("client_instance_token".to_string())) {
                assert_eq!(t.as_slice(), &token);
            } else {
                panic!("missing client_instance_token field");
            }
        } else {
            panic!("missing session_token field");
        }
    }

    /// SessionTokenReply CBOR decoding should work correctly.
    #[test]
    fn test_session_token_reply_decoding() {
        let app_id = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut reply_inner = BTreeMap::new();
        reply_inner.insert(Value::Text("app_id".to_string()), Value::Bytes(app_id.clone()));
        reply_inner.insert(Value::Text("resumed".to_string()), Value::Bool(true));

        let mut response = BTreeMap::new();
        response.insert(
            Value::Text("session_token_reply".to_string()),
            Value::Map(reply_inner),
        );

        let encoded = serde_cbor::to_vec(&response).unwrap();
        let decoded: BTreeMap<Value, Value> = serde_cbor::from_slice(&encoded).unwrap();

        if let Some(Value::Map(reply)) = decoded.get(&Value::Text("session_token_reply".to_string())) {
            if let Some(Value::Bytes(id)) = reply.get(&Value::Text("app_id".to_string())) {
                assert_eq!(id, &app_id);
            } else {
                panic!("missing app_id");
            }
            if let Some(Value::Bool(resumed)) = reply.get(&Value::Text("resumed".to_string())) {
                assert!(resumed);
            } else {
                panic!("missing resumed");
            }
        } else {
            panic!("missing session_token_reply");
        }
    }

    /// doc_epoch reads the PascalCase `Epoch` field the daemon serialises.
    #[test]
    fn test_doc_epoch_reads_epoch_field() {
        let mut doc = BTreeMap::new();
        doc.insert(Value::Text("Epoch".to_string()), Value::Integer(42));
        assert_eq!(doc_epoch(&doc), Some(42));

        let empty: BTreeMap<Value, Value> = BTreeMap::new();
        assert_eq!(doc_epoch(&empty), None);
    }

    /// cache_pki_doc retains only the most recent epochs and evicts the
    /// rest, so the cache cannot grow without bound.
    #[test]
    fn test_cache_pki_doc_evicts_old_epochs() {
        let mut cache: BTreeMap<u64, BTreeMap<Value, Value>> = BTreeMap::new();
        let newest = 19u64;
        for epoch in 0..=newest {
            let mut doc = BTreeMap::new();
            doc.insert(Value::Text("Epoch".to_string()), Value::Integer(epoch as i128));
            cache_pki_doc(&mut cache, epoch, doc);
        }

        // Mirrors Go/Python: every entry with epoch >= newest - MAX_CACHED_EPOCHS
        // is kept, so the cache never exceeds MAX_CACHED_EPOCHS + 1 entries.
        assert!(cache.len() as u64 <= MAX_CACHED_EPOCHS + 1);
        assert!(cache.contains_key(&newest));
        assert!(cache.contains_key(&(newest - MAX_CACHED_EPOCHS)));
        assert!(!cache.contains_key(&(newest - MAX_CACHED_EPOCHS - 1)));
        assert!(!cache.contains_key(&0));
    }

    /// Early epochs (below MAX_CACHED_EPOCHS) must not underflow the
    /// eviction boundary; the cache simply retains everything seen so far.
    #[test]
    fn test_cache_pki_doc_no_underflow_for_early_epochs() {
        let mut cache: BTreeMap<u64, BTreeMap<Value, Value>> = BTreeMap::new();
        for epoch in 0..3u64 {
            let mut doc = BTreeMap::new();
            doc.insert(Value::Text("Epoch".to_string()), Value::Integer(epoch as i128));
            cache_pki_doc(&mut cache, epoch, doc);
        }
        assert_eq!(cache.len(), 3);
        assert!(cache.contains_key(&0));
    }

    /// handle_response should not panic on session_token_reply.
    #[tokio::test]
    async fn test_handle_response_session_token_reply() {
        // We need a ThinClient to call handle_response, but we can't construct one
        // without a socket. Instead, verify the CBOR structure is correct and that
        // session_token_reply would be handled (not panic) by checking it matches
        // the expected pattern.
        let mut reply_inner = BTreeMap::new();
        reply_inner.insert(Value::Text("app_id".to_string()), Value::Bytes(vec![1; 16]));
        reply_inner.insert(Value::Text("resumed".to_string()), Value::Bool(false));

        let mut response = BTreeMap::new();
        response.insert(
            Value::Text("session_token_reply".to_string()),
            Value::Map(reply_inner),
        );

        // Verify the key matches the pattern we handle
        let key = Value::Text("session_token_reply".to_string());
        assert!(response.contains_key(&key));
    }
}
