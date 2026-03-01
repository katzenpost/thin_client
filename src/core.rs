// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! This module provides the main ThinClient struct and core functionality for
//! connecting to the client daemon, managing events, and sending messages.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration;

use serde_cbor::{from_slice, Value};

use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::task::JoinHandle;
use tokio::net::{TcpStream, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf as TcpReadHalf, OwnedWriteHalf as TcpWriteHalf};
use tokio::net::unix::{OwnedReadHalf as UnixReadHalf, OwnedWriteHalf as UnixWriteHalf};

use rand::RngCore;
use log::{debug, error};

use crate::error::ThinClientError;
use crate::{Config, ServiceDescriptor, PigeonholeGeometry};
use crate::helpers::find_services;

/// The size in bytes of a SURB (Single-Use Reply Block) identifier.
const SURB_ID_SIZE: usize = 16;

/// The size in bytes of a message identifier.
const MESSAGE_ID_SIZE: usize = 16;

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

    /// Returns the pigeonhole geometry from the config.
    /// This geometry defines the payload sizes and envelope formats for the pigeonhole protocol.
    pub fn pigeonhole_geometry(&self) -> &PigeonholeGeometry {
        &self.config.pigeonhole_geometry
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


    /// Send a CBOR request and wait for a reply with the matching query_id
    pub(crate) async fn send_and_wait(&self, query_id: &[u8], request: BTreeMap<Value, Value>) -> Result<BTreeMap<Value, Value>, ThinClientError> {
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
                        "start_resending_copy_command_reply",
                        "cancel_resending_copy_command_reply",
                        "create_courier_envelopes_from_payload_reply",
                        "create_courier_envelopes_from_payloads_reply",
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
}
