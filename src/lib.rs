// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

pub mod error;

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::net::UnixStream;
use tokio::sync::{Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task;

use serde_cbor::{from_slice, to_vec, Value};
use blake2::{Blake2b, Digest};
use generic_array::typenum::U32;
use rand::RngCore;
use log::{debug, info, error};

use crate::error::ThinClientError;

// Constants
const SURB_ID_SIZE: usize = 16;
const MESSAGE_ID_SIZE: usize = 16;
const DAEMON_SOCKET: &str = "\0katzenpost";

#[derive(Debug, Clone)]
pub struct ServiceDescriptor {
    pub recipient_queue_id: Vec<u8>,
    pub mix_descriptor: BTreeMap<Value, Value>,
}

impl ServiceDescriptor {
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

#[derive(Clone)]
pub struct Config {
    pub on_connection_status: Option<Arc<dyn Fn(&BTreeMap<Value, Value>) + Send + Sync>>,
    pub on_new_pki_document: Option<Arc<dyn Fn(&BTreeMap<Value, Value>) + Send + Sync>>,
    pub on_message_sent: Option<Arc<dyn Fn(&BTreeMap<Value, Value>) + Send + Sync>>,
    pub on_message_reply: Option<Arc<dyn Fn(&BTreeMap<Value, Value>) + Send + Sync>>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            on_connection_status: None,
            on_new_pki_document: None,
            on_message_sent: None,
            on_message_reply: None,
        }
    }
}

pub struct ThinClient {
    socket: Arc<Mutex<UnixStream>>,
    config: Config,
    pki_doc: Arc<RwLock<Option<BTreeMap<Value, Value>>>>,
}

impl ThinClient {

    pub async fn new(config: Config) -> Result<Arc<Self>, ThinClientError> {
	let mut client_id = [0u8; 16];
	rand::thread_rng().fill_bytes(&mut client_id);
	let abstract_name = format!("\0katzenpost_rust_thin_client_{:x?}", client_id);

	debug!("Binding to abstract Unix socket: {}", abstract_name);

	let socket = UnixStream::connect(DAEMON_SOCKET).await.map_err(ThinClientError::IoError)?;
	let client = Arc::new(Self {
            socket: Arc::new(Mutex::new(socket)),
            config,
            pki_doc: Arc::new(RwLock::new(None)),
	});

	let client_clone = Arc::clone(&client);  // ✅ Clone before moving into `start`
	client_clone.start().await;              // ✅ Calls `start` without moving `client`

	Ok(client)
    }
    
    /// Starts the ThinClient, connects to the daemon, and processes initial responses.
    pub async fn start(self: Arc<Self>) {
        debug!("Connecting to daemon at: {}", DAEMON_SOCKET);

        let mut socket = self.socket.lock().await;
        match UnixStream::connect(DAEMON_SOCKET).await {
            Ok(new_socket) => {
                *socket = new_socket;
                debug!("Connected to daemon.");
            }
            Err(err) => {
                error!("Failed to connect to daemon: {}", err);
                return;
            }
        }

        debug!("Waiting for initial daemon responses...");

        // Expect first message: connection status event
        if let Ok(response) = self.recv().await {
            if response.contains_key(&Value::Text("connection_status_event".to_string())) {
                self.handle_response(response).await;
            } else {
                error!("Expected connection status event, but received something else.");
            }
        }

        // Expect second message: PKI document event
        if let Ok(response) = self.recv().await {
            if response.contains_key(&Value::Text("new_pki_document_event".to_string())) {
                self.handle_response(response).await;
            } else {
                error!("Expected PKI document event, but received something else.");
            }
        }

        debug!("Starting background worker loop");
        let client = Arc::clone(&self);
        task::spawn(async move {
            client.worker_loop().await;
        });
    }
    
    pub async fn stop(&self) {
        let mut socket = self.socket.lock().await;
        let _ = socket.shutdown().await;
        debug!("Connection closed.");
    }

    pub fn new_message_id() -> Vec<u8> {
        let mut id = vec![0; MESSAGE_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    pub fn new_surb_id() -> Vec<u8> {
        let mut id = vec![0; SURB_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    pub async fn update_pki_document(&self, new_pki_doc: BTreeMap<Value, Value>) {
        let mut pki_doc_lock = self.pki_doc.write().await;
        *pki_doc_lock = Some(new_pki_doc);
        debug!("PKI document updated.");
    }

    pub async fn get_service(&self, service_name: &str) -> Result<ServiceDescriptor, ThinClientError> {
        let doc = self.pki_doc.read().await.clone().ok_or(ThinClientError::MissingPkiDocument)?;
        let services = find_services(service_name, &doc);
        services.into_iter().next().ok_or(ThinClientError::ServiceNotFound)
    }

    pub async fn recv(&self) -> Result<BTreeMap<Value, Value>, ThinClientError> {
        let mut socket = self.socket.lock().await;
        let mut length_prefix = [0; 4];
        socket.read_exact(&mut length_prefix).await?;
        let message_length = u32::from_be_bytes(length_prefix) as usize;

        let mut buffer = vec![0; message_length];
        socket.read_exact(&mut buffer).await?;

        let response: BTreeMap<Value, Value> = from_slice(&buffer)?;
        Ok(response)
    }

    pub async fn handle_response(&self, response: BTreeMap<Value, Value>) {
        for (event_name, event) in response {
            let Value::Text(event_name_str) = event_name else {
                continue;
            };

            let Value::Map(event_data) = event else {
                continue;
            };

            if event_name_str == "new_pki_document_event" {
                self.update_pki_document(event_data.clone()).await;
            }

            let callback = match event_name_str.as_str() {
                "connection_status_event" => &self.config.on_connection_status,
                "new_pki_document_event" => &self.config.on_new_pki_document,
                "message_sent_event" => &self.config.on_message_sent,
                "message_reply_event" => &self.config.on_message_reply,
                _ => {
                    error!("Unknown event type: {}", event_name_str);
                    continue;
                }
            };

            if let Some(cb) = callback {
                cb(&event_data);
            }
        }
    }

    pub async fn worker_loop(&self) {
        debug!("Worker loop started");
        while let Ok(response) = self.recv().await {
            self.handle_response(response).await;
        }
    }

    pub async fn send_cbor_request(&self, request: BTreeMap<Value, Value>) -> Result<(), ThinClientError> {
        let encoded_request = to_vec(&Value::Map(request))?;
        let mut socket = self.socket.lock().await;
        let length_prefix = (encoded_request.len() as u32).to_be_bytes();
        socket.write_all(&length_prefix).await?;
        socket.write_all(&encoded_request).await?;
        info!("Message sent successfully.");
        Ok(())
    }

    pub async fn send_message_without_reply(&self, payload: &[u8], dest_node: Vec<u8>, dest_queue: Vec<u8>) -> Result<(), ThinClientError> {
        let mut request = BTreeMap::new();
        request.insert(Value::Text("with_surb".to_string()), Value::Bool(false));
        request.insert(Value::Text("is_send_op".to_string()), Value::Bool(true));
        request.insert(Value::Text("payload".to_string()), Value::Bytes(payload.to_vec()));
        request.insert(Value::Text("destination_id_hash".to_string()), Value::Bytes(dest_node));
        request.insert(Value::Text("recipient_queue_id".to_string()), Value::Bytes(dest_queue));

        self.send_cbor_request(request).await
    }

    pub async fn send_message(&self, surb_id: Vec<u8>, payload: &[u8], dest_node: Vec<u8>, dest_queue: Vec<u8>) -> Result<(), ThinClientError> {
        let mut request = BTreeMap::new();
        request.insert(Value::Text("with_surb".to_string()), Value::Bool(true));
        request.insert(Value::Text("surbid".to_string()), Value::Bytes(surb_id));
        request.insert(Value::Text("destination_id_hash".to_string()), Value::Bytes(dest_node));
        request.insert(Value::Text("recipient_queue_id".to_string()), Value::Bytes(dest_queue));
        request.insert(Value::Text("payload".to_string()), Value::Bytes(payload.to_vec()));
        request.insert(Value::Text("is_send_op".to_string()), Value::Bool(true));

        self.send_cbor_request(request).await
    }

    pub async fn send_reliable_message(&self, message_id: Vec<u8>, payload: &[u8], dest_node: Vec<u8>, dest_queue: Vec<u8>) -> Result<(), ThinClientError> {
        let mut request = BTreeMap::new();
        request.insert(Value::Text("id".to_string()), Value::Bytes(message_id));
        request.insert(Value::Text("with_surb".to_string()), Value::Bool(true));
        request.insert(Value::Text("is_arq_send_op".to_string()), Value::Bool(true));
        request.insert(Value::Text("payload".to_string()), Value::Bytes(payload.to_vec()));
        request.insert(Value::Text("destination_id_hash".to_string()), Value::Bytes(dest_node));
        request.insert(Value::Text("recipient_queue_id".to_string()), Value::Bytes(dest_queue));

        self.send_cbor_request(request).await
    }
}

fn find_services(capability: &str, doc: &BTreeMap<Value, Value>) -> Vec<ServiceDescriptor> {
    let mut services = Vec::new();

    let Some(Value::Array(nodes)) = doc.get(&Value::Text("ServiceNodes".to_string())) else {
        return services;
    };

    for node in nodes {
        let Value::Bytes(node_bytes) = node else { continue };
        let Ok(mynode) = from_slice::<BTreeMap<Value, Value>>(node_bytes) else { continue };

        let Some(Value::Map(details)) = mynode.get(&Value::Text("omitempty".to_string())) else { continue };
        let Some(Value::Map(service)) = details.get(&Value::Text(capability.to_string())) else { continue };
        let Some(Value::Text(endpoint)) = service.get(&Value::Text("endpoint".to_string())) else { continue };

        services.push(ServiceDescriptor {
            recipient_queue_id: endpoint.as_bytes().to_vec(),
            mix_descriptor: mynode,
        });
    }

    services
}
