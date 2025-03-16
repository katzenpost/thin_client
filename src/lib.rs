// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

pub mod error;

use std::collections::BTreeMap;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::net::{TcpStream, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf as TcpReadHalf, OwnedWriteHalf as TcpWriteHalf};
use tokio::net::unix::{OwnedReadHalf as UnixReadHalf, OwnedWriteHalf as UnixWriteHalf};

use serde_cbor::{from_slice, Value};
use blake2::{Blake2b, Digest};
use generic_array::typenum::U32;
use rand::RngCore;
use log::{debug, error};

use crate::error::ThinClientError;

const SURB_ID_SIZE: usize = 16;
const MESSAGE_ID_SIZE: usize = 16;

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

/// Explicitly defines whether we're using TCP or Unix sockets
pub enum ServerAddr {
    Tcp(String),         // "192.168.1.100:64331"
    Unix(String),        // "/tmp/thinclient.sock" or abstract "katzenpost"
}

pub enum ReadHalf {
    Tcp(TcpReadHalf),
    Unix(UnixReadHalf),
}

pub enum WriteHalf {
    Tcp(TcpWriteHalf),
    Unix(UnixWriteHalf),
}

pub struct ThinClient {
    read_half: Mutex<ReadHalf>,
    write_half: Mutex<WriteHalf>,
    config: Config,
    pki_doc: Arc<RwLock<Option<BTreeMap<Value, Value>>>>,
    worker_task: Mutex<Option<JoinHandle<()>>>,
    shutdown: Arc<AtomicBool>,
}

impl ThinClient {

    pub async fn new(server_addr: ServerAddr, config: Config) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
	let client = match server_addr {
            ServerAddr::Tcp(addr) => {
		let socket = TcpStream::connect(addr).await?;
		let (read_half, write_half) = socket.into_split();
		Arc::new(Self {
                    read_half: Mutex::new(ReadHalf::Tcp(read_half)),
                    write_half: Mutex::new(WriteHalf::Tcp(write_half)),
                    config,
                    pki_doc: Arc::new(RwLock::new(None)),
                    worker_task: Mutex::new(None),
                    shutdown: Arc::new(AtomicBool::new(false)),
		})
            }
            ServerAddr::Unix(path) => {
		let socket = UnixStream::connect(path).await?;
		let (read_half, write_half) = socket.into_split();
		Arc::new(Self {
                    read_half: Mutex::new(ReadHalf::Unix(read_half)),
                    write_half: Mutex::new(WriteHalf::Unix(write_half)),
                    config,
                    pki_doc: Arc::new(RwLock::new(None)),
                    worker_task: Mutex::new(None),
                    shutdown: Arc::new(AtomicBool::new(false)),
		})
            }
	};

	let client_clone = Arc::clone(&client);
	let task = tokio::spawn(async move { client_clone.worker_loop().await });

	*client.worker_task.lock().await = Some(task);

	debug!("✅ ThinClient initialized and worker loop started.");
	Ok(client)
    }

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
	let mut length_prefix = [0; 4];

	debug!("📥 Waiting to read message length...");

	{
            let mut read_half = self.read_half.lock().await;
            match &mut *read_half {
		ReadHalf::Tcp(rh) => rh.read_exact(&mut length_prefix).await.map_err(ThinClientError::IoError)?,
		ReadHalf::Unix(rh) => rh.read_exact(&mut length_prefix).await.map_err(ThinClientError::IoError)?,
            };
	}

	let message_length = u32::from_be_bytes(length_prefix) as usize;
	debug!("📥 Message length received: {}", message_length);

	let mut buffer = vec![0; message_length];

	debug!("📥 Waiting to read message payload...");

	{
            let mut read_half = self.read_half.lock().await;
            match &mut *read_half {
		ReadHalf::Tcp(rh) => rh.read_exact(&mut buffer).await.map_err(ThinClientError::IoError)?,
		ReadHalf::Unix(rh) => rh.read_exact(&mut buffer).await.map_err(ThinClientError::IoError)?,
            };
	}

	debug!("📥 Raw CBOR data received ({} bytes): {:?}", buffer.len(), buffer);

	let response: BTreeMap<Value, Value> = match from_slice(&buffer) {
            Ok(parsed) => {
		debug!("✅ Successfully parsed response.");
		parsed
            }
            Err(err) => {
		error!("❌ Failed to parse CBOR: {:?}", err);
		return Err(ThinClientError::CborError(err));
            }
	};

	debug!("📥 Parsed response content: {:?}", response);
	Ok(response)
    }
    
    fn parse_status(&self, event: &BTreeMap<Value, Value>) {
        debug!("🔍 Parsing connection status event...");
        assert!(event.get(&Value::Text("is_connected".to_string())) == Some(&Value::Bool(true)), "❌ Connection status mismatch!");
        debug!("✅ Connection status verified.");
    }

    async fn parse_pki_doc(&self, event: &BTreeMap<Value, Value>) {
        debug!("📜 Parsing PKI document event...");

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

    fn mark_reply_received(&self) {
        debug!("📥 Marking reply as received.");
        // Placeholder for setting an event flag if needed
    }

    pub async fn handle_response(&self, response: BTreeMap<Value, Value>) {
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
            self.mark_reply_received();
            if let Some(cb) = self.config.on_message_reply.as_ref() {
                cb(event);
            }
            return;
        }

        error!("❌ Unknown event type received: {:?}", response);
    }

    pub async fn worker_loop(&self) {
        debug!("Worker loop started");
        while !self.shutdown.load(Ordering::Relaxed) {
            match self.recv().await {
                Ok(response) => self.handle_response(response).await,
                Err(_) if self.shutdown.load(Ordering::Relaxed) => break,
                Err(err) => error!("Error in recv: {}", err),
            }
        }
        debug!("Worker loop exited.");
    }

    pub async fn send_cbor_request(&self, request: BTreeMap<Value, Value>) -> Result<(), ThinClientError> {
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
    
    pub async fn send_message_without_reply(
	&self, 
	payload: &[u8], 
	dest_node: Vec<u8>, 
	dest_queue: Vec<u8>
    ) -> Result<(), ThinClientError> {
	let mut request = BTreeMap::new();
	request.insert(Value::Text("with_surb".to_string()), Value::Bool(false));
	request.insert(Value::Text("is_send_op".to_string()), Value::Bool(true));
	request.insert(Value::Text("payload".to_string()), Value::Bytes(payload.to_vec()));
	request.insert(Value::Text("destination_id_hash".to_string()), Value::Bytes(dest_node));
	request.insert(Value::Text("recipient_queue_id".to_string()), Value::Bytes(dest_queue));

	self.send_cbor_request(request).await
    }

    pub async fn send_message(
	&self, 
	surb_id: Vec<u8>, 
	payload: &[u8], 
	dest_node: Vec<u8>, 
	dest_queue: Vec<u8>
    ) -> Result<(), ThinClientError> {
	let mut request = BTreeMap::new();
	request.insert(Value::Text("with_surb".to_string()), Value::Bool(true));
	request.insert(Value::Text("surbid".to_string()), Value::Bytes(surb_id));
	request.insert(Value::Text("destination_id_hash".to_string()), Value::Bytes(dest_node));
	request.insert(Value::Text("recipient_queue_id".to_string()), Value::Bytes(dest_queue));
	request.insert(Value::Text("payload".to_string()), Value::Bytes(payload.to_vec()));
	request.insert(Value::Text("is_send_op".to_string()), Value::Bool(true));

	self.send_cbor_request(request).await
    }

    pub async fn send_reliable_message(
	&self, 
	message_id: Vec<u8>, 
	payload: &[u8], 
	dest_node: Vec<u8>, 
	dest_queue: Vec<u8>
    ) -> Result<(), ThinClientError> {
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
        println!("❌ No 'ServiceNodes' found in PKI document.");
        return services;
    };

    for node in nodes {
        let Value::Bytes(node_bytes) = node else { continue };
        let Ok(mynode) = from_slice::<BTreeMap<Value, Value>>(node_bytes) else { continue };

        // 🔍 Print available capabilities in each node
        if let Some(Value::Map(details)) = mynode.get(&Value::Text("omitempty".to_string())) {
            println!("🔍 Available Capabilities: {:?}", details.keys());
        }

        let Some(Value::Map(details)) = mynode.get(&Value::Text("omitempty".to_string())) else { continue };
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
