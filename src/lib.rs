// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

pub mod error;

use rand::RngCore;
use serde_cbor::{from_slice, to_vec, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::os::unix::io::FromRawFd;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use log::{debug, error, info};
use crate::error::ThinClientError;

// Constants
const SURB_ID_SIZE: usize = 16;
const MESSAGE_ID_SIZE: usize = 16;

#[derive(Clone)]
pub struct Config {
    on_connection_status: Option<Arc<dyn Fn(&BTreeMap<Value, Value>) + Send + Sync>>,
    on_new_pki_document: Option<Arc<dyn Fn(&BTreeMap<Value, Value>) + Send + Sync>>,
    on_message_sent: Option<Arc<dyn Fn(&BTreeMap<Value, Value>) + Send + Sync>>,
    on_message_reply: Option<Arc<dyn Fn(&BTreeMap<Value, Value>) + Send + Sync>>,
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

    pub fn handle_event(&self, event_name: &str, event: &BTreeMap<Value, Value>) {
        match event_name {
            "connection_status_event" => {
                if let Some(cb) = &self.on_connection_status {
                    cb(event);
                }
            }
            "new_pki_document_event" => {
                if let Some(cb) = &self.on_new_pki_document {
                    cb(event);
                }
            }
            "message_sent_event" => {
                if let Some(cb) = &self.on_message_sent {
                    cb(event);
                }
            }
            "message_reply_event" => {
                if let Some(cb) = &self.on_message_reply {
                    cb(event);
                }
            }
            _ => error!("Unknown event type: {}", event_name),
        }
    }
}

pub struct ThinClient {
    socket: Arc<Mutex<UnixStream>>,
    config: Config,
}

impl ThinClient {
    pub async fn new(config: Config) -> Result<Self, ThinClientError> {
        let mut client_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut client_id);

        let client_socket_name = format!("\0katzenpost_rust_thin_client_{}", hex::encode(client_id));

        let sock_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if sock_fd < 0 {
            return Err(ThinClientError::IoError(std::io::Error::last_os_error()));
        }

        // Bind client socket
        let mut client_addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        client_addr.sun_family = libc::AF_UNIX as u16;
        let client_socket_name_i8: Vec<i8> = client_socket_name.as_bytes().iter().map(|&b| b as i8).collect();
        client_addr.sun_path[..client_socket_name_i8.len()].copy_from_slice(&client_socket_name_i8);
        let client_addr_len = std::mem::size_of::<libc::sa_family_t>() + client_socket_name.len();

        if unsafe {
            libc::bind(
                sock_fd,
                &client_addr as *const _ as *const _,
                client_addr_len as u32,
            )
        } < 0
        {
            return Err(ThinClientError::IoError(std::io::Error::last_os_error()));
        }

        let server_socket_name = "\0katzenpost";
        let mut server_addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        server_addr.sun_family = libc::AF_UNIX as u16;
        let server_socket_name_i8: Vec<i8> = server_socket_name.as_bytes().iter().map(|&b| b as i8).collect();
        server_addr.sun_path[..server_socket_name_i8.len()].copy_from_slice(&server_socket_name_i8);

        let server_addr_len = std::mem::size_of::<libc::sa_family_t>() + server_socket_name.len();
        if unsafe {
            libc::connect(
                sock_fd,
                &server_addr as *const _ as *const _,
                server_addr_len as u32,
            )
        } < 0
        {
            return Err(ThinClientError::ConnectError);
        }

        let std_stream = unsafe { StdUnixStream::from_raw_fd(sock_fd) };
        std_stream.set_nonblocking(true)?;
        let socket = UnixStream::from_std(std_stream)?;

        Ok(Self {
            socket: Arc::new(Mutex::new(socket)),
            config,
        })
    }

    /// Generates a new random message ID of size MESSAGE_ID_SIZE.
    pub fn new_message_id() -> Vec<u8> {
        let mut id = vec![0; MESSAGE_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    /// Generates a new random SURB ID of size SURB_ID_SIZE.
    pub fn new_surb_id() -> Vec<u8> {
        let mut id = vec![0; SURB_ID_SIZE];
        rand::thread_rng().fill_bytes(&mut id);
        id
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

    pub async fn worker_loop(&self) {
	debug!("Read loop started");
	while let Ok(response) = self.recv().await {
            for (event_name, event) in response.iter() {
		if let (Value::Text(event_name_str), Value::Map(event_map)) = (event_name, event) {
                    let event_data: BTreeMap<Value, Value> = event_map.clone();
                    self.config.handle_event(event_name_str, &event_data);
		}
            }
	}
    }

    async fn send_cbor_request(&self, request: BTreeMap<Value, Value>) -> Result<(), ThinClientError> {
        let encoded_request = to_vec(&Value::Map(request))?;
        let mut socket = self.socket.lock().await;
        let length_prefix = (encoded_request.len() as u32).to_be_bytes();
        socket.write_all(&length_prefix).await?;
        socket.write_all(&encoded_request).await?;
        info!("Message sent successfully.");
        Ok(())
    }

    pub async fn send_message_without_reply(
        &self,
        payload: &[u8],
        dest_node: Vec<u8>,
        dest_queue: Vec<u8>,
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
        dest_queue: Vec<u8>,
    ) -> Result<(), ThinClientError> {
        let mut request = BTreeMap::new();
        request.insert(Value::Text("with_surb".to_string()), Value::Bool(true));
        request.insert(Value::Text("surbid".to_string()), Value::Bytes(surb_id));
        request.insert(Value::Text("payload".to_string()), Value::Bytes(payload.to_vec()));
        request.insert(Value::Text("destination_id_hash".to_string()), Value::Bytes(dest_node));
        request.insert(Value::Text("recipient_queue_id".to_string()), Value::Bytes(dest_queue));
        request.insert(Value::Text("is_send_op".to_string()), Value::Bool(true));

        self.send_cbor_request(request).await
    }

    pub async fn send_reliable_message(
        &self,
        message_id: Vec<u8>,
        payload: &[u8],
        dest_node: Vec<u8>,
        dest_queue: Vec<u8>,
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
    
    pub async fn stop(&self) {
        let mut socket = self.socket.lock().await;
        let _ = socket.shutdown().await;
        debug!("Connection closed.");
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixStream;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::collections::BTreeMap;
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    use serde_cbor::Value;
    use tokio::test;

    async fn setup_test_client() -> ThinClient {
        let config = Config::new();
        let (server, client) = UnixStream::pair().expect("Failed to create socket pair");
        let thin_client = ThinClient {
            socket: Arc::new(Mutex::new(client)),
            config,
        };
        tokio::spawn(async move {
            let mut server = server;
            let mut buffer = [0; 1024];
            while let Ok(size) = server.read(&mut buffer).await {
                if size == 0 {
                    break;
                }
                let _ = server.write_all(&buffer[..size]).await;
            }
        });

        thin_client
    }

    #[test]
    async fn test_send_message_without_reply() {
        let client = setup_test_client().await;
        let payload = b"Hello, world!".to_vec();
        let dest_node = vec![1, 2, 3, 4];
        let dest_queue = vec![5, 6, 7, 8];

        let result = client.send_message_without_reply(&payload, dest_node.clone(), dest_queue.clone()).await;
        assert!(result.is_ok(), "send_message_without_reply failed");
    }

    #[test]
    async fn test_send_message_with_surb() {
        let client = setup_test_client().await;
        let surb_id = vec![9, 9, 9, 9];
        let payload = b"Hello, SURB!".to_vec();
        let dest_node = vec![1, 2, 3, 4];
        let dest_queue = vec![5, 6, 7, 8];

        let result = client.send_message(surb_id.clone(), &payload, dest_node.clone(), dest_queue.clone()).await;
        assert!(result.is_ok(), "send_message failed");
    }

    #[test]
    async fn test_send_reliable_message() {
        let client = setup_test_client().await;
        let message_id = vec![42, 42, 42, 42];
        let payload = b"Reliable message".to_vec();
        let dest_node = vec![1, 2, 3, 4];
        let dest_queue = vec![5, 6, 7, 8];

        let result = client.send_reliable_message(message_id.clone(), &payload, dest_node.clone(), dest_queue.clone()).await;
        assert!(result.is_ok(), "send_reliable_message failed");
    }

    #[test]
    async fn test_recv_message() {
        let client = setup_test_client().await;

        let mut socket = client.socket.lock().await;
        let test_response = BTreeMap::from([
            (Value::Text("test_key".to_string()), Value::Text("test_value".to_string())),
        ]);
        let encoded_response = to_vec(&Value::Map(test_response.clone())).expect("Failed to encode CBOR");
        let length_prefix = (encoded_response.len() as u32).to_be_bytes();
        
        socket.write_all(&length_prefix).await.unwrap();
        socket.write_all(&encoded_response).await.unwrap();

        drop(socket);

        let response = client.recv().await.expect("Failed to receive message");
        assert_eq!(response, test_response, "Received message does not match expected");
    }

    #[test]
    async fn test_config_event_handling() {
        let mut config = Config::new();
        let received_events = Arc::new(StdMutex::new(Vec::new()));

        let received_events_clone = Arc::clone(&received_events);
        config.on_connection_status = Some(Arc::new(move |event| {
            received_events_clone.lock().unwrap().push(event.clone());
        }));

        let test_event = BTreeMap::from([
            (Value::Text("is_connected".to_string()), Value::Bool(true)),
        ]);

        config.handle_event("connection_status_event", &test_event);
        let events = received_events.lock().unwrap();
        assert_eq!(events.len(), 1, "No events received");
        assert_eq!(events[0], test_event, "Received event does not match expected");
    }
}
