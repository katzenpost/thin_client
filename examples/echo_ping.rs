use thin_client::{ThinClient, Config};
use serde_cbor::Value;
use std::collections::BTreeMap;
use tokio::time::{timeout, Duration};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

struct ClientState {
    reply_message: Arc<Mutex<Option<BTreeMap<Value, Value>>>>,
}

impl ClientState {
    fn new() -> Self {
        Self {
            reply_message: Arc::new(Mutex::new(None)),
        }
    }

    fn save_reply(&self, reply: &BTreeMap<Value, Value>) {
        let mut stored_reply = self.reply_message.lock().unwrap();
        *stored_reply = Some(reply.clone());
    }
}

fn main() {
    let rt = Runtime::new().unwrap();
    rt.block_on(run_client()).unwrap();
}

async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(ClientState::new());
    let state_for_reply = Arc::clone(&state);
    let state_for_pki = Arc::clone(&state);

    let cfg = Config {
        on_new_pki_document: Some(Arc::new(move |pki_doc| {
            println!("Received PKI document.");
            let mut stored_doc = state_for_pki.reply_message.lock().unwrap();
            *stored_doc = Some(pki_doc.clone());
        })),
        on_message_reply: Some(Arc::new(move |reply| state_for_reply.save_reply(reply))),
        ..Config::new()
    };

    let client = ThinClient::new(cfg).await?;

    println!("Waiting for initial daemon responses...");
    let status_response = client.recv().await?;
    client.handle_response(status_response).await;

    let pki_response = client.recv().await?;
    client.handle_response(pki_response).await;

    println!("PKI document received, proceeding...");

    let service_desc = client.get_service("echo").await?;
    let message_id = ThinClient::new_message_id();
    let payload = b"hello".to_vec();
    let (dest_node, dest_queue) = service_desc.to_destination();

    client.send_reliable_message(message_id, &payload, dest_node, dest_queue).await?;

    let state_for_reply_wait = Arc::clone(&state);
    let result = timeout(Duration::from_secs(5), async move {
        loop {
            if let Some(reply) = state_for_reply_wait.reply_message.lock().unwrap().as_ref() {
                if let Some(Value::Bytes(payload2)) = reply.get(&Value::Text("payload".to_string())) {
                    let payload2 = &payload2[..payload.len()];
                    assert_eq!(payload, payload2, "Reply does not match payload!");
                    println!("Received valid reply, stopping client.");
                    return Ok::<(), Box<dyn std::error::Error>>(());
                }
            }
            tokio::task::yield_now().await;
        }
    }).await;

    result.map_err(|e| Box::new(e))??;
    client.stop().await;
    Ok(())
}
