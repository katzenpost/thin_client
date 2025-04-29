
use std::env;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::process;

use tokio::time::{timeout, Duration};
use tokio::runtime::Runtime;

use serde_cbor::Value;

use katzenpost_thin_client::{ThinClient, Config, pretty_print_pki_doc};


struct ClientState {
    reply_message: Arc<Mutex<Option<BTreeMap<Value, Value>>>>,
    pki_received: Arc<Mutex<bool>>,
}

impl ClientState {
    fn new() -> Self {
        Self {
            reply_message: Arc::new(Mutex::new(None)),
            pki_received: Arc::new(Mutex::new(false)),
        }
    }

    fn save_reply(&self, reply: &BTreeMap<Value, Value>) {
        let mut stored_reply = self.reply_message.lock().unwrap();
        *stored_reply = Some(reply.clone());
    }

    fn set_pki_received(&self) {
        let mut pki_flag = self.pki_received.lock().unwrap();
        *pki_flag = true;
    }

    fn is_pki_received(&self) -> bool {
        *self.pki_received.lock().unwrap()
    }

    fn await_message_reply(&self) -> Option<BTreeMap<Value, Value>> {
        let stored_reply = self.reply_message.lock().unwrap();
        stored_reply.clone()
    }
}


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <config_path>", args[0]);
        process::exit(1);
    }
    let config_path = &args[1];

    let rt = Runtime::new().unwrap();
    rt.block_on(run_client(config_path)).unwrap();
}

async fn run_client(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(ClientState::new());
    let state_for_reply = Arc::clone(&state);
    let state_for_pki = Arc::clone(&state);

    let mut cfg = Config::new(config_path)?;
    cfg.on_new_pki_document = Some(Arc::new(move |_pki_doc| {
        println!("✅ PKI document received.");
        state_for_pki.set_pki_received();
    }));
    cfg.on_message_reply = Some(Arc::new(move |reply| {
        println!("📩 Received a reply!");
        state_for_reply.save_reply(reply);
    }));

    println!("🚀 Initializing ThinClient...");
    let client = ThinClient::new(cfg).await?;

    println!("⏳ Waiting for PKI document...");
    let result = timeout(Duration::from_secs(5), async {
        loop {
            if state.is_pki_received() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;

    if result.is_err() {
        return Err("❌ PKI document not received in time.".into());
    }

    println!("✅ Pretty printing PKI document:");
    let doc = client.pki_document().await;
    pretty_print_pki_doc(&doc);
    println!("AFTER Pretty printing PKI document");


    let service_desc = client.get_service("echo").await?;
    println!("got service descriptor for echo service");

    let surb_id = ThinClient::new_surb_id();
    let payload = b"hello".to_vec();
    let (dest_node, dest_queue) = service_desc.to_destination();

    println!("before calling send_message");
    client.send_message(surb_id, &payload, dest_node, dest_queue).await?;
    println!("after calling send_message");
    
    println!("⏳ Waiting for message reply...");
    let state_for_reply_wait = Arc::clone(&state);

    let result = timeout(Duration::from_secs(5), async move {
        loop {
            if let Some(reply) = state_for_reply_wait.await_message_reply() {
                if let Some(Value::Bytes(payload2)) = reply.get(&Value::Text("payload".to_string())) {
                    let payload2 = &payload2[..payload.len()];
                    assert_eq!(payload, payload2, "Reply does not match payload!");
                    println!("✅ Received valid reply, stopping client.");
                    return Ok::<(), Box<dyn std::error::Error>>(());
                }
            }
            tokio::task::yield_now().await;
        }
    }).await;

    result.map_err(|e| Box::new(e))??;
    client.stop().await;
    println!("✅ Client stopped successfully.");
    Ok(())
}
