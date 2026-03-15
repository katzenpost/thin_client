// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Group channel integration tests.
//!
//! Tests the generic `GroupChannel<E>` abstraction over a live mixnet.
//!
//! # Event types used
//!
//! `ChatEvent` — a simple text/introduction enum used for the basic group chat
//! tests that mirror the original test suite.
//!
//! `Dot<String>` — a `GCounter<String>` operation used for the CRDT test
//! that demonstrates `state = fold(events)`.
//!
//! # Running tests one at a time with output
//!
//! cargo test --test group_channel_test test_group_channel_three_members -- --nocapture
//! cargo test --test group_channel_test test_group_channel_introduction   -- --nocapture
//! cargo test --test group_channel_test test_group_crdt_gcounter          -- --nocapture

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use katzenpost_thin_client::group::{GroupChannel, Introduction};
use katzenpost_thin_client::persistent::PigeonholeClient;
use katzenpost_thin_client::{Config, ThinClient};

// ---------------------------------------------------------------------------
// Application event type for basic chat tests
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ChatEvent {
    Text(String),
    Introduction(Introduction),
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async fn setup_client(label: &str) -> Result<Arc<ThinClient>, Box<dyn std::error::Error>> {
    println!("[{}] ThinClient::new ...", label);
    let config = Config::new("testdata/thinclient.toml")?;
    let client = ThinClient::new(config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("[{}] setup_client done", label);
    Ok(client)
}

// ---------------------------------------------------------------------------
// Basic chat tests (ChatEvent)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_group_channel_three_members() {
    println!("\n=== Test: Group channel with Alice, Bob, and Carol ===");

    println!("\n--- Setup: create three clients in parallel ---");
    let (alice_thin, bob_thin, carol_thin) = tokio::join!(
        setup_client("alice"),
        setup_client("bob"),
        setup_client("carol"),
    );
    let alice_thin = alice_thin.expect("Failed to setup Alice");
    let bob_thin   = bob_thin.expect("Failed to setup Bob");
    let carol_thin = carol_thin.expect("Failed to setup Carol");

    let alice_ph = PigeonholeClient::new_in_memory(alice_thin.clone()).expect("Alice PigeonholeClient");
    let bob_ph   = PigeonholeClient::new_in_memory(bob_thin.clone()).expect("Bob PigeonholeClient");
    let carol_ph = PigeonholeClient::new_in_memory(carol_thin.clone()).expect("Carol PigeonholeClient");

    println!("\n--- Step 1: All members create group channels in parallel ---");
    let (alice_group, bob_group, carol_group) = tokio::join!(
        GroupChannel::create(&alice_ph, "test-room", "Alice"),
        GroupChannel::create(&bob_ph,   "test-room", "Bob"),
        GroupChannel::create(&carol_ph, "test-room", "Carol"),
    );
    let alice_group: GroupChannel<ChatEvent> = alice_group.expect("Alice group");
    let bob_group:   GroupChannel<ChatEvent> = bob_group.expect("Bob group");
    let carol_group: GroupChannel<ChatEvent> = carol_group.expect("Carol group");
    println!("✓ Alice, Bob, Carol created group 'test-room'");

    println!("\n--- Step 2: Exchange read capabilities ---");
    let alice_intro = alice_group.my_introduction();
    let bob_intro   = bob_group.my_introduction();
    let carol_intro = carol_group.my_introduction();

    alice_group.add_member(&alice_ph, &bob_intro).expect("Alice add Bob");
    alice_group.add_member(&alice_ph, &carol_intro).expect("Alice add Carol");
    bob_group.add_member(&bob_ph, &alice_intro).expect("Bob add Alice");
    bob_group.add_member(&bob_ph, &carol_intro).expect("Bob add Carol");
    carol_group.add_member(&carol_ph, &alice_intro).expect("Carol add Alice");
    carol_group.add_member(&carol_ph, &bob_intro).expect("Carol add Bob");

    println!("✓ Alice has {} members", alice_group.member_count());
    println!("✓ Bob has {} members", bob_group.member_count());
    println!("✓ Carol has {} members", carol_group.member_count());

    println!("\n--- Step 3: Alice sends a message ---");
    let alice_msg = "Hello everyone!";
    alice_group.send(&ChatEvent::Text(alice_msg.to_string())).await.expect("Alice send");
    println!("✓ Alice sent: '{}'", alice_msg);

    // Bob and Carol each have Alice as a member — receive_from_all races their
    // respective member channels concurrently.
    println!("\n--- Step 4: Bob and Carol receive Alice's message in parallel ---");
    let (bob_events, carol_events) = tokio::join!(
        bob_group.receive_from_all(),
        carol_group.receive_from_all(),
    );
    let bob_events   = bob_events.expect("Bob receive_from_all");
    let carol_events = carol_events.expect("Carol receive_from_all");

    // Bob and Carol each only have one member (Alice) at this point, so each
    // Vec has exactly one event.
    let bob_event   = bob_events.into_iter().find(|e| e.sender == "Alice").expect("Bob: no event from Alice");
    let carol_event = carol_events.into_iter().find(|e| e.sender == "Alice").expect("Carol: no event from Alice");

    let ChatEvent::Text(ref bob_text)   = bob_event.event   else { panic!("Expected Text") };
    let ChatEvent::Text(ref carol_text) = carol_event.event else { panic!("Expected Text") };
    assert_eq!(bob_text,   alice_msg);
    assert_eq!(carol_text, alice_msg);
    println!("✓ Bob received from Alice: '{}'", bob_text);
    println!("✓ Carol received from Alice: '{}'", carol_text);

    println!("\n--- Step 5+6: Bob and Carol reply in parallel ---");
    let bob_msg   = "Hi from Bob!";
    let carol_msg = "Hey, Carol here!";
    let bob_ev    = ChatEvent::Text(bob_msg.to_string());
    let carol_ev  = ChatEvent::Text(carol_msg.to_string());
    let (r1, r2) = tokio::join!(
        bob_group.send(&bob_ev),
        carol_group.send(&carol_ev),
    );
    r1.expect("Bob send"); r2.expect("Carol send");
    println!("✓ Bob sent: '{}'", bob_msg);
    println!("✓ Carol sent: '{}'", carol_msg);

    // Alice receives from all members (Bob and Carol) concurrently.
    println!("\n--- Step 7: Alice receives from all members ---");
    let alice_events = alice_group.receive_from_all().await.expect("Alice receive_from_all");

    let from_bob   = alice_events.iter().find(|e| e.sender == "Bob").expect("Alice: no event from Bob");
    let from_carol = alice_events.iter().find(|e| e.sender == "Carol").expect("Alice: no event from Carol");

    let ChatEvent::Text(ref bob_reply)   = from_bob.event   else { panic!("Expected Text from Bob") };
    let ChatEvent::Text(ref carol_reply) = from_carol.event else { panic!("Expected Text from Carol") };
    assert_eq!(bob_reply,   bob_msg);
    assert_eq!(carol_reply, carol_msg);
    println!("✓ Alice received from Bob: '{}'", bob_reply);
    println!("✓ Alice received from Carol: '{}'", carol_reply);

    println!("\n✅ Group channel three-member test passed!");
}

#[tokio::test]
async fn test_group_channel_introduction() {
    println!("\n=== Test: Alice introduces Carol to Bob ===");

    println!("\n--- Setup: create three clients in parallel ---");
    let (alice_thin, bob_thin, carol_thin) = tokio::join!(
        setup_client("alice"),
        setup_client("bob"),
        setup_client("carol"),
    );
    let alice_thin = alice_thin.expect("Failed to setup Alice");
    let bob_thin   = bob_thin.expect("Failed to setup Bob");
    let carol_thin = carol_thin.expect("Failed to setup Carol");

    let alice_ph = PigeonholeClient::new_in_memory(alice_thin.clone()).unwrap();
    let bob_ph   = PigeonholeClient::new_in_memory(bob_thin.clone()).unwrap();
    let carol_ph = PigeonholeClient::new_in_memory(carol_thin.clone()).unwrap();

    println!("\n--- Create group channels in parallel ---");
    let (alice_group, bob_group, carol_group) = tokio::join!(
        GroupChannel::create(&alice_ph, "intro-test", "Alice"),
        GroupChannel::create(&bob_ph,   "intro-test", "Bob"),
        GroupChannel::create(&carol_ph, "intro-test", "Carol"),
    );
    let alice_group: GroupChannel<ChatEvent> = alice_group.unwrap();
    let bob_group:   GroupChannel<ChatEvent> = bob_group.unwrap();
    let carol_group: GroupChannel<ChatEvent> = carol_group.unwrap();

    let alice_intro = alice_group.my_introduction();
    let bob_intro   = bob_group.my_introduction();
    let carol_intro = carol_group.my_introduction();

    // Alice knows everyone; Bob only knows Alice initially.
    alice_group.add_member(&alice_ph, &bob_intro).unwrap();
    alice_group.add_member(&alice_ph, &carol_intro).unwrap();
    bob_group.add_member(&bob_ph, &alice_intro).unwrap();
    carol_group.add_member(&carol_ph, &alice_intro).unwrap();
    carol_group.add_member(&carol_ph, &bob_intro).unwrap();
    println!("✓ Initial setup: Alice knows everyone, Bob only knows Alice");

    println!("\n--- Alice sends Carol's introduction ---");
    alice_group.send(&ChatEvent::Introduction(carol_intro.clone())).await.unwrap();
    println!("✓ Alice sent Carol's introduction");

    println!("\n--- Bob receives from all members (just Alice) ---");
    let msgs = bob_group.receive_from_all().await.unwrap();
    let msg = msgs.into_iter().find(|e| e.sender == "Alice").expect("Bob: no event from Alice");

    let ChatEvent::Introduction(ref intro) = msg.event else {
        panic!("Expected ChatEvent::Introduction");
    };
    println!("✓ Bob received introduction for: '{}'", intro.display_name);
    assert_eq!(intro.display_name, "Carol");

    bob_group.add_member(&bob_ph, intro).unwrap();
    println!("✓ Bob added Carol (member count: {})", bob_group.member_count());
    assert_eq!(bob_group.member_count(), 2); // Alice + Carol

    println!("\n--- Bob sends message to group (now including Carol) ---");
    let bob_text = "Hi Carol, nice to meet you!";
    bob_group.send(&ChatEvent::Text(bob_text.to_string())).await.unwrap();
    println!("✓ Bob sent: '{}'", bob_text);

    println!("\n--- Carol receives from all members ---");
    let carol_msgs = carol_group.receive_from_all().await.unwrap();
    let from_bob = carol_msgs.into_iter().find(|e| e.sender == "Bob").expect("Carol: no event from Bob");

    let ChatEvent::Text(ref carol_got) = from_bob.event else {
        panic!("Expected ChatEvent::Text from Bob");
    };
    assert_eq!(carol_got, bob_text);
    println!("✓ Carol got Bob's message: '{}'", carol_got);

    println!("\n✅ Introduction test passed!");
}

// ---------------------------------------------------------------------------
// CRDT integration test
// ---------------------------------------------------------------------------

/// Each of three participants broadcasts a GCounter increment operation on
/// their own channel.  After all messages propagate through the mixnet, every
/// participant folds the received operations into a local GCounter and verifies
/// the total matches the expected sum.
///
/// This directly demonstrates the `state = fold(events)` pattern described in
/// the Pigeonhole blog post.
#[tokio::test]
async fn test_group_crdt_gcounter() {
    use crdts::{CmRDT, Dot, GCounter};

    type CounterOp = Dot<String>;

    println!("\n=== Test: CRDT GCounter over group channel ===");

    println!("\n--- Setup: create three clients in parallel ---");
    let (alice_thin, bob_thin, carol_thin) = tokio::join!(
        setup_client("alice"),
        setup_client("bob"),
        setup_client("carol"),
    );
    let alice_thin = alice_thin.expect("Failed to setup Alice");
    let bob_thin   = bob_thin.expect("Failed to setup Bob");
    let carol_thin = carol_thin.expect("Failed to setup Carol");

    let alice_ph = PigeonholeClient::new_in_memory(alice_thin.clone()).unwrap();
    let bob_ph   = PigeonholeClient::new_in_memory(bob_thin.clone()).unwrap();
    let carol_ph = PigeonholeClient::new_in_memory(carol_thin.clone()).unwrap();

    println!("\n--- Create group channels in parallel ---");
    let (alice_group, bob_group, carol_group) = tokio::join!(
        GroupChannel::create(&alice_ph, "crdt-test", "Alice"),
        GroupChannel::create(&bob_ph,   "crdt-test", "Bob"),
        GroupChannel::create(&carol_ph, "crdt-test", "Carol"),
    );
    let alice_group: GroupChannel<CounterOp> = alice_group.unwrap();
    let bob_group:   GroupChannel<CounterOp> = bob_group.unwrap();
    let carol_group: GroupChannel<CounterOp> = carol_group.unwrap();

    let alice_intro = alice_group.my_introduction();
    let bob_intro   = bob_group.my_introduction();
    let carol_intro = carol_group.my_introduction();

    alice_group.add_member(&alice_ph, &bob_intro).unwrap();
    alice_group.add_member(&alice_ph, &carol_intro).unwrap();
    bob_group.add_member(&bob_ph, &alice_intro).unwrap();
    bob_group.add_member(&bob_ph, &carol_intro).unwrap();
    carol_group.add_member(&carol_ph, &alice_intro).unwrap();
    carol_group.add_member(&carol_ph, &bob_intro).unwrap();
    println!("✓ All members joined group 'crdt-test'");

    let alice_gen: GCounter<String> = GCounter::new();
    let bob_gen:   GCounter<String> = GCounter::new();
    let carol_gen: GCounter<String> = GCounter::new();

    let alice_op = alice_gen.inc("Alice".to_string());
    let bob_op   = bob_gen.inc("Bob".to_string());
    let carol_op = carol_gen.inc("Carol".to_string());

    println!("\n--- All three send in parallel ---");
    let (r1, r2, r3) = tokio::join!(
        alice_group.send(&alice_op),
        bob_group.send(&bob_op),
        carol_group.send(&carol_op),
    );
    r1.expect("Alice send"); r2.expect("Bob send"); r3.expect("Carol send");
    println!("✓ Alice, Bob, Carol each sent their counter op");

    println!("\n--- All three receive in parallel ---");
    let (alice_received, bob_received, carol_received) = tokio::join!(
        alice_group.receive_from_all(),
        bob_group.receive_from_all(),
        carol_group.receive_from_all(),
    );
    let alice_received = alice_received.expect("Alice receive_from_all");
    let bob_received   = bob_received.expect("Bob receive_from_all");
    let carol_received = carol_received.expect("Carol receive_from_all");
    println!("✓ All ops received");

    // Fold: each participant applies their own op plus the received ops.
    let mut alice_counter: GCounter<String> = GCounter::new();
    alice_counter.apply(alice_op.clone());
    for e in &alice_received { alice_counter.apply(e.event.clone()); }
    assert_eq!(alice_counter.read().to_string(), "3");
    println!("✓ Alice's counter = {} (expected 3)", alice_counter.read());

    let mut bob_counter: GCounter<String> = GCounter::new();
    bob_counter.apply(bob_op.clone());
    for e in &bob_received { bob_counter.apply(e.event.clone()); }
    assert_eq!(bob_counter.read().to_string(), "3");
    println!("✓ Bob's counter = {} (expected 3)", bob_counter.read());

    let mut carol_counter: GCounter<String> = GCounter::new();
    carol_counter.apply(carol_op.clone());
    for e in &carol_received { carol_counter.apply(e.event.clone()); }
    assert_eq!(carol_counter.read().to_string(), "3");
    println!("✓ Carol's counter = {} (expected 3)", carol_counter.read());

    println!("\n✅ CRDT GCounter group test passed!");
    println!("  All three participants independently converged to state = 3");
}
