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

use katzenpost_thin_client::chat::{ChatEvent, GroupChat};
use katzenpost_thin_client::persistent::PigeonholeClient;
use katzenpost_thin_client::{Config, ThinClient};


async fn setup_client(label: &str) -> Result<Arc<ThinClient>, Box<dyn std::error::Error>> {
    println!("[{}] ThinClient::new ...", label);
    let config = Config::new("testdata/thinclient.toml")?;
    let client = ThinClient::new(config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("[{}] setup_client done", label);
    Ok(client)
}

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

    let alice_ph = Arc::new(PigeonholeClient::new_in_memory(alice_thin.clone()).expect("Alice PigeonholeClient"));
    let bob_ph   = Arc::new(PigeonholeClient::new_in_memory(bob_thin.clone()).expect("Bob PigeonholeClient"));
    let carol_ph = Arc::new(PigeonholeClient::new_in_memory(carol_thin.clone()).expect("Carol PigeonholeClient"));

    println!("\n--- Step 1: All members create group channels in parallel ---");
    let (alice_group, bob_group, carol_group) = tokio::join!(
        GroupChat::create(alice_ph.clone(), "test-room", "Alice"),
        GroupChat::create(bob_ph.clone(),   "test-room", "Bob"),
        GroupChat::create(carol_ph.clone(), "test-room", "Carol"),
    );
    let alice_group: GroupChat = alice_group.expect("Alice group");
    let bob_group:   GroupChat = bob_group.expect("Bob group");
    let carol_group: GroupChat = carol_group.expect("Carol group");
    println!("✓ Alice, Bob, Carol created group 'test-room'");

    println!("\n--- Step 2: Exchange read capabilities ---");
    let alice_intro = alice_group.my_introduction();
    let bob_intro   = bob_group.my_introduction();
    let carol_intro = carol_group.my_introduction();

    // Alice knows everyone from the start.
    alice_group.add_member(&bob_intro).expect("Alice add Bob");
    alice_group.add_member(&carol_intro).expect("Alice add Carol");
    // Bob and Carol each only know Alice for now — this is intentional so that
    // receive_from_all in Step 4 waits for exactly one member and doesn't
    // block on a message that hasn't been sent yet.
    bob_group.add_member(&alice_intro).expect("Bob add Alice");
    carol_group.add_member(&alice_intro).expect("Carol add Alice");

    println!("✓ Alice has {} members", alice_group.member_count());
    println!("✓ Bob has {} members (Alice only)", bob_group.member_count());
    println!("✓ Carol has {} members (Alice only)", carol_group.member_count());

    println!("\n--- Step 3: Alice sends a message ---");
    let alice_msg = "Hello everyone!";
    alice_group.send_text(alice_msg).await.expect("Alice send");
    println!("✓ Alice sent: '{}'", alice_msg);

    // Bob and Carol each only know Alice, so receive_from_all returns as soon
    // as Alice's single message arrives.
    println!("\n--- Step 4: Bob and Carol receive Alice's message in parallel ---");
    let (bob_events, carol_events) = tokio::join!(
        bob_group.receive_from_all(),
        carol_group.receive_from_all(),
    );
    let bob_events   = bob_events.expect("Bob receive_from_all");
    let carol_events = carol_events.expect("Carol receive_from_all");

    let bob_event   = bob_events.into_iter().find(|e| e.sender == "Alice").expect("Bob: no event from Alice");
    let carol_event = carol_events.into_iter().find(|e| e.sender == "Alice").expect("Carol: no event from Alice");

    let ChatEvent::Text(ref bob_text)   = bob_event.event   else { panic!("Expected Text") };
    let ChatEvent::Text(ref carol_text) = carol_event.event else { panic!("Expected Text") };
    assert_eq!(bob_text,   alice_msg);
    assert_eq!(carol_text, alice_msg);
    println!("✓ Bob received from Alice: '{}'", bob_text);
    println!("✓ Carol received from Alice: '{}'", carol_text);

    println!("\n--- Step 5+6: Bob and Carol introduce themselves and reply in parallel ---");
    // Now that Bob and Carol have heard from Alice, introduce them to each other
    // so Alice can later receive_from_all across both of them.
    bob_group.add_member(&carol_intro).expect("Bob add Carol");
    carol_group.add_member(&bob_intro).expect("Carol add Bob");

    let bob_msg   = "Hi from Bob!";
    let carol_msg = "Hey, Carol here!";
    let (r1, r2) = tokio::join!(
        bob_group.send_text(bob_msg),
        carol_group.send_text(carol_msg),
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

    let alice_ph = Arc::new(PigeonholeClient::new_in_memory(alice_thin.clone()).unwrap());
    let bob_ph   = Arc::new(PigeonholeClient::new_in_memory(bob_thin.clone()).unwrap());
    let carol_ph = Arc::new(PigeonholeClient::new_in_memory(carol_thin.clone()).unwrap());

    println!("\n--- Create group channels in parallel ---");
    let (alice_group, bob_group, carol_group) = tokio::join!(
        GroupChat::create(alice_ph.clone(), "intro-test", "Alice"),
        GroupChat::create(bob_ph.clone(),   "intro-test", "Bob"),
        GroupChat::create(carol_ph.clone(), "intro-test", "Carol"),
    );
    let alice_group: GroupChat = alice_group.unwrap();
    let bob_group:   GroupChat = bob_group.unwrap();
    let carol_group: GroupChat = carol_group.unwrap();

    let alice_intro = alice_group.my_introduction();
    let bob_intro   = bob_group.my_introduction();
    let carol_intro = carol_group.my_introduction();

    // Alice knows everyone; Bob only knows Alice initially.
    alice_group.add_member(&bob_intro).unwrap();
    alice_group.add_member(&carol_intro).unwrap();
    bob_group.add_member(&alice_intro).unwrap();
    carol_group.add_member(&alice_intro).unwrap();
    carol_group.add_member(&bob_intro).unwrap();
    println!("✓ Initial setup: Alice knows everyone, Bob only knows Alice");

    println!("\n--- Alice sends Carol's introduction ---");
    alice_group.send_introduction(&carol_intro).await.unwrap();
    println!("✓ Alice sent Carol's introduction");

    println!("\n--- Bob receives from all members (just Alice) ---");
    let msgs = bob_group.receive_from_all().await.unwrap();
    let msg = msgs.into_iter().find(|e| e.sender == "Alice").expect("Bob: no event from Alice");

    let ChatEvent::Introduction(ref intro) = msg.event else {
        panic!("Expected ChatEvent::Introduction");
    };
    println!("✓ Bob received introduction for: '{}'", intro.display_name);
    assert_eq!(intro.display_name, "Carol");

    bob_group.add_member(intro).unwrap();
    println!("✓ Bob added Carol (member count: {})", bob_group.member_count());
    assert_eq!(bob_group.member_count(), 2); // Alice + Carol

    println!("\n--- Bob sends message to group (now including Carol) ---");
    let bob_text = "Hi Carol, nice to meet you!";
    bob_group.send_text(bob_text).await.unwrap();
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

/// Alice and Bob are in a two-member group.  Alice rotates her write channel.
///
/// The test verifies the complete handshake:
///
/// 1. Alice calls `rotate_channel()` — `rotation_pending()` becomes true and
///    a `Rotate` envelope is written to Alice's **old** channel.
/// 2. Alice sends an App message on the old channel so Bob has something to
///    receive that triggers the Rotate processing.
/// 3. Bob calls `receive_from_all()`.  The spawned task reads Alice's old
///    channel and finds `[Rotate, App("trigger")]` in order.  It loops
///    internally until it finds the App, collecting the Rotate.  The main
///    thread processes the Rotate: imports Alice's new channel and sends
///    `Ack` on Bob's own channel.
/// 4. Bob sends an App message so Alice has a trigger to process the Ack.
/// 5. Alice calls `receive_from_all()`.  The task reads Bob's channel and
///    finds `[Ack, App("ack-trigger")]`.  The main thread processes the Ack:
///    `acks_needed` becomes empty → rotation completes, `my_channel` and
///    `my_introduction` are atomically replaced.
/// 6. `rotation_pending()` is now false; Alice's `my_introduction()` has a
///    different read cap than before.
/// 7. Alice sends "post-rotation" on the **new** channel.  Bob's
///    `member_channels` already points to the new channel (updated in step 3),
///    so `receive_from_all()` transparently reads from the new endpoint.
#[tokio::test]
async fn test_group_channel_rotation() {
    println!("\n=== Test: Channel rotation handshake ===");

    let (alice_thin, bob_thin) = tokio::join!(
        setup_client("alice"),
        setup_client("bob"),
    );
    let alice_thin = alice_thin.expect("Alice ThinClient");
    let bob_thin   = bob_thin.expect("Bob ThinClient");

    let alice_ph = Arc::new(PigeonholeClient::new_in_memory(alice_thin.clone()).unwrap());
    let bob_ph   = Arc::new(PigeonholeClient::new_in_memory(bob_thin.clone()).unwrap());

    println!("\n--- Setup: Alice and Bob create channels and join the group ---");
    let (alice_group, bob_group) = tokio::join!(
        GroupChat::create(alice_ph.clone(), "rotation-test", "Alice"),
        GroupChat::create(bob_ph.clone(),   "rotation-test", "Bob"),
    );
    let alice_group: GroupChat = alice_group.unwrap();
    let bob_group:   GroupChat = bob_group.unwrap();

    let alice_intro_before = alice_group.my_introduction();
    let bob_intro           = bob_group.my_introduction();
    alice_group.add_member(&bob_intro).unwrap();
    bob_group.add_member(&alice_intro_before).unwrap();
    println!("✓ Alice and Bob set up two-member group");

    println!("\n--- Pre-rotation: verify basic messaging works ---");
    alice_group.send_text("pre-rotation").await.unwrap();
    let events = bob_group.receive_from_all().await.unwrap();
    let msg = events.into_iter().find(|e| e.sender == "Alice").unwrap();
    let ChatEvent::Text(ref t) = msg.event else { panic!("expected Text") };
    assert_eq!(t, "pre-rotation");
    println!("✓ Bob received Alice's pre-rotation message");

    println!("\n--- Step 1: Alice rotates her channel ---");
    alice_group.rotate_channel().await.unwrap();
    assert!(alice_group.rotation_pending(), "rotation should be pending after rotate_channel()");
    println!("✓ Alice initiated rotation; rotation_pending = true");

    // Alice sends an App event on the OLD channel so Bob's receive_from_all
    // task can loop past the Rotate and deliver an App to the main thread.
    alice_group.send_text("rotate-trigger").await.unwrap();
    println!("✓ Alice sent 'rotate-trigger' on old channel");

    println!("\n--- Step 2: Bob receives from all (processes Rotate transparently) ---");
    // The task reads: Rotate, App("rotate-trigger") → returns App.
    // Main thread calls process_envelopes([Rotate]):
    //   - imports Alice's new channel into member_channels
    //   - sends Ack on Bob's channel
    let bob_events = bob_group.receive_from_all().await.unwrap();
    let bob_msg = bob_events.into_iter().find(|e| e.sender == "Alice").unwrap();
    let ChatEvent::Text(ref t) = bob_msg.event else { panic!("expected Text") };
    assert_eq!(t, "rotate-trigger", "Bob should see the App event, not the Rotate");
    println!("✓ Bob received 'rotate-trigger'; Rotate processed silently, Ack sent");

    // Bob sends an App event on his channel so Alice's receive_from_all task
    // can loop past the Ack and deliver an App to the main thread.
    bob_group.send_text("ack-trigger").await.unwrap();
    println!("✓ Bob sent 'ack-trigger' on his channel");

    println!("\n--- Step 3: Alice receives from all (processes Ack, completes rotation) ---");
    // The task reads: Ack, App("ack-trigger") → returns App.
    // Main thread calls process_envelopes([Ack]):
    //   - acks_needed becomes empty → swaps my_channel and my_introduction
    let alice_events = alice_group.receive_from_all().await.unwrap();
    let alice_msg = alice_events.into_iter().find(|e| e.sender == "Bob").unwrap();
    let ChatEvent::Text(ref t) = alice_msg.event else { panic!("expected Text") };
    assert_eq!(t, "ack-trigger", "Alice should see the App event, not the Ack");
    println!("✓ Alice received 'ack-trigger'; Ack processed silently");

    println!("\n--- Step 4: Verify rotation completed ---");
    assert!(!alice_group.rotation_pending(), "rotation should be complete");
    let alice_intro_after = alice_group.my_introduction();
    assert_ne!(
        alice_intro_before.read_cap, alice_intro_after.read_cap,
        "read_cap must change after rotation"
    );
    assert_ne!(
        alice_intro_before.member_id(), alice_intro_after.member_id(),
        "member_id must change after rotation"
    );
    println!("✓ rotation_pending = false");
    println!("✓ Alice's read_cap changed (old member_id ≠ new member_id)");

    println!("\n--- Step 5: Messaging still works on the new channel ---");
    alice_group.send_text("post-rotation").await.unwrap();
    // Bob's member_channels was updated in step 2 to point at Alice's new
    // channel, so receive_from_all reads from the correct endpoint.
    let events = bob_group.receive_from_all().await.unwrap();
    let msg = events.into_iter().find(|e| e.sender == "Alice").unwrap();
    let ChatEvent::Text(ref t) = msg.event else { panic!("expected Text") };
    assert_eq!(t, "post-rotation");
    println!("✓ Bob received Alice's post-rotation message on the new channel");

    println!("\n✅ Channel rotation test passed!");
}
