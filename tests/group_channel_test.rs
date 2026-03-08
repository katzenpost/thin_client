// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Group channel integration tests.
//!
//! Tests the GroupChannel abstraction with three participants
//! (Alice, Bob, Carol) communicating over the mixnet.

use std::sync::Arc;
use std::time::Duration;

use katzenpost_thin_client::{Config, ThinClient};
use katzenpost_thin_client::group::GroupChannel;
use katzenpost_thin_client::persistent::PigeonholeClient;

/// Default timeout for polling messages through the mixnet.
const POLL_TIMEOUT: Duration = Duration::from_secs(120);
/// Interval between poll attempts.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

async fn setup_client() -> Result<Arc<ThinClient>, Box<dyn std::error::Error>> {
    let config = Config::new("testdata/thinclient.toml")?;
    let client = ThinClient::new(config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(client)
}

#[tokio::test]
async fn test_group_channel_three_members() {
    println!("\n=== Test: Group channel with Alice, Bob, and Carol ===");

    // Setup three thin clients
    let alice_thin = setup_client().await.expect("Failed to setup Alice");
    let bob_thin = setup_client().await.expect("Failed to setup Bob");
    let carol_thin = setup_client().await.expect("Failed to setup Carol");

    // Create high-level clients
    let alice_ph = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");
    let bob_ph = PigeonholeClient::new_in_memory(bob_thin.clone())
        .expect("Failed to create Bob's PigeonholeClient");
    let carol_ph = PigeonholeClient::new_in_memory(carol_thin.clone())
        .expect("Failed to create Carol's PigeonholeClient");

    // Step 1: All three create their group channels
    println!("\n--- Step 1: All members create group channels ---");
    let mut alice_group = GroupChannel::create(&alice_ph, "test-room", "Alice")
        .await.expect("Failed to create Alice's group");
    let mut bob_group = GroupChannel::create(&bob_ph, "test-room", "Bob")
        .await.expect("Failed to create Bob's group");
    let mut carol_group = GroupChannel::create(&carol_ph, "test-room", "Carol")
        .await.expect("Failed to create Carol's group");
    println!("✓ Alice, Bob, Carol created group 'test-room'");

    // Step 2: Exchange read capabilities (out-of-band)
    println!("\n--- Step 2: Exchange read capabilities ---");
    let alice_intro = alice_group.my_read_capability();
    let bob_intro = bob_group.my_read_capability();
    let carol_intro = carol_group.my_read_capability();

    // Alice adds Bob and Carol
    alice_group.add_member(&alice_ph, &bob_intro).expect("Alice failed to add Bob");
    alice_group.add_member(&alice_ph, &carol_intro).expect("Alice failed to add Carol");

    // Bob adds Alice and Carol
    bob_group.add_member(&bob_ph, &alice_intro).expect("Bob failed to add Alice");
    bob_group.add_member(&bob_ph, &carol_intro).expect("Bob failed to add Carol");

    // Carol adds Alice and Bob
    carol_group.add_member(&carol_ph, &alice_intro).expect("Carol failed to add Alice");
    carol_group.add_member(&carol_ph, &bob_intro).expect("Carol failed to add Bob");

    println!("✓ Alice has {} members", alice_group.member_count());
    println!("✓ Bob has {} members", bob_group.member_count());
    println!("✓ Carol has {} members", carol_group.member_count());

    // Step 3: Alice sends a message
    println!("\n--- Step 3: Alice sends a message ---");
    let alice_msg = "Hello everyone!";
    alice_group.send_text(alice_msg).await.expect("Alice failed to send");
    println!("✓ Alice sent: '{}'", alice_msg);

    // Step 4: Bob and Carol poll until they receive Alice's message
    println!("\n--- Step 4: Bob and Carol poll for messages ---");
    let bob_msgs = bob_group.poll_until(1, POLL_TIMEOUT, POLL_INTERVAL).await.expect("Bob failed to poll");
    println!("✓ Bob received from Alice: '{}'", bob_msgs[0].message.text.as_ref().unwrap());

    let carol_msgs = carol_group.poll_until(1, POLL_TIMEOUT, POLL_INTERVAL).await.expect("Carol failed to poll");
    println!("✓ Carol received from Alice: '{}'", carol_msgs[0].message.text.as_ref().unwrap());

    assert_eq!(bob_msgs[0].sender, "Alice");
    assert_eq!(carol_msgs[0].sender, "Alice");
    assert_eq!(bob_msgs[0].message.text.as_ref().unwrap(), alice_msg);
    assert_eq!(carol_msgs[0].message.text.as_ref().unwrap(), alice_msg);

    // Step 5: Bob replies
    println!("\n--- Step 5: Bob replies ---");
    let bob_msg = "Hi from Bob!";
    bob_group.send_text(bob_msg).await.expect("Bob failed to send");
    println!("✓ Bob sent: '{}'", bob_msg);

    // Step 6: Carol replies
    println!("\n--- Step 6: Carol replies ---");
    let carol_msg = "Hey, Carol here!";
    carol_group.send_text(carol_msg).await.expect("Carol failed to send");
    println!("✓ Carol sent: '{}'", carol_msg);

    // Step 7: Alice polls until she receives messages from both Bob and Carol
    println!("\n--- Step 7: Alice polls for messages ---");
    let alice_msgs = alice_group.poll_until(2, POLL_TIMEOUT, POLL_INTERVAL).await.expect("Alice failed to poll");

    // Find messages by sender (order is not guaranteed)
    let from_bob = alice_msgs.iter().find(|m| m.sender == "Bob");
    let from_carol = alice_msgs.iter().find(|m| m.sender == "Carol");

    assert!(from_bob.is_some(), "Alice should have received Bob's message");
    assert!(from_carol.is_some(), "Alice should have received Carol's message");
    assert_eq!(from_bob.unwrap().message.text.as_ref().unwrap(), bob_msg);
    assert_eq!(from_carol.unwrap().message.text.as_ref().unwrap(), carol_msg);
    println!("✓ Alice received from Bob: '{}'", from_bob.unwrap().message.text.as_ref().unwrap());
    println!("✓ Alice received from Carol: '{}'", from_carol.unwrap().message.text.as_ref().unwrap());

    println!("\n✅ Group channel three-member test passed!");
}

#[tokio::test]
async fn test_group_channel_introduction() {
    println!("\n=== Test: Alice introduces Carol to Bob ===");

    // Setup three clients
    let alice_thin = setup_client().await.expect("Failed to setup Alice");
    let bob_thin = setup_client().await.expect("Failed to setup Bob");
    let carol_thin = setup_client().await.expect("Failed to setup Carol");

    let alice_ph = PigeonholeClient::new_in_memory(alice_thin.clone()).unwrap();
    let bob_ph = PigeonholeClient::new_in_memory(bob_thin.clone()).unwrap();
    let carol_ph = PigeonholeClient::new_in_memory(carol_thin.clone()).unwrap();

    // Create groups
    let mut alice_group = GroupChannel::create(&alice_ph, "intro-test", "Alice").await.unwrap();
    let mut bob_group = GroupChannel::create(&bob_ph, "intro-test", "Bob").await.unwrap();
    let mut carol_group = GroupChannel::create(&carol_ph, "intro-test", "Carol").await.unwrap();

    // Get intros
    let alice_intro = alice_group.my_read_capability();
    let bob_intro = bob_group.my_read_capability();
    let carol_intro = carol_group.my_read_capability();

    // Initially: Alice knows Bob and Carol, but Bob only knows Alice
    alice_group.add_member(&alice_ph, &bob_intro).unwrap();
    alice_group.add_member(&alice_ph, &carol_intro).unwrap();
    bob_group.add_member(&bob_ph, &alice_intro).unwrap();
    carol_group.add_member(&carol_ph, &alice_intro).unwrap();
    carol_group.add_member(&carol_ph, &bob_intro).unwrap();
    println!("✓ Initial setup: Alice knows everyone, Bob only knows Alice");

    // Alice sends introduction for Carol to help Bob discover her
    println!("\n--- Alice sends introduction for Carol ---");
    alice_group.send_introduction(&carol_intro).await.unwrap();
    println!("✓ Alice sent Carol's introduction");

    // Bob polls until he receives the introduction
    println!("\n--- Bob polls for introduction ---");
    let messages = bob_group.poll_until(1, POLL_TIMEOUT, POLL_INTERVAL).await.unwrap();

    let intro = messages[0].message.introduction.as_ref()
        .expect("Expected Introduction message");
    println!("✓ Bob received introduction for: '{}'", intro.display_name);
    assert_eq!(intro.display_name, "Carol");

    // Bob can now add Carol using the received intro
    bob_group.add_member(&bob_ph, intro).unwrap();
    println!("✓ Bob added Carol (member count: {})", bob_group.member_count());
    assert_eq!(bob_group.member_count(), 2); // Alice + Carol

    // Now Bob can communicate with Carol
    println!("\n--- Bob sends message to group (now including Carol) ---");
    let bob_text = "Hi Carol, nice to meet you!";
    bob_group.send_text(bob_text).await.unwrap();
    println!("✓ Bob sent: '{}'", bob_text);

    // Carol polls until she receives Bob's message
    // (She should also get Alice's introduction)
    println!("\n--- Carol polls for messages ---");
    let carol_msgs = carol_group.poll_until(1, POLL_TIMEOUT, POLL_INTERVAL).await.unwrap();

    println!("✓ Carol received {} messages", carol_msgs.len());
    let from_bob = carol_msgs.iter().find(|m| m.sender == "Bob");
    assert!(from_bob.is_some(), "Carol should have received Bob's message");
    assert_eq!(from_bob.unwrap().message.text.as_ref().unwrap(), bob_text);
    println!("✓ Carol got Bob's message: '{}'", from_bob.unwrap().message.text.as_ref().unwrap());

    println!("\n✅ Introduction test passed!");
}

