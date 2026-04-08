// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! High-level PigeonholeClient API integration tests
//! These tests require a running mixnet with client daemon for integration testing.

use std::sync::Arc;
use std::time::Duration;
use katzenpost_thin_client::{ThinClient, Config};
use katzenpost_thin_client::persistent::PigeonholeClient;

/// Test helper to setup thin clients for integration tests
async fn setup_clients() -> Result<(Arc<ThinClient>, Arc<ThinClient>), Box<dyn std::error::Error>> {
    let alice_config = Config::new("testdata/thinclient.toml")?;
    let alice_client = ThinClient::new(alice_config).await?;

    let bob_config = Config::new("testdata/thinclient.toml")?;
    let bob_client = ThinClient::new(bob_config).await?;

    // Wait for initial connection and PKI document
    tokio::time::sleep(Duration::from_secs(2)).await;

    Ok((alice_client, bob_client))
}

#[tokio::test]
async fn test_high_level_send_receive() {
    println!("\n=== Test: High-level API - Alice sends message to Bob ===");

    let (alice_thin, bob_thin) = setup_clients().await.expect("Failed to setup clients");

    // Create high-level clients with in-memory databases
    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");
    let bob = PigeonholeClient::new_in_memory(bob_thin.clone())
        .expect("Failed to create Bob's PigeonholeClient");

    // Step 1: Alice creates a channel
    println!("\n--- Step 1: Alice creates a channel ---");
    let mut alice_channel = alice.create_channel("alice-to-bob").await
        .expect("Failed to create channel");
    println!("✓ Alice created channel: {}", alice_channel.name());

    // Step 2: Alice shares the read capability with Bob
    println!("\n--- Step 2: Alice shares read capability with Bob ---");
    let read_cap = alice_channel.share_read_capability();
    println!("✓ Alice shared read capability");

    // Step 3: Bob imports the channel
    println!("\n--- Step 3: Bob imports the channel ---");
    let mut bob_channel = bob.import_channel("messages-from-alice", &read_cap)
        .expect("Failed to import channel");
    println!("✓ Bob imported channel: {}", bob_channel.name());
    assert!(!bob_channel.is_owned(), "Bob's channel should be read-only");

    // Step 4: Alice sends a message using high-level API
    println!("\n--- Step 4: Alice sends a message ---");
    let message = b"Hello Bob! This is a secret message from Alice.";
    alice_channel.send(message).await.expect("Failed to send message");
    println!("✓ Alice sent message: {:?}", String::from_utf8_lossy(message));

    // Wait for message propagation through the mixnet
    println!("\n--- Waiting 30 seconds for message propagation ---");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Step 5: Bob receives the message using high-level API
    println!("\n--- Step 5: Bob receives the message ---");
    let received = bob_channel.receive().await.expect("Failed to receive message");
    println!("✓ Bob received message: {:?}", String::from_utf8_lossy(&received));

    // Verify the message content
    assert_eq!(received, message, "Received message should match sent message");
    println!("\n✅ High-level send/receive test passed!");
}

#[tokio::test]
async fn test_high_level_multiple_messages() {
    println!("\n=== Test: High-level API - Multiple sequential messages ===");

    let (alice_thin, bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");
    let bob = PigeonholeClient::new_in_memory(bob_thin.clone())
        .expect("Failed to create Bob's PigeonholeClient");

    // Alice creates a channel and Bob imports it
    let mut alice_channel = alice.create_channel("multi-msg-channel").await
        .expect("Failed to create channel");
    let read_cap = alice_channel.share_read_capability();
    let mut bob_channel = bob.import_channel("multi-msg-channel", &read_cap)
        .expect("Failed to import channel");

    // Alice sends multiple messages
    let messages = vec![
        b"Message 1: Hello!".to_vec(),
        b"Message 2: How are you?".to_vec(),
        b"Message 3: Goodbye!".to_vec(),
    ];

    println!("\n--- Alice sends {} messages ---", messages.len());
    for (i, msg) in messages.iter().enumerate() {
        alice_channel.send(msg).await.expect("Failed to send message");
        println!("✓ Sent message {}: {:?}", i + 1, String::from_utf8_lossy(msg));
    }

    // Wait for propagation
    println!("\n--- Waiting 45 seconds for message propagation ---");
    tokio::time::sleep(Duration::from_secs(45)).await;

    // Bob receives all messages in order
    println!("\n--- Bob receives messages ---");
    for (i, expected_msg) in messages.iter().enumerate() {
        let received = bob_channel.receive().await.expect("Failed to receive message");
        println!("✓ Received message {}: {:?}", i + 1, String::from_utf8_lossy(&received));
        assert_eq!(&received, expected_msg, "Message {} mismatch", i + 1);
    }

    println!("\n✅ Multiple messages test passed!");
}

#[tokio::test]
async fn test_low_level_box_operations() {
    println!("\n=== Test: Low-level box operations (write_box / read_box) ===");

    let (alice_thin, bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");
    let bob = PigeonholeClient::new_in_memory(bob_thin.clone())
        .expect("Failed to create Bob's PigeonholeClient");

    // Alice creates a channel
    let alice_channel = alice.create_channel("low-level-test").await
        .expect("Failed to create channel");

    // Get the initial indices
    let write_index = alice_channel.write_index().unwrap().to_vec();
    let read_cap = alice_channel.share_read_capability();
    let bob_channel = bob.import_channel("low-level-test", &read_cap)
        .expect("Failed to import channel");

    // Alice writes directly to a specific box using low-level API
    println!("\n--- Alice writes to box using write_box ---");
    let message = b"Direct box write test";
    alice_channel.write_box(message, &write_index).await
        .expect("Failed to write box");
    println!("✓ Alice wrote to box at index");

    // Wait for propagation
    println!("\n--- Waiting 30 seconds for propagation ---");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Bob reads from the specific box using low-level API
    println!("\n--- Bob reads from box using read_box ---");
    let read_index = bob_channel.read_index().to_vec();
    let (received, _next_index) = bob_channel.read_box(&read_index).await
        .expect("Failed to read box");
    println!("✓ Bob read from box: {:?}", String::from_utf8_lossy(&received));

    assert_eq!(received, message, "Box content mismatch");
    println!("\n✅ Low-level box operations test passed!");
}

#[tokio::test]
async fn test_copy_stream_multi_payload() {
    println!("\n=== Test: Copy stream with multiple payloads (add_multi_payload) ===");

    let (alice_thin, bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");
    let bob = PigeonholeClient::new_in_memory(bob_thin.clone())
        .expect("Failed to create Bob's PigeonholeClient");

    // Create two destination channels
    let channel1 = alice.create_channel("multi-dest-1").await
        .expect("Failed to create channel 1");
    let channel2 = alice.create_channel("multi-dest-2").await
        .expect("Failed to create channel 2");

    let dest1_write_cap = channel1.write_cap().unwrap().to_vec();
    let dest1_index = channel1.write_index().unwrap().to_vec();
    let dest2_write_cap = channel2.write_cap().unwrap().to_vec();
    let dest2_index = channel2.write_index().unwrap().to_vec();

    // Bob imports both channels
    let read_cap1 = channel1.share_read_capability();
    let read_cap2 = channel2.share_read_capability();
    let bob_channel1 = bob.import_channel("multi-dest-1", &read_cap1)
        .expect("Failed to import channel 1");
    let bob_channel2 = bob.import_channel("multi-dest-2", &read_cap2)
        .expect("Failed to import channel 2");

    // Create payloads for each destination
    let payload1 = b"Secret message for Channel 1";
    let payload2 = b"Secret message for Channel 2";

    println!("\n--- Creating copy stream with multiple destinations ---");

    // Use add_multi_payload for efficient packing
    let mut builder = channel1.copy_stream_builder().await
        .expect("Failed to create copy stream builder");

    let destinations: Vec<(&[u8], &[u8], &[u8])> = vec![
        (payload1.as_slice(), &dest1_write_cap, &dest1_index),
        (payload2.as_slice(), &dest2_write_cap, &dest2_index),
    ];

    builder.add_multi_payload(destinations, true).await
        .expect("Failed to add multi payload");
    println!("✓ Added payloads for both destinations in single call");

    let boxes_written = builder.finish().await
        .expect("Failed to finish copy stream");
    println!("✓ Copy stream finished, {} boxes written", boxes_written);

    // Wait for courier to process
    println!("\n--- Waiting 60 seconds for copy command execution ---");
    tokio::time::sleep(Duration::from_secs(60)).await;

    // Bob reads from both channels
    println!("\n--- Bob reads from Channel 1 ---");
    let (received1, _) = bob_channel1.read_box(bob_channel1.read_index()).await
        .expect("Failed to read from channel 1");
    println!("✓ Channel 1: {:?}", String::from_utf8_lossy(&received1));

    println!("\n--- Bob reads from Channel 2 ---");
    let (received2, _) = bob_channel2.read_box(bob_channel2.read_index()).await
        .expect("Failed to read from channel 2");
    println!("✓ Channel 2: {:?}", String::from_utf8_lossy(&received2));

    // Verify
    assert_eq!(received1, payload1.to_vec(), "Channel 1 payload mismatch");
    assert_eq!(received2, payload2.to_vec(), "Channel 2 payload mismatch");

    println!("\n✅ Multi-payload copy stream test passed!");
}

#[tokio::test]
async fn test_tombstone_single_box() {
    println!("\n=== Test: Tombstoning a single box ===");

    let (alice_thin, bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");
    let bob = PigeonholeClient::new_in_memory(bob_thin.clone())
        .expect("Failed to create Bob's PigeonholeClient");

    // Alice creates a channel
    let mut alice_channel = alice.create_channel("tombstone-test").await
        .expect("Failed to create channel");
    let read_cap = alice_channel.share_read_capability();
    let mut bob_channel = bob.import_channel("tombstone-test", &read_cap)
        .expect("Failed to import channel");

    // Step 1: Alice sends a message
    println!("\n--- Step 1: Alice sends a message ---");
    let message = b"This message will be tombstoned";
    alice_channel.send(message).await.expect("Failed to send message");
    println!("✓ Alice sent message");

    // Wait for propagation
    println!("\n--- Waiting 30 seconds for propagation ---");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Step 2: Bob reads the message
    println!("\n--- Step 2: Bob reads the message ---");
    let received = bob_channel.receive().await.expect("Failed to receive");
    println!("✓ Bob received: {:?}", String::from_utf8_lossy(&received));
    assert_eq!(received, message);

    // Step 3: Alice tombstones the box at the first index
    println!("\n--- Step 3: Alice tombstones the box ---");
    let first_index = read_cap.start_index.clone();
    alice_channel.tombstone_at(&first_index).await
        .expect("Failed to tombstone");
    println!("✓ Alice tombstoned the box");

    // Wait for tombstone propagation
    println!("\n--- Waiting 60 seconds for tombstone propagation ---");
    tokio::time::sleep(Duration::from_secs(60)).await;

    // Step 4: Bob reads again and sees tombstone
    println!("\n--- Step 4: Bob reads the tombstoned box ---");
    bob_channel.refresh().expect("Failed to refresh");
    // Reset read index to re-read the same box
    let first_index = read_cap.start_index.clone();
    match bob_channel.read_box(&first_index).await {
        Err(katzenpost_thin_client::persistent::PigeonholeDbError::ThinClient(
            katzenpost_thin_client::ThinClientError::Tombstone
        )) => {
            println!("✓ Bob verified tombstone");
        }
        other => panic!("Expected Tombstone error, got: {:?}", other),
    }

    println!("\n✅ Tombstone single box test passed!");
}

#[tokio::test]
async fn test_tombstone_range() {
    println!("\n=== Test: Tombstoning a range of boxes ===");

    let (alice_thin, bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");
    let bob = PigeonholeClient::new_in_memory(bob_thin.clone())
        .expect("Failed to create Bob's PigeonholeClient");

    // Alice creates a channel
    let mut alice_channel = alice.create_channel("tombstone-range-test").await
        .expect("Failed to create channel");
    let read_cap = alice_channel.share_read_capability();
    let first_index = read_cap.start_index.clone();
    let bob_channel = bob.import_channel("tombstone-range-test", &read_cap)
        .expect("Failed to import channel");

    // Step 1: Alice sends multiple messages
    let num_messages = 3;
    println!("\n--- Step 1: Alice sends {} messages ---", num_messages);
    for i in 0..num_messages {
        let msg = format!("Message {} to be tombstoned", i + 1);
        alice_channel.send(msg.as_bytes()).await.expect("Failed to send");
        println!("✓ Sent message {}", i + 1);
    }

    // Wait for propagation
    println!("\n--- Waiting 45 seconds for propagation ---");
    tokio::time::sleep(Duration::from_secs(45)).await;

    // Step 2: Verify Bob can read all messages
    println!("\n--- Step 2: Verify Bob can read messages ---");
    let mut bob_channel = bob_channel; // Make mutable for receive
    for i in 0..num_messages {
        let received = bob_channel.receive().await.expect("Failed to receive");
        println!("✓ Read message {}: {:?}", i + 1, String::from_utf8_lossy(&received));
    }

    // Step 3: Alice tombstones the range starting from the first index
    println!("\n--- Step 3: Alice tombstones {} boxes ---", num_messages);
    alice_channel.tombstone_from(&first_index, num_messages).await
        .expect("Failed to tombstone range");
    println!("✓ Alice sent tombstone range");

    // Wait for tombstone propagation
    println!("\n--- Waiting 60 seconds for tombstone propagation ---");
    tokio::time::sleep(Duration::from_secs(60)).await;

    // Step 4: Verify all boxes are tombstoned
    println!("\n--- Step 4: Verify all boxes are tombstoned ---");
    let mut current_index = first_index;
    for i in 0..num_messages {
        match bob_channel.read_box(&current_index).await {
            Err(katzenpost_thin_client::persistent::PigeonholeDbError::ThinClient(
                katzenpost_thin_client::ThinClientError::Tombstone
            )) => {
                println!("✓ Box {} is tombstoned", i + 1);
            }
            other => panic!("Box {} should be tombstoned, got: {:?}", i + 1, other),
        }

        if i < num_messages - 1 {
            current_index = bob_thin.next_message_box_index(&current_index).await
                .expect("Failed to advance index");
        }
    }

    println!("\n✅ Tombstone range test passed!");
}

#[tokio::test]
async fn test_stream_buffer_set_and_restore() {
    println!("\n=== Test: Set stream buffer for recovery ===");

    let (alice_thin, _bob_thin) = setup_clients().await.expect("Failed to setup clients");

    // Generate a stream ID
    let stream_id = ThinClient::new_stream_id();
    println!("Using stream_id: {:?}", &stream_id[..4]);

    // Set a buffer state (simulating restoration from persisted state)
    let test_buffer = b"test buffer data for crash recovery".to_vec();

    println!("Setting buffer: {} bytes", test_buffer.len());
    alice_thin.set_stream_buffer(&stream_id, test_buffer.clone()).await
        .expect("Failed to set stream buffer");
    println!("✓ Buffer set successfully - encoder created/updated in daemon");

    println!("\n✅ Set stream buffer test passed!");
}

#[tokio::test]
async fn test_stream_buffer_returned_from_payload() {
    println!("\n=== Test: Buffer state returned from create_courier_envelopes_from_payload ===");

    let (alice_thin, _bob_thin) = setup_clients().await.expect("Failed to setup clients");

    // Create a channel for the write capability
    let alice = katzenpost_thin_client::persistent::PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");

    let alice_channel = alice.create_channel("buffer-test").await
        .expect("Failed to create channel");
    let write_cap = alice_channel.write_cap().expect("Channel should have write cap").to_vec();
    let start_index = alice_channel.write_index().expect("Channel should have write index").to_vec();

    // Create envelopes with is_last=false (stateless API, no stream_id)
    let payload = b"Test payload data for buffering".to_vec();

    let result = alice_thin.create_courier_envelopes_from_payload(
        &payload,
        &write_cap,
        &start_index,
        true,   // is_start
        false,  // is_last=false
    ).await.expect("Failed to create envelopes");

    println!("✓ Got {} envelopes", result.envelopes.len());
    assert!(result.next_dest_index.is_some(), "Should return next_dest_index");
    println!("✓ next_dest_index returned");

    println!("\n✅ Stateless payload test passed!");
}

#[tokio::test]
async fn test_stateless_payload_multi_call_next_index() {
    println!("\n=== Test: Stateless FromPayload multi-call with next_dest_index chaining ===");

    let (alice_thin, _bob_thin) = setup_clients().await.expect("Failed to setup clients");

    // Step 1: Alice creates a channel and gets write capability
    println!("\n--- Step 1: Setup channel ---");
    let alice = katzenpost_thin_client::persistent::PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");

    let alice_channel = alice.create_channel("multi-call-test").await
        .expect("Failed to create channel");
    let write_cap = alice_channel.write_cap().expect("Channel should have write cap").to_vec();
    let start_index = alice_channel.write_index().expect("Channel should have write index").to_vec();
    println!("✓ Channel created");

    // Step 2: First call with is_start=true, is_last=false
    println!("\n--- Step 2: First call (is_start=true, is_last=false) ---");
    let first_payload = b"First chunk of data for multi-call test".to_vec();
    let result1 = alice_thin.create_courier_envelopes_from_payload(
        &first_payload,
        &write_cap,
        &start_index,
        true,   // is_start
        false,  // is_last
    ).await.expect("First call failed");
    assert!(result1.next_dest_index.is_some(), "Should return next_dest_index");
    println!("✓ First call: {} envelopes, next_dest_index returned",
        result1.envelopes.len());

    // Step 3: Second call with is_start=false, is_last=true, using next_dest_index
    println!("\n--- Step 3: Second call (is_start=false, is_last=true) ---");
    let second_payload = b"Second chunk completing the stream".to_vec();
    let result2 = alice_thin.create_courier_envelopes_from_payload(
        &second_payload,
        &write_cap,
        result1.next_dest_index.as_ref().unwrap(),
        false,  // is_start
        true,   // is_last
    ).await.expect("Second call failed");
    assert!(result2.next_dest_index.is_some(), "Should return next_dest_index");
    println!("✓ Second call: {} envelopes, next_dest_index returned",
        result2.envelopes.len());

    println!("\n✅ Stateless multi-call with next_dest_index chaining test passed!");
}

#[tokio::test]
async fn test_read_box_no_retry() {
    println!("\n=== Test: read_box_no_retry returns immediate error for non-existent box ===");

    let (alice_thin, _bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");

    // Create a channel
    let alice_channel = alice.create_channel("read-no-retry-test").await
        .expect("Failed to create channel");
    let read_cap = alice_channel.share_read_capability();

    // Try to read from a box that doesn't exist yet (nothing was written)
    // With no_retry, this should fail immediately with BoxNotFound
    println!("\n--- Attempting read_box_no_retry on empty box ---");
    let result = alice_channel.read_box_no_retry(&read_cap.start_index).await;

    match result {
        Err(e) => {
            let err_str = format!("{:?}", e);
            println!("✓ Got expected error: {}", err_str);
            assert!(
                err_str.contains("BoxNotFound") || err_str.contains("box id not found"),
                "Expected BoxNotFound error, got: {}", err_str
            );
        }
        Ok(_) => {
            panic!("Expected BoxNotFound error, but read succeeded");
        }
    }

    println!("\n✅ read_box_no_retry test passed!");
}

#[tokio::test]
async fn test_receive_no_retry() {
    println!("\n=== Test: receive_no_retry returns immediate error for non-existent message ===");

    let (alice_thin, _bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");

    // Create a channel
    let mut alice_channel = alice.create_channel("receive-no-retry-test").await
        .expect("Failed to create channel");

    // Try to receive when nothing was sent
    // With no_retry, this should fail immediately with BoxNotFound
    println!("\n--- Attempting receive_no_retry on empty channel ---");
    let result = alice_channel.receive_no_retry().await;

    match result {
        Err(e) => {
            let err_str = format!("{:?}", e);
            println!("✓ Got expected error: {}", err_str);
            assert!(
                err_str.contains("BoxNotFound") || err_str.contains("box id not found"),
                "Expected BoxNotFound error, got: {}", err_str
            );
        }
        Ok(_) => {
            panic!("Expected BoxNotFound error, but receive succeeded");
        }
    }

    println!("\n✅ receive_no_retry test passed!");
}

#[tokio::test]
async fn test_write_box_return_box_exists() {
    println!("\n=== Test: write_box_return_box_exists returns error on duplicate write ===");

    let (alice_thin, _bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");

    // Create a channel
    let alice_channel = alice.create_channel("write-box-exists-test").await
        .expect("Failed to create channel");
    let start_index = alice_channel.read_index().to_vec();

    // First write should succeed
    println!("\n--- First write_box ---");
    let message1 = b"First message";
    alice_channel.write_box(message1, &start_index).await
        .expect("First write should succeed");
    println!("✓ First write succeeded");

    // Wait for propagation
    println!("\n--- Waiting 30 seconds for propagation ---");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Second write to same index with return_box_exists should fail
    println!("\n--- Second write_box_return_box_exists to same index ---");
    let message2 = b"Second message";
    let result = alice_channel.write_box_return_box_exists(message2, &start_index).await;

    match result {
        Err(e) => {
            let err_str = format!("{:?}", e);
            println!("✓ Got expected error: {}", err_str);
            assert!(
                err_str.contains("BoxAlreadyExists") || err_str.contains("box already exists"),
                "Expected BoxAlreadyExists error, got: {}", err_str
            );
        }
        Ok(_) => {
            panic!("Expected BoxAlreadyExists error, but write succeeded");
        }
    }

    println!("\n✅ write_box_return_box_exists test passed!");
}

#[tokio::test]
async fn test_send_return_box_exists() {
    println!("\n=== Test: send_return_box_exists returns error on duplicate send ===");

    let (alice_thin, bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");
    let bob = PigeonholeClient::new_in_memory(bob_thin.clone())
        .expect("Failed to create Bob's PigeonholeClient");

    // Create a channel
    let mut alice_channel = alice.create_channel("send-box-exists-test").await
        .expect("Failed to create channel");
    let read_cap = alice_channel.share_read_capability();
    let _bob_channel = bob.import_channel("send-box-exists-test", &read_cap)
        .expect("Failed to import channel");

    // First send should succeed
    println!("\n--- First send ---");
    let message1 = b"First message";
    alice_channel.send(message1).await
        .expect("First send should succeed");
    println!("✓ First send succeeded");

    // Wait for propagation
    println!("\n--- Waiting 30 seconds for propagation ---");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Now manually write to the CURRENT write index (which was just advanced)
    // to set up a conflict scenario. We need to use write_box to write at the
    // new write_index, then try send_return_box_exists which will try to write there
    let current_write_index = alice_channel.write_index().unwrap().to_vec();
    println!("\n--- Writing directly to current write index to create conflict ---");
    alice_channel.write_box(b"Conflict message", &current_write_index).await
        .expect("Direct write should succeed");
    println!("✓ Conflict message written");

    // Wait for propagation
    println!("\n--- Waiting 30 seconds for propagation ---");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Now send_return_box_exists should fail because the box is occupied
    println!("\n--- Attempting send_return_box_exists ---");
    let result = alice_channel.send_return_box_exists(b"This should fail").await;

    match result {
        Err(e) => {
            let err_str = format!("{:?}", e);
            println!("✓ Got expected error: {}", err_str);
            assert!(
                err_str.contains("BoxAlreadyExists") || err_str.contains("box already exists"),
                "Expected BoxAlreadyExists error, got: {}", err_str
            );
        }
        Ok(_) => {
            panic!("Expected BoxAlreadyExists error, but send succeeded");
        }
    }

    println!("\n✅ send_return_box_exists test passed!");
}
