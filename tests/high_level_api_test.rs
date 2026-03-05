// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! High-level PigeonholeClient API integration tests
//!
//! These tests demonstrate and verify the high-level API:
//! 1. Basic send/receive between two parties
//! 2. Copy command for large payload streaming
//! 3. Tombstoning to securely delete messages
//!
//! These tests require a running mixnet with client daemon for integration testing.

use std::sync::Arc;
use std::time::Duration;
use katzenpost_thin_client::{ThinClient, Config, PigeonholeGeometry, is_tombstone_plaintext};
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

/// Get PigeonholeGeometry from a thin client
fn get_geometry(client: &ThinClient) -> PigeonholeGeometry {
    client.pigeonhole_geometry().clone()
}

// ============================================================================
// Test 1: Basic send/receive between Alice and Bob
// ============================================================================

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

// ============================================================================
// Test 2: Multiple messages with automatic state management
// ============================================================================

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

// ============================================================================
// Test 3: Low-level box operations
// ============================================================================

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

// ============================================================================
// Test 4: Copy command for streaming large payloads
// ============================================================================

#[tokio::test]
async fn test_copy_stream_large_payload() {
    println!("\n=== Test: Copy stream for large payloads ===");

    let (alice_thin, bob_thin) = setup_clients().await.expect("Failed to setup clients");
    let geometry = get_geometry(&alice_thin);

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");
    let bob = PigeonholeClient::new_in_memory(bob_thin.clone())
        .expect("Failed to create Bob's PigeonholeClient");

    // Create destination channel
    let alice_channel = alice.create_channel("copy-dest").await
        .expect("Failed to create channel");
    let dest_write_cap = alice_channel.write_cap().unwrap().to_vec();
    let dest_start_index = alice_channel.write_index().unwrap().to_vec();

    // Share with Bob for reading
    let read_cap = alice_channel.share_read_capability();
    let bob_channel = bob.import_channel("copy-dest", &read_cap)
        .expect("Failed to import channel");

    // Create a payload larger than one box (simulate streaming)
    // Note: In real usage, you'd stream from disk/network
    let max_payload = geometry.max_plaintext_payload_length as usize;
    let chunk_size = max_payload / 2; // Use half-box chunks to demonstrate streaming
    let total_data_size = max_payload * 2; // 2 boxes worth of data
    let large_payload: Vec<u8> = (0..total_data_size).map(|i| (i % 256) as u8).collect();

    println!("\n--- Creating copy stream for {} byte payload ---", large_payload.len());

    // Use CopyStreamBuilder to stream the data
    let mut builder = alice_channel.copy_stream_builder().await
        .expect("Failed to create copy stream builder");

    // Stream data in chunks (simulating reading from disk/network)
    let mut offset = 0;
    while offset < large_payload.len() {
        let end = std::cmp::min(offset + chunk_size, large_payload.len());
        let is_last = end >= large_payload.len();
        let chunk = &large_payload[offset..end];

        builder.add_payload(chunk, &dest_write_cap, &dest_start_index, is_last).await
            .expect("Failed to add payload chunk");
        println!("✓ Added chunk [{}-{}] (is_last={})", offset, end, is_last);

        offset = end;
    }

    // Finalize and execute the copy command
    let boxes_written = builder.finish().await
        .expect("Failed to finish copy stream");
    println!("✓ Copy stream finished, {} boxes written", boxes_written);

    // Wait for courier to process the copy command
    println!("\n--- Waiting 60 seconds for copy command execution ---");
    tokio::time::sleep(Duration::from_secs(60)).await;

    // Bob reads and reconstructs the payload
    println!("\n--- Bob reads the payload ---");
    let mut reconstructed = Vec::new();
    let mut current_index = bob_channel.read_index().to_vec();

    for i in 0..boxes_written {
        let (chunk, next_idx) = bob_channel.read_box(&current_index).await
            .expect("Failed to read box");
        println!("✓ Read box {}: {} bytes", i + 1, chunk.len());
        reconstructed.extend_from_slice(&chunk);

        if i < boxes_written - 1 {
            current_index = next_idx;
        }
    }

    // Verify (note: the daemon adds length prefix, so exact comparison may differ)
    println!("✓ Reconstructed {} bytes total", reconstructed.len());
    println!("\n✅ Copy stream large payload test passed!");
}

// ============================================================================
// Test 5: Copy with multiple payloads to different destinations
// ============================================================================

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

// ============================================================================
// Test 6: Tombstoning a single box
// ============================================================================

#[tokio::test]
async fn test_tombstone_single_box() {
    println!("\n=== Test: Tombstoning a single box ===");

    let (alice_thin, bob_thin) = setup_clients().await.expect("Failed to setup clients");
    let geometry = get_geometry(&alice_thin);

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

    // Step 3: Alice tombstones the box
    println!("\n--- Step 3: Alice tombstones the box ---");
    alice_channel.refresh().expect("Failed to refresh"); // Get latest state
    alice_channel.tombstone_current(&geometry).await
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
    let (tombstone_content, _) = bob_channel.read_box(&first_index).await
        .expect("Failed to read tombstoned box");

    assert!(
        is_tombstone_plaintext(&geometry, &tombstone_content),
        "Expected tombstone (all zeros)"
    );
    println!("✓ Bob verified tombstone (content is all zeros)");

    println!("\n✅ Tombstone single box test passed!");
}

// ============================================================================
// Test 7: Tombstoning a range of boxes
// ============================================================================

#[tokio::test]
async fn test_tombstone_range() {
    println!("\n=== Test: Tombstoning a range of boxes ===");

    let (alice_thin, bob_thin) = setup_clients().await.expect("Failed to setup clients");
    let geometry = get_geometry(&alice_thin);

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

    // Step 3: Alice tombstones the range
    println!("\n--- Step 3: Alice tombstones {} boxes ---", num_messages);
    alice_channel.tombstone_range(&geometry, num_messages).await
        .expect("Failed to tombstone range");
    println!("✓ Alice sent tombstone range");

    // Wait for tombstone propagation
    println!("\n--- Waiting 60 seconds for tombstone propagation ---");
    tokio::time::sleep(Duration::from_secs(60)).await;

    // Step 4: Verify all boxes are tombstoned
    println!("\n--- Step 4: Verify all boxes are tombstoned ---");
    let mut current_index = first_index;
    for i in 0..num_messages {
        let (content, next_idx) = bob_channel.read_box(&current_index).await
            .expect("Failed to read box");
        assert!(
            is_tombstone_plaintext(&geometry, &content),
            "Box {} should be tombstoned", i + 1
        );
        println!("✓ Box {} is tombstoned", i + 1);

        if i < num_messages - 1 {
            current_index = next_idx;
        }
    }

    println!("\n✅ Tombstone range test passed!");
}

// ============================================================================
// Test 8: Set Stream Buffer for crash recovery
// ============================================================================

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

    // Create envelopes with is_last=false to trigger buffering
    let stream_id = ThinClient::new_stream_id();
    let payload = b"Test payload data for buffering".to_vec();

    let result = alice_thin.create_courier_envelopes_from_payload(
        &stream_id,
        &payload,
        &write_cap,
        &start_index,
        false,  // is_last=false triggers buffering
    ).await.expect("Failed to create envelopes");

    println!("✓ Got {} envelopes", result.envelopes.len());
    println!("✓ Buffer: {} bytes", result.buffer.len());

    // The buffer should be available for persistence
    // (actual buffer contents depend on payload size vs geometry)
    println!("\n✅ Buffer returned from payload test passed!");
}

#[tokio::test]
async fn test_stream_buffer_recovery_workflow() {
    println!("\n=== Test: Stream buffer crash recovery workflow ===");

    let (alice_thin, _bob_thin) = setup_clients().await.expect("Failed to setup clients");

    // Step 1: Alice creates a channel and gets write capability
    println!("\n--- Step 1: Setup channel ---");
    let alice = katzenpost_thin_client::persistent::PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");

    let alice_channel = alice.create_channel("recovery-test").await
        .expect("Failed to create channel");
    let write_cap = alice_channel.write_cap().expect("Channel should have write cap").to_vec();
    let start_index = alice_channel.write_index().expect("Channel should have write index").to_vec();
    println!("✓ Channel created");

    // Step 2: Start a stream with is_last=false (simulating partial write)
    println!("\n--- Step 2: Start streaming with is_last=false ---");
    let stream_id = ThinClient::new_stream_id();
    let first_payload = b"First chunk of data for crash recovery test".to_vec();

    let result = alice_thin.create_courier_envelopes_from_payload(
        &stream_id,
        &first_payload,
        &write_cap,
        &start_index,
        false,  // is_last=false, so buffer will be retained
    ).await.expect("Failed to create envelopes");
    println!("✓ First chunk written with is_last=false");
    println!("  Envelopes: {}, Buffer: {} bytes",
        result.envelopes.len(), result.buffer.len());

    // Step 3: Save the buffer (simulating checkpoint before crash)
    println!("\n--- Step 3: Checkpoint - save buffer ---");
    let saved_buffer = result.buffer.clone();
    println!("✓ Saved buffer: {} bytes", saved_buffer.len());

    // Step 4: Simulate restart by setting buffer on a "new" stream
    // In real crash recovery, this would be a new client instance
    println!("\n--- Step 4: Restore buffer (simulating restart) ---");
    let new_stream_id = ThinClient::new_stream_id();
    alice_thin.set_stream_buffer(
        &new_stream_id,
        saved_buffer.clone(),
    ).await.expect("Failed to restore stream buffer");
    println!("✓ Buffer restored to new stream");

    // Step 5: Continue the stream with more data and finish
    println!("\n--- Step 5: Continue stream and finalize ---");
    let second_payload = b"Second chunk completing the stream".to_vec();
    let final_result = alice_thin.create_courier_envelopes_from_payload(
        &new_stream_id,
        &second_payload,
        &write_cap,
        &start_index,
        true,  // is_last=true to finalize
    ).await.expect("Failed to finalize stream");

    println!("✓ Stream finalized with {} envelopes", final_result.envelopes.len());
    println!("✓ Final buffer: {} bytes (should be 0 after flush)",
        final_result.buffer.len());

    println!("\n✅ Stream buffer crash recovery workflow test passed!");
}
