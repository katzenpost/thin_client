// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! NEW Pigeonhole API integration tests for the Rust thin client
//!
//! These tests verify the NEW Pigeonhole API:
//! 1. new_keypair - Generate WriteCap and ReadCap from seed
//! 2. encrypt_read - Encrypt a read operation
//! 3. encrypt_write - Encrypt a write operation
//! 4. start_resending_encrypted_message - Send encrypted message with ARQ
//! 5. cancel_resending_encrypted_message - Cancel ARQ for a message
//! 6. next_message_box_index - Increment MessageBoxIndex for multiple messages
//! 7. start_resending_copy_command - Send copy command via ARQ
//! 8. cancel_resending_copy_command - Cancel copy command ARQ
//! 9. create_courier_envelopes_from_payload - Chunk payload into courier envelopes
//! 10. create_courier_envelopes_from_payloads - Chunk multiple payloads efficiently
//!
//! Helper functions and tests:
//! - tombstone_box - Overwrite a box with zeros
//! - tombstone_range - Overwrite a range of boxes with zeros
//! - is_tombstone_plaintext - Check if plaintext is a tombstone
//!
//! These tests require a running mixnet with client daemon for integration testing.

use std::time::Duration;
use katzenpost_thin_client::{ThinClient, Config, is_tombstone_plaintext};

/// Test helper to setup a thin client for integration tests
async fn setup_thin_client() -> Result<std::sync::Arc<ThinClient>, Box<dyn std::error::Error>> {
    let config = Config::new("testdata/thinclient.toml")?;
    let client = ThinClient::new(config).await?;

    // Wait a bit for initial connection and PKI document
    tokio::time::sleep(Duration::from_secs(2)).await;

    Ok(client)
}

#[tokio::test]
async fn test_new_keypair_basic() {
    println!("\n=== Test: new_keypair basic functionality ===");

    let client = setup_thin_client().await.expect("Failed to setup client");

    // Generate a random 32-byte seed
    let seed: [u8; 32] = rand::random();

    // Create a new keypair
    let result = client.new_keypair(&seed).await;
    if let Err(ref e) = result {
        println!("new_keypair error: {:?}", e);
    }
    assert!(result.is_ok(), "new_keypair should succeed: {:?}", result.err());

    let (write_cap, read_cap, first_index) = result.unwrap();

    // Verify we got non-empty capabilities
    assert!(!write_cap.is_empty(), "WriteCap should not be empty");
    assert!(!read_cap.is_empty(), "ReadCap should not be empty");
    assert!(!first_index.is_empty(), "First message index should not be empty");

    println!("✓ Created keypair successfully");
    println!("  WriteCap length: {}", write_cap.len());
    println!("  ReadCap length: {}", read_cap.len());
    println!("  First index length: {}", first_index.len());
}

#[tokio::test]
async fn test_alice_sends_bob_complete_workflow() {
    println!("\n=== Test: Complete Alice sends to Bob workflow ===");

    let alice_client = setup_thin_client().await.expect("Failed to setup Alice client");
    let bob_client = setup_thin_client().await.expect("Failed to setup Bob client");

    // Alice creates a keypair
    let alice_seed: [u8; 32] = rand::random();
    let (alice_write_cap, bob_read_cap, first_index) = alice_client.new_keypair(&alice_seed).await
        .expect("Failed to create Alice's keypair");
    println!("✓ Alice created keypair");

    // Alice encrypts and sends a message
    let message = b"Hello Bob, this is Alice!";
    let (ciphertext, env_desc, env_hash) = alice_client
        .encrypt_write(message, &alice_write_cap, &first_index).await
        .expect("Failed to encrypt write");
    println!("✓ Alice encrypted message");

    // Alice starts resending the encrypted message
    let _alice_plaintext = alice_client.start_resending_encrypted_message(
        None,
        Some(&alice_write_cap),
        None,
        0,
        &env_desc,
        &ciphertext,
        &env_hash
    ).await.expect("Failed to start resending");

    println!("✓ Alice sent message via ARQ");

    // Wait for message propagation
    println!("Waiting for message propagation...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Bob encrypts a read operation
    let (bob_ciphertext, bob_next_index, bob_env_desc, bob_env_hash) = bob_client
        .encrypt_read(&bob_read_cap, &first_index).await
        .expect("Failed to encrypt read");
    println!("✓ Bob encrypted read operation");

    // Bob starts resending to retrieve the message
    let bob_plaintext = bob_client.start_resending_encrypted_message(
        Some(&bob_read_cap),
        None,
        Some(&bob_next_index),
        0,
        &bob_env_desc,
        &bob_ciphertext,
        &bob_env_hash
    ).await.expect("Failed to retrieve message");

    println!("✓ Bob received message");

    // Verify the message matches
    assert_eq!(bob_plaintext, message, "Bob should receive Alice's message");

    println!("✅ Complete workflow test passed!");
    println!("  Message sent: {:?}", String::from_utf8_lossy(message));
    println!("  Message received: {:?}", String::from_utf8_lossy(&bob_plaintext));
}

#[tokio::test]
async fn test_next_message_box_index() {
    println!("\n=== Test: next_message_box_index ===");

    let client = setup_thin_client().await.expect("Failed to setup client");

    // Generate keypair to get a first_index
    let seed: [u8; 32] = rand::random();
    let (_write_cap, _read_cap, first_index) = client.new_keypair(&seed).await
        .expect("Failed to create keypair");

    println!("✓ Created keypair");
    println!("  First index length: {}", first_index.len());

    // Increment the index
    let second_index = client.next_message_box_index(&first_index).await
        .expect("Failed to get next message box index");

    assert!(!second_index.is_empty(), "Second index should not be empty");
    assert_ne!(first_index, second_index, "Second index should differ from first");
    println!("✓ Got second index (length: {})", second_index.len());

    // Increment again
    let third_index = client.next_message_box_index(&second_index).await
        .expect("Failed to get third message box index");

    assert!(!third_index.is_empty(), "Third index should not be empty");
    assert_ne!(second_index, third_index, "Third index should differ from second");
    println!("✓ Got third index (length: {})", third_index.len());

    println!("✅ next_message_box_index test passed!");
}

#[tokio::test]
async fn test_create_courier_envelopes_from_payload() {
    println!("\n=== Test: create_courier_envelopes_from_payload with Copy Command ===");

    let alice_client = setup_thin_client().await.expect("Failed to setup Alice client");
    let bob_client = setup_thin_client().await.expect("Failed to setup Bob client");

    // Step 1: Alice creates destination channel
    println!("\n--- Step 1: Creating destination channel ---");
    let dest_seed: [u8; 32] = rand::random();
    let (dest_write_cap, dest_read_cap, dest_first_index) = alice_client.new_keypair(&dest_seed).await
        .expect("Failed to create destination keypair");
    println!("✓ Alice created destination channel");

    // Step 2: Alice creates temporary copy stream channel
    println!("\n--- Step 2: Creating temporary copy stream channel ---");
    let temp_seed: [u8; 32] = rand::random();
    let (temp_write_cap, _temp_read_cap, temp_first_index) = alice_client.new_keypair(&temp_seed).await
        .expect("Failed to create temp keypair");
    println!("✓ Alice created temporary copy stream channel");

    // Step 3: Create a payload with length prefix (like Go/Python tests)
    println!("\n--- Step 3: Creating payload ---");
    let random_data: Vec<u8> = (0..100).map(|_| rand::random::<u8>()).collect();
    let mut large_payload = Vec::new();
    large_payload.extend_from_slice(&(random_data.len() as u32).to_be_bytes());
    large_payload.extend_from_slice(&random_data);
    println!("✓ Alice created payload ({} bytes)", large_payload.len());

    // Step 4: Create copy stream chunks from the payload
    println!("\n--- Step 4: Creating copy stream chunks ---");
    let stream_id = ThinClient::new_stream_id();
    let copy_stream_chunks = alice_client.create_courier_envelopes_from_payload(
        &stream_id,
        &large_payload,
        &dest_write_cap,
        &dest_first_index,
        true // is_last
    ).await.expect("Failed to create courier envelopes from payload");

    assert!(!copy_stream_chunks.is_empty(), "Should have at least one chunk");
    println!("✓ Alice created {} copy stream chunks", copy_stream_chunks.len());

    // Step 5: Write all copy stream chunks to the temporary channel
    println!("\n--- Step 5: Writing copy stream chunks to temp channel ---");
    let mut temp_index = temp_first_index.clone();
    for (i, chunk) in copy_stream_chunks.iter().enumerate() {
        let (ciphertext, env_desc, env_hash) = alice_client
            .encrypt_write(chunk, &temp_write_cap, &temp_index).await
            .expect("Failed to encrypt chunk");

        let _ = alice_client.start_resending_encrypted_message(
            None,
            Some(&temp_write_cap),
            None,
            0,
            &env_desc,
            &ciphertext,
            &env_hash
        ).await.expect("Failed to send chunk via ARQ");

        println!("  ✓ Wrote chunk {} ({} bytes)", i + 1, chunk.len());

        // Advance to next index for next chunk
        temp_index = alice_client.next_message_box_index(&temp_index).await
            .expect("Failed to get next index");
    }

    // Wait for chunks to propagate
    println!("\n--- Waiting for copy stream chunks to propagate (30 seconds) ---");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Step 6: Send Copy command to courier
    println!("\n--- Step 6: Sending Copy command to courier via ARQ ---");
    alice_client.start_resending_copy_command(&temp_write_cap, None, None).await
        .expect("Failed to send copy command");
    println!("✓ Alice copy command completed");

    // Wait for copy command to execute
    println!("\n--- Waiting for copy command to execute (30 seconds) ---");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Step 7: Bob reads from destination channel
    println!("\n--- Step 7: Bob reads from destination channel ---");
    let (bob_ciphertext, bob_next_index, bob_env_desc, bob_env_hash) = bob_client
        .encrypt_read(&dest_read_cap, &dest_first_index).await
        .expect("Failed to encrypt read");

    let bob_plaintext = bob_client.start_resending_encrypted_message(
        Some(&dest_read_cap),
        None,
        Some(&bob_next_index),
        0,
        &bob_env_desc,
        &bob_ciphertext,
        &bob_env_hash
    ).await.expect("Failed to retrieve message");

    println!("✓ Bob received {} bytes", bob_plaintext.len());

    // Verify the payload matches
    assert_eq!(bob_plaintext, large_payload, "Received payload should match original");

    println!("✅ create_courier_envelopes_from_payload test passed!");
}

#[tokio::test]
async fn test_create_courier_envelopes_from_payloads_multi_channel() {
    println!("\n=== Test: create_courier_envelopes_from_payloads (efficient multi-channel) ===");

    let alice_client = setup_thin_client().await.expect("Failed to setup Alice client");
    let bob_client = setup_thin_client().await.expect("Failed to setup Bob client");

    // Step 1: Create two destination channels
    println!("\n--- Step 1: Creating two destination channels ---");
    let chan1_seed: [u8; 32] = rand::random();
    let (chan1_write_cap, chan1_read_cap, chan1_first_index) = alice_client.new_keypair(&chan1_seed).await
        .expect("Failed to create channel 1 keypair");
    println!("✓ Created Channel 1");

    let chan2_seed: [u8; 32] = rand::random();
    let (chan2_write_cap, chan2_read_cap, chan2_first_index) = alice_client.new_keypair(&chan2_seed).await
        .expect("Failed to create channel 2 keypair");
    println!("✓ Created Channel 2");

    // Step 2: Create temporary copy stream channel
    println!("\n--- Step 2: Creating temporary copy stream channel ---");
    let temp_seed: [u8; 32] = rand::random();
    let (temp_write_cap, _temp_read_cap, temp_first_index) = alice_client.new_keypair(&temp_seed).await
        .expect("Failed to create temp keypair");
    println!("✓ Created temporary copy stream channel");

    // Step 3: Create payloads for each channel
    println!("\n--- Step 3: Creating payloads ---");
    let payload1 = b"Hello from Channel 1! This is payload one.".to_vec();
    let payload2 = b"Hello from Channel 2! This is payload two.".to_vec();
    println!("✓ Created payload1 ({} bytes) and payload2 ({} bytes)", payload1.len(), payload2.len());

    // Step 4: Create copy stream chunks using efficient multi-destination API
    println!("\n--- Step 4: Creating copy stream chunks using efficient API ---");
    let stream_id = ThinClient::new_stream_id();

    let destinations = vec![
        (payload1.as_slice(), chan1_write_cap.as_slice(), chan1_first_index.as_slice()),
        (payload2.as_slice(), chan2_write_cap.as_slice(), chan2_first_index.as_slice()),
    ];

    let all_chunks = alice_client.create_courier_envelopes_from_payloads(
        &stream_id,
        destinations,
        true // is_last
    ).await.expect("Failed to create courier envelopes from payloads");

    assert!(!all_chunks.is_empty(), "Should have at least one chunk");
    println!("✓ Created {} copy stream chunks for both destinations", all_chunks.len());

    // Step 5: Write all chunks to temporary channel
    println!("\n--- Step 5: Writing copy stream chunks to temp channel ---");
    let mut temp_index = temp_first_index.clone();
    for (i, chunk) in all_chunks.iter().enumerate() {
        let (ciphertext, env_desc, env_hash) = alice_client
            .encrypt_write(chunk, &temp_write_cap, &temp_index).await
            .expect("Failed to encrypt chunk");

        let _ = alice_client.start_resending_encrypted_message(
            None,
            Some(&temp_write_cap),
            None,
            0,
            &env_desc,
            &ciphertext,
            &env_hash
        ).await.expect("Failed to send chunk via ARQ");

        println!("  ✓ Wrote chunk {} ({} bytes)", i + 1, chunk.len());

        temp_index = alice_client.next_message_box_index(&temp_index).await
            .expect("Failed to get next index");
    }

    // Wait for chunks to propagate
    println!("\n--- Waiting for copy stream chunks to propagate (30 seconds) ---");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Step 6: Send Copy command
    println!("\n--- Step 6: Sending Copy command via ARQ ---");
    alice_client.start_resending_copy_command(&temp_write_cap, None, None).await
        .expect("Failed to send copy command");
    println!("✓ Copy command completed");

    // Wait for copy command to execute
    println!("\n--- Waiting for copy command to execute (30 seconds) ---");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Step 7: Bob reads from Channel 1
    println!("\n--- Step 7: Bob reads from Channel 1 ---");
    let (bob1_ciphertext, bob1_next_index, bob1_env_desc, bob1_env_hash) = bob_client
        .encrypt_read(&chan1_read_cap, &chan1_first_index).await
        .expect("Failed to encrypt read for channel 1");

    let bob1_plaintext = bob_client.start_resending_encrypted_message(
        Some(&chan1_read_cap),
        None,
        Some(&bob1_next_index),
        0,
        &bob1_env_desc,
        &bob1_ciphertext,
        &bob1_env_hash
    ).await.expect("Failed to retrieve from channel 1");

    println!("✓ Bob received from Channel 1: {:?}", String::from_utf8_lossy(&bob1_plaintext));
    assert_eq!(bob1_plaintext, payload1, "Channel 1 payload mismatch");

    // Step 8: Bob reads from Channel 2
    println!("\n--- Step 8: Bob reads from Channel 2 ---");
    let (bob2_ciphertext, bob2_next_index, bob2_env_desc, bob2_env_hash) = bob_client
        .encrypt_read(&chan2_read_cap, &chan2_first_index).await
        .expect("Failed to encrypt read for channel 2");

    let bob2_plaintext = bob_client.start_resending_encrypted_message(
        Some(&chan2_read_cap),
        None,
        Some(&bob2_next_index),
        0,
        &bob2_env_desc,
        &bob2_ciphertext,
        &bob2_env_hash
    ).await.expect("Failed to retrieve from channel 2");

    println!("✓ Bob received from Channel 2: {:?}", String::from_utf8_lossy(&bob2_plaintext));
    assert_eq!(bob2_plaintext, payload2, "Channel 2 payload mismatch");

    println!("✅ create_courier_envelopes_from_payloads multi-channel test passed!");
}

#[tokio::test]
async fn test_tombstone_box() {
    println!("\n=== Test: tombstone_box ===");

    let alice_client = setup_thin_client().await.expect("Failed to setup Alice client");
    let bob_client = setup_thin_client().await.expect("Failed to setup Bob client");

    // Get the geometry from the config - this ensures we use the correct payload size
    let geometry = alice_client.pigeonhole_geometry().clone();

    // Create keypair
    let seed: [u8; 32] = rand::random();
    let (write_cap, read_cap, first_index) = alice_client.new_keypair(&seed).await
        .expect("Failed to create keypair");
    println!("✓ Created keypair");

    // Step 1: Alice writes a message
    println!("\n--- Step 1: Alice writes a message ---");
    let message = b"Secret message that will be tombstoned";
    let (ciphertext, env_desc, env_hash) = alice_client
        .encrypt_write(message, &write_cap, &first_index).await
        .expect("Failed to encrypt write");

    let _ = alice_client.start_resending_encrypted_message(
        None,
        Some(&write_cap),
        None,
        0,
        &env_desc,
        &ciphertext,
        &env_hash
    ).await.expect("Failed to send message");
    println!("✓ Alice wrote message");

    // Wait for message propagation
    println!("--- Waiting for message propagation (5 seconds) ---");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Step 2: Bob reads and verifies
    println!("\n--- Step 2: Bob reads and verifies ---");
    let (bob_ciphertext, bob_next_index, bob_env_desc, bob_env_hash) = bob_client
        .encrypt_read(&read_cap, &first_index).await
        .expect("Failed to encrypt read");

    let bob_plaintext = bob_client.start_resending_encrypted_message(
        Some(&read_cap),
        None,
        Some(&bob_next_index),
        0,
        &bob_env_desc,
        &bob_ciphertext,
        &bob_env_hash
    ).await.expect("Failed to read message");

    assert_eq!(bob_plaintext, message, "Message mismatch");
    println!("✓ Bob read message: {:?}", String::from_utf8_lossy(&bob_plaintext));

    // Step 3: Alice tombstones the box
    println!("\n--- Step 3: Alice tombstones the box ---");
    alice_client.tombstone_box(&geometry, &write_cap, &first_index).await
        .expect("Failed to tombstone box");
    println!("✓ Alice tombstoned the box");

    // Wait for tombstone propagation
    println!("--- Waiting for tombstone propagation (30 seconds) ---");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Step 4: Bob reads again and verifies tombstone
    println!("\n--- Step 4: Bob reads again and verifies tombstone ---");
    let (bob_ciphertext2, bob_next_index2, bob_env_desc2, bob_env_hash2) = bob_client
        .encrypt_read(&read_cap, &first_index).await
        .expect("Failed to encrypt read for tombstone");

    let bob_plaintext2 = bob_client.start_resending_encrypted_message(
        Some(&read_cap),
        None,
        Some(&bob_next_index2),
        0,
        &bob_env_desc2,
        &bob_ciphertext2,
        &bob_env_hash2
    ).await.expect("Failed to read tombstone");

    assert!(is_tombstone_plaintext(&geometry, &bob_plaintext2), "Expected tombstone (all zeros)");
    println!("✓ Bob verified tombstone (all zeros)");

    println!("✅ tombstone_box test passed!");
}

#[tokio::test]
async fn test_tombstone_range() {
    println!("\n=== Test: tombstone_range ===");

    let alice_client = setup_thin_client().await.expect("Failed to setup Alice client");

    // Get the geometry from the config
    let geometry = alice_client.pigeonhole_geometry().clone();

    // Create keypair
    let seed: [u8; 32] = rand::random();
    let (write_cap, _read_cap, first_index) = alice_client.new_keypair(&seed).await
        .expect("Failed to create keypair");
    println!("✓ Created keypair");

    // Write 3 messages to sequential boxes
    let num_messages: u32 = 3;
    let mut current_index = first_index.clone();

    println!("\n--- Writing {} messages ---", num_messages);
    for i in 0..num_messages {
        let message = format!("Message {} to be tombstoned", i + 1);
        let (ciphertext, env_desc, env_hash) = alice_client
            .encrypt_write(message.as_bytes(), &write_cap, &current_index).await
            .expect("Failed to encrypt write");

        let _ = alice_client.start_resending_encrypted_message(
            None,
            Some(&write_cap),
            None,
            0,
            &env_desc,
            &ciphertext,
            &env_hash
        ).await.expect("Failed to send message");
        println!("✓ Wrote message {}", i + 1);

        if i < num_messages - 1 {
            current_index = alice_client.next_message_box_index(&current_index).await
                .expect("Failed to get next index");
        }
    }

    // Wait for messages to propagate
    println!("--- Waiting for message propagation (30 seconds) ---");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Tombstone the range
    println!("\n--- Tombstoning {} boxes ---", num_messages);
    let result = alice_client.tombstone_range(&geometry, &write_cap, &first_index, num_messages).await;

    println!("✓ Tombstoned {} boxes", result.tombstoned);
    assert_eq!(result.tombstoned, num_messages, "Expected {} tombstoned, got {}", num_messages, result.tombstoned);
    assert!(result.error.is_none(), "Unexpected error: {:?}", result.error);
    assert!(!result.next.is_empty(), "Next index should not be empty");

    println!("✅ tombstone_range test passed! Tombstoned {} boxes successfully!", num_messages);
}
