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
//! 10. create_courier_envelopes_from_multi_payload - Chunk multiple payloads efficiently
//!
//! Helper functions:
//! - tombstone_range - Create tombstones for a range of boxes
//!
//! These tests require a running mixnet with client daemon for integration testing.

use std::time::Duration;
use katzenpost_thin_client::{ThinClient, Config};
use katzenpost_thin_client::pigeonhole::{KeypairResult, EncryptWriteResult};

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

    let KeypairResult { write_cap, read_cap, first_message_index: first_index } = result.unwrap();

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
    let KeypairResult { write_cap: alice_write_cap, read_cap: bob_read_cap, first_message_index: first_index } =
        alice_client.new_keypair(&alice_seed).await
            .expect("Failed to create Alice's keypair");
    println!("✓ Alice created keypair");

    // Alice encrypts and sends a message
    let message = b"Hello Bob, this is Alice!";
    let EncryptWriteResult { message_ciphertext: ciphertext, envelope_descriptor: env_desc, envelope_hash: env_hash, .. } =
        alice_client
            .encrypt_write(message, &alice_write_cap, &first_index).await
            .expect("Failed to encrypt write");
    println!("✓ Alice encrypted message");

    // Alice starts resending the encrypted message
    let _alice_plaintext = alice_client.start_resending_encrypted_message(
        None,
        Some(&alice_write_cap),
        None,
        Some(0),
        &env_desc,
        &ciphertext,
        &env_hash
    ).await.expect("Failed to start resending");

    println!("✓ Alice sent message via ARQ");

    // Wait for message propagation
    println!("Waiting for message propagation...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Bob encrypts a read operation
    let bob_read_result = bob_client
        .encrypt_read(&bob_read_cap, &first_index).await
        .expect("Failed to encrypt read");
    println!("✓ Bob encrypted read operation");

    // Bob starts resending to retrieve the message
    let bob_result = bob_client.start_resending_encrypted_message(
        Some(&bob_read_cap),
        None,
        Some(&first_index),
        Some(0),
        &bob_read_result.envelope_descriptor,
        &bob_read_result.message_ciphertext,
        &bob_read_result.envelope_hash
    ).await.expect("Failed to retrieve message");

    println!("✓ Bob received message");

    // Verify the message matches
    assert_eq!(bob_result.plaintext, message, "Bob should receive Alice's message");

    println!("✅ Complete workflow test passed!");
    println!("  Message sent: {:?}", String::from_utf8_lossy(message));
    println!("  Message received: {:?}", String::from_utf8_lossy(&bob_result.plaintext));
}

#[tokio::test]
async fn test_next_message_box_index() {
    println!("\n=== Test: next_message_box_index ===");

    let client = setup_thin_client().await.expect("Failed to setup client");

    // Generate keypair to get a first_index
    let seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap: _write_cap, read_cap: _read_cap, first_message_index: first_index } =
        client.new_keypair(&seed).await
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
    let KeypairResult { write_cap: dest_write_cap, read_cap: dest_read_cap, first_message_index: dest_first_index } =
        alice_client.new_keypair(&dest_seed).await
            .expect("Failed to create destination keypair");
    println!("✓ Alice created destination channel");

    // Step 2: Alice creates temporary copy stream channel
    println!("\n--- Step 2: Creating temporary copy stream channel ---");
    let temp_seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap: temp_write_cap, read_cap: _temp_read_cap, first_message_index: temp_first_index } =
        alice_client.new_keypair(&temp_seed).await
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
    let copy_stream_result = alice_client.create_courier_envelopes_from_payload(
        &large_payload,
        &dest_write_cap,
        &dest_first_index,
        true,  // is_start
        true,  // is_last
    ).await.expect("Failed to create courier envelopes from payload");

    assert!(!copy_stream_result.envelopes.is_empty(), "Should have at least one chunk");
    println!("✓ Alice created {} copy stream chunks", copy_stream_result.envelopes.len());

    // Step 5: Write all copy stream chunks to the temporary channel
    println!("\n--- Step 5: Writing copy stream chunks to temp channel ---");
    let mut temp_index = temp_first_index.clone();
    for (i, chunk) in copy_stream_result.envelopes.iter().enumerate() {
        let EncryptWriteResult { message_ciphertext: ciphertext, envelope_descriptor: env_desc, envelope_hash: env_hash, .. } =
            alice_client
                .encrypt_write(chunk, &temp_write_cap, &temp_index).await
                .expect("Failed to encrypt chunk");

        let _ = alice_client.start_resending_encrypted_message(
            None,
            Some(&temp_write_cap),
            None,
            Some(0),
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
    let bob_read_result = bob_client
        .encrypt_read(&dest_read_cap, &dest_first_index).await
        .expect("Failed to encrypt read");

    let bob_result = bob_client.start_resending_encrypted_message(
        Some(&dest_read_cap),
        None,
        Some(&dest_first_index),
        Some(0),
        &bob_read_result.envelope_descriptor,
        &bob_read_result.message_ciphertext,
        &bob_read_result.envelope_hash
    ).await.expect("Failed to retrieve message");

    println!("✓ Bob received {} bytes", bob_result.plaintext.len());

    // Verify the payload matches
    assert_eq!(bob_result.plaintext, large_payload, "Received payload should match original");

    println!("✅ create_courier_envelopes_from_payload test passed!");
}

#[tokio::test]
async fn test_create_courier_envelopes_from_multi_payload_multi_channel() {
    println!("\n=== Test: create_courier_envelopes_from_multi_payload (efficient multi-channel) ===");

    let alice_client = setup_thin_client().await.expect("Failed to setup Alice client");
    let bob_client = setup_thin_client().await.expect("Failed to setup Bob client");

    // Step 1: Create two destination channels
    println!("\n--- Step 1: Creating two destination channels ---");
    let chan1_seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap: chan1_write_cap, read_cap: chan1_read_cap, first_message_index: chan1_first_index } =
        alice_client.new_keypair(&chan1_seed).await
            .expect("Failed to create channel 1 keypair");
    println!("✓ Created Channel 1");

    let chan2_seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap: chan2_write_cap, read_cap: chan2_read_cap, first_message_index: chan2_first_index } =
        alice_client.new_keypair(&chan2_seed).await
            .expect("Failed to create channel 2 keypair");
    println!("✓ Created Channel 2");

    // Step 2: Create temporary copy stream channel
    println!("\n--- Step 2: Creating temporary copy stream channel ---");
    let temp_seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap: temp_write_cap, read_cap: _temp_read_cap, first_message_index: temp_first_index } =
        alice_client.new_keypair(&temp_seed).await
            .expect("Failed to create temp keypair");
    println!("✓ Created temporary copy stream channel");

    // Step 3: Create payloads for each channel
    println!("\n--- Step 3: Creating payloads ---");
    let payload1 = b"Hello from Channel 1! This is payload one.".to_vec();
    let payload2 = b"Hello from Channel 2! This is payload two.".to_vec();
    println!("✓ Created payload1 ({} bytes) and payload2 ({} bytes)", payload1.len(), payload2.len());

    // Step 4: Create copy stream chunks using efficient multi-destination API
    println!("\n--- Step 4: Creating copy stream chunks using efficient API ---");
    let destinations = vec![
        (payload1.as_slice(), chan1_write_cap.as_slice(), chan1_first_index.as_slice()),
        (payload2.as_slice(), chan2_write_cap.as_slice(), chan2_first_index.as_slice()),
    ];

    let result = alice_client.create_courier_envelopes_from_multi_payload(
        destinations,
        true, // is_start
        true, // is_last
        None, // buffer
    ).await.expect("Failed to create courier envelopes from multi payload");

    assert!(!result.envelopes.is_empty(), "Should have at least one chunk");
    println!("✓ Created {} copy stream chunks for both destinations", result.envelopes.len());

    // Step 5: Write all chunks to temporary channel
    println!("\n--- Step 5: Writing copy stream chunks to temp channel ---");
    let mut temp_index = temp_first_index.clone();
    for (i, chunk) in result.envelopes.iter().enumerate() {
        let EncryptWriteResult { message_ciphertext: ciphertext, envelope_descriptor: env_desc, envelope_hash: env_hash, .. } =
            alice_client
                .encrypt_write(chunk, &temp_write_cap, &temp_index).await
                .expect("Failed to encrypt chunk");

        let _ = alice_client.start_resending_encrypted_message(
            None,
            Some(&temp_write_cap),
            None,
            Some(0),
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
    let bob1_read_result = bob_client
        .encrypt_read(&chan1_read_cap, &chan1_first_index).await
        .expect("Failed to encrypt read for channel 1");

    let bob1_result = bob_client.start_resending_encrypted_message(
        Some(&chan1_read_cap),
        None,
        Some(&chan1_first_index),
        Some(0),
        &bob1_read_result.envelope_descriptor,
        &bob1_read_result.message_ciphertext,
        &bob1_read_result.envelope_hash
    ).await.expect("Failed to retrieve from channel 1");

    println!("✓ Bob received from Channel 1: {:?}", String::from_utf8_lossy(&bob1_result.plaintext));
    assert_eq!(bob1_result.plaintext, payload1, "Channel 1 payload mismatch");

    // Step 8: Bob reads from Channel 2
    println!("\n--- Step 8: Bob reads from Channel 2 ---");
    let bob2_read_result = bob_client
        .encrypt_read(&chan2_read_cap, &chan2_first_index).await
        .expect("Failed to encrypt read for channel 2");

    let bob2_result = bob_client.start_resending_encrypted_message(
        Some(&chan2_read_cap),
        None,
        Some(&chan2_first_index),
        Some(0),
        &bob2_read_result.envelope_descriptor,
        &bob2_read_result.message_ciphertext,
        &bob2_read_result.envelope_hash
    ).await.expect("Failed to retrieve from channel 2");

    println!("✓ Bob received from Channel 2: {:?}", String::from_utf8_lossy(&bob2_result.plaintext));
    assert_eq!(bob2_result.plaintext, payload2, "Channel 2 payload mismatch");

    println!("✅ create_courier_envelopes_from_multi_payload multi-channel test passed!");
}

// TestTombstoning tests the tombstoning API:
// 1. Alice writes a message to a box
// 2. Bob reads and verifies the message
// 3. Alice tombstones the box (deletes it with an empty payload)
// 4. Bob reads again and verifies the tombstone
#[tokio::test]
async fn test_tombstone_box() {
    let alice = setup_thin_client().await.expect("Failed to setup Alice client");
    let bob = setup_thin_client().await.expect("Failed to setup Bob client");

    // Create keypair
    let seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap, read_cap, first_message_index: first_index } =
        alice.new_keypair(&seed).await
            .expect("Failed to create keypair");
    println!("✓ Created keypair");

    // Step 1: Alice writes a message
    let message = b"Secret message that will be tombstoned";
    let EncryptWriteResult { message_ciphertext: ciphertext, envelope_descriptor: env_desc, envelope_hash: env_hash, .. } =
        alice
            .encrypt_write(message, &write_cap, &first_index).await
            .expect("Failed to encrypt write");

    let reply_index: u8 = 0;
    alice.start_resending_encrypted_message(
        None,
        Some(&write_cap),
        None,
        Some(reply_index),
        &env_desc,
        &ciphertext,
        &env_hash
    ).await.expect("Failed to send message");
    println!("✓ Alice wrote message");

    println!("Waiting for 30 seconds for message propagation...");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Step 2: Bob reads and verifies
    let bob_read_result = bob
        .encrypt_read(&read_cap, &first_index).await
        .expect("Failed to encrypt read");

    let read_result = bob.start_resending_encrypted_message(
        Some(&read_cap),
        None,
        Some(&first_index),
        Some(reply_index),
        &bob_read_result.envelope_descriptor,
        &bob_read_result.message_ciphertext,
        &bob_read_result.envelope_hash
    ).await.expect("Failed to read message");

    assert_eq!(read_result.plaintext, message, "Message mismatch");
    println!("✓ Bob read message: {:?}", String::from_utf8_lossy(&read_result.plaintext));

    // Step 3: Alice tombstones the box using tombstone_range with max_count=1
    let tomb_result = alice
        .tombstone_range(&write_cap, &first_index, 1).await;
    assert!(tomb_result.error.is_none(), "tombstone_range failed: {:?}", tomb_result.error);
    assert_eq!(tomb_result.envelopes.len(), 1, "Expected 1 tombstone envelope");
    let tomb_env = &tomb_result.envelopes[0];

    let tomb_env_hash_arr: [u8; 32] = tomb_env.envelope_hash.clone().try_into()
        .expect("envelope_hash should be 32 bytes");

    alice.start_resending_encrypted_message(
        None,
        Some(&write_cap),
        None,
        None,  // reply_index is nil for tombstone writes
        &tomb_env.envelope_descriptor,
        &tomb_env.message_ciphertext,
        &tomb_env_hash_arr
    ).await.expect("Failed to send tombstone");
    println!("✓ Alice tombstoned the box");

    // Step 4: Bob polls for tombstone with retries (matching Go test)
    const MAX_ATTEMPTS: u32 = 6;
    const POLL_INTERVAL_SECS: u64 = 10;
    let mut tombstone_verified = false;

    for attempt in 1..=MAX_ATTEMPTS {
        println!("Polling for tombstone (attempt {}/{})...", attempt, MAX_ATTEMPTS);
        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;

        let tomb_read_result = bob
            .encrypt_read(&read_cap, &first_index).await
            .expect("Failed to encrypt read for tombstone check");

        match bob.start_resending_encrypted_message(
            Some(&read_cap),
            None,
            Some(&first_index),
            Some(reply_index),
            &tomb_read_result.envelope_descriptor,
            &tomb_read_result.message_ciphertext,
            &tomb_read_result.envelope_hash
        ).await {
            Err(katzenpost_thin_client::ThinClientError::Tombstone) => {
                tombstone_verified = true;
                println!("✓ Bob verified tombstone on attempt {}", attempt);
                break;
            }
            Ok(_) => {
                println!("  Still seeing original message, retrying...");
            }
            Err(e) => panic!("Unexpected error reading tombstone: {}", e),
        }
    }

    assert!(tombstone_verified, "Tombstone not propagated after {} attempts", MAX_ATTEMPTS);
    println!("\n✅ Tombstoning test passed!");
}

#[tokio::test]
async fn test_tombstone_range() {
    println!("\n=== Test: tombstone_range ===");

    let alice_client = setup_thin_client().await.expect("Failed to setup Alice client");

    // Get the geometry from the config
    let _geometry = alice_client.pigeonhole_geometry().clone();

    // Create keypair
    let seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap, read_cap: _read_cap, first_message_index: first_index } =
        alice_client.new_keypair(&seed).await
            .expect("Failed to create keypair");
    println!("✓ Created keypair");

    // Write 3 messages to sequential boxes
    let num_messages: u32 = 3;
    let mut current_index = first_index.clone();

    println!("\n--- Writing {} messages ---", num_messages);
    for i in 0..num_messages {
        let message = format!("Message {} to be tombstoned", i + 1);
        let EncryptWriteResult { message_ciphertext: ciphertext, envelope_descriptor: env_desc, envelope_hash: env_hash, .. } =
            alice_client
                .encrypt_write(message.as_bytes(), &write_cap, &current_index).await
                .expect("Failed to encrypt write");

        let _ = alice_client.start_resending_encrypted_message(
            None,
            Some(&write_cap),
            None,
            Some(0),
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

    // Tombstone the range - creates envelopes without sending
    println!("\n--- Creating tombstones for {} boxes ---", num_messages);
    let result = alice_client.tombstone_range(&write_cap, &first_index, num_messages).await;

    assert!(result.error.is_none(), "Unexpected error: {:?}", result.error);
    assert_eq!(result.envelopes.len(), num_messages as usize, "Expected {} envelopes, got {}", num_messages, result.envelopes.len());
    assert!(!result.next.is_empty(), "Next index should not be empty");
    println!("✓ Created {} tombstone envelopes", result.envelopes.len());

    // Send all tombstone envelopes
    println!("\n--- Sending {} tombstone envelopes ---", num_messages);
    for (i, envelope) in result.envelopes.iter().enumerate() {
        // Convert envelope_hash Vec<u8> to [u8; 32]
        let env_hash: [u8; 32] = envelope.envelope_hash.clone().try_into()
            .expect("envelope_hash should be 32 bytes");
        alice_client.start_resending_encrypted_message(
            None,
            Some(&write_cap),
            None,
            None, // reply_index must be None for tombstone writes
            &envelope.envelope_descriptor,
            &envelope.message_ciphertext,
            &env_hash
        ).await.expect("Failed to send tombstone envelope");
        println!("✓ Sent tombstone envelope {}", i + 1);
    }

    println!("✅ tombstone_range test passed! Created and sent {} tombstones successfully!", num_messages);
}

#[tokio::test]
async fn test_box_id_not_found_error() {
    println!("\n=== Test: BoxIDNotFoundError ===");
    println!("This test verifies that reading from a non-existent box returns BoxNotFound error");

    let client = setup_thin_client().await.expect("Failed to setup client");

    // Create a fresh keypair - but do NOT write anything to it
    let seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap: _write_cap, read_cap, first_message_index: first_index } =
        client.new_keypair(&seed).await
            .expect("Failed to create keypair");
    println!("✓ Created fresh keypair (no messages written)");

    // Encrypt a read request for the non-existent box
    let read_result = client
        .encrypt_read(&read_cap, &first_index).await
        .expect("Failed to encrypt read");
    println!("✓ Encrypted read request for non-existent box");

    // Attempt to read - this should return BoxNotFound error
    // Use start_resending_encrypted_message_no_retry to get immediate error without retries
    println!("--- Attempting to read from non-existent box ---");
    let result = client.start_resending_encrypted_message_no_retry(
        Some(&read_cap),
        None,
        Some(&first_index),
        Some(0),
        &read_result.envelope_descriptor,
        &read_result.message_ciphertext,
        &read_result.envelope_hash
    ).await;

    // Verify we got the expected error
    match result {
        Err(katzenpost_thin_client::ThinClientError::BoxNotFound) => {
            println!("✓ Received expected BoxNotFound error");
            println!("✅ BoxIDNotFoundError test passed!");
        }
        Err(e) => {
            panic!("Expected BoxNotFound error but got: {:?}", e);
        }
        Ok(result) => {
            panic!("Expected BoxNotFound error but got success with plaintext len: {}", result.plaintext.len());
        }
    }
}

/// Test calling create_courier_envelopes_from_payload multiple times
/// to send a large payload to a single destination stream.
///
/// Exercises the stateless API: explicit is_start/is_last flags,
/// and next_dest_index returned in the result so the caller never does index math.
#[tokio::test]
async fn test_from_payload_multi_call() {
    println!("\n=== Test: FromPayload Multi-Call ===");

    let alice_client = setup_thin_client().await.expect("Failed to setup Alice client");
    let bob_client = setup_thin_client().await.expect("Failed to setup Bob client");

    // Create destination channel
    let dest_seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap: dest_write_cap, read_cap: dest_read_cap, first_message_index: dest_first_index } =
        alice_client.new_keypair(&dest_seed).await
            .expect("Failed to create destination keypair");

    // Create temp copy stream channel
    let temp_seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap: temp_write_cap, read_cap: _temp_read_cap, first_message_index: temp_first_index } =
        alice_client.new_keypair(&temp_seed).await
            .expect("Failed to create temp keypair");

    // Create payload large enough to split into 3 chunks
    let chunk_size = 2000;
    let full_payload: Vec<u8> = (0..3 * chunk_size).map(|_| rand::random::<u8>()).collect();
    let chunk1 = &full_payload[..chunk_size];
    let chunk2 = &full_payload[chunk_size..2 * chunk_size];
    let chunk3 = &full_payload[2 * chunk_size..];

    // Call create_courier_envelopes_from_payload 3 times with stateless API
    let mut all_temp_elements: Vec<Vec<u8>> = Vec::new();

    // First call: is_start=true, is_last=false
    let result1 = alice_client.create_courier_envelopes_from_payload(
        chunk1, &dest_write_cap, &dest_first_index, true, false,
    ).await.expect("Call 1 failed");
    assert!(!result1.envelopes.is_empty());
    assert!(result1.next_dest_index.is_some(), "Call 1 should return next_dest_index");
    all_temp_elements.extend(result1.envelopes);
    println!("Call 1: {} temp elements", all_temp_elements.len());

    // Second call: is_start=false, is_last=false — uses next_dest_index from reply
    let result2 = alice_client.create_courier_envelopes_from_payload(
        chunk2, &dest_write_cap, result1.next_dest_index.as_ref().unwrap(), false, false,
    ).await.expect("Call 2 failed");
    assert!(!result2.envelopes.is_empty());
    assert!(result2.next_dest_index.is_some(), "Call 2 should return next_dest_index");
    let result2_count = result2.envelopes.len();
    all_temp_elements.extend(result2.envelopes);
    println!("Call 2: {} new temp elements", result2_count);

    // Third call: is_start=false, is_last=true
    let result3 = alice_client.create_courier_envelopes_from_payload(
        chunk3, &dest_write_cap, result2.next_dest_index.as_ref().unwrap(), false, true,
    ).await.expect("Call 3 failed");
    assert!(!result3.envelopes.is_empty());
    assert!(result3.next_dest_index.is_some(), "Call 3 should return next_dest_index");
    let result3_count = result3.envelopes.len();
    all_temp_elements.extend(result3.envelopes);
    println!("Call 3: {} new temp elements", result3_count);

    // Write all temp stream elements to temp channel
    let mut temp_index = temp_first_index.clone();
    for (i, elem) in all_temp_elements.iter().enumerate() {
        let EncryptWriteResult { message_ciphertext: ciphertext, envelope_descriptor: env_desc, envelope_hash: env_hash, .. } =
            alice_client.encrypt_write(elem, &temp_write_cap, &temp_index).await
                .expect("Failed to encrypt chunk");

        let _ = alice_client.start_resending_encrypted_message(
            None, Some(&temp_write_cap), None, Some(0),
            &env_desc, &ciphertext, &env_hash,
        ).await.expect("Failed to send chunk via ARQ");

        temp_index = alice_client.next_message_box_index(&temp_index).await
            .expect("Failed to get next index");
        println!("  Wrote temp element {}/{}", i + 1, all_temp_elements.len());
    }

    println!("Waiting for temp stream to propagate (30 seconds)");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Send copy command
    alice_client.start_resending_copy_command(&temp_write_cap, None, None).await
        .expect("Failed to send copy command");
    println!("Copy command completed");

    println!("Waiting for copy command to execute (30 seconds)");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Bob reads all destination boxes and reconstructs the payload
    let mut bob_index = dest_first_index.clone();
    let mut reconstructed = Vec::new();
    while reconstructed.len() < full_payload.len() {
        let read_result = bob_client.encrypt_read(&dest_read_cap, &bob_index).await
            .expect("Failed to encrypt read");
        let msg_result = bob_client.start_resending_encrypted_message(
            Some(&dest_read_cap), None, Some(&bob_index), Some(0),
            &read_result.envelope_descriptor,
            &read_result.message_ciphertext,
            &read_result.envelope_hash,
        ).await.expect("Failed to retrieve message");
        assert!(!msg_result.plaintext.is_empty());
        reconstructed.extend_from_slice(&msg_result.plaintext);
        bob_index = bob_client.next_message_box_index(&bob_index).await
            .expect("Failed to get next index");
    }

    assert_eq!(reconstructed, full_payload, "Reconstructed payload doesn't match original");
    println!("✅ FromPayload multi-call test passed!");
}

/// Test calling create_courier_envelopes_from_multi_payload multiple times,
/// writing to two destination channels across two calls.
///
/// Exercises the stateless API with buffer passing and next_dest_indices in the
/// result so the caller can continue writing to the same destinations.
#[tokio::test]
async fn test_from_multi_payload_multi_call() {
    println!("\n=== Test: FromMultiPayload Multi-Call ===");

    let alice_client = setup_thin_client().await.expect("Failed to setup Alice client");
    let bob_client = setup_thin_client().await.expect("Failed to setup Bob client");

    // Create two destination channels
    let chan1_seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap: chan1_write_cap, read_cap: chan1_read_cap, first_message_index: chan1_first_index } =
        alice_client.new_keypair(&chan1_seed).await
            .expect("Failed to create channel 1 keypair");

    let chan2_seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap: chan2_write_cap, read_cap: chan2_read_cap, first_message_index: chan2_first_index } =
        alice_client.new_keypair(&chan2_seed).await
            .expect("Failed to create channel 2 keypair");

    // Create temp copy stream channel
    let temp_seed: [u8; 32] = rand::random();
    let KeypairResult { write_cap: temp_write_cap, read_cap: _temp_read_cap, first_message_index: temp_first_index } =
        alice_client.new_keypair(&temp_seed).await
            .expect("Failed to create temp keypair");

    // Create payloads — small enough to fit in one box each
    let payload1a = b"First batch of data for channel 1 - testing multi-call".to_vec();
    let payload2a = b"First batch of data for channel 2 - testing multi-call".to_vec();
    let payload1b = b"Second batch of data for channel 1 - multi-call works".to_vec();
    let payload2b = b"Second batch of data for channel 2 - multi-call works".to_vec();

    // First call: two destinations, is_start=true, is_last=false
    let destinations1 = vec![
        (payload1a.as_slice(), chan1_write_cap.as_slice(), chan1_first_index.as_slice()),
        (payload2a.as_slice(), chan2_write_cap.as_slice(), chan2_first_index.as_slice()),
    ];
    let result1 = alice_client.create_courier_envelopes_from_multi_payload(
        destinations1, true, false, None,
    ).await.expect("Multi-payload call 1 failed");
    assert!(!result1.envelopes.is_empty());
    assert!(result1.next_dest_indices.is_some(), "Call 1 should return next_dest_indices");
    let next_indices = result1.next_dest_indices.as_ref().unwrap();
    assert_eq!(next_indices.len(), 2, "Should have 2 next_dest_indices");
    println!("Call 1: {} temp elements", result1.envelopes.len());

    // Second call: same destinations, continue from next_dest_indices, is_last=true
    let destinations2 = vec![
        (payload1b.as_slice(), chan1_write_cap.as_slice(), next_indices[0].as_slice()),
        (payload2b.as_slice(), chan2_write_cap.as_slice(), next_indices[1].as_slice()),
    ];
    let result2 = alice_client.create_courier_envelopes_from_multi_payload(
        destinations2, false, true, Some(result1.buffer.clone()),
    ).await.expect("Multi-payload call 2 failed");
    assert!(!result2.envelopes.is_empty());
    assert!(result2.next_dest_indices.is_some(), "Call 2 should return next_dest_indices");
    assert_eq!(result2.next_dest_indices.as_ref().unwrap().len(), 2);
    println!("Call 2: {} temp elements", result2.envelopes.len());

    // Write all temp stream elements
    let mut all_elements = result1.envelopes.clone();
    all_elements.extend(result2.envelopes.clone());
    let mut temp_index = temp_first_index.clone();
    for (i, elem) in all_elements.iter().enumerate() {
        let EncryptWriteResult { message_ciphertext: ciphertext, envelope_descriptor: env_desc, envelope_hash: env_hash, .. } =
            alice_client.encrypt_write(elem, &temp_write_cap, &temp_index).await
                .expect("Failed to encrypt chunk");

        let _ = alice_client.start_resending_encrypted_message(
            None, Some(&temp_write_cap), None, Some(0),
            &env_desc, &ciphertext, &env_hash,
        ).await.expect("Failed to send chunk via ARQ");

        temp_index = alice_client.next_message_box_index(&temp_index).await
            .expect("Failed to get next index");
        println!("  Wrote temp element {}/{}", i + 1, all_elements.len());
    }

    println!("Waiting for temp stream to propagate (30 seconds)");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Send copy command
    alice_client.start_resending_copy_command(&temp_write_cap, None, None).await
        .expect("Failed to send copy command");
    println!("Copy command completed");

    println!("Waiting for copy command to execute (30 seconds)");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Bob reads from channel 1 — expects payload1a + payload1b
    let expected_chan1 = [payload1a.as_slice(), payload1b.as_slice()].concat();
    let mut bob_index = chan1_first_index.clone();
    let mut chan1_data = Vec::new();
    while chan1_data.len() < expected_chan1.len() {
        let read_result = bob_client.encrypt_read(&chan1_read_cap, &bob_index).await
            .expect("Failed to encrypt read for channel 1");
        let msg_result = bob_client.start_resending_encrypted_message(
            Some(&chan1_read_cap), None, Some(&bob_index), Some(0),
            &read_result.envelope_descriptor,
            &read_result.message_ciphertext,
            &read_result.envelope_hash,
        ).await.expect("Failed to retrieve from channel 1");
        assert!(!msg_result.plaintext.is_empty());
        chan1_data.extend_from_slice(&msg_result.plaintext);
        bob_index = bob_client.next_message_box_index(&bob_index).await
            .expect("Failed to get next index");
    }
    assert_eq!(chan1_data, expected_chan1, "Channel 1 data doesn't match");
    println!("Channel 1 verified");

    // Bob reads from channel 2 — expects payload2a + payload2b
    let expected_chan2 = [payload2a.as_slice(), payload2b.as_slice()].concat();
    let mut bob_index = chan2_first_index.clone();
    let mut chan2_data = Vec::new();
    while chan2_data.len() < expected_chan2.len() {
        let read_result = bob_client.encrypt_read(&chan2_read_cap, &bob_index).await
            .expect("Failed to encrypt read for channel 2");
        let msg_result = bob_client.start_resending_encrypted_message(
            Some(&chan2_read_cap), None, Some(&bob_index), Some(0),
            &read_result.envelope_descriptor,
            &read_result.message_ciphertext,
            &read_result.envelope_hash,
        ).await.expect("Failed to retrieve from channel 2");
        assert!(!msg_result.plaintext.is_empty());
        chan2_data.extend_from_slice(&msg_result.plaintext);
        bob_index = bob_client.next_message_box_index(&bob_index).await
            .expect("Failed to get next index");
    }
    assert_eq!(chan2_data, expected_chan2, "Channel 2 data doesn't match");
    println!("Channel 2 verified");

    println!("✅ FromMultiPayload multi-call test passed!");
}
