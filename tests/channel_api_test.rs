// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! NEW Pigeonhole API integration tests for the Rust thin client
//!
//! These tests verify the 5-function NEW Pigeonhole API:
//! 1. new_keypair - Generate WriteCap and ReadCap from seed
//! 2. encrypt_read - Encrypt a read operation
//! 3. encrypt_write - Encrypt a write operation
//! 4. start_resending_encrypted_message - Send encrypted message with ARQ
//! 5. cancel_resending_encrypted_message - Cancel ARQ for a message
//! 6. next_message_box_index - Increment MessageBoxIndex for multiple messages
//!
//! These tests require a running mixnet with client daemon for integration testing.

use std::time::Duration;
use katzenpost_thin_client::{ThinClient, Config};

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
    assert!(result.is_ok(), "new_keypair should succeed");

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
async fn test_encrypt_write_basic() {
    println!("\n=== Test: encrypt_write basic functionality ===");

    let client = setup_thin_client().await.expect("Failed to setup client");

    // Create a keypair first
    let seed: [u8; 32] = rand::random();
    let (write_cap, _read_cap, first_index) = client.new_keypair(&seed).await
        .expect("Failed to create keypair");

    // Encrypt a write operation
    let plaintext = b"Hello from Rust test!";
    let result = client.encrypt_write(plaintext, &write_cap, &first_index).await;

    assert!(result.is_ok(), "encrypt_write should succeed");

    let (ciphertext, env_desc, env_hash, epoch) = result.unwrap();

    // Verify we got valid encrypted data
    assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
    assert!(!env_desc.is_empty(), "Envelope descriptor should not be empty");
    assert_eq!(env_hash.len(), 32, "Envelope hash should be 32 bytes");
    assert!(epoch > 0, "Epoch should be greater than 0");

    println!("✓ Encrypted write operation successfully");
    println!("  Ciphertext length: {}", ciphertext.len());
    println!("  Envelope descriptor length: {}", env_desc.len());
    println!("  Epoch: {}", epoch);
}

#[tokio::test]
async fn test_encrypt_read_basic() {
    println!("\n=== Test: encrypt_read basic functionality ===");

    let client = setup_thin_client().await.expect("Failed to setup client");

    // Create a keypair first
    let seed: [u8; 32] = rand::random();
    let (_write_cap, read_cap, first_index) = client.new_keypair(&seed).await
        .expect("Failed to create keypair");

    // Encrypt a read operation
    let result = client.encrypt_read(&read_cap, &first_index).await;

    assert!(result.is_ok(), "encrypt_read should succeed");

    let (ciphertext, next_index, env_desc, env_hash, epoch) = result.unwrap();

    // Verify we got valid encrypted data
    assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
    assert!(!next_index.is_empty(), "Next index should not be empty");
    assert!(!env_desc.is_empty(), "Envelope descriptor should not be empty");
    assert_eq!(env_hash.len(), 32, "Envelope hash should be 32 bytes");
    assert!(epoch > 0, "Epoch should be greater than 0");

    println!("✓ Encrypted read operation successfully");
    println!("  Ciphertext length: {}", ciphertext.len());
    println!("  Next index length: {}", next_index.len());
    println!("  Envelope descriptor length: {}", env_desc.len());
    println!("  Epoch: {}", epoch);
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
    let (ciphertext, env_desc, env_hash, epoch) = alice_client
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
        &env_hash,
        epoch
    ).await.expect("Failed to start resending");

    println!("✓ Alice sent message via ARQ");

    // Wait for message propagation
    println!("Waiting for message propagation...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Bob encrypts a read operation
    let (bob_ciphertext, bob_next_index, bob_env_desc, bob_env_hash, bob_epoch) = bob_client
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
        &bob_env_hash,
        bob_epoch
    ).await.expect("Failed to retrieve message");

    println!("✓ Bob received message");

    // Verify the message matches
    assert_eq!(bob_plaintext, message, "Bob should receive Alice's message");

    println!("✅ Complete workflow test passed!");
    println!("  Message sent: {:?}", String::from_utf8_lossy(message));
    println!("  Message received: {:?}", String::from_utf8_lossy(&bob_plaintext));
}
