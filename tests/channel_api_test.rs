// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Channel API integration tests for the Rust thin client
//! 
//! These tests mirror the Go tests in courier_docker_test.go and require
//! a running mixnet with client daemon for integration testing.

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

/// Test basic channel API operations - equivalent to TestChannelAPIBasics from Go
/// This test demonstrates the full channel workflow: Alice creates a write channel,
/// Bob creates a read channel, Alice writes messages, Bob reads them back.
#[tokio::test]
async fn test_channel_api_basics() -> Result<(), Box<dyn std::error::Error>> {
    let alice_thin_client = setup_thin_client().await?;
    let bob_thin_client = setup_thin_client().await?;

    // Wait for PKI documents to be available and connection to mixnet
    println!("Waiting for daemon to connect to mixnet...");
    let mut attempts = 0;
    while !alice_thin_client.is_connected() && attempts < 30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        attempts += 1;
    }

    if !alice_thin_client.is_connected() {
        return Err("Daemon failed to connect to mixnet within 30 seconds".into());
    }

    println!("✅ Daemon connected to mixnet, using current PKI document");

    // Alice creates write channel
    println!("Alice: Creating write channel");
    let (alice_channel_id, read_cap, _write_cap) = alice_thin_client.create_write_channel().await?;
    println!("Alice: Created write channel {}", alice_channel_id);

    // Bob creates read channel using the read capability from Alice's write channel
    println!("Bob: Creating read channel");
    let bob_channel_id = bob_thin_client.create_read_channel(read_cap).await?;
    println!("Bob: Created read channel {}", bob_channel_id);

    // Alice writes first message
    let original_message = b"hello1";
    println!("Alice: Writing first message and waiting for completion");

    let (write_payload1, _current_index1, _next_index1, _envelope_descriptor1, _envelope_hash1) =
        alice_thin_client.write_channel(alice_channel_id, original_message).await?;
    println!("Alice: Write operation completed successfully");

    // Get the courier service from PKI
    let courier_service = alice_thin_client.get_service("courier").await?;
    let (dest_node, dest_queue) = courier_service.to_destination();

    let alice_message_id1 = ThinClient::new_message_id();

    let _reply1 = alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        &write_payload1,
        dest_node.clone(),
        dest_queue.clone(),
        alice_message_id1
    ).await?;

    // Alice writes a second message
    let second_message = b"hello2";
    println!("Alice: Writing second message and waiting for completion");

    let (write_payload2, _current_index2, _next_index2, _envelope_descriptor2, _envelope_hash2) =
        alice_thin_client.write_channel(alice_channel_id, second_message).await?;
    println!("Alice: Second write operation completed successfully");

    let alice_message_id2 = ThinClient::new_message_id();

    let _reply2 = alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        &write_payload2,
        dest_node.clone(),
        dest_queue.clone(),
        alice_message_id2
    ).await?;

    // Wait for message propagation to storage replicas
    println!("Waiting for message propagation to storage replicas");
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Bob reads first message
    println!("Bob: Reading first message");
    let (read_payload1, _current_index, _next_index, _reply_index, _envelope_descriptor1, _envelope_hash1) =
        bob_thin_client.read_channel(bob_channel_id, None, None).await?;

    let bob_message_id1 = ThinClient::new_message_id();

    // In a real implementation, you'd retry the SendChannelQueryAwaitReply until you get a response
    let mut bob_reply_payload = vec![];
    for i in 0..10 {
        match alice_thin_client.send_channel_query_await_reply(
            bob_channel_id,
            &read_payload1,
            dest_node.clone(),
            dest_queue.clone(),
            bob_message_id1.clone()
        ).await {
            Ok(payload) if !payload.is_empty() => {
                bob_reply_payload = payload;
                break;
            }
            Ok(_) => {
                println!("Bob: Read attempt {} returned empty payload, retrying...", i + 1);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    assert_eq!(original_message, bob_reply_payload.as_slice(), "Bob: Reply payload mismatch");

    // Bob reads second message
    println!("Bob: Reading second message");
    let (read_payload2, _current_index2, _next_index2, _reply_index2, _envelope_descriptor2, _envelope_hash2) =
        bob_thin_client.read_channel(bob_channel_id, None, None).await?;

    let bob_message_id2 = ThinClient::new_message_id();

    for i in 0..10 {
        println!("Bob: second read attempt {}", i + 1);
        match alice_thin_client.send_channel_query_await_reply(
            bob_channel_id,
            &read_payload2,
            dest_node.clone(),
            dest_queue.clone(),
            bob_message_id2.clone()
        ).await {
            Ok(payload) if !payload.is_empty() => {
                bob_reply_payload = payload;
                break;
            }
            Ok(_) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    assert_eq!(second_message, bob_reply_payload.as_slice(), "Bob: Second reply payload mismatch");

    // Clean up channels
    alice_thin_client.close_channel(alice_channel_id).await?;
    bob_thin_client.close_channel(bob_channel_id).await?;

    alice_thin_client.stop().await;
    bob_thin_client.stop().await;

    println!("✅ Channel API basics test completed successfully");
    Ok(())
}

/// Test resuming a write channel - equivalent to TestResumeWriteChannel from Go
/// This test demonstrates the write channel resumption workflow:
/// 1. Create a write channel
/// 2. Write the first message onto the channel
/// 3. Close the channel
/// 4. Resume the channel
/// 5. Write the second message onto the channel
/// 6. Create a read channel
/// 7. Read first and second message from the channel
/// 8. Verify payloads match
#[tokio::test]
async fn test_resume_write_channel() -> Result<(), Box<dyn std::error::Error>> {
    let alice_thin_client = setup_thin_client().await?;
    let bob_thin_client = setup_thin_client().await?;

    // Wait for PKI documents to be available and connection to mixnet
    println!("Waiting for daemon to connect to mixnet...");
    let mut attempts = 0;
    while !alice_thin_client.is_connected() && attempts < 30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        attempts += 1;
    }

    if !alice_thin_client.is_connected() {
        return Err("Daemon failed to connect to mixnet within 30 seconds".into());
    }

    println!("✅ Daemon connected to mixnet, using current PKI document");

    // Alice creates write channel
    println!("Alice: Creating write channel");
    let (alice_channel_id, read_cap, write_cap) = alice_thin_client.create_write_channel().await?;
    println!("Alice: Created write channel {}", alice_channel_id);

    // Alice writes first message
    let alice_payload1 = b"Hello, Bob!";
    println!("Alice: Writing first message");
    let (write_payload1, _current_message_index1, next_message_index1, _envelope_descriptor1, _envelope_hash1) =
        alice_thin_client.write_channel(alice_channel_id, alice_payload1).await?;

    // Get courier destination
    let (dest_node, dest_queue) = alice_thin_client.get_courier_destination().await?;
    let alice_message_id1 = ThinClient::new_message_id();

    // Send first message
    let _reply1 = alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        &write_payload1,
        dest_node.clone(),
        dest_queue.clone(),
        alice_message_id1
    ).await?;

    println!("Waiting for first message propagation to storage replicas");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Close the channel
    alice_thin_client.close_channel(alice_channel_id).await?;

    // Resume the write channel
    println!("Alice: Resuming write channel");
    let alice_channel_id = alice_thin_client.resume_write_channel(
        write_cap,
        Some(next_message_index1)
    ).await?;
    println!("Alice: Resumed write channel with ID {}", alice_channel_id);

    // Write second message after resume
    println!("Alice: Writing second message after resume");
    let alice_payload2 = b"Second message from Alice!";
    let (write_payload2, _current_message_index2, _next_message_index2, _envelope_descriptor2, _envelope_hash2) =
        alice_thin_client.write_channel(alice_channel_id, alice_payload2).await?;

    let alice_message_id2 = ThinClient::new_message_id();
    let _reply2 = alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        &write_payload2,
        dest_node.clone(),
        dest_queue.clone(),
        alice_message_id2
    ).await?;
    println!("Alice: Second write operation completed successfully");

    println!("Waiting for second message propagation to storage replicas");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Bob creates read channel
    println!("Bob: Creating read channel");
    let bob_channel_id = bob_thin_client.create_read_channel(read_cap).await?;
    println!("Bob: Created read channel {}", bob_channel_id);

    // Bob reads first message
    println!("Bob: Reading first message");
    let (read_payload1, _current_index1, _next_index1, _reply_index1, _envelope_descriptor1, _envelope_hash1) =
        bob_thin_client.read_channel(bob_channel_id, None, None).await?;

    let bob_message_id1 = ThinClient::new_message_id();
    let mut bob_reply_payload1 = vec![];

    for i in 0..10 {
        match alice_thin_client.send_channel_query_await_reply(
            bob_channel_id,
            &read_payload1,
            dest_node.clone(),
            dest_queue.clone(),
            bob_message_id1.clone()
        ).await {
            Ok(payload) if !payload.is_empty() => {
                bob_reply_payload1 = payload;
                break;
            }
            Ok(_) => {
                println!("Bob: First read attempt {} returned empty payload, retrying...", i + 1);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    assert_eq!(alice_payload1, bob_reply_payload1.as_slice(), "Bob: First message payload mismatch");

    // Bob reads second message
    println!("Bob: Reading second message");
    let (read_payload2, _current_index2, _next_index2, _reply_index2, _envelope_descriptor2, _envelope_hash2) =
        bob_thin_client.read_channel(bob_channel_id, None, None).await?;

    let bob_message_id2 = ThinClient::new_message_id();
    let mut bob_reply_payload2 = vec![];

    for i in 0..10 {
        println!("Bob: second message read attempt {}", i + 1);
        match alice_thin_client.send_channel_query_await_reply(
            bob_channel_id,
            &read_payload2,
            dest_node.clone(),
            dest_queue.clone(),
            bob_message_id2.clone()
        ).await {
            Ok(payload) if !payload.is_empty() => {
                bob_reply_payload2 = payload;
                break;
            }
            Ok(_) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Verify the second message content matches
    assert_eq!(alice_payload2, bob_reply_payload2.as_slice(), "Bob: Second message payload mismatch");
    println!("Bob: Successfully received and verified second message");

    // Clean up channels
    alice_thin_client.close_channel(alice_channel_id).await?;
    bob_thin_client.close_channel(bob_channel_id).await?;

    alice_thin_client.stop().await;
    bob_thin_client.stop().await;

    println!("✅ Resume write channel test completed successfully");
    Ok(())
}

/// Test resuming a write channel with query state - equivalent to TestResumeWriteChannelQuery from Go
/// This test demonstrates the write channel query resumption workflow:
/// 1. Create write channel
/// 2. Create first write query message but do not send to channel yet
/// 3. Close channel
/// 4. Resume write channel with query via ResumeWriteChannelQuery
/// 5. Send resumed write query to channel
/// 6. Send second message to channel
/// 7. Create read channel
/// 8. Read both messages from channel
/// 9. Verify payloads match
#[tokio::test]
async fn test_resume_write_channel_query() -> Result<(), Box<dyn std::error::Error>> {
    let alice_thin_client = setup_thin_client().await?;
    let bob_thin_client = setup_thin_client().await?;

    // Wait for PKI documents to be available and connection to mixnet
    println!("Waiting for daemon to connect to mixnet...");
    let mut attempts = 0;
    while !alice_thin_client.is_connected() && attempts < 30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        attempts += 1;
    }

    if !alice_thin_client.is_connected() {
        return Err("Daemon failed to connect to mixnet within 30 seconds".into());
    }

    println!("✅ Daemon connected to mixnet, using current PKI document");

    // Alice creates write channel
    println!("Alice: Creating write channel");
    let (alice_channel_id, read_cap, write_cap) = alice_thin_client.create_write_channel().await?;
    println!("Alice: Created write channel {}", alice_channel_id);

    // Alice prepares first message but doesn't send it yet
    let alice_payload1 = b"Hello, Bob!";
    let (alice_first_write_ciphertext, current_message_index, _next_message_index, envelope_descriptor, envelope_hash) =
        alice_thin_client.write_channel(alice_channel_id, alice_payload1).await?;

    // Get courier destination
    let (courier_node, courier_queue_id) = alice_thin_client.get_courier_destination().await?;
    let alice_message_id1 = ThinClient::new_message_id();

    // Close the channel immediately (like in Go test - no waiting for propagation)
    alice_thin_client.close_channel(alice_channel_id).await?;

    // Resume the write channel with query state using CurrentMessageIndex like Go test
    println!("Alice: Resuming write channel");
    let alice_channel_id = alice_thin_client.resume_write_channel_query(
        write_cap,
        current_message_index, // Use current_message_index like in Go test
        envelope_descriptor,
        envelope_hash
    ).await?;
    println!("Alice: Resumed write channel with ID {}", alice_channel_id);

    // Send the first message after resume
    println!("Alice: Writing first message after resume");
    let _reply1 = alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        &alice_first_write_ciphertext,
        courier_node.clone(),
        courier_queue_id.clone(),
        alice_message_id1
    ).await?;

    // Write second message
    println!("Alice: Writing second message");
    let alice_payload2 = b"Second message from Alice!";
    let (write_payload2, _current_message_index2, _next_message_index2, _envelope_descriptor2, _envelope_hash2) =
        alice_thin_client.write_channel(alice_channel_id, alice_payload2).await?;

    let alice_message_id2 = ThinClient::new_message_id();
    let _reply2 = alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        &write_payload2,
        courier_node.clone(),
        courier_queue_id.clone(),
        alice_message_id2
    ).await?;
    println!("Alice: Second write operation completed successfully");

    println!("Waiting for second message propagation to storage replicas");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Bob creates read channel
    println!("Bob: Creating read channel");
    let bob_channel_id = bob_thin_client.create_read_channel(read_cap).await?;
    println!("Bob: Created read channel {}", bob_channel_id);

    // Bob reads first message
    println!("Bob: Reading first message");
    let (read_payload1, _current_index1, _next_index1, _reply_index1, _envelope_descriptor1, _envelope_hash1) =
        bob_thin_client.read_channel(bob_channel_id, None, None).await?;

    let bob_message_id1 = ThinClient::new_message_id();
    let mut bob_reply_payload1 = vec![];

    for i in 0..10 {
        match alice_thin_client.send_channel_query_await_reply(
            bob_channel_id,
            &read_payload1,
            courier_node.clone(),
            courier_queue_id.clone(),
            bob_message_id1.clone()
        ).await {
            Ok(payload) if !payload.is_empty() => {
                bob_reply_payload1 = payload;
                break;
            }
            Ok(_) => {
                println!("Bob: First read attempt {} returned empty payload, retrying...", i + 1);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    assert_eq!(alice_payload1, bob_reply_payload1.as_slice(), "Bob: First message payload mismatch");

    // Bob reads second message
    println!("Bob: Reading second message");
    let (read_payload2, _current_index2, _next_index2, _reply_index2, _envelope_descriptor2, _envelope_hash2) =
        bob_thin_client.read_channel(bob_channel_id, None, None).await?;

    let bob_message_id2 = ThinClient::new_message_id();
    let mut bob_reply_payload2 = vec![];

    for i in 0..10 {
        println!("Bob: second message read attempt {}", i + 1);
        match alice_thin_client.send_channel_query_await_reply(
            bob_channel_id,
            &read_payload2,
            courier_node.clone(),
            courier_queue_id.clone(),
            bob_message_id2.clone()
        ).await {
            Ok(payload) if !payload.is_empty() => {
                bob_reply_payload2 = payload;
                break;
            }
            Ok(_) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Verify the second message content matches
    assert_eq!(alice_payload2, bob_reply_payload2.as_slice(), "Bob: Second message payload mismatch");
    println!("Bob: Successfully received and verified second message");

    // Clean up channels
    alice_thin_client.close_channel(alice_channel_id).await?;
    bob_thin_client.close_channel(bob_channel_id).await?;

    alice_thin_client.stop().await;
    bob_thin_client.stop().await;

    println!("✅ Resume write channel query test completed successfully");
    Ok(())
}

/// Test resuming a read channel - equivalent to TestResumeReadChannel from Go
/// This test demonstrates the read channel resumption workflow:
/// 1. Create a write channel
/// 2. Write two messages to the channel
/// 3. Create a read channel
/// 4. Read the first message from the channel
/// 5. Verify payload matches
/// 6. Close the read channel
/// 7. Resume the read channel
/// 8. Read the second message from the channel
/// 9. Verify payload matches
#[tokio::test]
async fn test_resume_read_channel() -> Result<(), Box<dyn std::error::Error>> {
    let alice_thin_client = setup_thin_client().await?;
    let bob_thin_client = setup_thin_client().await?;

    // Wait for PKI documents to be available and connection to mixnet
    println!("Waiting for daemon to connect to mixnet...");
    let mut attempts = 0;
    while !alice_thin_client.is_connected() && attempts < 30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        attempts += 1;
    }

    if !alice_thin_client.is_connected() {
        return Err("Daemon failed to connect to mixnet within 30 seconds".into());
    }

    println!("✅ Daemon connected to mixnet, using current PKI document");

    // Alice creates write channel
    println!("Alice: Creating write channel");
    let (alice_channel_id, read_cap, _write_cap) = alice_thin_client.create_write_channel().await?;
    println!("Alice: Created write channel {}", alice_channel_id);

    // Alice writes first message
    let alice_payload1 = b"Hello, Bob!";
    let (write_payload1, _current_message_index1, _next_message_index1, _envelope_descriptor1, _envelope_hash1) =
        alice_thin_client.write_channel(alice_channel_id, alice_payload1).await?;

    let (dest_node, dest_queue) = alice_thin_client.get_courier_destination().await?;
    let alice_message_id1 = ThinClient::new_message_id();

    let _reply1 = alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        &write_payload1,
        dest_node.clone(),
        dest_queue.clone(),
        alice_message_id1
    ).await?;

    println!("Waiting for first message propagation to storage replicas");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Alice writes second message
    println!("Alice: Writing second message");
    let alice_payload2 = b"Second message from Alice!";
    let (write_payload2, _current_message_index2, _next_message_index2, _envelope_descriptor2, _envelope_hash2) =
        alice_thin_client.write_channel(alice_channel_id, alice_payload2).await?;

    let alice_message_id2 = ThinClient::new_message_id();
    let _reply2 = alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        &write_payload2,
        dest_node.clone(),
        dest_queue.clone(),
        alice_message_id2
    ).await?;
    println!("Alice: Second write operation completed successfully");

    println!("Waiting for second message propagation to storage replicas");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Bob creates read channel
    println!("Bob: Creating read channel");
    let bob_channel_id = bob_thin_client.create_read_channel(read_cap.clone()).await?;
    println!("Bob: Created read channel {}", bob_channel_id);

    // Bob reads first message
    println!("Bob: Reading first message");
    let (read_payload1, _current_message_index, next_message_index, reply_index, _envelope_descriptor1, _envelope_hash1) =
        bob_thin_client.read_channel(bob_channel_id, None, None).await?;

    let bob_message_id1 = ThinClient::new_message_id();
    let mut bob_reply_payload1 = vec![];

    for i in 0..10 {
        match alice_thin_client.send_channel_query_await_reply(
            bob_channel_id,
            &read_payload1,
            dest_node.clone(),
            dest_queue.clone(),
            bob_message_id1.clone()
        ).await {
            Ok(payload) if !payload.is_empty() => {
                bob_reply_payload1 = payload;
                break;
            }
            Ok(_) => {
                println!("Bob: First read attempt {} returned empty payload, retrying...", i + 1);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    assert_eq!(alice_payload1, bob_reply_payload1.as_slice(), "Bob: First message payload mismatch");

    // Close the read channel
    bob_thin_client.close_channel(bob_channel_id).await?;

    // Resume the read channel
    println!("Bob: Resuming read channel");
    let bob_channel_id = bob_thin_client.resume_read_channel(
        read_cap,
        Some(next_message_index),
        reply_index
    ).await?;
    println!("Bob: Resumed read channel with ID {}", bob_channel_id);

    // Bob reads second message
    println!("Bob: Reading second message");
    let (read_payload2, _current_message_index2, _next_message_index2, _reply_index2, _envelope_descriptor2, _envelope_hash2) =
        bob_thin_client.read_channel(bob_channel_id, None, None).await?;

    let bob_message_id2 = ThinClient::new_message_id();
    let mut bob_reply_payload2 = vec![];

    for i in 0..10 {
        println!("Bob: second message read attempt {}", i + 1);
        match alice_thin_client.send_channel_query_await_reply(
            bob_channel_id,
            &read_payload2,
            dest_node.clone(),
            dest_queue.clone(),
            bob_message_id2.clone()
        ).await {
            Ok(payload) if !payload.is_empty() => {
                bob_reply_payload2 = payload;
                break;
            }
            Ok(_) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Verify the second message content matches
    assert_eq!(alice_payload2, bob_reply_payload2.as_slice(), "Bob: Second message payload mismatch");
    println!("Bob: Successfully received and verified second message");

    // Clean up channels
    alice_thin_client.close_channel(alice_channel_id).await?;
    bob_thin_client.close_channel(bob_channel_id).await?;

    alice_thin_client.stop().await;
    bob_thin_client.stop().await;

    println!("✅ Resume read channel test completed successfully");
    Ok(())
}

/// Test resuming a read channel with query state - equivalent to TestResumeReadChannelQuery from Go
/// This test demonstrates the read channel query resumption workflow:
/// 1. Create a write channel
/// 2. Write two messages to the channel
/// 3. Create read channel
/// 4. Make read query but do not send it
/// 5. Close read channel
/// 6. Resume read channel query with ResumeReadChannelQuery method
/// 7. Send previously made read query to channel
/// 8. Verify received payload matches
/// 9. Read second message from channel
/// 10. Verify received payload matches
#[tokio::test]
async fn test_resume_read_channel_query() -> Result<(), Box<dyn std::error::Error>> {
    let alice_thin_client = setup_thin_client().await?;
    let bob_thin_client = setup_thin_client().await?;

    // Wait for PKI documents to be available and connection to mixnet
    println!("Waiting for daemon to connect to mixnet...");
    let mut attempts = 0;
    while !alice_thin_client.is_connected() && attempts < 30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        attempts += 1;
    }

    if !alice_thin_client.is_connected() {
        return Err("Daemon failed to connect to mixnet within 30 seconds".into());
    }

    println!("✅ Daemon connected to mixnet, using current PKI document");

    // Alice creates write channel
    println!("Alice: Creating write channel");
    let (alice_channel_id, read_cap, _write_cap) = alice_thin_client.create_write_channel().await?;
    println!("Alice: Created write channel {}", alice_channel_id);

    // Alice writes first message
    let alice_payload1 = b"Hello, Bob!";
    let (write_payload1, _current_message_index1, _next_message_index1, _envelope_descriptor1, _envelope_hash1) =
        alice_thin_client.write_channel(alice_channel_id, alice_payload1).await?;

    let (dest_node, dest_queue) = alice_thin_client.get_courier_destination().await?;
    let alice_message_id1 = ThinClient::new_message_id();

    let _reply1 = alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        &write_payload1,
        dest_node.clone(),
        dest_queue.clone(),
        alice_message_id1
    ).await?;

    println!("Waiting for first message propagation to storage replicas");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Alice writes second message
    println!("Alice: Writing second message");
    let alice_payload2 = b"Second message from Alice!";
    let (write_payload2, _current_message_index2, _next_message_index2, _envelope_descriptor2, _envelope_hash2) =
        alice_thin_client.write_channel(alice_channel_id, alice_payload2).await?;

    let alice_message_id2 = ThinClient::new_message_id();
    let _reply2 = alice_thin_client.send_channel_query_await_reply(
        alice_channel_id,
        &write_payload2,
        dest_node.clone(),
        dest_queue.clone(),
        alice_message_id2
    ).await?;
    println!("Alice: Second write operation completed successfully");

    println!("Waiting for second message propagation to storage replicas");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Bob creates read channel
    println!("Bob: Creating read channel");
    let bob_channel_id = bob_thin_client.create_read_channel(read_cap.clone()).await?;
    println!("Bob: Created read channel {}", bob_channel_id);

    // Bob prepares first read query but doesn't send it yet
    println!("Bob: Reading first message");
    let (read_payload1, current_message_index, _next_message_index, reply_index, envelope_descriptor, envelope_hash) =
        bob_thin_client.read_channel(bob_channel_id, None, None).await?;

    // Close the read channel
    bob_thin_client.close_channel(bob_channel_id).await?;

    // Resume the read channel with query state
    println!("Bob: Resuming read channel");
    let bob_channel_id = bob_thin_client.resume_read_channel_query(
        read_cap,
        current_message_index,
        reply_index,
        envelope_descriptor,
        envelope_hash
    ).await?;
    println!("Bob: Resumed read channel with ID {}", bob_channel_id);

    // Send the first read query and get the message payload
    let bob_message_id1 = ThinClient::new_message_id();
    let mut bob_reply_payload1 = vec![];

    for i in 0..10 {
        println!("Bob: first message read attempt {}", i + 1);
        match alice_thin_client.send_channel_query_await_reply(
            bob_channel_id,
            &read_payload1,
            dest_node.clone(),
            dest_queue.clone(),
            bob_message_id1.clone()
        ).await {
            Ok(payload) if !payload.is_empty() => {
                bob_reply_payload1 = payload;
                break;
            }
            Ok(_) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    assert_eq!(alice_payload1, bob_reply_payload1.as_slice(), "Bob: First message payload mismatch");

    // Bob reads second message
    println!("Bob: Reading second message");
    let (read_payload2, _current_message_index2, _next_message_index2, _reply_index2, _envelope_descriptor2, _envelope_hash2) =
        bob_thin_client.read_channel(bob_channel_id, None, None).await?;

    let bob_message_id2 = ThinClient::new_message_id();
    let mut bob_reply_payload2 = vec![];

    for i in 0..10 {
        println!("Bob: second message read attempt {}", i + 1);
        match alice_thin_client.send_channel_query_await_reply(
            bob_channel_id,
            &read_payload2,
            dest_node.clone(),
            dest_queue.clone(),
            bob_message_id2.clone()
        ).await {
            Ok(payload) if !payload.is_empty() => {
                bob_reply_payload2 = payload;
                break;
            }
            Ok(_) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Verify the second message content matches
    assert_eq!(alice_payload2, bob_reply_payload2.as_slice(), "Bob: Second message payload mismatch");
    println!("Bob: Successfully received and verified second message");

    // Clean up channels
    alice_thin_client.close_channel(alice_channel_id).await?;
    bob_thin_client.close_channel(bob_channel_id).await?;

    alice_thin_client.stop().await;
    bob_thin_client.stop().await;

    println!("✅ Resume read channel query test completed successfully");
    Ok(())
}
