// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! High-level PigeonholeClient API integration tests.
//! These tests require a running mixnet with client daemon for integration testing.

use std::sync::Arc;
use std::time::Duration;

use rand::RngCore;

use katzenpost_thin_client::persistent::{PigeonholeClient, ReadChannel, WriteChannel};
use katzenpost_thin_client::{Config, ThinClient};

/// Test helper that brings up two thin clients pointing at the same daemon.
async fn setup_clients() -> Result<(Arc<ThinClient>, Arc<ThinClient>), Box<dyn std::error::Error>> {
    let alice_config = Config::new("testdata/thinclient.toml")?;
    let alice_client = ThinClient::new(alice_config).await?;

    let bob_config = Config::new("testdata/thinclient.toml")?;
    let bob_client = ThinClient::new(bob_config).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    Ok((alice_client, bob_client))
}

/// A matched pair of channels backed by a freshly-generated capability set.
/// The start index is retained for tests that need to address specific boxes
/// without relying on the channel's internally-tracked `next_index`.
struct ChannelPair {
    writer: WriteChannel,
    reader: ReadChannel,
    start_index: Vec<u8>,
}

async fn make_pair(
    alice: &PigeonholeClient,
    bob: &PigeonholeClient,
    alice_thin: &Arc<ThinClient>,
    name: &str,
) -> ChannelPair {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let kp = alice_thin
        .new_keypair(&seed)
        .await
        .expect("Failed to generate keypair");
    let writer = alice
        .load_write_channel(name, &kp.write_cap, &kp.first_message_index)
        .expect("Failed to load write channel");
    let reader = bob
        .load_read_channel(name, &kp.read_cap, &kp.first_message_index)
        .expect("Failed to load read channel");
    ChannelPair {
        writer,
        reader,
        start_index: kp.first_message_index,
    }
}

#[tokio::test]
async fn test_high_level_send_receive() {
    println!("\n=== Test: High-level API - Alice sends message to Bob ===");

    let (alice_thin, bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");
    let bob = PigeonholeClient::new_in_memory(bob_thin.clone())
        .expect("Failed to create Bob's PigeonholeClient");

    println!("\n--- Step 1: Alice generates keypair, both sides load their channel ---");
    let ChannelPair { mut writer, mut reader, .. } =
        make_pair(&alice, &bob, &alice_thin, "alice-to-bob").await;
    println!("✓ Alice has a write channel; Bob has a read channel");

    println!("\n--- Step 2: Alice sends a message ---");
    let message = b"Hello Bob! This is a secret message from Alice.";
    writer.send(message).await.expect("Failed to send message");
    println!("✓ Alice sent message: {:?}", String::from_utf8_lossy(message));

    // No propagation sleep: the retrying read below gates itself on BoxIDNotFound until the box propagates.

    println!("\n--- Step 3: Bob receives the message ---");
    let received = reader.receive().await.expect("Failed to receive message");
    println!("✓ Bob received message: {:?}", String::from_utf8_lossy(&received));

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

    let ChannelPair { mut writer, mut reader, .. } =
        make_pair(&alice, &bob, &alice_thin, "multi-msg-channel").await;

    let messages = vec![
        b"Message 1: Hello!".to_vec(),
        b"Message 2: How are you?".to_vec(),
        b"Message 3: Goodbye!".to_vec(),
    ];

    println!("\n--- Alice sends {} messages ---", messages.len());
    for (i, msg) in messages.iter().enumerate() {
        writer.send(msg).await.expect("Failed to send message");
        println!("✓ Sent message {}: {:?}", i + 1, String::from_utf8_lossy(msg));
    }

    // No propagation sleep: the retrying read below gates itself on BoxIDNotFound until the box propagates.

    println!("\n--- Bob receives messages ---");
    for (i, expected_msg) in messages.iter().enumerate() {
        let received = reader.receive().await.expect("Failed to receive message");
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

    let ChannelPair { writer, reader, start_index } =
        make_pair(&alice, &bob, &alice_thin, "low-level-test").await;

    println!("\n--- Alice writes to box using write_box ---");
    let message = b"Direct box write test";
    writer
        .write_box(message, &start_index)
        .await
        .expect("Failed to write box");
    println!("✓ Alice wrote to box at index");

    // No propagation sleep: the retrying read below gates itself on BoxIDNotFound until the box propagates.

    println!("\n--- Bob reads from box using read_box ---");
    let (received, _next_index) = reader
        .read_box(&start_index)
        .await
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

    let ChannelPair { writer: channel1, reader: bob_channel1, start_index: dest1_index } =
        make_pair(&alice, &bob, &alice_thin, "multi-dest-1").await;
    let ChannelPair { writer: channel2, reader: bob_channel2, start_index: dest2_index } =
        make_pair(&alice, &bob, &alice_thin, "multi-dest-2").await;

    let dest1_write_cap = channel1.write_cap().to_vec();
    let dest2_write_cap = channel2.write_cap().to_vec();

    let payload1 = b"Secret message for Channel 1";
    let payload2 = b"Secret message for Channel 2";

    println!("\n--- Creating copy stream with multiple destinations ---");

    let mut builder = channel1
        .copy_stream_builder()
        .await
        .expect("Failed to create copy stream builder");

    let destinations: Vec<(&[u8], &[u8], &[u8])> = vec![
        (payload1.as_slice(), &dest1_write_cap, &dest1_index),
        (payload2.as_slice(), &dest2_write_cap, &dest2_index),
    ];

    builder
        .add_multi_payload(destinations, true)
        .await
        .expect("Failed to add multi payload");
    println!("✓ Added payloads for both destinations in single call");

    let boxes_written = builder.finish().await.expect("Failed to finish copy stream");
    println!("✓ Copy stream finished, {} boxes written", boxes_written);

    // No propagation sleep: the retrying read of the destination box gates itself until the copy lands.

    println!("\n--- Bob reads from Channel 1 ---");
    let (received1, _) = bob_channel1
        .read_box(bob_channel1.next_index())
        .await
        .expect("Failed to read from channel 1");
    println!("✓ Channel 1: {:?}", String::from_utf8_lossy(&received1));

    println!("\n--- Bob reads from Channel 2 ---");
    let (received2, _) = bob_channel2
        .read_box(bob_channel2.next_index())
        .await
        .expect("Failed to read from channel 2");
    println!("✓ Channel 2: {:?}", String::from_utf8_lossy(&received2));

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

    let ChannelPair { mut writer, mut reader, start_index } =
        make_pair(&alice, &bob, &alice_thin, "tombstone-test").await;

    println!("\n--- Step 1: Alice sends a message ---");
    let message = b"This message will be tombstoned";
    writer.send(message).await.expect("Failed to send message");
    println!("✓ Alice sent message");

    // No propagation sleep: the retrying read below gates itself on BoxIDNotFound until the box propagates.

    println!("\n--- Step 2: Bob reads the message ---");
    let received = reader.receive().await.expect("Failed to receive");
    println!("✓ Bob received: {:?}", String::from_utf8_lossy(&received));
    assert_eq!(received, message);

    println!("\n--- Step 3: Alice tombstones the box ---");
    writer
        .tombstone_at(&start_index)
        .await
        .expect("Failed to tombstone");
    println!("✓ Alice tombstoned the box");

    println!("\n--- Step 4: Bob polls the box until tombstoned ---");
    reader.refresh().expect("Failed to refresh");
    const MAX_ATTEMPTS: u32 = 6;
    const POLL_INTERVAL_SECS: u64 = 10;
    let mut tombstone_verified = false;

    for attempt in 1..=MAX_ATTEMPTS {
        println!("Polling for tombstone (attempt {}/{})...", attempt, MAX_ATTEMPTS);
        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;

        match reader.read_box(&start_index).await {
            Err(katzenpost_thin_client::persistent::PigeonholeDbError::ThinClient(
                katzenpost_thin_client::ThinClientError::Tombstone,
            )) => {
                tombstone_verified = true;
                println!("✓ Bob verified tombstone on attempt {}", attempt);
                break;
            }
            Ok(_) => {
                println!("  Still seeing original message, retrying...");
            }
            other => panic!("Unexpected outcome reading tombstone: {:?}", other),
        }
    }

    assert!(tombstone_verified, "Tombstone not propagated after {} attempts", MAX_ATTEMPTS);

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

    let ChannelPair { mut writer, mut reader, start_index } =
        make_pair(&alice, &bob, &alice_thin, "tombstone-range-test").await;

    let num_messages = 3u32;
    println!("\n--- Step 1: Alice sends {} messages ---", num_messages);
    for i in 0..num_messages {
        let msg = format!("Message {} to be tombstoned", i + 1);
        writer.send(msg.as_bytes()).await.expect("Failed to send");
        println!("✓ Sent message {}", i + 1);
    }

    // No propagation sleep: the retrying read below gates itself on BoxIDNotFound until the box propagates.

    println!("\n--- Step 2: Verify Bob can read messages ---");
    for i in 0..num_messages {
        let received = reader.receive().await.expect("Failed to receive");
        println!("✓ Read message {}: {:?}", i + 1, String::from_utf8_lossy(&received));
    }

    println!("\n--- Step 3: Alice tombstones {} boxes ---", num_messages);
    writer
        .tombstone_from(&start_index, num_messages)
        .await
        .expect("Failed to tombstone range");
    println!("✓ Alice sent tombstone range");

    println!("\n--- Step 4: Poll the first box until tombstoned, then verify all ---");
    const MAX_ATTEMPTS: u32 = 6;
    const POLL_INTERVAL_SECS: u64 = 10;
    let mut tombstone_verified = false;

    for attempt in 1..=MAX_ATTEMPTS {
        println!("Polling for tombstone (attempt {}/{})...", attempt, MAX_ATTEMPTS);
        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;

        match reader.read_box(&start_index).await {
            Err(katzenpost_thin_client::persistent::PigeonholeDbError::ThinClient(
                katzenpost_thin_client::ThinClientError::Tombstone,
            )) => {
                tombstone_verified = true;
                println!("✓ First box tombstoned on attempt {}", attempt);
                break;
            }
            Ok(_) => {
                println!("  Still seeing original message, retrying...");
            }
            other => panic!("Unexpected outcome reading tombstone: {:?}", other),
        }
    }

    assert!(tombstone_verified, "Tombstone not propagated after {} attempts", MAX_ATTEMPTS);

    let mut current_index = start_index;
    for i in 0..num_messages {
        match reader.read_box(&current_index).await {
            Err(katzenpost_thin_client::persistent::PigeonholeDbError::ThinClient(
                katzenpost_thin_client::ThinClientError::Tombstone,
            )) => {
                println!("✓ Box {} is tombstoned", i + 1);
            }
            other => panic!("Box {} should be tombstoned, got: {:?}", i + 1, other),
        }

        if i < num_messages - 1 {
            current_index = bob_thin
                .next_message_box_index(&current_index)
                .await
                .expect("Failed to advance index");
        }
    }

    println!("\n✅ Tombstone range test passed!");
}

#[tokio::test]
async fn test_stream_buffer_returned_from_payload() {
    println!("\n=== Test: Buffer state returned from create_courier_envelopes_from_payload ===");

    let (alice_thin, _bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let kp = alice_thin
        .new_keypair(&seed)
        .await
        .expect("Failed to generate keypair");

    let payload = b"Test payload data for buffering".to_vec();

    let result = alice_thin
        .create_courier_envelopes_from_payload(
            &payload,
            &kp.write_cap,
            &kp.first_message_index,
            true,  // is_start
            false, // is_last
        )
        .await
        .expect("Failed to create envelopes");

    println!("✓ Got {} envelopes", result.envelopes.len());
    assert!(result.next_dest_index.is_some(), "Should return next_dest_index");
    println!("✓ next_dest_index returned");

    println!("\n✅ Stateless payload test passed!");
}

#[tokio::test]
async fn test_stateless_payload_multi_call_next_index() {
    println!("\n=== Test: Stateless FromPayload multi-call with next_dest_index chaining ===");

    let (alice_thin, _bob_thin) = setup_clients().await.expect("Failed to setup clients");

    println!("\n--- Step 1: Setup capability ---");
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let kp = alice_thin
        .new_keypair(&seed)
        .await
        .expect("Failed to generate keypair");
    println!("✓ Capability material generated");

    println!("\n--- Step 2: First call (is_start=true, is_last=false) ---");
    let first_payload = b"First chunk of data for multi-call test".to_vec();
    let result1 = alice_thin
        .create_courier_envelopes_from_payload(
            &first_payload,
            &kp.write_cap,
            &kp.first_message_index,
            true,  // is_start
            false, // is_last
        )
        .await
        .expect("First call failed");
    assert!(result1.next_dest_index.is_some(), "Should return next_dest_index");
    println!(
        "✓ First call: {} envelopes, next_dest_index returned",
        result1.envelopes.len()
    );

    println!("\n--- Step 3: Second call (is_start=false, is_last=true) ---");
    let second_payload = b"Second chunk completing the stream".to_vec();
    let result2 = alice_thin
        .create_courier_envelopes_from_payload(
            &second_payload,
            &kp.write_cap,
            result1.next_dest_index.as_ref().unwrap(),
            false, // is_start
            true,  // is_last
        )
        .await
        .expect("Second call failed");
    assert!(result2.next_dest_index.is_some(), "Should return next_dest_index");
    println!(
        "✓ Second call: {} envelopes, next_dest_index returned",
        result2.envelopes.len()
    );

    println!("\n✅ Stateless multi-call with next_dest_index chaining test passed!");
}

#[tokio::test]
async fn test_read_box_no_retry() {
    println!("\n=== Test: read_box_no_retry returns immediate error for non-existent box ===");

    let (alice_thin, _bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");

    // For a no-retry read test we only need the read side; generate a keypair
    // and load just the read channel against it.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let kp = alice_thin
        .new_keypair(&seed)
        .await
        .expect("Failed to generate keypair");
    let reader = alice
        .load_read_channel("read-no-retry-test", &kp.read_cap, &kp.first_message_index)
        .expect("Failed to load read channel");

    println!("\n--- Attempting read_box_no_retry on empty box ---");
    let result = reader.read_box_no_retry(&kp.first_message_index).await;

    match result {
        Err(e) => {
            let err_str = format!("{:?}", e);
            println!("✓ Got expected error: {}", err_str);
            assert!(
                err_str.contains("BoxNotFound") || err_str.contains("box id not found"),
                "Expected BoxNotFound error, got: {}",
                err_str
            );
        }
        Ok(_) => panic!("Expected BoxNotFound error, but read succeeded"),
    }

    println!("\n✅ read_box_no_retry test passed!");
}

#[tokio::test]
async fn test_receive_no_retry() {
    println!("\n=== Test: receive_no_retry returns immediate error for non-existent message ===");

    let (alice_thin, _bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let kp = alice_thin
        .new_keypair(&seed)
        .await
        .expect("Failed to generate keypair");
    let mut reader = alice
        .load_read_channel("receive-no-retry-test", &kp.read_cap, &kp.first_message_index)
        .expect("Failed to load read channel");

    println!("\n--- Attempting receive_no_retry on empty channel ---");
    let result = reader.receive_no_retry().await;

    match result {
        Err(e) => {
            let err_str = format!("{:?}", e);
            println!("✓ Got expected error: {}", err_str);
            assert!(
                err_str.contains("BoxNotFound") || err_str.contains("box id not found"),
                "Expected BoxNotFound error, got: {}",
                err_str
            );
        }
        Ok(_) => panic!("Expected BoxNotFound error, but receive succeeded"),
    }

    println!("\n✅ receive_no_retry test passed!");
}

#[tokio::test]
async fn test_write_box_return_box_exists() {
    println!("\n=== Test: write_box_return_box_exists returns error on duplicate write ===");

    let (alice_thin, _bob_thin) = setup_clients().await.expect("Failed to setup clients");

    let alice = PigeonholeClient::new_in_memory(alice_thin.clone())
        .expect("Failed to create Alice's PigeonholeClient");

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let kp = alice_thin
        .new_keypair(&seed)
        .await
        .expect("Failed to generate keypair");
    let writer = alice
        .load_write_channel("write-box-exists-test", &kp.write_cap, &kp.first_message_index)
        .expect("Failed to load write channel");
    let reader = alice
        .load_read_channel("write-box-exists-test", &kp.read_cap, &kp.first_message_index)
        .expect("Failed to load read channel");
    let start_index = kp.first_message_index.clone();

    println!("\n--- First write_box ---");
    let message1 = b"First message";
    writer
        .write_box(message1, &start_index)
        .await
        .expect("First write should succeed");
    println!("✓ First write succeeded");

    // Deterministic propagation gate: a retrying read of the just-written box returns only once it has landed, replacing a blind sleep.
    let _ = reader.read_box(&start_index).await;

    println!("\n--- Second write_box_return_box_exists to same index ---");
    let message2 = b"Second message";
    let result = writer.write_box_return_box_exists(message2, &start_index).await;

    match result {
        Err(e) => {
            let err_str = format!("{:?}", e);
            println!("✓ Got expected error: {}", err_str);
            assert!(
                err_str.contains("BoxAlreadyExists") || err_str.contains("box already exists"),
                "Expected BoxAlreadyExists error, got: {}",
                err_str
            );
        }
        Ok(_) => panic!("Expected BoxAlreadyExists error, but write succeeded"),
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

    let ChannelPair { mut writer, reader, .. } =
        make_pair(&alice, &bob, &alice_thin, "send-box-exists-test").await;

    println!("\n--- First send ---");
    let message1 = b"First message";
    writer.send(message1).await.expect("First send should succeed");
    println!("✓ First send succeeded");

    // Deterministic propagation gate: a retrying read of the just-written box returns only once it has landed, replacing a blind sleep.
    let mut reader = reader;
    let _ = reader.receive().await;

    // Manually write to the channel's CURRENT next_index (already advanced past
    // the first send) to set up a conflict for the next send.
    let current_next = writer.next_index().to_vec();
    println!("\n--- Writing directly to current next_index to create conflict ---");
    writer
        .write_box(b"Conflict message", &current_next)
        .await
        .expect("Direct write should succeed");
    println!("✓ Conflict message written");

    // Deterministic propagation gate: a retrying read of the just-written box returns only once it has landed, replacing a blind sleep.
    let _ = reader.read_box(&current_next).await;

    println!("\n--- Attempting send_return_box_exists ---");
    let result = writer.send_return_box_exists(b"This should fail").await;

    match result {
        Err(e) => {
            let err_str = format!("{:?}", e);
            println!("✓ Got expected error: {}", err_str);
            assert!(
                err_str.contains("BoxAlreadyExists") || err_str.contains("box already exists"),
                "Expected BoxAlreadyExists error, got: {}",
                err_str
            );
        }
        Ok(_) => panic!("Expected BoxAlreadyExists error, but send succeeded"),
    }

    println!("\n✅ send_return_box_exists test passed!");
}
