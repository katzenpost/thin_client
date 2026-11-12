// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Stateless courier-envelope API integration tests.
//! These tests require a running mixnet with client daemon for integration testing.

use std::sync::Arc;
use std::time::Duration;

use rand::RngCore;

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
