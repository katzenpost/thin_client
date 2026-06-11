// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Integration test for `get_directory_authorities`.
//!
//! Requires a running mixnet with a client daemon, as the method is a
//! round-trip to the daemon for its configured voting authority peers.

use std::time::Duration;

use katzenpost_thin_client::{Config, ThinClient};

async fn setup_thin_client() -> Result<std::sync::Arc<ThinClient>, Box<dyn std::error::Error>> {
    let config = Config::new("testdata/thinclient.toml")?;
    let client = ThinClient::new(config).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(client)
}

#[tokio::test]
async fn test_get_directory_authorities() {
    let client = setup_thin_client()
        .await
        .expect("Failed to setup client");

    let authorities = client
        .get_directory_authorities()
        .await
        .expect("get_directory_authorities should succeed");

    assert!(
        !authorities.is_empty(),
        "daemon should report its configured directory authorities"
    );

    for authority in &authorities {
        assert!(
            !authority.identifier.is_empty(),
            "every authority must have an identifier"
        );
        assert_eq!(
            authority.identity_key_hash.len(),
            32,
            "identity_key_hash must be a 32-byte fingerprint for {}",
            authority.identifier
        );
        assert!(
            !authority.identity_public_key_pem.is_empty(),
            "every authority must carry its identity public key in PEM"
        );
        println!(
            "authority {} fingerprint {}",
            authority.identifier,
            hex::encode(&authority.identity_key_hash)
        );
    }
}
