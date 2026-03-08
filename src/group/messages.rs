// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Group chat message types.

use blake2::{Blake2b, Digest};
use generic_array::typenum::U32;
use serde::{Deserialize, Serialize};

/// Introduction: display name + read capability + start index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Introduction {
    pub display_name: String,
    #[serde(with = "serde_bytes")]
    pub read_cap: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub start_index: Vec<u8>,
}

impl Introduction {
    pub fn new(display_name: &str, read_cap: Vec<u8>, start_index: Vec<u8>) -> Self {
        Self {
            display_name: display_name.to_string(),
            read_cap,
            start_index,
        }
    }
}

/// Group chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupChatMessage {
    /// Membership hash for consistency checking.
    #[serde(with = "serde_bytes")]
    pub membership_hash: Vec<u8>,
    /// Text payload (UTF-8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Introduction of a new member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introduction: Option<Introduction>,
}

impl GroupChatMessage {
    pub fn text(membership_hash: Vec<u8>, text: &str) -> Self {
        Self {
            membership_hash,
            text: Some(text.to_string()),
            introduction: None,
        }
    }

    pub fn introduction(membership_hash: Vec<u8>, display_name: &str, read_cap: Vec<u8>, start_index: Vec<u8>) -> Self {
        Self {
            membership_hash,
            text: None,
            introduction: Some(Introduction::new(display_name, read_cap, start_index)),
        }
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, serde_cbor::Error> {
        serde_cbor::to_vec(self)
    }

    pub fn from_cbor(data: &[u8]) -> Result<Self, serde_cbor::Error> {
        serde_cbor::from_slice(data)
    }
}

/// Compute membership hash from sorted read capabilities.
pub fn compute_membership_hash(read_caps: &[&[u8]]) -> Vec<u8> {
    let mut sorted: Vec<&[u8]> = read_caps.to_vec();
    sorted.sort();
    let mut hasher = Blake2b::<U32>::new();
    for cap in sorted {
        hasher.update(cap);
    }
    hasher.finalize().to_vec()
}

