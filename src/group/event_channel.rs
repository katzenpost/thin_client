// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Typed event channel wrapping a persistent ChannelHandle.
//!
//! `EventChannel<E>` serializes events of type `E` to CBOR before writing
//! to the underlying pigeonhole box, and deserializes on read.  This is the
//! primitive used by `GroupChannel<E>` and any higher-level protocol that
//! wants typed, ordered streams over Pigeonhole.
//!
//! # Channel rotation (future work)
//!
//! For post-compromise security each member should periodically rotate to a
//! fresh channel.  The rotation handshake requires the writer to receive an
//! ACK from every reader confirming they have imported the new read cap before
//! the old channel can be retired.  `EventChannel` is intentionally kept
//! simple so that rotation can be layered on top without changing its core
//! encode/decode contract.

use std::marker::PhantomData;

use serde::{Serialize, de::DeserializeOwned};

use crate::persistent::{ChannelHandle, ReadCapability};
use crate::persistent::error::{PigeonholeDbError, Result};

/// A typed, CBOR-encoded wrapper around a [`ChannelHandle`].
///
/// Every event sent through an `EventChannel<E>` is serialized with
/// `serde_cbor` before being handed to the underlying channel, and
/// deserialized on receipt.  The wire format is therefore opaque bytes from
/// the pigeonhole layer's perspective.
pub struct EventChannel<E> {
    handle: ChannelHandle,
    _phantom: PhantomData<E>,
}

impl<E: Serialize + DeserializeOwned> EventChannel<E> {
    /// Wrap an existing `ChannelHandle`.
    pub fn new(handle: ChannelHandle) -> Self {
        Self { handle, _phantom: PhantomData }
    }

    /// Consume the wrapper and return the underlying handle.
    pub fn into_inner(self) -> ChannelHandle {
        self.handle
    }

    /// Borrow the underlying handle.
    pub fn inner(&self) -> &ChannelHandle {
        &self.handle
    }

    /// Mutably borrow the underlying handle.
    pub fn inner_mut(&mut self) -> &mut ChannelHandle {
        &mut self.handle
    }

    pub fn name(&self) -> &str {
        self.handle.name()
    }

    pub fn is_owned(&self) -> bool {
        self.handle.is_owned()
    }

    pub fn read_cap(&self) -> &[u8] {
        self.handle.read_cap()
    }

    pub fn share_read_capability(&self) -> ReadCapability {
        self.handle.share_read_capability()
    }

    /// Serialize `event` to CBOR and write it to the next box in the channel.
    pub async fn send(&mut self, event: &E) -> Result<()> {
        let bytes = serde_cbor::to_vec(event)
            .map_err(|e| PigeonholeDbError::Other(format!("CBOR encode error: {}", e)))?;
        self.handle.send(&bytes).await
    }

    /// Read the next box and deserialize it as `E`.
    ///
    /// Blocks (with ARQ retries) until a message arrives.
    pub async fn receive(&mut self) -> Result<E> {
        let bytes = self.handle.receive().await?;
        serde_cbor::from_slice(&bytes)
            .map_err(|e| PigeonholeDbError::Other(format!("CBOR decode error: {}", e)))
    }

    /// Like [`receive`] but returns [`ThinClientError::BoxNotFound`] immediately
    /// instead of retrying when the box does not exist yet.
    pub async fn receive_no_retry(&mut self) -> Result<E> {
        let bytes = self.handle.receive_no_retry().await?;
        serde_cbor::from_slice(&bytes)
            .map_err(|e| PigeonholeDbError::Other(format!("CBOR decode error: {}", e)))
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};


    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_cbor_roundtrip_string() {
        let original = "hello pigeonhole".to_string();
        let bytes = serde_cbor::to_vec(&original).unwrap();
        let decoded: String = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_cbor_roundtrip_enum() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        enum TestEvent {
            Increment { actor: String, amount: u64 },
            Reset,
        }

        let cases = vec![
            TestEvent::Increment { actor: "Alice".to_string(), amount: 42 },
            TestEvent::Reset,
        ];

        for event in cases {
            let bytes = serde_cbor::to_vec(&event).unwrap();
            let decoded: TestEvent = serde_cbor::from_slice(&bytes).unwrap();
            assert_eq!(event, decoded);
        }
    }

    #[test]
    fn test_cbor_roundtrip_gcounter_dot() {
        // GCounter<String>::Op = Dot<String> — verify it is round-trippable.
        use crdts::Dot;
        let op: Dot<String> = Dot::new("Alice".to_string(), 7);
        let bytes = serde_cbor::to_vec(&op).unwrap();
        let decoded: Dot<String> = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(op, decoded);
    }

    // -----------------------------------------------------------------------
    // CRDT fold logic (no network required)
    // -----------------------------------------------------------------------

    #[test]
    fn test_gcounter_fold_over_ops() {
        use crdts::{CmRDT, Dot, GCounter};

        // Simulate three members each broadcasting one increment op through
        // their own stream.  A reader collects all ops and folds them.
        let ops = vec![
            Dot::new("Alice".to_string(), 1u64),
            Dot::new("Bob".to_string(), 1u64),
            Dot::new("Carol".to_string(), 1u64),
        ];

        let mut counter: GCounter<String> = GCounter::new();
        for op in ops {
            counter.apply(op);
        }

        assert_eq!(counter.read().to_string(), "3");
    }

    #[test]
    fn test_gcounter_fold_respects_per_actor_max() {
        use crdts::{CmRDT, Dot, GCounter};

        // If we receive two ops from the same actor, only the larger one wins.
        // This mirrors what happens when a member resends an op and the
        // GCounter's max-per-actor semantics deduplicate it.
        let mut counter: GCounter<String> = GCounter::new();
        counter.apply(Dot::new("Alice".to_string(), 3u64));
        counter.apply(Dot::new("Alice".to_string(), 1u64)); // lower — ignored
        counter.apply(Dot::new("Bob".to_string(), 2u64));

        // GCounter keeps the max per actor: Alice=3, Bob=2 → total=5
        assert_eq!(counter.read().to_string(), "5");
    }

    #[test]
    fn test_state_fold_pattern() {
        // Demonstrate `state = fold(events)` concretely without any network.
        // Each event is a Dot<String> serialized to CBOR, as it would arrive
        // from an EventChannel.
        use crdts::{CmRDT, Dot, GCounter};

        let events_on_wire: Vec<Vec<u8>> = vec![
            serde_cbor::to_vec(&Dot::new("Alice".to_string(), 2u64)).unwrap(),
            serde_cbor::to_vec(&Dot::new("Bob".to_string(), 5u64)).unwrap(),
        ];

        let mut counter: GCounter<String> = GCounter::new();
        for bytes in &events_on_wire {
            let op: Dot<String> = serde_cbor::from_slice(bytes).unwrap();
            counter.apply(op);
        }

        assert_eq!(counter.read().to_string(), "7");
    }
}
