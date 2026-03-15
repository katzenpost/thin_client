// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Generic group channel: each member owns one `EventChannel<E>` for writing;
//! the others hold imported read-only `EventChannel<E>`s for every peer.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::Mutex;

use crate::persistent::error::{PigeonholeDbError, Result};
use crate::persistent::{PigeonholeClient, ReadCapability};

use super::event_channel::EventChannel;

/// Out-of-band introduction: a member's display name, read capability, and
/// starting index.  Exchanged directly (e.g. QR code, secure side-channel)
/// to bootstrap group membership, or sent in-band as an application event
/// when one member wants to introduce another.
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

    /// A stable, collision-resistant identifier derived from the read
    /// capability bytes.  Two `Introduction`s with the same `display_name`
    /// but different read caps produce different IDs, preventing silent map
    /// collisions.  Used as the `HashMap` key and as the channel name
    /// component in the database.
    pub fn member_id(&self) -> String {
        hex::encode(Blake2s256::digest(&self.read_cap))
    }
}

/// An event received from a specific group member.
#[derive(Debug, Clone)]
pub struct ReceivedGroupEvent<E> {
    pub sender: String,
    pub event: E,
}

/// A group where every member publishes to their own `EventChannel<E>` and
/// reads from every other member's channel.
///
/// # Type parameter
///
/// `E` is the application event type.  It must be serializable with
/// `serde` (CBOR encoding is used on the wire).  Examples:
///
/// - A simple `enum ChatEvent { Text(String), Introduction(Introduction) }`
///   for plain group chat.
/// - A CRDT operation type such as `Dot<String>` (a `GCounter<String>` op)
///   for replicated-state applications.
///
/// # Receiving
///
/// Use [`receive_from`] to block until a specific member's next message
/// arrives, or [`receive_any`] to race all member channels and return
/// whichever delivers first.  Both rely on the daemon's ARQ mechanism
/// rather than an application-level sleep/poll loop.
///
/// # Channel rotation (future work)
///
/// For post-compromise security, each member should periodically rotate to a
/// freshly generated channel.  The rotation handshake requires the writer to
/// receive an explicit ACK from every reader confirming they have imported the
/// new read cap before the old channel is retired.  This is not yet
/// implemented; the current design keeps a single `EventChannel<E>` per
/// member for simplicity.
pub struct GroupChannel<E> {
    pub name: String,
    pub my_display_name: String,
    /// Cached at creation; immutable, so no lock needed to share it.
    my_introduction: Introduction,
    /// Wrapped in `Arc<Mutex<...>>` so `send` takes `&self` and can be
    /// called concurrently with `receive_from_all` in `tokio::join!`.
    my_channel: Arc<Mutex<EventChannel<E>>>,
    /// The member map is wrapped in `Arc<RwLock<...>>` so that `add_member`
    /// and `remove_member` take `&self` and can run concurrently with `send`.
    /// Receive methods take a snapshot (clone of `Arc`s) under a brief read
    /// lock, then do all async work outside it.  A `std::sync::RwLock` is
    /// used rather than `tokio::sync::RwLock` because every map operation is
    /// synchronous; the async work lives inside the per-channel `Mutex`.
    ///
    /// Key: `Introduction::member_id()` (Blake2s-256 hex of the read cap).
    /// Value: `(display_name, channel)` — display_name is stored alongside
    /// the channel so that `ReceivedGroupEvent::sender` stays human-readable.
    member_channels: Arc<RwLock<HashMap<String, (String, Arc<Mutex<EventChannel<E>>>)>>>,
    /// Events that were received by a `receive_any` call alongside the winner
    /// but not yet returned to the caller.  Because `ChannelHandle::receive`
    /// advances the persistent read cursor before it returns, any result that
    /// is produced must eventually be delivered — it cannot be silently
    /// discarded.  Buffered events are drained in FIFO order by the next
    /// `receive_any` call before new network I/O is issued.
    receive_any_buffer: Mutex<VecDeque<ReceivedGroupEvent<E>>>,
}

impl<E: Serialize + DeserializeOwned + Send + 'static> GroupChannel<E> {
    /// Create a new group and generate the local member's channel.
    pub async fn create(
        pigeonhole: &PigeonholeClient,
        group_name: &str,
        my_display_name: &str,
    ) -> Result<Self> {
        let my_channel_name = format!("group:{}:self", group_name);
        let handle = pigeonhole.create_channel(&my_channel_name).await?;
        let read_cap = handle.share_read_capability();
        let my_introduction = Introduction::new(my_display_name, read_cap.read_cap, read_cap.start_index);
        let my_channel = Arc::new(Mutex::new(EventChannel::new(handle)));

        Ok(Self {
            name: group_name.to_string(),
            my_display_name: my_display_name.to_string(),
            my_introduction,
            my_channel,
            member_channels: Arc::new(RwLock::new(HashMap::new())),
            receive_any_buffer: Mutex::new(VecDeque::new()),
        })
    }

    /// Restore a previously created group from persisted channels in the
    /// database.
    ///
    /// Unlike [`create`], this does not need network I/O — all data is already
    /// in the local DB.  The signature is `async` purely for API symmetry so
    /// callers can treat both constructors the same way.
    pub async fn restore(
        pigeonhole: &PigeonholeClient,
        group_name: &str,
        my_display_name: &str,
        member_intros: &[Introduction],
    ) -> Result<Self> {
        let my_channel_name = format!("group:{}:self", group_name);
        let handle = pigeonhole.get_channel(&my_channel_name)?;
        let read_cap = handle.share_read_capability();
        let my_introduction = Introduction::new(my_display_name, read_cap.read_cap, read_cap.start_index);
        let my_channel = Arc::new(Mutex::new(EventChannel::new(handle)));

        let mut map = HashMap::new();
        for intro in member_intros {
            let id = intro.member_id();
            let member_channel_name = format!("group:{}:member:{}", group_name, id);
            let handle = pigeonhole.get_channel(&member_channel_name)?;
            map.insert(
                id,
                (intro.display_name.clone(), Arc::new(Mutex::new(EventChannel::new(handle)))),
            );
        }

        Ok(Self {
            name: group_name.to_string(),
            my_display_name: my_display_name.to_string(),
            my_introduction,
            my_channel,
            member_channels: Arc::new(RwLock::new(map)),
            receive_any_buffer: Mutex::new(VecDeque::new()),
        })
    }

    /// Return an `Introduction` suitable for sharing with new members so they
    /// can import this member's channel.
    pub fn my_introduction(&self) -> Introduction {
        self.my_introduction.clone()
    }

    /// Number of remote member channels currently tracked.
    pub fn member_count(&self) -> usize {
        self.member_channels.read().expect("member_channels lock poisoned").len()
    }

    /// Import a member's read capability and start tracking their channel.
    ///
    /// The member is keyed internally by [`Introduction::member_id`] (a hash
    /// of the read cap), not by `display_name`.  Two members may share a
    /// display name without colliding.
    pub fn add_member(&self, pigeonhole: &PigeonholeClient, intro: &Introduction) -> Result<()> {
        let id = intro.member_id();
        let channel_name = format!("group:{}:member:{}", self.name, id);
        let read_cap = ReadCapability {
            read_cap: intro.read_cap.clone(),
            start_index: intro.start_index.clone(),
            name: Some(intro.display_name.clone()),
        };
        let handle = pigeonhole.import_channel(&channel_name, &read_cap)?;
        self.member_channels
            .write()
            .expect("member_channels lock poisoned")
            .insert(id, (intro.display_name.clone(), Arc::new(Mutex::new(EventChannel::new(handle)))));
        Ok(())
    }

    /// Remove a member's channel from local tracking.
    ///
    /// Pass [`Introduction::member_id`] as `member_id`.
    /// Returns `true` if the member was present.
    pub fn remove_member(&self, member_id: &str) -> bool {
        self.member_channels
            .write()
            .expect("member_channels lock poisoned")
            .remove(member_id)
            .is_some()
    }

    /// Send an event on the local member's channel.
    pub async fn send(&self, event: &E) -> Result<()> {
        self.my_channel.lock().await.send(event).await
    }

    /// Block until the next event from `member_id` arrives, using the daemon's
    /// ARQ mechanism.  Returns immediately if a message is already waiting.
    ///
    /// Pass [`Introduction::member_id`] as `member_id`.
    pub async fn receive_from(&self, member_id: &str) -> Result<ReceivedGroupEvent<E>> {
        let (display_name, channel) = self.member_channels
            .read()
            .expect("member_channels lock poisoned")
            .get(member_id)
            .ok_or_else(|| PigeonholeDbError::Other(format!("No member '{}' in group", member_id)))?
            .clone();
        let mut ch = channel.lock().await;
        let event = ch.receive().await?;
        Ok(ReceivedGroupEvent { sender: display_name, event })
    }

    /// Block until every member has delivered one event, receiving from all
    /// member channels concurrently.
    ///
    /// All ARQ requests are started simultaneously.  Results are collected in
    /// completion order (fastest channel first) so no channel waits on
    /// another.  Returns one event per member in the order they arrived.
    pub async fn receive_from_all(&self) -> Result<Vec<ReceivedGroupEvent<E>>> {
        // snapshot: (display_name, channel)
        let snapshot: Vec<(String, Arc<Mutex<EventChannel<E>>>)> = self.member_channels
            .read()
            .expect("member_channels lock poisoned")
            .values()
            .map(|(display_name, ch)| (display_name.clone(), ch.clone()))
            .collect();

        if snapshot.is_empty() {
            return Ok(vec![]);
        }

        let mut set = tokio::task::JoinSet::new();

        let results_cap = snapshot.len();
        for (name, channel) in snapshot {
            set.spawn(async move {
                let mut ch = channel.lock().await;
                ch.receive().await
                    .map(|event| ReceivedGroupEvent { sender: name, event })
            });
        }

        let mut results = Vec::with_capacity(results_cap);
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(event))  => results.push(event),
                Ok(Err(e))     => return Err(e),
                Err(join_err)  => return Err(PigeonholeDbError::Other(
                    format!("receive_from_all task panicked: {}", join_err)
                )),
            }
        }
        Ok(results)
    }

    /// Like [`receive_from_all`] but returns after `timeout` with whatever
    /// results have arrived, rather than blocking until every member delivers.
    ///
    /// Returns `Ok(events)` where `events` contains one entry per member that
    /// delivered within the deadline; members that did not deliver are simply
    /// absent from the result (their tasks are aborted before their
    /// `ChannelHandle::receive` completes, so no cursor is advanced and no
    /// message is lost on those channels).
    ///
    /// **No-loss guarantee**: any member whose `receive()` completed
    /// *concurrently* with the timeout — meaning its read cursor has already
    /// advanced — has its event placed in the internal pending buffer and will
    /// be returned by the next [`receive_any`] call.
    ///
    /// If any member's `receive()` returns an error, all already-collected
    /// events are moved to the pending buffer and the error is propagated.
    pub async fn receive_from_all_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Vec<ReceivedGroupEvent<E>>> {
        // snapshot: (display_name, channel)
        let snapshot: Vec<(String, Arc<Mutex<EventChannel<E>>>)> = self.member_channels
            .read()
            .expect("member_channels lock poisoned")
            .values()
            .map(|(dn, ch)| (dn.clone(), ch.clone()))
            .collect();

        if snapshot.is_empty() {
            return Ok(vec![]);
        }

        let n = snapshot.len();
        // Capacity = n: completing tasks send without blocking, preserving
        // results even if we time out before draining them.
        let (tx, mut rx) = tokio::sync::mpsc::channel(n);
        let mut handles = Vec::with_capacity(n);

        for (display_name, channel) in snapshot {
            let tx = tx.clone();
            let handle = tokio::spawn(async move {
                let mut ch = channel.lock().await;
                let result = ch.receive().await
                    .map(|event| ReceivedGroupEvent { sender: display_name, event });
                let _ = tx.send(result).await;
            });
            handles.push(handle);
        }
        drop(tx);

        let deadline = tokio::time::Instant::now() + timeout;
        let mut results = Vec::with_capacity(n);
        let mut first_err: Option<PigeonholeDbError> = None;

        loop {
            if results.len() == n {
                break; // all members delivered
            }
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(Ok(event))) => results.push(event),
                Ok(Some(Err(e)))    => { first_err = Some(e); break; }
                Ok(None) | Err(_)   => break, // channel closed or deadline
            }
        }

        // Abort tasks that haven't finished receive() yet.
        for handle in &handles {
            handle.abort();
        }

        // Drain any events that landed just before/during abort (their cursors
        // are already advanced and must not be discarded).
        let mut late: Vec<ReceivedGroupEvent<E>> = Vec::new();
        while let Ok(extra) = rx.try_recv() {
            if let Ok(event) = extra {
                late.push(event);
            }
        }

        if let Some(e) = first_err {
            // Move all successfully received events to the pending buffer so
            // they are not lost despite the error return.
            let mut buf = self.receive_any_buffer.lock().await;
            for event in results.into_iter().chain(late) {
                buf.push_back(event);
            }
            Err(e)
        } else {
            if !late.is_empty() {
                let mut buf = self.receive_any_buffer.lock().await;
                for event in late {
                    buf.push_back(event);
                }
            }
            Ok(results)
        }
    }

    /// Block until any member sends an event, racing all member channels
    /// concurrently.  The first to deliver wins; remaining tasks are aborted.
    ///
    /// **No-loss guarantee**: `ChannelHandle::receive` advances the persistent
    /// read cursor before it returns.  Any task that completes a receive must
    /// therefore have its result delivered to the caller — discarding it would
    /// permanently skip that message.  To handle races where multiple channels
    /// deliver simultaneously, the channel passed to spawned tasks has capacity
    /// equal to the member count, so every completing task can send its result
    /// without blocking.  After returning the first result, any extras already
    /// in the channel are drained into an internal buffer and returned by
    /// subsequent `receive_any` calls before new network I/O is issued.
    ///
    /// Each member's channel uses the daemon's ARQ mechanism, so there is no
    /// application-level sleep or timeout — the daemon retries automatically
    /// until the box is available.
    pub async fn receive_any(&self) -> Result<ReceivedGroupEvent<E>> {
        // Drain the buffer before doing any network I/O.
        {
            let mut buf = self.receive_any_buffer.lock().await;
            if let Some(event) = buf.pop_front() {
                return Ok(event);
            }
        }

        // snapshot: (display_name, channel)
        let snapshot: Vec<(String, Arc<Mutex<EventChannel<E>>>)> = self.member_channels
            .read()
            .expect("member_channels lock poisoned")
            .values()
            .map(|(display_name, ch)| (display_name.clone(), ch.clone()))
            .collect();

        if snapshot.is_empty() {
            return Err(PigeonholeDbError::Other("Group has no members".to_string()));
        }

        // One slot per member so that a completing task's tx.send() resolves
        // without yielding.  A non-yielding send completes before the tokio
        // scheduler can switch to our task, so by the time rx.recv() wakes us
        // up every task that finished receive() has already placed its result
        // in the channel.
        let n = snapshot.len();
        let (tx, mut rx) = tokio::sync::mpsc::channel(n);
        let mut handles = Vec::with_capacity(n);

        for (name, channel) in snapshot {
            let tx = tx.clone();
            let handle = tokio::spawn(async move {
                let mut ch = channel.lock().await;
                let result = ch.receive().await
                    .map(|event| ReceivedGroupEvent { sender: name, event });
                let _ = tx.send(result).await;
            });
            handles.push(handle);
        }
        drop(tx);

        let first = rx.recv().await
            .ok_or_else(|| PigeonholeDbError::Other("All member channels failed".to_string()))?;

        // Abort tasks that haven't completed receive() yet.  Tasks that already
        // completed sent their result non-blocking (capacity = n), so their
        // results are already in `rx` and will be captured by try_recv below.
        for handle in &handles {
            handle.abort();
        }

        // Drain results that arrived alongside the winner.  These come from
        // tasks whose receive() completed before the abort fired; their read
        // cursors have already advanced and the messages must not be discarded.
        {
            let mut buf = self.receive_any_buffer.lock().await;
            while let Ok(extra) = rx.try_recv() {
                if let Ok(event) = extra {
                    buf.push_back(event);
                }
                // An Err result means that receive() failed before advancing
                // the cursor, so nothing was consumed and we can drop it.
            }
        }

        first
    }
}
