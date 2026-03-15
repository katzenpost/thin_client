// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Generic group channel: each member owns one `EventChannel<Envelope<E>>` for
//! writing; the others hold imported read-only channels for every peer.
//!
//! # Channel rotation
//!
//! Call [`GroupChannel::rotate_channel`] to rotate your write channel for
//! post-compromise security.  Rotation events piggyback transparently on the
//! existing application channels via a private [`Envelope<E>`] wrapper; the
//! receive methods strip the wrapper and surface only `App` payloads to the
//! caller.
//!
//! The protocol:
//!
//! 1. Writer calls `rotate_channel()`: creates a new channel, sends
//!    `Envelope::Rotate { new_intro }` on the **old** channel, then waits for
//!    ACKs from every member.
//! 2. Each reader that receives a `Rotate` envelope imports the new channel
//!    and replies with `Envelope::Ack { new_member_id }` on *their own*
//!    channel.
//! 3. Once the writer has collected ACKs from every member, it atomically
//!    replaces `my_channel` and `my_introduction` with the new ones.
//!
//! Until all ACKs arrive the writer continues publishing on the old channel
//! so readers are never left without a valid endpoint.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::Duration;

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::Mutex;

use crate::persistent::error::{PigeonholeDbError, Result};
use crate::persistent::{PigeonholeClient, ReadCapability};

use super::event_channel::EventChannel;

// ============================================================================
// Public types
// ============================================================================

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

// ============================================================================
// Private wire format
// ============================================================================

/// All messages on group channels are framed in this envelope.
///
/// `App` carries normal application events.  `Rotate` and `Ack` implement the
/// channel-rotation handshake; they are stripped by the receive methods and
/// never surfaced to the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Envelope<E> {
    App(E),
    Rotate { new_intro: Introduction },
    Ack { new_member_id: String },
}

// ============================================================================
// Rotation state
// ============================================================================

struct PendingRotation<E> {
    /// The freshly-created channel that will replace `my_channel` once all
    /// members have ACKed.
    new_channel: EventChannel<Envelope<E>>,
    /// Introduction that readers will need to import the new channel.
    new_introduction: Introduction,
    /// Member IDs (hash of current read cap) that have not yet ACKed.
    acks_needed: HashSet<String>,
}

// ============================================================================
// GroupChannel
// ============================================================================

/// A group where every member publishes to their own `EventChannel<Envelope<E>>`
/// and reads from every other member's channel.
///
/// # Type parameter
///
/// `E` is the application event type.  It must be serializable with `serde`
/// (CBOR encoding is used on the wire).  Examples:
///
/// - `enum ChatEvent { Text(String), Introduction(Introduction) }`
/// - A CRDT operation type such as `Dot<String>` (a `GCounter<String>` op).
///
/// # Receiving
///
/// Use [`receive_from`] to block until a specific member's next message
/// arrives, or [`receive_any`] to race all member channels and return
/// whichever delivers first.  Both rely on the daemon's ARQ mechanism rather
/// than an application-level sleep/poll loop.  `Rotate` and `Ack` envelopes
/// are processed silently and never returned.
///
/// # Channel rotation
///
/// Call [`rotate_channel`] to initiate a post-compromise key rotation.  Check
/// [`rotation_pending`] to see if the handshake is still in progress.  While
/// rotation is pending the group continues to operate normally; new messages
/// are still written on the old channel until every peer ACKs.
pub struct GroupChannel<E> {
    pub name: String,
    pub my_display_name: String,
    /// Stored so `add_member` and `rotate_channel` can call pigeonhole without
    /// requiring the caller to pass it each time.
    pigeonhole: Arc<PigeonholeClient>,
    /// Swapped atomically on rotation completion.
    my_introduction: RwLock<Introduction>,
    /// The local member's write channel.  Swapped atomically on rotation
    /// completion.  `tokio::sync::Mutex` (not Arc-wrapped) because only `self`
    /// ever accesses it; Arc is not needed.
    my_channel: Mutex<EventChannel<Envelope<E>>>,
    /// Key: `Introduction::member_id()`.
    /// Value: `(display_name, channel)`.
    member_channels: Arc<RwLock<HashMap<String, (String, Arc<Mutex<EventChannel<Envelope<E>>>>)>>>,
    /// Events received alongside the winner of a `receive_any` race that have
    /// not yet been returned to the caller.  Drained in FIFO order before new
    /// network I/O.
    receive_any_buffer: Mutex<VecDeque<ReceivedGroupEvent<E>>>,
    /// Non-`None` while a rotation handshake is in progress.
    /// `std::sync::Mutex` because it is never held across `.await` points.
    pending_rotation: StdMutex<Option<PendingRotation<E>>>,
}

impl<E: Serialize + DeserializeOwned + Clone + Send + 'static> GroupChannel<E> {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new group and generate the local member's channel.
    pub async fn create(
        pigeonhole: Arc<PigeonholeClient>,
        group_name: &str,
        my_display_name: &str,
    ) -> Result<Self> {
        let my_channel_name = format!("group:{}:self", group_name);
        let handle = pigeonhole.create_channel(&my_channel_name).await?;
        let read_cap = handle.share_read_capability();
        let my_introduction = Introduction::new(my_display_name, read_cap.read_cap, read_cap.start_index);
        let my_channel = Mutex::new(EventChannel::new(handle));

        Ok(Self {
            name: group_name.to_string(),
            my_display_name: my_display_name.to_string(),
            pigeonhole,
            my_introduction: RwLock::new(my_introduction),
            my_channel,
            member_channels: Arc::new(RwLock::new(HashMap::new())),
            receive_any_buffer: Mutex::new(VecDeque::new()),
            pending_rotation: StdMutex::new(None),
        })
    }

    /// Restore a previously created group from persisted channels in the
    /// database.
    ///
    /// Unlike [`create`], this does not need network I/O — all data is already
    /// in the local DB.  The signature is `async` purely for API symmetry so
    /// callers can treat both constructors the same way.
    pub async fn restore(
        pigeonhole: Arc<PigeonholeClient>,
        group_name: &str,
        my_display_name: &str,
        member_intros: &[Introduction],
    ) -> Result<Self> {
        let my_channel_name = format!("group:{}:self", group_name);
        let handle = pigeonhole.get_channel(&my_channel_name)?;
        let read_cap = handle.share_read_capability();
        let my_introduction = Introduction::new(my_display_name, read_cap.read_cap, read_cap.start_index);
        let my_channel = Mutex::new(EventChannel::new(handle));

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
            pigeonhole,
            my_introduction: RwLock::new(my_introduction),
            my_channel,
            member_channels: Arc::new(RwLock::new(map)),
            receive_any_buffer: Mutex::new(VecDeque::new()),
            pending_rotation: StdMutex::new(None),
        })
    }

    // -----------------------------------------------------------------------
    // Membership
    // -----------------------------------------------------------------------

    /// Return an `Introduction` suitable for sharing with new members so they
    /// can import this member's channel.
    pub fn my_introduction(&self) -> Introduction {
        self.my_introduction.read().expect("my_introduction lock poisoned").clone()
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
    pub fn add_member(&self, intro: &Introduction) -> Result<()> {
        let id = intro.member_id();
        let channel_name = format!("group:{}:member:{}", self.name, id);
        let read_cap = ReadCapability {
            read_cap: intro.read_cap.clone(),
            start_index: intro.start_index.clone(),
            name: Some(intro.display_name.clone()),
        };
        let handle = self.pigeonhole.import_channel(&channel_name, &read_cap)?;
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

    // -----------------------------------------------------------------------
    // Send
    // -----------------------------------------------------------------------

    /// Send an event on the local member's channel.
    ///
    /// The event is wrapped in `Envelope::App` before writing to the wire.
    pub async fn send(&self, event: E) -> Result<()> {
        self.my_channel.lock().await.send(&Envelope::App(event)).await
    }

    // -----------------------------------------------------------------------
    // Channel rotation
    // -----------------------------------------------------------------------

    /// Initiate a channel rotation.
    ///
    /// Creates a new write channel, broadcasts a `Rotate` envelope on the
    /// current channel, then waits for ACKs from every member before
    /// atomically switching to the new channel.  Until all ACKs arrive,
    /// [`send`] continues to write on the old channel so peers are never
    /// left without a valid endpoint.
    ///
    /// Returns an error if a rotation is already in progress.
    pub async fn rotate_channel(&self) -> Result<()> {
        // Ensure no rotation is already pending.
        {
            let pr = self.pending_rotation.lock().expect("pending_rotation lock poisoned");
            if pr.is_some() {
                return Err(PigeonholeDbError::Other("Channel rotation already in progress".to_string()));
            }
        }

        // Create a new write channel with a unique name derived from the
        // current timestamp to avoid collisions with the existing one.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let new_channel_name = format!("group:{}:self:rot:{}", self.name, ts);
        let handle = self.pigeonhole.create_channel(&new_channel_name).await?;
        let read_cap = handle.share_read_capability();
        let new_introduction = Introduction::new(
            &self.my_display_name,
            read_cap.read_cap,
            read_cap.start_index,
        );
        let new_channel: EventChannel<Envelope<E>> = EventChannel::new(handle);

        // Collect current member IDs — these are the peers whose ACKs we need.
        let acks_needed: HashSet<String> = self.member_channels
            .read()
            .expect("member_channels lock poisoned")
            .keys()
            .cloned()
            .collect();

        // Announce the rotation on the current channel so peers can import the
        // new channel before we switch.
        let rotate_env = Envelope::<E>::Rotate { new_intro: new_introduction.clone() };
        self.my_channel.lock().await.send(&rotate_env).await?;

        if acks_needed.is_empty() {
            // No peers to ACK — complete the rotation immediately.
            *self.my_channel.lock().await = new_channel;
            *self.my_introduction.write().expect("my_introduction lock poisoned") = new_introduction;
        } else {
            *self.pending_rotation.lock().expect("pending_rotation lock poisoned") =
                Some(PendingRotation { new_channel, new_introduction, acks_needed });
        }

        Ok(())
    }

    /// Returns `true` if a channel rotation handshake is in progress.
    pub fn rotation_pending(&self) -> bool {
        self.pending_rotation.lock().expect("pending_rotation lock poisoned").is_some()
    }

    // -----------------------------------------------------------------------
    // Envelope processing (private)
    // -----------------------------------------------------------------------

    /// Process `Rotate` and `Ack` envelopes received from `sender_member_id`.
    ///
    /// This is called by the receive methods after stripping `App` payloads.
    /// Holding no locks on entry; acquires them internally for short critical
    /// sections, never across `.await` points.
    async fn process_envelopes(
        &self,
        sender_member_id: &str,
        envelopes: Vec<Envelope<E>>,
    ) -> Result<()> {
        for envelope in envelopes {
            match envelope {
                Envelope::App(_) => {
                    // Should not reach here — callers strip App before this call.
                    debug_assert!(false, "process_envelopes called with App envelope");
                }
                Envelope::Rotate { new_intro } => {
                    // Import the peer's new channel (sync — no await needed).
                    let new_id = new_intro.member_id();
                    let channel_name = format!("group:{}:member:{}", self.name, new_id);
                    let read_cap = ReadCapability {
                        read_cap: new_intro.read_cap.clone(),
                        start_index: new_intro.start_index.clone(),
                        name: Some(new_intro.display_name.clone()),
                    };
                    let handle = self.pigeonhole.import_channel(&channel_name, &read_cap)?;

                    // Replace the old channel entry with the new one.
                    {
                        let mut map = self.member_channels
                            .write()
                            .expect("member_channels lock poisoned");
                        map.remove(sender_member_id);
                        map.insert(
                            new_id.clone(),
                            (new_intro.display_name.clone(), Arc::new(Mutex::new(EventChannel::new(handle)))),
                        );
                    }

                    // If we have a pending rotation, rename the peer's ID in
                    // `acks_needed` so their subsequent ACK (sent on their new
                    // channel) is matched correctly.
                    {
                        let mut pr = self.pending_rotation.lock().expect("pending_rotation lock poisoned");
                        if let Some(ref mut pending) = *pr {
                            if pending.acks_needed.remove(sender_member_id) {
                                pending.acks_needed.insert(new_id.clone());
                            }
                        }
                    }

                    // Acknowledge the peer's rotation on our current channel.
                    let ack = Envelope::<E>::Ack { new_member_id: new_id };
                    self.my_channel.lock().await.send(&ack).await?;
                }
                Envelope::Ack { new_member_id } => {
                    // Determine whether this ACK satisfies our pending rotation.
                    let should_complete = {
                        let mut pr = self.pending_rotation.lock().expect("pending_rotation lock poisoned");
                        if let Some(ref mut pending) = *pr {
                            let matches = new_member_id == pending.new_introduction.member_id();
                            if matches {
                                pending.acks_needed.remove(sender_member_id);
                                pending.acks_needed.is_empty()
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    };

                    if should_complete {
                        // Take the pending rotation (brief lock, then dropped).
                        let completed = self.pending_rotation
                            .lock()
                            .expect("pending_rotation lock poisoned")
                            .take()
                            .expect("pending_rotation vanished between checks");

                        // Atomically replace the write channel and introduction.
                        *self.my_channel.lock().await = completed.new_channel;
                        *self.my_introduction.write().expect("my_introduction lock poisoned") =
                            completed.new_introduction;
                    }
                }
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Receive
    // -----------------------------------------------------------------------

    /// Block until the next event from `member_id` arrives, using the daemon's
    /// ARQ mechanism.  Returns immediately if a message is already waiting.
    ///
    /// `Rotate` and `Ack` envelopes are processed transparently; the method
    /// loops until an `App` payload is found.
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
        loop {
            match ch.receive().await? {
                Envelope::App(event) => return Ok(ReceivedGroupEvent { sender: display_name, event }),
                other => self.process_envelopes(member_id, vec![other]).await?,
            }
        }
    }

    /// Block until every member has delivered one `App` event, receiving from
    /// all member channels concurrently.
    ///
    /// Each spawned task loops on its channel until it finds an `App` payload,
    /// collecting any `Rotate`/`Ack` envelopes along the way.  Those are
    /// processed by the calling task after all spawned tasks complete.
    ///
    /// All ARQ requests are started simultaneously.  Results are collected in
    /// completion order so no channel waits on another.
    pub async fn receive_from_all(&self) -> Result<Vec<ReceivedGroupEvent<E>>> {
        // snapshot: (member_id, display_name, channel)
        let snapshot: Vec<(String, String, Arc<Mutex<EventChannel<Envelope<E>>>>)> =
            self.member_channels
                .read()
                .expect("member_channels lock poisoned")
                .iter()
                .map(|(id, (name, ch))| (id.clone(), name.clone(), ch.clone()))
                .collect();

        if snapshot.is_empty() {
            return Ok(vec![]);
        }

        let mut set = tokio::task::JoinSet::new();
        let results_cap = snapshot.len();

        for (member_id, display_name, channel) in snapshot {
            set.spawn(async move {
                let mut ch = channel.lock().await;
                let mut rotation_envelopes: Vec<Envelope<E>> = Vec::new();
                loop {
                    match ch.receive().await {
                        Ok(Envelope::App(e)) => {
                            return Ok::<_, PigeonholeDbError>((member_id, display_name, e, rotation_envelopes));
                        }
                        Ok(other) => rotation_envelopes.push(other),
                        Err(e) => return Err(e),
                    }
                }
            });
        }

        let mut results = Vec::with_capacity(results_cap);
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok((member_id, display_name, event, envelopes))) => {
                    if !envelopes.is_empty() {
                        self.process_envelopes(&member_id, envelopes).await?;
                    }
                    results.push(ReceivedGroupEvent { sender: display_name, event });
                }
                Ok(Err(e)) => return Err(e),
                Err(join_err) => return Err(PigeonholeDbError::Other(
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
    /// delivered within the deadline.  Members that did not deliver are simply
    /// absent from the result (their tasks are aborted before
    /// `ChannelHandle::receive` completes, so no cursor is advanced and no
    /// message is lost on those channels).
    ///
    /// **No-loss guarantee**: any member whose `receive()` completed
    /// *concurrently* with the timeout has its event placed in the internal
    /// pending buffer and will be returned by the next [`receive_any`] call.
    ///
    /// If any member's `receive()` returns an error, all already-collected
    /// events are moved to the pending buffer and the error is propagated.
    pub async fn receive_from_all_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Vec<ReceivedGroupEvent<E>>> {
        let snapshot: Vec<(String, String, Arc<Mutex<EventChannel<Envelope<E>>>>)> =
            self.member_channels
                .read()
                .expect("member_channels lock poisoned")
                .iter()
                .map(|(id, (dn, ch))| (id.clone(), dn.clone(), ch.clone()))
                .collect();

        if snapshot.is_empty() {
            return Ok(vec![]);
        }

        let n = snapshot.len();
        // Capacity = n: tasks send without blocking, preserving results even if
        // we time out before draining them.
        let (tx, mut rx) = tokio::sync::mpsc::channel(n);
        let mut handles = Vec::with_capacity(n);

        for (member_id, display_name, channel) in snapshot {
            let tx = tx.clone();
            let handle = tokio::spawn(async move {
                let mut ch = channel.lock().await;
                let mut rotation_envelopes: Vec<Envelope<E>> = Vec::new();
                loop {
                    match ch.receive().await {
                        Ok(Envelope::App(e)) => {
                            let _ = tx.send(Ok((member_id, display_name, e, rotation_envelopes))).await;
                            return;
                        }
                        Ok(other) => rotation_envelopes.push(other),
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            return;
                        }
                    }
                }
            });
            handles.push(handle);
        }
        drop(tx);

        let deadline = tokio::time::Instant::now() + timeout;
        let mut results = Vec::with_capacity(n);
        let mut pending_envelopes: Vec<(String, Vec<Envelope<E>>)> = Vec::new();
        let mut first_err: Option<PigeonholeDbError> = None;

        loop {
            if results.len() == n {
                break;
            }
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(Ok((mid, dname, event, envelopes)))) => {
                    pending_envelopes.push((mid, envelopes));
                    results.push(ReceivedGroupEvent { sender: dname, event });
                }
                Ok(Some(Err(e))) => { first_err = Some(e); break; }
                Ok(None) | Err(_) => break,
            }
        }

        // Abort tasks that haven't finished yet.
        for handle in &handles {
            handle.abort();
        }

        // Drain any events that landed just before/during abort.
        let mut late: Vec<ReceivedGroupEvent<E>> = Vec::new();
        while let Ok(extra) = rx.try_recv() {
            if let Ok((mid, dname, event, envelopes)) = extra {
                pending_envelopes.push((mid, envelopes));
                late.push(ReceivedGroupEvent { sender: dname, event });
            }
        }

        // Process accumulated rotation envelopes.
        for (mid, envelopes) in pending_envelopes {
            if !envelopes.is_empty() {
                if let Err(e) = self.process_envelopes(&mid, envelopes).await {
                    // Surface the first error, but don't lose results.
                    if first_err.is_none() { first_err = Some(e); }
                }
            }
        }

        if let Some(e) = first_err {
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

    /// Block until any member sends an `App` event, racing all member channels
    /// concurrently.  The first to deliver wins; remaining tasks are aborted.
    ///
    /// `Rotate` and `Ack` envelopes are processed transparently.  If the
    /// winning task (or the extras that arrived alongside it) contain only
    /// rotation envelopes, a new race is started immediately.
    ///
    /// **No-loss guarantee**: `ChannelHandle::receive` advances the persistent
    /// read cursor before it returns.  Any task that completes a receive must
    /// therefore have its result delivered.  The channel passed to spawned
    /// tasks has capacity equal to the member count, so every completing task
    /// can send its result without blocking.  After returning the first `App`
    /// result, any additional `App` results already in the channel are drained
    /// into the internal buffer and returned by subsequent `receive_any` calls.
    pub async fn receive_any(&self) -> Result<ReceivedGroupEvent<E>> {
        // Drain the buffer before doing any network I/O.
        {
            let mut buf = self.receive_any_buffer.lock().await;
            if let Some(event) = buf.pop_front() {
                return Ok(event);
            }
        }

        loop {
            let snapshot: Vec<(String, String, Arc<Mutex<EventChannel<Envelope<E>>>>)> =
                self.member_channels
                    .read()
                    .expect("member_channels lock poisoned")
                    .iter()
                    .map(|(id, (name, ch))| (id.clone(), name.clone(), ch.clone()))
                    .collect();

            if snapshot.is_empty() {
                return Err(PigeonholeDbError::Other("Group has no members".to_string()));
            }

            // One slot per member so that a completing task's tx.send() resolves
            // without yielding.
            let n = snapshot.len();
            let (tx, mut rx) = tokio::sync::mpsc::channel(n);
            let mut handles = Vec::with_capacity(n);

            for (member_id, display_name, channel) in snapshot {
                let tx = tx.clone();
                let handle = tokio::spawn(async move {
                    let mut ch = channel.lock().await;
                    let result = ch.receive().await
                        .map(|env| (member_id, display_name, env));
                    let _ = tx.send(result).await;
                });
                handles.push(handle);
            }
            drop(tx);

            let first = rx.recv().await
                .ok_or_else(|| PigeonholeDbError::Other("All member channels failed".to_string()))?;

            // Abort tasks that haven't completed receive() yet.
            for handle in &handles {
                handle.abort();
            }

            // Drain results that arrived alongside the winner.
            let mut extras: Vec<(String, String, Envelope<E>)> = Vec::new();
            while let Ok(Ok(extra)) = rx.try_recv() {
                extras.push(extra);
            }

            match first? {
                (_member_id, display_name, Envelope::App(event)) => {
                    // Process any extras and buffer App ones.
                    let mut rotation_extras: Vec<(String, Vec<Envelope<E>>)> = Vec::new();
                    {
                        let mut buf = self.receive_any_buffer.lock().await;
                        for (mid, dname, env) in extras {
                            match env {
                                Envelope::App(e) => buf.push_back(ReceivedGroupEvent { sender: dname, event: e }),
                                other => {
                                    rotation_extras.push((mid.clone(), vec![other]));
                                }
                            }
                        }
                    }
                    for (mid, envelopes) in rotation_extras {
                        self.process_envelopes(&mid, envelopes).await?;
                    }

                    return Ok(ReceivedGroupEvent { sender: display_name, event });
                }
                (member_id, _, non_app) => {
                    // Process the non-App result and any extras, then loop.
                    self.process_envelopes(&member_id, vec![non_app]).await?;

                    let mut rotation_extras: Vec<(String, Vec<Envelope<E>>)> = Vec::new();
                    {
                        let mut buf = self.receive_any_buffer.lock().await;
                        for (mid, dname, env) in extras {
                            match env {
                                Envelope::App(e) => buf.push_back(ReceivedGroupEvent { sender: dname, event: e }),
                                other => rotation_extras.push((mid.clone(), vec![other])),
                            }
                        }
                    }
                    for (mid, envelopes) in rotation_extras {
                        self.process_envelopes(&mid, envelopes).await?;
                    }

                    // Check if any App arrived while processing rotation events.
                    {
                        let mut buf = self.receive_any_buffer.lock().await;
                        if let Some(event) = buf.pop_front() {
                            return Ok(event);
                        }
                    }
                    // No App yet — race again.
                }
            }
        }
    }
}

// ============================================================================
// Unit tests (no network required)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    // A minimal application event type used across all round-trip tests.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    enum TestEvent {
        Text(String),
        Counter(u64),
    }

    fn make_intro(display_name: &str, read_cap: &[u8]) -> Introduction {
        Introduction::new(display_name, read_cap.to_vec(), vec![0u8; 8])
    }

    // -----------------------------------------------------------------------
    // Envelope round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn envelope_app_cbor_roundtrip() {
        let original: Envelope<TestEvent> = Envelope::App(TestEvent::Text("hello".to_string()));
        let bytes = serde_cbor::to_vec(&original).unwrap();
        let decoded: Envelope<TestEvent> = serde_cbor::from_slice(&bytes).unwrap();
        match decoded {
            Envelope::App(TestEvent::Text(s)) => assert_eq!(s, "hello"),
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn envelope_app_counter_cbor_roundtrip() {
        let original: Envelope<TestEvent> = Envelope::App(TestEvent::Counter(42));
        let bytes = serde_cbor::to_vec(&original).unwrap();
        let decoded: Envelope<TestEvent> = serde_cbor::from_slice(&bytes).unwrap();
        match decoded {
            Envelope::App(TestEvent::Counter(n)) => assert_eq!(n, 42),
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn envelope_rotate_cbor_roundtrip() {
        let intro = make_intro("Alice", b"alice_read_cap_bytes");
        let original: Envelope<TestEvent> = Envelope::Rotate { new_intro: intro.clone() };
        let bytes = serde_cbor::to_vec(&original).unwrap();
        let decoded: Envelope<TestEvent> = serde_cbor::from_slice(&bytes).unwrap();
        match decoded {
            Envelope::Rotate { new_intro } => {
                assert_eq!(new_intro.display_name, "Alice");
                assert_eq!(new_intro.read_cap, b"alice_read_cap_bytes");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn envelope_ack_cbor_roundtrip() {
        let original: Envelope<TestEvent> = Envelope::Ack {
            new_member_id: "deadbeef1234".to_string(),
        };
        let bytes = serde_cbor::to_vec(&original).unwrap();
        let decoded: Envelope<TestEvent> = serde_cbor::from_slice(&bytes).unwrap();
        match decoded {
            Envelope::Ack { new_member_id } => assert_eq!(new_member_id, "deadbeef1234"),
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    /// The three envelope variants must not decode as one another.
    #[test]
    fn envelope_variants_are_distinguishable() {
        let intro = make_intro("Bob", b"bob_cap");
        let app: Envelope<TestEvent>    = Envelope::App(TestEvent::Counter(1));
        let rotate: Envelope<TestEvent> = Envelope::Rotate { new_intro: intro };
        let ack: Envelope<TestEvent>    = Envelope::Ack { new_member_id: "abc".to_string() };

        let app_bytes    = serde_cbor::to_vec(&app).unwrap();
        let rotate_bytes = serde_cbor::to_vec(&rotate).unwrap();
        let ack_bytes    = serde_cbor::to_vec(&ack).unwrap();

        // Each decodes back to exactly its own variant.
        assert!(matches!(serde_cbor::from_slice::<Envelope<TestEvent>>(&app_bytes).unwrap(),    Envelope::App(_)));
        assert!(matches!(serde_cbor::from_slice::<Envelope<TestEvent>>(&rotate_bytes).unwrap(), Envelope::Rotate { .. }));
        assert!(matches!(serde_cbor::from_slice::<Envelope<TestEvent>>(&ack_bytes).unwrap(),    Envelope::Ack { .. }));

        // None decodes as a different variant.
        assert!(serde_cbor::from_slice::<Envelope<TestEvent>>(&app_bytes)
            .map(|e: Envelope<TestEvent>| !matches!(e, Envelope::Rotate { .. })).unwrap_or(true));
    }

    // -----------------------------------------------------------------------
    // Introduction round-trips and member_id properties
    // -----------------------------------------------------------------------

    #[test]
    fn introduction_cbor_roundtrip() {
        let original = make_intro("Carol", b"carol_cap_bytes_xyz");
        let bytes = serde_cbor::to_vec(&original).unwrap();
        let decoded: Introduction = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(decoded.display_name, original.display_name);
        assert_eq!(decoded.read_cap,     original.read_cap);
        assert_eq!(decoded.start_index,  original.start_index);
    }

    #[test]
    fn member_id_is_deterministic() {
        let intro = make_intro("Alice", b"stable_read_cap");
        assert_eq!(intro.member_id(), intro.member_id(),
            "member_id must return the same value on repeated calls");
    }

    #[test]
    fn member_id_differs_for_different_read_caps() {
        let a = make_intro("Alice", b"cap_a");
        let b = make_intro("Alice", b"cap_b"); // same display_name, different cap
        assert_ne!(a.member_id(), b.member_id(),
            "different read caps must produce different member_ids");
    }

    #[test]
    fn member_id_ignores_display_name() {
        let same_cap = b"shared_cap_bytes";
        let a = make_intro("Alice", same_cap);
        let b = make_intro("Bob",   same_cap); // different display_name, same cap
        assert_eq!(a.member_id(), b.member_id(),
            "member_id depends only on read_cap, not display_name");
    }

    #[test]
    fn member_id_ignores_start_index() {
        let cap = b"cap_for_start_index_test";
        let a = Introduction::new("Alice", cap.to_vec(), vec![0u8; 8]);
        let b = Introduction::new("Alice", cap.to_vec(), vec![1u8; 8]);
        assert_eq!(a.member_id(), b.member_id(),
            "member_id depends only on read_cap, not start_index");
    }

    /// A `Rotate` envelope survives a CBOR round-trip even with a non-trivial
    /// Introduction (multi-byte read_cap and non-zero start_index).
    #[test]
    fn envelope_rotate_preserves_intro_fields() {
        let intro = Introduction::new(
            "Dave",
            (0u8..32).collect(), // 32-byte read_cap
            (0u8..8).collect(),  // 8-byte start_index
        );
        let expected_id = intro.member_id();

        let env: Envelope<TestEvent> = Envelope::Rotate { new_intro: intro };
        let bytes = serde_cbor::to_vec(&env).unwrap();
        let decoded: Envelope<TestEvent> = serde_cbor::from_slice(&bytes).unwrap();

        match decoded {
            Envelope::Rotate { new_intro } => {
                assert_eq!(new_intro.display_name, "Dave");
                assert_eq!(new_intro.read_cap, (0u8..32).collect::<Vec<_>>());
                assert_eq!(new_intro.start_index, (0u8..8).collect::<Vec<_>>());
                assert_eq!(new_intro.member_id(), expected_id);
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    /// Round-tripping an `Ack` that uses the hex-encoded Blake2s-256 member_id
    /// format (as produced by `Introduction::member_id()`).
    #[test]
    fn envelope_ack_with_realistic_member_id() {
        let intro = make_intro("Eve", b"realistic_read_cap_32bytes_padded");
        let member_id = intro.member_id();
        assert_eq!(member_id.len(), 64, "Blake2s-256 hex is 64 chars");

        let env: Envelope<TestEvent> = Envelope::Ack { new_member_id: member_id.clone() };
        let bytes = serde_cbor::to_vec(&env).unwrap();
        let decoded: Envelope<TestEvent> = serde_cbor::from_slice(&bytes).unwrap();

        match decoded {
            Envelope::Ack { new_member_id } => assert_eq!(new_member_id, member_id),
            other => panic!("unexpected variant: {:?}", other),
        }
    }
}
