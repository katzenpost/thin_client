// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Distributed Doodle-style meeting poll built on [`GroupChannel`].
//!
//! A poll creator proposes a fixed set of [`TimeSlot`]s.  Every group
//! member — including the creator — publishes a [`DoodleEvent`] on their
//! own channel.  Any participant can derive the current poll state by
//! folding all events observed across the group's streams:
//!
//! ```text
//! state = fold(events)
//! ```
//!
//! # Protocol
//!
//! 1. The creator calls [`DoodlePoll::new_poll`], which broadcasts a
//!    `CreatePoll` event containing the poll title and the list of slots.
//! 2. Other participants call [`DoodlePoll::join_poll`] (or
//!    [`DoodlePoll::restore`] for a previously persisted poll) and
//!    exchange [`Introduction`]s with one another via [`GroupChannel`].
//! 3. Each participant calls [`DoodlePoll::cast_ballot`] to publish a
//!    [`CastBallot`] event mapping each slot ID to their [`Availability`].
//!    Ballots may be updated by publishing a new one; later ballots
//!    supersede earlier ones (last-write-wins, guaranteed by channel
//!    ordering).
//! 4. All participants call [`DoodlePoll::receive_and_apply`] (or the
//!    partial-results variant [`DoodlePoll::receive_and_apply_timeout`])
//!    to pull in remote events and update the local [`PollState`].
//! 5. Whoever wants a summary calls [`DoodlePoll::tally`] for per-slot
//!    counts or [`DoodlePoll::best_slot`] for the slot with the most
//!    "Yes" votes.
//!
//! # Example
//!
//! ```ignore
//! // Creator
//! let mut poll = DoodlePoll::new_poll(&ph, "standup", "Alice",
//!     "Weekly standup",
//!     vec![
//!         TimeSlot::new("mon-9", "Monday 09:00"),
//!         TimeSlot::new("tue-9", "Tuesday 09:00"),
//!     ],
//! ).await?;
//!
//! // Share poll.my_introduction() out-of-band, then:
//! poll.add_member(&ph, &bob_intro)?;
//!
//! // Bob
//! let mut bob_poll = DoodlePoll::join_poll(&ph, "standup", "Bob", &alice_intro).await?;
//! bob_poll.cast_ballot(hashmap! {
//!     "mon-9".to_string() => Availability::Yes,
//!     "tue-9".to_string() => Availability::No,
//! }).await?;
//!
//! // Alice receives and tallies
//! poll.receive_and_apply().await?;
//! println!("{:#?}", poll.tally());
//! ```

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::group::channel::{GroupChannel, ReceivedGroupEvent};
use crate::group::Introduction;
use crate::persistent::error::Result;
use crate::persistent::PigeonholeClient;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A candidate meeting time proposed by the poll creator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeSlot {
    /// Stable identifier used as the key in ballot maps.
    pub id: String,
    /// Human-readable label shown to participants.
    pub label: String,
}

impl TimeSlot {
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self { id: id.into(), label: label.into() }
    }
}

/// A participant's answer for a single time slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Availability {
    Yes,
    No,
    Maybe,
}

// ---------------------------------------------------------------------------
// Event type
// ---------------------------------------------------------------------------

/// Events published on a [`DoodlePoll`] group channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DoodleEvent {
    /// Emitted by the poll creator to establish the poll title and slot list.
    /// Every participant's local state is initialized from the first
    /// `CreatePoll` event they observe (subsequent ones are ignored).
    CreatePoll {
        title: String,
        slots: Vec<TimeSlot>,
    },
    /// A participant's complete ballot.  Each entry maps a slot ID to their
    /// availability.  A later ballot from the same sender completely replaces
    /// their earlier one (last-write-wins, guaranteed by channel ordering).
    CastBallot {
        /// Maps slot id → availability for every slot in the poll.
        votes: HashMap<String, Availability>,
    },
}

// ---------------------------------------------------------------------------
// State: fold(events)
// ---------------------------------------------------------------------------

/// The current poll state, derived by folding all observed events.
///
/// `title` and `slots` are set by the first `CreatePoll` event; subsequent
/// `CreatePoll` events are ignored (the creator's initial broadcast is
/// authoritative).  `ballots` is updated by every `CastBallot` event.
#[derive(Debug, Clone, Default)]
pub struct PollState {
    /// Poll title, empty until the first `CreatePoll` is applied.
    pub title: String,
    /// Ordered list of candidate slots, empty until `CreatePoll` is applied.
    pub slots: Vec<TimeSlot>,
    /// Latest ballot per sender.  Key: display name; Value: slot-id → availability.
    pub ballots: HashMap<String, HashMap<String, Availability>>,
}

impl PollState {
    /// Fold one `(sender, event)` pair into the state.
    pub fn apply(&mut self, sender: &str, event: DoodleEvent) {
        match event {
            DoodleEvent::CreatePoll { title, slots } => {
                // Only the first CreatePoll initializes the poll.
                if self.title.is_empty() {
                    self.title = title;
                    self.slots = slots;
                }
            }
            DoodleEvent::CastBallot { votes } => {
                // Last ballot from this sender wins.
                self.ballots.insert(sender.to_string(), votes);
            }
        }
    }

    /// Per-slot tally of Yes / No / Maybe counts across all known ballots.
    ///
    /// Returns one [`SlotTally`] per slot in creation order.  Participants
    /// who have not yet cast a ballot are excluded from the counts.
    pub fn tally(&self) -> Vec<SlotTally> {
        self.slots.iter().map(|slot| {
            let mut yes = 0u32;
            let mut no = 0u32;
            let mut maybe = 0u32;
            for ballot in self.ballots.values() {
                match ballot.get(&slot.id) {
                    Some(Availability::Yes)   => yes   += 1,
                    Some(Availability::No)    => no    += 1,
                    Some(Availability::Maybe) => maybe += 1,
                    None => {}
                }
            }
            SlotTally { slot: slot.clone(), yes, no, maybe }
        }).collect()
    }

    /// The slot with the highest `Yes` count, breaking ties by slot order.
    ///
    /// Returns `None` if the poll has no slots or no `Yes` votes at all.
    pub fn best_slot(&self) -> Option<&TimeSlot> {
        self.tally()
            .into_iter()
            .enumerate()
            .filter(|(_, t)| t.yes > 0)
            .max_by_key(|(idx, t)| (t.yes, -((*idx) as i64)))
            .map(|(idx, _)| &self.slots[idx])
    }
}

/// Vote counts for a single time slot.
#[derive(Debug, Clone)]
pub struct SlotTally {
    pub slot: TimeSlot,
    pub yes: u32,
    pub no: u32,
    pub maybe: u32,
}

// ---------------------------------------------------------------------------
// DoodlePoll
// ---------------------------------------------------------------------------

/// A distributed Doodle-style meeting poll backed by a
/// [`GroupChannel<DoodleEvent>`].
///
/// The local poll state is updated by calling [`receive_one_and_apply`],
/// [`receive_and_apply`], or [`receive_and_apply_timeout`].  State is
/// inspected with [`poll_state`], [`tally`], and [`best_slot`].
pub struct DoodlePoll {
    channel: GroupChannel<DoodleEvent>,
    state: PollState,
}

impl DoodlePoll {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new poll, broadcasting the slot list to the group channel.
    ///
    /// The creator is automatically recorded as the poll initiator.  Call
    /// [`add_member`] for each additional participant after sharing your
    /// [`my_introduction`] with them out-of-band.
    pub async fn new_poll(
        pigeonhole: &PigeonholeClient,
        poll_name: &str,
        my_display_name: &str,
        title: impl Into<String>,
        slots: Vec<TimeSlot>,
    ) -> Result<Self> {
        let channel = GroupChannel::create(pigeonhole, poll_name, my_display_name).await?;
        let title = title.into();
        let event = DoodleEvent::CreatePoll { title: title.clone(), slots: slots.clone() };
        channel.send(&event).await?;
        let mut state = PollState::default();
        state.apply(my_display_name, event);
        Ok(Self { channel, state })
    }

    /// Join an existing poll, given the creator's introduction.
    ///
    /// Call this after receiving the creator's [`Introduction`] out-of-band.
    /// To receive the `CreatePoll` event and initialize the local state, call
    /// [`receive_one_and_apply`] (or [`receive_and_apply`]).
    pub async fn join_poll(
        pigeonhole: &PigeonholeClient,
        poll_name: &str,
        my_display_name: &str,
        creator_intro: &Introduction,
    ) -> Result<Self> {
        let channel = GroupChannel::create(pigeonhole, poll_name, my_display_name).await?;
        channel.add_member(pigeonhole, creator_intro)?;
        Ok(Self { channel, state: PollState::default() })
    }

    /// Restore a previously persisted poll from the database.
    pub async fn restore(
        pigeonhole: &PigeonholeClient,
        poll_name: &str,
        my_display_name: &str,
        member_intros: &[Introduction],
    ) -> Result<Self> {
        let channel = GroupChannel::restore(pigeonhole, poll_name, my_display_name, member_intros).await?;
        Ok(Self { channel, state: PollState::default() })
    }

    // -----------------------------------------------------------------------
    // Membership
    // -----------------------------------------------------------------------

    /// Return an [`Introduction`] for sharing with other participants.
    pub fn my_introduction(&self) -> Introduction {
        self.channel.my_introduction()
    }

    /// Number of remote member channels currently tracked.
    pub fn member_count(&self) -> usize {
        self.channel.member_count()
    }

    /// Import a member's read capability and start tracking their channel.
    pub fn add_member(&self, pigeonhole: &PigeonholeClient, intro: &Introduction) -> Result<()> {
        self.channel.add_member(pigeonhole, intro)
    }

    /// Remove a member's channel from local tracking.
    pub fn remove_member(&self, member_id: &str) -> bool {
        self.channel.remove_member(member_id)
    }

    // -----------------------------------------------------------------------
    // Voting
    // -----------------------------------------------------------------------

    /// Publish a ballot mapping each slot ID to an [`Availability`] value.
    ///
    /// The ballot is applied to the local state immediately so that
    /// `tally()` and `best_slot()` include the caller's own votes without
    /// requiring a round-trip through the mixnet.
    ///
    /// A later `cast_ballot` call replaces the previous one; last-write-wins
    /// is guaranteed by channel ordering.
    pub async fn cast_ballot(&mut self, votes: HashMap<String, Availability>) -> Result<()> {
        let event = DoodleEvent::CastBallot { votes };
        self.channel.send(&event).await?;
        let my_name = self.channel.my_display_name.clone();
        self.state.apply(&my_name, event);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Receive + fold
    // -----------------------------------------------------------------------

    /// Block until any member delivers one event, then fold it into the local
    /// state.  Returns a reference to the updated [`PollState`].
    pub async fn receive_one_and_apply(&mut self) -> Result<&PollState> {
        let ReceivedGroupEvent { sender, event } = self.channel.receive_any().await?;
        self.state.apply(&sender, event);
        Ok(&self.state)
    }

    /// Block until every member has delivered one event, then fold all of
    /// them into the local state.  Returns a reference to the updated
    /// [`PollState`].
    pub async fn receive_and_apply(&mut self) -> Result<&PollState> {
        let events = self.channel.receive_from_all().await?;
        for ReceivedGroupEvent { sender, event } in events {
            self.state.apply(&sender, event);
        }
        Ok(&self.state)
    }

    /// Like [`receive_and_apply`] but returns partial results after `timeout`.
    pub async fn receive_and_apply_timeout(&mut self, timeout: Duration) -> Result<&PollState> {
        let events = self.channel.receive_from_all_timeout(timeout).await?;
        for ReceivedGroupEvent { sender, event } in events {
            self.state.apply(&sender, event);
        }
        Ok(&self.state)
    }

    // -----------------------------------------------------------------------
    // State inspection
    // -----------------------------------------------------------------------

    /// Read-only view of the current poll state.
    pub fn poll_state(&self) -> &PollState {
        &self.state
    }

    /// Per-slot vote counts derived from the current state.
    pub fn tally(&self) -> Vec<SlotTally> {
        self.state.tally()
    }

    /// The slot with the most "Yes" votes.  Returns `None` if no votes have
    /// been cast yet or no slot has a "Yes".
    pub fn best_slot(&self) -> Option<&TimeSlot> {
        self.state.best_slot()
    }
}
