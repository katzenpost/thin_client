// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Distributed meeting-availability poll built on [`GroupChannel`].
//!
//! A poll creator proposes a fixed set of [`Slot`]s.  Every group
//! member — including the creator — publishes a [`TallyEvent`] on their
//! own channel.  Any participant can derive the current poll state by
//! folding all events observed across the group's streams:
//!
//! ```text
//! state = fold(events)
//! ```
//!
//! # Protocol
//!
//! 1. The creator calls [`TallyPoll::new_poll`], which broadcasts a
//!    `CreatePoll` event containing the poll title and the list of slots.
//! 2. Other participants call [`TallyPoll::join_poll`] (or
//!    [`TallyPoll::restore`] for a previously persisted poll) and
//!    exchange [`Introduction`]s with one another via [`GroupChannel`].
//! 3. Each participant calls [`TallyPoll::cast_ballot`] to publish a
//!    [`CastBallot`] event mapping each slot ID to their [`Availability`].
//!    Ballots may be updated by publishing a new one; later ballots
//!    supersede earlier ones (last-write-wins, guaranteed by channel
//!    ordering).
//! 4. All participants call [`TallyPoll::receive_and_apply`] (or the
//!    partial-results variant [`TallyPoll::receive_and_apply_timeout`])
//!    to pull in remote events and update the local [`PollState`].
//! 5. Whoever wants a summary calls [`TallyPoll::tally`] for per-slot
//!    counts or [`TallyPoll::best_slot`] for the slot with the most
//!    "Yes" votes.
//!
//! # Example
//!
//! ```ignore
//! // Creator
//! let mut poll = TallyPoll::new_poll(&ph, "standup", "Alice",
//!     "Weekly standup",
//!     vec![
//!         Slot::new("mon-9", "Monday 09:00"),
//!         Slot::new("tue-9", "Tuesday 09:00"),
//!     ],
//! ).await?;
//!
//! // Share poll.my_introduction() out-of-band, then:
//! poll.add_member(&ph, &bob_intro)?;
//!
//! // Bob
//! let mut bob_poll = TallyPoll::join_poll(&ph, "standup", "Bob", &alice_intro).await?;
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
use std::sync::Arc;
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
pub struct Slot {
    /// Stable identifier used as the key in ballot maps.
    pub id: String,
    /// Human-readable label shown to participants.
    pub label: String,
}

impl Slot {
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

/// Events published on a [`TallyPoll`] group channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TallyEvent {
    /// Emitted by the poll creator to establish the poll title and slot list.
    /// Every participant's local state is initialized from the first
    /// `CreatePoll` event they observe (subsequent ones are ignored).
    CreatePoll {
        title: String,
        slots: Vec<Slot>,
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
    pub slots: Vec<Slot>,
    /// Latest ballot per sender.  Key: display name; Value: slot-id → availability.
    pub ballots: HashMap<String, HashMap<String, Availability>>,
}

impl PollState {
    /// Fold one `(sender, event)` pair into the state.
    pub fn apply(&mut self, sender: &str, event: TallyEvent) {
        match event {
            TallyEvent::CreatePoll { title, slots } => {
                // Only the first CreatePoll initializes the poll.
                if self.title.is_empty() {
                    self.title = title;
                    self.slots = slots;
                }
            }
            TallyEvent::CastBallot { votes } => {
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
    pub fn best_slot(&self) -> Option<&Slot> {
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
    pub slot: Slot,
    pub yes: u32,
    pub no: u32,
    pub maybe: u32,
}

// ---------------------------------------------------------------------------
// TallyPoll
// ---------------------------------------------------------------------------

/// A distributed meeting-availability poll backed by a
/// [`GroupChannel<TallyEvent>`].
///
/// The local poll state is updated by calling [`receive_one_and_apply`],
/// [`receive_and_apply`], or [`receive_and_apply_timeout`].  State is
/// inspected with [`poll_state`], [`tally`], and [`best_slot`].
pub struct TallyPoll {
    channel: GroupChannel<TallyEvent>,
    state: PollState,
}

impl TallyPoll {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new poll, broadcasting the slot list to the group channel.
    ///
    /// The creator is automatically recorded as the poll initiator.  Call
    /// [`add_member`] for each additional participant after sharing your
    /// [`my_introduction`] with them out-of-band.
    pub async fn new_poll(
        pigeonhole: Arc<PigeonholeClient>,
        poll_name: &str,
        my_display_name: &str,
        title: impl Into<String>,
        slots: Vec<Slot>,
    ) -> Result<Self> {
        let channel = GroupChannel::create(pigeonhole, poll_name, my_display_name).await?;
        let title = title.into();
        let event = TallyEvent::CreatePoll { title: title.clone(), slots: slots.clone() };
        channel.send(event.clone()).await?;
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
        pigeonhole: Arc<PigeonholeClient>,
        poll_name: &str,
        my_display_name: &str,
        creator_intro: &Introduction,
    ) -> Result<Self> {
        let channel = GroupChannel::create(pigeonhole, poll_name, my_display_name).await?;
        channel.add_member(creator_intro)?;
        Ok(Self { channel, state: PollState::default() })
    }

    /// Restore a previously persisted poll from the database.
    pub async fn restore(
        pigeonhole: Arc<PigeonholeClient>,
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
    pub fn add_member(&self, intro: &Introduction) -> Result<()> {
        self.channel.add_member(intro)
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
        let event = TallyEvent::CastBallot { votes };
        self.channel.send(event.clone()).await?;
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
    pub fn best_slot(&self) -> Option<&Slot> {
        self.state.best_slot()
    }
}

// ---------------------------------------------------------------------------
// Unit tests (no network required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn slots() -> Vec<Slot> {
        vec![
            Slot::new("mon", "Monday"),
            Slot::new("tue", "Tuesday"),
            Slot::new("wed", "Wednesday"),
        ]
    }

    fn create_poll() -> TallyEvent {
        TallyEvent::CreatePoll { title: "Standup".to_string(), slots: slots() }
    }

    fn ballot(mon: Availability, tue: Availability, wed: Availability) -> TallyEvent {
        TallyEvent::CastBallot {
            votes: HashMap::from([
                ("mon".to_string(), mon),
                ("tue".to_string(), tue),
                ("wed".to_string(), wed),
            ]),
        }
    }

    // --- CreatePoll ---

    #[test]
    fn create_poll_initialises_state() {
        let mut s = PollState::default();
        s.apply("Alice", create_poll());
        assert_eq!(s.title, "Standup");
        assert_eq!(s.slots.len(), 3);
        assert_eq!(s.slots[0].id, "mon");
    }

    #[test]
    fn second_create_poll_is_ignored() {
        let mut s = PollState::default();
        s.apply("Alice", create_poll());
        s.apply("Alice", TallyEvent::CreatePoll {
            title: "Impostor".to_string(),
            slots: vec![Slot::new("x", "X")],
        });
        assert_eq!(s.title, "Standup");
        assert_eq!(s.slots.len(), 3);
    }

    // --- CastBallot ---

    #[test]
    fn cast_ballot_records_votes() {
        let mut s = PollState::default();
        s.apply("Alice", create_poll());
        s.apply("Alice", ballot(Availability::Yes, Availability::No, Availability::Maybe));
        let alice = s.ballots.get("Alice").expect("Alice ballot");
        assert_eq!(alice["mon"], Availability::Yes);
        assert_eq!(alice["tue"], Availability::No);
        assert_eq!(alice["wed"], Availability::Maybe);
    }

    #[test]
    fn later_ballot_replaces_earlier_one() {
        let mut s = PollState::default();
        s.apply("Bob", create_poll());
        s.apply("Bob", ballot(Availability::No, Availability::No, Availability::No));
        s.apply("Bob", ballot(Availability::Yes, Availability::Yes, Availability::Yes));
        let bob = s.ballots.get("Bob").expect("Bob ballot");
        assert_eq!(bob["mon"], Availability::Yes);
    }

    // --- tally ---

    #[test]
    fn tally_counts_correctly() {
        let mut s = PollState::default();
        s.apply("Alice", create_poll());
        s.apply("Alice", ballot(Availability::Yes,  Availability::No,    Availability::Maybe));
        s.apply("Bob",   ballot(Availability::Yes,  Availability::Maybe, Availability::No));
        s.apply("Carol", ballot(Availability::No,   Availability::Yes,   Availability::Yes));

        let t = s.tally();
        let mon = t.iter().find(|x| x.slot.id == "mon").unwrap();
        let tue = t.iter().find(|x| x.slot.id == "tue").unwrap();
        let wed = t.iter().find(|x| x.slot.id == "wed").unwrap();

        assert_eq!((mon.yes, mon.no, mon.maybe), (2, 1, 0));
        assert_eq!((tue.yes, tue.no, tue.maybe), (1, 1, 1));
        assert_eq!((wed.yes, wed.no, wed.maybe), (1, 1, 1));
    }

    #[test]
    fn tally_empty_when_no_ballots() {
        let mut s = PollState::default();
        s.apply("Alice", create_poll());
        let t = s.tally();
        assert!(t.iter().all(|x| x.yes == 0 && x.no == 0 && x.maybe == 0));
    }

    // --- best_slot ---

    #[test]
    fn best_slot_returns_highest_yes() {
        let mut s = PollState::default();
        s.apply("Alice", create_poll());
        s.apply("Alice", ballot(Availability::No,  Availability::No,  Availability::Yes));
        s.apply("Bob",   ballot(Availability::No,  Availability::Yes, Availability::Yes));
        s.apply("Carol", ballot(Availability::Yes, Availability::Yes, Availability::Yes));
        // wed has 3 Yes, tue has 2, mon has 1
        assert_eq!(s.best_slot().unwrap().id, "wed");
    }

    #[test]
    fn best_slot_tie_broken_by_creation_order() {
        let mut s = PollState::default();
        s.apply("Alice", create_poll());
        // mon and tue each get 1 Yes; mon is first → mon wins
        s.apply("Alice", ballot(Availability::Yes, Availability::No,  Availability::No));
        s.apply("Bob",   ballot(Availability::No,  Availability::Yes, Availability::No));
        assert_eq!(s.best_slot().unwrap().id, "mon");
    }

    #[test]
    fn best_slot_none_when_no_yes_votes() {
        let mut s = PollState::default();
        s.apply("Alice", create_poll());
        s.apply("Alice", ballot(Availability::No, Availability::Maybe, Availability::No));
        assert!(s.best_slot().is_none());
    }

    #[test]
    fn best_slot_none_when_no_ballots() {
        let mut s = PollState::default();
        s.apply("Alice", create_poll());
        assert!(s.best_slot().is_none());
    }
}
