// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Group chat built on top of [`GroupChannel`].
//!
//! [`GroupChat`] is a thin newtype around `GroupChannel<ChatEvent>` that adds
//! typed convenience methods (`send_text`, `send_introduction`) so callers
//! never have to construct [`ChatEvent`] variants by hand.
//!
//! # Example
//!
//! ```ignore
//! let ph = Arc::new(PigeonholeClient::new_in_memory(thin_client.clone())?);
//! let chat = GroupChat::create(ph.clone(), "my-room", "Alice").await?;
//! let intro = chat.my_introduction();
//!
//! // share `intro` out-of-band, then:
//! chat.add_member(&bob_intro)?;
//!
//! chat.send_text("hello everyone!").await?;
//!
//! let events = chat.receive_from_all().await?;
//! for e in events {
//!     if let ChatEvent::Text(msg) = e.event {
//!         println!("{}: {}", e.sender, msg);
//!     }
//! }
//! ```

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::group::channel::{GroupChannel, ReceivedGroupEvent};
use crate::group::Introduction;
use crate::persistent::error::Result;
use crate::persistent::PigeonholeClient;

// ---------------------------------------------------------------------------
// Event type
// ---------------------------------------------------------------------------

/// The event type carried by every [`GroupChat`] channel.
///
/// `Text` is a plain UTF-8 message.  `Introduction` carries the read
/// capability of a new member so that existing members can add them without
/// a separate out-of-band exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChatEvent {
    Text(String),
    Introduction(Introduction),
}

// ---------------------------------------------------------------------------
// GroupChat
// ---------------------------------------------------------------------------

/// A group chat room backed by a [`GroupChannel<ChatEvent>`].
///
/// Wraps all membership and receive operations from the inner channel and
/// adds typed send helpers so callers work with chat concepts rather than
/// raw event envelopes.
pub struct GroupChat(GroupChannel<ChatEvent>);

impl GroupChat {
    /// Create a new chat room and generate the local member's channel.
    pub async fn create(
        pigeonhole: Arc<PigeonholeClient>,
        room_name: &str,
        my_display_name: &str,
    ) -> Result<Self> {
        GroupChannel::create(pigeonhole, room_name, my_display_name)
            .await
            .map(Self)
    }

    /// Restore a previously created chat room from persisted channels.
    pub async fn restore(
        pigeonhole: Arc<PigeonholeClient>,
        room_name: &str,
        my_display_name: &str,
        member_intros: &[Introduction],
    ) -> Result<Self> {
        GroupChannel::restore(pigeonhole, room_name, my_display_name, member_intros)
            .await
            .map(Self)
    }

    /// Return an [`Introduction`] suitable for sharing with new members.
    pub fn my_introduction(&self) -> Introduction {
        self.0.my_introduction()
    }

    /// Number of remote member channels currently tracked.
    pub fn member_count(&self) -> usize {
        self.0.member_count()
    }

    /// Import a member's read capability and start tracking their channel.
    ///
    /// Pass [`Introduction::member_id`] to `remove_member` to undo this.
    pub fn add_member(&self, intro: &Introduction) -> Result<()> {
        self.0.add_member(intro)
    }

    /// Remove a member's channel from local tracking.
    ///
    /// `member_id` is [`Introduction::member_id`] for the member to remove.
    /// Returns `true` if the member was present.
    pub fn remove_member(&self, member_id: &str) -> bool {
        self.0.remove_member(member_id)
    }

    // -----------------------------------------------------------------------
    // Typed send helpers
    // -----------------------------------------------------------------------

    /// Send a plain-text message to the group.
    pub async fn send_text(&self, text: &str) -> Result<()> {
        self.0.send(ChatEvent::Text(text.to_string())).await
    }

    /// Broadcast an [`Introduction`] so existing members can add the newcomer.
    pub async fn send_introduction(&self, intro: &Introduction) -> Result<()> {
        self.0.send(ChatEvent::Introduction(intro.clone())).await
    }

    // -----------------------------------------------------------------------
    // Channel rotation
    // -----------------------------------------------------------------------

    /// Initiate a channel rotation for post-compromise security.
    ///
    /// See [`GroupChannel::rotate_channel`] for the full protocol description.
    pub async fn rotate_channel(&self) -> crate::persistent::error::Result<()> {
        self.0.rotate_channel().await
    }

    /// Returns `true` if a channel rotation handshake is in progress.
    pub fn rotation_pending(&self) -> bool {
        self.0.rotation_pending()
    }

    // -----------------------------------------------------------------------
    // Receive
    // -----------------------------------------------------------------------

    /// Block until every member delivers one event.
    pub async fn receive_from_all(&self) -> Result<Vec<ReceivedGroupEvent<ChatEvent>>> {
        self.0.receive_from_all().await
    }

    /// Like [`receive_from_all`] but returns after `timeout` with partial results.
    pub async fn receive_from_all_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Vec<ReceivedGroupEvent<ChatEvent>>> {
        self.0.receive_from_all_timeout(timeout).await
    }

    /// Block until any member delivers an event.
    pub async fn receive_any(&self) -> Result<ReceivedGroupEvent<ChatEvent>> {
        self.0.receive_any().await
    }

    /// Block until the member identified by `member_id` delivers an event.
    ///
    /// `member_id` is [`Introduction::member_id`] for the target member.
    pub async fn receive_from(&self, member_id: &str) -> Result<ReceivedGroupEvent<ChatEvent>> {
        self.0.receive_from(member_id).await
    }
}
