// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Group channel: each member has their own BACAP stream.

use std::collections::HashMap;

use crate::error::ThinClientError;
use crate::persistent::error::{PigeonholeDbError, Result};
use crate::persistent::{ChannelHandle, PigeonholeClient, ReadCapability};

use super::messages::{compute_membership_hash, GroupChatMessage, Introduction};

/// A received message with sender info.
#[derive(Debug, Clone)]
pub struct ReceivedGroupMessage {
    pub sender: String,
    pub message: GroupChatMessage,
}

/// A group chat channel.
pub struct GroupChannel {
    pub name: String,
    pub my_display_name: String,
    my_channel: ChannelHandle,
    member_channels: HashMap<String, ChannelHandle>,
    membership_hash: Vec<u8>,
}

impl GroupChannel {
    /// Create a new group channel.
    pub async fn create(
        pigeonhole: &PigeonholeClient,
        group_name: &str,
        my_display_name: &str,
    ) -> Result<Self> {
        let my_channel_name = format!("group:{}:self", group_name);
        let my_channel = pigeonhole.create_channel(&my_channel_name).await?;
        let membership_hash = compute_membership_hash(&[my_channel.read_cap()]);

        Ok(Self {
            name: group_name.to_string(),
            my_display_name: my_display_name.to_string(),
            my_channel,
            member_channels: HashMap::new(),
            membership_hash,
        })
    }

    /// Restore from persisted channels in the database.
    pub fn restore(
        pigeonhole: &PigeonholeClient,
        group_name: &str,
        my_display_name: &str,
        member_names: &[&str],
    ) -> Result<Self> {
        let my_channel_name = format!("group:{}:self", group_name);
        let my_channel = pigeonhole.get_channel(&my_channel_name)?;

        let mut member_channels = HashMap::new();
        for name in member_names {
            let member_channel_name = format!("group:{}:member:{}", group_name, name);
            let channel = pigeonhole.get_channel(&member_channel_name)?;
            member_channels.insert(name.to_string(), channel);
        }

        let mut caps: Vec<&[u8]> = vec![my_channel.read_cap()];
        for channel in member_channels.values() {
            caps.push(channel.read_cap());
        }
        let membership_hash = compute_membership_hash(&caps);

        Ok(Self {
            name: group_name.to_string(),
            my_display_name: my_display_name.to_string(),
            my_channel,
            member_channels,
            membership_hash,
        })
    }

    /// Get our read capability for sharing with others.
    pub fn my_read_capability(&self) -> Introduction {
        let read_cap = self.my_channel.share_read_capability();
        Introduction::new(&self.my_display_name, read_cap.read_cap, read_cap.start_index)
    }

    pub fn member_count(&self) -> usize {
        self.member_channels.len()
    }

    /// Add a member by importing their read capability.
    pub fn add_member(&mut self, pigeonhole: &PigeonholeClient, intro: &Introduction) -> Result<()> {
        let channel_name = format!("group:{}:member:{}", self.name, intro.display_name);
        let read_cap = ReadCapability {
            read_cap: intro.read_cap.clone(),
            start_index: intro.start_index.clone(),
            name: Some(intro.display_name.clone()),
        };
        let channel = pigeonhole.import_channel(&channel_name, &read_cap)?;
        self.member_channels.insert(intro.display_name.clone(), channel);
        self.update_membership_hash();
        Ok(())
    }

    pub fn remove_member(&mut self, display_name: &str) -> bool {
        let removed = self.member_channels.remove(display_name).is_some();
        if removed {
            self.update_membership_hash();
        }
        removed
    }

    fn update_membership_hash(&mut self) {
        let mut caps: Vec<&[u8]> = vec![self.my_channel.read_cap()];
        for channel in self.member_channels.values() {
            caps.push(channel.read_cap());
        }
        self.membership_hash = compute_membership_hash(&caps);
    }

    /// Send a text message.
    pub async fn send_text(&mut self, text: &str) -> Result<()> {
        let msg = GroupChatMessage::text(self.membership_hash.clone(), text);
        let payload = msg.to_cbor()
            .map_err(|e| PigeonholeDbError::Other(format!("CBOR error: {}", e)))?;
        self.my_channel.send(&payload).await
    }

    /// Send an introduction message.
    pub async fn send_introduction(&mut self, intro: &Introduction) -> Result<()> {
        let msg = GroupChatMessage::introduction(
            self.membership_hash.clone(),
            &intro.display_name,
            intro.read_cap.clone(),
            intro.start_index.clone(),
        );
        let payload = msg.to_cbor()
            .map_err(|e| PigeonholeDbError::Other(format!("CBOR error: {}", e)))?;
        self.my_channel.send(&payload).await
    }

    /// Poll all members for new messages (non-blocking).
    pub async fn poll_all(&mut self) -> Result<Vec<ReceivedGroupMessage>> {
        let mut all_messages = Vec::new();
        let names: Vec<String> = self.member_channels.keys().cloned().collect();

        for name in names {
            loop {
                let channel = self.member_channels.get_mut(&name).unwrap();
                match channel.receive_no_retry().await {
                    Ok(payload) => {
                        let msg = GroupChatMessage::from_cbor(&payload)
                            .map_err(|e| PigeonholeDbError::Other(format!("CBOR error: {}", e)))?;
                        all_messages.push(ReceivedGroupMessage {
                            sender: name.clone(),
                            message: msg,
                        });
                    }
                    Err(PigeonholeDbError::ThinClient(ThinClientError::BoxNotFound)) => break,
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(all_messages)
    }

    /// Poll until at least `min_count` messages are received, or timeout.
    ///
    /// This method repeatedly calls `poll_all()` until the minimum number of
    /// messages is received, or the timeout expires. Useful for waiting on
    /// message propagation through the mixnet.
    ///
    /// # Arguments
    /// * `min_count` - Minimum number of messages to wait for
    /// * `timeout` - Maximum time to wait
    /// * `poll_interval` - Time to wait between poll attempts
    ///
    /// # Returns
    /// The received messages, or an error if the timeout expires.
    pub async fn poll_until(
        &mut self,
        min_count: usize,
        timeout: std::time::Duration,
        poll_interval: std::time::Duration,
    ) -> Result<Vec<ReceivedGroupMessage>> {
        let start = std::time::Instant::now();
        let mut all_messages = Vec::new();

        loop {
            let msgs = self.poll_all().await?;
            all_messages.extend(msgs);

            if all_messages.len() >= min_count {
                return Ok(all_messages);
            }

            if start.elapsed() > timeout {
                return Err(PigeonholeDbError::Other(format!(
                    "Timeout after {:?}: expected {} messages, got {}",
                    timeout, min_count, all_messages.len()
                )));
            }

            tokio::time::sleep(poll_interval).await;
        }
    }
}

