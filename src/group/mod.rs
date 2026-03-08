// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Group chat: each member has their own BACAP stream.

pub mod channel;
pub mod messages;

pub use channel::{GroupChannel, ReceivedGroupMessage};
pub use messages::{GroupChatMessage, Introduction};

