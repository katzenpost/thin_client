// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Group channel: each member has their own typed BACAP stream.

pub mod channel;
pub mod event_channel;

pub use channel::{GroupChannel, Introduction, ReceivedGroupEvent};
pub use event_channel::EventChannel;

