// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Error types for the persistent pigeonhole module.

use std::fmt;

/// Errors that can occur in the persistent pigeonhole module.
#[derive(Debug)]
pub enum PigeonholeDbError {
    /// Database error from rusqlite.
    Database(rusqlite::Error),
    /// Channel not found in database.
    ChannelNotFound(String),
    /// Channel already exists with the given name.
    ChannelAlreadyExists(String),
    /// Message not found.
    MessageNotFound(i64),
    /// Invalid capability data.
    InvalidCapability(String),
    /// Thin client error (from underlying pigeonhole operations).
    ThinClient(crate::error::ThinClientError),
    /// I/O error.
    Io(std::io::Error),
    /// Other error with message.
    Other(String),
}

impl fmt::Display for PigeonholeDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PigeonholeDbError::Database(e) => write!(f, "Database error: {}", e),
            PigeonholeDbError::ChannelNotFound(name) => write!(f, "Channel not found: {}", name),
            PigeonholeDbError::ChannelAlreadyExists(name) => {
                write!(f, "Channel already exists: {}", name)
            }
            PigeonholeDbError::MessageNotFound(id) => write!(f, "Message not found: {}", id),
            PigeonholeDbError::InvalidCapability(msg) => write!(f, "Invalid capability: {}", msg),
            PigeonholeDbError::ThinClient(e) => write!(f, "Thin client error: {}", e),
            PigeonholeDbError::Io(e) => write!(f, "I/O error: {}", e),
            PigeonholeDbError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for PigeonholeDbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PigeonholeDbError::Database(e) => Some(e),
            PigeonholeDbError::ThinClient(e) => Some(e),
            PigeonholeDbError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for PigeonholeDbError {
    fn from(err: rusqlite::Error) -> Self {
        PigeonholeDbError::Database(err)
    }
}

impl From<crate::error::ThinClientError> for PigeonholeDbError {
    fn from(err: crate::error::ThinClientError) -> Self {
        PigeonholeDbError::ThinClient(err)
    }
}

impl From<std::io::Error> for PigeonholeDbError {
    fn from(err: std::io::Error) -> Self {
        PigeonholeDbError::Io(err)
    }
}

/// Result type for persistent pigeonhole operations.
pub type Result<T> = std::result::Result<T, PigeonholeDbError>;
