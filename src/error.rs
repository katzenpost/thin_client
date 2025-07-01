// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ThinClientError {
    IoError(std::io::Error),
    CborError(serde_cbor::Error),
    ConnectError,
    MissingPkiDocument,
    ServiceNotFound,
    OfflineMode(String),
    Other(String),
}

impl fmt::Display for ThinClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ThinClientError::IoError(err) => write!(f, "IO Error: {}", err),
            ThinClientError::CborError(err) => write!(f, "CBOR Error: {}", err),
            ThinClientError::ConnectError => write!(f, "Connection error."),
            ThinClientError::MissingPkiDocument => write!(f, "Missing PKI document."),
            ThinClientError::ServiceNotFound => write!(f, "Service not found."),
            ThinClientError::OfflineMode(msg) => write!(f, "Offline mode error: {}", msg),
            ThinClientError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl Error for ThinClientError {}

impl From<std::io::Error> for ThinClientError {
    fn from(err: std::io::Error) -> Self {
        ThinClientError::IoError(err)
    }
}

impl From<serde_cbor::Error> for ThinClientError {
    fn from(err: serde_cbor::Error) -> Self {
        ThinClientError::CborError(err)
    }
}
