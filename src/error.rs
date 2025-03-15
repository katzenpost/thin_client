// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! ThinClient error types.

use std::error::Error;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum ThinClientError {
    ConnectError,
    IoError(io::Error),
    CborError(serde_cbor::Error),
    InvalidResponse,
    UnexpectedEOF,
}

impl fmt::Display for ThinClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ThinClientError::ConnectError => write!(f, "Failed to connect to server."),
            ThinClientError::IoError(ref err) => write!(f, "IO error: {}", err),
            ThinClientError::CborError(ref err) => write!(f, "CBOR parsing error: {}", err),
            ThinClientError::InvalidResponse => write!(f, "Received an invalid response."),
            ThinClientError::UnexpectedEOF => write!(f, "Unexpected EOF while reading socket."),
        }
    }
}

impl Error for ThinClientError {}

impl From<io::Error> for ThinClientError {
    fn from(err: io::Error) -> Self {
        ThinClientError::IoError(err)
    }
}

impl From<serde_cbor::Error> for ThinClientError {
    fn from(err: serde_cbor::Error) -> Self {
        ThinClientError::CborError(err)
    }
}

