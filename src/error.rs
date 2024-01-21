// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! ThinClient error types.

use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ThinClientError {
    ConnectError,
    IoError(std::io::Error),
}

impl fmt::Display for ThinClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ThinClientError::*;
        match *self {
	    ConnectError => write!(f, "Connect error."),
	    IoError(_) => write!(f, "IO error."),
	    
        }
    }
}

impl Error for ThinClientError {
    fn description(&self) -> &str {
        "I'm a SphinxUnwrapError."
    }

    fn cause(&self) -> Option<&dyn Error> {
        use self::ThinClientError::*;
        match *self {
            ConnectError => None,
	    IoError(_) => None,
        }
    }
}

// Implementing `From` for converting `std::io::Error` to `ThinClientError`
impl From<std::io::Error> for ThinClientError {
    fn from(err: std::io::Error) -> Self {
        ThinClientError::IoError(err)
    }
}
