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

    // Pigeonhole replica error codes (from pigeonhole/errors.go)
    /// Box ID not found on the replica (error code 1)
    BoxNotFound,
    /// Invalid box ID format (error code 2)
    InvalidBoxId,
    /// Invalid or missing signature (error code 3)
    InvalidSignature,
    /// Database operation failed (error code 4)
    DatabaseFailure,
    /// Invalid payload data (error code 5)
    InvalidPayload,
    /// Storage capacity exceeded (error code 6)
    StorageFull,
    /// Internal replica error (error code 7)
    ReplicaInternalError,
    /// Invalid epoch (error code 8)
    InvalidEpoch,
    /// Replication to other replicas failed (error code 9)
    ReplicationFailed,
    /// Box already exists / already written (error code 10)
    BoxAlreadyExists,
    /// Box contains a tombstone - intentional deletion (error code 11)
    Tombstone,
    /// MKEM decryption failed (error code 22)
    MkemDecryptionFailed,
    /// BACAP decryption failed (error code 23)
    BacapDecryptionFailed,
    /// Operation was cancelled (error code 24)
    StartResendingCancelled,
    /// Tombstone signature verification failed (error code 25)
    InvalidTombstoneSignature,
    /// Copy command reported CopyStatusFailed by the courier (error code 26).
    ///
    /// `replica_error_code` is the pigeonhole replica `ErrorCode` that
    /// triggered the abort (e.g. `10 = BoxAlreadyExists`); 0 if not reported.
    /// `failed_envelope_index` is the 1-based position in the copy stream of
    /// the envelope whose write triggered the abort; 0 if not applicable.
    /// This is NOT a BACAP message index.
    CopyCommandFailed {
        replica_error_code: u8,
        failed_envelope_index: u64,
    },

    Timeout(String),
    Other(String),
}

/// Maps daemon error codes to ThinClientError variants.
/// This matches the Go `errorCodeToSentinel` function.
pub fn error_code_to_error(error_code: u8) -> ThinClientError {
    match error_code {
        0 => ThinClientError::Other("unexpected success code in error path".to_string()),
        1 => ThinClientError::BoxNotFound,
        2 => ThinClientError::InvalidBoxId,
        3 => ThinClientError::InvalidSignature,
        4 => ThinClientError::DatabaseFailure,
        5 => ThinClientError::InvalidPayload,
        6 => ThinClientError::StorageFull,
        7 => ThinClientError::ReplicaInternalError,
        8 => ThinClientError::InvalidEpoch,
        9 => ThinClientError::ReplicationFailed,
        10 => ThinClientError::BoxAlreadyExists,
        11 => ThinClientError::Tombstone,
        22 => ThinClientError::MkemDecryptionFailed,
        23 => ThinClientError::BacapDecryptionFailed,
        24 => ThinClientError::StartResendingCancelled,
        25 => ThinClientError::InvalidTombstoneSignature,
        code => ThinClientError::Other(format!("unknown error code: {}", code)),
    }
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
            ThinClientError::BoxNotFound => write!(f, "Box ID not found"),
            ThinClientError::InvalidBoxId => write!(f, "Invalid box ID"),
            ThinClientError::InvalidSignature => write!(f, "Invalid signature"),
            ThinClientError::DatabaseFailure => write!(f, "Database failure"),
            ThinClientError::InvalidPayload => write!(f, "Invalid payload"),
            ThinClientError::StorageFull => write!(f, "Storage full"),
            ThinClientError::ReplicaInternalError => write!(f, "Replica internal error"),
            ThinClientError::InvalidEpoch => write!(f, "Invalid epoch"),
            ThinClientError::ReplicationFailed => write!(f, "Replication failed"),
            ThinClientError::BoxAlreadyExists => write!(f, "Box already exists"),
            ThinClientError::Tombstone => write!(f, "Tombstone"),
            ThinClientError::MkemDecryptionFailed => write!(f, "MKEM decryption failed"),
            ThinClientError::BacapDecryptionFailed => write!(f, "BACAP decryption failed"),
            ThinClientError::StartResendingCancelled => write!(f, "Start resending cancelled"),
            ThinClientError::InvalidTombstoneSignature => write!(f, "Invalid tombstone signature"),
            ThinClientError::CopyCommandFailed {
                replica_error_code,
                failed_envelope_index,
            } => write!(
                f,
                "Copy command failed: replica_error_code={}, failed_envelope_index={}",
                replica_error_code, failed_envelope_index
            ),
            ThinClientError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            ThinClientError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl ThinClientError {
    /// Returns true for error codes that represent completed operations
    /// rather than failures. These errors should not trigger retries.
    pub fn is_expected_outcome(&self) -> bool {
        matches!(self, ThinClientError::Tombstone | ThinClientError::BoxNotFound | ThinClientError::BoxAlreadyExists)
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
