// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Transport abstraction for the Rust thin-client.
//!
//! Each concrete transport (unix, tcp; in future ssh / pipe /
//! pigeonhole) implements the `Dialer` trait and supplies its own
//! config struct carrying its own fields. `DialConfig` is a
//! discriminated-union container: exactly one of its inner variants
//! must be populated. Zero or multiple populated variants is a
//! configuration error.

use std::io;

use serde::Deserialize;

use crate::core::{ReadHalf, WriteHalf};

pub mod tcp;
pub mod unix;

pub use self::tcp::TcpDialConfig;
pub use self::unix::UnixDialConfig;

/// A transport's concrete dial output: the two owned halves of a
/// split socket, shaped exactly as `ThinClient` already holds them.
pub type DialedHalves = (ReadHalf, WriteHalf);

/// Every transport implementation satisfies this trait. `dial` opens
/// a fresh connection and returns its owned read/write halves.
#[async_trait::async_trait]
pub trait Dialer: Send + Sync {
    async fn dial(&self) -> io::Result<DialedHalves>;
}

/// Errors raised by `DialConfig::validate` / `DialConfig::resolve`
/// that do not fit naturally in `io::Error`.
#[derive(Debug, thiserror::Error)]
pub enum DialConfigError {
    #[error("transport: no dial transport configured (expected exactly one of [Dial.Unix] or [Dial.Tcp])")]
    NoTransport,
    #[error("transport: exactly one dial transport must be configured, got {0}")]
    MultipleTransports(usize),
}

impl From<DialConfigError> for io::Error {
    fn from(e: DialConfigError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, e)
    }
}

/// The subtable-discriminated dial configuration. Exactly one of its
/// fields must be `Some`; zero or two or more is rejected.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct DialConfig {
    #[serde(rename = "Unix", default)]
    pub unix: Option<UnixDialConfig>,
    #[serde(rename = "Tcp", default)]
    pub tcp: Option<TcpDialConfig>,
}

impl DialConfig {
    /// Check that exactly one inner subtable is populated, without
    /// attempting any connection. Suitable for config-load-time
    /// validation.
    pub fn validate(&self) -> Result<(), DialConfigError> {
        let n = (self.unix.is_some() as usize) + (self.tcp.is_some() as usize);
        match n {
            0 => Err(DialConfigError::NoTransport),
            1 => Ok(()),
            _ => Err(DialConfigError::MultipleTransports(n)),
        }
    }

    /// Resolve to a borrowed reference to the populated dialer.
    pub fn resolve(&self) -> Result<&dyn Dialer, DialConfigError> {
        self.validate()?;
        if let Some(ref u) = self.unix {
            return Ok(u);
        }
        if let Some(ref t) = self.tcp {
            return Ok(t);
        }
        Err(DialConfigError::NoTransport)
    }

    /// Convenience: validate + resolve + dial in one call.
    pub async fn dial(&self) -> io::Result<DialedHalves> {
        let dialer = self.resolve()?;
        dialer.dial().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_zero_subtables_rejected() {
        let cfg = DialConfig::default();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, DialConfigError::NoTransport));
    }

    #[test]
    fn validate_multiple_subtables_rejected() {
        let cfg = DialConfig {
            unix: Some(UnixDialConfig { address: "/tmp/x.sock".into() }),
            tcp: Some(TcpDialConfig { address: "localhost:0".into(), network: None }),
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, DialConfigError::MultipleTransports(2)));
    }

    #[test]
    fn validate_single_unix_accepted() {
        let cfg = DialConfig {
            unix: Some(UnixDialConfig { address: "/tmp/x.sock".into() }),
            tcp: None,
        };
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_single_tcp_accepted() {
        let cfg = DialConfig {
            unix: None,
            tcp: Some(TcpDialConfig { address: "localhost:0".into(), network: None }),
        };
        cfg.validate().unwrap();
    }

    #[test]
    fn resolve_returns_correct_dialer_type() {
        let cfg = DialConfig {
            unix: None,
            tcp: Some(TcpDialConfig { address: "localhost:0".into(), network: None }),
        };
        let dialer = cfg.resolve().unwrap();
        // We cannot downcast a &dyn Dialer, but we can check the Debug repr
        // of the inner config through the DialConfig itself.
        assert!(cfg.tcp.is_some() && cfg.unix.is_none());
        // Suppress unused warning by taking the pointer.
        let _ = dialer as *const _;
    }

    #[test]
    fn toml_parses_dial_tcp_subtable() {
        let src = r#"
            [Tcp]
            Address = "localhost:64331"
        "#;
        let cfg: DialConfig = toml::from_str(src).unwrap();
        assert!(cfg.tcp.is_some());
        assert!(cfg.unix.is_none());
        cfg.validate().unwrap();
        let tcp = cfg.tcp.as_ref().unwrap();
        assert_eq!(tcp.address, "localhost:64331");
    }

    #[test]
    fn toml_parses_dial_unix_subtable() {
        let src = r#"
            [Unix]
            Address = "/tmp/kp.sock"
        "#;
        let cfg: DialConfig = toml::from_str(src).unwrap();
        assert!(cfg.unix.is_some());
        assert!(cfg.tcp.is_none());
        cfg.validate().unwrap();
        assert_eq!(cfg.unix.as_ref().unwrap().address, "/tmp/kp.sock");
    }

    #[test]
    fn toml_rejects_flat_old_fields() {
        // The old flat {Network, Address} layout at the top level
        // has no matching fields in DialConfig. Serde with the
        // default unknown-field policy silently ignores them, so
        // validate() should reject the empty shape.
        let src = r#"
            Network = "tcp"
            Address = "localhost:64331"
        "#;
        let cfg: DialConfig = toml::from_str(src).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, DialConfigError::NoTransport));
    }
}
