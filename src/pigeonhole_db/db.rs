// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Database layer for pigeonhole state persistence.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};

use super::error::{PigeonholeDbError, Result};
use super::models::{Channel, PendingMessage, ReceivedMessage};

/// Database handle for pigeonhole state.
///
/// This struct manages SQLite database operations for storing
/// channels, pending messages, and received messages.
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Open or create a database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    /// Open an in-memory database (useful for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    /// Initialize the database schema.
    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                write_cap BLOB,
                read_cap BLOB NOT NULL,
                write_index BLOB NOT NULL,
                read_index BLOB NOT NULL,
                is_owned INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER NOT NULL,
                plaintext BLOB NOT NULL,
                message_ciphertext BLOB NOT NULL,
                envelope_descriptor BLOB NOT NULL,
                envelope_hash BLOB NOT NULL UNIQUE,
                box_index BLOB NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                last_attempt_at INTEGER,
                FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS received_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER NOT NULL,
                plaintext BLOB NOT NULL,
                box_index BLOB NOT NULL,
                received_at INTEGER NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_messages(status);
            CREATE INDEX IF NOT EXISTS idx_pending_channel ON pending_messages(channel_id);
            CREATE INDEX IF NOT EXISTS idx_received_channel ON received_messages(channel_id);
            CREATE INDEX IF NOT EXISTS idx_received_unread ON received_messages(is_read);
            "#,
        )?;
        Ok(())
    }

    /// Get current Unix timestamp.
    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    // ========================================================================
    // Channel Operations
    // ========================================================================

    /// Create a new owned channel.
    pub fn create_channel(
        &self,
        name: &str,
        write_cap: &[u8],
        read_cap: &[u8],
        first_index: &[u8],
    ) -> Result<Channel> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        conn.execute(
            r#"INSERT INTO channels (name, write_cap, read_cap, write_index, read_index, is_owned, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7)"#,
            params![name, write_cap, read_cap, first_index, first_index, now, now],
        ).map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return PigeonholeDbError::ChannelAlreadyExists(name.to_string());
                }
            }
            PigeonholeDbError::Database(e)
        })?;

        let id = conn.last_insert_rowid();
        Ok(Channel {
            id,
            name: name.to_string(),
            write_cap: Some(write_cap.to_vec()),
            read_cap: read_cap.to_vec(),
            write_index: first_index.to_vec(),
            read_index: first_index.to_vec(),
            is_owned: true,
            created_at: now,
            updated_at: now,
        })
    }

    /// Import a read-only channel from a shared read capability.
    pub fn import_channel(
        &self,
        name: &str,
        read_cap: &[u8],
        start_index: &[u8],
    ) -> Result<Channel> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        conn.execute(
            r#"INSERT INTO channels (name, write_cap, read_cap, write_index, read_index, is_owned, created_at, updated_at)
               VALUES (?1, NULL, ?2, ?3, ?4, 0, ?5, ?6)"#,
            params![name, read_cap, start_index, start_index, now, now],
        ).map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return PigeonholeDbError::ChannelAlreadyExists(name.to_string());
                }
            }
            PigeonholeDbError::Database(e)
        })?;

        let id = conn.last_insert_rowid();
        Ok(Channel {
            id,
            name: name.to_string(),
            write_cap: None,
            read_cap: read_cap.to_vec(),
            write_index: start_index.to_vec(),
            read_index: start_index.to_vec(),
            is_owned: false,
            created_at: now,
            updated_at: now,
        })
    }

    /// Get a channel by name.
    pub fn get_channel(&self, name: &str) -> Result<Channel> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, write_cap, read_cap, write_index, read_index, is_owned, created_at, updated_at FROM channels WHERE name = ?1"
        )?;

        stmt.query_row(params![name], |row| {
            Ok(Channel {
                id: row.get(0)?,
                name: row.get(1)?,
                write_cap: row.get(2)?,
                read_cap: row.get(3)?,
                write_index: row.get(4)?,
                read_index: row.get(5)?,
                is_owned: row.get::<_, i64>(6)? != 0,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        }).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => PigeonholeDbError::ChannelNotFound(name.to_string()),
            _ => PigeonholeDbError::Database(e),
        })
    }

    /// Get a channel by ID.
    pub fn get_channel_by_id(&self, id: i64) -> Result<Channel> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, write_cap, read_cap, write_index, read_index, is_owned, created_at, updated_at FROM channels WHERE id = ?1"
        )?;

        stmt.query_row(params![id], |row| {
            Ok(Channel {
                id: row.get(0)?,
                name: row.get(1)?,
                write_cap: row.get(2)?,
                read_cap: row.get(3)?,
                write_index: row.get(4)?,
                read_index: row.get(5)?,
                is_owned: row.get::<_, i64>(6)? != 0,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        }).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => PigeonholeDbError::ChannelNotFound(format!("id={}", id)),
            _ => PigeonholeDbError::Database(e),
        })
    }

    /// List all channels.
    pub fn list_channels(&self) -> Result<Vec<Channel>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, write_cap, read_cap, write_index, read_index, is_owned, created_at, updated_at FROM channels ORDER BY name"
        )?;

        let channels = stmt.query_map([], |row| {
            Ok(Channel {
                id: row.get(0)?,
                name: row.get(1)?,
                write_cap: row.get(2)?,
                read_cap: row.get(3)?,
                write_index: row.get(4)?,
                read_index: row.get(5)?,
                is_owned: row.get::<_, i64>(6)? != 0,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(channels)
    }

    /// Update the write index for a channel.
    pub fn update_write_index(&self, channel_id: i64, new_index: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();
        conn.execute(
            "UPDATE channels SET write_index = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_index, now, channel_id],
        )?;
        Ok(())
    }

    /// Update the read index for a channel.
    pub fn update_read_index(&self, channel_id: i64, new_index: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();
        conn.execute(
            "UPDATE channels SET read_index = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_index, now, channel_id],
        )?;
        Ok(())
    }

    /// Delete a channel and all its messages.
    pub fn delete_channel(&self, name: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute("DELETE FROM channels WHERE name = ?1", params![name])?;
        if rows == 0 {
            return Err(PigeonholeDbError::ChannelNotFound(name.to_string()));
        }
        Ok(())
    }

    // ========================================================================
    // Pending Message Operations
    // ========================================================================

    /// Create a pending message.
    pub fn create_pending_message(
        &self,
        channel_id: i64,
        plaintext: &[u8],
        message_ciphertext: &[u8],
        envelope_descriptor: &[u8],
        envelope_hash: &[u8],
        box_index: &[u8],
    ) -> Result<PendingMessage> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        conn.execute(
            r#"INSERT INTO pending_messages
               (channel_id, plaintext, message_ciphertext, envelope_descriptor, envelope_hash, box_index, attempts, status, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 'pending', ?7)"#,
            params![channel_id, plaintext, message_ciphertext, envelope_descriptor, envelope_hash, box_index, now],
        )?;

        let id = conn.last_insert_rowid();
        Ok(PendingMessage {
            id,
            channel_id,
            plaintext: plaintext.to_vec(),
            message_ciphertext: message_ciphertext.to_vec(),
            envelope_descriptor: envelope_descriptor.to_vec(),
            envelope_hash: envelope_hash.to_vec(),
            box_index: box_index.to_vec(),
            attempts: 0,
            status: "pending".to_string(),
            created_at: now,
            last_attempt_at: None,
        })
    }

    /// Get all pending messages for a channel.
    pub fn get_pending_messages(&self, channel_id: i64) -> Result<Vec<PendingMessage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, channel_id, plaintext, message_ciphertext, envelope_descriptor,
                      envelope_hash, box_index, attempts, status, created_at, last_attempt_at
               FROM pending_messages WHERE channel_id = ?1 ORDER BY created_at"#
        )?;

        let messages = stmt.query_map(params![channel_id], |row| {
            Ok(PendingMessage {
                id: row.get(0)?,
                channel_id: row.get(1)?,
                plaintext: row.get(2)?,
                message_ciphertext: row.get(3)?,
                envelope_descriptor: row.get(4)?,
                envelope_hash: row.get(5)?,
                box_index: row.get(6)?,
                attempts: row.get(7)?,
                status: row.get(8)?,
                created_at: row.get(9)?,
                last_attempt_at: row.get(10)?,
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    /// Update pending message status.
    pub fn update_pending_message_status(&self, id: i64, status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();
        conn.execute(
            "UPDATE pending_messages SET status = ?1, attempts = attempts + 1, last_attempt_at = ?2 WHERE id = ?3",
            params![status, now, id],
        )?;
        Ok(())
    }

    /// Delete a pending message (after successful send).
    pub fn delete_pending_message(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM pending_messages WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Delete a pending message by envelope hash.
    pub fn delete_pending_message_by_hash(&self, envelope_hash: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM pending_messages WHERE envelope_hash = ?1", params![envelope_hash])?;
        Ok(())
    }

    // ========================================================================
    // Received Message Operations
    // ========================================================================

    /// Store a received message.
    pub fn create_received_message(
        &self,
        channel_id: i64,
        plaintext: &[u8],
        box_index: &[u8],
    ) -> Result<ReceivedMessage> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        conn.execute(
            r#"INSERT INTO received_messages (channel_id, plaintext, box_index, received_at, is_read)
               VALUES (?1, ?2, ?3, ?4, 0)"#,
            params![channel_id, plaintext, box_index, now],
        )?;

        let id = conn.last_insert_rowid();
        Ok(ReceivedMessage {
            id,
            channel_id,
            plaintext: plaintext.to_vec(),
            box_index: box_index.to_vec(),
            received_at: now,
            is_read: false,
        })
    }

    /// Get unread messages for a channel.
    pub fn get_unread_messages(&self, channel_id: i64) -> Result<Vec<ReceivedMessage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, channel_id, plaintext, box_index, received_at, is_read
               FROM received_messages WHERE channel_id = ?1 AND is_read = 0 ORDER BY received_at"#
        )?;

        let messages = stmt.query_map(params![channel_id], |row| {
            Ok(ReceivedMessage {
                id: row.get(0)?,
                channel_id: row.get(1)?,
                plaintext: row.get(2)?,
                box_index: row.get(3)?,
                received_at: row.get(4)?,
                is_read: row.get::<_, i64>(5)? != 0,
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    /// Mark a message as read.
    pub fn mark_message_read(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE received_messages SET is_read = 1 WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Get all messages for a channel (including read ones).
    pub fn get_all_messages(&self, channel_id: i64) -> Result<Vec<ReceivedMessage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, channel_id, plaintext, box_index, received_at, is_read
               FROM received_messages WHERE channel_id = ?1 ORDER BY received_at"#
        )?;

        let messages = stmt.query_map(params![channel_id], |row| {
            Ok(ReceivedMessage {
                id: row.get(0)?,
                channel_id: row.get(1)?,
                plaintext: row.get(2)?,
                box_index: row.get(3)?,
                received_at: row.get(4)?,
                is_read: row.get::<_, i64>(5)? != 0,
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(messages)
    }
}

