// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! Database layer for pigeonhole state persistence.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};

use super::error::{PigeonholeDbError, Result};
use super::models::{PendingMessage, ReadChannel, ReceivedMessage, WriteChannel};

/// Database handle for pigeonhole state.
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

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS write_channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                write_cap BLOB NOT NULL,
                next_index BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS read_channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                read_cap BLOB NOT NULL,
                next_index BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                write_channel_id INTEGER NOT NULL,
                plaintext BLOB NOT NULL,
                message_ciphertext BLOB NOT NULL,
                envelope_descriptor BLOB NOT NULL,
                envelope_hash BLOB NOT NULL UNIQUE,
                box_index BLOB NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                last_attempt_at INTEGER,
                FOREIGN KEY (write_channel_id) REFERENCES write_channels(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS received_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                read_channel_id INTEGER NOT NULL,
                plaintext BLOB NOT NULL,
                box_index BLOB NOT NULL,
                received_at INTEGER NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (read_channel_id) REFERENCES read_channels(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_messages(status);
            CREATE INDEX IF NOT EXISTS idx_pending_write_channel ON pending_messages(write_channel_id);
            CREATE INDEX IF NOT EXISTS idx_received_read_channel ON received_messages(read_channel_id);
            CREATE INDEX IF NOT EXISTS idx_received_unread ON received_messages(is_read);
            "#,
        )?;
        Ok(())
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    // ========================================================================
    // Write Channel Operations
    // ========================================================================

    pub fn create_write_channel(
        &self,
        name: &str,
        write_cap: &[u8],
        next_index: &[u8],
    ) -> Result<WriteChannel> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        conn.execute(
            r#"INSERT INTO write_channels (name, write_cap, next_index, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5)"#,
            params![name, write_cap, next_index, now, now],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                PigeonholeDbError::ChannelAlreadyExists(name.to_string())
            }
            other => PigeonholeDbError::Database(other),
        })?;

        let id = conn.last_insert_rowid();
        Ok(WriteChannel {
            id,
            name: name.to_string(),
            write_cap: write_cap.to_vec(),
            next_index: next_index.to_vec(),
            created_at: now,
            updated_at: now,
        })
    }

    pub fn get_write_channel(&self, name: &str) -> Result<WriteChannel> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, write_cap, next_index, created_at, updated_at \
             FROM write_channels WHERE name = ?1",
        )?;

        stmt.query_row(params![name], |row| {
            Ok(WriteChannel {
                id: row.get(0)?,
                name: row.get(1)?,
                write_cap: row.get(2)?,
                next_index: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                PigeonholeDbError::ChannelNotFound(name.to_string())
            }
            other => PigeonholeDbError::Database(other),
        })
    }

    pub fn get_write_channel_by_id(&self, id: i64) -> Result<WriteChannel> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, write_cap, next_index, created_at, updated_at \
             FROM write_channels WHERE id = ?1",
        )?;

        stmt.query_row(params![id], |row| {
            Ok(WriteChannel {
                id: row.get(0)?,
                name: row.get(1)?,
                write_cap: row.get(2)?,
                next_index: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                PigeonholeDbError::ChannelNotFound(format!("id={}", id))
            }
            other => PigeonholeDbError::Database(other),
        })
    }

    pub fn list_write_channels(&self) -> Result<Vec<WriteChannel>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, write_cap, next_index, created_at, updated_at \
             FROM write_channels ORDER BY name",
        )?;

        let channels = stmt
            .query_map([], |row| {
                Ok(WriteChannel {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    write_cap: row.get(2)?,
                    next_index: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(channels)
    }

    pub fn update_write_next_index(&self, channel_id: i64, new_index: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();
        conn.execute(
            "UPDATE write_channels SET next_index = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_index, now, channel_id],
        )?;
        Ok(())
    }

    pub fn delete_write_channel(&self, name: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute("DELETE FROM write_channels WHERE name = ?1", params![name])?;
        if rows == 0 {
            return Err(PigeonholeDbError::ChannelNotFound(name.to_string()));
        }
        Ok(())
    }

    // ========================================================================
    // Read Channel Operations
    // ========================================================================

    pub fn create_read_channel(
        &self,
        name: &str,
        read_cap: &[u8],
        next_index: &[u8],
    ) -> Result<ReadChannel> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        conn.execute(
            r#"INSERT INTO read_channels (name, read_cap, next_index, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5)"#,
            params![name, read_cap, next_index, now, now],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref err, _)
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                PigeonholeDbError::ChannelAlreadyExists(name.to_string())
            }
            other => PigeonholeDbError::Database(other),
        })?;

        let id = conn.last_insert_rowid();
        Ok(ReadChannel {
            id,
            name: name.to_string(),
            read_cap: read_cap.to_vec(),
            next_index: next_index.to_vec(),
            created_at: now,
            updated_at: now,
        })
    }

    pub fn get_read_channel(&self, name: &str) -> Result<ReadChannel> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, read_cap, next_index, created_at, updated_at \
             FROM read_channels WHERE name = ?1",
        )?;

        stmt.query_row(params![name], |row| {
            Ok(ReadChannel {
                id: row.get(0)?,
                name: row.get(1)?,
                read_cap: row.get(2)?,
                next_index: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                PigeonholeDbError::ChannelNotFound(name.to_string())
            }
            other => PigeonholeDbError::Database(other),
        })
    }

    pub fn get_read_channel_by_id(&self, id: i64) -> Result<ReadChannel> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, read_cap, next_index, created_at, updated_at \
             FROM read_channels WHERE id = ?1",
        )?;

        stmt.query_row(params![id], |row| {
            Ok(ReadChannel {
                id: row.get(0)?,
                name: row.get(1)?,
                read_cap: row.get(2)?,
                next_index: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                PigeonholeDbError::ChannelNotFound(format!("id={}", id))
            }
            other => PigeonholeDbError::Database(other),
        })
    }

    pub fn list_read_channels(&self) -> Result<Vec<ReadChannel>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, read_cap, next_index, created_at, updated_at \
             FROM read_channels ORDER BY name",
        )?;

        let channels = stmt
            .query_map([], |row| {
                Ok(ReadChannel {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    read_cap: row.get(2)?,
                    next_index: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(channels)
    }

    pub fn update_read_next_index(&self, channel_id: i64, new_index: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();
        conn.execute(
            "UPDATE read_channels SET next_index = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_index, now, channel_id],
        )?;
        Ok(())
    }

    pub fn delete_read_channel(&self, name: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute("DELETE FROM read_channels WHERE name = ?1", params![name])?;
        if rows == 0 {
            return Err(PigeonholeDbError::ChannelNotFound(name.to_string()));
        }
        Ok(())
    }

    // ========================================================================
    // Pending Message Operations
    // ========================================================================

    pub fn create_pending_message(
        &self,
        write_channel_id: i64,
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
               (write_channel_id, plaintext, message_ciphertext, envelope_descriptor, envelope_hash, box_index, attempts, status, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 'pending', ?7)"#,
            params![write_channel_id, plaintext, message_ciphertext, envelope_descriptor, envelope_hash, box_index, now],
        )?;

        let id = conn.last_insert_rowid();
        Ok(PendingMessage {
            id,
            write_channel_id,
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

    pub fn get_pending_messages(&self, write_channel_id: i64) -> Result<Vec<PendingMessage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, write_channel_id, plaintext, message_ciphertext, envelope_descriptor,
                      envelope_hash, box_index, attempts, status, created_at, last_attempt_at
               FROM pending_messages WHERE write_channel_id = ?1 ORDER BY created_at"#,
        )?;

        let messages = stmt
            .query_map(params![write_channel_id], |row| {
                Ok(PendingMessage {
                    id: row.get(0)?,
                    write_channel_id: row.get(1)?,
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
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    pub fn update_pending_message_status(&self, id: i64, status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();
        conn.execute(
            "UPDATE pending_messages SET status = ?1, attempts = attempts + 1, last_attempt_at = ?2 WHERE id = ?3",
            params![status, now, id],
        )?;
        Ok(())
    }

    pub fn delete_pending_message(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM pending_messages WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn delete_pending_message_by_hash(&self, envelope_hash: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM pending_messages WHERE envelope_hash = ?1",
            params![envelope_hash],
        )?;
        Ok(())
    }

    // ========================================================================
    // Received Message Operations
    // ========================================================================

    pub fn create_received_message(
        &self,
        read_channel_id: i64,
        plaintext: &[u8],
        box_index: &[u8],
    ) -> Result<ReceivedMessage> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        conn.execute(
            r#"INSERT INTO received_messages (read_channel_id, plaintext, box_index, received_at, is_read)
               VALUES (?1, ?2, ?3, ?4, 0)"#,
            params![read_channel_id, plaintext, box_index, now],
        )?;

        let id = conn.last_insert_rowid();
        Ok(ReceivedMessage {
            id,
            read_channel_id,
            plaintext: plaintext.to_vec(),
            box_index: box_index.to_vec(),
            received_at: now,
            is_read: false,
        })
    }

    pub fn get_unread_messages(&self, read_channel_id: i64) -> Result<Vec<ReceivedMessage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, read_channel_id, plaintext, box_index, received_at, is_read
               FROM received_messages WHERE read_channel_id = ?1 AND is_read = 0 ORDER BY received_at"#,
        )?;

        let messages = stmt
            .query_map(params![read_channel_id], |row| {
                Ok(ReceivedMessage {
                    id: row.get(0)?,
                    read_channel_id: row.get(1)?,
                    plaintext: row.get(2)?,
                    box_index: row.get(3)?,
                    received_at: row.get(4)?,
                    is_read: row.get::<_, i64>(5)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    pub fn mark_message_read(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE received_messages SET is_read = 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn get_all_messages(&self, read_channel_id: i64) -> Result<Vec<ReceivedMessage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, read_channel_id, plaintext, box_index, received_at, is_read
               FROM received_messages WHERE read_channel_id = ?1 ORDER BY received_at"#,
        )?;

        let messages = stmt
            .query_map(params![read_channel_id], |row| {
                Ok(ReceivedMessage {
                    id: row.get(0)?,
                    read_channel_id: row.get(1)?,
                    plaintext: row.get(2)?,
                    box_index: row.get(3)?,
                    received_at: row.get(4)?,
                    is_read: row.get::<_, i64>(5)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(messages)
    }
}
