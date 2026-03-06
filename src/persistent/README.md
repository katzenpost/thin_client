# Persistent Pigeonhole API

This module provides a high-level API for pigeonhole messaging with automatic state persistence via SQLite.

## API Summary

```rust
// PigeonholeClient
PigeonholeClient::new(client, db) -> Self
PigeonholeClient::new_in_memory(client) -> Result<Self>
client.create_channel(name) -> Result<ChannelHandle>
client.import_channel(name, &read_cap) -> Result<ChannelHandle>
client.get_channel(name) -> Result<ChannelHandle>
client.list_channels() -> Result<Vec<Channel>>
client.delete_channel(name) -> Result<()>

// ChannelHandle - State
channel.name() -> &str
channel.is_owned() -> bool
channel.refresh() -> Result<()>
channel.share_read_capability() -> ReadCapability
channel.write_cap() -> Option<&[u8]>
channel.read_cap() -> &[u8]
channel.write_index() -> Option<&[u8]>
channel.read_index() -> &[u8]

// ChannelHandle - Messaging
channel.send(&plaintext) -> Result<()>
channel.receive() -> Result<Vec<u8>>
channel.write_box(&plaintext, &index) -> Result<Vec<u8>>
channel.read_box(&index) -> Result<(Vec<u8>, Vec<u8>)>
channel.get_unread_messages() -> Result<Vec<ReceivedMessage>>
channel.get_all_messages() -> Result<Vec<ReceivedMessage>>
channel.mark_message_read(id) -> Result<()>

// ChannelHandle - Tombstones
channel.tombstone_current() -> Result<()>
channel.tombstone_range(count) -> Result<u32>

// ChannelHandle - Copy
channel.copy_stream_builder() -> Result<CopyStreamBuilder>
channel.execute_copy(courier_hash, queue_id) -> Result<()>
channel.cancel_copy(&write_cap_hash) -> Result<()>

// CopyStreamBuilder
builder.add_payload(&data, &dest_cap, &dest_idx, is_last) -> Result<usize>
builder.add_multi_payload(destinations, is_last) -> Result<usize>
builder.finish() -> Result<usize>
builder.finish_with_courier(&hash, &queue) -> Result<usize>
builder.buffer() -> &[u8]
builder.stream_id() -> &[u8; 16]
builder.temp_write_cap() -> &[u8]
```

## Overview

The persistent API simplifies pigeonhole operations by:

- **Automatic index tracking**: Write and read indices are managed automatically
- **Database persistence**: All state survives restarts
- **Pending message recovery**: Unsent messages can be retried after crashes
- **Message history**: Received messages are stored and can be queried

## Quick Start

```rust
use katzenpost_thin_client::persistent::{PigeonholeClient, Database};

// Open database and create client
let db = Database::open("my_app.db")?;
let client = PigeonholeClient::new(thin_client, db);

// Create a channel (you own this - can send and receive)
let mut alice_channel = client.create_channel("alice-inbox").await?;

// Send a message
alice_channel.send(b"Hello, world!").await?;

// Share read capability with someone else
let read_cap = alice_channel.share_read_capability();
println!("Share this: {:?}", read_cap.to_bytes());
```

## Channel Types

### Owned Channels

Created with `create_channel()`. You have full read/write access.

```rust
let mut channel = client.create_channel("my-channel").await?;
channel.send(b"message").await?;         // ✓ Can send
let msg = channel.receive().await?;       // ✓ Can receive
```

### Imported Channels (Read-Only)

Created by importing someone else's `ReadCapability`. You can only receive.

```rust
let read_cap = ReadCapability::from_bytes(&shared_bytes)?;
let channel = client.import_channel("friend-channel", &read_cap)?;
let msg = channel.receive().await?;       // ✓ Can receive
// channel.send(b"x").await?;             // ✗ Error: read-only
```

## Core Operations

### High-Level Send/Receive

The simplest way to use channels:

```rust
// Send (owned channels only)
channel.send(b"Hello!").await?;

// Receive (advances read index automatically)
let plaintext = channel.receive().await?;
```

### Low-Level Box Operations

For precise control over message indices:

```rust
// Write to a specific box (does NOT advance write index)
let next_idx = channel.write_box(b"payload", &box_index).await?;

// Read from a specific box (does NOT advance read index)
let (plaintext, next_idx) = channel.read_box(&box_index).await?;
```

### Message History

Query received messages from the database:

```rust
// Get unread messages
let unread = channel.get_unread_messages()?;

// Get all messages
let all = channel.get_all_messages()?;

// Mark as read
channel.mark_message_read(message.id)?;
```

## Tombstones (Deletion)

Tombstones delete messages by writing empty payloads with valid signatures.

```rust
// Delete the current write position
channel.tombstone_current().await?;

// Delete a range of boxes (returns count of successful tombstones)
let deleted = channel.tombstone_range(10).await?;
```

Reading a tombstoned box returns an empty `Vec<u8>`.

## Copy Streams (Large Payloads)

For payloads larger than a single box, use `CopyStreamBuilder`:

```rust
let mut builder = channel.copy_stream_builder().await?;

// Stream data in chunks (e.g., reading from a file)
while let Some(chunk) = file.read_chunk()? {
    let is_last = file.is_eof();
    builder.add_payload(&chunk, &dest_write_cap, &dest_index, is_last).await?;
}

// Execute the copy command
let boxes_written = builder.finish().await?;
```

### Multi-Destination Copy

Send to multiple destinations efficiently:

```rust
let destinations = vec![
    (payload1.as_slice(), dest1_write_cap.as_slice(), dest1_index.as_slice()),
    (payload2.as_slice(), dest2_write_cap.as_slice(), dest2_index.as_slice()),
];
builder.add_multi_payload(destinations, true).await?;
```

### Crash Recovery

The `CopyStreamBuilder` exposes its internal buffer for persistence:

```rust
// After each add_payload call, save the buffer
let buffer = builder.buffer().to_vec();
db.save_stream_state(&stream_id, &buffer)?;

// On restart, restore the buffer before continuing
thin_client.set_stream_buffer(&stream_id, &saved_buffer).await?;
```

## Database Schema

Three tables are used:

| Table | Purpose |
|-------|---------|
| `channels` | Channel state (capabilities, indices, ownership) |
| `pending_messages` | Outgoing messages awaiting confirmation |
| `received_messages` | Incoming messages with read/unread status |

## Error Handling

All operations return `Result<T, PigeonholeDbError>`:

```rust
match client.get_channel("nonexistent") {
    Ok(ch) => { /* use channel */ }
    Err(PigeonholeDbError::ChannelNotFound(name)) => {
        println!("Channel {} not found", name);
    }
    Err(e) => return Err(e.into()),
}
```

## Testing

Use `new_in_memory()` for tests:

```rust
let client = PigeonholeClient::new_in_memory(thin_client)?;
// All data is lost when client is dropped
```

