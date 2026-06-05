// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! pigeonhole-cp - A CLI tool for sending/receiving files to/from pigeonhole channels.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::{Parser, Subcommand};
use rand::RngCore;
use serde::Deserialize;
use tempfile::NamedTempFile;

use katzenpost_thin_client::persistent::PigeonholeClient;
use katzenpost_thin_client::{Config, ThinClient};

const MAX_NAME_LEN: usize = 255;

#[derive(Debug, thiserror::Error)]
pub enum FileNameError {
    #[error("path has no file name component")]
    NoFileName,
    #[error("file name is not valid UTF-8")]
    NotUtf8,
    #[error("file name is reserved: {0:?}")]
    Reserved(String),
    #[error("file name is empty")]
    Empty,
    #[error("file name exceeds 255 bytes")]
    TooLong,
    #[error("file name contains a path separator")]
    PathSeparator,
    #[error("file name contains a control character")]
    ControlChar,
    #[error("destination escapes target directory")]
    EscapesDir,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Validates a received file name against `dest_dir` and returns the
/// resolved on-disk path. The caller should still open the result with
/// `O_NOFOLLOW` and `create_new(true)` to defeat symlink and clobber races.
pub fn sanitize_for_receive(name: &str, dest_dir: &Path) -> Result<PathBuf, FileNameError> {
    if name.is_empty() {
        return Err(FileNameError::Empty);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(FileNameError::TooLong);
    }
    if name == "." || name == ".." {
        return Err(FileNameError::Reserved(name.to_string()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(FileNameError::PathSeparator);
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(FileNameError::ControlChar);
    }

    let dest_canon = dest_dir.canonicalize()?;
    let candidate = dest_canon.join(name);

    match candidate.parent() {
        Some(parent) if parent == dest_canon.as_path() => Ok(candidate),
        _ => Err(FileNameError::EscapesDir),
    }
}

/// Reduces a path to its basename for transmission in FileMetaData.
/// The receiver re-validates; this only ensures we send something sensible.
pub fn strip_for_send(path: &Path) -> Result<String, FileNameError> {
    let basename = path.file_name().ok_or(FileNameError::NoFileName)?;
    let name = basename.to_str().ok_or(FileNameError::NotUtf8)?.to_owned();
    if name == "." || name == ".." {
        return Err(FileNameError::Reserved(name));
    }
    Ok(name)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FileMetaData {
    name: String,
    size: u64,
}

#[derive(Parser)]
#[command(name = "pigeonhole-cp")]
#[command(about = "Katzenpost pigeonhole file copy tool")]
#[command(
    long_about = "A CLI tool for sending/receiving files to/from pigeonhole channels.\n\n\
Similar to rcp or scp:\n\
- Read a file off disk and send it to a Pigeonhole channel (send mode)\n\
- Read from a channel and write file to disk (receive mode)\n\n"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair and print both capabilities
    Genkey {
        /// Configuration file (required)
        #[arg(short, long)]
        config: PathBuf,
    },

    /// Read a file off disk and send it to a Pigeonhole channel
    Send {
        /// Configuration file (required)
        #[arg(short, long)]
        config: PathBuf,

        /// Write capability (base64)
        #[arg(short, long)]
        write_cap: String,

        /// Starting message box index (base64), as emitted by `genkey`
        #[arg(short, long)]
        index: String,

        /// Input file
        #[arg(short, long)]
        file: PathBuf,

        /// Skip the COPY command and write each box directly. The default
        /// is COPY, which gives atomic all-or-nothing semantics on the
        /// destination but caps the payload at roughly 9 MiB per transfer.
        #[arg(long)]
        no_copy: bool,

        /// Use the windowed SACK ARQ to write the payload, keeping many
        /// boxes in flight at once instead of the per-box stop-and-wait of
        /// --no-copy. Takes precedence over --no-copy. The window is
        /// computed automatically by the daemon from the PKI document
        /// (routing layers and Mu).
        #[arg(long)]
        sack: bool,
    },

    /// Read from a Pigeonhole channel and write to a file
    Receive {
        /// Configuration file (required)
        #[arg(short, long)]
        config: PathBuf,

        /// Read capability (base64)
        #[arg(short, long)]
        read_cap: String,

        /// Starting message box index (base64), as emitted by `genkey`
        #[arg(short, long)]
        index: String,

        /// Output directory (file name comes from the FileMetaData header)
        #[arg(short, long)]
        dest_dir: PathBuf,

        /// Use the windowed SACK ARQ to read the payload, keeping many
        /// boxes in flight at once instead of reading one box per round
        /// trip. The window is computed automatically by the daemon from
        /// the PKI document (routing layers and Mu).
        #[arg(long)]
        sack: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Genkey { config } => run_genkey(config).await,
        Commands::Send {
            config,
            write_cap,
            index,
            file,
            no_copy,
            sack,
        } => run_send(config, write_cap, index, file, no_copy, sack).await,
        Commands::Receive {
            config,
            read_cap,
            index,
            dest_dir,
            sack,
        } => run_receive(config, read_cap, index, dest_dir, sack).await,
    }
}

/// Initialize the thin client from config file.
///
/// `ThinClient::new` returns before the worker has finished the daemon
/// handshake (ConnectionStatusEvent + NewPKIDocumentEvent + SessionToken),
/// so issuing a request immediately can race and hang. A short pause lets
/// the handshake settle before the caller tries to use the client.
///
/// Before returning, a background task is spawned that waits for
/// SIGINT or SIGTERM and then calls `ThinClient::stop` so the daemon
/// receives `thin_close` and retires any in-flight ARQ entries cleanly,
/// mirroring what the Go `ping` and docker integration tests do.
/// `ThinClient` has no async `Drop`, so this explicit cleanup is the
/// equivalent.
async fn init_client(config_path: PathBuf) -> Result<Arc<ThinClient>, Box<dyn std::error::Error>> {
    let cfg = Config::new(config_path.to_str().ok_or("Invalid config path")?)?;
    let client = ThinClient::new(cfg).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    install_shutdown_handler(Arc::clone(&client));
    Ok(client)
}

/// Spawn a task that waits for SIGINT or SIGTERM and shuts the thin
/// client down cleanly, then exits the process.
fn install_shutdown_handler(client: Arc<ThinClient>) {
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        eprintln!("\npigeonhole-cp: received shutdown signal, closing thin client");
        client.stop().await;
        std::process::exit(130);
    });
}

/// Resolve as soon as either SIGINT (Ctrl-C) or SIGTERM arrives.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Generate a fresh capability triple and print the three values.
async fn run_genkey(config: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let client = init_client(config).await?;

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let kp = client.new_keypair(&seed).await?;

    println!("Read Capability (share with recipient):");
    println!("{}\n", BASE64.encode(&kp.read_cap));

    println!("Write Capability (keep secret):");
    println!("{}", BASE64.encode(&kp.write_cap));

    Ok(())
}

/// Read from disk and send to a Pigeonhole channel.
///
/// Wire format (both modes):
/// - First plaintext = `[CBOR FileMetaData][file bytes…]`. CBOR is
///   self-delimiting, so the receiver decodes the header and then knows
///   where the file payload begins.
/// - Subsequent plaintext is pure file bytes. The receiver stops after
///   consuming exactly `FileMetaData.size` file bytes.
///
/// Default uses the courier Copy command — the client populates a
/// temporary channel and the courier dispatches its contents to the
/// destination atomically. `--no-copy` falls back to writing each box
/// to the destination directly via per-box ARQ.
async fn run_send(
    config: PathBuf,
    write_cap_b64: String,
    next_index_b64: String,
    input_file: PathBuf,
    no_copy: bool,
    sack: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let write_cap = BASE64.decode(&write_cap_b64)?;
    let next_index = BASE64.decode(&next_index_b64)?;

    let meta = std::fs::metadata(&input_file)?;
    if !meta.is_file() {
        return Err(format!("input must be a regular file: {:?}", input_file).into());
    }
    let total_len = meta.len();
    let file_name = strip_for_send(&input_file)?;
    let header = serde_cbor::to_vec(&FileMetaData {
        name: file_name,
        size: total_len,
    })?;

    let client = init_client(config).await?;
    let pigeonhole = PigeonholeClient::new_in_memory(client.clone())?;

    // --no-copy chooses direct-vs-copy; --sack chooses the windowed ARQ over
    // per-box stop-and-wait. The four combinations are all valid.
    match (no_copy, sack) {
        (true, true) => send_sack(&pigeonhole, &next_index, &input_file, total_len, &header).await,
        (true, false) => {
            send_direct(
                &pigeonhole,
                &write_cap,
                &next_index,
                &input_file,
                total_len,
                &header,
            )
            .await
        }
        (false, true) => {
            send_sack_copy(&pigeonhole, &next_index, &input_file, total_len, &header).await
        }
        (false, false) => {
            send_copy(&pigeonhole, &next_index, &input_file, total_len, &header).await
        }
    }
}

/// SACK + COPY path: stage the payload into a temporary channel using the
/// windowed SACK ARQ, then issue the courier Copy command to dispatch it to
/// the destination atomically. The temporary channel is just a BACAP byte
/// stream of copy-stream elements, so filling it with `write_stream` produces
/// the same stream the per-box `send_copy` builds, only windowed.
async fn send_sack_copy(
    pigeonhole: &PigeonholeClient,
    dest_cap: &[u8],
    input_file: &Path,
    total_len: u64,
    header: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = Vec::with_capacity(header.len() + total_len as usize);
    payload.extend_from_slice(header);
    File::open(input_file)?.read_to_end(&mut payload)?;

    let client = pigeonhole.thin_client();

    // A fresh temporary channel to stage the copy stream.
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let kp = client.new_keypair(&seed).await?;

    // Encode the payload into copy-stream elements addressed at the
    // destination, then concatenate them into the byte stream the temp
    // channel must carry. `dest_cap` is the destination write cap
    // positioned at the box to write; it carries its own box position.
    let result = client
        .create_courier_envelopes_from_payload(&payload, dest_cap, true, true)
        .await?;
    let element_count = result.envelopes.len();
    let mut stream = Vec::new();
    for chunk in &result.envelopes {
        stream.extend_from_slice(chunk);
    }

    let box_payload_size = client.pigeonhole_geometry().max_plaintext_payload_length;
    let boxes = stream.len().div_ceil(box_payload_size - 4);

    let start = std::time::Instant::now();
    client.write_stream(&kp.write_cap, &stream, 0).await?;
    client
        .start_resending_copy_command(&kp.write_cap, None, None)
        .await?;
    print_throughput("sack-copy", total_len, boxes, start.elapsed());
    println!(
        "(staged {} copy-stream elements via temp channel, then COPY)",
        element_count
    );
    Ok(())
}

/// SACK path: assemble the whole payload and write it with the daemon's
/// windowed selective-ack ARQ in a single call, keeping `window` boxes in
/// flight at once. This is the bulk-write counterpart to the per-box
/// `send_direct`; the daemon does all chunking and encryption.
async fn send_sack(
    pigeonhole: &PigeonholeClient,
    write_cap: &[u8],
    input_file: &Path,
    total_len: u64,
    header: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = Vec::with_capacity(header.len() + total_len as usize);
    payload.extend_from_slice(header);
    File::open(input_file)?.read_to_end(&mut payload)?;

    let box_payload_size = pigeonhole
        .thin_client()
        .pigeonhole_geometry()
        .max_plaintext_payload_length;
    let per_box = box_payload_size - 4;
    let boxes = payload.len().div_ceil(per_box);

    let start = std::time::Instant::now();
    pigeonhole
        .thin_client()
        .write_stream(write_cap, &payload, 0)
        .await?;
    print_throughput("sack", total_len, boxes, start.elapsed());
    Ok(())
}

/// Direct path: write each box to the destination via per-box ARQ.
async fn send_direct(
    pigeonhole: &PigeonholeClient,
    write_cap: &[u8],
    next_index: &[u8],
    input_file: &Path,
    total_len: u64,
    header: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let box_payload_size = pigeonhole
        .thin_client()
        .pigeonhole_geometry()
        .max_plaintext_payload_length;

    if header.len() >= box_payload_size {
        return Err(format!(
            "FileMetaData header ({} bytes) leaves no room for payload in a {}-byte box",
            header.len(),
            box_payload_size
        )
        .into());
    }

    let mut input_reader = BufReader::new(File::open(input_file)?);
    let mut writer = pigeonhole.load_write_channel("pigeonhole-cp", write_cap, next_index)?;

    let start = std::time::Instant::now();
    let first_room = box_payload_size - header.len();
    let mut first_chunk = vec![0u8; first_room];
    let n = read_fill(&mut input_reader, &mut first_chunk)?;
    let mut first_box = Vec::with_capacity(header.len() + n);
    first_box.extend_from_slice(header);
    first_box.extend_from_slice(&first_chunk[..n]);
    writer.send(&first_box).await?;
    let mut bytes_sent = n as u64;
    let mut box_count = 1usize;

    let mut chunk_buf = vec![0u8; box_payload_size];
    while bytes_sent < total_len {
        let n = read_fill(&mut input_reader, &mut chunk_buf)?;
        if n == 0 {
            break;
        }
        writer.send(&chunk_buf[..n]).await?;
        bytes_sent += n as u64;
        box_count += 1;
    }

    if bytes_sent != total_len {
        return Err(format!(
            "short read: file claimed {} bytes, only sent {}",
            total_len, bytes_sent
        )
        .into());
    }

    print_throughput("direct", bytes_sent, box_count, start.elapsed());
    Ok(())
}

/// Copy path: build the full payload, hand it to a `CopyStreamBuilder`
/// for chunking onto a temp channel, then dispatch via the courier.
async fn send_copy(
    pigeonhole: &PigeonholeClient,
    next_index: &[u8],
    input_file: &Path,
    total_len: u64,
    header: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    // The daemon caps a single create_courier_envelopes_from_payload call
    // at 10 MiB; we leave headroom under that for the CBOR header.
    const COPY_PAYLOAD_LIMIT: u64 = 9 * 1024 * 1024;
    let total_payload_len = header.len() as u64 + total_len;
    if total_payload_len > COPY_PAYLOAD_LIMIT {
        return Err(format!(
            "payload of {} bytes exceeds COPY mode limit of {} bytes; rerun with --no-copy",
            total_payload_len, COPY_PAYLOAD_LIMIT
        )
        .into());
    }

    let mut payload = Vec::with_capacity(total_payload_len as usize);
    payload.extend_from_slice(header);
    File::open(input_file)?.read_to_end(&mut payload)?;

    let start = std::time::Instant::now();
    let mut builder = pigeonhole.copy_stream_builder().await?;
    builder.add_payload(&payload, next_index, true).await?;
    let boxes = builder.finish().await?;

    print_throughput("copy", total_len, boxes as usize, start.elapsed());
    Ok(())
}

/// Print a transfer's throughput: total bytes and boxes, the wall time
/// spent in the send, and the derived boxes/sec and bytes/sec. Used to
/// compare ARQ strategies (per-box, copy, SACK) on equal footing.
fn print_throughput(mode: &str, bytes: u64, boxes: usize, elapsed: std::time::Duration) {
    let secs = elapsed.as_secs_f64();
    let boxes_per_sec = if secs > 0.0 { boxes as f64 / secs } else { 0.0 };
    let kib_per_sec = if secs > 0.0 {
        (bytes as f64 / secs) / 1024.0
    } else {
        0.0
    };
    println!(
        "sent {} bytes in {} box(es) ({}) in {:.3}s: {:.2} boxes/s, {:.1} KiB/s",
        bytes, boxes, mode, secs, boxes_per_sec, kib_per_sec
    );
}

/// Read until `buf` is full or EOF. Returns the number of bytes read.
fn read_fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

/// Read from a Pigeonhole channel and write to a file in `dest_dir`.
///
/// Wire format mirrors `run_send`: the first box plaintext begins with a
/// CBOR `FileMetaData` header (self-delimiting), followed by the start of
/// the file payload. Subsequent boxes are pure file bytes. The receiver
/// stops after consuming exactly `FileMetaData.size` file bytes.
///
/// The on-disk filename comes from `metadata.name`, validated by
/// `sanitize_for_receive` against `dest_dir`. The transfer lands in a
/// temp file in the same directory and is renamed to its final name only
/// once all bytes have been written and fsynced; `persist_noclobber`
/// refuses to overwrite an existing file.
async fn run_receive(
    config: PathBuf,
    read_cap_b64: String,
    next_index_b64: String,
    dest_dir: PathBuf,
    sack: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let read_cap = BASE64.decode(&read_cap_b64)?;
    let next_index = BASE64.decode(&next_index_b64)?;

    let client = init_client(config).await?;

    if sack {
        return run_receive_sack(client, &next_index, dest_dir).await;
    }

    let pigeonhole = PigeonholeClient::new_in_memory(client.clone())?;
    let mut reader = pigeonhole.load_read_channel("pigeonhole-cp", &read_cap, &next_index)?;

    // First box: decode the CBOR header, then treat the rest of the same
    // plaintext as the start of the file payload. `from_reader`/`from_slice`
    // reject trailing bytes, but we have plenty — the streaming
    // `Deserializer` lets us consume exactly one value and read off its
    // byte offset to find where the file payload begins.
    let first_box = reader.receive().await?;
    let mut deserializer = serde_cbor::Deserializer::from_slice(&first_box);
    let metadata = FileMetaData::deserialize(&mut deserializer)?;
    let header_end = deserializer.byte_offset();
    let file_part = &first_box[header_end..];

    let final_path = sanitize_for_receive(&metadata.name, &dest_dir)?;
    let parent = final_path
        .parent()
        .expect("sanitize_for_receive guarantees a parent");
    let mut tmp = NamedTempFile::new_in(parent)?;

    let mut remaining: u64 = metadata.size;
    let take = (file_part.len() as u64).min(remaining) as usize;
    tmp.write_all(&file_part[..take])?;
    remaining -= take as u64;
    let mut box_count = 1usize;

    while remaining > 0 {
        let chunk = reader.receive().await?;
        let take = (chunk.len() as u64).min(remaining) as usize;
        tmp.write_all(&chunk[..take])?;
        remaining -= take as u64;
        box_count += 1;
    }

    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(&final_path).map_err(|e| e.error)?;

    println!(
        "received {} bytes in {} box(es) -> {}",
        metadata.size,
        box_count,
        final_path.display()
    );
    Ok(())
}

/// SACK receive: the windowed counterpart to `run_receive`. The read needs
/// the box count up front, so it first reads box zero to recover the file
/// size from its `FileMetaData` header, computes how many boxes the payload
/// spans (the daemon chunks a write at `MaxPlaintextPayloadLength - 4` per
/// box), then reads the remainder in a single windowed `read_stream` call.
/// The daemon computes the window itself from the PKI document.
async fn run_receive_sack(
    client: Arc<ThinClient>,
    start_index: &[u8],
    dest_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();

    let (first, second_index) = client.read_stream(start_index, 1, 0).await?;
    let mut deserializer = serde_cbor::Deserializer::from_slice(&first);
    let metadata = FileMetaData::deserialize(&mut deserializer)?;
    let header_end = deserializer.byte_offset();

    let per_box = client.pigeonhole_geometry().max_plaintext_payload_length - 4;
    let total_payload_len = header_end + metadata.size as usize;
    let total_boxes = total_payload_len.div_ceil(per_box);

    let mut file_bytes = Vec::with_capacity(metadata.size as usize);
    file_bytes.extend_from_slice(&first[header_end..]);
    if total_boxes > 1 {
        let (rest, _next) = client
            .read_stream(&second_index, (total_boxes - 1) as u32, 0)
            .await?;
        file_bytes.extend_from_slice(&rest);
    }
    file_bytes.truncate(metadata.size as usize);

    let final_path = sanitize_for_receive(&metadata.name, &dest_dir)?;
    let parent = final_path
        .parent()
        .expect("sanitize_for_receive guarantees a parent");
    let mut tmp = NamedTempFile::new_in(parent)?;
    tmp.write_all(&file_bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(&final_path).map_err(|e| e.error)?;

    println!(
        "received {} bytes in {} box(es) (sack) in {:.3}s -> {}",
        metadata.size,
        total_boxes,
        start.elapsed().as_secs_f64(),
        final_path.display()
    );
    Ok(())
}
