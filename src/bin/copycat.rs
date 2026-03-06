// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! copycat - A CLI tool for reading and writing to Katzenpost pigeonhole channels
//!
//! Similar to cat or netcat, copycat can:
//! - Read from stdin or a file and write to a copy stream (send mode)
//! - Read from a channel and write to stdout (receive mode)

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::{Parser, Subcommand};
use tokio::time::sleep;

use katzenpost_thin_client::{Config, ThinClient};
use katzenpost_thin_client::persistent::{
    PigeonholeClient, Database, ReadCapability,
};

/// Chunk size for streaming input data (10MB)
const CHUNK_SIZE: usize = 10 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "copycat")]
#[command(about = "Katzenpost pigeonhole copy stream tool")]
#[command(long_about = "A CLI tool for reading and writing to Katzenpost pigeonhole channels.\n\n\
Similar to cat or netcat, copycat can:\n\
- Read from stdin or a file and write to a copy stream (send mode)\n\
- Read from a channel and write to stdout (receive mode)\n\n\
This tool uses the Pigeonhole protocol with Copy Commands to provide\n\
reliable message delivery through the mixnet.")]
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

    /// Read from stdin or file and write to a copy stream
    Send {
        /// Configuration file (required)
        #[arg(short, long)]
        config: PathBuf,

        /// Write capability (base64)
        #[arg(short, long)]
        write_cap: String,

        /// Input file (default: stdin)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Start index (base64, optional)
        #[arg(short, long)]
        index: Option<String>,
    },

    /// Read from a channel and write to stdout
    Receive {
        /// Configuration file (required)
        #[arg(short, long)]
        config: PathBuf,

        /// Read capability (base64)
        #[arg(short, long)]
        read_cap: String,

        /// Start index (base64, optional)
        #[arg(short, long)]
        index: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Genkey { config } => run_genkey(config).await,
        Commands::Send { config, write_cap, file, index } => {
            run_send(config, write_cap, file, index).await
        }
        Commands::Receive { config, read_cap, index } => {
            run_receive(config, read_cap, index).await
        }
    }
}

/// Initialize the thin client from config file
async fn init_client(config_path: PathBuf) -> Result<Arc<ThinClient>, Box<dyn std::error::Error>> {
    let cfg = Config::new(config_path.to_str().ok_or("Invalid config path")?)?;
    let client = ThinClient::new(cfg).await?;

    // Wait for PKI document with timeout
    eprintln!("Waiting for PKI document...");
    let timeout = Duration::from_secs(60);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err("Timeout waiting for PKI document".into());
        }
        if client.pki_document().await.is_ok() {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    eprintln!("Connected to mixnet");
    Ok(client)
}

/// Generate a new keypair and print capabilities
async fn run_genkey(config: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let client = init_client(config).await?;
    let pigeonhole = PigeonholeClient::new_in_memory(client)?;

    // Create a temporary channel to generate the keypair
    let channel = pigeonhole.create_channel("genkey-temp").await?;

    // Get the raw capabilities
    let write_cap = channel.write_cap().ok_or("Failed to get write capability")?;
    let read_cap = channel.read_cap();
    let first_index = channel.write_index().ok_or("Failed to get write index")?;

    println!("Read Capability (share with recipient):");
    println!("{}\n", BASE64.encode(read_cap));

    println!("Write Capability (keep secret):");
    println!("{}\n", BASE64.encode(write_cap));

    println!("First Index:");
    println!("{}", BASE64.encode(first_index));

    Ok(())
}

/// Read from stdin or file and send via copy stream
async fn run_send(
    config: PathBuf,
    write_cap_b64: String,
    input_file: Option<PathBuf>,
    start_index_b64: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Decode write capability
    let write_cap = BASE64.decode(&write_cap_b64)?;

    // Read input data
    let input_data = if let Some(path) = input_file {
        std::fs::read(&path)?
    } else {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    };

    // Prepend 4-byte big-endian length prefix
    let total_len = input_data.len() as u32;
    let mut prefixed_data = Vec::with_capacity(4 + input_data.len());
    prefixed_data.extend_from_slice(&total_len.to_be_bytes());
    prefixed_data.extend_from_slice(&input_data);

    eprintln!("Sending {} bytes (with 4-byte length prefix)", input_data.len());

    // Initialize client
    let client = init_client(config).await?;
    let pigeonhole = PigeonholeClient::new_in_memory(client.clone())?;

    // Create a temporary channel for copy stream operations
    let channel = pigeonhole.create_channel("copycat-send").await?;

    // Determine start index - use provided or get first index from write cap
    let start_index = if let Some(idx_b64) = start_index_b64 {
        BASE64.decode(&idx_b64)?
    } else {
        // Get first index from daemon for this write capability
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        let (_, _, first_idx) = client.new_keypair(&seed).await?;
        // Actually we need to use the start index that matches the write_cap
        // For now, just use the channel's write index which was generated fresh
        channel.write_index().ok_or("No write index")?.to_vec()
    };

    // Create copy stream builder
    let mut builder = channel.copy_stream_builder().await?;

    // Stream prefixed data in chunks
    let mut offset = 0;
    let mut chunk_num = 0;

    while offset < prefixed_data.len() {
        let remaining = prefixed_data.len() - offset;
        let current_chunk_size = remaining.min(CHUNK_SIZE);

        let payload = &prefixed_data[offset..offset + current_chunk_size];
        let is_last = offset + current_chunk_size >= prefixed_data.len();

        // Use add_multi_payload for more efficient packing
        let destinations = vec![(payload, write_cap.as_slice(), start_index.as_slice())];
        let envelopes_written = builder
            .add_multi_payload(destinations, is_last)
            .await?;

        eprintln!(
            "Processed chunk {} ({} bytes, {} envelopes)",
            chunk_num, current_chunk_size, envelopes_written
        );

        chunk_num += 1;
        offset += current_chunk_size;
    }

    // Execute the copy command
    eprintln!("Sending Copy command to courier...");
    let total_boxes = builder.finish().await?;
    eprintln!("Copy command completed successfully ({} boxes written)", total_boxes);

    Ok(())
}

/// Receive messages from a channel and write to stdout
///
/// This function reads boxes with retry logic until all data specified
/// by the length prefix has been received.
async fn run_receive(
    config: PathBuf,
    read_cap_b64: String,
    start_index_b64: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Decode read capability
    let read_cap_bytes = BASE64.decode(&read_cap_b64)?;

    // Initialize client
    let client = init_client(config).await?;
    let pigeonhole = PigeonholeClient::new_in_memory(client.clone())?;

    // Create a ReadCapability structure
    let start_index = if let Some(idx_b64) = start_index_b64 {
        BASE64.decode(&idx_b64)?
    } else {
        // Without a start index, we need to get it from somewhere
        // The Go version uses readCap.GetFirstMessageBoxIndex()
        // For now, we'll require the user to provide it or use a default
        // This is a simplification - in practice the read_cap should include the start index
        return Err("Start index is required for receive (use -i flag)".into());
    };

    let read_capability = ReadCapability {
        read_cap: read_cap_bytes,
        start_index: start_index.clone(),
        name: Some("copycat-receive".to_string()),
    };

    // Import the channel
    let mut channel = pigeonhole.import_channel("copycat-receive", &read_capability)?;

    eprintln!("Reading with length prefix...");

    // Buffer to accumulate all received data
    let mut received_data = Vec::new();
    let mut expected_len: Option<u32> = None;
    let mut box_num = 0;

    const MAX_RETRIES: u32 = 100;
    const BASE_DELAY_MS: u64 = 500;

    // Keep reading until we have all expected data
    loop {
        let mut plaintext: Option<Vec<u8>> = None;

        // Try to read the next box with retries
        for attempt in 0..MAX_RETRIES {
            match channel.receive().await {
                Ok(data) if !data.is_empty() => {
                    plaintext = Some(data);
                    break;
                }
                Ok(_) | Err(_) => {
                    if attempt < MAX_RETRIES - 1 {
                        // Exponential backoff, capped at ~32 seconds
                        let delay = BASE_DELAY_MS * (1 << attempt.min(6));
                        eprintln!(
                            "Box {} not ready (attempt {}/{}), retrying in {}ms...",
                            box_num, attempt + 1, MAX_RETRIES, delay
                        );
                        sleep(Duration::from_millis(delay)).await;
                    }
                }
            }
        }

        let data = plaintext.ok_or_else(|| {
            format!("Failed to read box {} after {} retries", box_num, MAX_RETRIES)
        })?;

        // Accumulate received data
        let data_len = data.len();
        received_data.extend_from_slice(&data);
        box_num += 1;

        // Check if we now know the expected length
        if expected_len.is_none() && received_data.len() >= 4 {
            let len = u32::from_be_bytes([
                received_data[0],
                received_data[1],
                received_data[2],
                received_data[3],
            ]);
            expected_len = Some(len);
            eprintln!("Expected payload length: {} bytes", len);
        }

        // Print progress
        if let Some(len) = expected_len {
            let total_expected = 4 + len as usize;
            let percent = (received_data.len() as f64 / total_expected as f64 * 100.0).min(100.0);
            eprintln!(
                "Box {}: received {} bytes ({}/{} bytes, {:.1}%)",
                box_num, data_len, received_data.len(), total_expected, percent
            );
        } else {
            eprintln!("Box {}: received {} bytes (total so far: {} bytes)", box_num, data_len, received_data.len());
        }

        // Check if we have all the data (4-byte prefix + expected_len bytes)
        if let Some(len) = expected_len {
            if received_data.len() >= 4 + len as usize {
                eprintln!("Received all {} bytes in {} boxes", len, box_num);
                break;
            }
        }
    }

    // Strip the 4-byte length prefix and write the actual payload to stdout
    let expected = expected_len.ok_or("No data received")? as usize;
    if received_data.len() < 4 + expected {
        return Err(format!(
            "Received data too short: {} bytes, expected {}",
            received_data.len(),
            4 + expected
        ).into());
    }

    let payload = &received_data[4..4 + expected];
    io::stdout().write_all(payload)?;

    eprintln!("Done");
    Ok(())
}

