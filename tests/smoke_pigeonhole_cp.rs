// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end smoke test for the `pigeonhole-cp` binary.
//!
//! Generates a fresh keypair, sends a multi-box random file, reads it
//! back, and verifies the round-tripped bytes match the original.
//! Requires the docker mixnet up and reachable per `testdata/thinclient.toml`.
//!
//! Only built when the `cli` feature is enabled, since it shells out to
//! the `pigeonhole-cp` binary which itself is gated on `cli`.

#![cfg(feature = "cli")]

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use assert_cmd::Command;
use rand::RngCore;

const CONFIG: &str = "testdata/thinclient.toml";

/// Parse `pigeonhole-cp genkey` stdout into `(read_cap, write_cap, first_index)`.
///
/// genkey emits each capability as a labelled line followed by the base64
/// value on the next non-blank line.
fn parse_genkey(stdout: &str) -> (String, String, String) {
    let mut read_cap: Option<String> = None;
    let mut write_cap: Option<String> = None;
    let mut first_index: Option<String> = None;
    let mut lines = stdout.lines();
    while let Some(line) = lines.next() {
        if line.starts_with("Read Capability") {
            read_cap = lines.next().map(|s| s.trim().to_string());
        } else if line.starts_with("Write Capability") {
            write_cap = lines.next().map(|s| s.trim().to_string());
        } else if line.starts_with("First Index") {
            first_index = lines.next().map(|s| s.trim().to_string());
        }
    }
    (
        read_cap.expect("genkey output missing Read Capability"),
        write_cap.expect("genkey output missing Write Capability"),
        first_index.expect("genkey output missing First Index"),
    )
}

#[tokio::test]
async fn smoke_round_trip_multibox() {
    // 4 KiB of random input. With MaxPlaintextPayloadLength=1553 and a
    // CBOR FileMetaData header of ~25 bytes, the wire shape is:
    //   box 1: ~25-byte header + 1528 file bytes
    //   box 2: 1553 file bytes
    //   box 3: 1015 file bytes
    let work = tempfile::tempdir().expect("tempdir");
    let input_path = work.path().join("multibox.bin");
    let mut input_data = vec![0u8; 4096];
    rand::thread_rng().fill_bytes(&mut input_data);
    fs::write(&input_path, &input_data).expect("write input file");

    println!("==> generated {} bytes of random input", input_data.len());

    let genkey_out = Command::cargo_bin("pigeonhole-cp")
        .expect("locate pigeonhole-cp binary")
        .args(["genkey", "-c", CONFIG])
        .output()
        .expect("run genkey");
    assert!(
        genkey_out.status.success(),
        "genkey failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&genkey_out.stdout),
        String::from_utf8_lossy(&genkey_out.stderr),
    );
    let genkey_stdout = String::from_utf8(genkey_out.stdout).expect("genkey utf-8 output");
    let (read_cap, write_cap, first_index) = parse_genkey(&genkey_stdout);
    println!("==> generated keypair");

    let send_out = Command::cargo_bin("pigeonhole-cp")
        .expect("locate pigeonhole-cp binary")
        .args([
            "send",
            "-c", CONFIG,
            "-w", &write_cap,
            "-i", &first_index,
            "-f", input_path.to_str().expect("utf-8 input path"),
        ])
        .output()
        .expect("run send");
    assert!(
        send_out.status.success(),
        "send failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&send_out.stdout),
        String::from_utf8_lossy(&send_out.stderr),
    );
    println!("==> send completed");

    println!("==> waiting 60s for mixnet propagation");
    tokio::time::sleep(Duration::from_secs(60)).await;

    let dest_dir = work.path().join("dest");
    fs::create_dir(&dest_dir).expect("create dest dir");
    let recv_out = Command::cargo_bin("pigeonhole-cp")
        .expect("locate pigeonhole-cp binary")
        .args([
            "receive",
            "-c", CONFIG,
            "-r", &read_cap,
            "-i", &first_index,
            "-d", dest_dir.to_str().expect("utf-8 dest path"),
        ])
        .output()
        .expect("run receive");
    assert!(
        recv_out.status.success(),
        "receive failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&recv_out.stdout),
        String::from_utf8_lossy(&recv_out.stderr),
    );
    println!("==> receive completed");

    let received_files: Vec<PathBuf> = fs::read_dir(&dest_dir)
        .expect("read dest dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    assert_eq!(
        received_files.len(),
        1,
        "expected exactly one file in dest, found {:?}",
        received_files,
    );

    let received = fs::read(&received_files[0]).expect("read received file");
    assert_eq!(
        received.len(),
        input_data.len(),
        "received {} bytes, expected {}",
        received.len(),
        input_data.len(),
    );
    assert_eq!(received, input_data, "round-tripped bytes differ from original");
    println!("==> {} bytes round-tripped byte-for-byte", input_data.len());
}
