// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end smoke tests for the `pigeonhole-cp` binary.
//!
//! Two cases: the default COPY-command path, and the per-box direct
//! write path under `--no-copy`. Each generates a fresh keypair, sends
//! a multi-box random file, reads it back, and verifies the round-tripped
//! bytes match the original. Requires the docker mixnet up and reachable
//! per `testdata/thinclient.toml`.
//!
//! Only built when the `cli` feature is enabled, since they shell out
//! to the `pigeonhole-cp` binary which is itself gated on `cli`.

#![cfg(feature = "cli")]

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use rand::RngCore;

const CONFIG: &str = "testdata/thinclient.toml";

/// Parse `pigeonhole-cp genkey` stdout into `(read_cap, write_cap)`.
fn parse_genkey(stdout: &str) -> (String, String) {
    let mut read_cap: Option<String> = None;
    let mut write_cap: Option<String> = None;
    let mut lines = stdout.lines();
    while let Some(line) = lines.next() {
        if line.starts_with("Read Capability") {
            read_cap = lines.next().map(|s| s.trim().to_string());
        } else if line.starts_with("Write Capability") {
            write_cap = lines.next().map(|s| s.trim().to_string());
        }
    }
    (
        read_cap.expect("genkey output missing Read Capability"),
        write_cap.expect("genkey output missing Write Capability"),
    )
}

/// Round-trip a 4 KiB random file through `pigeonhole-cp` and verify
/// the bytes match. Spans 3 boxes given MaxPlaintextPayloadLength=1553
/// and a ~25-byte CBOR FileMetaData header — exercises both the
/// first-box header carve-out and at least one pure file-bytes box.
async fn round_trip(label: &str, no_copy: bool) {
    let work = tempfile::tempdir().expect("tempdir");
    let input_path = work.path().join(format!("{label}-input.bin"));
    let mut input_data = vec![0u8; 4096];
    rand::thread_rng().fill_bytes(&mut input_data);
    fs::write(&input_path, &input_data).expect("write input file");
    println!(
        "==> [{label}] generated {} bytes of random input",
        input_data.len()
    );

    let genkey_out = Command::cargo_bin("pigeonhole-cp")
        .expect("locate pigeonhole-cp binary")
        .args(["genkey", "-c", CONFIG])
        .output()
        .expect("run genkey");
    assert!(
        genkey_out.status.success(),
        "[{label}] genkey failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&genkey_out.stdout),
        String::from_utf8_lossy(&genkey_out.stderr),
    );
    let genkey_stdout = String::from_utf8(genkey_out.stdout).expect("genkey utf-8 output");
    let (read_cap, write_cap) = parse_genkey(&genkey_stdout);
    println!("==> [{label}] generated keypair");

    // The caps carry their own first box position, so the position-cap
    // CLI argument is the write_cap on send and the read_cap on receive.
    let mut send_args: Vec<&str> = vec![
        "send",
        "-c",
        CONFIG,
        "-w",
        &write_cap,
        "-i",
        &write_cap,
        "-f",
        input_path.to_str().expect("utf-8 input path"),
    ];
    if no_copy {
        send_args.push("--no-copy");
    }
    let send_out = Command::cargo_bin("pigeonhole-cp")
        .expect("locate pigeonhole-cp binary")
        .args(&send_args)
        .output()
        .expect("run send");
    assert!(
        send_out.status.success(),
        "[{label}] send failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&send_out.stdout),
        String::from_utf8_lossy(&send_out.stderr),
    );
    println!(
        "==> [{label}] send completed: {}",
        String::from_utf8_lossy(&send_out.stdout).trim()
    );

    // No propagation sleep: the retrying read below gates itself on BoxIDNotFound until the box propagates.

    let dest_dir = work.path().join("dest");
    fs::create_dir(&dest_dir).expect("create dest dir");
    let recv_out = Command::cargo_bin("pigeonhole-cp")
        .expect("locate pigeonhole-cp binary")
        .args([
            "receive",
            "-c",
            CONFIG,
            "-r",
            &read_cap,
            "-i",
            &read_cap,
            "-d",
            dest_dir.to_str().expect("utf-8 dest path"),
        ])
        .output()
        .expect("run receive");
    assert!(
        recv_out.status.success(),
        "[{label}] receive failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&recv_out.stdout),
        String::from_utf8_lossy(&recv_out.stderr),
    );
    println!("==> [{label}] receive completed");

    let received_files: Vec<PathBuf> = fs::read_dir(&dest_dir)
        .expect("read dest dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    assert_eq!(
        received_files.len(),
        1,
        "[{label}] expected exactly one file in dest, found {:?}",
        received_files,
    );

    let received = fs::read(&received_files[0]).expect("read received file");
    assert_eq!(
        received.len(),
        input_data.len(),
        "[{label}] received {} bytes, expected {}",
        received.len(),
        input_data.len(),
    );
    assert_eq!(
        received, input_data,
        "[{label}] round-tripped bytes differ from original",
    );
    println!(
        "==> [{label}] {} bytes round-tripped byte-for-byte",
        input_data.len()
    );
}

#[tokio::test]
async fn smoke_round_trip_copy() {
    round_trip("copy", false).await;
}

#[tokio::test]
async fn smoke_round_trip_direct() {
    round_trip("direct", true).await;
}
