# katzenpost_thin_client

*A thin client for sending and receiving messages via the Katzenpost
mix network.*

This crate provides an async Rust thin client library for
interacting with a [Katzenpost](https://katzenpost.network/) mixnet.

A mix network is a type of anonymous communications network. A
thin client library is code you may use as a dependency in your
application so that it can anonymously interact with services on
the mix network. The Katzenpost client daemon (`kpclientd`) is a
multiplexing client; many applications on the same device may use
their thin client libraries to connect to the daemon and interact
with mixnet services concurrently. All cryptographic operations,
including PQ Noise transport, Sphinx packet construction, and ARQ
retransmission, are performed by the daemon, not by this library.


## Pigeonhole, in brief

Beyond simple request-response services, Katzenpost provides a
storage layer called Pigeonhole. Applications communicate through
encrypted, append-only streams composed of fixed-size, padded Boxes,
sharded across storage replicas via consistent hashing. Access is
governed by cryptographic capabilities: a write capability appends
messages or places tombstones, whilst a separate read capability
decrypts and verifies without conferring any ability to write.
Streams are single-writer, multi-reader, and unlinkable to outside
observers. Storage is ephemeral: Boxes are garbage-collected after
roughly two weeks, so Pigeonhole is not intended for long-term
archival storage. For a developer-oriented introduction, see
[Understanding Pigeonhole](https://katzenpost.network/docs/pigeonhole_explained/).


## Documentation

- [Thin Client How-to Guide](https://katzenpost.network/docs/thin_client_howto/), task-oriented examples in Go, Rust, and Python.
- [Thin Client API Reference](https://katzenpost.network/docs/thin_client_api_reference/), the unified API reference for all three languages.
- [Rust API reference](https://docs.rs/katzenpost_thin_client/latest/katzenpost_thin_client/) on docs.rs.
- [Understanding Pigeonhole](https://katzenpost.network/docs/pigeonhole_explained/), conceptual background on Pigeonhole.
- [Build from source](https://katzenpost.network/docs/build_from_source/), the canonical record of pinned versions for `kpclientd` and the thin clients.


## Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
katzenpost_thin_client = "0.0.16"
```

Please consult
[Build from source](https://katzenpost.network/docs/build_from_source/)
for the version pinned alongside the rest of the stack; that page
is the canonical record for `kpclientd`, the Go reference thin
client, the Rust and Python thin clients, and `katzenqt`.


## pigeonhole-cp

The crate also ships a small command-line utility, `pigeonhole-cp`,
for sending and receiving files to and from Pigeonhole channels.
It is gated behind the `cli` feature:

```bash
cargo build --release --features cli --bin pigeonhole-cp
```

It has three subcommands:

- `genkey -c <config>` prints a fresh write capability, read capability,
  and first message box index.
- `send -c <config> -w <write-cap> -i <index> -f <file>` reads a file
  and writes it to a channel. The transfer mode is chosen by these
  flags:
  - (default, no flag) writes each Box directly with the per-box ARQ,
    reading the file one Box at a time. It never loads the whole file
    into memory and has no payload size limit.
  - `--copy` uses the courier COPY command, which is atomic but buffers
    the whole file in memory and caps the payload near 9 MiB.
  - `--sack` uses the windowed SACK ARQ, keeping a block of Boxes in
    flight at once. It streams the file a block at a time, so it too
    never loads the whole file into memory.
- `receive -c <config> -r <read-cap> -i <index> -d <dest-dir>` reads a
  channel and writes the file to disk. `--sack` reads it with the same
  windowed SACK ARQ instead of one Box per round trip.

Under `--sack`, in either direction, the daemon sizes the window itself
from the PKI document (routing layers and Mu), so there is no window
flag to tune.

Its source is at
[`src/bin/pigeonhole_cp.rs`](https://github.com/katzenpost/thin_client/blob/main/src/bin/pigeonhole_cp.rs)
and serves as a worked example of the persistent Pigeonhole API.


## Running the tests

The `tests/` directory contains the integration suite, which doubles
as a working reference for the API. The tests expect a running
Katzenpost mixnet; the most convenient way to obtain one is the
docker test mixnet shipped with the
[Katzenpost monorepo](https://github.com/katzenpost/katzenpost).
Full instructions are in
[Docker test network](https://katzenpost.network/docs/admin_guide/docker.html);
the short form is:

```bash
cd katzenpost/docker
make start wait run-ping
```

The mixnet runs `kpclientd` inside a container exposed on
`127.0.0.1:64331`, and writes a thin client configuration to
`voting_mixnet/client/thinclient.toml`. The test suite uses the
preconfigured fixture at `testdata/thinclient.toml`, which dials
the daemon on that port. Run the suite with:

```bash
cargo test --features cli
```


## Compatibility

This crate is intended to be used with the version of `kpclientd`
listed in
[Build from source](https://katzenpost.network/docs/build_from_source/).


## Contributions

This is a work in progress, and we welcome feedback from developers
who try to use it. Pull requests are welcome at
<https://github.com/katzenpost/thin_client>.


## License

AGPLv3.
