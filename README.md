# Katzenpost thin client libraries

*Thin client libraries for sending and receiving messages via the
Katzenpost mix network.*

This repository contains the [Rust](README_rust.md) and
[Python](README_python.md) thin client libraries for
[Katzenpost](https://katzenpost.network/), together with
`pigeonhole-cp`, a small command-line utility for sending and
receiving files over Pigeonhole channels.


## What is a thin client?

A mix network is a type of anonymous communications network. The
Katzenpost stack is split between a local daemon, `kpclientd`, and
the application that uses it. The daemon performs all cryptographic
and network operations: PQ Noise transport, Sphinx packet
construction, courier discovery, and ARQ retransmission. A thin
client is the small library on the application side: it speaks a
CBOR-framed protocol over a local socket to the daemon, and exposes
a friendly API in its host language. Several applications on the
same device may share a single daemon concurrently by way of their
respective thin clients.

The reference Go implementation lives in
[`katzenpost/client/thin`](https://github.com/katzenpost/katzenpost/tree/main/client/thin)
within the Katzenpost monorepo. The Rust and Python ports are
maintained here.


## Pigeonhole, in brief

Beyond simple request-response services, Katzenpost provides a
storage layer called Pigeonhole. Applications communicate through
encrypted, append-only streams composed of fixed-size, padded Boxes,
which are sharded across storage replicas via consistent hashing
(two replicas per Box). Access is governed by cryptographic
capabilities: a write capability can append messages or place
tombstones, whilst a separate read capability decrypts and verifies
without conferring any ability to write. Streams are single-writer
and multi-reader, and unlinkable in the sense that storage servers
cannot tell which messages belong to the same stream. Storage is
ephemeral: Boxes are garbage-collected after roughly two weeks, so
Pigeonhole is not intended for long-term archival storage.

Clients never speak to replicas directly. Each Pigeonhole operation
is carried as a Sphinx round-trip through the mix layers to a
courier service, which then forwards the request to the appropriate
replicas on fixed-throughput connections so that traffic patterns
reveal nothing to an outside observer. Many higher-level protocols
(group chat, file transfer, request-response services) compose
readily on top of these streams by sharing read capabilities
out-of-band.

For a developer-oriented introduction see
[Understanding Pigeonhole](https://katzenpost.network/docs/pigeonhole_explained/).
For the wire-level details see the
[Pigeonhole specification](https://katzenpost.network/docs/specs/pigeonhole/)
and §§4-5 of the [Echomix paper](https://arxiv.org/abs/2501.02933).


## Documentation

- [Project website](https://katzenpost.network/)
- [Thin Client How-to Guide](https://katzenpost.network/docs/thin_client_howto/), task-oriented examples in Go, Rust, and Python.
- [Thin Client API Reference](https://katzenpost.network/docs/thin_client_api_reference/), the unified API reference for all three languages.
- [Build from source](https://katzenpost.network/docs/build_from_source/), the canonical record of pinned versions for the whole stack.
- [Docker test network](https://katzenpost.network/docs/admin_guide/docker.html), instructions for running a local mixnet for development.


## Per-language READMEs

- [Python thin client](README_python.md), distributed via PyPI as [`katzenpost_thinclient`](https://pypi.org/project/katzenpost_thinclient/).
- [Rust thin client](README_rust.md), distributed via crates.io as [`katzenpost_thin_client`](https://crates.io/crates/katzenpost_thin_client).


## pigeonhole-cp

`pigeonhole-cp` is a small command-line utility, written in Rust,
for sending and receiving files to and from Pigeonhole channels.
It is a thin wrapper over the persistent Pigeonhole API and serves
both as a utility in its own right and as a worked example for
application authors. Build it with the `cli` feature:

```bash
cargo build --release --features cli --bin pigeonhole-cp
```

The source lives at [`src/bin/pigeonhole_cp.rs`](src/bin/pigeonhole_cp.rs).


## Directory layout

```
thin_client/
├── src/                            Rust thin client (crates.io: katzenpost_thin_client)
│   ├── lib.rs                      Crate root; re-exports the public API.
│   ├── core.rs                     ThinClient struct: connection, events, message send.
│   ├── pigeonhole.rs               Low-level Pigeonhole API (manual cap and index handling).
│   ├── persistent/                 High-level Pigeonhole API with SQLite-backed state.
│   │   ├── mod.rs                  PigeonholeClient and ChannelHandle.
│   │   ├── channel.rs              Channel state machine and box send/receive.
│   │   ├── db.rs                   SQLite persistence for caps, indices, and messages.
│   │   ├── models.rs               Channel, capability, and message records.
│   │   └── error.rs                Errors specific to the persistent layer.
│   ├── transport/                  Pluggable daemon transports.
│   │   ├── mod.rs                  Dialer trait and DialConfig discriminated union.
│   │   ├── unix.rs                 Abstract Unix domain socket transport.
│   │   └── tcp.rs                  TCP transport (used by the docker mixnet).
│   ├── helpers.rs                  PKI document utilities (find_services, pretty print).
│   ├── error.rs                    Error types and error code translation.
│   └── bin/
│       └── pigeonhole_cp.rs        pigeonhole-cp file send/receive utility.
├── katzenpost_thinclient/          Python thin client (PyPI: katzenpost_thinclient)
│   ├── __init__.py                 Public API and module docstring.
│   ├── core.py                     ThinClient and Config; replica error types.
│   ├── pigeonhole.py               Capability-based Pigeonhole API.
│   └── transport/                  Daemon transports (TCP and Unix).
├── tests/                          Integration tests (Rust and Python).
│   ├── conftest.py                 Pytest fixtures; expects the daemon on 127.0.0.1:64331.
│   ├── high_level_api_test.rs      Persistent Pigeonhole API tests.
│   ├── channel_api_test.rs         Channel API tests.
│   ├── smoke_pigeonhole_cp.rs      pigeonhole-cp smoke test.
│   └── test_*.py                   Python integration tests.
├── testdata/
│   └── thinclient.toml             Fixture config (TCP dial, Sphinx and Pigeonhole geometry).
├── Cargo.toml                      Rust crate manifest.
├── pyproject.toml                  Python package manifest.
├── requirements.txt                Python runtime dependencies.
├── pydoc-markdown.yml              Pydoc generation config for the Python API reference.
├── README.md                       This file (rendered on GitHub).
├── README_python.md                Bundled with the PyPI package.
├── README_rust.md                  Bundled with the crates.io package.
└── RELEASING.md                    Release and publish procedure.
```


## Compatibility

Both libraries track the Katzenpost stack at the tag listed in
[Build from source](https://katzenpost.network/docs/build_from_source/);
that page is the canonical record of pinned versions for `kpclientd`,
the Go reference thin client, the Rust and Python thin clients, and
`katzenqt`. The reference daemon is built from the
[katzenpost monorepo](https://github.com/katzenpost/katzenpost) at
that same tag.


## Contributions

Pull requests are welcome at
<https://github.com/katzenpost/thin_client>. The CI pipeline runs
the integration suite against a docker mixnet pinned to a specific
commit of the [katzenpost monorepo](https://github.com/katzenpost/katzenpost);
protocol-level changes should be coordinated with that pin in mind.

Maintainers: see [RELEASING.md](RELEASING.md) for the release and
publish procedure.


## License

AGPLv3.
