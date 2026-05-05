# katzenpost_thinclient

*A thin client for sending and receiving messages via the Katzenpost
mix network.*

This PyPI package provides an async Python thin client library for
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
- [Python API reference](https://katzenpost.network/docs/python_thin_client.html), pydoc-formatted reference for this package.
- [Understanding Pigeonhole](https://katzenpost.network/docs/pigeonhole_explained/), conceptual background on Pigeonhole.
- [Build from source](https://katzenpost.network/docs/build_from_source/), the canonical record of pinned versions for `kpclientd` and the thin clients.


## Installation

Install from PyPI:

```bash
pip install katzenpost_thinclient
```

Or, from a checkout of this repository:

```bash
pip install -e .
```


## Compatibility

This package is intended to be used with the version of `kpclientd`
listed in [Build from source](https://katzenpost.network/docs/build_from_source/).
That page is the canonical record of currently pinned tags for the
whole stack; please consult it before pinning a version of your own.


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
`voting_mixnet/client/thinclient.toml`. The test suite locates a
preconfigured fixture at `testdata/thinclient.toml`, which dials
the daemon on that port:

```bash
pytest
```


## Applications using this library

Two larger programs that use this library:

1. **[stats](https://github.com/katzenpost/status)**, a terminal
   application that prints the current mixnet status.
2. **[worldmap](https://github.com/katzenpost/worldmap)**, which
   renders an image of the mixnet transposed over a world map.


## Contributions

This is a work in progress, and we welcome feedback from developers
who try to use it. Pull requests are welcome at
<https://github.com/katzenpost/thin_client>.


## License

AGPLv3.
