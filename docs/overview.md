# Thin clients and Pigeonhole

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
within the Katzenpost monorepo. The Rust, Python and Lean ports are
maintained in this repository.


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
