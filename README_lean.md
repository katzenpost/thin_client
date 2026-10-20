# ThinClient

*A thin client for sending and receiving messages via the Katzenpost
mix network, in Lean 4.*

This Lake package provides a Lean thin client library for
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

For Pigeonhole, the storage layer most of the API is about, see
[Pigeonhole, in brief](README.md#pigeonhole-in-brief).


## Installation

Add the package to your `lakefile.toml`, pinned to a commit:

```toml
[[require]]
name = "thinclient"
git = "https://github.com/katzenpost/thin_client.git"
rev = "<commit>"
```

and import it with `import ThinClient`.


## Usage

The API runs in `ClientM`, which carries the connection to the
daemon and fails with a `ThinClientError`. `withClient addr port`
connects over TCP, and `withClientUnix path` over a Unix socket (an
abstract one when the path starts with `@`). This writes a Box and
reads it back:

```lean
import ThinClient

open Std.Async ThinClient

def hello : ClientM ByteArray := do
  let kp ← newKeypair (← FixedBytes.random 32)
  -- Write a box with the write capability.
  let w ← encryptWrite "hello".toUTF8 kp.writeCap kp.firstMessageIndex
  discard <| startResendingEncryptedMessage (.write kp.writeCap)
    w.envelopeDescriptor w.messageCiphertext w.envelopeHash
  -- Read it back with the read capability.
  let r ← encryptRead kp.readCap kp.firstMessageIndex
  let got ← startResendingEncryptedMessage (.read kp.readCap kp.firstMessageIndex)
    r.envelopeDescriptor r.messageCiphertext r.envelopeHash
  return got.plaintext

def main : IO Unit := do
  match ← (withClientUnix "@kpclientd" hello).block with
  | .ok bytes => IO.println (String.fromUTF8! bytes)
  | .error e => IO.eprintln s!"error: {e}"
```

The client reconnects by itself if the daemon goes away, and
replays what was in flight. `subscribe` returns a `Subscription`
whose `recv` yields the daemon's events.

The API, by module:

- `ThinClient.Api.Pigeonhole`: keypairs, encrypted reads and
  writes, resending, Copy commands, courier envelopes and tombstones.
- `ThinClient.Api.Messaging`: messages to mixnet services, with or
  without a reply.
- `ThinClient.Api.Pki`: the PKI document, directory authorities and
  services.
- `ThinClient.Api.Voucher`: minting, inducting and opening vouchers,
  and deriving their streams.

The [Thin Client API Reference](https://katzenpost.network/docs/thin_client_api_reference/)
describes the same operations for Go, Rust and Python.


## Running the tests

The unit tests need no mixnet:

```bash
make test-lean
```

The integration tests expect a running Katzenpost mixnet, such as
the docker test mixnet described in [README_rust.md](README_rust.md#running-the-tests):

```bash
make test-lean-integration
```

or against another daemon:

```bash
lake exe thinclient-integration 127.0.0.1 64331
lake exe thinclient-integration @kpclientd
```


## Compatibility

This package is intended to be used with the version of `kpclientd`
listed in
[Build from source](https://katzenpost.network/docs/build_from_source/).


## License

AGPLv3.
