# Lean thin client: engineering plan

A Lean 4 thin client for kpclientd, ported from the Go thin client in
`katzenpost/client/thin`. The Go client is the reference implementation.

## Scope

Version 1 connects to kpclientd over TCP and matches the Go client on:

- the connection handshake and session resume
- legacy messaging (`sendMessage`, `sendMessageWithoutReply`, `blockingSendMessage`)
- PKI document and directory authority queries, and service lookup
- the Pigeonhole API: keypairs, encrypt read/write, start and cancel resending,
  copy commands, box index helpers, courier envelopes, tombstones
- vouchers: mint, induct, open, derive stream
- the event sink
- reconnecting after a daemon disconnect, and replaying in-flight resends

## Layout

`lean/` is a Lake package using toolchain v4.33.1. Its modules are:

| Module | Contents |
|---|---|
| `Frame` | Frames: a 4-byte big-endian length followed by a CBOR body; frames over 40 MiB are rejected |
| `Messages` | Request, reply and event types and their codecs |
| `Geometry` | Pigeonhole geometry, and the Sphinx geometry codec |
| `Pki` | The PKI document and its descriptors |
| `Errors` | Thin client error codes 0–34, the replica error codes, and the mappings from codes to errors |
| `Config` | The `[Dial.Tcp]` config file |
| `Client` | Handshake, frame dispatch, query ID matching, the event sink, reconnect and replay |
| `Pigeonhole` | Pigeonhole API |
| `Voucher` | Voucher API |

## Types

Every type below is a Lean structure with a cborg `Serialise` instance whose
encoding matches what the Go daemon sends and accepts, byte for byte.

### Sphinx geometry

The client uses CryptWalker's `CryptWalker.Sphinx.Geometry.Geometry`; the thin
client does not define its own type. On the wire the geometry is a map keyed by
Go field names: `PacketLength`, `NrHops`, `HeaderLength`, `RoutingInfoLength`,
`PerHopRoutingInfoLength`, `SURBLength`, `SphinxPlaintextHeaderLength`,
`PayloadTagLength`, `ForwardPayloadLength`, `UserForwardPayloadLength`,
`NextNodeHopLength`, `SPRPKeyMaterialLength`, `NIKEName` and `KEMName`.

The codec reads `NIKEName` and `KEMName` into CryptWalker's `scheme` field. A
geometry whose `NIKEName` and `KEMName` are both set, or both empty, is
rejected.

A geometry decoded from the daemon's `ConnectionStatusEvent` must equal what
CryptWalker's `ofNIKE`/`ofKEM` compute for the same scheme, hop count and
payload length, and it must re-encode to the identical bytes.

### Pigeonhole geometry

`PigeonholeGeometry` mirrors `pigeonhole/geo/geometry.go`. Its fields are:

- `MaxPlaintextPayloadLength`
- `CourierQueryReadLength`, `CourierQueryWriteLength`
- `CourierQueryReplyReadLength`, `CourierQueryReplyWriteLength`
- `NIKEName`, `SignatureSchemeName`

On the wire, the keys are these Go field names.

### PKI document

`Document` mirrors `core/pki/document.go` without the signatures. Its fields are:

- `Epoch`, `GenesisEpoch`
- `Mu`, `LambdaP`, `LambdaL`, `LambdaM`, `LambdaG`, `LambdaR`
- `Topology`, `GatewayNodes`, `ServiceNodes`
- `StorageReplicas`, `ConfiguredReplicaIDs`, `ConfiguredReplicaIdentityKeys`
- `SharedRandomCommit`, `SharedRandomReveal`, `SharedRandomValue`, `PriorSharedRandom`
- `SphinxGeometryHash`, `Version`, `PKISignatureScheme`

`MixDescriptor` mirrors `core/pki/descriptor.go`. Its fields are:

- `Name`, `Epoch`, `IdentityKey`, `LinkKey`, `MixKeys`, `Addresses`
- `Kaetzchen` and `KaetzchenAdvertizedData`, whose values are free-form and are
  held as cborg `Term`
- `IsGatewayNode`, `IsServiceNode`, `LoadWeight`, `AuthenticationType`, `Version`

`ReplicaDescriptor` has `Name`, `ReplicaID`, `Epoch`, `IdentityKey`, `LinkKey`,
`EnvelopeKeys` and `Addresses`.

`getServices` and `getService`, and the per-epoch document cache, are built on
these types.

#### Encoding

`NewPKIDocumentEvent` carries the unsigned document as a CBOR byte string in
its `payload` field. `GetPKIDocumentReply.payload` instead carries the signed,
certificate-wrapped document, and `getPKIDocumentRaw` returns it unparsed.

Inside the document, the descriptor types are encoded differently:

- Each `MixDescriptor` (in `Topology`, `GatewayNodes` and `ServiceNodes`) is
  itself a byte string that wraps the descriptor's canonical CBOR map.
- `ReplicaDescriptor` entries are plain maps.

## Dependencies

Every `require` in the lakefile names a GitHub URL; none is a local path.

```toml
[[require]]
name = "cborg"
git = "https://github.com/katzenpost/cborg"
rev = "main"

[[require]]
name = "CryptWalker"
git = "https://github.com/katzenpost/CryptWalker.git"
rev = "main"
```

- **cborg**: CBOR encoding and decoding, including streaming decode of frame
  bodies.
- **CryptWalker**: the Sphinx geometry type and BLAKE2b-256. BLAKE2b-256 of a
  marshalled WriteCap is the key for an in-flight copy command in the replay
  map.
- **Lean core**: `Std.Async.TCP` for the connection, and `IO.getRandomBytes` for
  message, query and SURB IDs and the instance token.
- **Config parsing**: `Lake.Toml`.

## Verification

The Lean client is correct when it writes the same frames to the socket as the Go
client, and reacts to every frame from the daemon the same way.

### Test vectors

cborg's `scripts/gen-vectors` encodes frames with the Go daemon's own types, into
`testdata/thinclient/`. It is extended to cover:

- every request, reply and event variant
- every error code
- both geometries
- a populated PKI document from the docker mixnet, with mix, gateway, service
  and replica descriptors

The Lean tests decode every vector and re-encode it to the same bytes. The Go
side decodes the Lean encodings.

### Client logic

The edge cases covered by the Go test suite are ported to Lean tests that run
against an in-process fake daemon, with no sockets:

- interleaved frames during the handshake
- a misbehaving daemon: garbage, oversized frames, missing geometry, early shutdown
- disconnects, reconnects and in-flight replay
- session resume
- error code mapping

### End to end

The integration scenarios run with the Lean client against the docker mixnet,
using `test-integration.sh`.

### Proofs

Round-trip theorems (decoding an encoded value gives back the value) for the
message, geometry and PKI codecs.

Version 1 is done when the test vectors, the client logic tests and the end to
end run all pass in CI.

## CI

- `make test-lean` builds the package and runs the Lean tests.
- The GitHub, Forgejo and Woodpecker CI configs each gain a job that runs it.
- `.ci/Dockerfile` installs elan.

## Milestones

1. Framing, message codecs, the geometry and PKI types, and the test vectors.
2. Config, the TCP connection, and the handshake.
3. Legacy messaging, PKI queries, and the event sink.
4. Pigeonhole, vouchers, and in-flight replay.
5. End to end tests and CI.
