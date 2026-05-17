# katzenpost-reticulum: pkimirror

A small service and a matching client library that publish Katzenpost PKI
documents over a Reticulum mesh. The service connects to a local
`kpclientd` via the Python thin client, captures fresh PKI documents as
they arrive, and serves them to Reticulum peers over a Link session. The
client lets a calling application discover, fetch, and cache those
documents.

This is a prerequisite to a forthcoming multi-homed pigeonhole courier
service that will also listen on Reticulum and will rely on pkimirror's
client API to obtain the consensus.


## Overview

Many instances of pkimirror may run concurrently across a single mesh.
Each instance is its own destination with its own persisted Reticulum
identity, and each one announces the cached epoch in its announce
`app_data` so that callers may rank announcements before opening a Link
to any one mirror.

Two query paths are exposed by every pkimirror destination:

- `/pki/current`: returns the freshest cached PKI document.
- `/pki/epoch`: with a CBOR-encoded integer in the request body, returns
  the document for that epoch from the five-epoch local history.

Responses are uniform CBOR envelopes whose schema is described in
"Response envelope" below.


## Installation

From a checkout of the thin_client repository:

```
pip install '.[reticulum]'
```

This pulls in the optional Reticulum dependency (`rns`) alongside the
core thin client. A local `kpclientd` is required at runtime; for
development testing the Katzenpost docker mixnet at
`~/katzenpost/docker/` provides one.


## Running the service

```
pkimirror \
    --thinclient-config /path/to/thinclient.toml \
    --identity         /var/lib/pkimirror/identity \
    --rns-config       /etc/reticulum \
    --dirauth-config   /etc/pkimirror/dirauth.toml \
    --announce-interval 300 \
    --stale-after      600 \
    --app-name         katzenpost \
    --aspect           pkimirror \
    --log-level        INFO
```

Flags in detail:

- `--thinclient-config PATH` (required). Path to the TOML configuration
  used by the Python thin client to reach the local `kpclientd`.
- `--identity PATH`. Persistent Reticulum identity file. Created with
  mode `0600` if it does not exist; loaded otherwise. Default
  `~/.config/pkimirror/identity`.
- `--rns-config PATH`. Reticulum configuration directory. If omitted,
  RNS uses its own default location (`~/.reticulum`).
- `--dirauth-config PATH`. TOML file enumerating the directory authority
  identity public keys for the deployment being mirrored. See "Dirauth
  identity configuration" below. Default
  `~/.config/pkimirror/dirauth.toml`.
- `--announce-interval SECONDS`. Period between routine destination
  announces. Default 300. An out-of-band announce is also emitted
  whenever the cache advances to a new epoch, so peers learn of fresh
  consensus promptly without relying on the periodic timer.
- `--stale-after SECONDS`. How old the cached document may be before
  successful responses are flagged `stale = True`. Stale documents are
  still served (more useful than no document), but the flag lets
  cautious callers decline. Default 600.
- `--app-name STR`, `--aspect STR`. Reticulum destination identifiers.
  Default `katzenpost.pkimirror`.
- `--log-level STR`. One of `DEBUG`, `INFO`, `WARNING`, `ERROR`,
  `CRITICAL`. Default `INFO`.

On startup pkimirror prints its destination hash to stdout and logs
both the hash and the first cached PKI epoch at INFO. Operators may
hand the hash to clients out of band, or rely on Reticulum's announce
discovery; both are supported.


## Using the client

A small synchronous client lives at
`katzenpost_reticulum.pkimirror.PkiMirrorClient`. The minimal flow:

```python
import cbor2
from katzenpost_reticulum.pkimirror.client import PkiMirrorClient

with PkiMirrorClient(reticulum_config="/etc/reticulum") as client:
    announces = client.discover(timeout=30.0, max_announces=3)
    if not announces:
        raise SystemExit("no pkimirror found on the mesh")

    best = max(announces, key=lambda a: (a.has_pki, a.epoch))
    client.connect(best.destination_hash, timeout=30.0)

    result = client.get_current(timeout=30.0)
    if result.code != 0:
        raise SystemExit(f"pkimirror error: {result.msg}")
    pki = cbor2.loads(result.doc)
    print(f"epoch: {pki['Epoch']}, services: {len(pki.get('ServiceNodes', []))}")
```

The local cache makes repeat lookups cheap. Pre-warm it once and then
operate from cache:

```python
with PkiMirrorClient(reticulum_config="/etc/reticulum") as client:
    client.connect(destination_hash)
    for epoch in (current_epoch - 1, current_epoch, current_epoch + 1):
        client.get_for_epoch(epoch)        # fetched and cached

    # subsequent calls in this process do not touch the network
    cached = client.get_for_epoch(current_epoch)
    assert cached.code == 0
    assert client.cached_epochs() == sorted({current_epoch - 1, current_epoch, current_epoch + 1})
```

Notes on semantics:

- `get_current(use_cache=False)` (the default) always issues a network
  request, since "current" is by definition not stable. Successful
  responses are added to the local cache by epoch.
- `get_for_epoch(epoch, use_cache=True)` (the default) returns the
  cached entry if present; otherwise it fetches and caches. Pass
  `use_cache=False` to force a network request.
- A `PkiResult` with `code != 0` is returned, not raised. The caller
  decides whether `PKIMIRROR_EPOCH_NOT_CACHED` is fatal.


## Fetching from the command line

For one-off retrieval without writing Python, the `pkimirror-fetch`
console script wraps the client. It discovers a mirror (or takes one
by `--destination`), opens a Link, fetches the consensus, and writes
the raw document bytes to a file or stdout; the epoch, staleness, and
verification status are reported on stderr.

```
# Discover the freshest mirror and write the current consensus
pkimirror-fetch --rns-config /etc/reticulum --output pki.cbor

# A specific mirror and epoch, verified against the dirauth identities
pkimirror-fetch \
    --rns-config /etc/reticulum \
    --destination 3a7f... \
    --epoch 12345 \
    --dirauth-config dirauth.toml \
    --output pki.cbor
```

It exits non-zero if no mirror answers or the mirror returns an error
code. Diagnostics go to stderr so stdout remains a clean document
stream suitable for piping. Equivalent to
`python -m katzenpost_reticulum.pkimirror.fetch`.


## Response envelope

Every server response is a CBOR-encoded map with this schema, regardless
of success or failure:

```python
{
    "code":  int,           # 0 = success
    "epoch": int | None,    # epoch this response describes
    "doc":   bytes | None,  # raw PKI CBOR; non-None only when code == 0
    "msg":   str | None,    # diagnostic; non-None only when code != 0
    "stale": bool,          # True iff the cache is older than --stale-after
}
```

Defined error codes:

| Code | Name | Meaning |
|---|---|---|
| 0 | `PKIMIRROR_OK` | Document attached. |
| 1 | `PKIMIRROR_PKI_UNAVAILABLE` | Mirror has not yet received any PKI. |
| 2 | `PKIMIRROR_EPOCH_NOT_CACHED` | Requested epoch is outside the five-epoch window. |
| 3 | `PKIMIRROR_BAD_REQUEST` | Request body is malformed. |
| 4 | `PKIMIRROR_INTERNAL_ERROR` | Server caught an unexpected exception. |


## Dirauth identity configuration

Both the service and the client accept a TOML file naming the directory
authority identity public keys. Each entry carries a name and a
PEM-encoded public key, matching the format used by katzenpost's own
`authority.toml` so an operator may copy the relevant block across
verbatim. The PEM marker label names the signature scheme (e.g.
`ED25519`, `FALCON-PADDED-512-ED25519`) and the parser captures it on
each loaded `DirauthIdentity`.

```toml
[[dirauths]]
name = "auth1"
identity_public_key = """
-----BEGIN FALCON-PADDED-512-ED25519 PUBLIC KEY-----
<base64-encoded public key>
-----END FALCON-PADDED-512-ED25519 PUBLIC KEY-----
"""

[[dirauths]]
name = "auth2"
identity_public_key = """
-----BEGIN FALCON-PADDED-512-ED25519 PUBLIC KEY-----
<base64-encoded public key>
-----END FALCON-PADDED-512-ED25519 PUBLIC KEY-----
"""
```

The client consumes these keys to verify the `cert.Certificate` wrapper
around each PKI document received from a pkimirror. The bridge inside
the service fetches the signed wrapper from `kpclientd` via its
`get_pki_document_raw` API and serves those bytes over Reticulum; the
client decodes the wrapper, reconstructs the canonical signed message
(`u32-LE Version || u64-LE Expiration || ASCII KeyType || Certified`)
per `katzenpost/core/cert`, and requires a simple majority of
configured dirauth signatures to verify before returning the stripped
`Certified` document to the caller. A `PkiResult.verified` flag
records whether verification was performed.


## Signature scheme caveat

Please attend to this section before deploying. **The choice of dirauth
signature scheme has a decisive effect on whether pkimirror is useful
at all.**

Katzenpost's current Sphincs+ parameterisation in hpqc produces
signatures of approximately 49 KB each. With three or more directory
authorities signing every PKI document, the resulting signed document
balloons to a size that is uncomfortable on most low-bandwidth meshes
and well beyond what a sensible Reticulum deployment ought to relay.
Sphincs+ is therefore unsuitable for use with this integration.

For deployments behind pkimirror we recommend the
**Falcon-padded-512-Ed25519** hybrid signature scheme. Two factors
converge on this choice. First, signature size: at roughly 730 bytes
the hybrid signature is smaller than ML-DSA-44-Ed25519's ~2.5 KB,
keeping the on-wire footprint of a multi-dirauth-signed PKI document
manageable on low-bandwidth links. Second, verifier availability: this
is presently the only post-quantum hybrid scheme that hpqc's Python
bindings can verify, so it is the only scheme under which a
Reticulum-side pkimirror client can actually check directory authority
signatures today. Set
`PKISignatureScheme = "Falcon-padded-512-Ed25519"` in each dirauth's
`authority.toml`, then copy each authority's public key block into
pkimirror's dirauth config (see above).

If a deployment cannot adopt Falcon-padded-512-Ed25519 immediately,
the classical **Ed25519** scheme remains acceptable on the wire and
will likewise verify under pkimirror's client, with the understanding
that one forfeits post-quantum signature security until the upgrade is
made. We expect to revisit this recommendation in turn as more compact
post-quantum signature schemes find their way into hpqc.


## Roadmap

These items are not in the present revision; they are signposted here
so callers may plan accordingly.

- A more compact post-quantum signature scheme in hpqc, after which
  the recommendation in "Signature scheme caveat" may be revisited.
  Falcon-padded-512-Ed25519 is the present recommendation; should hpqc
  expose a verifier for an even smaller scheme, the choice should be
  reconsidered.
- A multi-homed pigeonhole courier service on Reticulum, which will
  use pkimirror's client API to keep abreast of the consensus and
  route pigeonhole traffic accordingly. The shape of pkimirror (the
  cache-first client, the announce app_data carrying the epoch, the
  uniform error envelope, the dirauth config slot) anticipates that
  follow-on.


## Troubleshooting

- **"no PKI document yet received from kpclientd".** The mirror has
  started but `kpclientd` has not yet delivered an initial PKI. Either
  the daemon is not running, the thin-client TOML's socket path is
  wrong, or the mixnet has not yet reached consensus. Check the
  daemon's logs and the dirauths' epoch number.
- **Destination hash never appears.** The service prints its hash on
  stdout once Reticulum has initialised. If stdout is empty, the
  process never made it past `RNS.Reticulum(...)`; check that the
  Reticulum config is valid and that any TCP/UDP interfaces can bind.
- **Client `discover()` returns nothing.** No mirror is announcing on
  the mesh, or your local Reticulum is not connected to one that has
  been announced on. Confirm a path with `rnpath -t <hash>` if you have
  the destination hash, or use `rnstatus` to inspect interfaces.
- **`stale: True` returned.** The cache has not been refreshed within
  `--stale-after`. Either kpclientd has been disconnected, or the
  configured threshold is too tight for normal epoch transitions on
  this deployment. Inspect the service's logs for `kpclientd`-related
  messages.

For detail, raise the log level: `--log-level DEBUG`.
