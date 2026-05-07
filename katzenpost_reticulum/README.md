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
  May be repeated for `--aspect`. Default `katzenpost.pkimirror`.
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
authority identity public keys. The format:

```toml
sphincs_warning = "ed25519"

[[dirauths]]
name     = "auth1"
identity = "8c3f9aa01b...deadbeef"   # hex-encoded public key

[[dirauths]]
name     = "auth2"
identity = "5e7b21c9d4...cafe"
```

For the present revision the loaded keys are not yet used: the Python
thin client delivers PKI documents stripped of their signatures, so a
Reticulum-side observer has nothing to verify against. The slot exists
now so that when a forthcoming thin-client API method returns the fully
signed document, signature verification can be inserted without a
config-format change. See "Roadmap" below.


## Signature scheme caveat

Please attend to this section, sir, before deploying. **The choice of
dirauth signature scheme has a decisive effect on whether pkimirror is
useful at all.**

Katzenpost's current Sphincs+ parameterisation in hpqc produces
signatures of approximately 49 KB each. With three or more directory
authorities signing every PKI document, the resulting signed document
balloons to a size that is uncomfortable on most low-bandwidth meshes
and well beyond what a sensible Reticulum deployment ought to relay.

For the time being we therefore recommend that deployments using
pkimirror configure their directory authorities to sign with **Ed25519**
only. The PKI document remains comfortably small and traverses
Reticulum without strain.

This is a temporary recommendation. Once ML-DSA is added to hpqc, a
hybrid Ed25519+ML-DSA scheme will replace it as the recommended
configuration for Reticulum-bridged deployments, restoring
post-quantum signature security at a manageable size.


## Roadmap

These items are not in the present revision; they are signposted here
so callers may plan accordingly.

- A new thin-client API method that returns the fully signed PKI
  document (working title: `pki_document_signed()`), so a
  Reticulum-side client may verify dirauth signatures itself. This
  belongs in the katzenpost monorepo.
- ML-DSA in hpqc, and a hybrid Ed25519+ML-DSA signature scheme, after
  which the recommendation in "Signature scheme caveat" will change.
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
