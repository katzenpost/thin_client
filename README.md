# Katzenpost thin client libraries

[![ci](https://github.com/katzenpost/thin_client/actions/workflows/ci.yml/badge.svg)](https://github.com/katzenpost/thin_client/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/katzenpost_thinclient)](https://pypi.org/project/katzenpost_thinclient/)
[![crates.io](https://img.shields.io/crates/v/katzenpost_thin_client)](https://crates.io/crates/katzenpost_thin_client)
[![docs.rs](https://img.shields.io/docsrs/katzenpost_thin_client)](https://docs.rs/katzenpost_thin_client)

Rust, Python and Lean libraries that let an application send messages
and use Pigeonhole storage over a [Katzenpost](https://github.com/katzenpost)
mixnet, by talking to the local client daemon `kpclientd`.

This is for application developers. A thin client does no cryptography
and no networking of its own: it speaks a CBOR-framed protocol over a
local socket, and `kpclientd` does the rest, so you need a running
daemon. Go programs should use the reference thin client in
[`katzenpost/client/thin`](https://github.com/katzenpost/katzenpost/tree/main/client/thin)
instead. [docs/overview.md](docs/overview.md) explains thin clients and
Pigeonhole in more detail.

## Quick start

With `kpclientd` running and its thin client config in `thinclient.toml`
([Docker test network](https://katzenpost.network/docs/admin_guide/docker.html)):

```bash
pip install katzenpost_thinclient
```

```python
import asyncio
from katzenpost_thinclient import ThinClient, Config

async def main():
    client = ThinClient(Config("thinclient.toml"))
    await client.start(asyncio.get_running_loop())
    print("PKI epoch", client.pki_document()["Epoch"])
    client.stop()

asyncio.run(main())
```

For Rust (`cargo add katzenpost_thin_client`) and Lean, see the
per-language READMEs below. The
[how-to guide](https://katzenpost.network/docs/thin_client_howto/) and
[API reference](https://katzenpost.network/docs/thin_client_api_reference/)
cover Pigeonhole streams and messaging.

## What is here

- [`src/`](src/): Rust crate `katzenpost_thin_client`; [README_rust.md](README_rust.md).
- [`katzenpost_thinclient/`](katzenpost_thinclient/): Python package; [README_python.md](README_python.md).
- [`ThinClient/`](ThinClient/): Lean Lake package `thinclient`; [README_lean.md](README_lean.md).
- [`tests/`](tests/): Python and Rust tests, mostly integration tests against a daemon.
- [`scripts/gen-vectors/`](scripts/gen-vectors/): writes [`testdata/vectors.json`](testdata/vectors.json) from the daemon's Go types.
- [`packaging/`](packaging/), [`debian/`](debian/): Debian packages.

[docs/layout.md](docs/layout.md) lists every file.

## Status and compatibility

Pre-1.0. The Python and Rust clients share one version (`pyproject.toml`,
`Cargo.toml`); the Lean client has its own (`lakefile.toml`).
All three speak to the `kpclientd` built from the Katzenpost commit pinned
as `katzenpost_ref` in the [Makefile](Makefile), which the integration
CI runs against. The test vectors in `testdata/vectors.json` are encoded by
the Go thin client's own types, at the Katzenpost version pinned in
`scripts/gen-vectors/go.mod`; the Rust, Python and Lean tests check against them, and
`make test-lean` checks that Lean-encoded requests decode in Go.
[Build from source](https://katzenpost.network/docs/build_from_source/)
lists the versions pinned across the stack.

## Testing and contributing

`make test` runs the Python and Rust tests (Python needs `uv`; daemon
tests are skipped without one), `make test-lean` the Lean tests, and
`make check-live` builds `kpclientd` and runs a few tests against the
live namenlos mixnet (needs Go). Pull requests are welcome; maintainers
see [RELEASING.md](RELEASING.md).

## License

AGPL-3.0-only; see [LICENSE](LICENSE).
