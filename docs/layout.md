# Directory layout

```
thin_client/
├── src/                            Rust thin client (crates.io: katzenpost_thin_client)
│   ├── lib.rs                      Crate root; re-exports the public API.
│   ├── core.rs                     ThinClient struct: connection, events, message send.
│   ├── pigeonhole.rs               Low-level Pigeonhole API (manual cap and index handling).
│   ├── transport/                  Pluggable daemon transports.
│   │   ├── mod.rs                  Dialer trait and DialConfig discriminated union.
│   │   ├── unix.rs                 Abstract Unix domain socket transport.
│   │   └── tcp.rs                  TCP transport (used by the docker mixnet).
│   ├── helpers.rs                  PKI document utilities (find_services, pretty print).
│   └── error.rs                    Error types and error code translation.
├── katzenpost_thinclient/          Python thin client (PyPI: katzenpost_thinclient)
│   ├── __init__.py                 Public API and module docstring.
│   ├── core.py                     ThinClient and Config; replica error types.
│   ├── pigeonhole.py               Capability-based Pigeonhole API.
│   └── transport/                  Daemon transports (TCP and Unix).
├── ThinClient/                     Lean thin client (Lake package: thinclient)
│   ├── Api/                        Messaging, Pigeonhole, PKI, box and voucher API.
│   └── Tests/                      Lean unit and integration tests.
├── tests/                          Integration tests (Rust and Python).
│   ├── conftest.py                 Pytest fixtures; dials the daemon named in testdata/thinclient.toml.
│   ├── high_level_api_test.rs      Stateless courier-envelope tests.
│   ├── channel_api_test.rs         Channel API tests.
│   ├── directory_authorities_test.rs  get_directory_authorities test.
│   └── test_*.py                   Python unit and integration tests.
├── testdata/
│   ├── thinclient.toml             Fixture config (TCP dial, Sphinx and Pigeonhole geometry).
│   └── vectors.json                Protocol test vectors written by scripts/gen-vectors.
├── scripts/gen-vectors/            Go generator of protocol test vectors from the daemon's types.
├── docs/                           Longer notes linked from the README.
├── packaging/, debian/             Debian package build.
├── Makefile                        Test, lint and live-mixnet targets.
├── Cargo.toml                      Rust crate manifest.
├── lakefile.toml                   Lean package manifest.
├── pyproject.toml                  Python package manifest.
├── requirements.txt                Python runtime dependencies.
├── pydoc-markdown.yml              Pydoc generation config for the Python API reference.
├── README.md                       Top-level README (rendered on GitHub).
├── README_python.md                Bundled with the PyPI package.
├── README_lean.md                  Lean thin client README.
├── README_rust.md                  Bundled with the crates.io package.
└── RELEASING.md                    Release and publish procedure.
```
