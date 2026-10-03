#!/bin/sh
set -eu

python3 -c "import katzenpost_thinclient"
python3 -c "from katzenpost_thinclient import ThinClient"
python3 -c "import katzenpost_thinclient.core"

crate=$(ls -d /usr/share/cargo/registry/katzenpost_thin_client-*)
test -f "$crate/Cargo.toml"
test -f "$crate/src/lib.rs"
test -f "$crate/.cargo-checksum.json"
