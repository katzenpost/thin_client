#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

katzenpost_ref=${katzenpost_ref:?}
katzenpost_dir=${katzenpost_dir:-.katzenpost}
live_dir=${live_dir:-.live}

if [ ! -d "$katzenpost_dir/.git" ]; then
	git clone --quiet https://github.com/katzenpost/katzenpost "$katzenpost_dir"
fi
git -C "$katzenpost_dir" fetch --quiet origin "$katzenpost_ref" || true
git -C "$katzenpost_dir" checkout --quiet "$katzenpost_ref"

mkdir -p "$live_dir"
make -C "$katzenpost_dir/docker" start wait
trap 'make -C "$katzenpost_dir/docker" stop || true; git checkout -- testdata/thinclient.toml 2>/dev/null || true' EXIT INT TERM

cp "$katzenpost_dir/docker/mixnet-alpine/client/thinclient.toml" testdata/thinclient.toml
uv run --with pytest --with pytest-asyncio --with pytest-timeout pytest tests/ -q --timeout=1200
cargo test --test '*' -- --nocapture --test-threads=3
