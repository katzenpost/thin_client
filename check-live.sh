#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

katzenpost_ref=${katzenpost_ref:?}
katzenpost_dir=${katzenpost_dir:-.katzenpost}
live_dir=${live_dir:-.live}
connect_deadline=${connect_deadline:-480}

if [ ! -d "$katzenpost_dir/.git" ]; then
	git clone --quiet https://github.com/katzenpost/katzenpost "$katzenpost_dir"
fi
git -C "$katzenpost_dir" fetch --quiet origin "$katzenpost_ref" || true
git -C "$katzenpost_dir" checkout --quiet "$katzenpost_ref"

mkdir -p "$live_dir"
live=$(cd "$live_dir" && pwd)
( cd "$katzenpost_dir/cmd/kpclientd" && go build -trimpath -o "$live/kpclientd" . )

sed -e "s#^\( *Address = \)\"@katzenpost\"#\1\"$live/kpclientd.sock\"#" \
	-e '/^ *Addresses = \["\$XDG_RUNTIME_DIR/d' \
	"$katzenpost_dir/docker/client-configs/namenlos.toml" > "$live/client.toml"
sed "s#@katzenpost#$live/kpclientd.sock#" \
	"$katzenpost_dir/docker/client-configs/namenlos-thin.toml" > "$live/thinclient.toml"

"$live/kpclientd" -c "$live/client.toml" > "$live/kpclientd.log" 2>&1 &
daemon=$!
trap 'kill $daemon 2>/dev/null || true; git checkout -- testdata/thinclient.toml 2>/dev/null || true' EXIT INT TERM

deadline=$(( $(date +%s) + connect_deadline ))
connected=no
daemon_died=no
while [ "$(date +%s)" -lt "$deadline" ]; do
	if grep -q 'Connected to gateway' "$live/kpclientd.log" 2>/dev/null; then
		connected=yes
		break
	fi
	if ! kill -0 "$daemon" 2>/dev/null; then
		daemon_died=yes
		break
	fi
	sleep 5
done

if [ "$daemon_died" = yes ]; then
	echo "the client daemon exited before it connected; this is a failure, not an unreachable network"
	tail -40 "$live/kpclientd.log" 2>/dev/null || true
	exit 1
fi

if [ "$connected" = no ]; then
	echo "namenlos is unreachable, treating this run as inconclusive"
	tail -40 "$live/kpclientd.log" 2>/dev/null || true
	exit 0
fi

cp "$live/thinclient.toml" testdata/thinclient.toml
status=0
uv run --with pytest --with pytest-asyncio --with pytest-timeout pytest -q --timeout=900 \
	tests/test_core.py \
	tests/test_new_pigeonhole_api.py::test_alice_sends_bob_complete_workflow || status=$?
cargo test --test directory_authorities_test -- --nocapture || status=$?
if [ "$status" != 0 ]; then
	echo "the clients reached namenlos and then failed their tests"
	exit "$status"
fi
echo "namenlos check passed"
