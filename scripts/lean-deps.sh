#!/bin/sh
# Restores .lake/packages, with the dependencies' native objects built, from an
# OCI artifact on GHCR keyed by the toolchain and dependency pins. On a miss it
# builds them, and pushes them when LEAN_DEPS_PUSH=1.
# Usage: LEAN_DEPS_REPO=ghcr.io/<owner>/<name> scripts/lean-deps.sh
set -eu

: "${LEAN_DEPS_REPO:?set LEAN_DEPS_REPO}"
key=$(cat lean-toolchain lake-manifest.json | sha256sum | cut -c1-32)-$(uname -m)
ref="$LEAN_DEPS_REPO:$key"
tarball=lean-deps.tar.zst

if oras manifest fetch "$ref" >/dev/null 2>&1; then
	echo "restoring $ref"
	oras pull -o .lake-deps "$ref"
	mkdir -p .lake
	zstd -dc ".lake-deps/$tarball" | tar -C .lake -xf -
	rm -rf .lake-deps
	exit 0
fi

echo "$ref not found, building"
lake exe cache get
lake build thinclient-test thinclient-integration

if [ "${LEAN_DEPS_PUSH:-0}" = 1 ]; then
	tar -C .lake -cf - packages | zstd -T0 -q -o "$tarball"
	oras push "$ref" "$tarball:application/zstd"
	rm "$tarball"
fi
