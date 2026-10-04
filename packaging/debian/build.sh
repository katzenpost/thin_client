#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."
dpkg-buildpackage -b -uc -us "$@"
mkdir -p dist
mv ../python3-katzenpost-thinclient_*.deb dist/
mv ../librust-katzenpost-thin-client-dev_*.deb dist/
sha256sum dist/*.deb
