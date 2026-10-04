#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
debs=${DEBS_DIR:-/tmp/debs}
mkdir -p "$debs"
cd "$root"

need_tools=
for tool in dpkg-buildpackage dh flit cargo python3; do
    command -v "$tool" >/dev/null || need_tools=1
done
if [ -n "$need_tools" ]; then
    apt update
    apt install -y --no-install-recommends \
        build-essential debhelper dh-python dpkg-dev \
        pybuild-plugin-pyproject python3-all rust-all \
        flit \
        python3-cbor2 python3-coloredlogs python3-toml \
        python3-pip unzip ca-certificates
fi

packaging/debian/build.sh
cp dist/*.deb "$debs"/

apt update
apt install -y "$debs"/*.deb
packaging/debian/test.sh
packaging/debian/assert-reproducible.sh
