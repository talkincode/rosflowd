#!/usr/bin/env bash
set -euo pipefail
# Build nDPI 6.0 from source when distro packages are too old.
VER="${NDPI_VERSION:-6.0}"
PREFIX="${NDPI_PREFIX:-/usr/local}"
if pkg-config --exists libndpi; then
  echo "libndpi $(pkg-config --modversion libndpi)"
  exit 0
fi
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential git autoconf automake libtool pkg-config \
  flex bison libjson-c-dev libpcap-dev
src="$(mktemp -d)"
git clone --depth 1 --branch "$VER" https://github.com/ntop/nDPI.git "$src/nDPI"
cd "$src/nDPI"
./autogen.sh
./configure --prefix="$PREFIX" --with-only-libndpi
make -j"$(nproc)"
sudo make install
sudo ldconfig
pkg-config --modversion libndpi
