#!/usr/bin/env bash
#
# Build rs_srp release binaries for Linux, Windows, and macOS.
#
# Cross-compilation uses cargo-zigbuild: everything builds natively on the host
# (fast, no Docker, no per-build container image). cargo-zigbuild is installed
# automatically if missing; the `zig` toolchain must already be present
# (`brew install zig`, etc.).
#
# A containerised alternative is provided in build/Dockerfile.
set -euo pipefail

cd "$(dirname "$0")/.."
DIST="build/dist"
LINUX_TARGET="x86_64-unknown-linux-gnu"
WINDOWS_TARGET="x86_64-pc-windows-gnu"

# ---- toolchain ----
if ! command -v zig >/dev/null 2>&1; then
    echo ">> 'zig' not found — install it (e.g. 'brew install zig') and re-run." >&2
    exit 1
fi
if ! cargo zigbuild --version >/dev/null 2>&1; then
    echo ">> installing cargo-zigbuild…"
    cargo install cargo-zigbuild --locked
fi
rustup target add "$LINUX_TARGET" "$WINDOWS_TARGET" >/dev/null

rm -rf "$DIST"

# ---- Linux x86_64 (glibc 2.31 floor → runs on any modern distro) ----
echo ">> building Linux x86_64…"
cargo zigbuild --release --target "${LINUX_TARGET}.2.31"
mkdir -p "$DIST/linux-x86_64"
cp "target/$LINUX_TARGET/release/rs_srpd" \
   "target/$LINUX_TARGET/release/rs_srpc" "$DIST/linux-x86_64/"

# ---- Windows x86_64 ----
echo ">> building Windows x86_64…"
cargo zigbuild --release --target "$WINDOWS_TARGET"
mkdir -p "$DIST/windows-x86_64"
cp "target/$WINDOWS_TARGET/release/rs_srpd.exe" \
   "target/$WINDOWS_TARGET/release/rs_srpc.exe" "$DIST/windows-x86_64/"

# ---- macOS (host-native; only produced when run on a Mac) ----
if [ "$(uname -s)" = "Darwin" ]; then
    echo ">> building macOS…"
    host_target="$(rustc -vV | sed -n 's/^host: //p')"
    cargo build --release --target "$host_target"
    out="$DIST/macos-$(uname -m)"
    mkdir -p "$out"
    cp "target/$host_target/release/rs_srpd" \
       "target/$host_target/release/rs_srpc" "$out/"
else
    echo ">> not on macOS — skipping the macOS build"
fi

echo
echo ">> done. artifacts under $DIST/:"
find "$DIST" -type f | sort
