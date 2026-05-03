#!/usr/bin/env bash
# Build libgary-ffi static library for iOS Simulator (Apple Silicon host).
# Prerequisites: rustup target add aarch64-apple-ios-sim
# Uses rustup's cargo when ~/.cargo/env exists (Homebrew rustc alone cannot install std for iOS).
# If xcrun cannot find iphonesimulator (only Command Line Tools selected), points at Xcode.app.
set -euo pipefail

if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck source=/dev/null
    source "${HOME}/.cargo/env"
fi
if [[ -d "/Applications/Xcode.app/Contents/Developer" ]]; then
    export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/examples/ios/LibGaryShell/rust-lib"
mkdir -p "$OUT"

cargo build -p libgary-ffi --release --target aarch64-apple-ios-sim

cp "$ROOT/target/aarch64-apple-ios-sim/release/liblibgary_ffi.a" "$OUT/"
echo "Installed $OUT/liblibgary_ffi.a"
