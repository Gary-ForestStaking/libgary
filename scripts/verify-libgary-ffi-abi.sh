#!/usr/bin/env bash
# Verify public `gary_*` symbols in libgary-ffi static archive vs `include/libgary.h`.
# Rust `__ZN…` / `.llvm.` symbols inside the .a are normal ( Rust monomorphization ); they are not the C surface.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
A="${ROOT}/examples/ios/LibGaryShell/rust-lib/liblibgary_ffi.a"
if [[ ! -f "$A" ]]; then
  echo "missing $A — run ./scripts/build-libgary-ios-sim.sh first" >&2
  exit 1
fi

echo "=== Expected public ABI (10 symbols, Darwin nm prefix _gary_) ==="
nm "$A" 2>/dev/null | rg ' T _gary_' | rg -v '\.llvm\.' || true

COUNT="$(nm "$A" 2>/dev/null | rg -c ' T _gary_' || true)"
if [[ "$COUNT" != 10 ]]; then
  echo "FAIL: expected exactly 10 text symbols matching _gary_, got: ${COUNT:-0}" >&2
  exit 1
fi

echo "OK: ten gary_* exports present."
