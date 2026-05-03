# Rust toolchain policy

This repository pins the compiler with **`rust-toolchain.toml`** (via **rustup**) and declares **`rust-version`** / **`edition`** in the workspace **`Cargo.toml`**.

## Why pin?

- **Reproducible builds** — combine pinned `rustc`/`cargo`, **`Cargo.lock`**, and git revision for auditable, repeatable artifacts.
- **Stable CI and reviews** — optimizer, diagnostics, Clippy, and standard-library behavior stay consistent across machines.
- **Crypto hygiene** — fewer “works on my rustc” surprises; upgrades are explicit decisions.
- **Fuzzing parity** — sanitizer/fuzz stacks behave consistently when the toolchain is fixed (`rust-src` is included for source-aware tooling).

## Current pin

- **Channel:** see **`rust-toolchain.toml`** (e.g. `1.95.0`).
- **MSRV:** **`rust-version`** in root **`Cargo.toml`** (workspace package metadata).

Homebrew’s standalone `rustc` may ignore `rust-toolchain.toml`; use **rustup** locally and in CI so the pin is enforced.

## Bump checklist

Before advancing the pinned channel / MSRV:

1. **`cargo test --workspace`**
2. **Vector parity** — golden tests in **`crates/libgary-core/tests/doc_vectors.rs`** against **`docs/test-vectors.md`**
3. **Fuzz smoke** — when fuzz targets exist, run a short fuzz session on the new toolchain
4. **Benchmark diff** — if you track perf, compare before/after on representative workloads

Then update **`rust-toolchain.toml`**, workspace **`rust-version`**, and this doc’s “Current pin” if needed.

## Future targets

When Android FFI lands, add **`aarch64-linux-android`** (and other NDK ABIs you support) under **`[toolchain].targets`** in **`rust-toolchain.toml`**.
