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

Homebrew’s standalone `rustc` may ignore `rust-toolchain.toml`; use **rustup** locally and on **Linux** so the pin is enforced.

## Linux and macOS hosts

1. Install **rustup** ([https://rustup.rs/](https://rustup.rs/)) — on Linux use the shell installer; avoid distro `rustc` only if you want this repo’s pinned version.
2. Clone the repo and run **`cargo test --workspace`** from the repo root. Rustup reads **`rust-toolchain.toml`**, installs **1.95.0**, components, and the listed **extra** targets.
3. Your **host** standard library (e.g. `x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-gnu` on Linux, `aarch64-apple-darwin` / `x86_64-apple-darwin` on macOS) is installed automatically for the machine you’re on. The **`targets`** list in **`rust-toolchain.toml`** adds cross-target `rust-std` so Mac and Linux machines stay aligned when building or CI-checking the other OS.

Static musl builds (`*-unknown-linux-musl`) are not pinned here yet; add a triple under **`[toolchain].targets`** if you standardize on musl for releases.

## Bump checklist

Before advancing the pinned channel / MSRV:

1. **`cargo test --workspace`**
2. **Vector parity** — golden tests in **`crates/libgary-core/tests/doc_vectors.rs`** against **`docs/test-vectors.md`**
3. **Fuzz smoke** — when fuzz targets exist, run a short fuzz session on the new toolchain
4. **Benchmark diff** — if you track perf, compare before/after on representative workloads

Then update **`rust-toolchain.toml`**, workspace **`rust-version`**, and this doc’s “Current pin” if needed.

## Future targets

When Android FFI lands, add **`aarch64-linux-android`** (and other NDK ABIs you support) under **`[toolchain].targets`** in **`rust-toolchain.toml`**.
