# libgary — private 1:1 messenger (v0 protocol)

End-to-end encrypted messenger with Signal-like security, built from standard primitives (not libsignal). **v1 is intentionally narrow**; protocol work is named internally **v0 protocol**.

This repository contains the **normative specs** under [`docs/`](docs/README.md) and a **Rust reference workspace** (ratchet engine, wire codec, atomic WAL persistence, FFI stub).

**Normative specs:** [`docs/v0-protocol.md`](docs/v0-protocol.md) (framing + ratchet) and [`docs/v0-handshake.md`](docs/v0-handshake.md) (transcripts + handshake/control AEAD) — index: [`docs/README.md`](docs/README.md).

**Shipping boundary for embedders:** [`docs/session-handle-boundary.md`](docs/session-handle-boundary.md) (ingress rule, WAL / Option A, errors, FFI rules).

**License:** [Apache License 2.0](LICENSE).

---

## Rust workspace

| Crate | Role |
|--------|------|
| [`crates/libgary-core`](crates/libgary-core) | X3DH session material, HKDF tree helpers, AEAD, **`SessionHandle`** ratchet engine |
| [`crates/libgary-wire`](crates/libgary-wire) | Headers, `OuterRecord`, relay envelope, `PAD()` |
| [`crates/libgary-storage`](crates/libgary-storage) | Atomic LGW1 WAL + trusted meta / rollback detection |
| [`crates/libgary-ffi`](crates/libgary-ffi) | Minimal **C ABI** façade (opaque session + safe free path — extend deliberately) |
| [`crates/libgary-attach`](crates/libgary-attach) | Attachment crypto scaffolding (v0 attachments spec) |
| [`crates/libgary-testvec`](crates/libgary-testvec) | Fixture placeholders / linkage |

Toolchain: **Rust 1.95** (see workspace [`Cargo.toml`](Cargo.toml) `rust-version`).

### Build and test

```bash
cargo build --workspace --locked
```

**Default tests** (CI-safe subset — includes golden persistence digest + doc vectors):

```bash
cargo test --workspace --locked
```

**Full protocol / chaos integration tests** (enable crate feature `protocol-test-api` on `libgary-core`):

```bash
cargo test --workspace --locked --all-features
```

CI runs the **all-features** suite (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

### Embedder API (Rust)

Use **`SessionHandle`** only at the application boundary (crate-private ratchet `Session`). Ingress on the wire should go through **`handle_inbound_outer`** unless your caller mirrors the same epoch / RESET policy; details are fixed in [`docs/session-handle-boundary.md`](docs/session-handle-boundary.md).

Advanced drills (`RESET` transitions, mode introspection) compile only with **`protocol-test-api`** — **do not enable that feature** in production embedding (`default-features = false` on the dependency).

Persistence is **`SessionStore`** in `libgary-storage` (`save_session` / `load_session`), not extra methods on the handle.

### Fuzzing

The [`fuzz/`](fuzz/) tree is a separate Cargo workspace. Typical ingress fuzz:

```bash
cd fuzz
cargo fuzz run handle_inbound_outer
```

---

## Non-goals (for first shipping version)

Do **not** start with: groups, voice/video calls, public usernames, bots, channels, or federation. Add those only after the 1:1 core is specified, implemented, and reviewed.

## Engineering principles

- **Do not invent cryptography.** Only compose known primitives and documented constructions.
- **Protocol spec first, code second.** Document handshake, packet format, ratchet state, replay handling, and recovery like an RFC (including test vectors / hex fixtures per message type).
- **Production wire format:** canonical **binary framing** (version, type, length-prefixed fields, explicit endianness and maximum lengths). Avoid ad hoc JSON on the wire.
- Your differentiation is **protocol UX**, **metadata posture**, and **product**—not new cipher math.

## Privacy posture (“extreme privacy” defaults)

Optimize for **privacy over convenience**: **[full 32-byte `account_id`](docs/v0-protocol.md)** (SHA-256 of Ed25519 pk), **invite / QR-only** discovery ([`docs/v0-invite-uri.md`](docs/v0-invite-uri.md)), **wake-only** push, **minimal server logs**, **[relay outer envelope](docs/v0-protocol.md)** (`route_token` only—opaque E2E inside), **universal `PAD()` buckets** §6.5, **sealed sender** deferred to **[v0.5](docs/v0.5-sealed-sender.md)**, **safety numbers before transparency logs**, **invite-only** growth, **backup off by default** — see [`docs/privacy-architecture.md`](docs/privacy-architecture.md).

### Normative sequence (stop spec drift)

1. Handshake transcripts + confirmation + control AEAD — **[docs/v0-handshake.md](docs/v0-handshake.md)** + **[docs/test-vectors.md](docs/test-vectors.md)**  
2. **`NONCE24` + KDF tree + label registry** — **[docs/v0-kdf.md](docs/v0-kdf.md)**, **[docs/label-registry.md](docs/label-registry.md)**  
3. Double Ratchet §8 — **[docs/v0-protocol.md](docs/v0-protocol.md)**  
4. Catastrophic recovery — **[docs/v0-reset.md](docs/v0-reset.md)**  
5. Mailbox fetch privacy — **[docs/v0-mailbox-fetch.md](docs/v0-mailbox-fetch.md)**  
6. Padding — **§6.5** (all types + relay envelope)  
7. **`ERR_GENERIC`** wire posture — **[docs/v0-protocol.md](docs/v0-protocol.md)** §10  
8. Local anti-rollback — **[docs/v0-state-integrity.md](docs/v0-state-integrity.md)**  
9. Invite revocation (`invite_id`) — **[docs/v0-invite-revocation.md](docs/v0-invite-revocation.md)**  
10. Integration transcript — `python3 tools/gen_test_vectors.py --integration`  
11. Invite blob — **[docs/v0-invite-uri.md](docs/v0-invite-uri.md)**  
12. Sealed sender mini-spec — **[docs/v0.5-sealed-sender.md](docs/v0.5-sealed-sender.md)** (after core stable)

## Protocol stack (v0) — summary

Full detail remains in **`docs/v0-protocol.md`**. At a glance:

1. **Identity** — Ed25519 long-term keys; Apple-friendly secure storage on clients.  
2. **Prekeys** — signed prekey + one-time prekeys for async starts.  
3. **Handshake** — X25519 / X3DH-shaped transcript binding + Ed25519 authentication scope in spec.  
4. **Ratchet** — Double Ratchet (root, chains, bounded skip cache, explicit DH rotation rules).  
5. **Payloads** — AEAD (v0 uses ChaCha20-Poly1305 family per spec); explicit nonces and AD binding.  
6. **Replay** — counters, ordering window, reset semantics specified in protocol.  
7. **Recovery** — reset vs continuation; multi-device deferred unless explicitly scoped.  
8. **Attachments** — **[docs/v0-attachments.md](docs/v0-attachments.md)**.

## Binary framing (outline)

Canonical records: magic/version, message type, bounded fields, inner `length || bytes`, declared endianness — **normative detail and limits in [`docs/v0-protocol.md`](docs/v0-protocol.md)** and wire tests under `crates/libgary-wire/tests/`.

## Server role (trusted delivery only)

Directory / relay of opaque blobs / wakeup push / attachment relay — **must not** decrypt application payloads.

## Tech stack (directional)

**Reference crypto & session engine:** Rust workspace (this repo).

**Client (product direction):** Swift, SQLite / SQLCipher, libsodium via Swift wrapper — integrates via FFI against a deliberately small Rust surface (`libgary-ffi` direction).

**Backend (product direction):** Rust or Go, PostgreSQL, Redis queue, QUIC — orthogonal to the E2E boundary described above.

## Future (explicitly not v1)

- **Disappearing messages** — [`docs/privacy-architecture.md`](docs/privacy-architecture.md) §12.  
- **Group chat / MLS** — separate track from 1:1 v0.  
- **XMPP / Prosody** — only if you ship XMPP; not implied by the custom relay design.

## Next steps

1. Keep **`docs/v0-protocol.md`** and **`docs/test-vectors.md`** authoritative; extend vectors where gaps remain.  
2. Run **`cargo test --workspace --locked`** before every change; use **`--all-features`** before merge / in CI.  
3. When wiring Swift or another host, treat [`docs/session-handle-boundary.md`](docs/session-handle-boundary.md) as the integration contract alongside the protocol docs.
