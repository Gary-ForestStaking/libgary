# SessionHandle boundary — v0 shipping contract

Single operational contract for embedders and FFI. Normative protocol prose stays in `docs/v0-*.md`; this file is **rules only**.

---

## A. Ingress rule

Only `SessionHandle::handle_inbound_outer` is trusted for **wire ingress**: validated header, enforced epoch / RESET policy, then decrypt.

Direct `recv_*` bypasses RESET-era policy that ingress applies — use only when the caller already mirrors those guarantees.

---

## B. State model (minimal)

Runtime overlays only (**not** part of the cryptographic WAL blob in v0):

- **Active(epoch)** — normal traffic under current epoch.
- **ResetPending** — isolation window after local RESET rebootstrap (reject configured late DATA).
- **Bootstrapping(epoch)** — post-reset handshake alignment before returning to Active.

After blob reload / `from_export`, mode is rebuilt as **Active(epoch)** — see persistence rule.

---

## C. Persistence rule

- WAL stores a **cryptographic ratchet snapshot** (`SessionExport` bundle), not UI/session UX state.
- **No `SessionMode` persistence in v0** (Option A).
- Reload / import **always** yields **Active(epoch)** for mode semantics.

---

## D. RESET rule

- RESET lifecycle is **runtime-only** — lost on crash unless reconstructed by higher layers from transport facts.
- **No replayable durable reset window** in v0 WAL semantics.

---

## E. Save / load rule

- **Before save**: call `SessionHandle::recompute_anchor_commitment()` after any ratchet progress so anchor commitment matches exported snapshot (see `docs/v0-state-integrity.md`).
- **Load** (`SessionStore::load_session` / `SessionHandle::from_export`) returns a **fresh handle** — never assume an older in-memory handle matches disk without reloading or replaying the same transcript.

Persistence API: `libgary_storage::SessionStore` — `save_session` / `load_session`; not inherent methods on `SessionHandle`.

---

## F. Error semantics (application mapping)

| Variant | Meaning |
|--------|---------|
| `ReplayRejected` | Duplicate / too-old wire counter vs receiver window. |
| `StaleEpochRejected` | Header epoch inconsistent with session epoch (includes wrong epoch on decrypt paths). |
| `LateDataAfterReset` | DATA on prior epoch while ingress RESET isolation applies (`handle_inbound_outer` policy). |
| `DecryptionFailed` | AEAD / framing MAC verification failed. |

Other variants (`InvalidHeader`, `FutureEpoch`, `UnknownSession`, …) remain machine-readable via `SessionError`; map to stable integer codes at FFI.

---

## FFI shape

- **Opaque pointer only** — no Rust structs across the boundary.
- **No epoch or mode** exposed.
- **Errors**: integer codes only at ABI edge.
- **Panic boundary**: foreign entrypoints must not unwind into C — wrap Rust calls (`catch_unwind` / abort policy); never `unwrap` on foreign bytes.

Stub crate: `libgary-ffi` (`libgary_session_free`; expand later).

---

## Protocol tests only

Crate feature `protocol-test-api` on `libgary-core` exposes RESET helpers and introspection for integration tests — **disable in production embedding** (`default-features = false` on the dependency).

Full CI: `cargo test --workspace --locked --all-features`.

Minimal CI / golden digest only: `cargo test --workspace --locked` (skips feature-gated integration binaries).
