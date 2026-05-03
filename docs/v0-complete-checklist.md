# v0 complete gate — checklist

Do **not** treat “design richness” as shipped product; gate releases / FFI/mobile embedding on this list.

Legend: **[done]** verified today · **[partial]** exists but incomplete · **[open]** not satisfied  

---

## Execution correctness

| Gate | Status | Evidence / gap |
|------|--------|----------------|
| Clean send/receive loop end-to-end (paired peers, typed payloads). | **[partial]** | `tests/full_transcript.rs`, `engine_session_tests.rs`, wire fixtures — broaden fixture-linked vectors vs docs. |
| **Restart** does not break sessions (reload-safe semantics). | **[partial]** | WAL reload + `from_export`; “restart” = fresh handle + same persisted blob (`recovery_equivalence`, storage tests). Mobile lifecycle packaging still separate. |
| **Replay** reproduces cryptographic equivalence (`persistence_equivalence_digest`). | **[done]** | `recovery_equivalence.rs`; CI via default workspace tests. |
| **RESET / epoch** transitions deterministic given scripted transcript inputs. | **[partial]** | `full_transcript.rs`, `full_transcript_chaos.rs`, `api_boundary.rs` (`protocol-test-api`); **step-by-step hex vectors for RESET chain still thin vs handshake/DATA.** |

---

## Spec parity / ambiguity elimination

| Gate | Status | Evidence / gap |
|------|--------|----------------|
| **Test vectors are source of truth** — behavior absent from vectors is not asserted as v0. | **[open]** | `docs/test-vectors.md` + `doc_vectors.rs` cover subsets; expand ratchet chains, RESET steps, replay negatives systematically. |
| **No hidden production vs test divergence** — optional internals obviously flagged. | **[partial]** | `protocol-test-api` isolates drills from default embedding surface (`session-handle-boundary.md`); **`SessionWalSource` persistence accessors remain reachable via trait** (acceptable plumbing). Audit FFI exports (`libgary-ffi`). |

---

## Persistence hardening

| Gate | Status | Evidence / gap |
|------|--------|----------------|
| Deterministic replay from disk vs forward execution (golden digest). | **[done]** | `recovery_equivalence.rs`. |
| Crash-conservative WAL narrative documented **and** tested for rollback/tamper. | **[partial]** | `storage_tests.rs`, `docs/v0-state-integrity.md` — write explicit **“no migration v0”** decision once locked (`bundle`/anchor versioning prose). |

---

## Embedding boundary

| Gate | Status | Evidence / gap |
|------|--------|----------------|
| **`SessionHandle` minimal surface** in production builds (`default-features = false`). | **[partial]** | Narrow inherent API documented (`README.md`, `session-handle-boundary.md`); hold count stable (~targets ≤ 8 logical ops after consolidating persistence ergonomics). |
| **FFI cannot stumble into protocol-debug hooks.** | **[partial]** | `libgary-ffi` stub is minimal; expand FFI **only** with ABI tables + panic guards (`catch_unwind` pattern established). |

---

## Explicit deferrals (not v0-complete blockers but forbidden expansions mid-freeze)

Per **`docs/v0-golden-path.md`**: invite production UX depth, mailbox fetch optimizations, attachment breadth, multi-device transport explorations — **after** gates above trend **[done]**.

---

## Review cadence

Re-score statuses each meaningful milestone **from Rust CI outputs**, not intent docs alone:

```bash
cargo test --workspace --locked
cargo test --workspace --locked --all-features
```
