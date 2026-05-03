# v0 golden execution path

Single strict flow everything else hangs off of. Until this path is **deterministic** (same inputs ⇒ same observable crypto state / digest gates), expanding invite systems, mailbox fetch, attachments, or transport variants is wasted scope.

## Canonical stages

| Step | What must happen | Primary proof in-tree |
|------|-------------------|----------------------|
| 1 | **Identity material** available for handshake binding (long-term keys, fixtures acceptable for reference impl). | `crates/libgary-core/tests/full_transcript.rs` (`DocFixture` keys loaded); production wire identity UX still separate from engine. |
| 2 | **Handshake** — X3DH-shaped KM + transcript binds (`TH0`/`TH1`), INIT/ACK inner AEAD as specified. | `tests/full_transcript.rs`; **`tests/doc_vectors.rs`** (`docs/test-vectors.md` excerpts). |
| 3 | **Session establishment** — derive session OKM / bootstrap ratchet (`SessionHandle::bootstrap_*`). | `full_transcript.rs`, `engine_session_tests.rs` (`protocol-test-api`). |
| 4 | **Send message** — DATA framing (`OuterRecord`), PAD buckets where outer path applies. | `full_transcript.rs`, `recovery_equivalence.rs`, `full_transcript_chaos.rs` (`protocol-test-api`). |
| 5 | **Receive message** — ingress (`handle_inbound_outer`) or explicit recv paths matched to caller policy (`session-handle-boundary.md`). | Same + `tests/api_boundary.rs` (`protocol-test-api`). |
| 6 | **Persistence** — WAL atomic commit (`SessionStore::save_session`) after **`recompute_anchor_commitment`**. | **`tests/recovery_equivalence.rs`**; **`crates/libgary-storage/tests/storage_tests.rs`**. |
| 7 | **Reload** — `load_session` / `from_export` yields fresh handle matching cryptographic snapshot + anchor gates. | `recovery_equivalence.rs`, storage rollback tests. |
| 8 | **Replay from persisted / transcript bytes** — bit-identical convergence vs forward execution (digest invariant). | **`recovery_equivalence::golden_persistence_equivalence_digest_forward_wal_replay`**. |

## Minimal CI invocation for “golden gate”

```bash
cargo test --workspace --locked
```

Runs persistence equivalence + doc vectors + WAL drills **without** `protocol-test-api`.

Full golden-path extras (RESET half-open, expanded chaos):

```bash
cargo test --workspace --locked --all-features
```

## Freeze discipline (temporary)

Until this checklist is green (**[`v0-complete-checklist.md`](v0-complete-checklist.md)**):

- **No new protocol features** without a **named hex/test-vector delta** in `docs/test-vectors.md` (or generated artifact tracked beside it) **before** implementation merges.
- **No drift**: Rust merges that change observable transcript/session semantics **must** update vectors **and** golden digest expectations in the same change.

Invite UX, mailbox fetch optimizations, attachment breadth, multi-device, and alternate transports stay **out of the execution-critical path** until the golden path and vectors claim completeness.
