# libgary v0 — Domain separation label registry

**Normative.** Single source of truth for protocol **octet strings** used in KDFs, hashes, HMACs, and AEAD AAD prefixes.  
Implementations **must** use **exact** UTF-8 bytes listed here — **no** paraphrases, locale variants, or alternate spellings.

Companion specs split usage across documents; **this file is the collision-free registry.**  
New labels for **v1+** **must** extend with **`libgary-v1/`…** (or higher) — **never** overload **`libgary-v0/`** semantics.

See also [v0-protocol.md](v0-protocol.md) §2, [v0-kdf.md](v0-kdf.md), [v0-handshake.md](v0-handshake.md), [v0-reset.md](v0-reset.md), [v0-mailbox-fetch.md](v0-mailbox-fetch.md).

---

## 1. HKDF `info` arguments (`HKDF-SHA-256`, RFC 5869)

| Label (UTF-8) | Role |
|-----------------|------|
| `libgary-v0/root-key-v1` | Session **`OKM`** from **`IKM_session`** ([v0-handshake.md](v0-handshake.md) §3.4) |
| `libgary-v0/libgary-chain` | BOOT → initial **`CKs`** / **`CKr`** ([v0-protocol.md](v0-protocol.md) §8.2) |
| `libgary-v0/libgary-root` | DH ratchet **`RK'`** + mixed chains ([v0-protocol.md](v0-protocol.md) §8.5) |
| `libgary-v0/libgary-msg` | Prefix only; wire uses **`‖ big_endian_u64(m)`** ([v0-protocol.md](v0-protocol.md) §8.1) |
| `libgary-v0/confirm-v1` | **`confirm_key`** from **`OKM`** ([v0-handshake.md](v0-handshake.md) §4) |
| `libgary-v0/init-aead-v1` | **`K_init`** from **`KM ‖ TH0`** ([v0-handshake.md](v0-handshake.md) §5) |
| `libgary-v0/ack-aead-v1` | **`K_ack`** from **`OKM`** ([v0-handshake.md](v0-handshake.md) §6) |
| `libgary-v0/control-aead-v1` | **`K_control`** from **`OKM`** ([v0-handshake.md](v0-handshake.md) §7) |
| `libgary-v0/init-inner-v1` | INIT inner plaintext filler ([v0-handshake.md](v0-handshake.md) §5) |
| `libgary-v0/ack-inner-v1` | INIT_ACK inner plaintext filler ([v0-handshake.md](v0-handshake.md) §6) |
| `libgary-v0/ctrl-pad-v1` | Control body HKDF pad ([v0-handshake.md](v0-handshake.md) §7) |
| `libgary-v0/data-inner-pad-v1` | DATA semantic → fixed **512 B** inner ([v0-protocol.md](v0-protocol.md) §6.4) |
| `libgary-v0/nonce-v1` | **`NONCE24`** HKDF `info` ([v0-kdf.md](v0-kdf.md) §3) |
| `libgary-v0/fetch-cap-key-v1` | Server **`K_fetch_epoch`** derivation ([v0-mailbox-fetch.md](v0-mailbox-fetch.md) §2.3) |

---

## 2. HKDF salt labels

| Label | Role |
|-------|------|
| **`SHA256(UTF-8 `libgary-v0-handshake`)`** (32 B) | Salt for **`OKM`** / **`OKM_r`** ([v0-handshake.md](v0-handshake.md) §3.4; [v0-reset.md](v0-reset.md)) |
| **`ZERO32`** (32× `0x00`) | Common HKDF salt for sub-keys, **`NONCE24`**, chain steps ([v0-handshake.md](v0-handshake.md), [v0-protocol.md](v0-protocol.md) §8) |

---

## 3. SHA-256 transcript / fingerprint prefixes

Concatenated **before** indicated payloads **as UTF-8** unless noted.

| Prefix (UTF-8) | Role |
|----------------|------|
| `libgary-v0/th0-v1` | **`TH0`** over **`InitBody`** ([v0-handshake.md](v0-handshake.md) §3.1) |
| `libgary-v0/th1-v1` | **`TH1`** over **`TH0 ‖ InitAckCore`** ([v0-handshake.md](v0-handshake.md) §3.2) |
| `libgary-v0/th0-reset-v1` | **`TH0_r`** ([v0-reset.md](v0-reset.md) §4.1) |
| `libgary-v0/th1-reset-v1` | **`TH1_r`** ([v0-reset.md](v0-reset.md) §4.2) |
| `libgary-v0/state-commit-v1` | **`DeviceStateAnchor`** preimage ([v0-state-integrity.md](v0-state-integrity.md) §4) |
| `libgary-v0/safety-number-v1` | Pairwise fingerprint ([v0-protocol.md](v0-protocol.md) §3.3) |

---

## 4. AEAD associated-data string prefixes (UTF-8)

| Prefix | Role |
|--------|------|
| `libgary-v0/init-aad-v1` | INIT inner AEAD AAD ([v0-handshake.md](v0-handshake.md) §5.3) |
| `libgary-v0/ack-aad-v1` | INIT_ACK inner AEAD AAD ([v0-handshake.md](v0-handshake.md) §6) |
| `libgary-v0/reset-init-aad-v1` | RESET_INIT AAD ([v0-reset.md](v0-reset.md) §4.3) |
| `libgary-v0/reset-ack-aad-v1` | RESET_ACK AAD ([v0-reset.md](v0-reset.md) §4.3) |

(`DATA` uses **canonical 63-byte Header** as AAD — no string prefix.)

---

## 5. `NONCE24` ASCII tags inside `label_dist` (UTF-8)

These are **not** HKDF `info` strings; they prefix **`epoch_be ‖ …`** per [v0-kdf.md](v0-kdf.md) §3.

| Tag | Context |
|-----|---------|
| `INIT` | INIT inner AEAD |
| `ACK` | INIT_ACK inner AEAD |
| `RINIT` | RESET_INIT inner AEAD |
| `RACK` | RESET_ACK inner AEAD |
| `CTRL` | **`‖ u8(type) ‖ epoch ‖ counter ‖ session_id`** — REKEY/CLOSE in v0 |
| `DATA` | **`‖ epoch ‖ counter ‖ session_id ‖ ratchet_pub`** |

---

## 6. Mailbox fetch capability (**`FetchCapV1`**)

| Label (UTF-8) | Role |
|----------------|------|
| `libgary-v0/fetch-cap-v1` | **HMAC-SHA-256 `msg` prefix** for **`fetch_cap_mac`** ([v0-mailbox-fetch.md](v0-mailbox-fetch.md) §2.1) |

HKDF **`libgary-v0/fetch-cap-key-v1`** for **`K_fetch_epoch`** — §1 (distinct string — **not** interchangeable with the HMAC prefix above).

---

## 7. Algorithm notes (not HKDF `info`)

| Mechanism | Detail |
|-----------|--------|
| **`CONFIRM_MAC`** | **`trunc_128(HMAC-SHA256(confirm_key, TH1))`** — key from HKDF **`libgary-v0/confirm-v1`** ([v0-handshake.md](v0-handshake.md) §4) |

---

## 8. Freeze policy (after implementation parity)

Once Swift + Rust harnesses match **[test-vectors.md](test-vectors.md)** byte-for-byte:

| Frozen | Changes allowed |
|--------|-----------------|
| Wire bytes in vectors | Bugfixes, editorial clarity, **version-bumped** security patches only |
| Entries **§1–§8** of **this document** | **`libgary-v1/…`** namespace or explicit doc revision — **no silent edits** to **`libgary-v0/…`** meanings |

Do **not** add new **`libgary-v0/`** labels in patches without bumping protocol **`kdf_suite_id`** / **`protocol_version`** ([v0-state-integrity.md](v0-state-integrity.md), [v0-protocol.md](v0-protocol.md) §2).

---

## Document history

| Rev | Note |
|-----|------|
| v0-freeze | Initial registry + **`fetch-cap-v1`** / **`fetch-cap-key-v1`** |
