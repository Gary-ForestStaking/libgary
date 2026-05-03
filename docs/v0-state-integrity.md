# libgary v0 — Local state integrity & anti-rollback

**Normative product/crypto hygiene.** Complements [v0-protocol.md](v0-protocol.md) §8–§9 (ratchet + replay) and [v0-reset.md](v0-reset.md) (network-visible catastrophic recovery).

The relay cannot detect **local state rewind**. Clients **must**.

---

## 1. Threat: stale snapshot restore

**Scenario:** an attacker or buggy backup restores an **older** copy of the messaging database (or extracts VM snapshot).

After rewind the honest client may:

- reuse **chain keys** and **MK** derivation linearity inconsistent with what the peer has advanced  
- reuse **`Header.counter_be`** values → violates §9 monotonicity from the peer’s perspective  
- break **`NONCE24`** uniqueness expectations relative to stored ciphertext  

Symptoms: reject loops, silent forks, or worst case ambiguous decryption windows — post-compromise recovery assumptions ([threat-model.md](threat-model.md)) and [**replay**](v0-protocol.md) rules collapse until **`RESET_*`** / new handshake.

---

## 2. Goals

| Goal | Mechanism |
|------|-----------|
| Detect rollback | Monotonic **device-local integrity anchor** independent of chat DB |
| Refuse downgrade | Never accept persisted `(epoch, counter_be, m_s/m_r, RK)` **lower** than anchor |
| Tamper evident | Bind blob §8.7 fields under **`state_commitment`** |

---

## 3. Integrity anchor (per-device)

Maintain **`DeviceStateAnchor`** in storage **harder to rewind than** the chat DB:

- **Apple:** Keychain item **`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`** (or stricter), **not** included in ordinary encrypted backups users toggle casually — document exact entitlement posture per app distribution.
- **Other platforms:** OS TPM / Keystore / **minimal secret-backed file** with ACL denying duplicate restores onto older images — deployment-specific.

**Recommended persisted fields** (`opaque_encoding`, big-endian where numeric):

```
struct DeviceStateAnchorV1 {
    u16 anchor_version_be;           // 0x0001
    u16 protocol_version_be;         // MUST equal `Header.version` profile — **1** for v0 ([v0-protocol.md](v0-protocol.md))
    u32 kdf_suite_id_be;             // **1** = §2 suite (HKDF-SHA-256 + XChaCha20-Poly1305 + Ed25519 + X25519 as specified)
    u64 global_epoch_be;             // strictly increases on each §11 handshake-open / RESET-complete / reinstall fence
    u64 highest_wire_seen_be;        // max Header.counter_be observed across all ACTIVE sessions (all dirs), clamp semantics §9
    u32 ratchet_blob_scheme_be;      // profile id — matches RatchetStateBlob.blob_version (§8.7)
    u8  state_commitment[32];        // SHA256(canonical snapshot §4)
};
```

**`protocol_version_be`** and **`kdf_suite_id_be`** **must** match the values hashed into **`state_commitment`** so future migrations never collide silently with legacy anchors.

### 3.1 Monotonicity rules

On **every successful decrypt / encrypt commit** that advances `(session_id, epoch)` ratchet state:

1. Load **`DeviceStateAnchor`**.  
2. Let **`snapshot`** = canonical serialization of **critical fields** committed from §8.7 blobs §4.  
3. Compute **`candidate_commitment = SHA256(snapshot)`**.  
4. **Reject persist** if any invariant fails:

   - `global_epoch_be` **never decreases**.  
   - For each session half: outbound **`send_count_be`** (next assigned counter) **never decreases**; inbound **`recv_high_water_be`** **never decreases**.  
   - **`send_sym_idx_be` / `recv_sym_idx_be`** **never decrease** while `(RK || CKs || CKr)` pair unchanged — after **`RESET_*`** or §11.1 new epoch, **re-anchor** entire blob atomically.

5. Write **`state_commitment`** and **`DeviceStateAnchor`** **before** acknowledging ACK to user (“delivered”) — single transactional filesystem boundary where possible.

**Rollback simulation:** if DB restores **`RatchetStateBlob`** older than anchor ⇒ **`FAIL_CLOSED`** → wipe pairwise epoch → **`RESET_*`** or user-guided repair — outward **`ERR_GENERIC`** only.

---

## 4. `state_commitment` binding

Canonical **`snapshot`** includes **at minimum** (concatenate in order):

```
UTF-8 "libgary-v0/state-commit-v1"
|| big_endian_u16(protocol_version_be)    // v0: 1 — matches Header.version profile
|| big_endian_u32(kdf_suite_id_be)       // v0: 1 — matches §2 cryptographic suite id ([v0-protocol.md](v0-protocol.md) §2)
|| FOR each ACTIVE session (ordered lexicographically by session_id[16]):
       session_id || epoch_be || RK || CKs || CKr
    || dh_ratchet_pk || peer_ratchet_pub
    || send_count_be || recv_high_water_be
    || send_sym_idx_be || recv_sym_idx_be
|| big_endian_u64(global_epoch_be)
```

**`state_commitment = SHA256(snapshot)`** (32 bytes).

(Hash covers semantics — exact canonical bytes **must** be documented with fixtures alongside §8.7.)

---

## 5. Interaction with backup / migration

| Flow | Rule |
|------|------|
| **Full device backup** including Keychain | Treat as **atomic** — Apple docs vary by backup type; apps **must** document whether rollback remains possible via device swap |
| **Export “messages only”** | **Unsafe** unless pairing export embeds **`DeviceStateAnchor`** — default **off** |
| **Cross-device clone** | Requires intentional **`RESET_*`** on old device before trusting new — outside v0 multi-device scope |

---

## 6. Operational failures

| Event | Response |
|-------|----------|
| Anchor missing | Prefer bootstrap **`RESET_*`** + anchor recreate |
| Anchor newer than DB | Refuse start → repair UX |
| Commitment mismatch | **`ERR_INVALID_KEY`** internally → teardown session |

---

## Document history

| Rev | Note |
|-----|------|
| v0 | Anti-rollback anchor + binding rules |
| v0 freeze | `protocol_version_be` / `kdf_suite_id_be` in anchor + `state_commitment` preimage §4 |
