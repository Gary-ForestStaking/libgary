# libgary v0 — Handshake, transcripts, authentication

**Normative companion** to [v0-protocol.md](v0-protocol.md).  
Conflicts: **v0-protocol.md** wins on numeric § alignment for framing; **this document wins** on handshake byte semantics, transcript binding, confirmation, and control-plane AEAD.

HKDF / HMAC / SHA prefixes used below — **[label-registry.md](label-registry.md)**.

---

## 1. Goals

| Goal | Mechanism |
|------|-----------|
| **Integrity** | No structured protocol record is “PAD-only plaintext.” INIT / INIT_ACK / REKEY / CLOSE are **AEAD-authenticated** (XChaCha20-Poly1305). (**`RECEIPT`** deprecated v0 — [v0-protocol.md](v0-protocol.md) §7.) |
| **Transcript binding** | `TH0`, `TH1` mixed into session `IKM` before `OKM` derivation §3. |
| **Key confirmation** | Truncated **HMAC-SHA256** over `TH1` using key derived from `OKM` §4. |
| **Replay control** | Explicit rules for handshake & control duplicates §8. |
| **Cryptographic erasure** | Normative deletion behaviors §9. |

Constants reuse [v0-protocol.md](v0-protocol.md) §2 suite (`HKDF-SHA-256`, `XChaCha20-Poly1305`, `SHA-256`, `HMAC-SHA-256`).

```
ZERO32 = 32 × 0x00
```

---

## 2. Canonical handshake bodies

### 2.1 `InitBody` (100 bytes) — initiator → responder

```
initiator_sig_pk[32]      // Ed25519
initiator_dh_pk[32]       // X25519 IK_DH
ephemeral_ek_pub[32]      // X25519 ephemeral
otp_index_be              // u16, 0xFFFF = SPK-only
reserved_be               // u16 MUST be 0
```

### 2.2 `InitAckCore` (72 bytes) — responder → initiator

```
responder_sig_pk[32]
responder_dh_pk[32]
ack_nonce_be              // u64 CSPRNG (freshness)
```

### 2.3 `InitAckWire` (88 bytes)

```
init_ack_core = InitAckCore        // 72 bytes
confirm_mac[16]                   // §4
```

---

## 3. Transcript hashes & session `IKM → OKM`

### 3.1 `TH0` — client (`INIT`)

```
TH0 = SHA256( UTF-8 "libgary-v0/th0-v1" || InitBody )
```

### 3.2 `TH1` — after `InitAckCore` fixed

`InitAckCore` must be hashed **without** `confirm_mac` so both peers compute the same digest before MAC expansion:

```
TH1 = SHA256( UTF-8 "libgary-v0/th1-v1" || TH0 || InitAckCore )
```

### 3.3 X3DH shared secret `KM`

Exactly as [v0-protocol.md](v0-protocol.md) §5.1–§5.2 (`DH1…DH4`, concatenation rules).

### 3.4 Session `IKM` & `OKM` (**replaces** naive `HKDF(salt, KM)`)

```
salt_handshake = SHA256(UTF-8 "libgary-v0-handshake")    # 32 bytes; same salt label as legacy doc
IKM_session    = KM || TH0 || TH1
info_root      = UTF-8 "libgary-v0/root-key-v1"
OKM            = HKDF-SHA256(salt=salt_handshake, ikm=IKM_session, info=info_root, L=64)
```

Interpretation ([v0-protocol.md](v0-protocol.md) §8):

```
root_key      = OKM[0..32]
bootstrap_key = OKM[32..64]
```

### 3.5 Bindings (explicit)

| Derived material | Binds transcript? |
|------------------|------------------|
| `OKM` | **Yes** (`KM‖TH0‖TH1`). |
| Double Ratchet root / chains | **Yes** (seeded from `OKM`). |
| Safety number / fingerprint ([privacy-architecture.md](privacy-architecture.md)) | **SHOULD** include `SHA256(TH1‖peer_identity_pk)` or equivalent UX-defined encoding — exact UI bytes **non-normative**; document chosen fingerprint in client release notes. |

---

## 4. Key confirmation

```
confirm_key = HKDF-SHA256(salt=ZERO32, ikm=OKM, info=UTF-8 "libgary-v0/confirm-v1", L=32)
CONFIRM_MAC = trunc_128( HMAC-SHA256(confirm_key, TH1) )   # first 16 bytes
```

Responder sets `confirm_mac` field in `InitAckWire`. Initiator recomputes `TH1`, `OKM`, verifies MAC equals **before** trusting session.

Mismatch ⇒ **`ERR_INVALID_KEY`** and teardown.

---

## 5. `INIT` authenticated framing (`type = 0x01`)

### 5.1 Sub-keys

```
K_init = HKDF-SHA256(salt=ZERO32, ikm= KM || TH0, info=UTF-8 "libgary-v0/init-aead-v1", L=32)
```

(`KM` and `TH0` available to Alice before send; Bob recomputes after parsing `InitBody`.)

### 5.2 Nonce

```
nonce_init = NONCE24(i_core = KM || TH0,
                     label_dist = UTF-8 "INIT" || epoch_be || session_id_hdr[16])
```

See **[v0-kdf.md](v0-kdf.md) §3** (`NONCE24`).

### 5.3 Associated data

Bind ciphertext to handshake transcript **before** optional QUIC outer layers:

```
AAD_INIT = UTF-8 "libgary-v0/init-aad-v1"
        || big_endian_u32(epoch_hdr)
        || session_id_hdr[16]
        || InitBody
```

Use **Header** fields `epoch_be`, `session_id` from the enclosing `OuterRecord` ([v0-protocol.md](v0-protocol.md) §6.3).

### 5.4 Plaintext & wire layout

**Inner plaintext** (inside AEAD, length **256 bytes** — smallest `PADDING_BUCKETS` tier, reproducible for vectors):

```
plain_inner_init = HKDF-SHA256(salt=ZERO32, ikm=TH0, info=UTF-8 "libgary-v0/init-inner-v1", L=256)
```

**Associated data** binds `InitBody` cryptographically; tampering any bound field breaks the Poly1305 tag. Implementations **must verify AEAD before** consuming OTP slots or branching on `InitBody`.

```
inner_aead = XChaCha20-Poly1305_encrypt(K_init, nonce_init, plain_inner_init, AAD_INIT)

logical_INIT_pre_pad = InitBody || nonce_init[24] || inner_aead
OuterRecord.payload   = PAD_outer(logical_INIT_pre_pad)    // random tail per [v0-protocol.md](v0-protocol.md) §6.5
```

(`PAD_outer` is the global wire `PAD()` rule.)

---

## 6. `INIT_ACK` authenticated framing (`type = 0x02`)

After Bob computes `OKM` and `confirm_mac`:

```
K_ack = HKDF-SHA256(salt=ZERO32, ikm=OKM, info=UTF-8 "libgary-v0/ack-aead-v1", L=32)

nonce_ack = NONCE24(i_core = OKM,
                    label_dist = UTF-8 "ACK" || epoch_be || session_id_hdr[16])

AAD_ACK = UTF-8 "libgary-v0/ack-aad-v1"
       || big_endian_u32(epoch_hdr)
       || session_id_hdr[16]
       || InitAckWire           # full 88 bytes

plain_inner_ack = HKDF-SHA256(salt=ZERO32, ikm=TH1, info=UTF-8 "libgary-v0/ack-inner-v1", L=256)

inner_aead_ack = XChaCha20-Poly1305_encrypt(K_ack, nonce_ack, plain_inner_ack, AAD_ACK)

logical_ACK_pre_pad = InitAckWire || nonce_ack[24] || inner_aead_ack
OuterRecord.payload  = PAD_outer(logical_ACK_pre_pad)
```

Initiator verifies AEAD then `CONFIRM_MAC`.

---

## 7. Post-handshake control packets (`REKEY` / `CLOSE`)

**`RECEIPT`** (`0x04`) is **not used** in v0 ([v0-protocol.md](v0-protocol.md) §7; [v0-mailbox-fetch.md](v0-mailbox-fetch.md) §6).

After successful handshake:

```
K_control = HKDF-SHA256(salt=ZERO32, ikm=OKM, info=UTF-8 "libgary-v0/control-aead-v1", L=32)

nonce_ctrl = NONCE24(
    i_core = OKM,
    label_dist = UTF-8 "CTRL" || u8(type) || big_endian_u32(epoch) || big_endian_u64(counter) || session_id[16]
)

AAD_CTRL = canonical Header (63 bytes)

body = serialize(RekeyBody | CloseBody)                   // fixed structs — MUST satisfy len(body) ≤ 256

plain_inner_ctrl = body || HKDF-SHA256(salt=ZERO32, ikm=body, info=UTF-8 "libgary-v0/ctrl-pad-v1", L=256 - len(body))
```

(`serialize(...)` per [v0-protocol.md](v0-protocol.md) §7.)

```
inner_ctrl = XChaCha20-Poly1305_encrypt(K_control, nonce_ctrl, plain_inner_ctrl, AAD_CTRL)

logical_ctrl_pre_pad = nonce_ctrl[24] || inner_ctrl
OuterRecord.payload   = PAD_outer(logical_ctrl_pre_pad)
```

**DATA** messages remain ratchet-encrypted per [v0-protocol.md](v0-protocol.md) §6.4 §8.

---

## 8. Replay & duplicate semantics

| Record | Rule |
|--------|------|
| **INIT** | Per responder mailbox (`account_id`), reject if `ephemeral_ek_pub` (from verified `InitBody`) seen **non-superseded** within retention window (≥ 24 h recommended). Optional: LRU of recent ephemerals (bounded). |
| **INIT_ACK** | Accept **at most one** successful ACK per `(session_id, epoch)` for a pending INIT. Duplicate ⇒ `ERR_REPLAY`. |
| **REKEY / CLOSE** | Standard counter replay window ([v0-protocol.md](v0-protocol.md) §9); duplicate `(type, counter)` ⇒ `ERR_REPLAY`. |

Out-of-order **control** messages follow same sliding discipline as DATA where counters apply; **INIT** uses distinct epoch/session bootstrap state machine ([state-machine.md](state-machine.md)).

---

## 9. Cryptographic erasure (normative)

Implementations **must**:

| Secret material | When to delete |
|-----------------|----------------|
| Consumed **one-time prekey** private halves (server/client) | Immediately after first successful handshake using that OTP slot. |
| **Message keys** `MK` | Immediately after encrypt/decrypt completes for that message (unless debugging flag explicitly disables — non-production only). |
| Old **chain keys** superseded by ratchet advance | Immediately after new keys committed to persistent store. |
| Skipped message keys when consumed | Remove entry from skipped map **before** ACK to sender if applicable. |
| **Attachment CEKs** | After TTL / local policy / user burn; zeroize decrypted file keys after use when disappearing-message policy applies. |
| **OKM** / `confirm_key` | May retained only inside sealed ratchet state blob; **must not** log. |

Implementations **should** `explicit_bzero` / secure alloc zeroization APIs where available.

---

## 10. Implementation ordering

1. Implement §3–§7 literally; verify against **[test-vectors.md](test-vectors.md)** after regeneration.  
2. Multi-step integration tests: run `python3 tools/gen_test_vectors.py --integration` (`STEP01…STEP06`) **before** Swift/Rust split releases.  
3. Invite vectors ([v0-invite-uri.md](v0-invite-uri.md)) **after** handshake vectors stabilize.

---

## Document history

| Rev | Note |
|-----|------|
| v0 | Transcript-bound `OKM`, CONFIRM_MAC, AEAD on control-plane records, erasure + replay rules |
| v0 freeze | **`RECEIPT`** out of scope for send path — [v0-protocol.md](v0-protocol.md) §7 |
