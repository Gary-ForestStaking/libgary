# libgary v0 — Catastrophic reset & session replacement

**Normative.** When local state is corrupt, keys are lost, or ratchets diverge irrecoverably, clients **must** converge on a **fresh cryptographic session** instead of silent forks.

Companion: [v0-handshake.md](v0-handshake.md), [v0-protocol.md](v0-protocol.md) §7, §11.

---

## 1. When to reset

| Trigger | Action |
|---------|--------|
| Persistent decrypt failures / MAC failures after bounded retries | **Catastrophic reset** §2 |
| User “Reset encryption” | **Catastrophic reset** |
| Detected duplicate/conflicting ratchet state | **Catastrophic reset** |
| Storage corruption / restore from backup missing ratchet blob | **Catastrophic reset** |
| Normal PCS / voluntary rekey within healthy session | Prefer **REKEY** / DH ratchet §8 — **not** this document |

---

## 2. Wire types

| Value | Name | Role |
|-------|------|------|
| `0x07` | **`RESET_INIT`** | New X3DH bootstrap + transcripts; replaces broken session |
| `0x08` | **`RESET_ACK`** | Completes reset handshake |

Cryptographic layout **mirrors** `INIT` / `INIT_ACK` ([v0-handshake.md](v0-handshake.md)) with **domain-separated** transcripts so resets cannot be spliced with first-time handshakes.

---

## 3. Header obligations

For **both** `RESET_INIT` and `RESET_ACK`:

1. **`epoch_be`** = previous epoch **plus one** (mod 2³²; reject unreasonable rollback vs local policy).  
2. **`session_id`** = fresh **16-byte** CSPRNG (must **not** reuse prior active session id).  
3. **`counter_be`** restarts at **`0`** for the new session half.

---

## 4. Transcripts (reset domain)

### 4.1 `ResetInitBody`

**Byte-identical** struct to `InitBody` ([v0-protocol.md](v0-protocol.md) §7.2) — 100 bytes.

```
TH0_r = SHA256( UTF-8 "libgary-v0/th0-reset-v1" || ResetInitBody )
```

### 4.2 `ResetAckCore` / `ResetAckWire`

Same sizes as `InitAckCore` (72 B) / `InitAckWire` (88 B) ([v0-handshake.md](v0-handshake.md) §2):

```
TH1_r = SHA256( UTF-8 "libgary-v0/th1-reset-v1" || TH0_r || ResetAckCore )

KM_r    = X3DH shared secret from ResetInitBody geometry (fresh ephemeral + fresh OTP consumption)
IKM_r   = KM_r || TH0_r || TH1_r
OKM_r   = HKDF(salt_handshake, ikm=IKM_r, info="libgary-v0/root-key-v1", L=64)
```

`CONFIRM_MAC` for reset uses **`OKM_r`** and **`TH1_r`** exactly like §4 [v0-handshake.md](v0-handshake.md) (`confirm_key` derived from `OKM_r`, MAC input `TH1_r`).

### 4.3 AEAD keys & nonces

| Packet | Key material | Nonce |
|--------|--------------|-------|
| `RESET_INIT` inner | `K_init_r = HKDF(ZERO32, KM_r‖TH0_r, "libgary-v0/init-aead-v1", 32)` | [v0-kdf.md](v0-kdf.md) **`NONCE24(KM_r‖TH0_r, "RINIT"‖epoch‖session_id)`** |
| `RESET_ACK` inner | `K_ack_r = HKDF(ZERO32, OKM_r, "libgary-v0/ack-aead-v1", 32)` | **`NONCE24(OKM_r, "RACK"‖epoch‖session_id)`** |

Inner plaintext fillers: HKDF from **`TH0_r`** / **`TH1_r`** with labels **`libgary-v0/init-inner-v1`** / **`libgary-v0/ack-inner-v1`** (same lengths as normal handshake).

`AAD` strings: UTF-8 **`libgary-v0/reset-init-aad-v1`** and **`libgary-v0/reset-ack-aad-v1`** respectively, followed by **`epoch_be ‖ session_id ‖` body copy** (parallel to normal INIT/ACK AAD structure).

---

## 5. Revocation / tombstone

Upon **successful** verification of `RESET_ACK`:

1. **Zeroize** keys & counters for the **prior** `(epoch_prev, session_id_prev)`.  
2. Mark **`session_id_prev`** **tombstoned** — reject any future ciphertext claiming that pair (counterfeit detection → **`ERR_GENERIC`** outward per [v0-protocol.md](v0-protocol.md) §10).  
3. Persist **`OKM_r`**-derived ratchet state only.

---

## 6. Replay

| Record | Rule |
|--------|------|
| `RESET_INIT` | Same ephemeral uniqueness policy as `INIT` ([v0-handshake.md](v0-handshake.md) §8), scoped per peer `account_id`. |
| `RESET_ACK` | At most **one** accepted `RESET_ACK` per `(epoch_new, session_id_new)` pending reset. |

---

## 7. State machine

Extend [state-machine.md](state-machine.md):

```
ACTIVE --(unrecoverable failure / user reset)--> NONE --(RESET_INIT)--> RESET_SENT --(RESET_ACK)--> ACTIVE'
```

`CLOSE` remains polite shutdown without implying catastrophic corruption.

---

## Document history

| Rev | Note |
|-----|------|
| v0 | RESET_INIT / RESET_ACK, domain-separated transcripts, tombstone prior session |
