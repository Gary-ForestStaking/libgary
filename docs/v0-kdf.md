# libgary v0 — KDF tree & nonce derivation

**Normative.** Companion to [v0-protocol.md](v0-protocol.md), [v0-handshake.md](v0-handshake.md), [v0-attachments.md](v0-attachments.md).  
**All HKDF / transcript labels:** canonical table **[label-registry.md](label-registry.md)**.

All KDF = **HKDF-SHA-256** (RFC 5869).  
`ZERO32 = 32 × 0x00`.

---

## 1. Master session secret (`OKM`)

After X3DH `KM` and transcripts `TH0`, `TH1` ([v0-handshake.md](v0-handshake.md) §3):

```
salt_handshake = SHA256(UTF-8 "libgary-v0-handshake")
IKM_session    = KM || TH0 || TH1
OKM            = HKDF(salt=salt_handshake, ikm=IKM_session, info=UTF-8 "libgary-v0/root-key-v1", L=64)
```

Split:

```
RK0  = OKM[0..32]      # initial Double Ratchet root ([v0-protocol.md](v0-protocol.md) §8)
BOOT = OKM[32..64]     # chain bootstrap ("libgary-chain")
```

---

## 2. Derivation tree from `OKM` / handshake

```
OKM (64)
├── RK0 ─────────────────────────► Double Ratchet root ([v0-protocol.md](v0-protocol.md) §8.5 `libgary-root` updates)
├── BOOT ─────► HKDF(..., "libgary-v0/libgary-chain") ──► CKs / CKr
├── confirm_key ──► HKDF(salt=ZERO32, ikm=OKM, info="libgary-v0/confirm-v1", L=32) ──► CONFIRM_MAC key
├── K_ack ───────► HKDF(salt=ZERO32, ikm=OKM, info="libgary-v0/ack-aead-v1", L=32)
├── K_control ───► HKDF(salt=ZERO32, ikm=OKM, info="libgary-v0/control-aead-v1", L=32)
└── (attachment branch) ──► **see [v0-attachments.md](v0-attachments.md)** — CEK / manifest keys MUST NOT be spawned from OKM; use ratchet `MK`-wrapped blobs only.

KM-only branch (before final `OKM`):

```
K_init ─► HKDF(salt=ZERO32, ikm= KM || TH0, info=UTF-8 "libgary-v0/init-aead-v1", L=32)
```

Inner handshake plaintext fillers ([v0-handshake.md](v0-handshake.md) §5–§6):

```
plain_inner_init = HKDF(ZERO32, TH0, info=UTF-8 "libgary-v0/init-inner-v1", L=256)
plain_inner_ack  = HKDF(ZERO32, TH1, info=UTF-8 "libgary-v0/ack-inner-v1",  L=256)
```

Ratchet message keys:

```
(MK, CK') = HKDF-split on CKs / CKr with info UTF-8 "libgary-v0/libgary-msg" || BE64(m)
           where m = symmetric chain index m_s / m_r ([v0-protocol.md](v0-protocol.md) §8.3–§8.4) — not Header.counter_be
```

DH ratchet mixing:

```
OKM_dh = HKDF(salt=RK_old, ikm=DH_out, info=UTF-8 "libgary-v0/libgary-root", L=96)
```

---

## 3. Canonical nonce — **`NONCE24` (single rule)**

All **24-byte** AEAD nonces (XChaCha20-IETF) **must** use:

```
NONCE24(i_core: bytes, label_dist: bytes) :=
    HKDF-SHA256(
        salt = ZERO32,
        ikm  = i_core || label_dist,
        info = UTF-8 "libgary-v0/nonce-v1",
        L    = 24
    )
```

| Context | `i_core` | `label_dist` (concatenation) |
|---------|----------|------------------------------|
| **`INIT` inner AEAD** | `KM ‖ TH0` | UTF-8 **`"INIT"`** ‖ `epoch_be` ‖ `session_id[16]` |
| **`INIT_ACK` inner** | `OKM` | UTF-8 **`"ACK"`** ‖ `epoch_be` ‖ `session_id[16]` |
| **`RESET_INIT`** ([v0-reset.md](v0-reset.md)) | `KM_r ‖ TH0_r` | UTF-8 **`"RINIT"`** ‖ `epoch_be` ‖ `session_id[16]` |
| **`RESET_ACK`** | `OKM_r` | UTF-8 **`"RACK"`** ‖ `epoch_be` ‖ `session_id[16]` |
| **Control** (`REKEY`/`CLOSE`; **`RECEIPT`** reserved v0) | `OKM` | UTF-8 **`"CTRL"`** ‖ `u8(type)` ‖ `epoch_be` ‖ `counter_be` ‖ `session_id[16]` |
| **`DATA`** | **`MK`** (per-message ratchet key) | UTF-8 **`"DATA"`** ‖ `epoch_be` ‖ `counter_be` ‖ `session_id[16]` ‖ `ratchet_pub[32]` |

**Rules:**

1. **`epoch_be`, `counter_be`** — big-endian wire widths matching Header ([v0-protocol.md](v0-protocol.md) §6.3).  
2. **`session_id`** — exactly **16** bytes from the same Header.  
3. **`ratchet_pub`** — sender’s ratchet public key in that Header (32 B).  
4. **Never reuse** `(MK, epoch, counter, session_id, ratchet_pub)` tuple for two distinct payloads.

Deprecated: ad-hoc `SHA256(prefix||…)[0:24]` nonce recipes — do **not** implement.

---

## 4. ASCII overview

```
                    KM ─────┬──► TH0 ──┐
                            │          ├──► IKM_session ──► OKM ──┬──► RK0 / BOOT
                    X3DH    └──► TH1 ──┘                         ├──► confirm_key
                                                                  ├──► K_ack
                                                                  └──► K_control

KM ‖ TH0 ──► K_init ──► INIT inner AEAD
OKM      ──► K_ack  ──► INIT_ACK inner AEAD
OKM      ──► K_control ──► control-plane AEAD

BOOT ──► libgary-chain ──► CKs, CKr ──► libgary-msg + counter ──► MK ──► DATA AEAD + NONCE24(MK, "DATA"‖…)
RK0 + DH_out ──► libgary-root ──► RK', chains…

Attachments: CEK inside DATA plaintext only ([v0-attachments.md](v0-attachments.md)); separate HKDF labels there.
```

---

## Document history

| Rev | Note |
|-----|------|
| v0 | Single NONCE24 primitive; OKM tree diagram |
