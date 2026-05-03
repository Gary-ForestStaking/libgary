# libgary v0 protocol (normative)

**Version:** v0 wire + cryptography profile  
**Endianness:** Multi-byte integers use **network byte order (big-endian)** unless stated otherwise.  
**Conflicts:** Wire framing / numeric § alignment wins here; **[v0-handshake.md](v0-handshake.md)** wins on transcript hashes, `OKM` composition, `CONFIRM_MAC`, and handshake/control AEAD layouts.

---

## 1. Protocol goals

### 1.1 In scope

| Goal | Meaning |
|------|---------|
| **1:1 async messaging** | Two-party conversations; messages deliver while recipient offline via server queue. |
| **Offline delivery** | Server stores opaque ciphertext until fetch; no decryption requirement. |
| **Forward secrecy** | Past message keys not derivable from future keys after honest deletion / ratchet advance (see threat model). |
| **Post-compromise security** | After ephemeral/local compromise heals, new DH ratchet steps recover confidentiality (best-effort under stated assumptions). |
| **Encrypted attachments** | See [v0-attachments.md](v0-attachments.md); CEKs carried inside ratchet ciphertext. |
| **Replay protection** | Reject duplicated / stale counters per §9. |
| **Out-of-order delivery** | Bounded skipped-key cache §8. |
| **Traffic-shape quantization** | All logical payloads **and** relay envelopes use `PAD()` §6.5. |
| **Relay outer envelope** | Relay parses **only** `route_token`; `opaque_bytes` carries `OuterRecord` §6.1. |

### 1.2 Privacy phases (routing metadata)

| Phase | Sender identity visible to relay? |
|-------|-----------------------------------|
| **v0** | **Yes.** Authenticated clients identify the sender for routing, quotas, and abuse controls. E2E payloads remain inside `opaque_bytes`. |
| **v0.5** | **Goal: no.** Sealed-sender routing — see [v0.5-sealed-sender.md](v0.5-sealed-sender.md). |

### 1.3 Out of scope (v0)

- Groups, voice/video calls, federation, bots, **usernames**, searchable cloud backup of plaintext or keys.  
- **Disappearing-message timers** as enforceable protocol semantics (TTL deletion is a **client/product policy** until optional inner-plaintext fields + server caps are specified—see [privacy-architecture.md](privacy-architecture.md) §12).  
- **Sealed sender** (normative bytes + anonymous credentials): **v0.5** — implement only after core ratchet + invite UX are stable.

---

## 2. Cryptographic suite (single profile)

No algorithm agility in v0.

| Mechanism | Algorithm |
|-----------|-----------|
| **Signing identity** | Ed25519 (`crypto_sign` / equivalent) |
| **DH** | X25519 (`crypto_scalarmult` / Curve25519 ECDH) |
| **KDF** | HKDF-SHA-256 (RFC 5869) |
| **AEAD** | XChaCha20-Poly1305 (IETF, 24-byte nonce, 16-byte tag) |
| **Hash** | SHA-256 |
| **RNG** | OS CSPRNG (`getrandom`, `SecRandomCopyBytes`, etc.) |

**`kdf_suite_id`:** **`1`** — this exact suite column ([v0-state-integrity.md](v0-state-integrity.md) §4 `state_commitment`). Future suites increment id **never** reuse **`1`** with different primitives.

---

## 3. Identity model (**Option B — adopted**)

### 3.1 Account identifier

Each party has an **Ed25519 signing public key** `IK_sig_ed` (32 bytes).

```
account_id = SHA256(IK_sig_ed)         # full 32-byte digest, opaque identifier
```

Implementations **must** use the **full 32-byte** value everywhere (directory keys, logs, invite blobs). **Do not truncate** for “compactness.”

### 3.2 DH identity

Ed25519 keys are **not** directly used for X25519 DH. Each device additionally generates an **X25519 identity keypair** `IK_dh` published in the prekey bundle.

**Rationale:** avoids non-standard Ed25519→X25519 conversions; keeps signatures and DH algebra explicit.

### 3.3 Safety number fingerprint (**normative**)

Parties verify identity material out-of-band (QR). Implementations **must** derive the **same** 32-byte digest:

```
Let IK_A, IK_B be the two peers’ Ed25519 identity public keys (32 B each).
Let SPK_A, SPK_B be each peer’s **signed prekey** X25519 public keys (32 B each)
from the **`PrekeyBundle`** (§4) active at verification time.

IK_lo = min(IK_A, IK_B)    // lexicographic compare on raw 32 bytes
IK_hi = max(IK_A, IK_B)
SPK_lo = min(SPK_A, SPK_B)
SPK_hi = max(SPK_A, SPK_B)

safety_number = SHA256(
    UTF-8 "libgary-v0/safety-number-v1"
 || IK_lo || IK_hi || SPK_lo || SPK_hi
)
```

Display **may** truncate **`safety_number`** for UX (e.g. grouped digits); cryptographic compare **must** use **full 32 bytes**. Fixture: [test-vectors.md](test-vectors.md).

---

## 4. Registration bundle (`PrekeyBundle`)

### 4.1 Wire layout

All multi-byte integers **big-endian**.

```
struct PrekeyBundle {
    u8   bundle_version;          // 0x01 for this document
    u8   identity_sig_pk[32];     // Ed25519 IK_sig_ed (must equal SHA256^-1 witness via possession)
    u8   identity_dh_pk[32];      // X25519 long-term IK_DH public key
    u8   signed_prekey_pk[32];    // X25519 signed prekey (SPK)
    u8   signed_prekey_sig[64];   // Ed25519 signature
    u16  otp_count_be;            // number of one-time prekey public keys (may be 0)
    u8   otp_pk[otp_count][32];   // X25519 OTP public keys
};
```

**Minimum bundle size:** `97 + otp_count*32` bytes.

### 4.2 Signed prekey signature transcript

The responder signs **exactly** these concatenated bytes:

```
SIG_TRANSCRIPT =
      u8(bundle_version)
   || identity_sig_pk[32]
   || identity_dh_pk[32]
   || signed_prekey_pk[32]
```

Verification: `Ed25519_verify(pk=identity_sig_pk, msg=SIG_TRANSCRIPT, sig=signed_prekey_sig)`.

### 4.3 Publication

The server stores `PrekeyBundle` keyed by `account_id` (and optional device id in future revisions). Clients refuse bundles with unknown `bundle_version`.

---

## 5. Handshake transcript (X3DH-shaped)

Roles:

- **Initiator** Alice has Bob’s `PrekeyBundle`.
- **Responder** Bob published the bundle.

Alice generates ephemeral X25519 keypair `EK_A`.

Let:

- `IK_A_DH` = Alice X25519 DH identity secret / public (from Alice bundle).
- `IK_B_DH` = Bob’s published `identity_dh_pk`.
- `SPK_B` = Bob’s `signed_prekey_pk`.
- `OTP_B` = Bob OTP public at index `j` (optional).

### 5.1 DH secrets (each output is 32 raw bytes)

```
DH1 = X25519(IK_A_DH_secret, SPK_B_public)
DH2 = X25519(EK_A_secret,    IK_B_DH_public)
DH3 = X25519(EK_A_secret,    SPK_B_public)
DH4 = X25519(EK_A_secret,    OTP_B_public)   // only if OTP consumed
```

### 5.2 Key material concatenation `KM`

If **one-time prekey** used:

```
KM = DH1 || DH2 || DH3 || DH4      # 128 bytes
```

If **no OTP** (Bob exhausted OTP array and Alice uses `_SPK-only` mode):

```
KM = DH1 || DH2 || DH3            # 96 bytes
```

Implementations **must not** pad DH4 with zeros when OTP absent.

### 5.3 Session secret `OKM` (**transcript-bound**)

After exchanging **`INIT`** and **`INIT_ACK`**, both parties compute transcript digests `TH0`, `TH1` and derive:

```
salt_handshake = SHA256(UTF-8 "libgary-v0-handshake")
IKM_session    = KM || TH0 || TH1
OKM            = HKDF-SHA256(salt=salt_handshake, ikm=IKM_session, info=UTF-8 "libgary-v0/root-key-v1", L=64)
```

Interpretation:

```
root_key       = OKM[0..32]
bootstrap_key  = OKM[32..64]
```

**Normative:** authentication, confirmation MAC, inner AEAD layouts, replay rules, erasure — **[v0-handshake.md](v0-handshake.md)**.

### 5.4 Messaging exchange order

1. Initiator sends **`INIT`** (`type=0x01`) — AEAD integrity over `InitBody` per [v0-handshake.md](v0-handshake.md) §5.  
2. Responder verifies `INIT`, derives `KM`, `TH0`, forms `InitAckCore`, `TH1`, `OKM`, `CONFIRM_MAC`, sends **`INIT_ACK`** (`type=0x02`) — §6 *loc. cit.*  
3. Initiator verifies `INIT_ACK`, confirms MAC, enters **`ACTIVE`** ratchet §8.

---

## 6. Packet framing

### 6.1 Relay outer envelope (mandatory on client ↔ relay wire)

All bytes submitted to the relay for message delivery **must** be wrapped so the relay can route without parsing E2E internals.

```
struct RelayOuterEnvelope {
    u8   relay_version;           // 0x01
    u16  route_token_len_be;      // MUST be ≤ 512 in v0
    u8   route_token[];         // server-visible routing + capability (encoding deployment-specific)
    u32  opaque_len_be;
    u8   opaque_bytes[];        // MUST be an exact serialized OuterRecord (§6.2)
};
```

**Relay behavior (v0):** Parse `route_token` only. Treat `opaque_bytes` as **opaque** (no decryption). Apply §6.5 padding to the **full serialized envelope** so wire length is quantized.

**Mailbox correlation:** If **`route_token`** authenticates fetch/upload to the relay, it **must** embed rotating **`FetchCapV1`** (or derivative ticket) per **[v0-mailbox-fetch.md](v0-mailbox-fetch.md)** §2 — **no** lifetime-static MAC over **`account_id`**.

**Clients:** MUST NOT put message plaintext or CEKs in `route_token`.

### 6.2 Outer record (`opaque_bytes`)

```
struct OuterRecord {
    u32 record_length_be;   // byte length of all following fields in this record
    Header header;
    u8   payload[];         // PAD(logical_payload) per §6.5; AEAD layouts §6.4 + [v0-handshake.md](v0-handshake.md)
};
```

`record_length_be` counts bytes **after** itself (i.e. `sizeof(Header) + len(payload)`).

Maximum `record_length_be` is implementation-defined but **must** be ≤ `1_048_576` (1 MiB) for v0 receivers unless negotiated otherwise.

### 6.3 Header (63 bytes, fixed)

```
struct Header {
    u8   version;           // 0x01 for v0
    u8   type;              // §7
    u8   flags;             // bitfield; v0: reserved 0x00
    u32  epoch_be;
    u8   session_id[16];    // opaque random identifier per pairwise session epoch
    u64  counter_be;
    u8   ratchet_pub[32];   // current sending DH ratchet public key (X25519)
};
```

**AEAD nonce (24 bytes) for DATA payload:** **`NONCE24`** only ([v0-kdf.md](v0-kdf.md) §3).

```
nonce_DATA = NONCE24(
    i_core      = MK,                                  # §8.3 message key for this send
    label_dist  = UTF-8 "DATA"
               || big_endian_u32(epoch)
               || big_endian_u64(counter)
               || session_id[16]
               || ratchet_pub[32]                     # sender DH ratchet public from same Header
)
```

**Associated data (AAD)** for DATA AEAD:

```
AAD = canonical Header bytes (63 bytes, verbatim)
```

### 6.4 DATA AEAD payload

```
payload = XChaCha20-Poly1305_encrypt(
            key = message_key,
            nonce = nonce,
            plaintext = inner_plaintext,
            aad = AAD
          )
```

**Semantic payload** (variable length **≤ 504** bytes for `content` so header + content fits §6.6):

```
semantic_plaintext =
    big_endian_u16(inner_version)    // 0x0001
 || big_endian_u16(content_type)     // 0x0001=text UTF-8, 0x0002=attachment-ref
 || big_endian_u32(content_len)
 || content[content_len]
```

**Fixed inner length:** **`DATA_INNER_LEN = 512`** bytes. Append **`pad`**:

```
pad_len = 512 - len(semantic_plaintext)
pad = HKDF-SHA256(salt=ZERO32, ikm=semantic_plaintext, info=UTF-8 "libgary-v0/data-inner-pad-v1", L=pad_len)
inner_plaintext_pre_bucket = semantic_plaintext || pad          # exactly 512 bytes
inner_plaintext = PAD(inner_plaintext_pre_bucket)               # §6.5 smallest bucket ≥512 (typically 512)
```

If **`len(semantic_plaintext) > 512`**, use an attachment reference instead of oversized inline content.

Attachment references **must** follow [v0-attachments.md](v0-attachments.md).

### 6.5 Universal padding buckets (normative)

Define ascending bucket sizes (bytes):

```
PADDING_BUCKETS = {256, 512, 1024, 2048, 4096, 8192, 16384, 32768}
```

**Rule `PAD(logical_bytes)`:** Let `n = len(logical_bytes)`. Choose the **smallest** `B ∈ PADDING_BUCKETS` such that `n ≤ B`. Append `(B - n)` bytes sampled **uniformly at random** from the OS CSPRNG. Output length is exactly `B`.

If **no** bucket fits, the sender **must** fragment via attachments / multi-record policy (future sub-spec) or shrink content.

**Applies to:**

1. **RelayOuterEnvelope:** serialize fields `relay_version || route_token_len || route_token || opaque_len || opaque_bytes` **without** trailing random padding into `T`; relay wire bytes are `PAD(T)`.  
2. **OuterRecord payload** for **every** `Header.type` (`INIT`, `INIT_ACK`, `DATA`, `REKEY`, `CLOSE`, `RESET_INIT`, `RESET_ACK`): `payload` **must** equal `PAD(logical_payload)` where `logical_payload` is defined per §7. (**`RECEIPT`** excluded — deprecated §7.)  
3. **DATA:** form **`inner_plaintext`** per §6.4 (fixed **512** B semantic+padded core, then `PAD()`).

**Rationale:** uniform quantization across record classes reduces packet-class fingerprinting.

### 6.6 Fixed logical inner plaintext lengths (**v0 freeze**)

Before **`PAD_outer`** on **`OuterRecord.payload`**, type-specific **AEAD plaintext inputs** **must** occupy **exactly** these lengths so ciphertext widths do not fingerprint implementations:

| Record class | Inner plaintext length (bytes, input to XChaCha20-Poly1305) | Notes |
|--------------|------------------------------------------------------------------|-------|
| **`INIT` inner AEAD** | **256** | [v0-handshake.md](v0-handshake.md) §5 |
| **`INIT_ACK` inner AEAD** | **256** | [v0-handshake.md](v0-handshake.md) §6 |
| **`DATA` inner AEAD** | **512** → then §6.5 `PAD()` on that | §6.4 |
| **`REKEY` / `CLOSE` inner AEAD** | **256** | `body ‖ HKDF_pad` — [v0-handshake.md](v0-handshake.md) §7 |
| **`RESET_INIT` / `RESET_ACK` inner AEAD** | **256** | [v0-reset.md](v0-reset.md) |

---

## 7. Message types

Only these **type** byte values are legal for `Header.type`:

| Value | Name | Purpose |
|-------|------|---------|
| `0x01` | `INIT` | Begin handshake; carries initiator DH/ephemeral material + OTP index |
| `0x02` | `INIT_ACK` | Completes handshake |
| `0x03` | `DATA` | Application data |
| `0x04` | **`RECEIPT`** | **Reserved — MUST NOT send in v0.** Delivery inference is **mailbox dequeue + local UX only** ([v0-mailbox-fetch.md](v0-mailbox-fetch.md) §6). Future profiles may redefine **`RECEIPT`**. |
| `0x05` | `REKEY` | Explicit DH ratchet step signal (may be redundant if DATA always rotates—implementation choice; if unused, still reserved) |
| `0x06` | `CLOSE` | Session teardown marker |
| `0x07` | `RESET_INIT` | Catastrophic recovery / session replacement — initiator — **[v0-reset.md](v0-reset.md)** |
| `0x08` | `RESET_ACK` | Catastrophic recovery / session replacement — responder — **[v0-reset.md](v0-reset.md)** |
| `0x09`–`0x1F` | *reserved* | Do not send in v0. |
| `0x20`–`0x2F` | *reserved — multi-device / device-sync (future)* | **v0 is single-device:** normative scope is **one active libgary identity per physical device** as shipped; these opcodes are namespace placeholders so future multi-device sync does not collide with v0. Implementations **must not** emit `0x20`–`0x2F` until specified. |

Unknown `version` or `type` → **`ERR_GENERIC`** on forward-facing APIs where indistinguishability matters (§10.2); internally map to `ERR_BAD_VERSION` / `ERR_BAD_MAC` as appropriate.

### 7.1 AEAD coverage

| `Header.type` | Keying | Specification |
|---------------|--------|---------------|
| `INIT` | `K_init` derived from `KM‖TH0` | [v0-handshake.md](v0-handshake.md) §5 |
| `INIT_ACK` | `K_ack` derived from `OKM` | [v0-handshake.md](v0-handshake.md) §6 |
| `DATA` | Ratchet `MK` §8 | §6.4; nonces [v0-kdf.md](v0-kdf.md) §3 |
| `REKEY` / `CLOSE` | `K_control` derived from `OKM` | [v0-handshake.md](v0-handshake.md) §7 |
| `RESET_INIT` / `RESET_ACK` | Reset AEAD keys (`K_reset_*`) | [v0-reset.md](v0-reset.md) |

`OuterRecord.payload` **always** ends with `PAD_outer(...)` per §6.5 after forming the logical concatenation `… || nonce || AEAD_output` described in **v0-handshake**.

### 7.2 `InitBody` (serialized cleartext prefix inside `INIT` logical bytes)

```
struct InitBody {
    u8  initiator_sig_pk[32];
    u8  initiator_dh_pk[32];
    u8  ephemeral_ek_pub[32];
    u16 otp_index_be;
    u16 reserved_be;        // MUST be 0
};
```

### 7.3 `InitAckWire`

```
struct InitAckWire {
    u8  responder_sig_pk[32];
    u8  responder_dh_pk[32];
    u64 ack_nonce_be;
    u8  confirm_mac[16];    // key confirmation — [v0-handshake.md](v0-handshake.md) §4
};
```

(`InitAckCore` = first 72 bytes; transcript `TH1` hashes **only** those 72 bytes.)

### 7.4 Control structs (`REKEY` / `CLOSE`)

`ReceiptBody` (**below**) is **reserved for post-v0** explicit receipts — **not used** when **`RECEIPT`** sending is forbidden (§7 table).

```
struct ReceiptBody {
    u16 receipt_version_be; // 0x0001 — reserved / future use
    u8  receipt_kind;
    u8  reserved0;
    u64 ref_counter_be;
};

struct RekeyBody {
    u16 rekey_version_be;
    u16 reserved_be;
};

struct CloseBody {
    u16 close_version_be;
    u8  reason_code;
    u8  reserved0;
};
```

Serialization length **must** satisfy `len(body) ≤ 256` bytes before inner HKDF padding ([v0-handshake.md](v0-handshake.md) §7).

---

## 8. Ratchet state (Double Ratchet — normative)

### 8.1 Symbols

| Symbol | Meaning |
|--------|---------|
| `RK` | 32-byte **root key** |
| `CKs`, `CKr` | 32-byte **send / recv chain keys** |
| `MK` | 32-byte **message key** (AEAD key for one DATA record) |
| `DH_out` | 32-byte raw X25519 shared secret |
| **`counter_be`** | **`Header.counter_be`** — monotonic `u64` per outbound **direction** within `(session_id, epoch)` for **all** record types (`DATA`, `REKEY`, …); never decreases (§9). |
| **`m_s`, `m_r`** | Symmetric indices fed to `INFO_MSG(·)`; reset to **`0`** whenever `CKs` / `CKr` is installed fresh (§8.2) or replaced by §8.5. |

HKDF always means **HKDF-SHA-256** (RFC 5869) with `salt`, `ikm`, `info`, length `L`.

Constants:

```
ZERO32 = 32 zero bytes
INFO_CHAIN     = UTF-8 "libgary-v0/libgary-chain"    # expands BOOT → initial CKs / CKr
INFO_ROOT      = UTF-8 "libgary-v0/libgary-root"    # DH ratchet
INFO_MSG(m)    = UTF-8 "libgary-v0/libgary-msg" || big_endian_u64(m)    # m = m_s or m_r — not wire counter_be
```

### 8.2 Handshake to ratchet bootstrap

From handshake §5.3, obtain `OKM` (64 bytes):

```
RK    = OKM[0..32]
BOOT  = OKM[32..64]
TMP   = HKDF(salt=ZERO32, ikm=BOOT, info=INFO_CHAIN, L=64)
```

**Initiator:**

```
CKs = TMP[0..32]
CKr = TMP[32..64]
```

**Responder** (swap):

```
CKs = TMP[32..64]
CKr = TMP[0..32]
```

Each party **must** generate an X25519 **ratchet** keypair `(dh_ratchet_sk, dh_ratchet_pk)` when entering `ACTIVE`. `Header.ratchet_pub` carries the **current** sending-side `dh_ratchet_pk` for outbound DATA.

Initialize **`m_s = m_r = 0`** when installing `CKs`/`CKr` from **`BOOT`**.

### 8.3 Symmetric send step (DATA)

Let **`m_s`** be the current **send-chain index** for `CKs` (persisted — §8.7).

When sending DATA:

```
OKM_step = HKDF(salt=ZERO32, ikm=CKs, info=INFO_MSG(m_s), L=64)
MK       = OKM_step[0..32]
CKs      = OKM_step[32..64]        # overwrite send chain before the next message
```

Assign **`Header.counter_be`** to the **next monotonic wire counter** for this `(session_id, epoch, outbound direction)` (starts at `0` when the session epoch opens; increments by **exactly `1`** per outbound record — DATA or control — §9).

Build **`NONCE24(MK, …)`** using **that same** `Header.counter_be` ([v0-kdf.md](v0-kdf.md) §3).

Encrypt §6.4 using `MK`. Then **`m_s ← m_s + 1`** before persisting state.

### 8.4 Symmetric receive step (DATA)

Define **`STEP_recv(CKr, m_r)`**:

```
OKM   = HKDF(salt=ZERO32, ikm=CKr, info=INFO_MSG(m_r), L=64)
MK    = OKM[0..32]
CKr   = OKM[32..64]
```

After §9 admits inbound **`Header.counter_be = c`**:

1. If skipped-cache §8.6 contains `MK` for `(peer_ratchet_pub, c)`, decrypt with it and delete the entry.

2. Otherwise repeat: compute **`STEP_recv(CKr, m_r)`**, **`m_r ← m_r + 1`**, attempt AEAD decrypt of this record with `MK`.  
   - On success, stop.  
   - On failure, **`MK`** **must** be stored in skipped-cache under the **smallest still-unfilled** admitted wire counter **`c_gap`** in `(last_decrypted_inbound, c)` per §9 ordering for this `(session_id, epoch)` (standard gap-fill behavior).

Implementations **must** bound derivations per record (`MAX_SKIP` §8.6); exhaustion ⇒ `ERR_REPLAY` internally / **`ERR_GENERIC`** outward (§10).

When §8.5 replaces **`CKr`**: **`m_r ← 0`**.

### 8.5 DH ratchet (ordering)

When inbound **DATA** presents `Header.ratchet_pub = P_new` **distinct** from the peer ratchet public currently bound to this session half:

1. Let `dh_out = X25519(dh_ratchet_sk_local, P_new)` where `dh_ratchet_sk_local` is the **local ratchet secret previously advertised** (the one matching the last outbound `ratchet_pub` known to peer).
2. Update root + chains:

```
OKM_dh = HKDF(salt=RK, ikm=dh_out, info=INFO_ROOT, L=96)
RK'    = OKM_dh[0..32]
A      = OKM_dh[32..64]
B      = OKM_dh[64..96]
```

**Initiator-path assignment** after processing peer’s new ratchet:

```
RK   ← RK'
CKs  ← A
CKr  ← B
```

**Responder-path assignment** (swap mixed chains):

```
RK   ← RK'
CKs  ← B
CKr  ← A
```

3. **`m_s ← 0`** and **`m_r ← 0`** — new symmetric chains; wire counters **`counter_be`** stay monotonic (§9).

4. Rotate local ratchet keypair for subsequent sends; publish new `ratchet_pub` on next outbound DATA.

Full multi-message DH alternation — **[test-vectors.md](test-vectors.md)** §integration + §12.

### 8.6 Skipped-message key cache

```
MAX_SKIP = 2000
```

On-disk / in-memory map keyed by **opaque record**:

```
map_key = peer_ratchet_pub[32] || big_endian_u64(counter)
value   = message_key[32]
```

**Hard bound:** total stored skipped entries **≤ MAX_SKIP** per session. Overflow → `ERR_REPLAY` (or `ERR_INVALID_KEY`) **without** decrypting.

### 8.7 Persisted serialization (`RatchetStateBlob`)

**Normative: `blob_version = 2`.**

```
u8  blob_version = 2
u8  role_flag              // 0x00 initiator path, 0x01 responder path (matches §8.5 swap behavior)
u8  RK[32]
u8  CKs[32]
u8  CKr[32]
u8  dh_ratchet_sk[32]
u8  dh_ratchet_pk[32]
u8  peer_ratchet_pub[32]
u64 send_count_be          // next outbound Header.counter_be to assign (§9 monotonicity)
u64 recv_high_water_be     // §9 accepted inbound high_water for this `(session_id, epoch)` half
u64 send_sym_idx_be        // next outbound symmetric index m_s (§8.3)
u64 recv_sym_idx_be        // next recv symmetric index m_r (§8.4)
u32 skipped_count_be
;; repeat skipped_count times:
;;   peer_ratchet_pub_skipped[32] || counter_be || mk[32]
```

**Legacy `blob_version = 1`** omitted `send_sym_idx_be` / `recv_sym_idx_be`. Implementations **must not** emit v1. Readers **must** treat v1 as **non-loadable** unless completing a documented migration that re-derives `(m_s, m_r)` (generally impossible without peer replay) — default **`RESET_*`** / new handshake — see **[v0-state-integrity.md](v0-state-integrity.md)**.

Implementations **must** persist blobs inside integrity-checked storage ([v0-state-integrity.md](v0-state-integrity.md) §3).

---

## 9. Replay window

1. Maintain highest accepted **`Header.counter_be`** per `(session_id, epoch, inbound direction)` as **`recv_high_water_be`** (§8.7).
2. **Reject** exact duplicate counters.
3. **Reject** counters `< high_water - MAX_SKIP` (ancient).
4. Accept counters `> high_water` after stashing intermediates into `skipped_keys` within bounds.
5. **Epoch** increments (§11) reset replay state for new `session_id`.

---

## 10. Error semantics

### 10.1 Detailed codes (internal diagnostics)

Implementations **may** use distinct codes for logging, metrics, and tests:

| Code | Name | Meaning |
|------|------|---------|
| `0x0001` | `ERR_BAD_VERSION` | Unknown wire `version` |
| `0x0002` | `ERR_BAD_MAC` | AEAD verification failure |
| `0x0003` | `ERR_REPLAY` | Counter / duplicate violation |
| `0x0004` | `ERR_UNKNOWN_SESSION` | Unknown `session_id` |
| `0x0005` | `ERR_EXPIRED_CAP` | Download capability token expired (attachments) |
| `0x0006` | `ERR_INVALID_KEY` | Signature / bundle / ratchet key invalid |

### 10.2 Wire-facing indistinguishability (`ERR_GENERIC`)

Many failures (`ERR_BAD_MAC`, unknown session, replay rejection, bad decrypt, malformed inner plaintext after AEAD success, header/session mismatch) **must not** produce distinguishable **network-visible** errors when doing so would aid remote fingerprinting.

**Normative (privacy-facing surfaces):** collapse externally to a single **`ERR_GENERIC`** (reserved **`0xFFFF`**—wire numeric details remain deployment-defined). Preserve detailed codes **internal-only** (structured logs behind ACLs, debug builds).

---

## 11. Recovery & PCS healing

### 11.1 Planned reset / voluntary new epoch

Triggers: explicit user reset, benign rotation policy, `CLOSE` received.

Actions:

1. Increment **epoch** (`epoch_be` in Header).
2. Issue fresh random `session_id` (16 bytes CSPRNG).
3. Fetch fresh `PrekeyBundle` from peer.
4. Run handshake §5 again.

Old chain keys **should** be zeroized.

### 11.2 Catastrophic reset / session replacement

When local state is corrupt, keys are lost, or ratchet state has forked irrecoverably, implementations **must** support **`RESET_INIT` / `RESET_ACK`** — normative transcripts, tombstoning, and replay rules in **[v0-reset.md](v0-reset.md)**. Do **not** silently fork sessions across peers.

### 11.3 Local state integrity & rollback

Protect persisted ratchet blobs and counters against **restore of stale snapshots** — **[v0-state-integrity.md](v0-state-integrity.md)**.

### 11.4 CLOSE

`CLOSE` message transitions to closed state per [state-machine.md](state-machine.md); subsequent sends require new handshake.

---

## 12. Test vectors

Handshake + Double Ratchet KDF steps + AEAD sanity: [test-vectors.md](test-vectors.md), regenerated by `tools/gen_test_vectors.py`.

Implementations **must** match **HKDF outputs** byte-for-byte.

**Integration transcript** (INIT inner AEAD → ACK inner AEAD → DATA → synthetic DH step → DATA → REKEY):

```bash
python3 tools/gen_test_vectors.py --integration
```

The script prints `STEP01…STEP06` hex lines intended for cross-language harnesses.

---

## 13. Threat model reference

See [threat-model.md](threat-model.md).

---

## Document history

| Rev | Note |
|-----|------|
| v0 spec draft | Initial normative skeleton + handshake HKDF + framing |
| v0 ratchet freeze | `libgary-root` / `libgary-chain` / `libgary-msg` HKDF, universal `PAD()`, relay envelope, **full** `account_id` (32 B) |
| v0 handshake companion | Transcript-bound `OKM`, AEAD on INIT/ACK/control, CONFIRM_MAC — [v0-handshake.md](v0-handshake.md) |
| v0 NONCE24 + KDF tree | [v0-kdf.md](v0-kdf.md); DATA AEAD nonces frozen |
| v0 catastrophic recovery | `RESET_*`, tombstone — [v0-reset.md](v0-reset.md); **`ERR_GENERIC`** §10.2 |
| v0 mailbox fetch privacy | Bucketed opaque batches — [v0-mailbox-fetch.md](v0-mailbox-fetch.md) |
| v0 wire vs symmetric indices | §8 `m_s`/`m_r` vs monotonic `counter_be`; blob **v2** — §8.7 |
| v0 reserved types | `0x20`–`0x2F` multi-device placeholder — §7 |
| v0 state integrity | Anti-rollback anchor — [v0-state-integrity.md](v0-state-integrity.md) |
| v0 invite revocation | [v0-invite-revocation.md](v0-invite-revocation.md) |
| **v0 freeze batch** | §3.3 safety number; **`kdf_suite_id`** §2; §6.6 fixed inner lengths (**DATA** 512 B); **`RECEIPT`** forbidden — [v0-mailbox-fetch.md](v0-mailbox-fetch.md) §6; **`FetchCapV1`** mailbox credential — *loc. cit.* §2; anchor preimage **`protocol_version`/`kdf_suite_id`** — [v0-state-integrity.md](v0-state-integrity.md) §4; KDF labels — [label-registry.md](label-registry.md) |
