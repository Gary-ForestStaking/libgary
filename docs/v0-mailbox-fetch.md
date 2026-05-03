# libgary v0 — Mailbox fetch (metadata discipline)

**Normative transport/product behavior.** End-to-end payloads stay opaque; **fetch patterns** still leak **quantity** and **timing** unless bounded.

See also [privacy-architecture.md](privacy-architecture.md).

---

## 1. Goals

| Goal | Requirement |
|------|-------------|
| Hide queue depth | Responses **must not** encode exact pending message count in a distinguishable way. |
| Shape traffic | Batch sizes drawn from **fixed buckets**; pad responses. |
| Single client API | Prefer **`FETCH(FetchCapV1)`** returning **opaque batch** only. |
| **Fetch identity FS** | Relay **must not** authenticate polls with **lifetime-static** secrets — **[§2 `FetchCapV1`](#2-client-request-fetchcapv1)** |

Even with jittered cadence ([§5](v0-mailbox-fetch.md)), a **fixed mailbox credential** lets the relay correlate **“this subscriber polls forever.”** Short-lived, rotating caps bound that linkage.

---

## 2. Client request (`FetchCapV1`)

```
FetchCapV1 {
    u32  fetch_version_be;     // 0x00000001
    u16  batch_bucket_be;      // allowed: 256, 512, 1024, 2048, 4096 (FETCH_RESP upper-bound hint)
    u64  cap_epoch_be;         // issuer rotation epoch — bumps ≥ daily server-side; opaque to client
    u64  expiry_unix_be;       // UNIX seconds — relay MUST reject if now > expiry
    u8   account_id[32];       // SHA256(IK_sig_ed); routing key — see §2.1
    u8   fetch_cap_mac[32];    // HMAC-SHA256 authentication tag — §2.2
}
```

### 2.1 MAC preimage (`fetch_cap_mac`)

```
fetch_cap_mac = HMAC-SHA256(
    key = K_fetch_epoch,      // server-derived secret bound to cap_epoch_be (see §2.3)
    msg = UTF-8 "libgary-v0/fetch-cap-v1"
       || big_endian_u32(fetch_version_be)
       || big_endian_u64(cap_epoch_be)
       || big_endian_u64(expiry_unix_be)
       || account_id[32]
)
```

**`batch_bucket_be`** is **not** MAC-bound — clients may vary bucket per request without reissuing the cap.

Label **`libgary-v0/fetch-cap-v1`** is registry-canonical ([label-registry.md](label-registry.md) §6).

### 2.2 Operational constraints (normative)

| Rule | Requirement |
|------|-------------|
| **TTL** | **`expiry_unix_be − issued_time ≤ 86400`** seconds (**24 h** max validity per issued cap). |
| **Rotation** | Servers **must** bump **`cap_epoch_be`** at least once per **UTC day** (or more often). Clients **must** refresh **`FetchCapV1`** before **`expiry_unix_be`**. |
| **Session tie-in (recommended)** | Issue fresh **`FetchCapV1`** when local **`DeviceStateAnchor.global_epoch_be`** advances ([v0-state-integrity.md](v0-state-integrity.md)) or after **`RESET_*`** completes — limits linkage across cryptographic epochs. |
| **Replay** | Relay **must** reject **`fetch_cap_mac`** replay within TTL using bounded server-side state (deployment-specific). |

### 2.3 Server keying (`K_fetch_epoch`)

Normative shape (deployment **may** use equivalent HKDF):

```
K_fetch_epoch = HKDF-SHA256(
    salt = ZERO32,
    ikm  = server_master_fetch_secret || big_endian_u64(cap_epoch_be),
    info = UTF-8 "libgary-v0/fetch-cap-key-v1",
    L    = 32
)
```

Register **`libgary-v0/fetch-cap-key-v1`** — dedicated **`HKDF info`** for fetch-cap key derivation (**distinct** from §2.1 HMAC message prefix **`libgary-v0/fetch-cap-v1`**).

### 2.4 Relationship to `route_token`

[Relay envelope](v0-protocol.md) **`route_token`** **may** embed **`FetchCapV1`** verbatim or carry a **compact derived ticket** — deployment-defined — but **must** satisfy §2.2 TTL + rotation. **Do not** use a single static bearer MAC over **`account_id`** without **`cap_epoch_be`** / **`expiry_unix_be`**.

### 2.5 Privacy note

**`account_id`** remains visible to the relay for routing — unavoidable for v0 authenticated fetch. **`FetchCapV1`** removes **infinite-lived stable MAC material**: linkage resets when **`cap_epoch`** rotates and **`expiry`** elapses.

---

## 3. Server response

```
FETCH_RESP {
    u32  response_version_be;  // 0x00000001
    u16  payload_bucket_be;    // actual bucket used ∈ same ladder + {8192,…} if needed
    u8   opaque_batch[];       // concatenation of zero or more RelayOuterEnvelope records ([v0-protocol.md](v0-protocol.md) §6.1), each already padded
    u8   response_pad[];       // random padding so len(opaque_batch‖response_pad) hits payload_bucket
}
```

**Rules:**

1. **Never** return distinguishable **empty** vs **non-empty** frames at fixed sizes — smallest bucket **still contains PRNG padding** when queue empty (client decrypts zero inner records).  
2. **Never** return scalar **`msg_count`** outside AEAD-protected client-only channels.  
3. **Long-poll / QUIC push**: wake-only ([privacy-architecture.md](privacy-architecture.md)); fetch afterward uses same **`FETCH_RESP`** shaping.  
4. **`batch_bucket`** is a **maximum**; server may return smaller logical batch but **must** fill to declared **`payload_bucket`** with padding.

---

## 4. Privacy notes

- Constant-ish sizes defeat naive **“0 vs 1 vs N messages”** observers on TLS payload length.  
- Global traffic analysts still see **timing**; mitigation = §5 constants ([privacy-architecture.md](privacy-architecture.md) §6).  
- This doc does **not** mandate Tor; optional ingress hops remain product-tiered.

---

## 5. Normative fetch cadence — **fixed constants (v0)**

Implementations **must** implement **exactly** these rules so distinct clients do not fingerprint each other:

| Constant | Value | Meaning |
|----------|-------|---------|
| **`T_base`** | **45** seconds | Mean automatic polling period (between successful **`FETCH`** completions). |
| **`JITTER_FRAC`** | **0.20** | Symmetric ±20% multiplier spread on each reschedule. |
| **`p_cover`** | **0.35** | Bernoulli probability of scheduling **one extra** shaped **`FETCH`** after a completed automatic fetch ([§3](v0-mailbox-fetch.md)). |
| **`cover_delay_min`** | **5** s | Lower bound uniform delay before optional cover fetch fires. |
| **`cover_delay_max`** | **25** s | Upper bound uniform delay before optional cover fetch fires. |
| **`T_longpoll_hold`** | **20** seconds | Server **must** hold long-poll response body up to this bound when long-poll is enabled. |
| **`RTT_budget`** | **5** seconds | Client long-poll socket timeout **`≥ T_longpoll_hold + RTT_budget`**. |
| **`N_burst_cap`** | **4** | Maximum timer-driven **`FETCH`** completions (§5.1 **and** §5.2 cover branch) per rolling **60** minute window **per device**. **Does not** count explicit user pull-to-refresh. |
| **`t_quiet`** | **2** seconds | After network link transitions **up**, suppress first automatic fetch until **`t_quiet`** elapsed (collapse reconnect storms). |

### 5.1 Timer reschedule

After each automatic **`FETCH`** completes, compute next fire:

```
u ← uniform random in [-JITTER_FRAC, +JITTER_FRAC]      // inclusive endpoints
T_next ← T_base × (1 + u)
```

Schedule the next automatic **`FETCH`** after **`T_next`** seconds ( wall-clock monotonic timer).

### 5.2 Cover fetch

Immediately after an automatic **`FETCH`** completes (not user refresh): with probability **`p_cover`**, schedule **one** additional **`FETCH`** after delay **`uniform[cover_delay_min, cover_delay_max]`** seconds, same **`FETCH_RESP`** shaping §3.

### 5.3 Long-poll

If transport supports long-poll: server **`hold_seconds = T_longpoll_hold`** (**20**); client **`timeout ≥ T_longpoll_hold + RTT_budget`** (**25** s minimum).

### 5.4 Burst cap

Maintain a sliding window of **60** minutes. If completing this **`FETCH`** would exceed **`N_burst_cap`** automatic completions in the window, **delay** until the oldest counted completion exits the window — **unless** user explicitly triggered refresh (uncounted).

**Push-assisted wake:** still **must** eventually perform shaped **`FETCH`** ([privacy-architecture.md](privacy-architecture.md)); push alone **must not** encode queue depth.

---

## 6. Delivery inference — **no `RECEIPT` packets (v0)**

Wire type **`RECEIPT`** (`0x04`) **must not** be sent in v0 ([v0-protocol.md](v0-protocol.md) §7).

**Normative v0 stance:** delivery / read guarantees are **not** signaled by per-message E2E **`RECEIPT`** records (they leak timing + online metadata).

Instead:

1. **Implicit confirmation:** when the recipient performs a shaped **`FETCH`** whose **`opaque_batch`** causes the relay to **dequeue / ACK-at-edge** server-side delivery records per relay policy, the sender **may** infer “likely delivered” **only** as product UX — not as cryptographic receipt.  
2. **Local UX:** show **“sent” / “likely delivered”** based on local send commit + optional server-side **opaque** delivery cursor returned inside **`FETCH_RESP`** **AEAD** (deployment-defined — **must not** expose per-message timing off-device).

Cryptographic read receipts require a **future** profile (batched opaque windows or voluntary explicit receipts outside v0 defaults).

---

## Document history

| Rev | Note |
|-----|------|
| v0 | Bucketed FETCH_RESP, forbid naked queue counts |
| v0 cadence freeze | §5 numeric constants |
| v0 receipts | §6 implicit delivery model |
| v0 fetch-cap | **`FetchCapV1`** rotating credential §2; relay **`route_token`** cross-ref [v0-protocol.md](v0-protocol.md) §6.1 |
