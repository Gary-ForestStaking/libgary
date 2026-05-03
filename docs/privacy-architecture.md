# libgary — extreme privacy architecture

libgary optimizes for **privacy first**, including UX that is deliberately harder (no global discovery, no phone-book onboarding).

This document is **product / infrastructure architecture**. Wire-level rules that affect parsers live in [v0-protocol.md](v0-protocol.md) (e.g. padded plaintext buckets).

Philosophical aim: **Signal-grade cryptography** with **SimpleX-style metadata minimization**—few long-lived identifiers visible to infrastructure.

---

## 1. Identity: public-key identity only

### Use

- Long-term **Ed25519** identity keypair per device/persona (signing).
- **DH identity** is separate **X25519** material published in the prekey bundle ([v0-protocol.md](v0-protocol.md) §3–§4).

### Account id

```
account_id = SHA256(identity_ed25519_pubkey)   # full 32-byte digest everywhere
```

Normative: **[v0-protocol.md](v0-protocol.md) §3.1** — **no truncation.**

Safety-number fingerprint (QR verification): exact **`SHA256`** formula **[v0-protocol.md](v0-protocol.md) §3.3** — implementations **must** match byte-for-byte.

### Explicitly excluded (v1)

- Phone numbers  
- Email registration  
- Global username registry  
- Contact upload / “sync address book”  

### Tradeoffs

| Pros | Cons |
|------|------|
| Minimal PII | Harder “find my friends” |
| No SIM-swap against libgary identity | Users must verify keys out-of-band |
| No searchable global directory | Discovery is intentional |

---

## 2. Contact discovery: invite tokens / QR only

No global user lookup.

Preferred patterns:

- **`gary://invite/v1/<base64url(blob)>`** — see [v0-invite-uri.md](v0-invite-uri.md).
- **In-person QR** exchange of **identity key + prekey bundle fragment** (or signed capability).

Properties:

- Discovery is **consensual** and **pairwise**.
- Server learns **only what routing requires** when messages flow—not “who searched whom.”

---

## 3. Server knowledge: minimize aggressively

### Server **may** hold

- **Opaque `account_id`**
- **Public device bundle** (PrekeyBundle bytes)
- **Queued ciphertext blobs** (opaque)
- **Push wakeup handles** (ideally **provider-isolated** from message routing DB)

### Server **must not** require (for extreme privacy deployment)

- Address books  
- Social graph / “contacts of contacts”  
- Plaintext message bodies or attachment CEKs  
- Long-lived “who messaged whom” analytic graphs  

Operational stance: **blind relay**—routing on mailbox identifiers and cryptographic caps, not PII.

---

## 4. Sealed sender — **v0.5** (not v0)

| Milestone | Relay sees sender? |
|-----------|-------------------|
| **v0** | **Yes** (authenticated mailbox routing). |
| **v0.5** | **Goal: no.** Mini-protocol: [v0.5-sealed-sender.md](v0.5-sealed-sender.md). |

Implement core ratchet + invites **before** sealed sender.

---

## 5. Relay outer envelope + padding (v0)

Even **before** sealed sender, the relay parses **only** `route_token`; `opaque_bytes` carries the E2E `OuterRecord` ([v0-protocol.md](v0-protocol.md) §6.1).

**All** logical payloads—including **INIT**, **INIT_ACK**, control types—and the serialized relay envelope use **`PAD()`** to shared buckets ([v0-protocol.md](v0-protocol.md) §6.5).

---

## 6. Timing obfuscation (optional deployment modes)

If feasible for a deployment tier:

- Random **send jitter**  
- **Batch** uploads/downloads  
- Optional **cover traffic** (dummy ciphertext uploads at low rate)  

Tradeoffs: **battery**, **bandwidth**, **latency**.

Not mandatory for all installs—may be a “Paranoia mode.”

---

## 7. Attachments

The attachment cryptosystem in [v0-attachments.md](v0-attachments.md) already aligns with extreme privacy:

- Random CEKs  
- Authenticated manifest  
- Encrypted thumbnail **or none**  
- Random opaque blob IDs  
- Short-lived download capabilities  

---

## 8. Push notifications (APNs): wake-only

APNs metadata is a known leak.

**Design target:**

```json
{ "wake": 1 }
```

**Forbidden** in push payload for extreme privacy profile:

- Sender identity or handles  
- Message preview  
- Conversation IDs usable without fetching  
- Any cryptographic secrets  

Flow: push wakes client → client pulls **encrypted queue** over authenticated channel.

---

## 9. IP privacy

Standard messaging leaks IP to the relay.

**Stronger options** (product tiers):

- Separate **ingress** relay vs **mailbox** service  
- Optional **multi-hop**  
- Tor-style ingress or trusted VPN integration  

Tradeoff: **latency** and operational complexity.

---

## 10. Metadata retention & logs

**Delete aggressively.**

Reasonable extreme-privacy defaults:

- Keep **queued ciphertext** only as long as delivery requires  
- Keep **minimal abuse counters** (rate limits), not contents  

Avoid retaining:

- IP logs tied to message IDs  
- Fine-grained access logs usable for traffic analysis  
- Long-lived delivery history  

Targets: **hours**, not **months**, for correlatable metadata—exact numbers are deployment policy, but philosophy is “data not collected cannot leak.”

---

## 11. Forward secrecy & PCS

Mandatory properties of the session protocol—see [v0-protocol.md](v0-protocol.md) and [threat-model.md](threat-model.md).

---

## 12. Local security

Client obligations:

- **Encrypted local DB** (e.g. SQLCipher)  
- **Hardware-backed** storage for long-term keys where OS supports it  
- **Secure wipe** of decrypted attachment cache + CEKs  

### Backup policy (**locked default**)

- **Default:** **no** OS/cloud backup of keys or plaintext-capable state—**device loss ⇒ cryptographic account loss** unless the user explicitly opts into recovery.  
- **Optional:** **client-side encrypted export**; user retains recovery secret offline.

### Disappearing messages (planned)

You intend to ship **TTL-based disappearing messages** later. That is primarily a **client retention + UX policy**, not a substitute for E2E—but it reduces forensic residue on devices and backups.

**Design intent (to specify before implementation):**

| Topic | Direction |
|-------|-----------|
| **Scope** | Per-conversation timer (e.g. off / 5 minutes / 24 hours / 7 days); sender default vs mutual agreement is a product choice. |
| **Local deletion** | After deadline: delete message row, plaintext, derived keys in cache, decrypted attachment bytes, and thumbnails; zeroize CEKs where applicable. |
| **Server** | Optional **max queue lifetime** for ciphertext (delivery window)—helps purge relay copies; does **not** force deletion on the recipient’s phone. |
| **Honesty** | Recipients can still **screenshot**, **export**, or **delay offline**; disappearing messages reduce casual retention, not malicious archiving. |
| **Wire protocol** | Optional future `content_expires_at` / timer flag inside **AEAD plaintext** so both clients agree on semantics; normative bytes **not** in v0 yet. |
| **Sync** | Multi-device: define whether timers start at send, delivery, or read—each choice has different privacy/metadata tradeoffs. |

Coordinate disappearing timers with **backup policy** (icloud/desktop backups defeat the feature unless keys/plaintext never enter backup scope).

---

## 13. Key assurance (**locked order**)

Without transparency or explicit verification, a malicious relay can **swap keys**.

**Phase 1 (ship first):** **Safety numbers** + **QR fingerprint verify** between peers (offline, no extra infra).

**Phase 2:** **Append-only transparency log** for published device bundles.

---

## 14. Abuse model (without plaintext surveillance)

**Locked bootstrap:** **invite-only** network growth initially—each invite may carry **limited join credits** / capability semantics (no phone/email/KYC verification pipeline).

Hardest tension in minimal-metadata designs.

Non-surveillance options (combine with invites):

- Strict **rate limiting** / quotas  
- Referral / invite caps  
- Lightweight **proof-of-work** at signup or send  
- User-managed **blocklists**  

Explicit non-goal: server-side **content moderation** of plaintext—there is no plaintext.

---

## End-state summary (“libgary extreme privacy stack”)

| Layer | Choice |
|-------|--------|
| Identity | Public-key — **`account_id = SHA256(Ed25519 pk)`** (32 bytes); **no** phone/username registry |
| Discovery | **`gary://invite/v1/…`** ([v0-invite-uri.md](v0-invite-uri.md)); QR first |
| Relay | **v0:** outer envelope — relay parses `route_token` only; **v0.5:** sealed sender ([v0.5-sealed-sender.md](v0.5-sealed-sender.md)) |
| Transport | QUIC + TLS |
| E2E | X3DH-shaped handshake + Double Ratchet ([v0-protocol.md](v0-protocol.md)) |
| Payload | **Padded** binary packets |
| Attachments | CEK + manifest + opaque blobs ([v0-attachments.md](v0-attachments.md)) |
| Push | **Wake-only** |
| Server | Blind relay; minimal durable metadata |
| Logs | Near-zero correlatable retention |
| Accountability | **Safety numbers first**; transparency log later |
| Backup | **Default off**; optional encrypted export |
| Growth | **Invite-only** bootstrap + credits |

This stack is closer to **Signal cryptography + SimpleX-style infrastructure discipline** than to traditional centralized social apps.
