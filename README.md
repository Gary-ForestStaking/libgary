# libgary — private 1:1 messenger (v0 protocol)

End-to-end encrypted messenger with Signal-like security, built from standard primitives (not libsignal). **v1 is intentionally narrow**; protocol work is named internally **v0 protocol**.

**Normative specs:** [docs/v0-protocol.md](docs/v0-protocol.md) (framing + ratchet) and [docs/v0-handshake.md](docs/v0-handshake.md) (transcripts + handshake/control AEAD) — index: [docs/README.md](docs/README.md).

**License:** [Apache License 2.0](LICENSE).

## Non-goals (for first shipping version)

Do **not** start with: groups, voice/video calls, public usernames, bots, channels, or federation. Add those only after the 1:1 core is specified, implemented, and reviewed.

## Engineering principles

- **Do not invent cryptography.** Only compose known primitives and documented constructions.
- **Protocol spec first, code second.** Document handshake, packet format, ratchet state, replay handling, and recovery like an RFC (including test vectors / hex fixtures per message type).
- **Production wire format:** canonical **binary framing** (version, type, length-prefixed fields, explicit endianness and maximum lengths). Avoid ad hoc JSON on the wire.
- Your differentiation is **protocol UX**, **metadata posture**, and **product**—not new cipher math.

## Privacy posture (“extreme privacy” defaults)

Optimize for **privacy over convenience**: **[full 32-byte `account_id`](docs/v0-protocol.md)** (SHA-256 of Ed25519 pk), **invite / QR-only** discovery ([docs/v0-invite-uri.md](docs/v0-invite-uri.md)), **wake-only** push, **minimal server logs**, **[relay outer envelope](docs/v0-protocol.md)** (`route_token` only—opaque E2E inside), **universal `PAD()` buckets** §6.5, **sealed sender** deferred to **[v0.5](docs/v0.5-sealed-sender.md)**, **safety numbers before transparency logs**, **invite-only** growth, **backup off by default** — see [docs/privacy-architecture.md](docs/privacy-architecture.md).

### Normative sequence (stop spec drift)

1. Handshake transcripts + confirmation + control AEAD — **[docs/v0-handshake.md](docs/v0-handshake.md)** + **[docs/test-vectors.md](docs/test-vectors.md)**  
2. **`NONCE24` + KDF tree + label registry** — **[docs/v0-kdf.md](docs/v0-kdf.md)**, **[docs/label-registry.md](docs/label-registry.md)**  
3. Double Ratchet §8 — **[docs/v0-protocol.md](docs/v0-protocol.md)**  
4. Catastrophic recovery — **[docs/v0-reset.md](docs/v0-reset.md)**  
5. Mailbox fetch privacy — **[docs/v0-mailbox-fetch.md](docs/v0-mailbox-fetch.md)**  
6. Padding — **§6.5** (all types + relay envelope)  
7. **`ERR_GENERIC`** wire posture — **[docs/v0-protocol.md](docs/v0-protocol.md)** §10  
8. Local anti-rollback — **[docs/v0-state-integrity.md](docs/v0-state-integrity.md)**  
9. Invite revocation (`invite_id`) — **[docs/v0-invite-revocation.md](docs/v0-invite-revocation.md)**  
10. Integration transcript — `python3 tools/gen_test_vectors.py --integration`  
11. Invite blob — **[docs/v0-invite-uri.md](docs/v0-invite-uri.md)**  
12. Sealed sender mini-spec — **[docs/v0.5-sealed-sender.md](docs/v0.5-sealed-sender.md)** (after core stable)

## Protocol stack (v0)

### 1. Identity

- Long-term **Ed25519** identity keypair.
- Stored via **Apple Keychain** / Secure Enclave–friendly APIs on Apple platforms.
- **Public identity** published to your server (directory).

### 2. Prekeys (async messaging)

- **Signed prekey** (medium-term, rotates periodically).
- **One-time prekeys** (typical upload bucket: **100–500**; replenish on connect).

Together this defines **how encrypted sessions start when the peer is offline**.

### 3. Handshake

- Use **X25519** with **multiple DH exchanges** (X3DH-shaped construction).
- Derive shared secret via a **hash-based KDF** (e.g. HKDF-SHA-256, or a libsodium-consistent choice)—specified **byte-for-byte** (inputs, labels, lengths).
- **Bind identities** in the transcript (both peers’ identity keys and relevant prekey material) so the server cannot silently reroute sessions.
- **Authenticate** critical handshake material with **Ed25519** (exact signing scope belongs in the spec).

### 4. Ratchet (core session)

Implement the standard Double Ratchet structure:

- Root key  
- Send / receive chains  
- Skipped-message key cache (**bounded**; eviction + DoS limits are mandatory)  
- DH ratchet on rotation rules you define explicitly  

Document **when** ratchet steps occur and how **post-compromise** behavior works.

### 5. Encrypt payloads

- **XChaCha20-Poly1305** for message payloads.
- Define **nonce construction** and **associated data** so headers are cryptographically bound to ciphertext (**no nonce reuse**).

### 6. Replay handling

Specify in the spec:

- Monotonic counters / chain identifiers per direction  
- Duplicate and out-of-order policy within an accepted window  
- Behavior on large jumps / reset  

### 7. Recovery

Document:

- Local state loss vs compromise  
- Session reset vs continuation  
- Multi-device is **out of scope** until v1 is stable unless you add an explicit later phase  

### 8. Attachments (v0 attachment cryptosystem)

Forward secrecy for files requires a **random file key**, **HKDF-derived** chunk keys/nonces, an **authenticated manifest**, optional **Merkle** chunk integrity, **short-lived download tokens**, **no plaintext transcoding or thumbnails** on the relay, **random blob IDs** (no plaintext-hash dedup), and a strict **local cache / backup** story.

Normative detail: **[docs/v0-attachments.md](docs/v0-attachments.md)**.

## Binary framing (outline)

Define a single canonical record layout, for example:

1. Magic / protocol identifier (fixed bytes)  
2. **Version** (e.g. `1` for v0 wire)  
3. **Message type** (handshake, application data, control, …)  
4. Fixed or length-prefixed identifiers (**max lengths** everywhere)  
5. Inner payload: **only** `length || bytes` for variable fields  
6. Declare integer endianness (e.g. **little-endian**) for all multi-byte values  

Include **max sizes** per field for anti-DoS and **test vectors** per type.

## Server role (trusted delivery only)

The server handles:

- Public key / prekey directory  
- Relay of **opaque encrypted blobs**  
- **APNs** (or equivalent) for wakeup  
- Attachment relay (opaque ciphertext + metadata policy you define)  

The server **must not** be able to decrypt message contents.

## Tech stack (directional)

**Client**

- Swift  
- SQLite / **SQLCipher** for local encrypted storage  
- **libsodium** via a Swift wrapper  

**Backend**

- Rust **or** Go  
- PostgreSQL  
- Redis queue  
- **QUIC** transport (TLS identity and traffic/metadata analysis are separate concerns—document padding/timing goals if you care.)  

## Future (explicitly not v1)

- **Disappearing messages** (per-chat TTL, local secure deletion, optional server queue caps)—product + retention policy; optional wire hints later; see [docs/privacy-architecture.md](docs/privacy-architecture.md) §12.  
- **Group chat** may later use **MLS (RFC 9420)** with a Rust core (e.g. OpenMLS) and Swift via FFI; separate from this 1:1 v0 track.  
- **XMPP / Prosody** modules (SASL2, MUC push helpers, etc.) apply only if you ship an XMPP-based product; they are **not** implied by the custom QUIC + blob relay design above.

## Next steps

1. Review **[docs/v0-protocol.md](docs/v0-protocol.md)** (normative) and **[docs/test-vectors.md](docs/test-vectors.md)**.  
2. Add **Double Ratchet step vectors** (v0.1) to `tools/gen_test_vectors.py` and validate Swift + Rust/Go against them.  
3. Implement clients/server strictly against the spec.
