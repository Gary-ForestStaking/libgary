# v0 — Attachment cryptosystem

Attachments share forward secrecy with chat **only if** file ciphertext stays opaque on the relay and **secrets live inside ratchet-protected messages**. This document refines the attachment layer for **libgary / v0 protocol**: key hierarchy, manifests, integrity, relay policy, and device-side pitfalls.

Scope: normative goals for attachment cryptography; **multi-byte integers follow [v0-protocol.md](v0-protocol.md)** (network byte order). Outer records use the same framing discipline as chat packets unless noted.

### Transport boundary (normative)

**Content encryption keys (`CEK`), manifest bytes, derived attachment metadata, or anything that makes ciphertext decryptable — MUST appear only inside an inner **`DATA`** plaintext that is itself protected by ratchet **`MK`** + **`NONCE24`** + Header-bound AEAD ([v0-protocol.md](v0-protocol.md) §6.4, [v0-kdf.md](v0-kdf.md) §3).**

Implementations **must not** place CEKs or manifests in:

- **`INIT` / `INIT_ACK` / control** payloads (except future specs explicitly allowing — none in v0)  
- Push notification cleartext / server-rendered payload fields  
- **`RelayOuterEnvelope.route_token`** or other relay-visible metadata  
- Mailbox **`FETCH`** capability tokens or bucket framing ([v0-mailbox-fetch.md](v0-mailbox-fetch.md))  
- Analytics / crash logs / debug hooks in production builds  

Violation ⇒ invite-only FS boundary collapses.

---

## 1. Separate CEK from chunk material

Do **not** encrypt every chunk with the raw file key.

**Preferred hierarchy**

```text
master_file_key (32 random bytes)
       │ HKDF (explicit salt + info labels per subkey)
       ├── enc_key          — chunk AEAD keying material
       ├── nonce_base       — input to per-chunk nonce (see below)
       └── manifest_key     — optional: authenticate encrypt manifest fields
```

**Per-chunk nonces** (pick one approach and specify sizes so nonces are unique and total length matches your AEAD, e.g. 24 bytes for XChaCha20-Poly1305):

- `nonce_i = nonce_base ‖ LE64(i)` (if lengths line up), or  
- `chunk_key_i = HKDF(enc_key, chunk_index ‖ domain_label)` with independent nonces per chunk.

**Benefits:** domain separation, safer upgrades (new `enc_scheme` version), less accidental nonce/key reuse.

---

## 2. Manifest as authenticated cryptographic material

Treat attachment metadata as **security-critical**, not UX fluff.

**Logical manifest** (serialize to bytes in fixed field order for signing/AEAD):

| Field (conceptual) | Role |
|-------------------|------|
| `version` | Manifest / attachment format version |
| `file_id` | Opaque blob identifier (random; see §8) |
| `mime` | Type hint for client only |
| `total_size` | Total plaintext length |
| `chunk_size` | Bytes per chunk |
| `chunk_count` | Number of chunks |
| `sha256_root` | Merkle root over chunk hashes (§3) |
| `enc_scheme` | AEAD + KDF profile identifier |

**Bindings**

- Serialize manifest (canonical encoding).
- Either: **sign** manifest with `manifest_key` / Ed25519 attachment key, **or** include manifest in **AEAD AAD** for the outer blob that carries keys—**and** bind manifest into ratchet payload AAD where applicable.

**Prevents:** swap/truncation/type-confusion between blobs and messages.

---

## 3. Merkle root for chunk verification

For large files:

- Compute **per-chunk hash** over ciphertext or plaintext (pick one; document it—usually ciphertext hashes align with “what the relay stored”).
- Build a **Merkle tree**; `sha256_root` in manifest.

**Recipient:** verify chunks independently → **resumable downloads**, corruption detection, **relay tamper** detection.

---

## 4. Download authorization

Avoid **permanent** blob URLs.

Issue **short-lived capability tokens**:

```text
blob_id ‖ expiry ‖ … 
    → MAC or signature (server-side secret or asymmetric key held only by relay auth layer)
```

Relay checks token + expiry before serving bytes. CDN caches must respect TTL or use auth at edge consistent with your threat model.

**Avoids:** leaked URLs that work forever; accidental long-lived cache disclosure.

---

## 5. Thumbnails

Plaintext previews on the server are a **common privacy leak**.

- Generate **encrypted thumbnail** with **`CEK_thumbnail`** (separate random key), upload ciphertext only; deliver key inside ratchet message **or** derive from `master_file_key` only if spec explicitly ties thumbnail FS to file FS, **or**  
- **No server-side preview** at all.

---

## 6. Media transcoding

Server **must not** operate on plaintext:

- No resize, re-encode, optimize, compress, or malware scan on decrypted content.

Relay handles **opaque ciphertext** only. Otherwise the encryption boundary and trust model collapse.

---

## 7. Local cache policy

Forward secrecy is often broken **off-protocol**:

- **Encrypted** cache at rest  
- **TTL** and eviction  
- **Secure deletion** (overwrite/delete APIs appropriate to OS)  
- Sensitive paths in **OS-protected storage** where possible  

Watch **iCloud/Desktop backups**, **crash dumps**, **temp files**, and **memory dumps**—document what you guarantee vs what users must configure.

---

## 8. Deduplication

Do **not** content-address blobs by **plaintext** hash (e.g. “bad: SHA256(file plaintext)”): identical files become linkable across users/conversations.

Use **random `blob_id`** (and optionally per-upload ciphertext salting) unless you accept intentional dedup with clear privacy tradeoffs.

---

## 9. Attachment reference (inside ratchet ciphertext)

The **chat message** body (ratchet-protected) should carry something logically equivalent to:

- `blob_id`  
- CEK material (or wrapped CEK—§10)  
- `manifest_hash` (commitment to manifest bytes)  
- `auth_token` + `expiry` (download capability)  

All of this lives **inside** the end-to-end encrypted payload—not in cleartext headers visible to the relay (beyond minimal routing).

**Wire format:** binary record, not JSON.

---

## 10. Optional stronger FS for CEK

Additional layer (optional in v0):

```text
wrapped_cek = AEAD(message_key_slice, nonce, CEK, AAD=manifest_hash ‖ …)
```

After decrypting the attachment in memory, **zeroize** CEK and consider deleting / not retaining `message_key` longer than required by your ratchet policy—so local compromise must recover **both** ratchet state **and** wrapped blobs to unlock old files.

---

## Big picture

You are specifying four coupled systems:

1. **Message protocol** (ratchet + framing + replay)  
2. **Key lifecycle** (derivation, deletion, backups)  
3. **Attachment cryptosystem** (this document)  
4. **Metadata minimization + device security model**

Together that **is** your secure messaging stack—not “chat crypto plus files.”
