# libgary documentation

Normative and supporting documents for **v0 protocol** (private 1:1 messenger).

| Document | Purpose |
|----------|---------|
| [privacy-architecture.md](privacy-architecture.md) | Extreme-privacy product choices (identity, discovery, relay, push, logs, transparency). |
| [v0-invite-uri.md](v0-invite-uri.md) | `gary://invite/v1/…` self-contained bootstrap blob. |
| [v0.5-sealed-sender.md](v0.5-sealed-sender.md) | Placeholder for relay-blind sender (**v0.5**). |
| [threat-model.md](threat-model.md) | What v0 does and does **not** protect. |
| [v0-protocol.md](v0-protocol.md) | **Normative** wire format, crypto suite, framing, ratchet, replay, errors, recovery. |
| [v0-handshake.md](v0-handshake.md) | Transcript hashes, `OKM`, key confirmation, AEAD on handshake/control, replay + erasure. |
| [v0-kdf.md](v0-kdf.md) | **`NONCE24`** + normative `OKM` / ratchet derivation tree. |
| [label-registry.md](label-registry.md) | **Canonical HKDF / HMAC / SHA prefixes** (`libgary-v0/…`) — collision-free freeze table. |
| [v0-reset.md](v0-reset.md) | Catastrophic recovery: `RESET_INIT` / `RESET_ACK`, tombstone prior session. |
| [v0-mailbox-fetch.md](v0-mailbox-fetch.md) | Bucketed opaque mailbox fetch (metadata posture). |
| [v0-state-integrity.md](v0-state-integrity.md) | Anti-rollback anchor, monotonic persistence, `state_commitment`. |
| [v0-invite-revocation.md](v0-invite-revocation.md) | Signed **`InviteRevokeV1`** + **`invite_id`** lifecycle. |
| [v0-attachments.md](v0-attachments.md) | Attachment key hierarchy, manifest, relay rules (references packet framing in v0-protocol). |
| [test-vectors.md](test-vectors.md) | Hex fixtures; implementations **must** match. |
| [state-machine.md](state-machine.md) | Session lifecycle and valid transitions. |

**Rules:**

- README prose vs **v0-protocol.md** → protocol wins.  
- Handshake transcript / control-plane AEAD vs **v0-protocol.md** → **[v0-handshake.md](v0-handshake.md)** wins.

Regenerate cryptographic fixtures:

```bash
pip3 install cryptography pynacl
python3 tools/gen_test_vectors.py
```
