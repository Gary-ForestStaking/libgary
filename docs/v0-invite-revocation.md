# libgary v0 — Invite revocation

**Normative relay-visible revocation** for **[v0-invite-uri.md](v0-invite-uri.md)** blobs.

QR invites default **reusable + TTL** (e.g. 30 days). If an invite URI leaks, **TTL alone is insufficient** — peers must **stop honoring** the invite **before** expiry.

---

## 1. `invite_id`

Every **`InviteBlobV1`** **must** carry an opaque **`invite_id[16]`** (CSPRNG at creation).

**Wire change:** extend **`InviteBlobV1`** (next **`blob_version_be`**, e.g. `0x0002`) with:

```
u8 invite_id[16];       // NEW — MUST be present in signed prefix for blob_version ≥ 0x0002
```

(`v1` blobs without `invite_id` remain verifiable but **cannot** be revoked individually — only SPK rotation / global invite-disable.)

---

## 2. Revocation record (`InviteRevokeV1`)

Published by relay directory **or** pinned alongside **`account_id`**:

```
struct InviteRevokeV1 {
    u16   revoke_version_be;       // 0x0001
    u8    issuer_identity_pk[32]; // Ed25519 — MUST equal invite issuer identity key
    u8    invite_id[16];          // matches blob field
    u64   revoked_unix_be;       // wall-clock server/client convergence anchor (≤ now at acceptance)
    u64   min_expiry_override_be;// OPTIONAL — force treats invite expired before original TTL (0 = unused)
    u64   reserved_be;           // 0
};
sig = Ed25519_sign(sk_identity, serialize(InviteRevokeV1_fields_without_sig))
wire = serialize(...) || sig[64]
```

### 2.1 Verification order

Before trusting **`InviteBlobV1`**:

1. Verify blob signature + **`expiry_unix`** ([v0-invite-uri.md](v0-invite-uri.md)).  
2. Fetch **`InviteRevokeV1`** candidates for **`issuer_identity_pk`** (relay API deployment-defined).  
3. For matching **`invite_id`**, verify **`sig`**; if **`revoked_unix_be ≤ now`**, **reject** invite — detailed reason **internal-only** / **`ERR_GENERIC`** outward ([v0-protocol.md](v0-protocol.md) §10).  
4. If **`min_expiry_override_be > 0`**, treat **`effective_expiry = min(blob.expiry, override)`**.

---

## 3. Relay API (informative shape)

```
POST /v1/invites/revoke         body: InviteRevokeV1 wire (authenticated session)
GET  /v1/invites/revocations?account_id=…   → stream of active revocations (bounded TTL cache)
```

Exact REST framing **non-normative** — semantic **must**: issuer-authenticated publication + replica propagation SLA.

---

## Document history

| Rev | Note |
|-----|------|
| v0 | `InviteRevokeV1`, `invite_id`, expiry override |
