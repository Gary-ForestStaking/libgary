# v0 — Invite URI & bootstrap blob

Self-contained contact bootstrap **without** a public user directory.

## URI shape

```
gary://invite/v1/<base64url_no_padding(blob)>
```

- **`v1`**: invite format version (string literal in URI path).  
- **`blob`**: opaque bytes (§2). Encoding **base64url** without `=` padding.

## Blob (`InviteBlobV1`) — logical layout

Serialize **fixed-order fields**, then sign:

```
struct InviteBlobV1 {
    u16 blob_version_be;          // 0x0001 — future **0x0002** adds **`invite_id[16]`** before signing scope ([v0-invite-revocation.md](v0-invite-revocation.md))
    u64 expiry_unix_be;           // TTL anchor (default policy: 30 days from creation)
    u8  identity_sig_pk[32];      // Ed25519 (matches PrekeyBundle.identity_sig_pk)
    u8  signed_prekey_pk[32];     // X25519 SPK snapshot at invite creation
    u64 signed_prekey_id_be;      // monotonic SPK id / epoch for freshness (0 if unused)
    u16 route_hint_len_be;        // MAY be 0
    u8  route_hint[];             // optional_intro_route — relay bootstrap hint (opaque to clients if unused)
    u16 nickname_hint_len_be;     // MAY be 0
    u8  nickname_hint_utf8[];     // **local display only** — never authoritative identity
};
```

Immediately append Ed25519 signature over **the canonical serialized bytes of all fields above excluding signature**:

```
sig = Ed25519_sign(sk = identity_sig_sk, msg = serialize(InviteBlobV1_fields_only))
```

Wire blob:

```
blob = serialize(InviteBlobV1_fields_only) || sig[64]
```

## Policies

| Policy | Default |
|--------|---------|
| TTL | **30 days** (`expiry_unix`) |
| Single-use invites | **Optional** product flag |
| Reusable invites | **Default** |
| Revocation | **`invite_id` + signed revocation list** — **[v0-invite-revocation.md](v0-invite-revocation.md)** (`blob_version ≥ 0x0002` invites). |

For **`blob_version = 0x0001`** blobs without `invite_id`, rotation of **`signed_prekey_pk`** + honest peer behavior limits blast radius — still publish **`InviteRevokeV1`** only after **`invite_id`** ships.

## Verification

1. Decode base64url → `blob`.  
2. Split trailing 64 bytes signature vs prefix.  
3. Verify Ed25519(signature, pubkey=`identity_sig_pk`, msg=prefix).  
4. Check `now ≤ expiry_unix`.  
5. Optionally cross-check `signed_prekey_pk` against **[live PrekeyBundle]** fetched out-of-band when online—invite may lag rotations.

## Privacy notes

- Server **need not resolve** invite URIs; they are **offline-capable** bootstrap hints.  
- `nickname_hint` is UI sugar only; cryptographic identity is **`identity_sig_pk` / `account_id`** ([v0-protocol.md](v0-protocol.md) §3).  
- Long-term discovery remains **QR / link exchange only** — no global lookup.

## Normative status

Byte-for-byte serialization rules (TLV constraints, max lengths) **must** align with [v0-protocol.md](v0-protocol.md) endianness. Until locked with hex fixtures, treat field ordering above as **normative intent**—add `tools/gen_invite_vectors.py` when freezing.
