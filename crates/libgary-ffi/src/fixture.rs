//! Deterministic initiator/responder pair matching `docs/test-vectors.md` VECTOR 001–002 bootstrap.
//!
//! Embedded here so the FFI crate stays self-contained without `tests/common`.

use libgary_core::engine::{DeviceStateAnchorV1, SessionHandle as CoreSession};
use x25519_dalek::{PublicKey, StaticSecret};

/// Normative `OKM` from handshake transcript row in `docs/test-vectors.md`.
const DOC_HANDSHAKE_OKM_HEX: &str = "4bc45cc7fddf45d3e624d78e3805aa9f06309548b48d7a6dc382b950544930b0ca94f844ddf80d7c208a9b8c0345c87a63f9d5d46279df66972ed22406997130";

/// Initiator ratchet pubkey derived from `DocFixture::ek_a_seed` (DATA header fixture).
const DOC_ALICE_RATCHET_PUB_HEX: &str =
    "a736bf0fdc88494658777e47d321926950d321c3c98cbfa108ead46ba84ed25d";

/// X25519 scalar seed for Alice ratchet (`tests/common/mod.rs` `DocFixture::ek_a_seed`).
const DOC_EK_A_SEED_HEX: &str =
    "78e2a3a56e1179a99946f2a1e21e0150863153f4051b3b34fcbe317d88221d07";

pub(crate) fn epoch_policy_vector_responder() -> CoreSession {
    let mut okm = [0u8; 64];
    hex::decode_to_slice(DOC_HANDSHAKE_OKM_HEX, &mut okm).expect("fixture OKM hex");

    let mut alice_rp = [0u8; 32];
    hex::decode_to_slice(DOC_ALICE_RATCHET_PUB_HEX, &mut alice_rp).expect("fixture alice rp hex");

    let session_id = [0x01u8; 16];
    let epoch = 7u32;
    let anchor = DeviceStateAnchorV1::new_v0(901);
    let bob_sk = std::array::from_fn(|i| i.wrapping_add(3) as u8);

    let mut bob =
        CoreSession::bootstrap_responder(&okm, session_id, epoch, bob_sk, Some(alice_rp), anchor);
    bob.recompute_anchor_commitment();
    bob
}

pub(crate) fn epoch_policy_vector_initiator() -> CoreSession {
    let mut okm = [0u8; 64];
    hex::decode_to_slice(DOC_HANDSHAKE_OKM_HEX, &mut okm).expect("fixture OKM hex");

    let mut alice_sk = [0u8; 32];
    hex::decode_to_slice(DOC_EK_A_SEED_HEX, &mut alice_sk).expect("fixture ek_a hex");

    let bob_sk = std::array::from_fn(|i| i.wrapping_add(3) as u8);
    let bob_rp = *PublicKey::from(&StaticSecret::from(bob_sk)).as_bytes();

    let session_id = [0x01u8; 16];
    let epoch = 7u32;
    let anchor = DeviceStateAnchorV1::new_v0(901);

    let mut alice =
        CoreSession::bootstrap_initiator(&okm, session_id, epoch, alice_sk, Some(bob_rp), anchor);
    alice.recompute_anchor_commitment();
    alice
}
