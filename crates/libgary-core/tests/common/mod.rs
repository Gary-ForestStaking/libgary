//! Deterministic seeds matching `tools/gen_test_vectors.py`.

use ed25519_dalek::SigningKey;
use libgary_wire::{InitAckCore, InitBody};
use x25519_dalek::{PublicKey, StaticSecret};

fn hb32(s: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    hex::decode_to_slice(s, &mut o).unwrap();
    o
}

pub struct DocFixture;

impl DocFixture {
    pub fn alice_ik_priv() -> [u8; 32] {
        hb32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    }

    pub fn bob_ik_priv() -> [u8; 32] {
        hb32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    }

    pub fn ek_a_seed() -> [u8; 32] {
        hb32("78e2a3a56e1179a99946f2a1e21e0150863153f4051b3b34fcbe317d88221d07")
    }

    pub fn spk_b_seed() -> [u8; 32] {
        hb32("8abf814cb2ad0eb491fc4abbf0f374d79db18cfe02b423139bd08878f2aa23fc")
    }

    pub fn otp_b_seed() -> [u8; 32] {
        hb32("86a166d04c8405960967ad0f01aec2221555a068c3cd3c0a2a3afb9e64068c68")
    }

    pub fn alice_ed_seed() -> [u8; 32] {
        hb32("cfd9b04b123f8b4c4309b2e2340bab100ab86eb38925a539412d6707c20a0147")
    }

    pub fn bob_ed_seed() -> [u8; 32] {
        hb32("0a0433b062961d3164d66e509b4088d9df5bb8cba6d975daf0a5fe721665aed0")
    }

    pub fn alice_spk_seed() -> [u8; 32] {
        hb32("cf99f7eca40c775915cfbbb76c4ef57da9d6615bd88487dbd35748ff2ea30f21")
    }

    pub fn ratchet_after_dh_seed() -> [u8; 32] {
        hb32("8f32da07870610fdd3d6f2201a3dd3dde9c2f06a67697607181fdc6e913d0231")
    }

    pub fn alice_signing_key() -> SigningKey {
        SigningKey::from_bytes(&Self::alice_ed_seed())
    }

    pub fn bob_signing_key() -> SigningKey {
        SigningKey::from_bytes(&Self::bob_ed_seed())
    }

    pub fn init_body() -> InitBody {
        InitBody {
            initiator_sig_pk: *Self::alice_signing_key().verifying_key().as_bytes(),
            initiator_dh_pk: *PublicKey::from(&StaticSecret::from(Self::alice_ik_priv())).as_bytes(),
            ephemeral_ek_pub: *PublicKey::from(&StaticSecret::from(Self::ek_a_seed())).as_bytes(),
            otp_index_be: 0,
            reserved_be: 0,
        }
    }

    pub fn init_ack_core() -> InitAckCore {
        InitAckCore {
            responder_sig_pk: *Self::bob_signing_key().verifying_key().as_bytes(),
            responder_dh_pk: *PublicKey::from(&StaticSecret::from(Self::bob_ik_priv())).as_bytes(),
            ack_nonce_be: 1,
        }
    }

    pub fn alice_spk_pub() -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from(Self::alice_spk_seed())).as_bytes()
    }

    pub fn bob_signed_prekey_pub() -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from(Self::spk_b_seed())).as_bytes()
    }

    pub fn ratchet_pub_after_dh() -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from(Self::ratchet_after_dh_seed())).as_bytes()
    }
}
