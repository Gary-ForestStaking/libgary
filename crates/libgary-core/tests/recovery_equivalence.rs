//! Golden persistence equivalence: forward trace ≡ WAL reload ≡ replay-from-bootstrap ([`SessionHandle::persistence_equivalence_digest`]).

#[path = "common/mod.rs"]
mod common;

use common::DocFixture;
use libgary_core::data::data_inner_plaintext;
use libgary_core::engine::{DeviceStateAnchorV1, SessionHandle};
use libgary_core::session::{ikm_session, okm_root_bootstrap};
use libgary_core::transcript::{th0, th1};
use libgary_core::x3dh::km_with_otp;
use libgary_storage::SessionStore;
use libgary_wire::OuterRecord;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use tempfile::tempdir;
use x25519_dalek::{PublicKey, StaticSecret};

fn handshake_okm() -> [u8; 64] {
    let ik_a = StaticSecret::from(DocFixture::alice_ik_priv());
    let ek_a = StaticSecret::from(DocFixture::ek_a_seed());
    let ik_b_pub = PublicKey::from(&StaticSecret::from(DocFixture::bob_ik_priv()));
    let spk_b_pub = PublicKey::from(&StaticSecret::from(DocFixture::spk_b_seed()));
    let otp_b_pub = PublicKey::from(&StaticSecret::from(DocFixture::otp_b_seed()));
    let km = km_with_otp(&ik_a, &ek_a, &ik_b_pub, &spk_b_pub, &otp_b_pub);
    let init_bytes = DocFixture::init_body().encode();
    let th0_d = th0(&init_bytes);
    let core = DocFixture::init_ack_core();
    let th1_d = th1(&th0_d, &core);
    let ikm = ikm_session(&km, &th0_d, &th1_d);
    okm_root_bootstrap(&ikm)
}

fn alice_ratchet_pub() -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(DocFixture::ek_a_seed())).as_bytes()
}

fn peer_pub_from_sk(sk: &[u8; 32]) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(*sk)).as_bytes()
}

fn paired_sessions() -> (SessionHandle, SessionHandle) {
    let okm = handshake_okm();
    let sid = [0xabu8; 16];
    let epoch = 0u32;
    let anchor = DeviceStateAnchorV1::new_v0(100);
    let bob_sk = std::array::from_fn(|i| (i.wrapping_add(3)) as u8);
    let mut alice = SessionHandle::bootstrap_initiator(
        &okm,
        sid,
        epoch,
        DocFixture::ek_a_seed(),
        Some(peer_pub_from_sk(&bob_sk)),
        anchor.clone(),
    );
    let mut bob = SessionHandle::bootstrap_responder(
        &okm,
        sid,
        epoch,
        bob_sk,
        Some(alice_ratchet_pub()),
        anchor,
    );
    alice.recompute_anchor_commitment();
    bob.recompute_anchor_commitment();
    (alice, bob)
}

#[test]
fn golden_persistence_equivalence_digest_forward_wal_replay() {
    let mut pad_rng = ChaCha12Rng::from_seed([0x72u8; 32]);
    let mut bob_decrypt_rng = ChaCha12Rng::from_seed([0x73u8; 32]);

    let (mut alice, mut bob) = paired_sessions();

    let mut encoded_outers: Vec<Vec<u8>> = Vec::new();

    for step in 0u8..3u8 {
        let pt = data_inner_plaintext(1, 1, &[step]).unwrap();
        let (hdr, pay) = alice
            .send_data_plain512_outer(&pt, &mut pad_rng)
            .unwrap();
        encoded_outers.push(
            OuterRecord {
                header: hdr,
                payload: pay,
            }
            .encode()
            .unwrap(),
        );
        let rec = OuterRecord::decode(encoded_outers.last().unwrap()).unwrap();
        bob.recv_data_outer(&rec.header, &rec.payload, &mut bob_decrypt_rng)
            .unwrap();
    }

    let (rh, rp) = alice
        .send_rekey_ctrl_outer(&[0xde, 0xad, 0xbe, 0xef], &mut pad_rng)
        .unwrap();
    encoded_outers.push(
        OuterRecord {
            header: rh,
            payload: rp,
        }
        .encode()
        .unwrap(),
    );
    let rec = OuterRecord::decode(encoded_outers.last().unwrap()).unwrap();
    bob.recv_rekey_ctrl_outer(&rec.header, &rec.payload, &mut bob_decrypt_rng)
        .unwrap();

    bob.recompute_anchor_commitment();
    let digest_forward = bob.persistence_equivalence_digest();

    let dir = tempdir().unwrap();
    let store = SessionStore::new(dir.path().join("equiv.wal"));
    store.save_session(&bob).unwrap();
    let bob_loaded = store.load_session().unwrap();
    assert_eq!(
        bob_loaded.persistence_equivalence_digest(),
        digest_forward,
        "WAL reload must preserve persistence equivalence digest"
    );

    let (_, mut bob_reply) = paired_sessions();
    let mut bob_reply_rng = ChaCha12Rng::from_seed([0x73u8; 32]);
    for bytes in &encoded_outers {
        let r = OuterRecord::decode(bytes).unwrap();
        match r.header.typ {
            0x03 => {
                bob_reply
                    .recv_data_outer(&r.header, &r.payload, &mut bob_reply_rng)
                    .unwrap();
            }
            0x05 => {
                bob_reply
                    .recv_rekey_ctrl_outer(&r.header, &r.payload, &mut bob_reply_rng)
                    .unwrap();
            }
            _ => panic!("unexpected typ {}", r.header.typ),
        }
    }
    bob_reply.recompute_anchor_commitment();
    assert_eq!(
        bob_reply.persistence_equivalence_digest(),
        digest_forward,
        "replay-from-bootstrap must converge to same digest as forward execution"
    );
}
