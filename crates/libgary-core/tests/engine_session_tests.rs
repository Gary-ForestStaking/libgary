//! Stateful ratchet `Session` tests (v0-protocol §8–§9).

mod common;

use common::DocFixture;
use libgary_core::constants::MAX_SKIP;
use libgary_core::data::data_inner_plaintext;
use libgary_core::engine::skipped::SkippedKeyCache;
use libgary_core::engine::{DeviceStateAnchorV1, SessionError, SessionHandle};
use libgary_core::session::{ikm_session, okm_root_bootstrap};
use libgary_core::transcript::{th0, th1};
use libgary_core::x3dh::km_with_otp;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use x25519_dalek::{PublicKey, StaticSecret};

fn hb(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

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

#[test]
fn session_matches_integration_step03_data_counter0() {
    let okm = handshake_okm();
    let sid = [0u8; 16];
    let epoch = 0u32;
    let anchor = DeviceStateAnchorV1::new_v0(1);

    let mut alice = SessionHandle::bootstrap_initiator(
        &okm,
        sid,
        epoch,
        DocFixture::ek_a_seed(),
        None,
        anchor.clone(),
    );
    let bob_ratchet_seed = std::array::from_fn(|i| (i + 1) as u8);
    let mut bob = SessionHandle::bootstrap_responder(
        &okm,
        sid,
        epoch,
        bob_ratchet_seed,
        Some(alice_ratchet_pub()),
        anchor,
    );

    let pt = data_inner_plaintext(1, 1, b"hello-libgary-v0").unwrap();
    let (_hdr, ct) = alice.send_data_plain512(&pt).unwrap();
    assert_eq!(
        hb(
            "5b6750a07c2d2b5677904e227d8718f1a28177cf3e02b6e6d9fc9f6eee63486869d9a7f3705c3498817bd180457f722a8c7b28bec1925bd97611578ff09255e4931857d9e644d32dc1447960ec3d89fd22e87716bdf97ba6592228874b98ace467995493215b1a4950b7366883be7990610a4db2d928fdd83f440497e8c2791685b17610f618c2a9df3771c4e2748ba8687200cc0bd293ac3c82f44d1767ebccf0f591d4a0272dd3589225708b56ac223c82f357f134c56e162fb1f089b39fb128edea9a6a5b7f5b10b5e3abba10a7993c8822efd389e585f91cb87a2e29fb8817fa414bdef286439be4b1d9159cfc6e3239a2ea884b43699c84de34676557f82ac019256fb3a40adbd08e03585a71a09525bc7619a283a569c5c88d44f99eda48ed02d01069216ea9124d60445a21aaa2346261694cac236652d8fdd7f68eaa104eb80da1d032c91c2607929f9d5f1f8687a0e90873051ebb7aee113053e0d9e3d5d7df99af9c9545852516daad6721dc6e12480357be85ed540df8b8b7e45786503403b80590db7c46f90d866946c7773c2a20956368a9deb857db86da8c74b81498268a81243c77856ccc6e476c5a90bd7ad6aa67036ae5778e20b29e3c9c52fbdcde92a166a33663408383ac8517ad00fed75e323514fd938711eca6dcf923e2eebece9d9f3e110932d1033a50e3a7c12016c59e4f906c81dd17a6446c064d1f275e7369b9b6e41239cf51131f7e"
        ),
        ct
    );

    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let hdr = libgary_wire::Header {
        version: 1,
        typ: 0x03,
        flags: 0,
        epoch_be: epoch,
        session_id: sid,
        counter_be: 0,
        ratchet_pub: alice_ratchet_pub(),
    };
    let out = bob.recv_data_plain512(&hdr, &ct, &mut rng).unwrap();
    assert_eq!(pt, *out);
}

#[test]
fn decrypt_out_of_order_and_duplicate_and_stale_epoch() {
    let okm = handshake_okm();
    let sid = [0u8; 16];
    let epoch = 0u32;
    let anchor = DeviceStateAnchorV1::new_v0(1);

    let mut alice = SessionHandle::bootstrap_initiator(
        &okm,
        sid,
        epoch,
        DocFixture::ek_a_seed(),
        None,
        anchor.clone(),
    );
    let bob_ratchet_seed = std::array::from_fn(|i| i.wrapping_mul(7).wrapping_add(11) as u8);
    let mut bob = SessionHandle::bootstrap_responder(
        &okm,
        sid,
        epoch,
        bob_ratchet_seed,
        Some(alice_ratchet_pub()),
        anchor,
    );

    let p0 = data_inner_plaintext(1, 1, b"m0").unwrap();
    let p1 = data_inner_plaintext(1, 1, b"m1").unwrap();
    let (h0, c0) = alice.send_data_plain512(&p0).unwrap();
    let (h1, c1) = alice.send_data_plain512(&p1).unwrap();

    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    bob.recv_data_plain512(&h1, &c1, &mut rng).unwrap();

    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    bob.recv_data_plain512(&h0, &c0, &mut rng).unwrap();

    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    assert_eq!(
        bob.recv_data_plain512(&h0, &c0, &mut rng).unwrap_err(),
        SessionError::ReplayRejected
    );

    let mut bad = h1.clone();
    bad.epoch_be = 9;
    let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
    assert_eq!(
        bob.recv_data_plain512(&bad, &c1, &mut rng).unwrap_err(),
        SessionError::StaleEpochRejected
    );

    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    assert_eq!(
        bob.recv_data_plain512(&h1, &c1, &mut rng).unwrap_err(),
        SessionError::ReplayRejected
    );
}

#[test]
fn decrypt_gap_exceeds_max_skip_errors() {
    let okm = handshake_okm();
    let sid = [0u8; 16];
    let epoch = 0u32;
    let anchor = DeviceStateAnchorV1::new_v0(1);

    let mut alice = SessionHandle::bootstrap_initiator(
        &okm,
        sid,
        epoch,
        DocFixture::ek_a_seed(),
        None,
        anchor.clone(),
    );
    let bob_ratchet_seed = [0xaa_u8; 32];
    let mut bob = SessionHandle::bootstrap_responder(
        &okm,
        sid,
        epoch,
        bob_ratchet_seed,
        Some(alice_ratchet_pub()),
        anchor,
    );

    let p0 = data_inner_plaintext(1, 1, b"m0").unwrap();
    let (h0, c0) = alice.send_data_plain512(&p0).unwrap();
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    bob.recv_data_plain512(&h0, &c0, &mut rng).unwrap();

    let overshoot = (MAX_SKIP as u64).saturating_add(50).saturating_add(1);
    let bogus_hdr = libgary_wire::Header {
        version: 1,
        typ: 0x03,
        flags: 0,
        epoch_be: epoch,
        session_id: sid,
        counter_be: overshoot,
        ratchet_pub: alice_ratchet_pub(),
    };
    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
    assert_eq!(
        bob.recv_data_plain512(&bogus_hdr, &c0, &mut rng)
            .unwrap_err(),
        SessionError::MaxSkipExceeded
    );
}

#[test]
fn skipped_cache_duplicate_insert_rejected() {
    let mut s = SkippedKeyCache::new();
    let peer = [7u8; 32];
    let mk = [11u8; 32];
    s.insert(&peer, 1, mk).unwrap();
    assert_eq!(
        s.insert(&peer, 1, mk).unwrap_err(),
        SessionError::ReplayRejected
    );
}

#[test]
fn export_import_roundtrip_preserves_crypto_state() {
    let okm = handshake_okm();
    let sid = [3u8; 16];
    let epoch = 7u32;
    let mut anchor = DeviceStateAnchorV1::new_v0(42);
    anchor.highest_wire_seen_be = 9;

    let mut alice = SessionHandle::bootstrap_initiator(
        &okm,
        sid,
        epoch,
        DocFixture::ek_a_seed(),
        None,
        anchor.clone(),
    );
    let pt = data_inner_plaintext(1, 1, b"x").unwrap();
    alice.send_data_plain512(&pt).unwrap();
    alice.recompute_anchor_commitment();

    let digest_alice = alice.persistence_equivalence_digest();
    let mut export = alice.export_state();
    let imported = SessionHandle::from_export(export.clone()).unwrap();
    assert_eq!(imported.session_id(), sid);
    assert_eq!(imported.epoch(), epoch);
    assert_eq!(imported.persistence_equivalence_digest(), digest_alice);
    assert_eq!(imported.send_wire_counter(), alice.send_wire_counter());

    export.anchor.state_commitment[0] ^= 0xFF;
    let tampered = SessionHandle::from_export(export).unwrap();
    assert!(!tampered.verify_anchor_commitment());
}
