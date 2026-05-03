//! Misuse resistance: illegal call sequences and confused buffers must error — not advance state silently.

#[path = "common/mod.rs"]
mod common;

use common::DocFixture;
use libgary_core::data::data_inner_plaintext;
use libgary_core::engine::mode::SessionMode;
use libgary_core::engine::{DeviceStateAnchorV1, SessionError, SessionHandle};
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
    let sid = [0xc9u8; 16];
    let epoch = 0u32;
    let anchor = DeviceStateAnchorV1::new_v0(42);
    let bob_sk = std::array::from_fn(|i| (i.wrapping_add(9)) as u8);
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
fn finish_reset_on_active_session_always_invalid_header() {
    let (_alice, mut bob) = paired_sessions();
    assert_eq!(
        bob.finish_reset_half_open_to_active(),
        Err(SessionError::InvalidHeader)
    );
    assert_eq!(
        bob.finish_reset_half_open_to_active(),
        Err(SessionError::InvalidHeader)
    );
}

#[test]
fn finish_reset_twice_after_half_open_second_call_errors() {
    let old_e = 5u32;
    let new_e = old_e + 1;
    let sid = [0x77u8; 16];
    let anchor = DeviceStateAnchorV1::new_v0(3);
    let bob_sk = std::array::from_fn(|i| i.wrapping_add(2) as u8);
    let okm = handshake_okm();

    let mut bob = SessionHandle::bootstrap_responder(
        &okm,
        sid,
        new_e,
        bob_sk,
        Some(alice_ratchet_pub()),
        anchor,
    );
    bob.recompute_anchor_commitment();

    bob.enter_reset_pending_after_rebootstrap(old_e, None)
        .unwrap();
    bob.finish_reset_half_open_to_active().unwrap();
    assert!(matches!(bob.ingress_mode(), SessionMode::Active { .. }));

    assert_eq!(
        bob.finish_reset_half_open_to_active(),
        Err(SessionError::InvalidHeader)
    );
}

#[test]
fn feeding_decrypted_plain512_back_as_inner_ciphertext_fails() {
    let (mut alice, mut bob) = paired_sessions();

    let p0 = data_inner_plaintext(1, 1, b"m0").unwrap();
    let p1 = data_inner_plaintext(1, 1, b"m1").unwrap();
    let (h0, c0) = alice.send_data_plain512(&p0).unwrap();
    let (h1, c1) = alice.send_data_plain512(&p1).unwrap();

    let mut rng = ChaCha12Rng::from_seed([0xb0u8; 32]);
    let decrypted_m0 = bob.recv_data_plain512(&h0, &c0, &mut rng).unwrap();

    let after_m0 = bob.export_state();
    let mut rng = ChaCha12Rng::from_seed([0xb1u8; 32]);
    assert_eq!(
        bob.recv_data_plain512(&h1, decrypted_m0.as_ref(), &mut rng),
        Err(SessionError::DecryptionFailed),
        "plaintext is not a valid inner ciphertext for the next header"
    );

    let mut rng = ChaCha12Rng::from_seed([0xb2u8; 32]);
    let mut bob_clean = SessionHandle::from_export(after_m0).unwrap();
    bob_clean
        .recv_data_plain512(&h1, &c1, &mut rng)
        .expect("receiver after first honest decrypt still accepts the real second packet");
}

#[test]
fn recv_outer_bypass_on_late_epoch_data_errors_and_skips_ingress_policy() {
    let old_e = 17u32;
    let new_e = old_e + 1;
    let sid = [0x88u8; 16];
    let anchor = DeviceStateAnchorV1::new_v0(11);
    let bob_sk = std::array::from_fn(|i| i.wrapping_add(31) as u8);
    let okm = handshake_okm();

    let mut alice = SessionHandle::bootstrap_initiator(
        &okm,
        sid,
        old_e,
        DocFixture::ek_a_seed(),
        Some(peer_pub_from_sk(&bob_sk)),
        anchor.clone(),
    );
    let mut bob = SessionHandle::bootstrap_responder(
        &okm,
        sid,
        new_e,
        bob_sk,
        Some(alice_ratchet_pub()),
        anchor,
    );
    alice.recompute_anchor_commitment();
    bob.recompute_anchor_commitment();

    bob.enter_reset_pending_after_rebootstrap(old_e, None)
        .unwrap();

    let mut pad = ChaCha12Rng::from_seed([0xc0u8; 32]);
    let pt = data_inner_plaintext(1, 1, b"late-pre-reset").unwrap();
    let (hdr, payload) = alice.send_data_plain512_outer(&pt, &mut pad).unwrap();
    let outer = OuterRecord {
        header: hdr,
        payload,
    };

    let recv_hw_before = bob.recv_high_water();
    let recv_sym_before = bob.recv_sym_idx();

    let mut rng = ChaCha12Rng::from_seed([0xc1u8; 32]);
    assert_eq!(
        bob.handle_inbound_outer(outer.clone(), 0, &mut rng)
            .unwrap_err(),
        SessionError::LateDataAfterReset
    );

    let mut rng = ChaCha12Rng::from_seed([0xc2u8; 32]);
    assert_eq!(
        bob.recv_data_outer(&outer.header, &outer.payload, &mut rng)
            .unwrap_err(),
        SessionError::StaleEpochRejected
    );

    assert_eq!(bob.recv_high_water(), recv_hw_before);
    assert_eq!(bob.recv_sym_idx(), recv_sym_before);
}

#[test]
fn stale_in_memory_handle_diverges_from_latest_wal_after_reload_advances_elsewhere() {
    let (mut alice, mut bob_mem) = paired_sessions();
    let mut pad = ChaCha12Rng::from_seed([0xd0u8; 32]);

    let pt_a = data_inner_plaintext(1, 1, b"a").unwrap();
    let (ha, pa) = alice.send_data_plain512_outer(&pt_a, &mut pad).unwrap();
    let mut rng = ChaCha12Rng::from_seed([0xd1u8; 32]);
    bob_mem.recv_data_outer(&ha, &pa, &mut rng).unwrap();
    bob_mem.recompute_anchor_commitment();

    let dir = tempdir().unwrap();
    let store = SessionStore::new(dir.path().join("stale.wal"));
    store.save_session(&bob_mem).unwrap();

    let mut bob_loaded = store.load_session().unwrap();
    assert_eq!(
        bob_loaded.persistence_equivalence_digest(),
        bob_mem.persistence_equivalence_digest()
    );

    let pt_b = data_inner_plaintext(1, 1, b"b").unwrap();
    let (hb, pb) = alice.send_data_plain512_outer(&pt_b, &mut pad).unwrap();
    let mut rng = ChaCha12Rng::from_seed([0xd2u8; 32]);
    bob_loaded.recv_data_outer(&hb, &pb, &mut rng).unwrap();
    bob_loaded.recompute_anchor_commitment();
    store.save_session(&bob_loaded).unwrap();

    let bob_from_disk = store.load_session().unwrap();
    assert_eq!(
        bob_from_disk.persistence_equivalence_digest(),
        bob_loaded.persistence_equivalence_digest()
    );
    assert_ne!(
        bob_mem.persistence_equivalence_digest(),
        bob_from_disk.persistence_equivalence_digest(),
        "an in-memory handle that did not persist further progress must disagree with latest WAL"
    );
}
