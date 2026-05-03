//! Hostile wire / storage cases against live [`Session`] + [`OuterRecord`] + WAL (`docs/v0-state-integrity.md`).

#[path = "common/mod.rs"]
mod common;

use common::DocFixture;
use libgary_core::constants::MAX_SKIP;
use libgary_core::data::data_inner_plaintext;
use libgary_core::engine::mode::SessionMode;
use libgary_core::engine::{DeviceStateAnchorV1, SessionError, SessionHandle};
use libgary_core::session::{ikm_session, okm_root_bootstrap};
use libgary_core::transcript::{th0, th1};
use libgary_core::x3dh::km_with_otp;
use libgary_storage::{SessionStore, StorageError};
use libgary_storage::wal_envelope::{decode_wal_envelope, encode_wal_envelope};
use libgary_wire::{Header, OuterRecord, RelayOuterEnvelope, WireError};
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
    let sid = [0u8; 16];
    let epoch = 0u32;
    let anchor = DeviceStateAnchorV1::new_v0(1);
    let bob_sk = std::array::from_fn(|i| (i + 3) as u8);
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
fn data_outer_out_of_order_then_duplicate_replay() {
    let mut pad = ChaCha12Rng::from_seed([1u8; 32]);
    let (mut alice, mut bob) = paired_sessions();

    let p0 = data_inner_plaintext(1, 1, b"c0").unwrap();
    let p1 = data_inner_plaintext(1, 1, b"c1").unwrap();
    let (h0, pay0) = alice.send_data_plain512_outer(&p0, &mut pad).unwrap();
    let (h1, pay1) = alice.send_data_plain512_outer(&p1, &mut pad).unwrap();

    let mut rng = ChaCha12Rng::from_seed([2u8; 32]);
    bob.recv_data_outer(&h1, &pay1, &mut rng).unwrap();
    let mut rng = ChaCha12Rng::from_seed([3u8; 32]);
    bob.recv_data_outer(&h0, &pay0, &mut rng).unwrap();

    let mut rng = ChaCha12Rng::from_seed([4u8; 32]);
    assert_eq!(
        bob.recv_data_outer(&h0, &pay0, &mut rng).unwrap_err(),
        SessionError::ReplayRejected
    );
}

#[test]
fn relay_forged_route_token_opaque_unchanged() {
    let mut pad = ChaCha12Rng::from_seed([5u8; 32]);
    let (mut alice, mut bob) = paired_sessions();
    let pt = data_inner_plaintext(1, 1, b"relay-opaque").unwrap();
    let (hdr, payload) = alice.send_data_plain512_outer(&pt, &mut pad).unwrap();
    let outer = OuterRecord { header: hdr, payload }.encode().unwrap();

    let env_good = RelayOuterEnvelope {
        route_token: vec![0x01],
        opaque_bytes: outer.clone(),
    };
    let padded = env_good.encode_padded_wire(&mut pad).unwrap();

    let env_bad = RelayOuterEnvelope {
        route_token: vec![0xff, 0xfe, 0xfd], // receiver cannot authenticate route_token here
        opaque_bytes: outer,
    };
    let forged_pad = env_bad.encode_padded_wire(&mut pad).unwrap();

    assert_ne!(padded, forged_pad);
    let got = RelayOuterEnvelope::decode_padded_wire(&forged_pad)
        .unwrap()
        .opaque_bytes;
    let rec = OuterRecord::decode(&got).unwrap();
    let mut rng = ChaCha12Rng::from_seed([6u8; 32]);
    let plain = bob.recv_data_outer(&rec.header, &rec.payload, &mut rng).unwrap();
    assert_eq!(pt.as_slice(), plain.as_slice());
}

#[test]
fn truncated_outer_bucket_fails_before_ratchet_then_recover() {
    let mut pad = ChaCha12Rng::from_seed([7u8; 32]);
    let (mut alice, mut bob) = paired_sessions();

    let p0 = data_inner_plaintext(1, 1, b"ok").unwrap();
    let (h0, pay0) = alice.send_data_plain512_outer(&p0, &mut pad).unwrap();
    let truncated = pay0[..512].to_vec();

    let mut rng = ChaCha12Rng::from_seed([8u8; 32]);
    assert_eq!(
        bob.recv_data_outer(&h0, &truncated, &mut rng).unwrap_err(),
        SessionError::InvalidHeader
    );

    let mut rng = ChaCha12Rng::from_seed([9u8; 32]);
    let got = bob.recv_data_outer(&h0, &pay0, &mut rng).unwrap();
    assert_eq!(p0.as_slice(), got.as_slice());
}

#[test]
fn corrupted_inner_ciphertext_bad_mac_after_recv_material_spent() {
    let mut pad = ChaCha12Rng::from_seed([0x17u8; 32]);
    let (mut alice, mut bob) = paired_sessions();

    let p0 = data_inner_plaintext(1, 1, b"tamper-ct").unwrap();
    let (h0, pay0) = alice.send_data_plain512_outer(&p0, &mut pad).unwrap();
    let mut pay_bad = pay0.clone();
    pay_bad[40] ^= 0xff;

    let mut rng = ChaCha12Rng::from_seed([0x18u8; 32]);
    assert_eq!(
        bob.recv_data_outer(&h0, &pay_bad, &mut rng).unwrap_err(),
        SessionError::DecryptionFailed
    );

    let mut rng = ChaCha12Rng::from_seed([0x19u8; 32]);
    assert_eq!(
        bob.recv_data_outer(&h0, &pay0, &mut rng).unwrap_err(),
        SessionError::DecryptionFailed
    );
}

#[test]
fn corrupted_random_tail_pad_outer_decrypt_unchanged() {
    let mut pad = ChaCha12Rng::from_seed([0x1au8; 32]);
    let (mut alice, mut bob) = paired_sessions();

    let p0 = data_inner_plaintext(1, 1, b"pad-tail").unwrap();
    let (h0, mut pay0) = alice.send_data_plain512_outer(&p0, &mut pad).unwrap();
    pay0[900] ^= 0xff;

    let mut rng = ChaCha12Rng::from_seed([0x1bu8; 32]);
    let got = bob.recv_data_outer(&h0, &pay0, &mut rng).unwrap();
    assert_eq!(p0.as_slice(), got.as_slice());
}

#[test]
fn invalid_header_flags_outer_encode_rejected() {
    let hdr = Header {
        version: 1,
        typ: 0x03,
        flags: 0x04,
        epoch_be: 0,
        session_id: [0u8; 16],
        counter_be: 0,
        ratchet_pub: alice_ratchet_pub(),
    };
    let rec = OuterRecord {
        header: hdr,
        payload: vec![0u8; 8],
    };
    assert_eq!(
        rec.encode().unwrap_err(),
        WireError::InvalidHeaderFlags
    );
}

#[test]
fn max_skip_outer_decrypt_rejected() {
    let mut pad = ChaCha12Rng::from_seed([0xa1u8; 32]);
    let (mut alice, mut bob) = paired_sessions();

    let p0 = data_inner_plaintext(1, 1, b"m0").unwrap();
    let (h0, pay0) = alice.send_data_plain512_outer(&p0, &mut pad).unwrap();
    let mut rng = ChaCha12Rng::from_seed([0xa2u8; 32]);
    bob.recv_data_outer(&h0, &pay0, &mut rng).unwrap();

    let overshoot = (MAX_SKIP as u64).saturating_add(50).saturating_add(1);
    let bogus = Header {
        version: 1,
        typ: 0x03,
        flags: 0,
        epoch_be: 0,
        session_id: [0u8; 16],
        counter_be: overshoot,
        ratchet_pub: alice_ratchet_pub(),
    };
    let mut rng = ChaCha12Rng::from_seed([0xa3u8; 32]);
    assert_eq!(
        bob.recv_data_outer(&bogus, &pay0, &mut rng).unwrap_err(),
        SessionError::MaxSkipExceeded
    );
}

#[test]
fn replayed_wire_counter_on_data_outer() {
    let mut pad = ChaCha12Rng::from_seed([0xb1u8; 32]);
    let (mut alice, mut bob) = paired_sessions();

    let p0 = data_inner_plaintext(1, 1, b"once").unwrap();
    let (h0, pay0) = alice.send_data_plain512_outer(&p0, &mut pad).unwrap();
    let mut rng = ChaCha12Rng::from_seed([0xb2u8; 32]);
    bob.recv_data_outer(&h0, &pay0, &mut rng).unwrap();
    let mut rng = ChaCha12Rng::from_seed([0xb3u8; 32]);
    assert_eq!(
        bob.recv_data_outer(&h0, &pay0, &mut rng).unwrap_err(),
        SessionError::ReplayRejected
    );
}

#[test]
fn replay_rekey_outer_second_decrypt_rejected() {
    let mut pad = ChaCha12Rng::from_seed([0xc1u8; 32]);
    let (mut alice, mut bob) = paired_sessions();

    let body = [0x01u8, 0x02, 0x03, 0x04];
    let (hdr, pay) = alice.send_rekey_ctrl_outer(&body, &mut pad).unwrap();
    let mut rng = ChaCha12Rng::from_seed([0xc2u8; 32]);
    bob.recv_rekey_ctrl_outer(&hdr, &pay, &mut rng).unwrap();
    let mut rng = ChaCha12Rng::from_seed([0xc3u8; 32]);
    assert_eq!(
        bob.recv_rekey_ctrl_outer(&hdr, &pay, &mut rng).unwrap_err(),
        SessionError::ReplayRejected
    );
}

#[test]
fn wal_mismatched_bundle_and_meta_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("session.wal");
    let store = SessionStore::new(&path);

    let mut alice = paired_sessions().0;
    let pt = data_inner_plaintext(1, 1, b"persist").unwrap();
    let mut pad = ChaCha12Rng::from_seed([0xd1u8; 32]);
    alice.send_data_plain512_outer(&pt, &mut pad).unwrap();
    alice.send_data_plain512_outer(&pt, &mut pad).unwrap();
    alice.recompute_anchor_commitment();
    store.save_session(&alice).unwrap();

    let wal_old = std::fs::read(store.envelope_path()).unwrap();
    let (bundle_old, _meta_old) = decode_wal_envelope(&wal_old).unwrap();

    let mut alice2 = store.load_session().unwrap();
    alice_encrypt_one_more(&mut alice2, &mut pad);
    alice_encrypt_one_more(&mut alice2, &mut pad);
    alice_encrypt_one_more(&mut alice2, &mut pad);
    alice2.recompute_anchor_commitment();
    store.save_session(&alice2).unwrap();

    let wal_new = std::fs::read(store.envelope_path()).unwrap();
    let (_bundle_new, meta_new) = decode_wal_envelope(&wal_new).unwrap();

    let malicious = encode_wal_envelope(&bundle_old, &meta_new);
    std::fs::write(store.envelope_path(), malicious).unwrap();

    match store.load_session() {
        Err(StorageError::RollbackDetected) => {}
        Err(e) => panic!("unexpected storage error: {e:?}"),
        Ok(_) => panic!("expected RollbackDetected"),
    }
}

fn alice_encrypt_one_more(alice: &mut SessionHandle, pad: &mut ChaCha12Rng) {
    let pt = data_inner_plaintext(1, 1, b"x").unwrap();
    alice.send_data_plain512_outer(&pt, pad).unwrap();
}

#[test]
fn stale_epoch_outer_decrypt_rejected() {
    let mut pad = ChaCha12Rng::from_seed([0xe1u8; 32]);
    let (mut alice, mut bob) = paired_sessions();

    let p0 = data_inner_plaintext(1, 1, b"e0").unwrap();
    let (mut h0, pay0) = alice.send_data_plain512_outer(&p0, &mut pad).unwrap();
    h0.epoch_be = 99;

    let mut rng = ChaCha12Rng::from_seed([0xe2u8; 32]);
    assert_eq!(
        bob.recv_data_outer(&h0, &pay0, &mut rng).unwrap_err(),
        SessionError::StaleEpochRejected
    );
}

#[test]
fn decrypt_pending_second_packet_duplicate_first_still_replay() {
    let mut pad = ChaCha12Rng::from_seed([0xf1u8; 32]);
    let (mut alice, mut bob) = paired_sessions();

    let p0 = data_inner_plaintext(1, 1, b"first").unwrap();
    let _p1 = data_inner_plaintext(1, 1, b"second").unwrap();
    let (h0, pay0) = alice.send_data_plain512_outer(&p0, &mut pad).unwrap();
    let (_h1, _pay1) = alice.send_data_plain512_outer(&_p1, &mut pad).unwrap();

    let mut rng = ChaCha12Rng::from_seed([0xf2u8; 32]);
    bob.recv_data_outer(&h0, &pay0, &mut rng).unwrap();

    let mut rng = ChaCha12Rng::from_seed([0xf3u8; 32]);
    assert_eq!(
        bob.recv_data_outer(&h0, &pay0, &mut rng).unwrap_err(),
        SessionError::ReplayRejected
    );
}

/// Epoch transition at receiver invalidates in-flight DATA from sender still on prior epoch.
#[test]
fn reset_half_open_epoch_isolation() {
    let old_e = 11u32;
    let new_e = old_e + 1;
    let sid = [0x33u8; 16];
    let anchor = DeviceStateAnchorV1::new_v0(7);
    let bob_sk = std::array::from_fn(|i| i.wrapping_add(19) as u8);
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

    bob.enter_reset_pending_after_rebootstrap(old_e, None).unwrap();

    let mut pad = ChaCha12Rng::from_seed([0x40u8; 32]);
    let pt = data_inner_plaintext(1, 1, b"delayed-pre-reset-data").unwrap();
    let (hdr, payload) = alice.send_data_plain512_outer(&pt, &mut pad).unwrap();
    let outer = OuterRecord {
        header: hdr,
        payload,
    }
    .encode()
    .unwrap();

    let dir = tempdir().unwrap();
    let store = SessionStore::new(dir.path().join("half_open.wal"));
    store.save_session(&bob).unwrap();
    let wal_before = std::fs::read(store.envelope_path()).unwrap();

    let recv_hw_before = bob.recv_high_water();
    let recv_sym_before = bob.recv_sym_idx();

    let rec = OuterRecord::decode(&outer).unwrap();
    let mut rng = ChaCha12Rng::from_seed([0x41u8; 32]);
    assert_eq!(
        bob.handle_inbound_outer(rec, 0, &mut rng).unwrap_err(),
        SessionError::LateDataAfterReset
    );

    assert_eq!(bob.recv_high_water(), recv_hw_before);
    assert_eq!(bob.recv_sym_idx(), recv_sym_before);
    assert!(matches!(
        bob.ingress_mode(),
        SessionMode::ResetPending {
            old_epoch: oe,
            ..
        } if oe == old_e
    ));

    let wal_after = std::fs::read(store.envelope_path()).unwrap();
    assert_eq!(wal_before, wal_after);
}
