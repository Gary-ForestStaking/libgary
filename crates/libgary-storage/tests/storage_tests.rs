//! Rollback / corruption drills (`docs/v0-state-integrity.md` §6). WAL envelope (`LGW1`).

#[path = "../../libgary-core/tests/common/mod.rs"]
mod common;

use common::DocFixture;
use libgary_core::data::data_inner_plaintext;
use libgary_core::engine::{DeviceStateAnchorV1, SessionHandle, SessionWalSource};
use libgary_core::session::{ikm_session, okm_root_bootstrap};
use libgary_core::transcript::{th0, th1};
use libgary_core::x3dh::km_with_otp;
use libgary_storage::bundle_codec::encode_bundle;
use libgary_storage::wal_envelope::{decode_wal_envelope, encode_wal_envelope};
use libgary_storage::{SessionStore, StorageError, verify_anchor};
use rand_chacha::ChaCha20Rng;
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

fn store_wal(dir: &tempfile::TempDir) -> SessionStore {
    SessionStore::new(dir.path().join("state.wal"))
}

fn alice_session_epoch(epoch: u32) -> SessionHandle {
    let okm = handshake_okm();
    let sid = [0xabu8; 16];
    let anchor = DeviceStateAnchorV1::new_v0(1);
    let mut alice =
        SessionHandle::bootstrap_initiator(&okm, sid, epoch, DocFixture::ek_a_seed(), None, anchor);
    alice.recompute_anchor_commitment();
    alice
}

fn paired_sessions() -> (SessionHandle, SessionHandle) {
    let okm = handshake_okm();
    let sid = [0xabu8; 16];
    let epoch = 3u32;
    let anchor = DeviceStateAnchorV1::new_v0(1);
    let alice = SessionHandle::bootstrap_initiator(
        &okm,
        sid,
        epoch,
        DocFixture::ek_a_seed(),
        None,
        anchor.clone(),
    );
    let bob_ratchet_seed = std::array::from_fn(|i| (i + 1) as u8);
    let bob = SessionHandle::bootstrap_responder(
        &okm,
        sid,
        epoch,
        bob_ratchet_seed,
        Some(alice_ratchet_pub()),
        anchor,
    );
    (alice, bob)
}

#[test]
fn save_load_roundtrip() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let (mut alice, _) = paired_sessions();
    alice.recompute_anchor_commitment();
    store.save_session(&alice).unwrap();
    let loaded = store.load_session().unwrap();
    assert_eq!(
        SessionWalSource::send_wire_counter(&loaded),
        SessionWalSource::send_wire_counter(&alice),
    );
    assert!(verify_anchor(&loaded));
}

#[test]
fn wal_missing_fails_closed() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let (mut alice, _) = paired_sessions();
    alice.recompute_anchor_commitment();
    store.save_session(&alice).unwrap();
    std::fs::remove_file(store.envelope_path()).unwrap();
    assert!(matches!(store.load_session(), Err(StorageError::NoBundle)));
}

#[test]
fn stale_bundle_vs_trusted_meta_counter_rollback() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let (mut alice, _) = paired_sessions();
    alice.recompute_anchor_commitment();
    let stale = encode_bundle(&alice.export_state());

    let pt = data_inner_plaintext(1, 1, b"advance-counter").unwrap();
    alice.send_data_plain512(&pt).unwrap();
    alice.recompute_anchor_commitment();
    store.save_session(&alice).unwrap();

    let wal = std::fs::read(store.envelope_path()).unwrap();
    let (_old_b, meta) = decode_wal_envelope(&wal).unwrap();
    let new_wal = encode_wal_envelope(&stale, &meta);
    std::fs::write(store.envelope_path(), new_wal).unwrap();

    assert!(matches!(
        store.load_session(),
        Err(StorageError::RollbackDetected)
    ));
}

#[test]
fn epoch_rollback_detected() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let stale_bundle = encode_bundle(&alice_session_epoch(7).export_state());

    let alice_new = alice_session_epoch(8);
    store.save_session(&alice_new).unwrap();

    let wal = std::fs::read(store.envelope_path()).unwrap();
    let (_b, meta) = decode_wal_envelope(&wal).unwrap();
    std::fs::write(
        store.envelope_path(),
        encode_wal_envelope(&stale_bundle, &meta),
    )
    .unwrap();

    assert!(matches!(
        store.load_session(),
        Err(StorageError::RollbackDetected)
    ));
}

#[test]
fn corrupted_wal_fail_closed() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let (mut alice, _) = paired_sessions();
    alice.recompute_anchor_commitment();
    store.save_session(&alice).unwrap();

    std::fs::write(store.envelope_path(), b"not-a-wal").unwrap();
    assert!(matches!(
        store.load_session(),
        Err(StorageError::CorruptBlob)
    ));
}

#[test]
fn truncated_wal_corrupt() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let (mut alice, _) = paired_sessions();
    alice.recompute_anchor_commitment();
    store.save_session(&alice).unwrap();

    let bytes = std::fs::read(store.envelope_path()).unwrap();
    std::fs::write(
        store.envelope_path(),
        &bytes[..bytes.len().saturating_sub(9)],
    )
    .unwrap();
    assert!(matches!(
        store.load_session(),
        Err(StorageError::CorruptBlob)
    ));
}

#[test]
fn commitment_mismatch_fail_closed() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let (mut alice, _) = paired_sessions();
    alice.recompute_anchor_commitment();
    let mut exp = alice.export_state();
    exp.anchor.state_commitment[7] ^= 0x80;

    let meta = libgary_storage::TrustedAnchorMeta::from_wal_source(&alice);
    let wal = encode_wal_envelope(&encode_bundle(&exp), meta.encode().as_slice());
    std::fs::write(store.envelope_path(), wal).unwrap();

    assert!(matches!(
        store.load_session(),
        Err(StorageError::CommitmentMismatch)
    ));
}

#[test]
fn pre_decrypt_bundle_restored_after_decrypt_fails_closed() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let (mut alice, mut bob) = paired_sessions();
    let pt = data_inner_plaintext(1, 1, b"bob-should-see").unwrap();
    let (hdr, ct) = alice.send_data_plain512(&pt).unwrap();

    bob.recompute_anchor_commitment();
    let stale_bob = encode_bundle(&bob.export_state());

    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    bob.recv_data_plain512(&hdr, &ct, &mut rng).unwrap();
    bob.recompute_anchor_commitment();
    store.save_session(&bob).unwrap();

    let wal = std::fs::read(store.envelope_path()).unwrap();
    let (_b, meta) = decode_wal_envelope(&wal).unwrap();
    std::fs::write(
        store.envelope_path(),
        encode_wal_envelope(&stale_bob, &meta),
    )
    .unwrap();

    assert!(matches!(
        store.load_session(),
        Err(StorageError::CommitmentMismatch)
    ));
}

#[test]
fn global_epoch_rollback_detected() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let (alice_base, _) = paired_sessions();
    let mut exp9 = alice_base.export_state();
    exp9.anchor.global_epoch_be = 9;
    let mut alice = SessionHandle::from_export(exp9).unwrap();
    alice.recompute_anchor_commitment();
    let bundle_g9 = encode_bundle(&alice.export_state());

    let mut exp10 = alice.export_state();
    exp10.anchor.global_epoch_be = 10;
    alice = SessionHandle::from_export(exp10).unwrap();
    alice.recompute_anchor_commitment();
    store.save_session(&alice).unwrap();

    let wal = std::fs::read(store.envelope_path()).unwrap();
    let (_b, meta) = decode_wal_envelope(&wal).unwrap();
    std::fs::write(
        store.envelope_path(),
        encode_wal_envelope(&bundle_g9, &meta),
    )
    .unwrap();

    assert!(matches!(
        store.load_session(),
        Err(StorageError::RollbackDetected)
    ));
}

#[test]
fn interrupted_atomic_simulation_keeps_prior_wal_readable() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let (mut alice, _) = paired_sessions();
    alice.recompute_anchor_commitment();
    store.save_session(&alice).unwrap();
    let good = std::fs::read(store.envelope_path()).unwrap();

    std::fs::write(store.envelope_path(), &good[..20.min(good.len())]).unwrap();
    assert!(store.load_session().is_err());

    std::fs::write(store.envelope_path(), good).unwrap();
    assert!(store.load_session().is_ok());
}

#[test]
fn envelope_checksum_tamper_rejected() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let (mut alice, _) = paired_sessions();
    alice.recompute_anchor_commitment();
    store.save_session(&alice).unwrap();

    let mut wal = std::fs::read(store.envelope_path()).unwrap();
    let last = wal.len() - 1;
    wal[last] ^= 0x01;
    std::fs::write(store.envelope_path(), wal).unwrap();

    assert!(matches!(
        store.load_session(),
        Err(StorageError::CorruptBlob)
    ));
}

#[test]
fn session_identity_mismatch() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let (mut alice, _) = paired_sessions();
    alice.recompute_anchor_commitment();
    store.save_session(&alice).unwrap();

    let wal = std::fs::read(store.envelope_path()).unwrap();
    let (bundle, meta_bytes) = decode_wal_envelope(&wal).unwrap();
    let mut meta = libgary_storage::TrustedAnchorMeta::decode(&meta_bytes).unwrap();
    meta.session_id = [0xffu8; 16];
    let new_wal = encode_wal_envelope(&bundle, meta.encode().as_slice());
    std::fs::write(store.envelope_path(), new_wal).unwrap();

    assert!(matches!(
        store.load_session(),
        Err(StorageError::SessionIdentityMismatch)
    ));
}

#[test]
fn commit_anchor_matches_save_session() {
    let dir = tempdir().unwrap();
    let store = store_wal(&dir);
    let (mut alice, _) = paired_sessions();
    alice.recompute_anchor_commitment();
    store.commit_anchor(&alice).unwrap();
    assert!(store.load_session().is_ok());
}
