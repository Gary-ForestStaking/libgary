//! Authoritative end-to-end transcript (§ handshake wire § DATA § REKEY § RESET § WAL).
//!
//! Uses live [`OuterRecord`], [`RelayOuterEnvelope`], [`strip_outer_pad`]/[`pad_outer`],
//! and [`SessionStore`] (`LGW1` WAL).

#[path = "common/mod.rs"]
mod common;

use common::DocFixture;
use libgary_core::data::data_inner_plaintext;
use libgary_core::engine::mode::SessionMode;
use libgary_core::engine::{DeviceStateAnchorV1, SessionHandle};
use libgary_core::handshake::{
    decrypt_ack_inner, decrypt_init_inner, encrypt_ack_inner, encrypt_init_inner, nonce_ack,
    nonce_init,
};
use libgary_core::reset_handshake::{
    decrypt_reset_ack_inner, decrypt_reset_init_inner, encrypt_reset_ack_inner,
    encrypt_reset_init_inner, nonce_reset_ack, nonce_reset_init,
};
use libgary_core::session::{
    confirm_key, confirm_mac, ikm_session, okm_root_bootstrap, verify_confirm_mac,
};
use libgary_core::transcript::{th0, th0_reset, th1, th1_reset};
use libgary_core::x3dh::km_with_otp;
use libgary_storage::SessionStore;
use libgary_wire::{
    pad_outer, strip_outer_pad, Header, InitAckWire, OuterRecord, RelayOuterEnvelope,
};
use rand_chacha::ChaCha12Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use tempfile::tempdir;
use x25519_dalek::{PublicKey, StaticSecret};

const LOG_INIT: usize = 100 + 24 + 272;
const LOG_ACK: usize = 88 + 24 + 272;

fn alice_ratchet_pub() -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(DocFixture::ek_a_seed())).as_bytes()
}

fn bob_ratchet_pub(seed: &[u8; 32]) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(*seed)).as_bytes()
}

fn relay_roundtrip(opaque: Vec<u8>, rng: &mut (impl RngCore + CryptoRng)) -> Vec<u8> {
    let env = RelayOuterEnvelope {
        route_token: vec![0x01, 0x02, 0xfe],
        opaque_bytes: opaque,
    };
    let padded = env.encode_padded_wire(rng).unwrap();
    RelayOuterEnvelope::decode_padded_wire(&padded)
        .unwrap()
        .opaque_bytes
}

#[test]
fn full_transcript_happy_path() {
    let _alice_identity = DocFixture::alice_signing_key().verifying_key();
    let _bob_identity = DocFixture::bob_signing_key().verifying_key();

    let mut pad_rng = ChaCha12Rng::from_seed([0xA5u8; 32]);

    let epoch_hs = 0u32;
    let session_id_hs = [0x11u8; 16];

    let ik_a = StaticSecret::from(DocFixture::alice_ik_priv());
    let ek_a = StaticSecret::from(DocFixture::ek_a_seed());
    let ik_b_pub = PublicKey::from(&StaticSecret::from(DocFixture::bob_ik_priv()));
    let spk_b_pub = PublicKey::from(&StaticSecret::from(DocFixture::spk_b_seed()));
    let otp_b_pub = PublicKey::from(&StaticSecret::from(DocFixture::otp_b_seed()));
    let km = km_with_otp(&ik_a, &ek_a, &ik_b_pub, &spk_b_pub, &otp_b_pub);

    let init_body = DocFixture::init_body();
    let init_bytes = init_body.encode();
    let th0_d = th0(&init_bytes);

    let ct_init = encrypt_init_inner(&km, &th0_d, epoch_hs, &session_id_hs, &init_bytes).unwrap();
    let nn_init = nonce_init(&km, &th0_d, epoch_hs, &session_id_hs);
    let mut logical_init = Vec::with_capacity(LOG_INIT);
    logical_init.extend_from_slice(&init_bytes);
    logical_init.extend_from_slice(&nn_init);
    logical_init.extend_from_slice(&ct_init);
    assert_eq!(logical_init.len(), LOG_INIT);
    let pad_init = pad_outer(&logical_init, &mut pad_rng).unwrap();

    let hdr_init = Header {
        version: 1,
        typ: 0x01,
        flags: 0,
        epoch_be: epoch_hs,
        session_id: session_id_hs,
        counter_be: 0,
        ratchet_pub: alice_ratchet_pub(),
    };
    let outer_init = OuterRecord {
        header: hdr_init,
        payload: pad_init,
    }
    .encode()
    .unwrap();

    let outer_init = relay_roundtrip(outer_init, &mut pad_rng);

    let rec_init = OuterRecord::decode(&outer_init).unwrap();
    assert_eq!(rec_init.header.epoch_be, epoch_hs);
    assert_eq!(rec_init.header.session_id, session_id_hs);
    let strip_init = strip_outer_pad(&rec_init.payload, LOG_INIT).expect("INIT PAD strip");
    let bob_init_body: [u8; 100] = strip_init[0..100].try_into().unwrap();
    let ct_init_in = &strip_init[124..LOG_INIT];
    decrypt_init_inner(
        &km,
        &th0_d,
        epoch_hs,
        &session_id_hs,
        &bob_init_body,
        ct_init_in,
    )
    .unwrap();

    let core = DocFixture::init_ack_core();
    let th1_bob = th1(&th0_d, &core);
    let ikm_bob = ikm_session(&km, &th0_d, &th1_bob);
    let okm_bob = okm_root_bootstrap(&ikm_bob);
    let ck_bob = confirm_key(&okm_bob);
    let mac = confirm_mac(&ck_bob, &th1_bob);
    let wire = InitAckWire {
        core: core.clone(),
        confirm_mac: mac,
    };
    let wire_bytes = wire.encode();

    let ct_ack =
        encrypt_ack_inner(&okm_bob, &th1_bob, epoch_hs, &session_id_hs, &wire_bytes).unwrap();
    let nn_ack = nonce_ack(&okm_bob, epoch_hs, &session_id_hs);
    let mut logical_ack = Vec::with_capacity(LOG_ACK);
    logical_ack.extend_from_slice(&wire_bytes);
    logical_ack.extend_from_slice(&nn_ack);
    logical_ack.extend_from_slice(&ct_ack);
    let pad_ack = pad_outer(&logical_ack, &mut pad_rng).unwrap();

    let bob_rs = std::array::from_fn(|i| (i + 1) as u8);
    let hdr_ack = Header {
        version: 1,
        typ: 0x02,
        flags: 0,
        epoch_be: epoch_hs,
        session_id: session_id_hs,
        counter_be: 0,
        ratchet_pub: bob_ratchet_pub(&bob_rs),
    };
    let outer_ack = OuterRecord {
        header: hdr_ack,
        payload: pad_ack,
    }
    .encode()
    .unwrap();

    let outer_ack = relay_roundtrip(outer_ack, &mut pad_rng);
    let rec_ack = OuterRecord::decode(&outer_ack).unwrap();
    let strip_ack = strip_outer_pad(&rec_ack.payload, LOG_ACK).unwrap();
    let wire_recv: [u8; 88] = strip_ack[0..88].try_into().unwrap();
    let wire_parsed = InitAckWire::decode(&wire_recv);
    let th1_alice = th1(&th0_d, &wire_parsed.core);
    let ikm_alice = ikm_session(&km, &th0_d, &th1_alice);
    let okm_alice = okm_root_bootstrap(&ikm_alice);
    let ck_alice = confirm_key(&okm_alice);
    assert!(verify_confirm_mac(
        &ck_alice,
        &th1_alice,
        &wire_parsed.confirm_mac
    ));

    let ct_ack_in = &strip_ack[112..LOG_ACK];
    decrypt_ack_inner(
        &okm_alice,
        epoch_hs,
        &session_id_hs,
        &wire_recv,
        ct_ack_in,
    )
    .unwrap();

    assert_eq!(okm_alice, okm_bob);

    let anchor = DeviceStateAnchorV1::new_v0(1);
    let mut alice = SessionHandle::bootstrap_initiator(
        &okm_alice,
        session_id_hs,
        epoch_hs,
        DocFixture::ek_a_seed(),
        Some(bob_ratchet_pub(&bob_rs)),
        anchor.clone(),
    );
    let mut bob = SessionHandle::bootstrap_responder(
        &okm_alice,
        session_id_hs,
        epoch_hs,
        bob_rs,
        Some(alice_ratchet_pub()),
        anchor,
    );
    alice.recompute_anchor_commitment();
    bob.recompute_anchor_commitment();

    let dir = tempdir().unwrap();
    let store = SessionStore::new(dir.path().join("state.wal"));
    store.save_session(&alice).unwrap();
    alice = store.load_session().unwrap();

    let pt_a = data_inner_plaintext(1, 1, b"hello-full-transcript").unwrap();
    let (hdr_d0, pay_d0) = alice
        .send_data_plain512_outer(&pt_a, &mut pad_rng)
        .unwrap();
    let out_d0 = OuterRecord {
        header: hdr_d0,
        payload: pay_d0,
    }
    .encode()
    .unwrap();
    let rec_d0 = OuterRecord::decode(&out_d0).unwrap();
    let mut rng_b = ChaCha12Rng::from_seed([0x3Cu8; 32]);
    let pt_bob = bob
        .recv_data_outer(&rec_d0.header, &rec_d0.payload, &mut rng_b)
        .unwrap();
    assert_eq!(pt_a.as_slice(), pt_bob.as_slice());

    let pt_b = data_inner_plaintext(1, 1, b"reply-from-bob").unwrap();
    let (hdr_d1, pay_d1) = bob.send_data_plain512_outer(&pt_b, &mut pad_rng).unwrap();
    let out_d1 = OuterRecord {
        header: hdr_d1,
        payload: pay_d1,
    }
    .encode()
    .unwrap();
    let rec_d1 = OuterRecord::decode(&out_d1).unwrap();
    let mut rng_a = ChaCha12Rng::from_seed([0xC3u8; 32]);
    let pt_alice = alice
        .recv_data_outer(&rec_d1.header, &rec_d1.payload, &mut rng_a)
        .unwrap();
    assert_eq!(pt_b.as_slice(), pt_alice.as_slice());

    let rekey_body = [0xdeu8, 0xadu8, 0xbeu8, 0xefu8];
    let (hdr_rk, pay_rk) = bob
        .send_rekey_ctrl_outer(&rekey_body, &mut pad_rng)
        .unwrap();
    let out_rk = OuterRecord {
        header: hdr_rk,
        payload: pay_rk,
    }
    .encode()
    .unwrap();
    let rec_rk = OuterRecord::decode(&out_rk).unwrap();
    let mut rng_ra = ChaCha12Rng::from_seed([0x77u8; 32]);
    let plain_ctrl = alice
        .recv_rekey_ctrl_outer(&rec_rk.header, &rec_rk.payload, &mut rng_ra)
        .unwrap();
    assert_eq!(&plain_ctrl[..4], &rekey_body);

    // RESET handshake → fresh `(session_id, epoch)` ratchet.
    let epoch_new = epoch_hs.saturating_add(1);
    let sid_new = [0x22u8; 16];
    let ek_reset = StaticSecret::from([0x88u8; 32]);
    let mut rb = DocFixture::init_body();
    rb.ephemeral_ek_pub = *PublicKey::from(&ek_reset).as_bytes();
    rb.otp_index_be = 1;

    let rb_enc = rb.encode();
    let th0_r = th0_reset(&rb_enc);
    let km_r = km_with_otp(&ik_a, &ek_reset, &ik_b_pub, &spk_b_pub, &otp_b_pub);

    let ct_rinit =
        encrypt_reset_init_inner(&km_r, &th0_r, epoch_new, &sid_new, &rb_enc).unwrap();
    let nn_rinit = nonce_reset_init(&km_r, &th0_r, epoch_new, &sid_new);
    let mut logical_rinit = Vec::with_capacity(LOG_INIT);
    logical_rinit.extend_from_slice(&rb_enc);
    logical_rinit.extend_from_slice(&nn_rinit);
    logical_rinit.extend_from_slice(&ct_rinit);
    let pad_rinit = pad_outer(&logical_rinit, &mut pad_rng).unwrap();

    let alice_reset_sk = [0xAAu8; 32];
    let hdr_rinit = Header {
        version: 1,
        typ: 0x07,
        flags: 0,
        epoch_be: epoch_new,
        session_id: sid_new,
        counter_be: 0,
        ratchet_pub: bob_ratchet_pub(&alice_reset_sk),
    };
    let outer_rinit = OuterRecord {
        header: hdr_rinit,
        payload: pad_rinit,
    }
    .encode()
    .unwrap();
    let outer_rinit = relay_roundtrip(outer_rinit, &mut pad_rng);

    let rec_rinit = OuterRecord::decode(&outer_rinit).unwrap();
    let strip_rinit = strip_outer_pad(&rec_rinit.payload, LOG_INIT).unwrap();
    let rb_body: [u8; 100] = strip_rinit[0..100].try_into().unwrap();
    let ct_rin = &strip_rinit[124..LOG_INIT];
    decrypt_reset_init_inner(&km_r, &th0_r, epoch_new, &sid_new, &rb_body, ct_rin).unwrap();

    let mut core_r = DocFixture::init_ack_core();
    core_r.ack_nonce_be = 0x42;
    let th1_r_bob = th1_reset(&th0_r, &core_r);
    let ikm_r_bob = ikm_session(&km_r, &th0_r, &th1_r_bob);
    let okm_r_bob = okm_root_bootstrap(&ikm_r_bob);
    let mac_r = confirm_mac(&confirm_key(&okm_r_bob), &th1_r_bob);
    let wire_r = InitAckWire {
        core: core_r.clone(),
        confirm_mac: mac_r,
    };
    let wb_r = wire_r.encode();
    let ct_rack =
        encrypt_reset_ack_inner(&okm_r_bob, &th1_r_bob, epoch_new, &sid_new, &wb_r).unwrap();
    let nn_rack = nonce_reset_ack(&okm_r_bob, epoch_new, &sid_new);
    let mut logical_rack = Vec::with_capacity(LOG_ACK);
    logical_rack.extend_from_slice(&wb_r);
    logical_rack.extend_from_slice(&nn_rack);
    logical_rack.extend_from_slice(&ct_rack);
    let pad_rack = pad_outer(&logical_rack, &mut pad_rng).unwrap();

    let bob_reset_sk = [0xBBu8; 32];
    let hdr_rack = Header {
        version: 1,
        typ: 0x08,
        flags: 0,
        epoch_be: epoch_new,
        session_id: sid_new,
        counter_be: 0,
        ratchet_pub: bob_ratchet_pub(&bob_reset_sk),
    };
    let outer_rack = OuterRecord {
        header: hdr_rack,
        payload: pad_rack,
    }
    .encode()
    .unwrap();
    let outer_rack = relay_roundtrip(outer_rack, &mut pad_rng);

    let rec_rack = OuterRecord::decode(&outer_rack).unwrap();
    let strip_rack = strip_outer_pad(&rec_rack.payload, LOG_ACK).unwrap();
    let wire_r_recv: [u8; 88] = strip_rack[0..88].try_into().unwrap();
    let wp = InitAckWire::decode(&wire_r_recv);
    let th1_r_alice = th1_reset(&th0_r, &wp.core);
    let ikm_r_alice = ikm_session(&km_r, &th0_r, &th1_r_alice);
    let okm_r_alice = okm_root_bootstrap(&ikm_r_alice);
    assert!(verify_confirm_mac(
        &confirm_key(&okm_r_alice),
        &th1_r_alice,
        &wp.confirm_mac
    ));

    let ct_rack_in = &strip_rack[112..LOG_ACK];
    decrypt_reset_ack_inner(
        &okm_r_alice,
        epoch_new,
        &sid_new,
        &wire_r_recv,
        ct_rack_in,
    )
    .unwrap();
    assert_eq!(okm_r_alice, okm_r_bob);

    let anchor2 = DeviceStateAnchorV1::new_v0(2);
    alice = SessionHandle::bootstrap_initiator(
        &okm_r_alice,
        sid_new,
        epoch_new,
        alice_reset_sk,
        Some(bob_ratchet_pub(&bob_reset_sk)),
        anchor2.clone(),
    );
    bob = SessionHandle::bootstrap_responder(
        &okm_r_alice,
        sid_new,
        epoch_new,
        bob_reset_sk,
        Some(bob_ratchet_pub(&alice_reset_sk)),
        anchor2,
    );

    // Production RESET lifecycle (ingress policy): isolate prior epoch, then commit to Active.
    alice
        .enter_reset_pending_after_rebootstrap(epoch_hs, None)
        .unwrap();
    bob.enter_reset_pending_after_rebootstrap(epoch_hs, None).unwrap();
    alice.reset_pending_to_bootstrapping().unwrap();
    bob.reset_pending_to_bootstrapping().unwrap();
    alice.finish_reset_half_open_to_active().unwrap();
    bob.finish_reset_half_open_to_active().unwrap();

    assert!(matches!(
        alice.ingress_mode(),
        SessionMode::Active { epoch } if epoch == epoch_new
    ));
    assert!(matches!(
        bob.ingress_mode(),
        SessionMode::Active { epoch } if epoch == epoch_new
    ));

    alice.recompute_anchor_commitment();
    bob.recompute_anchor_commitment();

    store.save_session(&alice).unwrap();
    alice = store.load_session().unwrap();
    // v0 ratchet blob does not persist `SessionMode`; reload is always [`SessionMode::Active`].
    assert!(matches!(
        alice.ingress_mode(),
        SessionMode::Active { epoch } if epoch == epoch_new
    ));

    let pt_post = data_inner_plaintext(1, 1, b"post-reset-epoch").unwrap();
    let (hd, py) = alice
        .send_data_plain512_outer(&pt_post, &mut pad_rng)
        .unwrap();
    let outer_post = OuterRecord {
        header: hd,
        payload: py,
    }
    .encode()
    .unwrap();
    let rp = OuterRecord::decode(&outer_post).unwrap();
    let mut rng_final = ChaCha12Rng::from_seed([0x99u8; 32]);
    let got = bob
        .recv_data_outer(&rp.header, &rp.payload, &mut rng_final)
        .unwrap();
    assert_eq!(pt_post.as_slice(), got.as_slice());
}
