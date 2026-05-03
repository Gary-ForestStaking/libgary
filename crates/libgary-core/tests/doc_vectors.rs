//! Bytes lifted from `docs/test-vectors.md` — implementations **must** match.

mod common;

use common::DocFixture;
use ed25519_dalek::{Signature, VerifyingKey};
use libgary_core::{
    control::{ctrl_inner_padded256, encrypt_ctrl_payload},
    data::{data_inner_plaintext, encrypt_data_payload},
    engine::{DeviceStateAnchorV1, SessionError, SessionHandle, SessionWalSource},
    handshake::{decrypt_ack_inner, decrypt_init_inner, encrypt_ack_inner, encrypt_init_inner},
    identity::{account_id, safety_number},
    ratchet::{chain_bootstrap, dh_mix, msg_step},
    session::{confirm_key, confirm_mac, ikm_session, okm_root_bootstrap, verify_confirm_mac},
    transcript::{th0, th1},
    x3dh::km_with_otp,
};
use libgary_wire::{Header, InitAckWire, OuterRecord};
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use x25519_dalek::{PublicKey, StaticSecret};

fn hb(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// VECTOR 001 / 002 — full `OuterRecord` wire bytes (67 B): DATA, `epoch_be=6`, empty payload.
const DOC_VECTOR_001_STALE_DATA_OUTER_HEX: &str = concat!(
    "0000003f0103000000000601010101010101010101010101010101",
    "00000000000000000202020202020202020202020202020202020202020202020202020202020202"
);

const DOC_VECTOR_001_GOLDEN_PERSISTENCE_DIGEST_HEX: &str =
    "ccf1a632cc36524036d11270ee1e8965a5313927db009fafef5acf3ae50425da";

fn handshake_okm_doc_fixture() -> [u8; 64] {
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

/// Shared responder session for stale-epoch policy vectors (`docs/test-vectors.md` VECTOR 001–002).
fn doc_epoch_policy_fixture_responder() -> SessionHandle {
    let okm = handshake_okm_doc_fixture();
    let session_id = [0x01u8; 16];
    let epoch = 7u32;
    let anchor = DeviceStateAnchorV1::new_v0(901);
    let bob_sk = std::array::from_fn(|i| i.wrapping_add(3) as u8);
    let alice_rp = *PublicKey::from(&StaticSecret::from(DocFixture::ek_a_seed())).as_bytes();

    let mut bob =
        SessionHandle::bootstrap_responder(&okm, session_id, epoch, bob_sk, Some(alice_rp), anchor);
    bob.recompute_anchor_commitment();
    bob
}

#[test]
fn doc_identity_and_safety() {
    let alice_pk = *DocFixture::alice_signing_key().verifying_key().as_bytes();
    let bob_pk = *DocFixture::bob_signing_key().verifying_key().as_bytes();
    assert_eq!(
        hb("dc9834c4f3d675265dc71e013ae03c366e6841fb02ed4cddf9ccf3c66262d53e"),
        alice_pk.to_vec()
    );
    assert_eq!(
        hb("78e60152ea1f542c22b8f16997a7e96726e6cb58640bbf5afdf9e6d302ba1adf"),
        bob_pk.to_vec()
    );
    let aid = account_id(&bob_pk);
    assert_eq!(
        hb("e2d456b446fff2087a185449cf8291ecd643dcb006efd9150baca63afb11f99f"),
        aid.to_vec()
    );

    let sn = safety_number(
        &alice_pk,
        &bob_pk,
        &DocFixture::alice_spk_pub(),
        &DocFixture::bob_signed_prekey_pub(),
    );
    assert_eq!(
        hb("827b1e786e5294ee3ce31d95e40d22cb3dfafbfc514a03ef8f64eb625ee74074"),
        sn.to_vec()
    );
}

#[test]
fn doc_handshake_transcript_okm_and_inner_aead() {
    let ik_a = StaticSecret::from(DocFixture::alice_ik_priv());
    let ek_a = StaticSecret::from(DocFixture::ek_a_seed());
    let ik_b_pub = PublicKey::from(&StaticSecret::from(DocFixture::bob_ik_priv()));
    let spk_b_pub = PublicKey::from(&StaticSecret::from(DocFixture::spk_b_seed()));
    let otp_b_pub = PublicKey::from(&StaticSecret::from(DocFixture::otp_b_seed()));
    let km = km_with_otp(&ik_a, &ek_a, &ik_b_pub, &spk_b_pub, &otp_b_pub);
    assert_eq!(
        hb(
            "20b14b1e47fc8831c97122520966cde964d4bfda35778781a8957068f439b9490796ffb2cd8c723b7cf6e2331e8dfe063b072f1b182df818452814cf3c608e79c32111649419ddaec41c391912b6aa528fc8184f3219958282acaf8dcad1ec6d200af6990e294c94695dc39e6e33ebf6ab3314bc73b16000b2718f52de9d5e6b"
        ),
        km.to_vec()
    );

    let init = DocFixture::init_body();
    let init_bytes = init.encode();
    assert_eq!(
        hb(
            "dc9834c4f3d675265dc71e013ae03c366e6841fb02ed4cddf9ccf3c66262d53e8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6aa736bf0fdc88494658777e47d321926950d321c3c98cbfa108ead46ba84ed25d00000000"
        ),
        init_bytes.to_vec()
    );

    let th0_d = th0(&init_bytes);
    assert_eq!(
        hb("3e4342a8d747665cdfd1c9eee3144838bd197d293c158755afafd1c97c1ac75f"),
        th0_d.to_vec()
    );

    let core = DocFixture::init_ack_core();
    let core_bytes = core.encode();
    assert_eq!(
        hb(
            "78e60152ea1f542c22b8f16997a7e96726e6cb58640bbf5afdf9e6d302ba1adfde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f0000000000000001"
        ),
        core_bytes.to_vec()
    );

    let th1_d = th1(&th0_d, &core);
    assert_eq!(
        hb("edb88fb5aa3c9fe2c01a78c79f17cc69ceed8e0a21886de6205b712aab4544a1"),
        th1_d.to_vec()
    );

    let ikm = ikm_session(&km, &th0_d, &th1_d);
    assert_eq!(
        hb(
            "20b14b1e47fc8831c97122520966cde964d4bfda35778781a8957068f439b9490796ffb2cd8c723b7cf6e2331e8dfe063b072f1b182df818452814cf3c608e79c32111649419ddaec41c391912b6aa528fc8184f3219958282acaf8dcad1ec6d200af6990e294c94695dc39e6e33ebf6ab3314bc73b16000b2718f52de9d5e6b3e4342a8d747665cdfd1c9eee3144838bd197d293c158755afafd1c97c1ac75fedb88fb5aa3c9fe2c01a78c79f17cc69ceed8e0a21886de6205b712aab4544a1"
        ),
        ikm
    );

    let okm = okm_root_bootstrap(&ikm);
    assert_eq!(
        hb(
            "4bc45cc7fddf45d3e624d78e3805aa9f06309548b48d7a6dc382b950544930b0ca94f844ddf80d7c208a9b8c0345c87a63f9d5d46279df66972ed22406997130"
        ),
        okm.to_vec()
    );

    let ck = confirm_key(&okm);
    let mac = confirm_mac(&ck, &th1_d);
    assert_eq!(hb("ad1ce2031766bdf115511283f4b3c56e"), mac.to_vec());
    assert!(verify_confirm_mac(&ck, &th1_d, &mac));

    let wire = InitAckWire {
        core: core.clone(),
        confirm_mac: mac,
    };
    let wire_bytes = wire.encode();
    assert_eq!(
        hb(
            "78e60152ea1f542c22b8f16997a7e96726e6cb58640bbf5afdf9e6d302ba1adfde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f0000000000000001ad1ce2031766bdf115511283f4b3c56e"
        ),
        wire_bytes.to_vec()
    );

    let epoch = 0u32;
    let session_id = [0u8; 16];

    let ct_init = encrypt_init_inner(&km, &th0_d, epoch, &session_id, &init_bytes).unwrap();
    assert_eq!(
        hb(
            "8164e665bc7f82ba04acf11862b29f018307d135cdb00dfd34e3e061d40d5179e0664dee766b9d4436e914e52a610c29e4e2ac0d331fb144ac8bf9d14fb8ba042931dbdc3ab1629dd5af5b03f26332e2a625ac544912459af91c4b5fdcfd86b1b8370db76e7bf0f0e34d3d6db454c10f816a3c5a56b9cd4c1e377c35014a1f3c084f1e2bc29847f8684d96e24b607b1f76f167ea269eea244d260a188a01a4ee72850a325911c8aa4e45bae8311d6bd690824e281645d136d0d210f1af792dd2ad7297fca5bfd6a721faea24d7847260f7969e3324b4f8e510de23d7cad95a4c40984aa4b93273eed98e7c94ac1c35adf9cfdb9f418d7bb3e8baa7e87f08124ede54d48b0dfe74b19fdc23238803d6a4"
        ),
        ct_init
    );

    let pt_init =
        decrypt_init_inner(&km, &th0_d, epoch, &session_id, &init_bytes, &ct_init).unwrap();
    assert_eq!(
        hb(
            "cf2a47dd699f3a6f77b964b175f6deb88332d55526c8f16a63060e8b838f9a8a709a09d7fef62c4c069746bf84064cf9ea72bf299f2ba4cbc30b41a7aa3c288d6ce9cbde6f57b2fcaa0ff2ce11de374977f7210e44cd2bb886478302d9f2fc7fe3d8fcee40e3c7b73ed2b1d255be11ce7c4e26c144845f9b8862ffde61310db177907020b300ccecc4ba1f89b87af08f3f4a2ca346ec67d834923c821ef18b970d1546690cd4ba0cabda5acf62e9393b60a5680992a837c85afa29552bed53591dca277a9f66c116fbfdf39de9ab3bf351561e63e675f243b1326d7f8c0344be7c920f9bcf40dbb762958900c8cce42c094ad930d1fcbaa2d5f6acf691251803"
        ),
        pt_init.to_vec()
    );

    let ct_ack = encrypt_ack_inner(&okm, &th1_d, epoch, &session_id, &wire_bytes).unwrap();
    assert_eq!(
        hb(
            "5569956315464218fcec3c41206e79425fbcc374b2708a2b1858c90daf63ba1fa476149dd0052adee2a16eea6d5cf1c43d7edc5dfb82624fcd88f88f817425168835df57b97c08615a42f5a86a841dd5cfe51abb195d2053709c98527326bfb04c6185fb46ea794f97949f90ab0671a75193dcb7c4d94ef0f168b5ce31804ec0bdd834f7023471ee48516bea999bd2e73c8cb5fa9655d6d505b3b1c4c60c2ba4588be38aad42a9a9f3536983c6839f97179e0070109cf3181a68f88fbf8845457aeb16b6c8cd6a447f09293d304e3e38b750406a0d7871e075792850973f494af6fa6423be454a539774d2760b41f22dd187ba9816b85b7d154928a05b49558315e56a47b2d95f0012c21b5b02e35830"
        ),
        ct_ack
    );

    let pt_ack = decrypt_ack_inner(&okm, epoch, &session_id, &wire_bytes, &ct_ack).unwrap();
    assert_eq!(
        hb(
            "024e35f935a0fc1641e3b37380fc519c9ca62653a2453f8ff5e335e38d32d507d661db235c3492c298d5420bdf7cb4443125b94bbaeac7a765f2867461c9c2e8f88005c86f60c33cec52c1f3d559840e5d21f1d9c5ea54b2274bc42a4ae74f98bb86ca21a20d9fd8ba3a1b0b222f6b3beb6a7a2c170b99589f1db08c4c5b10c4406a03933adf2e81a681b8139557a9166c8340cd2c8260fe2440f5fff27017ee3d7eb4aabfb2a755844e0be024589174fe1ede89a7a4032be35e0269f369b44d89982e0bf1b81bccf256c365fae6f6be93ef3af96879ff07d3e5253ccd6f227995bc63710e9a3fc873ff44540a3d52e6da10bd8f5d0474b3ef1487760ff8a16a"
        ),
        pt_ack.to_vec()
    );
}

#[test]
fn doc_ratchet_chain_and_data_rekey() {
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
    let okm = okm_root_bootstrap(&ikm);

    let root_key: [u8; 32] = okm[0..32].try_into().unwrap();
    let bootstrap_key: [u8; 32] = okm[32..64].try_into().unwrap();
    assert_eq!(
        hb("4bc45cc7fddf45d3e624d78e3805aa9f06309548b48d7a6dc382b950544930b0"),
        root_key.to_vec()
    );
    assert_eq!(
        hb("ca94f844ddf80d7c208a9b8c0345c87a63f9d5d46279df66972ed22406997130"),
        bootstrap_key.to_vec()
    );

    let (cks, ckr) = chain_bootstrap(&bootstrap_key);
    assert_eq!(
        hb("3fcdafa0cdeef755c8a8b8fb8a2b699ef3a42c19c1972ebfd3ceb8c9d2939cf7"),
        cks.to_vec()
    );
    assert_eq!(
        hb("96d64b84fe5c5485cdfac12ebc24fe75f8c3d9ebffc042db7ef1369dd782c822"),
        ckr.to_vec()
    );

    let (mk0, ck_after_0) = msg_step(&cks, 0);
    assert_eq!(
        hb("03c46aa996f2b1b52d1766c33deefac08766d0680d699fab69b40425f3904c34"),
        mk0.to_vec()
    );
    assert_eq!(
        hb("ce885340944c09bfe5a726aa44f69bb761a36d99e7111a177ce46d585372a5a4"),
        ck_after_0.to_vec()
    );

    let (mk1, ck_after_1) = msg_step(&ck_after_0, 1);
    assert_eq!(
        hb("45d396b7bfed81fac3d8fd2a98f8b34b18662965730d2dc2f002b037354d3a77"),
        mk1.to_vec()
    );
    assert_eq!(
        hb("78af6ff20e16da9289489c4c98c0eaf444cf74e508a332434de7c1f44beb1fac"),
        ck_after_1.to_vec()
    );

    let dh_out: [u8; 32] = [0x42; 32];
    let (rk_new, mix_a, mix_b) = dh_mix(&root_key, &dh_out);
    assert_eq!(
        hb("0e61f833f852599800ac5d30b95bd60c727c79dfaaa8c12dcce3c729958a9504"),
        rk_new.to_vec()
    );
    assert_eq!(
        hb("3be4381c6bee8458764d539db87dff251a8e370459f43ba95c3ae35ce03ac017"),
        mix_a.to_vec()
    );
    assert_eq!(
        hb("8ba43e53a73754241c549e90ddbb8dc0ba630692c83dafd79f25b442704de4f0"),
        mix_b.to_vec()
    );

    let ratchet_pub_after = DocFixture::ratchet_pub_after_dh();
    assert_eq!(
        hb("a4416520f8bd7d3383c7d8c2cbd090e1d8ab3c2cbde0b7f954aa541b0320a242"),
        ratchet_pub_after.to_vec()
    );

    let (mk_post_dh, ck_post_first) = msg_step(&mix_a, 0);
    assert_eq!(
        hb("f0d27ea5846ff24ef9d07945f86d9d7c4d3a65180a0d343682cffcdfe79ca7c9"),
        mk_post_dh.to_vec()
    );
    assert_eq!(
        hb("fd2fafcd3ae50892127ed5d0edb83b8a8c265e1256b82737167fc568dcc737af"),
        ck_post_first.to_vec()
    );

    let epoch = 0u32;
    let session_id = [0u8; 16];
    let ratchet_pub0 = *PublicKey::from(&StaticSecret::from(DocFixture::ek_a_seed())).as_bytes();

    let hdr0 = Header {
        version: 1,
        typ: 0x03,
        flags: 0,
        epoch_be: epoch,
        session_id,
        counter_be: 0,
        ratchet_pub: ratchet_pub0,
    };
    assert_eq!(
        hb(
            "01030000000000000000000000000000000000000000000000000000000000a736bf0fdc88494658777e47d321926950d321c3c98cbfa108ead46ba84ed25d"
        ),
        hdr0.encode().to_vec()
    );

    let pt0 = data_inner_plaintext(1, 1, b"hello-libgary-v0").unwrap();
    let ct0 = encrypt_data_payload(&mk0, &hdr0, &pt0).unwrap();
    assert_eq!(
        hb(
            "5b6750a07c2d2b5677904e227d8718f1a28177cf3e02b6e6d9fc9f6eee63486869d9a7f3705c3498817bd180457f722a8c7b28bec1925bd97611578ff09255e4931857d9e644d32dc1447960ec3d89fd22e87716bdf97ba6592228874b98ace467995493215b1a4950b7366883be7990610a4db2d928fdd83f440497e8c2791685b17610f618c2a9df3771c4e2748ba8687200cc0bd293ac3c82f44d1767ebccf0f591d4a0272dd3589225708b56ac223c82f357f134c56e162fb1f089b39fb128edea9a6a5b7f5b10b5e3abba10a7993c8822efd389e585f91cb87a2e29fb8817fa414bdef286439be4b1d9159cfc6e3239a2ea884b43699c84de34676557f82ac019256fb3a40adbd08e03585a71a09525bc7619a283a569c5c88d44f99eda48ed02d01069216ea9124d60445a21aaa2346261694cac236652d8fdd7f68eaa104eb80da1d032c91c2607929f9d5f1f8687a0e90873051ebb7aee113053e0d9e3d5d7df99af9c9545852516daad6721dc6e12480357be85ed540df8b8b7e45786503403b80590db7c46f90d866946c7773c2a20956368a9deb857db86da8c74b81498268a81243c77856ccc6e476c5a90bd7ad6aa67036ae5778e20b29e3c9c52fbdcde92a166a33663408383ac8517ad00fed75e323514fd938711eca6dcf923e2eebece9d9f3e110932d1033a50e3a7c12016c59e4f906c81dd17a6446c064d1f275e7369b9b6e41239cf51131f7e"
        ),
        ct0
    );

    let hdr1 = Header {
        version: 1,
        typ: 0x03,
        flags: 0,
        epoch_be: epoch,
        session_id,
        counter_be: 1,
        ratchet_pub: ratchet_pub_after,
    };
    let pt1 = data_inner_plaintext(1, 1, b"second-msg-vector").unwrap();
    let ct1 = encrypt_data_payload(&mk_post_dh, &hdr1, &pt1).unwrap();
    assert_eq!(
        hb(
            "df1092bdaa1cebea3f39a9c714fcf72ad653dad230b09993cd37d3573ead173c9593f115ef2027c1f134464094504c7641278dc6c30b3efd7e74d460b3859d309c840c33dc23aa912f5cd96d0ce815f7fcc5b24e9b8f49b71b97687b6437fcb87333e36ca98b23253ff3be51235edfc84dfccd50571d2f5e37f2446fec8fb8ffbaa2f9c6f0a3dfdc7732b913f604a8b382840e682d8691682e34d041f181bf4e8e1c9d4f9e15bfabedf342ddb68b5de2717d81e49536cf914abc4e9fa122be2c33065ecfdb59400959c7b15b9dfe203dbf2037b06b0eee37646b8626afeaaea68923793f717cc930cd46812f070a8083fabac0ee8f4dc10d1b1489f90580abc5f96e0a34cf7395b0e29ef1e05b376f0af2e360c5da8581fedfaed4ff58781479f7a95520a4f113cf361aa2f5a14d9c8f31d6e1d60fb8e7ba69a67639dd46d3de2e9d54134c7990db4484b34cbcf068c07b2a7b7ad509aefb82c3987ba302fc38ec1769ddf657f6cc422b7e9290397cc2396095f905b4acfd6bf295fcd43ef030f7e56bc0989e5e61bf755738464f77b44ea55c0435ec6510b00750f99c2b135bc8936217620027d5b2024c7e6cb0c81b0726f5893784f7bf41cb2f64425f9b1b689ce0bc810746d108e8275452b97fc23d457d4737e14a338f49c02e97607944aa351c99e7363e7f058104230a1c25ff59f0b35f6850a5496079d214ae4ebb9eb2926e343ae1706d3d432715b9e5b53d"
        ),
        ct1
    );

    let hdr_rekey = Header {
        version: 1,
        typ: 0x05,
        flags: 0,
        epoch_be: epoch,
        session_id,
        counter_be: 2,
        ratchet_pub: ratchet_pub_after,
    };
    let body_rekey = [0u8, 1, 0, 0];
    let plain_rekey = ctrl_inner_padded256(&body_rekey).unwrap();
    let ct_rekey = encrypt_ctrl_payload(&okm, &hdr_rekey, &plain_rekey).unwrap();
    assert_eq!(
        hb(
            "e7304997b3f9b1d1fa148208ddd8094bee1ada0fb4e7fab2e2472f6630d2ea703f68544139752838ffd057197bdcb068ca1b591fd3f1e487136e297126e35b2748515426a1cf30403ac481562210c8ed2d1ac0fd901a14e26114165effc9cb6d8c0bf4544d055a359c1111552c05c5a1361b2a990cea126c654c610cec5b681aa71e35da8910e98243cce2a881c124bd2854e5e4b628833d2116df0a936baa5c667bd8cc9bb97e3d8c5853ee36a046526fd6aefcf317d41d51cf7bdab911ffe6777168459a229545bd102ff0ad1b186779532ff6a0326896585918a2e334f68ec3f30c8b7207905b5823e21cb4bebad00d0216380f83832c9921e8499f6f1f1fa862a225833fe6ef83b2587eabb2cb70"
        ),
        ct_rekey
    );
}

#[test]
fn doc_epoch_policy_stale_data_vector_001() {
    let mut bob = doc_epoch_policy_fixture_responder();

    let before_digest = bob.persistence_equivalence_digest();
    let before_epoch = SessionWalSource::epoch(&bob);
    let before_session_id = SessionWalSource::session_id(&bob);

    assert_eq!(
        hex::encode(before_digest),
        DOC_VECTOR_001_GOLDEN_PERSISTENCE_DIGEST_HEX
    );

    let wire = hb(DOC_VECTOR_001_STALE_DATA_OUTER_HEX);
    let rec = OuterRecord::decode(&wire).expect("DOC_VECTOR_001 OuterRecord");

    let mut rng = ChaCha12Rng::from_seed([0x99u8; 32]);
    let err = bob
        .handle_inbound_outer(rec, 0, &mut rng)
        .expect_err("stale Header.epoch_be must reject before decrypt");

    assert!(matches!(err, SessionError::StaleEpochRejected));
    assert_eq!(SessionWalSource::epoch(&bob), before_epoch);
    assert_eq!(SessionWalSource::session_id(&bob), before_session_id);
    assert_eq!(
        bob.persistence_equivalence_digest(),
        before_digest,
        "epoch gate must not mutate WAL-visible export preimage"
    );
}

#[test]
fn doc_epoch_policy_stale_data_repeated_vector_002() {
    const N: usize = 64;

    let mut bob = doc_epoch_policy_fixture_responder();
    let before_digest = bob.persistence_equivalence_digest();
    let before_epoch = SessionWalSource::epoch(&bob);
    let before_session_id = SessionWalSource::session_id(&bob);

    assert_eq!(
        hex::encode(before_digest),
        DOC_VECTOR_001_GOLDEN_PERSISTENCE_DIGEST_HEX
    );

    let wire = hb(DOC_VECTOR_001_STALE_DATA_OUTER_HEX);
    let template = OuterRecord::decode(&wire).expect("DOC_VECTOR_001 OuterRecord");

    for i in 0..N {
        let mut rng = ChaCha12Rng::from_seed([0x99u8; 32]);
        let err = bob
            .handle_inbound_outer(template.clone(), 0, &mut rng)
            .expect_err("each stale envelope must reject identically");
        assert_eq!(err, SessionError::StaleEpochRejected, "iteration {i}");
        assert_eq!(SessionWalSource::epoch(&bob), before_epoch, "iteration {i}");
        assert_eq!(
            SessionWalSource::session_id(&bob),
            before_session_id,
            "iteration {i}"
        );
        assert_eq!(
            bob.persistence_equivalence_digest(),
            before_digest,
            "iteration {i}"
        );
    }
}

#[test]
fn doc_bob_prekey_bundle_signature() {
    let vk_bytes: [u8; 32] = hb("78e60152ea1f542c22b8f16997a7e96726e6cb58640bbf5afdf9e6d302ba1adf")
        .try_into()
        .unwrap();
    let vk = VerifyingKey::from_bytes(&vk_bytes).expect("Bob IK_sig_ed");
    let transcript = hb(
        "0178e60152ea1f542c22b8f16997a7e96726e6cb58640bbf5afdf9e6d302ba1adfde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4fe8127f449ae2082b5560c41b8e99c799602b631a22a758ddfcffb73d830b6943",
    );
    let sig_bytes: [u8; 64] = hb("68505016ed7c782abd21dbeb7c4207cbee84e24de3a69f8422f65cb12136321fd1d739a22bd60e50d7ecf1eae8fdf07fc711ce9ca2b426455e6e932003098007")
        .try_into()
        .unwrap();
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(&transcript, &sig).expect("bundle sig");
}
