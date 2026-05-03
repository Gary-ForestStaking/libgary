#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Regenerate hex strings for docs/test-vectors.md (libgary v0).

Requires: pip install cryptography pynacl

DATA inner plaintext is fixed 512 B per v0-protocol §6.4 (semantic ‖ HKDF_pad).

Usage:
  python3 tools/gen_test_vectors.py          # core vectors
  python3 tools/gen_test_vectors.py --integration   # append transcript outline
"""
from __future__ import annotations

import hashlib
import hmac
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

ZERO32 = bytes(32)
INFO_CHAIN = b"libgary-v0/libgary-chain"
INFO_ROOT = b"libgary-v0/libgary-root"
DATA_INNER_FIXED = 512  # [v0-protocol.md] §6.6


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(
        ikm
    )


def nonce24(i_core: bytes, label_dist: bytes) -> bytes:
    """[docs/v0-kdf.md] §3 NONCE24."""
    return hkdf(ZERO32, i_core + label_dist, b"libgary-v0/nonce-v1", 24)


def data_inner_plaintext_v0(inner_version: int, content_type: int, content: bytes) -> bytes:
    """Fixed 512 B semantic DATA inner before §6.5 inner PAD()."""
    semantic = (
        inner_version.to_bytes(2, "big")
        + content_type.to_bytes(2, "big")
        + len(content).to_bytes(4, "big")
        + content
    )
    need = DATA_INNER_FIXED - len(semantic)
    if need < 0:
        raise ValueError("DATA content too large for v0 inner (max 504 B UTF-8)")
    pad = hkdf(ZERO32, semantic, b"libgary-v0/data-inner-pad-v1", need)
    return semantic + pad


def msg_step(ck: bytes, counter: int) -> tuple[bytes, bytes]:
    info = b"libgary-v0/libgary-msg" + counter.to_bytes(8, "big")
    okm = hkdf(ZERO32, ck, info, 64)
    return okm[0:32], okm[32:64]


def header63(version: int, typ: int, flags: int, epoch_be: bytes, session_id: bytes, counter_be: bytes, ratchet_pub: bytes) -> bytes:
    assert len(epoch_be) == 4 and len(session_id) == 16 and len(counter_be) == 8
    assert len(ratchet_pub) == 32
    return bytes([version, typ, flags]) + epoch_be + session_id + counter_be + ratchet_pub


def main() -> None:
    salt_handshake = hashlib.sha256(b"libgary-v0-handshake").digest()

    alice_ik_priv_bytes = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    bob_ik_priv_bytes = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    alice_ik = X25519PrivateKey.from_private_bytes(alice_ik_priv_bytes)
    bob_ik = X25519PrivateKey.from_private_bytes(bob_ik_priv_bytes)
    alice_ik_pub = alice_ik.public_key().public_bytes_raw()
    bob_ik_pub = bob_ik.public_key().public_bytes_raw()

    ek_a = X25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"libgary-EKa-seed").digest()
    )
    spk_b = X25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"libgary-SPKb-seed").digest()
    )
    otp_b = X25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"libgary-OPKb-seed").digest()
    )

    dh1 = alice_ik.exchange(spk_b.public_key())
    dh2 = ek_a.exchange(bob_ik.public_key())
    dh3 = ek_a.exchange(spk_b.public_key())
    dh4 = ek_a.exchange(otp_b.public_key())
    km = dh1 + dh2 + dh3 + dh4

    alice_ed_seed = hashlib.sha256(b"libgary-v0-alice-ed25519-seed").digest()
    alice_ed_sk = Ed25519PrivateKey.from_private_bytes(alice_ed_seed)
    alice_ed_pk = alice_ed_sk.public_key().public_bytes_raw()

    alice_spk_priv = X25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"libgary-alice-SPK-seed").digest()
    )
    alice_spk_pub = alice_spk_priv.public_key().public_bytes_raw()

    bob_ed_seed = hashlib.sha256(b"libgary-v0-test-bob-ed25519-seed").digest()
    bob_ed_sk = Ed25519PrivateKey.from_private_bytes(bob_ed_seed)
    bob_ed_pk = bob_ed_sk.public_key().public_bytes_raw()

    otp_index_be = (0).to_bytes(2, "big")
    reserved_be = (0).to_bytes(2, "big")
    init_body = (
        alice_ed_pk
        + alice_ik_pub
        + ek_a.public_key().public_bytes_raw()
        + otp_index_be
        + reserved_be
    )
    assert len(init_body) == 100

    th0 = hashlib.sha256(b"libgary-v0/th0-v1" + init_body).digest()

    ack_nonce_be = (1).to_bytes(8, "big")
    init_ack_core = bob_ed_pk + bob_ik_pub + ack_nonce_be
    th1 = hashlib.sha256(b"libgary-v0/th1-v1" + th0 + init_ack_core).digest()

    ikm_session = km + th0 + th1
    okm = hkdf(salt_handshake, ikm_session, b"libgary-v0/root-key-v1", 64)

    confirm_key = hkdf(ZERO32, okm, b"libgary-v0/confirm-v1", 32)
    confirm_mac = hmac.new(confirm_key, th1, hashlib.sha256).digest()[:16]
    init_ack_wire = init_ack_core + confirm_mac

    epoch_be = (0).to_bytes(4, "big")
    session_id = bytes(16)
    ratchet_pub = ek_a.public_key().public_bytes_raw()

    aad_init = b"libgary-v0/init-aad-v1" + epoch_be + session_id + init_body

    k_init = hkdf(ZERO32, km + th0, b"libgary-v0/init-aead-v1", 32)
    nonce_init = nonce24(km + th0, b"INIT" + epoch_be + session_id)
    plain_inner_init = hkdf(ZERO32, th0, b"libgary-v0/init-inner-v1", 256)
    ct_init = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plain_inner_init, aad_init, nonce_init, k_init
    )

    k_ack = hkdf(ZERO32, okm, b"libgary-v0/ack-aead-v1", 32)
    nonce_ack = nonce24(okm, b"ACK" + epoch_be + session_id)
    aad_ack = b"libgary-v0/ack-aad-v1" + epoch_be + session_id + init_ack_wire
    plain_inner_ack = hkdf(ZERO32, th1, b"libgary-v0/ack-inner-v1", 256)
    ct_ack = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plain_inner_ack, aad_ack, nonce_ack, k_ack
    )

    root_key = okm[0:32]
    bootstrap = okm[32:64]

    tmp = hkdf(ZERO32, bootstrap, INFO_CHAIN, 64)
    initiator_send_ck = tmp[0:32]
    initiator_recv_ck = tmp[32:64]

    mk0, ck_after_0 = msg_step(initiator_send_ck, 0)
    mk1_same_chain, ck_after_1 = msg_step(ck_after_0, 1)

    dh_out = bytes([0x42] * 32)
    okm_dh = hkdf(root_key, dh_out, INFO_ROOT, 96)
    r1 = okm_dh[0:32]
    mix_a = okm_dh[32:64]
    mix_b = okm_dh[64:96]

    ratchet_pub_after_dh = X25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"libgary-ratchet-after-DH").digest()
    ).public_key().public_bytes_raw()

    # Post-DH: symmetric send index resets to 0 (§8.5); wire counter stays monotonic (=1).
    mk_after_dh, ck_after_dh_first = msg_step(mix_a, 0)

    spk_pub = spk_b.public_key().public_bytes_raw()
    bundle_version = bytes([1])
    sig_transcript = bundle_version + bob_ed_pk + bob_ik_pub + spk_pub
    sig = bob_ed_sk.sign(sig_transcript)

    bob_account_id = hashlib.sha256(bob_ed_pk).digest()

    counter0 = (0).to_bytes(8, "big")
    counter1 = (1).to_bytes(8, "big")
    hdr_data0 = header63(1, 0x03, 0, epoch_be, session_id, counter0, ratchet_pub)
    nonce_data0 = nonce24(
        mk0,
        b"DATA" + epoch_be + counter0 + session_id + ratchet_pub,
    )
    pt_data = data_inner_plaintext_v0(1, 1, b"hello-libgary-v0")
    ct_data0 = crypto_aead_xchacha20poly1305_ietf_encrypt(
        pt_data, hdr_data0, nonce_data0, mk0
    )

    hdr_data1 = header63(
        1, 0x03, 0, epoch_be, session_id, counter1, ratchet_pub_after_dh
    )
    nonce_data1 = nonce24(
        mk_after_dh,
        b"DATA" + epoch_be + counter1 + session_id + ratchet_pub_after_dh,
    )
    pt_data1 = data_inner_plaintext_v0(1, 1, b"second-msg-vector")
    ct_data1 = crypto_aead_xchacha20poly1305_ietf_encrypt(
        pt_data1, hdr_data1, nonce_data1, mk_after_dh
    )

    k_control = hkdf(ZERO32, okm, b"libgary-v0/control-aead-v1", 32)
    rekey_ctr = (2).to_bytes(8, "big")
    hdr_rekey = header63(
        1, 0x05, 0, epoch_be, session_id, rekey_ctr, ratchet_pub_after_dh
    )
    nonce_rekey = nonce24(
        okm,
        b"CTRL" + bytes([0x05]) + epoch_be + rekey_ctr + session_id,
    )
    body_rekey = (1).to_bytes(2, "big") + (0).to_bytes(2, "big")
    plain_rekey = body_rekey + hkdf(
        ZERO32, body_rekey, b"libgary-v0/ctrl-pad-v1", 256 - len(body_rekey)
    )
    ct_rekey = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plain_rekey, hdr_rekey, nonce_rekey, k_control
    )

    ia_sig, ib_sig = min(alice_ed_pk, bob_ed_pk), max(alice_ed_pk, bob_ed_pk)
    sa_spk, sb_spk = min(alice_spk_pub, spk_pub), max(alice_spk_pub, spk_pub)
    safety_preimage = (
        b"libgary-v0/safety-number-v1" + ia_sig + ib_sig + sa_spk + sb_spk
    )
    safety_number_sha256 = hashlib.sha256(safety_preimage).digest()

    def hx(label: str, b: bytes) -> None:
        print(f"{label}: {b.hex()}")

    hx("bob_account_id_sha256_ed25519_pk_full32", bob_account_id)
    hx("alice_ed25519_identity_pk", alice_ed_pk)
    hx("bob_ed25519_identity_pk", bob_ed_pk)
    hx("InitBody_100B", init_body)
    hx("TH0", th0)
    hx("InitAckCore_72B", init_ack_core)
    hx("TH1", th1)
    hx("IKM_session_KM_TH0_TH1", ikm_session)
    hx("OKM_root_key_v1", okm)
    hx("confirm_mac_16B", confirm_mac)
    hx("InitAckWire_88B", init_ack_wire)
    hx("K_init", k_init)
    hx("nonce_init_24_NONCE24", nonce_init)
    hx("plain_inner_init_256", plain_inner_init)
    hx("INIT_inner_aead_ciphertext_plus_tag", ct_init)
    hx("K_ack", k_ack)
    hx("nonce_ack_24_NONCE24", nonce_ack)
    hx("plain_inner_ack_256", plain_inner_ack)
    hx("INIT_ACK_inner_aead_ciphertext_plus_tag", ct_ack)
    hx("alice_x25519_ik_pub_rfc7748", alice_ik_pub)
    hx("bob_x25519_ik_pub_rfc7748", bob_ik_pub)
    hx("KM_concat_DH1_to_DH4", km)
    hx("alice_signed_prekey_pub_vector_only", alice_spk_pub)
    hx("bob_signed_prekey_pub", spk_pub)
    hx("bob_otp_pub", otp_b.public_key().public_bytes_raw())
    hx("alice_ephemeral_pub_EKa", ratchet_pub)
    hx("DH1_IKa_SPBb", dh1)
    hx("DH2_EKa_IKb", dh2)
    hx("DH3_EKa_SPBb", dh3)
    hx("DH4_EKa_OTPb", dh4)
    hx("root_key_OKM_prefix32", root_key)
    hx("bootstrap_key_OKM_suffix32", bootstrap)
    hx("TMP_libgary-chain_initiator_send_ck", initiator_send_ck)
    hx("TMP_libgary-chain_initiator_recv_ck", initiator_recv_ck)
    hx("MK_send_counter0_libgary-msg", mk0)
    hx("CKs_after_send_counter0", ck_after_0)
    hx("MK_send_counter1_libgary-msg_same_chain_no_DH", mk1_same_chain)
    hx("CKs_after_send_counter1_same_chain", ck_after_1)
    hx("ratchet_pub_after_DH_step", ratchet_pub_after_dh)
    hx("MK_DATA_sym0_after_DH_wire_counter1", mk_after_dh)
    hx("CKs_after_first_send_on_post_DH_chain", ck_after_dh_first)
    hx("DH_out_synthetic_32x42", dh_out)
    hx("RK_new_after_libgary-root", r1)
    hx("CK_mixed_A_libgary-root", mix_a)
    hx("CK_mixed_B_libgary-root", mix_b)
    hx("prekey_signature_transcript_v1_Bob", sig_transcript)
    hx("prekey_signature_ed25519_Bob", sig)
    hx("safety_number_sha256_full32", safety_number_sha256)
    hx("sample_HEADER_DATA_counter0_63B", hdr_data0)
    hx("sample_NONCE24_DATA_MK0", nonce_data0)
    hx("sample_DATA_inner_plaintext_512B_counter0", pt_data)
    hx("sample_DATA_ciphertext_counter0_MK0", ct_data0)
    hx("sample_HEADER_DATA_counter1_63B", hdr_data1)
    hx("sample_NONCE24_DATA_MK1", nonce_data1)
    hx("sample_DATA_inner_plaintext_512B_counter1", pt_data1)
    hx("sample_DATA_ciphertext_counter1_MK1", ct_data1)
    hx("K_control", k_control)
    hx("sample_HEADER_REKEY_counter2_63B", hdr_rekey)
    hx("sample_NONCE24_CTRL_REKEY", nonce_rekey)
    hx("sample_REKEY_inner_aead", ct_rekey)

    if "--integration" in sys.argv:
        print()
        print("=== integration_transcript (Alice initiator, epoch=0, session_id=0..0) ===")
        print("STEP01_INIT_INNER_AEAD:", ct_init.hex())
        print("STEP02_INIT_ACK_INNER_AEAD:", ct_ack.hex())
        print("STEP03_DATA_COUNTER0:", ct_data0.hex())
        print(
            "STEP04_DH_RATCHET:",
            dh_out.hex(),
            "-> RK'",
            r1.hex(),
            "ratchet_pub'",
            ratchet_pub_after_dh.hex(),
        )
        print("STEP05_DATA_COUNTER1_POST_DH:", ct_data1.hex())
        print("STEP06_REKEY_CTRL:", ct_rekey.hex())


if __name__ == "__main__":
    main()
