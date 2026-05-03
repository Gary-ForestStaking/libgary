//! Symmetric chain stepping + DH mixing labels ([v0-protocol](docs/v0-protocol.md) §8, [v0-kdf](docs/v0-kdf.md)).

use crate::constants::{INFO_CHAIN, INFO_MSG_PREFIX, INFO_ROOT_MIX};
use crate::kdf::{hkdf_sha256, hkdf_zero32};

pub fn chain_bootstrap(bootstrap_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let okm = hkdf_zero32(bootstrap_key, INFO_CHAIN, 64);
    let cks: [u8; 32] = okm[0..32].try_into().unwrap();
    let ckr: [u8; 32] = okm[32..64].try_into().unwrap();
    (cks, ckr)
}

/// One symmetric send/receive step: `m` is chain index `m_s` / `m_r` (not wire counter).
pub fn msg_step(ck: &[u8; 32], m: u64) -> ([u8; 32], [u8; 32]) {
    let mut info = Vec::with_capacity(INFO_MSG_PREFIX.len() + 8);
    info.extend_from_slice(INFO_MSG_PREFIX);
    info.extend_from_slice(&m.to_be_bytes());
    let okm = hkdf_zero32(ck, &info, 64);
    let mk: [u8; 32] = okm[0..32].try_into().unwrap();
    let ck_next: [u8; 32] = okm[32..64].try_into().unwrap();
    (mk, ck_next)
}

/// `HKDF(salt=RK_old, ikm=DH_out, info=libgary-root, L=96)` → `RK' ‖ mixed_A ‖ mixed_B`.
pub fn dh_mix(root_key_old: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let okm = hkdf_sha256(root_key_old, dh_out, INFO_ROOT_MIX, 96);
    let rk_new: [u8; 32] = okm[0..32].try_into().unwrap();
    let a: [u8; 32] = okm[32..64].try_into().unwrap();
    let b: [u8; 32] = okm[64..96].try_into().unwrap();
    (rk_new, a, b)
}
