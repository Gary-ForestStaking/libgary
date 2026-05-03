use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::constants::ZERO32;

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut okm = vec![0u8; out_len];
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, &mut okm)
        .expect("HKDF expand length is valid for SHA256");
    okm
}

/// HKDF-SHA256 with `salt = ZERO32` (dominant pattern for sub-keys in v0).
pub fn hkdf_zero32(ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    hkdf_sha256(&ZERO32, ikm, info, out_len)
}

pub fn sha256_label(prefix: &[u8], body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prefix);
    h.update(body);
    h.finalize().into()
}
