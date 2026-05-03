use crate::constants::{INFO_NONCE_V1, ZERO32};
use crate::kdf::hkdf_sha256;

/// `NONCE24(i_core, label_dist)` (v0-kdf §3).
pub fn nonce24(i_core: &[u8], label_dist: &[u8]) -> [u8; 24] {
    let mut ikm = Vec::with_capacity(i_core.len() + label_dist.len());
    ikm.extend_from_slice(i_core);
    ikm.extend_from_slice(label_dist);
    hkdf_sha256(&ZERO32, &ikm, INFO_NONCE_V1, 24)
        .try_into()
        .expect("length 24")
}
