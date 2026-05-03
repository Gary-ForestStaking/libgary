//! Identity fingerprint helpers ([v0-protocol](docs/v0-protocol.md) §3.3).

use crate::constants::SAFETY_NUMBER_PREFIX;
use sha2::{Digest, Sha256};

fn min_max_32<'a>(a: &'a [u8; 32], b: &'a [u8; 32]) -> (&'a [u8; 32], &'a [u8; 32]) {
    if a.as_slice() < b.as_slice() {
        (a, b)
    } else {
        (b, a)
    }
}

pub fn safety_number(
    ik_a: &[u8; 32],
    ik_b: &[u8; 32],
    spk_a: &[u8; 32],
    spk_b: &[u8; 32],
) -> [u8; 32] {
    let (ik_lo, ik_hi) = min_max_32(ik_a, ik_b);
    let (spk_lo, spk_hi) = min_max_32(spk_a, spk_b);
    let mut h = Sha256::new();
    h.update(SAFETY_NUMBER_PREFIX);
    h.update(ik_lo);
    h.update(ik_hi);
    h.update(spk_lo);
    h.update(spk_hi);
    h.finalize().into()
}

pub fn account_id(ed25519_pk: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ed25519_pk);
    h.finalize().into()
}
