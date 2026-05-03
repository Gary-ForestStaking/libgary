//! X25519 triple-/quad-DH per v0-protocol §5 (`DH1…DH4`, `KM` concatenation).

use x25519_dalek::{PublicKey, StaticSecret};

fn dh(secret: &StaticSecret, peer: &PublicKey) -> [u8; 32] {
    *secret.diffie_hellman(peer).as_bytes()
}

/// `KM = DH1 ‖ DH2 ‖ DH3 ‖ DH4` when a one-time prekey is consumed.
pub fn km_with_otp(
    ik_a: &StaticSecret,
    ek_a: &StaticSecret,
    ik_b_pub: &PublicKey,
    spk_b_pub: &PublicKey,
    otp_b_pub: &PublicKey,
) -> [u8; 128] {
    let dh1 = dh(ik_a, spk_b_pub);
    let dh2 = dh(ek_a, ik_b_pub);
    let dh3 = dh(ek_a, spk_b_pub);
    let dh4 = dh(ek_a, otp_b_pub);
    let mut km = [0u8; 128];
    km[0..32].copy_from_slice(&dh1);
    km[32..64].copy_from_slice(&dh2);
    km[64..96].copy_from_slice(&dh3);
    km[96..128].copy_from_slice(&dh4);
    km
}
