#![no_main]

//! Fuzz [`libgary_core::engine::SessionHandle::handle_inbound_outer`] with arbitrary decoded [`OuterRecord`] input.

use libgary_core::engine::{DeviceStateAnchorV1, SessionHandle};
use libgary_wire::OuterRecord;
use libfuzzer_sys::fuzz_target;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use x25519_dalek::{PublicKey, StaticSecret};

fn ratchet_pub(sk: [u8; 32]) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(sk)).as_bytes()
}

fuzz_target!(|data: &[u8]| {
    let okm = std::array::from_fn(|i| (i as u8).wrapping_mul(3));
    let sid = [0x91u8; 16];
    let epoch = 0u32;
    let anchor = DeviceStateAnchorV1::new_v0(4);
    let alice_sk = std::array::from_fn(|i| i as u8);
    let bob_sk = std::array::from_fn(|i| i.wrapping_add(40) as u8);

    let mut session = SessionHandle::bootstrap_responder(
        &okm,
        sid,
        epoch,
        bob_sk,
        Some(ratchet_pub(alice_sk)),
        anchor,
    );
    session.recompute_anchor_commitment();

    let Ok(record) = OuterRecord::decode(data) else {
        return;
    };

    let mut seed = [0u8; 32];
    let n = data.len().min(32);
    seed[..n].copy_from_slice(&data[..n]);
    let mut rng = ChaCha12Rng::from_seed(seed);
    let ticks = data.first().copied().map(u64::from).unwrap_or(0);
    let _ = session.handle_inbound_outer(record, ticks, &mut rng);
});
