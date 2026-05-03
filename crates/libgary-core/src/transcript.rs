use crate::constants::{TH0_PREFIX, TH1_PREFIX};
use crate::kdf::sha256_label;
use libgary_wire::InitAckCore;

pub fn th0(init_body: &[u8; 100]) -> [u8; 32] {
    sha256_label(TH0_PREFIX, init_body.as_slice())
}

pub fn th1(th0_digest: &[u8; 32], init_ack_core: &InitAckCore) -> [u8; 32] {
    let core = init_ack_core.encode();
    let mut buf = Vec::with_capacity(32 + InitAckCore::LEN);
    buf.extend_from_slice(th0_digest);
    buf.extend_from_slice(&core);
    sha256_label(TH1_PREFIX, &buf)
}
