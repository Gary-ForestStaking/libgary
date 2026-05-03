use crate::constants::{TH0_PREFIX, TH0_RESET_PREFIX, TH1_PREFIX, TH1_RESET_PREFIX};
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

/// Transcript `TH0_r` ([v0-reset.md](docs/v0-reset.md) §4.1).
pub fn th0_reset(reset_init_body: &[u8; 100]) -> [u8; 32] {
    sha256_label(TH0_RESET_PREFIX, reset_init_body.as_slice())
}

/// Transcript `TH1_r` ([v0-reset.md](docs/v0-reset.md) §4.2).
pub fn th1_reset(th0_r: &[u8; 32], reset_ack_core: &InitAckCore) -> [u8; 32] {
    let core = reset_ack_core.encode();
    let mut buf = Vec::with_capacity(32 + InitAckCore::LEN);
    buf.extend_from_slice(th0_r);
    buf.extend_from_slice(&core);
    sha256_label(TH1_RESET_PREFIX, &buf)
}
