//! Device-local integrity anchor (v0-state-integrity §3–§4).

use sha2::{Digest, Sha256};

/// `DeviceStateAnchorV1` wire layout (v0-state-integrity §3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceStateAnchorV1 {
    pub anchor_version_be: u16,
    pub protocol_version_be: u16,
    pub kdf_suite_id_be: u32,
    pub global_epoch_be: u64,
    pub highest_wire_seen_be: u64,
    pub ratchet_blob_scheme_be: u32,
    pub state_commitment: [u8; 32],
}

impl DeviceStateAnchorV1 {
    pub const LEN: usize = 2 + 2 + 4 + 8 + 8 + 4 + 32;

    pub fn new_v0(global_epoch_be: u64) -> Self {
        Self {
            anchor_version_be: 1,
            protocol_version_be: 1,
            kdf_suite_id_be: 1,
            global_epoch_be,
            highest_wire_seen_be: 0,
            ratchet_blob_scheme_be: 2,
            state_commitment: [0u8; 32],
        }
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..2].copy_from_slice(&self.anchor_version_be.to_be_bytes());
        out[2..4].copy_from_slice(&self.protocol_version_be.to_be_bytes());
        out[4..8].copy_from_slice(&self.kdf_suite_id_be.to_be_bytes());
        out[8..16].copy_from_slice(&self.global_epoch_be.to_be_bytes());
        out[16..24].copy_from_slice(&self.highest_wire_seen_be.to_be_bytes());
        out[24..28].copy_from_slice(&self.ratchet_blob_scheme_be.to_be_bytes());
        out[28..60].copy_from_slice(&self.state_commitment);
        out
    }

    pub fn decode(bytes: &[u8; Self::LEN]) -> Self {
        Self {
            anchor_version_be: u16::from_be_bytes(bytes[0..2].try_into().unwrap()),
            protocol_version_be: u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
            kdf_suite_id_be: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            global_epoch_be: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            highest_wire_seen_be: u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            ratchet_blob_scheme_be: u32::from_be_bytes(bytes[24..28].try_into().unwrap()),
            state_commitment: bytes[28..60].try_into().unwrap(),
        }
    }
}

/// Canonical `state_commitment` preimage (v0-state-integrity §4).
pub fn compute_state_commitment(
    active_sessions_canonical: &[u8],
    global_epoch_be: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"libgary-v0/state-commit-v1");
    h.update(1u16.to_be_bytes()); // protocol_version_be profile v0 header.version
    h.update(1u32.to_be_bytes()); // kdf_suite_id_be
    h.update(active_sessions_canonical);
    h.update(global_epoch_be.to_be_bytes());
    h.finalize().into()
}
