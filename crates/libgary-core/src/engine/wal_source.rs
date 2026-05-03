//! Trait for types that can be persisted via WAL (`SessionExport` + trusted meta).
//!
//! Application code should treat this as **persistence plumbing** for `libgary_storage::SessionStore`-style
//! callers — not a second control plane for sessions. Prefer [`super::SessionHandle`] for encrypt/decrypt traffic.

use super::anchor::DeviceStateAnchorV1;
use super::session::{Session, SessionExport};

/// Snapshot fields required for LGW1 trusted meta + bundle encode (`docs/v0-state-integrity.md` §3).
pub trait SessionWalSource {
    fn export_state(&self) -> SessionExport;
    fn session_id(&self) -> [u8; 16];
    fn epoch(&self) -> u32;
    fn recv_high_water(&self) -> Option<u64>;
    fn send_wire_counter(&self) -> u64;
    fn anchor(&self) -> &DeviceStateAnchorV1;
    fn verify_anchor_commitment(&self) -> bool;
}

impl SessionWalSource for Session {
    fn export_state(&self) -> SessionExport {
        Session::export_state(self)
    }

    fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    fn epoch(&self) -> u32 {
        self.epoch
    }

    fn recv_high_water(&self) -> Option<u64> {
        Session::recv_high_water(self)
    }

    fn send_wire_counter(&self) -> u64 {
        self.send_wire_counter
    }

    fn anchor(&self) -> &DeviceStateAnchorV1 {
        &self.anchor
    }

    fn verify_anchor_commitment(&self) -> bool {
        Session::verify_anchor_commitment(self)
    }
}
