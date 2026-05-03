//! Ship-facing session API: **ingress** via [`SessionHandle::handle_inbound_outer`] and explicit sends.
//!
//! Raw [`crate::engine::session::Session`] is crate-private; embedding code should use this handle only.
//!
//! Operational contract: repository `docs/session-handle-boundary.md` (v0).

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use libgary_wire::{Header, OuterRecord};

use super::anchor::DeviceStateAnchorV1;
use super::error::SessionError;
#[cfg(feature = "protocol-test-api")]
use super::mode::SessionMode;
use super::session::{InboundInner, Session, SessionExport};
use super::wal_source::SessionWalSource;
use crate::constants::DATA_INNER_FIXED;

/// Opaque ratchet session — use [`Self::handle_inbound_outer`] for wire decrypt paths that enforce epoch / RESET policy.
pub struct SessionHandle {
    pub(crate) session: Session,
}

impl SessionHandle {
    pub fn bootstrap_initiator(
        okm: &[u8; 64],
        session_id: [u8; 16],
        epoch: u32,
        ratchet_sk: [u8; 32],
        initial_peer_ratchet_pub: Option<[u8; 32]>,
        anchor: DeviceStateAnchorV1,
    ) -> Self {
        Self {
            session: Session::bootstrap_initiator(
                okm,
                session_id,
                epoch,
                ratchet_sk,
                initial_peer_ratchet_pub,
                anchor,
            ),
        }
    }

    pub fn bootstrap_responder(
        okm: &[u8; 64],
        session_id: [u8; 16],
        epoch: u32,
        ratchet_sk: [u8; 32],
        initial_peer_ratchet_pub: Option<[u8; 32]>,
        anchor: DeviceStateAnchorV1,
    ) -> Self {
        Self {
            session: Session::bootstrap_responder(
                okm,
                session_id,
                epoch,
                ratchet_sk,
                initial_peer_ratchet_pub,
                anchor,
            ),
        }
    }

    pub fn from_export(export: SessionExport) -> Result<Self, SessionError> {
        Session::import_state(export).map(|session| Self { session })
    }

    /// Single ingress gate: header validation, epoch / RESET policy, then decrypt.
    pub fn handle_inbound_outer(
        &mut self,
        record: OuterRecord,
        now_ticks: u64,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<InboundInner, SessionError> {
        self.session.handle_inbound_outer(record, now_ticks, rng)
    }

    pub fn send_data_plain512(
        &mut self,
        plaintext512: &[u8; DATA_INNER_FIXED],
    ) -> Result<(Header, Vec<u8>), SessionError> {
        self.session.encrypt_data_plain512(plaintext512)
    }

    /// Receive DATA **inner** ciphertext (no outer `PAD()`); prefer [`Self::handle_inbound_outer`] for wire paths.
    pub fn recv_data_plain512(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Zeroizing<[u8; DATA_INNER_FIXED]>, SessionError> {
        self.session.decrypt_data(header, ciphertext, rng)
    }

    pub fn send_data_plain512_outer(
        &mut self,
        plaintext512: &[u8; DATA_INNER_FIXED],
        pad_rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(Header, Vec<u8>), SessionError> {
        self.session
            .encrypt_data_plain512_outer(plaintext512, pad_rng)
    }

    pub fn recv_data_outer(
        &mut self,
        header: &Header,
        padded_logical: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Zeroizing<[u8; DATA_INNER_FIXED]>, SessionError> {
        self.session.decrypt_data_outer(header, padded_logical, rng)
    }

    pub fn send_rekey_ctrl_outer(
        &mut self,
        rekey_body_leading_4: &[u8; 4],
        pad_rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(Header, Vec<u8>), SessionError> {
        self.session
            .encrypt_rekey_ctrl_outer(rekey_body_leading_4, pad_rng)
    }

    pub fn recv_rekey_ctrl_outer(
        &mut self,
        header: &Header,
        padded_logical: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<[u8; 256], SessionError> {
        self.session
            .decrypt_rekey_ctrl_outer(header, padded_logical, rng)
    }

    /// Canonical serialized ratchet snapshot for persistence (`SessionStore`) and tooling.
    pub fn export_state(&self) -> SessionExport {
        self.session.export_state()
    }

    /// Recompute `DeviceStateAnchorV1` commitment from live ratchet fields — **required before WAL save** after progress.
    pub fn recompute_anchor_commitment(&mut self) {
        self.session.recompute_anchor_commitment()
    }

    pub fn verify_anchor_commitment(&self) -> bool {
        self.session.verify_anchor_commitment()
    }

    /// Stable digest for golden persistence / replay equivalence tests (`tests/recovery_equivalence.rs`).
    pub fn persistence_equivalence_digest(&self) -> [u8; 32] {
        self.session.persistence_equivalence_digest()
    }
}

/// Protocol drills and integration tests only — see crate feature `protocol-test-api`.
#[cfg(feature = "protocol-test-api")]
impl SessionHandle {
    pub fn enter_reset_pending_after_rebootstrap(
        &mut self,
        prior_epoch: u32,
        drain_until_ticks: Option<u64>,
    ) -> Result<(), SessionError> {
        self.session
            .enter_reset_pending_after_rebootstrap(prior_epoch, drain_until_ticks)
    }

    pub fn reset_pending_to_bootstrapping(&mut self) -> Result<(), SessionError> {
        self.session.reset_pending_to_bootstrapping()
    }

    pub fn finish_reset_half_open_to_active(&mut self) -> Result<(), SessionError> {
        self.session.finish_reset_half_open_to_active()
    }

    pub fn recv_high_water(&self) -> Option<u64> {
        self.session.recv_high_water()
    }

    pub fn recv_sym_idx(&self) -> u64 {
        self.session.recv_sym_idx
    }

    pub fn send_wire_counter(&self) -> u64 {
        self.session.send_wire_counter
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session.session_id
    }

    pub fn epoch(&self) -> u32 {
        self.session.epoch
    }

    pub fn ingress_mode(&self) -> SessionMode {
        self.session.mode
    }

    pub fn skipped_cache_len(&self) -> usize {
        self.session.skipped_cache_len()
    }
}

impl SessionWalSource for SessionHandle {
    fn export_state(&self) -> SessionExport {
        self.session.export_state()
    }

    fn session_id(&self) -> [u8; 16] {
        self.session.session_id
    }

    fn epoch(&self) -> u32 {
        self.session.epoch
    }

    fn recv_high_water(&self) -> Option<u64> {
        self.session.recv_high_water()
    }

    fn send_wire_counter(&self) -> u64 {
        self.session.send_wire_counter
    }

    fn anchor(&self) -> &DeviceStateAnchorV1 {
        &self.session.anchor
    }

    fn verify_anchor_commitment(&self) -> bool {
        self.session.verify_anchor_commitment()
    }
}
