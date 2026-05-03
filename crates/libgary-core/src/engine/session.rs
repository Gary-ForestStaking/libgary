//! Authoritative Double Ratchet session state (v0-protocol §8–§9).

use std::collections::HashSet;

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::constants::{DATA_INNER_FIXED, MAX_SKIP};
use crate::data;
use crate::ratchet::{chain_bootstrap, dh_mix, msg_step};
use libgary_wire::{pad_outer, strip_outer_pad, Header, OuterRecord};

use super::anchor::{DeviceStateAnchorV1, compute_state_commitment};
use super::blob::{decode_blob_v2, encode_blob_v2};
use super::error::SessionError;
use super::mode::SessionMode;
use super::skipped::SkippedKeyCache;
use super::types::Role;

const HEADER_VERSION_V0: u8 = 1;

fn random_static_secret(rng: &mut (impl RngCore + CryptoRng)) -> StaticSecret {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    StaticSecret::from(b)
}

/// Sentinel for “no inbound successfully decrypted yet” in `RatchetStateBlob.recv_high_water_be` export.
pub const RECV_HIGH_WATER_NONE_SENTINEL: u64 = u64::MAX;

/// Serialized session secrets for persistence (`RatchetStateBlob` does not carry `OKM` — keep alongside).
#[derive(Clone, Debug)]
pub struct SessionExport {
    pub ratchet_blob: Vec<u8>,
    pub okm: [u8; 64],
    pub anchor: DeviceStateAnchorV1,
    pub session_id: [u8; 16],
    pub epoch: u32,
}

/// Decrypted application payload after validated ingress (`DATA` / `REKEY` §6).
#[derive(Debug)]
pub enum InboundInner {
    Data(Zeroizing<[u8; DATA_INNER_FIXED]>),
    /// Plain padded ctrl body (`ctrl_inner_padded256` preimage semantics).
    RekeyPlain([u8; 256]),
}

/// Stateful Double Ratchet engine — crate-private; embed [`super::SessionHandle`].
pub(crate) struct Session {
    pub(crate) session_id: [u8; 16],
    pub(crate) epoch: u32,
    /// Ingress policy overlay. **Not** serialized in v0 ratchet blobs; loaders rebuild [`SessionMode::Active`]
    /// at [`Session::epoch`] (see [`Session::import_state`]).
    pub(crate) mode: SessionMode,
    okm: Zeroizing<[u8; 64]>,
    pub(crate) root_key: Zeroizing<[u8; 32]>,
    send_ck: Zeroizing<[u8; 32]>,
    recv_ck: Zeroizing<[u8; 32]>,
    pub(crate) send_wire_counter: u64,
    recv_high_water: Option<u64>,
    pub(crate) send_sym_idx: u64,
    pub(crate) recv_sym_idx: u64,
    ratchet_sk: StaticSecret,
    pub(crate) my_ratchet_pub: [u8; 32],
    peer_ratchet_pub: Option<[u8; 32]>,
    skipped: SkippedKeyCache,
    pub(crate) role: Role,
    pub(crate) anchor: DeviceStateAnchorV1,
    decrypted_counters: HashSet<u64>,
}

impl Session {
    /// Highest accepted inbound [`Header::counter_be`] for this epoch (`None` until first decrypt).
    #[inline]
    pub(crate) fn recv_high_water(&self) -> Option<u64> {
        self.recv_high_water
    }

    pub(crate) fn bootstrap_initiator(
        okm: &[u8; 64],
        session_id: [u8; 16],
        epoch: u32,
        ratchet_sk: [u8; 32],
        initial_peer_ratchet_pub: Option<[u8; 32]>,
        anchor: DeviceStateAnchorV1,
    ) -> Self {
        let root_key = Zeroizing::new(okm[..32].try_into().unwrap());
        let boot: [u8; 32] = okm[32..64].try_into().unwrap();
        let (cks, ckr) = chain_bootstrap(&boot);
        let ratchet_sk = StaticSecret::from(ratchet_sk);
        let my_ratchet_pub = *PublicKey::from(&ratchet_sk).as_bytes();
        Self {
            session_id,
            epoch,
            mode: SessionMode::Active { epoch },
            okm: Zeroizing::new(*okm),
            root_key,
            send_ck: Zeroizing::new(cks),
            recv_ck: Zeroizing::new(ckr),
            send_wire_counter: 0,
            recv_high_water: None,
            send_sym_idx: 0,
            recv_sym_idx: 0,
            ratchet_sk,
            my_ratchet_pub,
            peer_ratchet_pub: initial_peer_ratchet_pub,
            skipped: SkippedKeyCache::new(),
            role: Role::Initiator,
            anchor,
            decrypted_counters: HashSet::new(),
        }
    }

    pub(crate) fn bootstrap_responder(
        okm: &[u8; 64],
        session_id: [u8; 16],
        epoch: u32,
        ratchet_sk: [u8; 32],
        initial_peer_ratchet_pub: Option<[u8; 32]>,
        anchor: DeviceStateAnchorV1,
    ) -> Self {
        let root_key = Zeroizing::new(okm[..32].try_into().unwrap());
        let boot: [u8; 32] = okm[32..64].try_into().unwrap();
        let (cks, ckr) = chain_bootstrap(&boot);
        let ratchet_sk = StaticSecret::from(ratchet_sk);
        let my_ratchet_pub = *PublicKey::from(&ratchet_sk).as_bytes();
        Self {
            session_id,
            epoch,
            mode: SessionMode::Active { epoch },
            okm: Zeroizing::new(*okm),
            root_key,
            send_ck: Zeroizing::new(ckr),
            recv_ck: Zeroizing::new(cks),
            send_wire_counter: 0,
            recv_high_water: None,
            send_sym_idx: 0,
            recv_sym_idx: 0,
            ratchet_sk,
            my_ratchet_pub,
            peer_ratchet_pub: initial_peer_ratchet_pub,
            skipped: SkippedKeyCache::new(),
            role: Role::Responder,
            anchor,
            decrypted_counters: HashSet::new(),
        }
    }

    /// After local RESET rebootstrap (`epoch == prior_epoch + 1`), arm explicit rejection of late DATA on `prior_epoch`.
    #[cfg(feature = "protocol-test-api")]
    pub(crate) fn enter_reset_pending_after_rebootstrap(
        &mut self,
        prior_epoch: u32,
        drain_until_ticks: Option<u64>,
    ) -> Result<(), SessionError> {
        let expected = prior_epoch.checked_add(1).ok_or(SessionError::InvalidHeader)?;
        if self.epoch != expected {
            return Err(SessionError::InvalidHeader);
        }
        self.mode = SessionMode::ResetPending {
            old_epoch: prior_epoch,
            new_epoch: self.epoch,
            drain_until_ticks,
        };
        Ok(())
    }

    /// [`SessionMode::ResetPending`] → [`SessionMode::Bootstrapping`] at the same [`Session::epoch`].
    #[cfg(feature = "protocol-test-api")]
    pub(crate) fn reset_pending_to_bootstrapping(&mut self) -> Result<(), SessionError> {
        match &self.mode {
            SessionMode::ResetPending { new_epoch, .. } if *new_epoch == self.epoch => {
                self.mode = SessionMode::Bootstrapping { epoch: self.epoch };
                Ok(())
            }
            _ => Err(SessionError::InvalidHeader),
        }
    }

    /// Clear [`SessionMode::ResetPending`] / [`SessionMode::Bootstrapping`] after transport confirms alignment.
    #[cfg(feature = "protocol-test-api")]
    pub(crate) fn finish_reset_half_open_to_active(&mut self) -> Result<(), SessionError> {
        match &self.mode {
            SessionMode::ResetPending { new_epoch, .. } if *new_epoch == self.epoch => {
                self.mode = SessionMode::Active { epoch: self.epoch };
                Ok(())
            }
            SessionMode::Bootstrapping { epoch } if *epoch == self.epoch => {
                self.mode = SessionMode::Active { epoch: self.epoch };
                Ok(())
            }
            _ => Err(SessionError::InvalidHeader),
        }
    }

    /// Enter [`SessionMode::Bootstrapping`] (e.g. immediately after bumping `epoch` before first post-RESET accept).
    // Reserved for future RESET / epoch transitions — not wired through [`super::session_handle::SessionHandle`] v0.
    #[allow(dead_code)]
    pub(crate) fn enter_bootstrapping_for_epoch(&mut self, epoch: u32) -> Result<(), SessionError> {
        if epoch != self.epoch {
            return Err(SessionError::InvalidHeader);
        }
        self.mode = SessionMode::Bootstrapping { epoch };
        Ok(())
    }

    fn maybe_expire_reset_pending(&mut self, now_ticks: u64) {
        let expire = match &self.mode {
            SessionMode::ResetPending {
                drain_until_ticks: Some(limit),
                ..
            } => now_ticks > *limit,
            _ => false,
        };
        if expire {
            self.mode = SessionMode::Active { epoch: self.epoch };
        }
    }

    fn check_inbound_epoch_policy(&self, hdr: &Header) -> Result<(), SessionError> {
        let e = hdr.epoch_be;
        if e > self.epoch.saturating_add(1) {
            return Err(SessionError::FutureEpoch);
        }
        if let SessionMode::ResetPending { old_epoch, .. } = &self.mode {
            if hdr.typ == 0x03 && e == *old_epoch {
                return Err(SessionError::LateDataAfterReset);
            }
        }
        if e < self.epoch {
            return Err(SessionError::StaleEpochRejected);
        }
        if e != self.epoch {
            return Err(SessionError::StaleEpochRejected);
        }
        Ok(())
    }

    /// Single ingress gate for outer framing + epoch / RESET policy + decrypt.
    pub(crate) fn handle_inbound_outer(
        &mut self,
        record: OuterRecord,
        now_ticks: u64,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<InboundInner, SessionError> {
        self.maybe_expire_reset_pending(now_ticks);
        record
            .header
            .validate_v0()
            .map_err(|_| SessionError::InvalidHeader)?;
        if record.header.session_id != self.session_id {
            return Err(SessionError::UnknownSession);
        }
        self.check_inbound_epoch_policy(&record.header)?;

        let OuterRecord { header, payload } = record;
        match header.typ {
            0x03 => self
                .decrypt_data_outer(&header, &payload, rng)
                .map(InboundInner::Data),
            0x05 => self
                .decrypt_rekey_ctrl_outer(&header, &payload, rng)
                .map(InboundInner::RekeyPlain),
            _ => Err(SessionError::InvalidHeader),
        }
    }

    fn send_step_mk(&mut self) -> Result<[u8; 32], SessionError> {
        let (mk, ck2) = msg_step(&self.send_ck, self.send_sym_idx);
        self.send_ck = Zeroizing::new(ck2);
        self.send_sym_idx = self
            .send_sym_idx
            .checked_add(1)
            .ok_or(SessionError::ReplayRejected)?;
        Ok(mk)
    }

    fn recv_step_mk(&mut self) -> Result<[u8; 32], SessionError> {
        let (mk, ck2) = msg_step(&self.recv_ck, self.recv_sym_idx);
        self.recv_ck = Zeroizing::new(ck2);
        self.recv_sym_idx = self
            .recv_sym_idx
            .checked_add(1)
            .ok_or(SessionError::ReplayRejected)?;
        Ok(mk)
    }

    fn fill_recv_gap_to_counter(
        &mut self,
        sender_pub: &[u8; 32],
        base: u64,
        target: u64,
    ) -> Result<(), SessionError> {
        if base >= target {
            return Ok(());
        }
        let additional_skips = (target - base) as usize;
        if self.skipped.len() + additional_skips > MAX_SKIP {
            return Err(SessionError::MaxSkipExceeded);
        }
        for cnt in base..target {
            let mk = self.recv_step_mk()?;
            self.skipped.insert(sender_pub, cnt, mk)?;
        }
        Ok(())
    }

    fn replay_precheck(&self, c: u64) -> Result<(), SessionError> {
        if self.decrypted_counters.contains(&c) {
            return Err(SessionError::ReplayRejected);
        }
        if let Some(hw) = self.recv_high_water {
            if c < hw.saturating_sub(MAX_SKIP as u64) {
                return Err(SessionError::ReplayRejected);
            }
        }
        Ok(())
    }

    fn prune_decrypted_cache(&mut self) {
        let Some(hw) = self.recv_high_water else {
            return;
        };
        let floor = hw.saturating_sub(MAX_SKIP as u64);
        self.decrypted_counters.retain(|&x| x >= floor);
    }

    fn bind_or_dh_ratchet(
        &mut self,
        sender_pub: [u8; 32],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(), SessionError> {
        match self.peer_ratchet_pub {
            None => {
                self.peer_ratchet_pub = Some(sender_pub);
            }
            Some(p) if p == sender_pub => {}
            Some(_) => {
                self.apply_inbound_dh_ratchet(sender_pub, rng)?;
            }
        }
        Ok(())
    }

    fn apply_inbound_dh_ratchet(
        &mut self,
        p_new: [u8; 32],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(), SessionError> {
        let dh_out = self.ratchet_sk.diffie_hellman(&PublicKey::from(p_new));
        let dh_bytes = *dh_out.as_bytes();
        let (rk_new, mix_a, mix_b) = dh_mix(&self.root_key, &dh_bytes);
        self.root_key = Zeroizing::new(rk_new);
        match self.role {
            Role::Initiator => {
                self.send_ck = Zeroizing::new(mix_a);
                self.recv_ck = Zeroizing::new(mix_b);
            }
            Role::Responder => {
                self.send_ck = Zeroizing::new(mix_b);
                self.recv_ck = Zeroizing::new(mix_a);
            }
        }
        self.send_sym_idx = 0;
        self.recv_sym_idx = 0;
        self.peer_ratchet_pub = Some(p_new);
        let new_sk = random_static_secret(rng);
        self.ratchet_sk = new_sk;
        self.my_ratchet_pub = *PublicKey::from(&self.ratchet_sk).as_bytes();
        Ok(())
    }

    /// Apply peer DH ratchet advance explicitly (normally driven by [`Session::decrypt_data`]).
    // Reserved for tests / tooling; inbound ratchet is normally driven by decrypt paths.
    #[allow(dead_code)]
    pub(crate) fn dh_ratchet(
        &mut self,
        new_peer_pub: [u8; 32],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(), SessionError> {
        self.apply_inbound_dh_ratchet(new_peer_pub, rng)
    }

    pub(crate) fn encrypt_data_plain512(
        &mut self,
        plaintext512: &[u8; DATA_INNER_FIXED],
    ) -> Result<(Header, Vec<u8>), SessionError> {
        let mk = self.send_step_mk()?;
        let hdr = Header {
            version: HEADER_VERSION_V0,
            typ: 0x03,
            flags: 0,
            epoch_be: self.epoch,
            session_id: self.session_id,
            counter_be: self.send_wire_counter,
            ratchet_pub: self.my_ratchet_pub,
        };
        let ct = data::encrypt_data_payload(&mk, &hdr, plaintext512)
            .map_err(|_| SessionError::DecryptionFailed)?;
        let ctr = self.send_wire_counter;
        self.send_wire_counter = self
            .send_wire_counter
            .checked_add(1)
            .ok_or(SessionError::ReplayRejected)?;
        self.anchor.highest_wire_seen_be = self.anchor.highest_wire_seen_be.max(ctr);
        Ok((hdr, ct))
    }

    /// Inner REKEY encrypt without outer `PAD()` — use outer wrapping on [`Self::encrypt_rekey_ctrl_outer`] for wire.
    // Reserved: exposed outer path via SessionHandle.
    #[allow(dead_code)]
    pub(crate) fn encrypt_rekey_ctrl(
        &mut self,
        rekey_body_leading_4: &[u8; 4],
    ) -> Result<(Header, Vec<u8>), SessionError> {
        let plain = crate::control::ctrl_inner_padded256(rekey_body_leading_4)
            .map_err(|_| SessionError::InvalidHeader)?;
        let hdr = Header {
            version: HEADER_VERSION_V0,
            typ: 0x05,
            flags: 0,
            epoch_be: self.epoch,
            session_id: self.session_id,
            counter_be: self.send_wire_counter,
            ratchet_pub: self.my_ratchet_pub,
        };
        let ct = crate::control::encrypt_ctrl_payload(&self.okm, &hdr, &plain)
            .map_err(|_| SessionError::DecryptionFailed)?;
        let ctr = self.send_wire_counter;
        self.send_wire_counter = self
            .send_wire_counter
            .checked_add(1)
            .ok_or(SessionError::ReplayRejected)?;
        self.anchor.highest_wire_seen_be = self.anchor.highest_wire_seen_be.max(ctr);
        Ok((hdr, ct))
    }

    /// DATA logical `nonce ‖ ciphertext` padded with §6.5 `PAD()` for [`libgary_wire::OuterRecord`].
    pub(crate) fn encrypt_data_plain512_outer(
        &mut self,
        plaintext512: &[u8; DATA_INNER_FIXED],
        pad_rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(Header, Vec<u8>), SessionError> {
        let mk = self.send_step_mk()?;
        let hdr = Header {
            version: HEADER_VERSION_V0,
            typ: 0x03,
            flags: 0,
            epoch_be: self.epoch,
            session_id: self.session_id,
            counter_be: self.send_wire_counter,
            ratchet_pub: self.my_ratchet_pub,
        };
        let ct = data::encrypt_data_payload(&mk, &hdr, plaintext512)
            .map_err(|_| SessionError::DecryptionFailed)?;
        let mut logical = Vec::with_capacity(24 + ct.len());
        logical.extend_from_slice(&data::nonce_data(&mk, &hdr));
        logical.extend_from_slice(&ct);
        let ctr = self.send_wire_counter;
        self.send_wire_counter = self
            .send_wire_counter
            .checked_add(1)
            .ok_or(SessionError::ReplayRejected)?;
        self.anchor.highest_wire_seen_be = self.anchor.highest_wire_seen_be.max(ctr);
        pad_outer(&logical, pad_rng).map_err(|_| SessionError::InvalidHeader)
            .map(|payload| (hdr, payload))
    }

    /// Inverse of [`Self::encrypt_data_plain512_outer`] after outer framing (`strip_outer_pad` with logical length 552).
    pub(crate) fn decrypt_data_outer(
        &mut self,
        header: &Header,
        padded_logical: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Zeroizing<[u8; DATA_INNER_FIXED]>, SessionError> {
        const DATA_LOGICAL: usize = 24 + DATA_INNER_FIXED + 16;
        let logical = strip_outer_pad(padded_logical, DATA_LOGICAL)
            .map_err(|_| SessionError::InvalidHeader)?;
        let ct = &logical[24..];
        self.decrypt_data(header, ct, rng)
    }

    /// REKEY logical `nonce ‖ ciphertext` padded for [`libgary_wire::OuterRecord`].
    pub(crate) fn encrypt_rekey_ctrl_outer(
        &mut self,
        rekey_body_leading_4: &[u8; 4],
        pad_rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(Header, Vec<u8>), SessionError> {
        let plain = crate::control::ctrl_inner_padded256(rekey_body_leading_4)
            .map_err(|_| SessionError::InvalidHeader)?;
        let hdr = Header {
            version: HEADER_VERSION_V0,
            typ: 0x05,
            flags: 0,
            epoch_be: self.epoch,
            session_id: self.session_id,
            counter_be: self.send_wire_counter,
            ratchet_pub: self.my_ratchet_pub,
        };
        let ct = crate::control::encrypt_ctrl_payload(&self.okm, &hdr, &plain)
            .map_err(|_| SessionError::DecryptionFailed)?;
        let nonce = crate::control::nonce_ctrl(
            &self.okm,
            hdr.typ,
            hdr.epoch_be,
            hdr.counter_be,
            &hdr.session_id,
        );
        let mut logical = Vec::with_capacity(24 + ct.len());
        logical.extend_from_slice(&nonce);
        logical.extend_from_slice(&ct);
        let ctr = self.send_wire_counter;
        self.send_wire_counter = self
            .send_wire_counter
            .checked_add(1)
            .ok_or(SessionError::ReplayRejected)?;
        self.anchor.highest_wire_seen_be = self.anchor.highest_wire_seen_be.max(ctr);
        pad_outer(&logical, pad_rng).map_err(|_| SessionError::InvalidHeader)
            .map(|payload| (hdr, payload))
    }

    /// Verify peer REKEY AEAD after stripping outer `PAD()` (logical length 296).
    pub(crate) fn decrypt_rekey_ctrl_outer(
        &mut self,
        header: &Header,
        padded_logical: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<[u8; 256], SessionError> {
        if header.version != HEADER_VERSION_V0 || header.typ != 0x05 {
            return Err(SessionError::InvalidHeader);
        }
        if header.session_id != self.session_id || header.epoch_be != self.epoch {
            return Err(SessionError::StaleEpochRejected);
        }
        let c = header.counter_be;
        self.replay_precheck(c)?;
        self.bind_or_dh_ratchet(header.ratchet_pub, rng)?;
        const CTRL_LOGICAL: usize = 24 + 256 + 16;
        let logical = strip_outer_pad(padded_logical, CTRL_LOGICAL)
            .map_err(|_| SessionError::InvalidHeader)?;
        let ct = &logical[24..];
        let pt = crate::control::decrypt_ctrl_payload(&self.okm, header, ct)
            .map_err(|_| SessionError::DecryptionFailed)?;
        self.decrypted_counters.insert(c);
        self.recv_high_water = Some(self.recv_high_water.map(|h| h.max(c)).unwrap_or(c));
        self.prune_decrypted_cache();
        self.anchor.highest_wire_seen_be = self.anchor.highest_wire_seen_be.max(c);
        Ok(pt)
    }

    #[allow(unused_variables)] // RNG is required only when an inbound DH ratchet rotates keys (§8.5).
    pub(crate) fn decrypt_data(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Zeroizing<[u8; DATA_INNER_FIXED]>, SessionError> {
        if header.version != HEADER_VERSION_V0 || header.typ != 0x03 {
            return Err(SessionError::InvalidHeader);
        }
        if header.session_id != self.session_id || header.epoch_be != self.epoch {
            return Err(SessionError::StaleEpochRejected);
        }
        let c = header.counter_be;
        self.replay_precheck(c)?;

        let sender_pub = header.ratchet_pub;
        self.bind_or_dh_ratchet(sender_pub, rng)?;

        let mk = if let Some(mk) = self.skipped.take(&sender_pub, c) {
            mk
        } else if let Some(hw) = self.recv_high_water {
            if c <= hw {
                return Err(SessionError::ReplayRejected);
            }
            let base = hw.saturating_add(1);
            self.fill_recv_gap_to_counter(&sender_pub, base, c)?;
            self.recv_step_mk()?
        } else {
            self.fill_recv_gap_to_counter(&sender_pub, 0, c)?;
            self.recv_step_mk()?
        };

        let nonce = data::nonce_data(&mk, header);
        let pt = crate::aead::xdecrypt(&mk, &nonce, ciphertext, &header.encode())
            .map_err(|_| SessionError::DecryptionFailed)?;
        let pt_arr: [u8; DATA_INNER_FIXED] =
            pt.try_into().map_err(|_| SessionError::InvalidHeader)?;

        self.decrypted_counters.insert(c);
        self.recv_high_water = Some(self.recv_high_water.map(|h| h.max(c)).unwrap_or(c));
        self.prune_decrypted_cache();
        self.anchor.highest_wire_seen_be = self.anchor.highest_wire_seen_be.max(c);
        Ok(Zeroizing::new(pt_arr))
    }

    /// Zeroize session cryptographic material (destructive).
    // Reserved for explicit teardown API — no stable SessionHandle wrapper in v0.
    #[allow(dead_code)]
    pub(crate) fn reset(&mut self) {
        self.reset_local();
    }

    #[allow(dead_code)]
    pub(crate) fn reset_local(&mut self) {
        self.okm.zeroize();
        self.root_key.zeroize();
        self.send_ck.zeroize();
        self.recv_ck.zeroize();
        self.skipped.clear();
        self.decrypted_counters.clear();
        self.recv_high_water = None;
        self.send_wire_counter = 0;
        self.send_sym_idx = 0;
        self.recv_sym_idx = 0;
        self.peer_ratchet_pub = None;
        self.mode = SessionMode::Active { epoch: self.epoch };
    }

    pub(crate) fn session_snapshot_preimage(&self) -> Vec<u8> {
        let peer = self.peer_ratchet_pub.unwrap_or([0u8; 32]);
        let mut v = Vec::new();
        v.extend_from_slice(&self.session_id);
        v.extend_from_slice(&self.epoch.to_be_bytes());
        v.extend_from_slice(&*self.root_key);
        v.extend_from_slice(&*self.send_ck);
        v.extend_from_slice(&*self.recv_ck);
        v.extend_from_slice(&self.my_ratchet_pub);
        v.extend_from_slice(&peer);
        v.extend_from_slice(&self.send_wire_counter.to_be_bytes());
        let recv_hw = self
            .recv_high_water
            .unwrap_or(RECV_HIGH_WATER_NONE_SENTINEL);
        v.extend_from_slice(&recv_hw.to_be_bytes());
        v.extend_from_slice(&self.send_sym_idx.to_be_bytes());
        v.extend_from_slice(&self.recv_sym_idx.to_be_bytes());
        v
    }

    pub(crate) fn recompute_anchor_commitment(&mut self) {
        let snap = self.session_snapshot_preimage();
        self.anchor.state_commitment = compute_state_commitment(&snap, self.anchor.global_epoch_be);
    }

    pub(crate) fn verify_anchor_commitment(&self) -> bool {
        let snap = self.session_snapshot_preimage();
        let candidate = compute_state_commitment(&snap, self.anchor.global_epoch_be);
        candidate == self.anchor.state_commitment
    }

    pub(crate) fn export_state(&self) -> SessionExport {
        let peer = self.peer_ratchet_pub.unwrap_or([0u8; 32]);
        let recv_hw = self
            .recv_high_water
            .map(|h| h as u64)
            .unwrap_or(RECV_HIGH_WATER_NONE_SENTINEL);
        let blob = encode_blob_v2(
            self.role,
            &self.root_key,
            &self.send_ck,
            &self.recv_ck,
            &self.ratchet_sk.to_bytes(),
            &self.my_ratchet_pub,
            &peer,
            self.send_wire_counter,
            recv_hw,
            self.send_sym_idx,
            self.recv_sym_idx,
            &self.skipped,
        );
        SessionExport {
            ratchet_blob: blob,
            okm: *self.okm,
            anchor: self.anchor.clone(),
            session_id: self.session_id,
            epoch: self.epoch,
        }
    }

    /// Stable digest over everything that **round-trips through v0 WAL / [`SessionExport`]**.
    ///
    /// Domain label `libgary.session.persistence-equiv.v0` — bump if [`Self::export_state`] layout changes.
    ///
    /// Intentionally excludes ephemeral fields (`decrypted_counters`, [`SessionMode`]) not stored in v0 blobs.
    #[must_use]
    pub(crate) fn persistence_equivalence_digest(&self) -> [u8; 32] {
        let export = self.export_state();
        let mut h = Sha256::new();
        h.update(b"libgary.session.persistence-equiv.v0");
        h.update(&export.epoch.to_be_bytes());
        h.update(&export.session_id);
        h.update(&export.okm);
        h.update(&(export.ratchet_blob.len() as u64).to_be_bytes());
        h.update(&export.ratchet_blob);
        h.update(&export.anchor.encode());
        h.finalize().into()
    }

    pub(crate) fn import_state(export: SessionExport) -> Result<Self, SessionError> {
        let parsed = decode_blob_v2(&export.ratchet_blob)?;
        let recv_high_water = if parsed.recv_high_water_be == RECV_HIGH_WATER_NONE_SENTINEL {
            None
        } else {
            Some(parsed.recv_high_water_be)
        };
        Ok(Self {
            session_id: export.session_id,
            epoch: export.epoch,
            mode: SessionMode::Active {
                epoch: export.epoch,
            },
            okm: Zeroizing::new(export.okm),
            root_key: Zeroizing::new(parsed.rk),
            send_ck: Zeroizing::new(parsed.cks),
            recv_ck: Zeroizing::new(parsed.ckr),
            send_wire_counter: parsed.send_count_be,
            recv_high_water,
            send_sym_idx: parsed.send_sym_idx_be,
            recv_sym_idx: parsed.recv_sym_idx_be,
            ratchet_sk: StaticSecret::from(parsed.dh_ratchet_sk),
            my_ratchet_pub: parsed.dh_ratchet_pk,
            peer_ratchet_pub: {
                let z = parsed.peer_ratchet_pub;
                if z == [0u8; 32] { None } else { Some(z) }
            },
            skipped: parsed.skipped,
            role: parsed.role,
            anchor: export.anchor,
            decrypted_counters: HashSet::new(),
        })
    }

    #[cfg(feature = "protocol-test-api")]
    pub(crate) fn skipped_cache_len(&self) -> usize {
        self.skipped.len()
    }
}
