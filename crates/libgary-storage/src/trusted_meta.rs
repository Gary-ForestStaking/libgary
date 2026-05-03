//! Device-trusted monotonic line (`docs/v0-state-integrity.md` §3) — **not** restored from chat backup.

use libgary_core::engine::SessionWalSource;

use crate::StorageError;

const META_MAGIC: &[u8; 4] = b"LGTM";
const META_VERSION: u32 = 1;

/// Persisted alongside the bundle to detect chat-DB / snapshot rewind while trusted store stays new.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedAnchorMeta {
    pub session_id: [u8; 16],
    pub epoch: u32,
    pub global_epoch_be: u64,
    pub highest_wire_seen_be: u64,
    pub send_wire_counter: u64,
    /// `true` iff `recv_high_water` was `None` at persist time.
    pub recv_hw_none: bool,
    pub recv_hw_be: u64,
    pub state_commitment: [u8; 32],
}

impl TrustedAnchorMeta {
    pub const ENCODED_LEN: usize = 4 + 4 + 16 + 4 + 8 + 8 + 8 + 8 + 1 + 32;

    pub fn from_wal_source<S: SessionWalSource>(session: &S) -> Self {
        let recv_hw_none = session.recv_high_water().is_none();
        let recv_hw_be = session.recv_high_water().unwrap_or(0);
        let anchor = session.anchor();
        Self {
            session_id: session.session_id(),
            epoch: session.epoch(),
            global_epoch_be: anchor.global_epoch_be,
            highest_wire_seen_be: anchor.highest_wire_seen_be,
            send_wire_counter: session.send_wire_counter(),
            recv_hw_none,
            recv_hw_be,
            state_commitment: anchor.state_commitment,
        }
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        let mut w = 0usize;
        out[w..w + 4].copy_from_slice(META_MAGIC);
        w += 4;
        out[w..w + 4].copy_from_slice(&META_VERSION.to_be_bytes());
        w += 4;
        out[w..w + 16].copy_from_slice(&self.session_id);
        w += 16;
        out[w..w + 4].copy_from_slice(&self.epoch.to_be_bytes());
        w += 4;
        out[w..w + 8].copy_from_slice(&self.global_epoch_be.to_be_bytes());
        w += 8;
        out[w..w + 8].copy_from_slice(&self.highest_wire_seen_be.to_be_bytes());
        w += 8;
        out[w..w + 8].copy_from_slice(&self.send_wire_counter.to_be_bytes());
        w += 8;
        out[w..w + 8].copy_from_slice(&self.recv_hw_be.to_be_bytes());
        w += 8;
        out[w] = if self.recv_hw_none { 1u8 } else { 0u8 };
        w += 1;
        out[w..w + 32].copy_from_slice(&self.state_commitment);
        w += 32;
        debug_assert_eq!(w, Self::ENCODED_LEN);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(StorageError::MetaDecode("length"));
        }
        if &bytes[0..4] != META_MAGIC {
            return Err(StorageError::MetaDecode("magic"));
        }
        let ver = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        if ver != META_VERSION {
            return Err(StorageError::MetaDecode("version"));
        }
        let mut o = 8usize;
        let session_id = bytes[o..o + 16].try_into().unwrap();
        o += 16;
        let epoch = u32::from_be_bytes(bytes[o..o + 4].try_into().unwrap());
        o += 4;
        let global_epoch_be = u64::from_be_bytes(bytes[o..o + 8].try_into().unwrap());
        o += 8;
        let highest_wire_seen_be = u64::from_be_bytes(bytes[o..o + 8].try_into().unwrap());
        o += 8;
        let send_wire_counter = u64::from_be_bytes(bytes[o..o + 8].try_into().unwrap());
        o += 8;
        let recv_hw_be = u64::from_be_bytes(bytes[o..o + 8].try_into().unwrap());
        o += 8;
        let recv_hw_none = bytes[o] != 0;
        o += 1;
        let state_commitment = bytes[o..o + 32].try_into().unwrap();
        Ok(Self {
            session_id,
            epoch,
            global_epoch_be,
            highest_wire_seen_be,
            send_wire_counter,
            recv_hw_none,
            recv_hw_be,
            state_commitment,
        })
    }
}

pub fn assert_monotonic_vs_trusted<S: SessionWalSource>(
    loaded: &S,
    meta: &TrustedAnchorMeta,
) -> Result<(), StorageError> {
    if loaded.session_id() != meta.session_id {
        return Err(StorageError::SessionIdentityMismatch);
    }
    if loaded.epoch() < meta.epoch {
        return Err(StorageError::RollbackDetected);
    }
    let anchor = loaded.anchor();
    if anchor.global_epoch_be < meta.global_epoch_be {
        return Err(StorageError::RollbackDetected);
    }
    if anchor.highest_wire_seen_be < meta.highest_wire_seen_be {
        return Err(StorageError::RollbackDetected);
    }
    if loaded.send_wire_counter() < meta.send_wire_counter {
        return Err(StorageError::RollbackDetected);
    }
    if anchor.state_commitment != meta.state_commitment {
        return Err(StorageError::CommitmentMismatch);
    }

    match (meta.recv_hw_none, loaded.recv_high_water()) {
        (true, None) => Ok(()),
        (true, Some(_)) => Ok(()),
        (false, None) => Err(StorageError::RollbackDetected),
        (false, Some(lc)) => {
            if lc < meta.recv_hw_be {
                Err(StorageError::RollbackDetected)
            } else {
                Ok(())
            }
        }
    }
}
