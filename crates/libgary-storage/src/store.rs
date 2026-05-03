//! High-level session persistence API.

use std::path::{Path, PathBuf};

use libgary_core::engine::{SessionHandle, SessionWalSource};

use crate::atomic_write::{atomic_write, read_if_exists};
use crate::bundle_codec::{decode_bundle, encode_bundle};
use crate::trusted_meta::{TrustedAnchorMeta, assert_monotonic_vs_trusted};
use crate::wal_envelope::{decode_wal_envelope, encode_wal_envelope};
use crate::StorageError;

/// Persisted session store: one checksum’d WAL file (`bundle ‖ trusted_meta`) per §3.1 atomic replace.
#[derive(Clone, Debug)]
pub struct SessionStore {
    envelope_path: PathBuf,
}

impl SessionStore {
    pub fn new(envelope_path: impl Into<PathBuf>) -> Self {
        Self {
            envelope_path: envelope_path.into(),
        }
    }

    pub fn envelope_path(&self) -> &Path {
        &self.envelope_path
    }

    /// Atomic persist: temp ‖ fsync ‖ rename ‖ fsync dir — single envelope avoids bundle/meta split crashes.
    pub fn save_session<S: SessionWalSource>(&self, session: &S) -> Result<(), StorageError> {
        let export = session.export_state();
        let bundle = encode_bundle(&export);
        let meta = TrustedAnchorMeta::from_wal_source(session);
        let meta_arr = meta.encode();
        let wal = encode_wal_envelope(&bundle, meta_arr.as_slice());
        atomic_write(&self.envelope_path, &wal)?;
        Ok(())
    }

    /// Same transactional semantics as [`Self::save_session`].
    pub fn commit_anchor<S: SessionWalSource>(&self, session: &S) -> Result<(), StorageError> {
        self.save_session(session)
    }

    pub fn load_session(&self) -> Result<SessionHandle, StorageError> {
        let wal_bytes = match read_if_exists(&self.envelope_path)? {
            Some(b) => b,
            None => return Err(StorageError::NoBundle),
        };
        let (bundle_bytes, meta_bytes) = decode_wal_envelope(&wal_bytes).map_err(|e| match e {
            StorageError::EnvelopeTruncated
            | StorageError::BadEnvelopeMagic
            | StorageError::EnvelopeChecksum => StorageError::CorruptBlob,
            o => o,
        })?;

        let export = decode_bundle(&bundle_bytes).map_err(|e| match e {
            StorageError::BadMagic | StorageError::BundleDecode(_) => StorageError::CorruptBlob,
            o => o,
        })?;
        let session = SessionHandle::from_export(export)?;

        if !verify_anchor(&session) {
            return Err(StorageError::CommitmentMismatch);
        }

        let meta = TrustedAnchorMeta::decode(&meta_bytes)?;
        assert_monotonic_vs_trusted(&session, &meta)?;
        Ok(session)
    }
}

/// `state_commitment` matches canonical ratchet snapshot (`docs/v0-state-integrity.md` §4).
#[inline]
pub fn verify_anchor<S: SessionWalSource>(session: &S) -> bool {
    session.verify_anchor_commitment()
}
