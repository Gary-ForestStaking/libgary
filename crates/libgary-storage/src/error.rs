use libgary_core::engine::SessionError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("bundle decode error: {0}")]
    BundleDecode(&'static str),

    #[error("trusted anchor meta decode error: {0}")]
    MetaDecode(&'static str),

    #[error("session cryptographic error")]
    Session(#[from] SessionError),

    #[error("bundle magic or version mismatch")]
    BadMagic,

    #[error("ratchet blob corrupted")]
    CorruptBlob,

    #[error("state_commitment does not match ratchet snapshot")]
    CommitmentMismatch,

    #[error("trusted anchor meta missing (fail closed)")]
    TrustedMetaMissing,

    #[error("persisted session identity does not match trusted meta")]
    SessionIdentityMismatch,

    #[error("detected stale snapshot / rollback vs trusted anchor")]
    RollbackDetected,

    #[error("no persisted session bundle")]
    NoBundle,

    #[error("WAL envelope truncated")]
    EnvelopeTruncated,

    #[error("WAL envelope magic or version mismatch")]
    BadEnvelopeMagic,

    #[error("WAL envelope checksum mismatch")]
    EnvelopeChecksum,
}
