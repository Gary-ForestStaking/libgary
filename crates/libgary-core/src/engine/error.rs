//! Session engine errors (v0-protocol §10 internal mapping).

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SessionError {
    #[error("replay / ordering violation")]
    ReplayRejected,
    #[error("Header.epoch_be is stale vs session epoch")]
    StaleEpochRejected,
    #[error("AEAD verification failed")]
    DecryptionFailed,
    #[error("skipped-message derivation bound exceeded (MAX_SKIP)")]
    MaxSkipExceeded,
    #[error("malformed header / record")]
    InvalidHeader,
    #[error("session identifier mismatch")]
    UnknownSession,
    #[error("local integrity anchor rejected persisted state")]
    StateIntegrity,
    #[error("session reset / catastrophic recovery required")]
    ResetRequired,
    #[error("DATA from prior epoch during RESET isolation window")]
    LateDataAfterReset,
    #[error("Header.epoch_be jumps ahead more than one epoch")]
    FutureEpoch,
}
