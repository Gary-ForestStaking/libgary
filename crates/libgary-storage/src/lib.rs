//! Atomic session persistence + trusted-anchor rollback detection (`docs/v0-state-integrity.md`).
#![forbid(unsafe_code)]

mod atomic_write;
pub mod bundle_codec;
mod error;
mod store;
mod trusted_meta;
pub mod wal_envelope;

pub use error::StorageError;
pub use libgary_core::engine::SessionHandle;
pub use store::{SessionStore, verify_anchor};
pub use trusted_meta::TrustedAnchorMeta;
