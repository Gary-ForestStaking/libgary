//! Stateful Double Ratchet session engine (v0-protocol §8–§9).

pub mod anchor;
pub mod blob;
pub mod error;
pub mod mode;
pub mod session;
pub mod session_handle;
pub mod skipped;
pub mod types;
pub mod wal_source;

pub use anchor::{DeviceStateAnchorV1, compute_state_commitment};
pub use blob::{decode_blob_v2, encode_blob_v2};
pub use error::SessionError;
pub use session::{InboundInner, RECV_HIGH_WATER_NONE_SENTINEL, SessionExport};
pub use session_handle::SessionHandle;
pub use wal_source::SessionWalSource;
