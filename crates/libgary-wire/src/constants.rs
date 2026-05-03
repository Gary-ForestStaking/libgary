//! Normative sizes (`docs/v0-protocol.md` §6).

/// Relay envelope `relay_version` for v0 (`docs/v0-protocol.md` §6.1).
pub const RELAY_VERSION_V0: u8 = 0x01;

/// Header `version` for v0 (`docs/v0-protocol.md` §6.3).
pub const HEADER_VERSION_V0: u8 = 0x01;

/// Maximum `record_length_be` value (bytes of `Header ‖ payload`) — §6.2.
pub const MAX_RECORD_BODY_LEN: usize = 1_048_576;

/// Maximum `route_token` length in v0 — §6.1.
pub const MAX_ROUTE_TOKEN_LEN: usize = 512;

/// Maximum serialized `OuterRecord` length we accept inside relay opaque bytes (`4 + MAX_RECORD_BODY_LEN`).
pub const MAX_OUTER_RECORD_SERIALIZED: usize = 4 + MAX_RECORD_BODY_LEN;
