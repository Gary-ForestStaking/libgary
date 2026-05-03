use thiserror::Error;

/// Parser / framing failure (`docs/v0-protocol.md` §6).
#[derive(Debug, Error, Eq, PartialEq)]
pub enum WireError {
    #[error("truncated wire")]
    Truncated,
    #[error("record length mismatch")]
    RecordLengthMismatch,
    #[error("record body exceeds v0 maximum")]
    RecordTooLarge,
    #[error("INIT reserved_be must be 0")]
    InitReservedNonZero,
    #[error("logical payload too large for PAD buckets")]
    LogicalTooLarge,
    #[error("padding length does not match normative bucket")]
    PaddingBucketMismatch,
    #[error("logical length inconsistent with padded buffer")]
    PaddingLogicalMismatch,
    #[error("unsupported header version")]
    InvalidHeaderVersion,
    #[error("illegal or reserved header type")]
    InvalidHeaderType,
    #[error("unsupported header flags")]
    InvalidHeaderFlags,
    #[error("unsupported relay outer version")]
    InvalidRelayVersion,
    #[error("route_token exceeds v0 limit")]
    RouteTokenTooLong,
    #[error("opaque_len does not match buffer")]
    OpaqueLengthMismatch,
    #[error("opaque_bytes exceeds implementation limit")]
    OpaqueTooLarge,
}
