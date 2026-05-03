//! Relay outer envelope (`docs/v0-protocol.md` §6.1).

use rand_core::{CryptoRng, RngCore};

use crate::constants::{MAX_OUTER_RECORD_SERIALIZED, MAX_ROUTE_TOKEN_LEN, RELAY_VERSION_V0};
use crate::error::WireError;
use crate::pad::{pad_outer, smallest_padding_bucket};

/// Logical relay payload after stripping §6.5 `PAD()` — relay parses **only** token bounds + opaque length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayOuterEnvelope {
    pub route_token: Vec<u8>,
    pub opaque_bytes: Vec<u8>,
}

impl RelayOuterEnvelope {
    /// Serialize `relay_version ‖ route_token_len_be ‖ route_token ‖ opaque_len_be ‖ opaque_bytes` **without** padding.
    pub fn encode_logical(&self) -> Result<Vec<u8>, WireError> {
        if self.route_token.len() > MAX_ROUTE_TOKEN_LEN {
            return Err(WireError::RouteTokenTooLong);
        }
        let ol = self.opaque_bytes.len();
        let ol_u32: u32 = ol.try_into().map_err(|_| WireError::OpaqueTooLarge)?;
        if MAX_OUTER_RECORD_SERIALIZED < ol {
            return Err(WireError::OpaqueTooLarge);
        }

        let logical_len = 1usize
            .checked_add(2)
            .and_then(|x| x.checked_add(self.route_token.len()))
            .and_then(|x| x.checked_add(4))
            .and_then(|x| x.checked_add(ol))
            .ok_or(WireError::OpaqueTooLarge)?;

        let mut out = Vec::with_capacity(logical_len);
        out.push(RELAY_VERSION_V0);
        out.extend_from_slice(&(self.route_token.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.route_token);
        out.extend_from_slice(&ol_u32.to_be_bytes());
        out.extend_from_slice(&self.opaque_bytes);
        debug_assert_eq!(out.len(), logical_len);
        Ok(out)
    }

    /// Decode logical bytes (already stripped of relay-level `PAD()`).
    pub fn decode_logical(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < 1 + 2 + 4 {
            return Err(WireError::Truncated);
        }
        if bytes[0] != RELAY_VERSION_V0 {
            return Err(WireError::InvalidRelayVersion);
        }
        let route_token_len = u16::from_be_bytes(bytes[1..3].try_into().unwrap()) as usize;
        if route_token_len > MAX_ROUTE_TOKEN_LEN {
            return Err(WireError::RouteTokenTooLong);
        }
        let header_end = 3usize
            .checked_add(route_token_len)
            .ok_or(WireError::Truncated)?;
        if bytes.len() < header_end.saturating_add(4) {
            return Err(WireError::Truncated);
        }
        let route_token = bytes[3..header_end].to_vec();
        let opaque_len =
            u32::from_be_bytes(bytes[header_end..header_end + 4].try_into().unwrap()) as usize;
        let logical_total = header_end
            .checked_add(4)
            .and_then(|x| x.checked_add(opaque_len))
            .ok_or(WireError::OpaqueTooLarge)?;
        if logical_total != bytes.len() {
            return Err(WireError::OpaqueLengthMismatch);
        }
        if opaque_len > MAX_OUTER_RECORD_SERIALIZED {
            return Err(WireError::OpaqueTooLarge);
        }
        let opaque_bytes = bytes[header_end + 4..].to_vec();
        debug_assert_eq!(opaque_bytes.len(), opaque_len);
        Ok(Self {
            route_token,
            opaque_bytes,
        })
    }

    /// §6.1 wire bytes: `PAD(encode_logical(..))`.
    pub fn encode_padded_wire(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, WireError> {
        let logical = self.encode_logical()?;
        pad_outer(&logical, rng)
    }

    /// Parse relay-visible framing after stripping §6.5 padding from the wire.
    pub fn decode_padded_wire(padded: &[u8]) -> Result<Self, WireError> {
        let logical_total = Self::logical_len_from_prefix(padded)?;
        if logical_total > padded.len() {
            return Err(WireError::Truncated);
        }
        let bucket = smallest_padding_bucket(logical_total).ok_or(WireError::LogicalTooLarge)?;
        if padded.len() != bucket {
            return Err(WireError::PaddingBucketMismatch);
        }
        Self::decode_logical(&padded[..logical_total])
    }

    fn logical_len_from_prefix(padded: &[u8]) -> Result<usize, WireError> {
        if padded.len() < 1 + 2 + 4 {
            return Err(WireError::Truncated);
        }
        if padded[0] != RELAY_VERSION_V0 {
            return Err(WireError::InvalidRelayVersion);
        }
        let route_token_len = u16::from_be_bytes(padded[1..3].try_into().unwrap()) as usize;
        if route_token_len > MAX_ROUTE_TOKEN_LEN {
            return Err(WireError::RouteTokenTooLong);
        }
        let ol_pos = 3usize
            .checked_add(route_token_len)
            .ok_or(WireError::Truncated)?;
        if padded.len() < ol_pos.saturating_add(4) {
            return Err(WireError::Truncated);
        }
        let opaque_len =
            u32::from_be_bytes(padded[ol_pos..ol_pos + 4].try_into().unwrap()) as usize;
        let total = ol_pos
            .checked_add(4)
            .and_then(|x| x.checked_add(opaque_len))
            .ok_or(WireError::OpaqueTooLarge)?;
        Ok(total)
    }
}
