//! `OuterRecord` (`docs/v0-protocol.md` §6.2).

use crate::Header;
use crate::constants::MAX_RECORD_BODY_LEN;
use crate::error::WireError;

/// Serialized E2E record: `record_length_be ‖ Header ‖ payload`.
///
/// `record_length_be` is **not** stored — it is always `Header::LEN + payload.len()` on encode and
/// checked against the prefix on decode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OuterRecord {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl OuterRecord {
    #[inline]
    pub fn record_body_len(&self) -> usize {
        Header::LEN + self.payload.len()
    }

    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        self.header.validate_v0()?;
        let rl = self.record_body_len();
        if rl > MAX_RECORD_BODY_LEN {
            return Err(WireError::RecordTooLarge);
        }
        let rl_u32: u32 = rl.try_into().map_err(|_| WireError::RecordTooLarge)?;
        let mut out = Vec::with_capacity(4 + rl);
        out.extend_from_slice(&rl_u32.to_be_bytes());
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < 4 {
            return Err(WireError::Truncated);
        }
        let rl = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if rl > MAX_RECORD_BODY_LEN {
            return Err(WireError::RecordTooLarge);
        }
        let total = 4usize
            .checked_add(rl)
            .ok_or(WireError::RecordLengthMismatch)?;
        if bytes.len() != total {
            return Err(WireError::RecordLengthMismatch);
        }
        if rl < Header::LEN {
            return Err(WireError::Truncated);
        }
        let header_bytes: &[u8; Header::LEN] = bytes[4..4 + Header::LEN]
            .try_into()
            .map_err(|_| WireError::Truncated)?;
        let header = Header::decode(header_bytes);
        header.validate_v0()?;
        let payload = bytes[4 + Header::LEN..].to_vec();
        debug_assert_eq!(rl, Header::LEN + payload.len());
        Ok(Self { header, payload })
    }
}
