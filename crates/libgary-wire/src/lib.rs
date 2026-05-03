//! Fixed-layout wire structs for libgary v0 (`docs/v0-protocol.md` §6).
#![forbid(unsafe_code)]

mod constants;
mod error;
mod outer;
mod pad;
mod relay;

pub use constants::{
    HEADER_VERSION_V0, MAX_OUTER_RECORD_SERIALIZED, MAX_RECORD_BODY_LEN, MAX_ROUTE_TOKEN_LEN,
    RELAY_VERSION_V0,
};
pub use error::WireError;
pub use outer::OuterRecord;
pub use pad::{PADDING_BUCKETS, pad_outer, smallest_padding_bucket, strip_outer_pad};
pub use relay::RelayOuterEnvelope;

/// Outer-record header: exactly **63** bytes (v0-protocol §6.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub version: u8,
    pub typ: u8,
    pub flags: u8,
    pub epoch_be: u32,
    pub session_id: [u8; 16],
    pub counter_be: u64,
    pub ratchet_pub: [u8; 32],
}

impl Header {
    pub const LEN: usize = 63;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = self.version;
        out[1] = self.typ;
        out[2] = self.flags;
        out[3..7].copy_from_slice(&self.epoch_be.to_be_bytes());
        out[7..23].copy_from_slice(&self.session_id);
        out[23..31].copy_from_slice(&self.counter_be.to_be_bytes());
        out[31..63].copy_from_slice(&self.ratchet_pub);
        out
    }

    pub fn decode(bytes: &[u8; Self::LEN]) -> Self {
        Self {
            version: bytes[0],
            typ: bytes[1],
            flags: bytes[2],
            epoch_be: u32::from_be_bytes(bytes[3..7].try_into().unwrap()),
            session_id: bytes[7..23].try_into().unwrap(),
            counter_be: u64::from_be_bytes(bytes[23..31].try_into().unwrap()),
            ratchet_pub: bytes[31..63].try_into().unwrap(),
        }
    }

    /// Decode the first 63 bytes and run [`Self::validate_v0`].
    pub fn parse_checked(slice: &[u8]) -> Result<Self, WireError> {
        if slice.len() < Self::LEN {
            return Err(WireError::Truncated);
        }
        let arr: &[u8; Self::LEN] = slice[..Self::LEN].try_into().unwrap();
        let h = Self::decode(arr);
        h.validate_v0()?;
        Ok(h)
    }

    /// Structural validation for v0 records (`docs/v0-protocol.md` §6.3 §7).
    pub fn validate_v0(&self) -> Result<(), WireError> {
        if self.version != HEADER_VERSION_V0 {
            return Err(WireError::InvalidHeaderVersion);
        }
        if self.flags != 0 {
            return Err(WireError::InvalidHeaderFlags);
        }
        match self.typ {
            // INIT, INIT_ACK, DATA, REKEY, CLOSE, RESET_INIT, RESET_ACK
            0x01 | 0x02 | 0x03 | 0x05 | 0x06 | 0x07 | 0x08 => Ok(()),
            // RECEIPT deprecated / reserved opcodes
            _ => Err(WireError::InvalidHeaderType),
        }
    }
}

/// Handshake `InitBody` — initiator → responder (**100** bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitBody {
    pub initiator_sig_pk: [u8; 32],
    pub initiator_dh_pk: [u8; 32],
    pub ephemeral_ek_pub: [u8; 32],
    pub otp_index_be: u16,
    pub reserved_be: u16,
}

impl InitBody {
    pub const LEN: usize = 100;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..32].copy_from_slice(&self.initiator_sig_pk);
        out[32..64].copy_from_slice(&self.initiator_dh_pk);
        out[64..96].copy_from_slice(&self.ephemeral_ek_pub);
        out[96..98].copy_from_slice(&self.otp_index_be.to_be_bytes());
        out[98..100].copy_from_slice(&self.reserved_be.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8; Self::LEN]) -> Result<Self, WireError> {
        if u16::from_be_bytes(bytes[98..100].try_into().unwrap()) != 0 {
            return Err(WireError::InitReservedNonZero);
        }
        Ok(Self {
            initiator_sig_pk: bytes[0..32].try_into().unwrap(),
            initiator_dh_pk: bytes[32..64].try_into().unwrap(),
            ephemeral_ek_pub: bytes[64..96].try_into().unwrap(),
            otp_index_be: u16::from_be_bytes(bytes[96..98].try_into().unwrap()),
            reserved_be: u16::from_be_bytes(bytes[98..100].try_into().unwrap()),
        })
    }
}

/// `InitAckCore` — responder → initiator (**72** bytes), without MAC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitAckCore {
    pub responder_sig_pk: [u8; 32],
    pub responder_dh_pk: [u8; 32],
    pub ack_nonce_be: u64,
}

impl InitAckCore {
    pub const LEN: usize = 72;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..32].copy_from_slice(&self.responder_sig_pk);
        out[32..64].copy_from_slice(&self.responder_dh_pk);
        out[64..72].copy_from_slice(&self.ack_nonce_be.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8; Self::LEN]) -> Self {
        Self {
            responder_sig_pk: bytes[0..32].try_into().unwrap(),
            responder_dh_pk: bytes[32..64].try_into().unwrap(),
            ack_nonce_be: u64::from_be_bytes(bytes[64..72].try_into().unwrap()),
        }
    }
}

/// `InitAckWire` = `InitAckCore` ‖ `confirm_mac` (**88** bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitAckWire {
    pub core: InitAckCore,
    pub confirm_mac: [u8; 16],
}

impl InitAckWire {
    pub const LEN: usize = 88;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        let core = self.core.encode();
        out[0..72].copy_from_slice(&core);
        out[72..88].copy_from_slice(&self.confirm_mac);
        out
    }

    pub fn decode(bytes: &[u8; Self::LEN]) -> Self {
        Self {
            core: InitAckCore::decode(bytes[0..72].try_into().unwrap()),
            confirm_mac: bytes[72..88].try_into().unwrap(),
        }
    }
}
