//! Role and shared engine types.

use super::error::SessionError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    pub fn role_flag(self) -> u8 {
        match self {
            Role::Initiator => 0x00,
            Role::Responder => 0x01,
        }
    }

    pub fn from_role_flag(b: u8) -> Result<Self, SessionError> {
        match b {
            0x00 => Ok(Role::Initiator),
            0x01 => Ok(Role::Responder),
            _ => Err(SessionError::InvalidHeader),
        }
    }
}
