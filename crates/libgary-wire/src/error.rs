use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum WireError {
    #[error("InitBody reserved_be must be 0")]
    InitReservedNonZero,
}
