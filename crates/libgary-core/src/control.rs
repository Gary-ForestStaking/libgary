//! Control-plane AEAD (`REKEY`, `CLOSE`, …) ([v0-handshake](docs/v0-handshake.md)).

use crate::aead::{xencrypt, AeadError};
use crate::constants::{INFO_CONTROL_AEAD_V1, INFO_CTRL_PAD_V1};
use crate::kdf::hkdf_zero32;
use crate::nonce::nonce24;
use libgary_wire::Header;

pub fn k_control(okm: &[u8; 64]) -> [u8; 32] {
    hkdf_zero32(okm, INFO_CONTROL_AEAD_V1, 32)
        .try_into()
        .unwrap()
}

pub fn nonce_ctrl(
    okm: &[u8; 64],
    typ: u8,
    epoch_be: u32,
    counter_be: u64,
    session_id: &[u8; 16],
) -> [u8; 24] {
    let mut label = Vec::with_capacity(1 + 4 + 8 + 16 + b"CTRL".len());
    label.extend_from_slice(b"CTRL");
    label.push(typ);
    label.extend_from_slice(&epoch_be.to_be_bytes());
    label.extend_from_slice(&counter_be.to_be_bytes());
    label.extend_from_slice(session_id);
    nonce24(okm, &label)
}

pub fn ctrl_inner_padded256(body_leading: &[u8]) -> Result<[u8; 256], CtrlPadError> {
    if body_leading.len() > 256 {
        return Err(CtrlPadError::TooLong);
    }
    let pad_len = 256 - body_leading.len();
    let pad = hkdf_zero32(body_leading, INFO_CTRL_PAD_V1, pad_len);
    let mut out = [0u8; 256];
    out[..body_leading.len()].copy_from_slice(body_leading);
    out[body_leading.len()..].copy_from_slice(&pad);
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum CtrlPadError {
    #[error("control inner body too long")]
    TooLong,
}

pub fn encrypt_ctrl_payload(
    okm: &[u8; 64],
    hdr: &Header,
    inner_plaintext256: &[u8; 256],
) -> Result<Vec<u8>, AeadError> {
    let key = k_control(okm);
    let nonce = nonce_ctrl(
        okm,
        hdr.typ,
        hdr.epoch_be,
        hdr.counter_be,
        &hdr.session_id,
    );
    let aad = hdr.encode();
    xencrypt(&key, &nonce, inner_plaintext256, &aad)
}
