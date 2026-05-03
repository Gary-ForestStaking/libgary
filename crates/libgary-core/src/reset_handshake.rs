//! `RESET_INIT` / `RESET_ACK` inner AEAD ([v0-reset.md](docs/v0-reset.md) §4.3).

use libgary_wire::InitAckWire;

use crate::aead::{AeadError, xdecrypt, xencrypt};
use crate::constants::{AAD_RESET_ACK_PREFIX, AAD_RESET_INIT_PREFIX};
use crate::handshake::{k_ack, k_init, plain_inner_ack, plain_inner_init};
use crate::nonce::nonce24;

pub fn nonce_reset_init(
    km: &[u8],
    th0_r: &[u8; 32],
    epoch_be: u32,
    session_id: &[u8; 16],
) -> [u8; 24] {
    let mut label = Vec::with_capacity(5 + 4 + 16);
    label.extend_from_slice(b"RINIT");
    label.extend_from_slice(&epoch_be.to_be_bytes());
    label.extend_from_slice(session_id);
    let mut i_core = Vec::with_capacity(km.len() + 32);
    i_core.extend_from_slice(km);
    i_core.extend_from_slice(th0_r);
    nonce24(&i_core, &label)
}

pub fn nonce_reset_ack(okm: &[u8; 64], epoch_be: u32, session_id: &[u8; 16]) -> [u8; 24] {
    let mut label = Vec::with_capacity(4 + 4 + 16);
    label.extend_from_slice(b"RACK");
    label.extend_from_slice(&epoch_be.to_be_bytes());
    label.extend_from_slice(session_id);
    nonce24(okm, &label)
}

pub fn aad_reset_init(
    epoch_be: u32,
    session_id: &[u8; 16],
    reset_init_body: &[u8; 100],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_RESET_INIT_PREFIX.len() + 4 + 16 + 100);
    aad.extend_from_slice(AAD_RESET_INIT_PREFIX);
    aad.extend_from_slice(&epoch_be.to_be_bytes());
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(reset_init_body);
    aad
}

pub fn aad_reset_ack(
    epoch_be: u32,
    session_id: &[u8; 16],
    reset_ack_wire: &[u8; InitAckWire::LEN],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_RESET_ACK_PREFIX.len() + 4 + 16 + InitAckWire::LEN);
    aad.extend_from_slice(AAD_RESET_ACK_PREFIX);
    aad.extend_from_slice(&epoch_be.to_be_bytes());
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(reset_ack_wire);
    aad
}

pub fn encrypt_reset_init_inner(
    km: &[u8],
    th0_r: &[u8; 32],
    epoch_be: u32,
    session_id: &[u8; 16],
    reset_init_body: &[u8; 100],
) -> Result<Vec<u8>, AeadError> {
    let key = k_init(km, th0_r);
    let nonce = nonce_reset_init(km, th0_r, epoch_be, session_id);
    let aad = aad_reset_init(epoch_be, session_id, reset_init_body);
    let pt = plain_inner_init(th0_r);
    xencrypt(&key, &nonce, &pt, &aad)
}

pub fn decrypt_reset_init_inner(
    km: &[u8],
    th0_r: &[u8; 32],
    epoch_be: u32,
    session_id: &[u8; 16],
    reset_init_body: &[u8; 100],
    ciphertext: &[u8],
) -> Result<[u8; 256], AeadError> {
    let key = k_init(km, th0_r);
    let nonce = nonce_reset_init(km, th0_r, epoch_be, session_id);
    let aad = aad_reset_init(epoch_be, session_id, reset_init_body);
    let pt = xdecrypt(&key, &nonce, ciphertext, &aad)?;
    pt.try_into().map_err(|_| AeadError::Cipher)
}

pub fn encrypt_reset_ack_inner(
    okm: &[u8; 64],
    th1_r: &[u8; 32],
    epoch_be: u32,
    session_id: &[u8; 16],
    reset_ack_wire: &[u8; InitAckWire::LEN],
) -> Result<Vec<u8>, AeadError> {
    let key = k_ack(okm);
    let nonce = nonce_reset_ack(okm, epoch_be, session_id);
    let aad = aad_reset_ack(epoch_be, session_id, reset_ack_wire);
    let pt = plain_inner_ack(th1_r);
    xencrypt(&key, &nonce, &pt, &aad)
}

pub fn decrypt_reset_ack_inner(
    okm: &[u8; 64],
    epoch_be: u32,
    session_id: &[u8; 16],
    reset_ack_wire: &[u8; InitAckWire::LEN],
    ciphertext: &[u8],
) -> Result<[u8; 256], AeadError> {
    let key = k_ack(okm);
    let nonce = nonce_reset_ack(okm, epoch_be, session_id);
    let aad = aad_reset_ack(epoch_be, session_id, reset_ack_wire);
    let pt = xdecrypt(&key, &nonce, ciphertext, &aad)?;
    pt.try_into().map_err(|_| AeadError::Cipher)
}
