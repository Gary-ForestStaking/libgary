//! Inner handshake AEAD helpers ([v0-handshake](docs/v0-handshake.md), [v0-kdf](docs/v0-kdf.md)).

use crate::aead::{xdecrypt, xencrypt, AeadError};
use crate::constants::{
    AAD_ACK_PREFIX, AAD_INIT_PREFIX, INFO_ACK_AEAD_V1, INFO_ACK_INNER_V1, INFO_INIT_AEAD_V1,
    INFO_INIT_INNER_V1,
};
use crate::kdf::hkdf_zero32;
use crate::nonce::nonce24;
use libgary_wire::InitAckWire;

pub fn k_init(km: &[u8], th0: &[u8; 32]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(km.len() + 32);
    ikm.extend_from_slice(km);
    ikm.extend_from_slice(th0);
    hkdf_zero32(&ikm, INFO_INIT_AEAD_V1, 32)
        .try_into()
        .unwrap()
}

pub fn nonce_init(km: &[u8], th0: &[u8; 32], epoch_be: u32, session_id: &[u8; 16]) -> [u8; 24] {
    let mut label = Vec::with_capacity(4 + 16 + b"INIT".len());
    label.extend_from_slice(b"INIT");
    label.extend_from_slice(&epoch_be.to_be_bytes());
    label.extend_from_slice(session_id);
    let mut i_core = Vec::with_capacity(km.len() + 32);
    i_core.extend_from_slice(km);
    i_core.extend_from_slice(th0);
    nonce24(&i_core, &label)
}

pub fn aad_init(epoch_be: u32, session_id: &[u8; 16], init_body: &[u8; 100]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_INIT_PREFIX.len() + 4 + 16 + 100);
    aad.extend_from_slice(AAD_INIT_PREFIX);
    aad.extend_from_slice(&epoch_be.to_be_bytes());
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(init_body);
    aad
}

pub fn plain_inner_init(th0: &[u8; 32]) -> [u8; 256] {
    hkdf_zero32(th0, INFO_INIT_INNER_V1, 256)
        .try_into()
        .unwrap()
}

pub fn encrypt_init_inner(
    km: &[u8],
    th0: &[u8; 32],
    epoch_be: u32,
    session_id: &[u8; 16],
    init_body: &[u8; 100],
) -> Result<Vec<u8>, AeadError> {
    let key = k_init(km, th0);
    let nonce = nonce_init(km, th0, epoch_be, session_id);
    let aad = aad_init(epoch_be, session_id, init_body);
    let pt = plain_inner_init(th0);
    xencrypt(&key, &nonce, &pt, &aad)
}

pub fn k_ack(okm: &[u8; 64]) -> [u8; 32] {
    hkdf_zero32(okm, INFO_ACK_AEAD_V1, 32)
        .try_into()
        .unwrap()
}

pub fn nonce_ack(okm: &[u8; 64], epoch_be: u32, session_id: &[u8; 16]) -> [u8; 24] {
    let mut label = Vec::with_capacity(4 + 16 + b"ACK".len());
    label.extend_from_slice(b"ACK");
    label.extend_from_slice(&epoch_be.to_be_bytes());
    label.extend_from_slice(session_id);
    nonce24(okm, &label)
}

pub fn aad_ack(epoch_be: u32, session_id: &[u8; 16], init_ack_wire: &[u8; InitAckWire::LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_ACK_PREFIX.len() + 4 + 16 + InitAckWire::LEN);
    aad.extend_from_slice(AAD_ACK_PREFIX);
    aad.extend_from_slice(&epoch_be.to_be_bytes());
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(init_ack_wire);
    aad
}

pub fn plain_inner_ack(th1: &[u8; 32]) -> [u8; 256] {
    hkdf_zero32(th1, INFO_ACK_INNER_V1, 256)
        .try_into()
        .unwrap()
}

pub fn encrypt_ack_inner(
    okm: &[u8; 64],
    th1: &[u8; 32],
    epoch_be: u32,
    session_id: &[u8; 16],
    init_ack_wire: &[u8; InitAckWire::LEN],
) -> Result<Vec<u8>, AeadError> {
    let key = k_ack(okm);
    let nonce = nonce_ack(okm, epoch_be, session_id);
    let aad = aad_ack(epoch_be, session_id, init_ack_wire);
    let pt = plain_inner_ack(th1);
    xencrypt(&key, &nonce, &pt, &aad)
}

pub fn decrypt_ack_inner(
    okm: &[u8; 64],
    epoch_be: u32,
    session_id: &[u8; 16],
    init_ack_wire: &[u8; InitAckWire::LEN],
    ciphertext: &[u8],
) -> Result<[u8; 256], AeadError> {
    let key = k_ack(okm);
    let nonce = nonce_ack(okm, epoch_be, session_id);
    let aad = aad_ack(epoch_be, session_id, init_ack_wire);
    let pt = xdecrypt(&key, &nonce, ciphertext, &aad)?;
    pt.try_into().map_err(|_| AeadError::Cipher)
}

pub fn decrypt_init_inner(
    km: &[u8],
    th0: &[u8; 32],
    epoch_be: u32,
    session_id: &[u8; 16],
    init_body: &[u8; 100],
    ciphertext: &[u8],
) -> Result<[u8; 256], AeadError> {
    let key = k_init(km, th0);
    let nonce = nonce_init(km, th0, epoch_be, session_id);
    let aad = aad_init(epoch_be, session_id, init_body);
    let pt = xdecrypt(&key, &nonce, ciphertext, &aad)?;
    pt.try_into().map_err(|_| AeadError::Cipher)
}
