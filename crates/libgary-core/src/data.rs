//! DATA inner plaintext layout ([v0-protocol](docs/v0-protocol.md) §6.4).

use crate::aead::{AeadError, xencrypt};
use crate::constants::{DATA_INNER_FIXED, INFO_DATA_INNER_PAD_V1};
use crate::kdf::hkdf_zero32;
use crate::nonce::nonce24;
use libgary_wire::Header;

#[derive(Debug, thiserror::Error)]
pub enum DataInnerError {
    #[error("content too large for v0 DATA inner")]
    ContentTooLarge,
}

pub fn data_inner_plaintext(
    inner_version: u16,
    content_type: u16,
    content: &[u8],
) -> Result<[u8; DATA_INNER_FIXED], DataInnerError> {
    let mut semantic = Vec::with_capacity(8 + content.len());
    semantic.extend_from_slice(&inner_version.to_be_bytes());
    semantic.extend_from_slice(&content_type.to_be_bytes());
    semantic.extend_from_slice(&(content.len() as u32).to_be_bytes());
    semantic.extend_from_slice(content);
    let need = DATA_INNER_FIXED.saturating_sub(semantic.len());
    if semantic.len() > DATA_INNER_FIXED {
        return Err(DataInnerError::ContentTooLarge);
    }
    let pad = hkdf_zero32(&semantic, INFO_DATA_INNER_PAD_V1, need);
    let mut out = [0u8; DATA_INNER_FIXED];
    out[..semantic.len()].copy_from_slice(&semantic);
    out[semantic.len()..].copy_from_slice(&pad);
    Ok(out)
}

pub fn nonce_data(mk: &[u8; 32], hdr: &Header) -> [u8; 24] {
    let mut label = Vec::with_capacity(4 + 8 + 16 + 32 + b"DATA".len());
    label.extend_from_slice(b"DATA");
    label.extend_from_slice(&hdr.epoch_be.to_be_bytes());
    label.extend_from_slice(&hdr.counter_be.to_be_bytes());
    label.extend_from_slice(&hdr.session_id);
    label.extend_from_slice(&hdr.ratchet_pub);
    nonce24(mk, &label)
}

pub fn encrypt_data_payload(
    mk: &[u8; 32],
    hdr: &Header,
    inner_plaintext512: &[u8; DATA_INNER_FIXED],
) -> Result<Vec<u8>, AeadError> {
    let nonce = nonce_data(mk, hdr);
    let aad = hdr.encode();
    xencrypt(mk, &nonce, inner_plaintext512, &aad)
}
