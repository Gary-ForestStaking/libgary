use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AeadError {
    #[error("chacha20poly1305")]
    Cipher,
}

pub fn xencrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher =
        XChaCha20Poly1305::new(Key::from_slice(key));
    let n = XNonce::from_slice(nonce);
    cipher
        .encrypt(
            n,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AeadError::Cipher)
}

pub fn xdecrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let n = XNonce::from_slice(nonce);
    cipher
        .decrypt(
            n,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadError::Cipher)
}
