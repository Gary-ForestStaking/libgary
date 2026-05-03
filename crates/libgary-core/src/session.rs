use crate::constants::{INFO_CONFIRM_V1, INFO_ROOT_KEY_V1, SALT_HANDSHAKE_LABEL};
use crate::kdf::{hkdf_sha256, hkdf_zero32, sha256_label};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub fn salt_handshake() -> [u8; 32] {
    sha256_label(SALT_HANDSHAKE_LABEL, &[])
}

/// Session `IKM_session = KM ‖ TH0 ‖ TH1`.
pub fn ikm_session(km: &[u8], th0: &[u8; 32], th1: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(km.len() + 64);
    v.extend_from_slice(km);
    v.extend_from_slice(th0);
    v.extend_from_slice(th1);
    v
}

/// HKDF transcript-bound `OKM`, 64 bytes: root_key ‖ bootstrap_key.
pub fn okm_root_bootstrap(ikm_session: &[u8]) -> [u8; 64] {
    let salt = salt_handshake();
    hkdf_sha256(&salt, ikm_session, INFO_ROOT_KEY_V1, 64)
        .try_into()
        .unwrap()
}

pub fn confirm_key(okm: &[u8; 64]) -> [u8; 32] {
    hkdf_zero32(okm, INFO_CONFIRM_V1, 32).try_into().unwrap()
}

pub fn confirm_mac(confirm_key: &[u8; 32], th1: &[u8; 32]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(confirm_key).expect("HMAC key length");
    mac.update(th1);
    let full = mac.finalize().into_bytes();
    full[..16].try_into().unwrap()
}

pub fn verify_confirm_mac(confirm_key: &[u8; 32], th1: &[u8; 32], mac: &[u8; 16]) -> bool {
    let expected = confirm_mac(confirm_key, th1);
    mac.ct_eq(&expected).into()
}
