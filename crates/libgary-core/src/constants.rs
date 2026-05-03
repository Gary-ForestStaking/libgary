//! Canonical HKDF / transcript labels (`docs/label-registry.md`).

pub const ZERO32: [u8; 32] = [0u8; 32];

pub const SALT_HANDSHAKE_LABEL: &[u8] = b"libgary-v0-handshake";
pub const INFO_ROOT_KEY_V1: &[u8] = b"libgary-v0/root-key-v1";
pub const INFO_CONFIRM_V1: &[u8] = b"libgary-v0/confirm-v1";
pub const INFO_INIT_AEAD_V1: &[u8] = b"libgary-v0/init-aead-v1";
pub const INFO_ACK_AEAD_V1: &[u8] = b"libgary-v0/ack-aead-v1";
pub const INFO_CONTROL_AEAD_V1: &[u8] = b"libgary-v0/control-aead-v1";
pub const INFO_INIT_INNER_V1: &[u8] = b"libgary-v0/init-inner-v1";
pub const INFO_ACK_INNER_V1: &[u8] = b"libgary-v0/ack-inner-v1";
pub const INFO_NONCE_V1: &[u8] = b"libgary-v0/nonce-v1";
pub const INFO_CHAIN: &[u8] = b"libgary-v0/libgary-chain";
pub const INFO_ROOT_MIX: &[u8] = b"libgary-v0/libgary-root";
pub const INFO_MSG_PREFIX: &[u8] = b"libgary-v0/libgary-msg";
pub const INFO_DATA_INNER_PAD_V1: &[u8] = b"libgary-v0/data-inner-pad-v1";
pub const INFO_CTRL_PAD_V1: &[u8] = b"libgary-v0/ctrl-pad-v1";

pub const TH0_PREFIX: &[u8] = b"libgary-v0/th0-v1";
pub const TH1_PREFIX: &[u8] = b"libgary-v0/th1-v1";
pub const TH0_RESET_PREFIX: &[u8] = b"libgary-v0/th0-reset-v1";
pub const TH1_RESET_PREFIX: &[u8] = b"libgary-v0/th1-reset-v1";

pub const AAD_INIT_PREFIX: &[u8] = b"libgary-v0/init-aad-v1";
pub const AAD_ACK_PREFIX: &[u8] = b"libgary-v0/ack-aad-v1";
pub const AAD_RESET_INIT_PREFIX: &[u8] = b"libgary-v0/reset-init-aad-v1";
pub const AAD_RESET_ACK_PREFIX: &[u8] = b"libgary-v0/reset-ack-aad-v1";

pub const SAFETY_NUMBER_PREFIX: &[u8] = b"libgary-v0/safety-number-v1";

/// Fixed logical DATA inner length before outer `PAD()` (v0-protocol §6.6).
pub const DATA_INNER_FIXED: usize = 512;

/// Skipped-message key cache bound (v0-protocol §8.6).
pub const MAX_SKIP: usize = 2000;
