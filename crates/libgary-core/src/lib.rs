//! libgary v0 reference cryptography (handshake transcripts, HKDF tree, AEAD, ratchet helpers).
//!
//! Normative docs live under repository `docs/`. Golden fixtures are checked by integration tests
//! (`cargo test -p libgary-core`).
#![forbid(unsafe_code)]

pub mod aead;
pub mod constants;
pub mod control;
pub mod data;
pub mod engine;
pub mod handshake;
pub mod identity;
pub mod kdf;
pub mod nonce;
pub mod ratchet;
pub mod reset_handshake;
pub mod session;
pub mod transcript;
pub mod x3dh;
