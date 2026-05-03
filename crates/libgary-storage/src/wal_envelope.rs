//! Single-file atomic persistence: `bundle ‖ trusted_meta ‖ SHA256(version‖lens‖payloads)` (`LGW1`).

use sha2::{Digest, Sha256};

use crate::StorageError;

const WAL_MAGIC: &[u8; 4] = b"LGW1";
const WAL_VERSION: u32 = 1;

/// Serialized envelope for one atomic `rename` + directory fsync (see [`crate::SessionStore`]).
pub fn encode_wal_envelope(bundle: &[u8], trusted_meta: &[u8]) -> Vec<u8> {
    let bl = bundle.len() as u32;
    let ml = trusted_meta.len() as u32;

    let mut h = Sha256::new();
    h.update(WAL_VERSION.to_be_bytes());
    h.update(&bl.to_be_bytes());
    h.update(&ml.to_be_bytes());
    h.update(bundle);
    h.update(trusted_meta);
    let checksum: [u8; 32] = h.finalize().into();

    let mut out = Vec::with_capacity(4 + 4 + 4 + 4 + bundle.len() + trusted_meta.len() + 32);
    out.extend_from_slice(WAL_MAGIC);
    out.extend_from_slice(&WAL_VERSION.to_be_bytes());
    out.extend_from_slice(&bl.to_be_bytes());
    out.extend_from_slice(&ml.to_be_bytes());
    out.extend_from_slice(bundle);
    out.extend_from_slice(trusted_meta);
    out.extend_from_slice(&checksum);
    out
}

pub fn decode_wal_envelope(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
    if bytes.len() < 4 + 4 + 4 + 4 + 32 {
        return Err(StorageError::EnvelopeTruncated);
    }
    if bytes.len() < 16 || bytes[0..4] != *WAL_MAGIC {
        return Err(StorageError::BadEnvelopeMagic);
    }
    let ver = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    if ver != WAL_VERSION {
        return Err(StorageError::BadEnvelopeMagic);
    }
    let bundle_len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let meta_len = u32::from_be_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let body_end = 16usize
        .checked_add(bundle_len)
        .and_then(|x| x.checked_add(meta_len))
        .ok_or(StorageError::EnvelopeTruncated)?;
    if bytes.len()
        != body_end
            .checked_add(32)
            .ok_or(StorageError::EnvelopeTruncated)?
    {
        return Err(StorageError::EnvelopeTruncated);
    }

    let bundle = bytes[16..16 + bundle_len].to_vec();
    let meta = bytes[16 + bundle_len..body_end].to_vec();

    let mut h = Sha256::new();
    h.update(WAL_VERSION.to_be_bytes());
    h.update(&(bundle_len as u32).to_be_bytes());
    h.update(&(meta_len as u32).to_be_bytes());
    h.update(&bundle);
    h.update(&meta);
    let expected: [u8; 32] = h.finalize().into();
    let got: [u8; 32] = bytes[body_end..body_end + 32].try_into().unwrap();
    if expected != got {
        return Err(StorageError::EnvelopeChecksum);
    }

    Ok((bundle, meta))
}
