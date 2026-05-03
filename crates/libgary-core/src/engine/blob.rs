//! `RatchetStateBlob` v2 (v0-protocol §8.7).

use super::error::SessionError;
use super::skipped::SkippedKeyCache;
use super::types::Role;

pub const BLOB_V2_PREFIX_LEN: usize = 2 + 32 * 6 + 8 * 4 + 4;

pub fn encode_blob_v2(
    role: Role,
    rk: &[u8; 32],
    cks: &[u8; 32],
    ckr: &[u8; 32],
    dh_ratchet_sk: &[u8; 32],
    dh_ratchet_pk: &[u8; 32],
    peer_ratchet_pub: &[u8; 32],
    send_count_be: u64,
    recv_high_water_be: u64,
    send_sym_idx_be: u64,
    recv_sym_idx_be: u64,
    skipped: &SkippedKeyCache,
) -> Vec<u8> {
    let entries = skipped.encode_sorted_entries();
    let skipped_count = entries.len();
    let mut out = Vec::with_capacity(BLOB_V2_PREFIX_LEN + skipped_count * 72);
    out.push(2u8);
    out.push(role.role_flag());
    out.extend_from_slice(rk);
    out.extend_from_slice(cks);
    out.extend_from_slice(ckr);
    out.extend_from_slice(dh_ratchet_sk);
    out.extend_from_slice(dh_ratchet_pk);
    out.extend_from_slice(peer_ratchet_pub);
    out.extend_from_slice(&send_count_be.to_be_bytes());
    out.extend_from_slice(&recv_high_water_be.to_be_bytes());
    out.extend_from_slice(&send_sym_idx_be.to_be_bytes());
    out.extend_from_slice(&recv_sym_idx_be.to_be_bytes());
    out.extend_from_slice(&(skipped_count as u32).to_be_bytes());
    for (key, mk) in entries {
        out.extend_from_slice(&key[..32]);
        out.extend_from_slice(&key[32..]);
        out.extend_from_slice(&mk);
    }
    out
}

pub fn decode_blob_v2(bytes: &[u8]) -> Result<ParsedRatchetBlobV2, SessionError> {
    if bytes.len() < BLOB_V2_PREFIX_LEN {
        return Err(SessionError::InvalidHeader);
    }
    if bytes[0] != 2 {
        return Err(SessionError::InvalidHeader);
    }
    let role = Role::from_role_flag(bytes[1])?;
    let rk = bytes[2..34].try_into().unwrap();
    let cks = bytes[34..66].try_into().unwrap();
    let ckr = bytes[66..98].try_into().unwrap();
    let dh_sk = bytes[98..130].try_into().unwrap();
    let dh_pk = bytes[130..162].try_into().unwrap();
    let peer_pk = bytes[162..194].try_into().unwrap();
    let send_count = u64::from_be_bytes(bytes[194..202].try_into().unwrap());
    let recv_hw = u64::from_be_bytes(bytes[202..210].try_into().unwrap());
    let send_sym = u64::from_be_bytes(bytes[210..218].try_into().unwrap());
    let recv_sym = u64::from_be_bytes(bytes[218..226].try_into().unwrap());
    let skipped_count = u32::from_be_bytes(bytes[226..230].try_into().unwrap()) as usize;
    let body = &bytes[230..];
    if body.len() != skipped_count * 72 {
        return Err(SessionError::InvalidHeader);
    }
    let mut pairs = Vec::with_capacity(skipped_count);
    for i in 0..skipped_count {
        let base = i * 72;
        let peer = body[base..base + 32].try_into().unwrap();
        let ctr = u64::from_be_bytes(body[base + 32..base + 40].try_into().unwrap());
        let mk = body[base + 40..base + 72].try_into().unwrap();
        let mut key = [0u8; 40];
        key[..32].copy_from_slice(peer);
        key[32..].copy_from_slice(&ctr.to_be_bytes());
        pairs.push((key, mk));
    }
    let skipped = SkippedKeyCache::restore_sorted_entries(pairs)?;
    Ok(ParsedRatchetBlobV2 {
        role,
        rk,
        cks,
        ckr,
        dh_ratchet_sk: dh_sk,
        dh_ratchet_pk: dh_pk,
        peer_ratchet_pub: peer_pk,
        send_count_be: send_count,
        recv_high_water_be: recv_hw,
        send_sym_idx_be: send_sym,
        recv_sym_idx_be: recv_sym,
        skipped,
    })
}

pub struct ParsedRatchetBlobV2 {
    pub role: Role,
    pub rk: [u8; 32],
    pub cks: [u8; 32],
    pub ckr: [u8; 32],
    pub dh_ratchet_sk: [u8; 32],
    pub dh_ratchet_pk: [u8; 32],
    pub peer_ratchet_pub: [u8; 32],
    pub send_count_be: u64,
    pub recv_high_water_be: u64,
    pub send_sym_idx_be: u64,
    pub recv_sym_idx_be: u64,
    pub skipped: SkippedKeyCache,
}
