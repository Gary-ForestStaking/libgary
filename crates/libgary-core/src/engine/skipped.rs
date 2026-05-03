//! Skipped-message key cache (v0-protocol §8.6).

use std::collections::HashMap;

use zeroize::{Zeroize, Zeroizing};

use crate::constants::MAX_SKIP;

use super::error::SessionError;

pub(crate) fn cache_key(peer_ratchet_pub: &[u8; 32], counter_be: u64) -> [u8; 40] {
    let mut k = [0u8; 40];
    k[..32].copy_from_slice(peer_ratchet_pub);
    k[32..].copy_from_slice(&counter_be.to_be_bytes());
    k
}

pub struct SkippedKeyCache {
    map: HashMap<[u8; 40], Zeroizing<[u8; 32]>>,
}

impl SkippedKeyCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn insert(
        &mut self,
        peer_ratchet_pub: &[u8; 32],
        counter_be: u64,
        mk: [u8; 32],
    ) -> Result<(), SessionError> {
        if self.map.len() >= MAX_SKIP {
            return Err(SessionError::MaxSkipExceeded);
        }
        let key = cache_key(peer_ratchet_pub, counter_be);
        if self.map.contains_key(&key) {
            return Err(SessionError::ReplayRejected);
        }
        self.map.insert(key, Zeroizing::new(mk));
        Ok(())
    }

    pub fn take(&mut self, peer_ratchet_pub: &[u8; 32], counter_be: u64) -> Option<[u8; 32]> {
        let key = cache_key(peer_ratchet_pub, counter_be);
        self.map.remove(&key).map(|z| *z)
    }

    pub fn clear(&mut self) {
        for (_, mut v) in self.map.drain() {
            v.zeroize();
        }
    }

    /// Deterministic export order for `RatchetStateBlob` v2.
    pub(crate) fn encode_sorted_entries(&self) -> Vec<([u8; 40], [u8; 32])> {
        let mut v: Vec<_> = self.map.iter().map(|(k, z)| (*k, **z)).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    pub(crate) fn restore_sorted_entries(
        entries: Vec<([u8; 40], [u8; 32])>,
    ) -> Result<Self, SessionError> {
        let mut s = Self::new();
        for (key, mk) in entries {
            let peer: [u8; 32] = key[..32].try_into().unwrap();
            let ctr = u64::from_be_bytes(key[32..40].try_into().unwrap());
            s.insert(&peer, ctr, mk)?;
        }
        Ok(s)
    }
}

impl Default for SkippedKeyCache {
    fn default() -> Self {
        Self::new()
    }
}
