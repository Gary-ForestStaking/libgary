//! Universal `PAD()` (`docs/v0-protocol.md` §6.5).

use rand_core::{CryptoRng, RngCore};

use crate::WireError;

/// Ascending bucket sizes — §6.5 (frozen).
pub const PADDING_BUCKETS: [usize; 8] = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768];

/// Smallest `B` in [`PADDING_BUCKETS`] with `n <= B`.
#[inline]
pub fn smallest_padding_bucket(n: usize) -> Option<usize> {
    PADDING_BUCKETS.iter().copied().find(|&b| n <= b)
}

/// `PAD(logical_bytes)` — append uniform random tail until output length is exactly one bucket.
///
/// Production senders must derive uniform pad bytes from an OS CSPRNG surfaced through this trait.
/// Deterministic PRNGs belong **only** in tests and golden-vector generators.
///
/// Returns [`WireError::LogicalTooLarge`] when no bucket fits (`logical.len() > 32768`).
pub fn pad_outer(
    logical: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>, WireError> {
    let bucket = smallest_padding_bucket(logical.len()).ok_or(WireError::LogicalTooLarge)?;
    let pad_len = bucket - logical.len();
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(logical);
    out.resize(out.len() + pad_len, 0);
    let start = logical.len();
    rng.fill_bytes(&mut out[start..]);
    Ok(out)
}

/// Strip outer padding after the caller has determined `logical_len` from authenticated structure.
///
/// Verifies `padded.len()` equals the normative bucket for `logical_len` and returns `padded[..logical_len]`.
#[inline]
pub fn strip_outer_pad<'a>(padded: &'a [u8], logical_len: usize) -> Result<&'a [u8], WireError> {
    let bucket = smallest_padding_bucket(logical_len).ok_or(WireError::LogicalTooLarge)?;
    if padded.len() != bucket {
        return Err(WireError::PaddingBucketMismatch);
    }
    padded
        .get(..logical_len)
        .ok_or(WireError::PaddingLogicalMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    #[test]
    fn pad_then_strip_roundtrip() {
        let logical = [7u8; 300];
        let mut rng = ChaCha12Rng::from_seed([3u8; 32]);
        let padded = pad_outer(&logical, &mut rng).unwrap();
        assert_eq!(padded.len(), 512);
        assert_eq!(
            strip_outer_pad(&padded, logical.len()).unwrap(),
            logical.as_slice()
        );
    }

    #[test]
    fn strip_rejects_wrong_bucket_len() {
        let logical = [1u8; 100];
        let mut rng = ChaCha12Rng::from_seed([1u8; 32]);
        let padded = pad_outer(&logical, &mut rng).unwrap();
        assert!(strip_outer_pad(&padded[..255], logical.len()).is_err());
    }
}
