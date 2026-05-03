//! Parser edge cases (`docs/v0-protocol.md` §6).

use libgary_wire::{Header, OuterRecord, RelayOuterEnvelope, WireError, pad_outer};
use rand_chacha::ChaCha12Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

fn hdr(typ: u8, counter: u64) -> Header {
    Header {
        version: 1,
        typ,
        flags: 0,
        epoch_be: 1,
        session_id: [0x33u8; 16],
        counter_be: counter,
        ratchet_pub: [0x44u8; 32],
    }
}

#[test]
fn outer_roundtrip() {
    let logical = [0xabu8; 50];
    let mut rng = ChaCha12Rng::from_seed([7u8; 32]);
    let payload = pad_outer(&logical, &mut rng).unwrap();
    let rec = OuterRecord {
        header: hdr(0x03, 0),
        payload,
    };
    let wire = rec.encode().unwrap();
    let got = OuterRecord::decode(&wire).unwrap();
    assert_eq!(got.header, rec.header);
    assert_eq!(got.payload, rec.payload);
}

#[test]
fn outer_rejects_length_mismatch() {
    let logical = [0u8; 10];
    let mut rng = ChaCha12Rng::from_seed([8u8; 32]);
    let payload = pad_outer(&logical, &mut rng).unwrap();
    let rec = OuterRecord {
        header: hdr(0x01, 0),
        payload,
    };
    let mut wire = rec.encode().unwrap();
    wire.push(0xff);
    assert_eq!(
        OuterRecord::decode(&wire),
        Err(WireError::RecordLengthMismatch)
    );
}

#[test]
fn outer_rejects_truncated() {
    assert_eq!(OuterRecord::decode(&[]), Err(WireError::Truncated));
    assert_eq!(
        OuterRecord::decode(&[0, 0, 0, 63]),
        Err(WireError::RecordLengthMismatch)
    );
}

#[test]
fn outer_rejects_reserved_header_type_after_decode() {
    let logical = [0u8; 8];
    let mut rng = ChaCha12Rng::from_seed([9u8; 32]);
    let payload = pad_outer(&logical, &mut rng).unwrap();
    let mut bad = OuterRecord {
        header: hdr(0x03, 0),
        payload,
    };
    bad.header.typ = 0x04; // RECEIPT — illegal in v0
    assert_eq!(bad.encode(), Err(WireError::InvalidHeaderType));
    let raw_hdr = bad.header.encode();
    let rl = libgary_wire::Header::LEN + bad.payload.len();
    let mut wire = Vec::new();
    wire.extend_from_slice(&(rl as u32).to_be_bytes());
    wire.extend_from_slice(&raw_hdr);
    wire.extend_from_slice(&bad.payload);
    assert_eq!(
        OuterRecord::decode(&wire),
        Err(WireError::InvalidHeaderType)
    );
}

#[test]
fn header_parse_checked_rejects_bad_version() {
    let mut h = hdr(0x03, 0);
    h.version = 2;
    assert_eq!(h.validate_v0(), Err(WireError::InvalidHeaderVersion));
}

#[test]
fn relay_roundtrip_padded() {
    let outer = OuterRecord {
        header: hdr(0x03, 2),
        payload: vec![0xedu8; 40],
    }
    .encode()
    .unwrap();
    let env = RelayOuterEnvelope {
        route_token: vec![0x01, 0x02, 0xfe],
        opaque_bytes: outer,
    };
    let mut rng = ChaCha12Rng::from_seed([11u8; 32]);
    let padded = env.encode_padded_wire(&mut rng).unwrap();
    let got = RelayOuterEnvelope::decode_padded_wire(&padded).unwrap();
    assert_eq!(got.route_token, env.route_token);
    assert_eq!(got.opaque_bytes, env.opaque_bytes);
}

#[test]
fn relay_rejects_bad_padding_bucket() {
    let env = RelayOuterEnvelope {
        route_token: vec![0xaa],
        opaque_bytes: vec![0xbb; 100],
    };
    let mut rng = ChaCha12Rng::from_seed([12u8; 32]);
    let mut padded = env.encode_padded_wire(&mut rng).unwrap();
    padded.push(0); // breaks bucket size
    assert_eq!(
        RelayOuterEnvelope::decode_padded_wire(&padded),
        Err(WireError::PaddingBucketMismatch)
    );
}

#[derive(Clone)]
struct CountingRng(u64);

impl RngCore for CountingRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = (self.0 & 0xff) as u8;
            self.0 = self.0.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
}

impl CryptoRng for CountingRng {}

#[test]
fn golden_fixture_rng_is_deterministic_for_pad() {
    let logical = [0x5Au8; 396];
    let mut rng = CountingRng(0xdeadbeefcafe0000);
    let padded = pad_outer(&logical, &mut rng).unwrap();
    assert_eq!(padded.len(), 512);
    assert_eq!(&padded[..logical.len()], logical.as_slice());
}
