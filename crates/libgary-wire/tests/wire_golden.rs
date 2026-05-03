//! Golden `OuterRecord` hex fixtures (`tests/fixtures/*.hex`).
//!
//! Refresh with:
//! `cargo test -p libgary-wire refresh_hex_fixtures -- --ignored --nocapture`

use hex;
use libgary_wire::{Header, OuterRecord, pad_outer};
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use std::path::PathBuf;

/// Frozen ChaCha12 seed — fixtures byte-stable across platforms for this RNG.
const FIXTURE_SEED: [u8; 32] = *b"libgary-wire/fixtures/seed123456";

fn fixture_header(typ: u8) -> Header {
    Header {
        version: 1,
        typ,
        flags: 0,
        epoch_be: 0x0102_0304,
        session_id: *b"fixture_sess_id!",
        counter_be: 0x0102_0304_0506_0708,
        ratchet_pub: [0x77u8; 32],
    }
}

fn mk_outer(typ: u8, logical_len: usize, rng: &mut ChaCha12Rng) -> Vec<u8> {
    let logical = vec![0x5Au8; logical_len];
    let payload = pad_outer(&logical, rng).unwrap();
    OuterRecord {
        header: fixture_header(typ),
        payload,
    }
    .encode()
    .unwrap()
}

#[test]
fn golden_hex_fixtures_roundtrip() {
    const CASES: &[(&str, u8, usize)] = &[
        ("init_record", 0x01, 396),  // v0-handshake §5.4 logical_INIT_pre_pad
        ("ack_record", 0x02, 384),   // §6 logical_ACK_pre_pad
        ("data_record", 0x03, 552),  // nonce24 ‖ AEAD(inner 512)
        ("rekey_record", 0x05, 296), // nonce24 ‖ AEAD(ctrl inner 256)
        ("reset_init", 0x07, 396),   // mirrors INIT layout — v0-reset.md §4
    ];
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (file, typ, logical_len) in CASES {
        let path = dir.join(format!("{file}.hex"));
        let hex_str = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("missing fixture {}: {e}", path.display());
        });
        let bytes = hex::decode(hex_str.trim()).unwrap();
        let rec = OuterRecord::decode(&bytes).unwrap();
        assert_eq!(rec.header.typ, *typ);
        assert_eq!(
            rec.header.epoch_be, 0x0102_0304,
            "fixture header drift for {file}"
        );
        let wire = rec.encode().unwrap();
        assert_eq!(wire, bytes, "re-encode stable for {file}");
        assert_eq!(
            rec.record_body_len(),
            libgary_wire::Header::LEN + rec.payload.len()
        );
        let bucket = libgary_wire::smallest_padding_bucket(*logical_len).unwrap();
        assert_eq!(rec.payload.len(), bucket, "payload PAD bucket for {file}");
    }
}

#[test]
#[ignore = "run manually to regenerate tests/fixtures/*.hex"]
fn refresh_hex_fixtures() {
    let mut rng = ChaCha12Rng::from_seed(FIXTURE_SEED);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    let cases = [
        ("init_record", 0x01u8, 396usize),
        ("ack_record", 0x02, 384),
        ("data_record", 0x03, 552),
        ("rekey_record", 0x05, 296),
        ("reset_init", 0x07, 396),
    ];
    for (file, typ, len) in cases {
        let bytes = mk_outer(typ, len, &mut rng);
        std::fs::write(dir.join(format!("{file}.hex")), hex::encode(&bytes)).unwrap();
    }
}
