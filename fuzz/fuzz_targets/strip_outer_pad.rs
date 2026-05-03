#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Harness-only layout (not wire metadata): fake logical length prefix for coverage.
    if data.len() < 8 {
        return;
    }
    let logical = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    let _ = libgary_wire::strip_outer_pad(&data[8..], logical);
});
