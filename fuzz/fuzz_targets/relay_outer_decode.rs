#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = libgary_wire::RelayOuterEnvelope::decode_padded_wire(data);
});
