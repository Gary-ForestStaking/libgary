//! C ABI façade for [`libgary_core::engine::SessionHandle`] (engine) behind an opaque FFI handle.
//!
//! Canonical symbols: `gary_*` (`include/libgary.h`). Rules: `docs/session-handle-boundary.md`.
#![allow(unsafe_code)]

mod fixture;

use std::ffi::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::NonNull;

use libgary_core::constants::DATA_INNER_FIXED;
use libgary_core::data::data_inner_plaintext;
use libgary_core::engine::{InboundInner, SessionError, SessionHandle as CoreSession};
use libgary_wire::{OuterRecord, RelayOuterEnvelope, WireError};
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;

// --- Stable ABI numeric codes (mirror `include/libgary.h`) ------------------------------

pub const GARY_CODE_OK: i32 = 0;
pub const GARY_CODE_NULL_POINTER: i32 = 1;
pub const GARY_CODE_PANIC: i32 = 2;

pub const GARY_CODE_WIRE_TRUNCATED: i32 = 10;
pub const GARY_CODE_WIRE_RECORD_LENGTH_MISMATCH: i32 = 11;
pub const GARY_CODE_WIRE_RECORD_TOO_LARGE: i32 = 12;
pub const GARY_CODE_WIRE_INVALID_HEADER_VERSION: i32 = 13;
pub const GARY_CODE_WIRE_INVALID_HEADER_TYPE: i32 = 14;
pub const GARY_CODE_WIRE_INVALID_HEADER_FLAGS: i32 = 15;
pub const GARY_CODE_WIRE_OTHER: i32 = 19;

pub const GARY_CODE_CONTENT_TOO_LARGE: i32 = 20;
pub const GARY_CODE_BUFFER_TOO_SMALL: i32 = 21;

pub const GARY_CODE_SESSION_REPLAY_REJECTED: i32 = 100;
pub const GARY_CODE_SESSION_STALE_EPOCH: i32 = 101;
pub const GARY_CODE_SESSION_DECRYPTION_FAILED: i32 = 102;
pub const GARY_CODE_SESSION_MAX_SKIP_EXCEEDED: i32 = 103;
pub const GARY_CODE_SESSION_INVALID_HEADER: i32 = 104;
pub const GARY_CODE_SESSION_UNKNOWN_SESSION: i32 = 105;
pub const GARY_CODE_SESSION_STATE_INTEGRITY: i32 = 106;
pub const GARY_CODE_SESSION_RESET_REQUIRED: i32 = 107;
pub const GARY_CODE_SESSION_LATE_DATA_AFTER_RESET: i32 = 108;
pub const GARY_CODE_SESSION_FUTURE_EPOCH: i32 = 109;

/// Opaque session heap object (`typedef struct SessionHandle SessionHandle` in C).
pub struct SessionHandle {
    inner: CoreSession,
    last_code: i32,
    /// NUL-terminated UTF-8 (valid until the next mutating call on this handle).
    last_msg: [u8; 256],
    /// Last successfully decrypted DATA inner semantic UTF-8 (`inner_version=1`, `content_type=1`).
    last_inbound_utf8: [u8; 512],
}

impl SessionHandle {
    fn new(inner: CoreSession) -> Self {
        Self {
            inner,
            last_code: GARY_CODE_OK,
            last_msg: [0u8; 256],
            last_inbound_utf8: [0u8; 512],
        }
    }

    fn clear_last_inbound(&mut self) {
        self.last_inbound_utf8.fill(0);
    }

    fn store_last_inbound_from_plain(&mut self, pt: &[u8; DATA_INNER_FIXED]) {
        self.clear_last_inbound();
        let Some(text) = decode_inner_semantic_utf8(pt.as_slice()) else {
            return;
        };
        let bytes = text.as_bytes();
        let n = bytes.len().min(self.last_inbound_utf8.len().saturating_sub(1));
        self.last_inbound_utf8[..n].copy_from_slice(&bytes[..n]);
        self.last_inbound_utf8[n] = 0;
    }

    fn latch_ok(&mut self) {
        self.last_code = GARY_CODE_OK;
        self.last_msg[0] = 0;
    }

    fn latch_wire(&mut self, code: i32, msg: &'static str) {
        self.last_code = code;
        copy_static_msg(&mut self.last_msg, msg);
    }

    fn latch_session_err(&mut self, err: SessionError) {
        self.last_code = session_error_code(&err);
        copy_static_msg(&mut self.last_msg, session_error_msg(&err));
    }
}

fn copy_static_msg(buf: &mut [u8; 256], msg: &'static str) {
    let n = msg.len().min(buf.len().saturating_sub(1));
    buf[..n].copy_from_slice(&msg.as_bytes()[..n]);
    buf[n] = 0;
    buf[n + 1..].fill(0);
}

fn wire_error_code(e: &WireError) -> i32 {
    match e {
        WireError::Truncated => GARY_CODE_WIRE_TRUNCATED,
        WireError::RecordLengthMismatch => GARY_CODE_WIRE_RECORD_LENGTH_MISMATCH,
        WireError::RecordTooLarge => GARY_CODE_WIRE_RECORD_TOO_LARGE,
        WireError::InvalidHeaderVersion => GARY_CODE_WIRE_INVALID_HEADER_VERSION,
        WireError::InvalidHeaderType => GARY_CODE_WIRE_INVALID_HEADER_TYPE,
        WireError::InvalidHeaderFlags => GARY_CODE_WIRE_INVALID_HEADER_FLAGS,
        WireError::InitReservedNonZero
        | WireError::LogicalTooLarge
        | WireError::PaddingBucketMismatch
        | WireError::PaddingLogicalMismatch
        | WireError::InvalidRelayVersion
        | WireError::RouteTokenTooLong
        | WireError::OpaqueLengthMismatch
        | WireError::OpaqueTooLarge => GARY_CODE_WIRE_OTHER,
    }
}

fn wire_error_static_msg(e: &WireError) -> &'static str {
    match e {
        WireError::Truncated => "wire: truncated",
        WireError::RecordLengthMismatch => "wire: record length mismatch",
        WireError::RecordTooLarge => "wire: record too large",
        WireError::InvalidHeaderVersion => "wire: invalid header version",
        WireError::InvalidHeaderType => "wire: invalid header type",
        WireError::InvalidHeaderFlags => "wire: invalid header flags",
        WireError::InitReservedNonZero => "wire: init reserved non-zero",
        WireError::LogicalTooLarge => "wire: logical too large",
        WireError::PaddingBucketMismatch => "wire: padding bucket mismatch",
        WireError::PaddingLogicalMismatch => "wire: padding logical mismatch",
        WireError::InvalidRelayVersion => "wire: invalid relay version",
        WireError::RouteTokenTooLong => "wire: route token too long",
        WireError::OpaqueLengthMismatch => "wire: opaque length mismatch",
        WireError::OpaqueTooLarge => "wire: opaque too large",
    }
}

fn session_error_code(e: &SessionError) -> i32 {
    match e {
        SessionError::ReplayRejected => GARY_CODE_SESSION_REPLAY_REJECTED,
        SessionError::StaleEpochRejected => GARY_CODE_SESSION_STALE_EPOCH,
        SessionError::DecryptionFailed => GARY_CODE_SESSION_DECRYPTION_FAILED,
        SessionError::MaxSkipExceeded => GARY_CODE_SESSION_MAX_SKIP_EXCEEDED,
        SessionError::InvalidHeader => GARY_CODE_SESSION_INVALID_HEADER,
        SessionError::UnknownSession => GARY_CODE_SESSION_UNKNOWN_SESSION,
        SessionError::StateIntegrity => GARY_CODE_SESSION_STATE_INTEGRITY,
        SessionError::ResetRequired => GARY_CODE_SESSION_RESET_REQUIRED,
        SessionError::LateDataAfterReset => GARY_CODE_SESSION_LATE_DATA_AFTER_RESET,
        SessionError::FutureEpoch => GARY_CODE_SESSION_FUTURE_EPOCH,
    }
}

fn decode_inner_semantic_utf8(pt: &[u8]) -> Option<&str> {
    if pt.len() != DATA_INNER_FIXED {
        return None;
    }
    let len = u32::from_be_bytes(pt[4..8].try_into().ok()?) as usize;
    let end = 8usize.checked_add(len)?;
    if end > DATA_INNER_FIXED {
        return None;
    }
    std::str::from_utf8(&pt[8..end]).ok()
}

fn session_error_msg(e: &SessionError) -> &'static str {
    match e {
        SessionError::ReplayRejected => "session: replay rejected",
        SessionError::StaleEpochRejected => "session: stale epoch rejected",
        SessionError::DecryptionFailed => "session: decryption failed",
        SessionError::MaxSkipExceeded => "session: max skip exceeded",
        SessionError::InvalidHeader => "session: invalid header",
        SessionError::UnknownSession => "session: unknown session",
        SessionError::StateIntegrity => "session: state integrity",
        SessionError::ResetRequired => "session: reset required",
        SessionError::LateDataAfterReset => "session: late data after reset",
        SessionError::FutureEpoch => "session: future epoch",
    }
}

/// Serialized `OuterRecord` DATA (UTF‑8 semantic v1) — normative encode path shared by direct send and relay wrap.
fn build_data_outer_record_bytes(sess: &mut SessionHandle, utf8_slice: &[u8]) -> Result<Vec<u8>, i32> {
    let plain = match data_inner_plaintext(1, 1, utf8_slice) {
        Ok(p) => p,
        Err(_) => {
            sess.latch_wire(GARY_CODE_CONTENT_TOO_LARGE, "session: DATA inner content too large");
            return Err(sess.last_code);
        }
    };

    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        sess.last_code = GARY_CODE_PANIC;
        copy_static_msg(&mut sess.last_msg, "rng: getrandom failed");
        return Err(sess.last_code);
    }
    let mut pad_rng = ChaCha12Rng::from_seed(seed);

    let (hdr, pay) = match sess.inner.send_data_plain512_outer(&plain, &mut pad_rng) {
        Ok(x) => x,
        Err(e) => {
            sess.latch_session_err(e);
            return Err(sess.last_code);
        }
    };

    match (OuterRecord {
        header: hdr,
        payload: pay,
    })
    .encode()
    {
        Ok(w) => Ok(w),
        Err(e) => {
            let c = wire_error_code(&e);
            sess.latch_wire(c, wire_error_static_msg(&e));
            Err(sess.last_code)
        }
    }
}

fn ingest_inner(sess: &mut SessionHandle, slice: &[u8]) -> i32 {
    let record = match OuterRecord::decode(slice) {
        Ok(r) => r,
        Err(e) => {
            let c = wire_error_code(&e);
            sess.latch_wire(c, wire_error_static_msg(&e));
            return c;
        }
    };

    sess.clear_last_inbound();

    let mut rng = ChaCha12Rng::from_seed([0x99u8; 32]);
    match sess.inner.handle_inbound_outer(record, 0, &mut rng) {
        Ok(InboundInner::Data(pt)) => {
            sess.store_last_inbound_from_plain(&*pt);
            sess.latch_ok();
            GARY_CODE_OK
        }
        Ok(InboundInner::RekeyPlain(_)) => {
            sess.latch_ok();
            GARY_CODE_OK
        }
        Err(e) => {
            sess.latch_session_err(e);
            sess.last_code
        }
    }
}

fn persistence_digest_copy(session: *const SessionHandle, out32: *mut u8) -> i32 {
    let Some(sess) = (unsafe { session.as_ref() }) else {
        return GARY_CODE_NULL_POINTER;
    };
    let Some(out) = NonNull::new(out32) else {
        return GARY_CODE_NULL_POINTER;
    };
    let digest = sess.inner.persistence_equivalence_digest();
    unsafe {
        std::ptr::copy_nonoverlapping(digest.as_ptr(), out.as_ptr(), 32);
    }
    GARY_CODE_OK
}

/// Default responder session (`docs/test-vectors.md` VECTOR 001–002 fixture).
#[unsafe(no_mangle)]
pub extern "C" fn gary_session_new() -> *mut SessionHandle {
    let out = catch_unwind(|| {
        let inner = fixture::epoch_policy_vector_responder();
        Box::into_raw(Box::new(SessionHandle::new(inner)))
    });
    match out {
        Ok(p) => p,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Paired initiator session (same handshake fixture as [`gary_session_new`] responder).
#[unsafe(no_mangle)]
pub extern "C" fn gary_session_new_initiator() -> *mut SessionHandle {
    let out = catch_unwind(|| {
        let inner = fixture::epoch_policy_vector_initiator();
        Box::into_raw(Box::new(SessionHandle::new(inner)))
    });
    match out {
        Ok(p) => p,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Encrypt UTF-8 into one serialized `OuterRecord` DATA frame (v0 inner_version=1 content_type=1).
/// On [`GARY_CODE_OK`], `*out_written` is wire length. Requires crypto RNG (`getrandom`).
#[unsafe(no_mangle)]
pub extern "C" fn gary_send_utf8_data_outer(
    session: *mut SessionHandle,
    utf8: *const u8,
    utf8_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_written: *mut usize,
) -> i32 {
    let Some(sess) = (unsafe { session.as_mut() }) else {
        return GARY_CODE_NULL_POINTER;
    };
    if out_written.is_null() {
        return GARY_CODE_NULL_POINTER;
    }
    unsafe {
        *out_written = 0;
    }
    if utf8.is_null() && utf8_len != 0 {
        return GARY_CODE_NULL_POINTER;
    }
    if out_buf.is_null() || out_cap == 0 {
        return GARY_CODE_NULL_POINTER;
    }

    let utf8_slice = unsafe { std::slice::from_raw_parts(utf8, utf8_len) };

    let result = catch_unwind(AssertUnwindSafe(|| {
        let wire = match build_data_outer_record_bytes(sess, utf8_slice) {
            Ok(w) => w,
            Err(code) => return code,
        };

        if wire.len() > out_cap {
            sess.latch_wire(GARY_CODE_BUFFER_TOO_SMALL, "session: output buffer too small");
            return sess.last_code;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(wire.as_ptr(), out_buf, wire.len());
            *out_written = wire.len();
        }
        sess.latch_ok();
        GARY_CODE_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            sess.last_code = GARY_CODE_PANIC;
            copy_static_msg(&mut sess.last_msg, "rust panic while sending");
            GARY_CODE_PANIC
        }
    }
}

/**
 * Internet/lab relay path: UTF‑8 DATA → `OuterRecord` → [`RelayOuterEnvelope`] → §6.5 `PAD()` wire.
 * Swift sends `out_buf[..*out_written]` on TLS/WebSocket without inspecting bytes.
 * Use `out_cap >= GARY_RELAY_WIRE_CAP`.
 */
#[unsafe(no_mangle)]
pub extern "C" fn gary_prepare_relay_outbound_utf8(
    session: *mut SessionHandle,
    route_token: *const u8,
    route_token_len: usize,
    utf8: *const u8,
    utf8_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_written: *mut usize,
) -> i32 {
    let Some(sess) = (unsafe { session.as_mut() }) else {
        return GARY_CODE_NULL_POINTER;
    };
    if out_written.is_null() {
        return GARY_CODE_NULL_POINTER;
    }
    unsafe {
        *out_written = 0;
    }
    if route_token.is_null() && route_token_len != 0 {
        return GARY_CODE_NULL_POINTER;
    }
    if utf8.is_null() && utf8_len != 0 {
        return GARY_CODE_NULL_POINTER;
    }
    if out_buf.is_null() || out_cap == 0 {
        return GARY_CODE_NULL_POINTER;
    }

    let rt = unsafe { std::slice::from_raw_parts(route_token, route_token_len) };
    let utf8_slice = unsafe { std::slice::from_raw_parts(utf8, utf8_len) };

    let result = catch_unwind(AssertUnwindSafe(|| {
        let opaque = match build_data_outer_record_bytes(sess, utf8_slice) {
            Ok(w) => w,
            Err(code) => return code,
        };

        let env = RelayOuterEnvelope {
            route_token: rt.to_vec(),
            opaque_bytes: opaque,
        };

        let mut seed2 = [0u8; 32];
        if getrandom::getrandom(&mut seed2).is_err() {
            sess.last_code = GARY_CODE_PANIC;
            copy_static_msg(&mut sess.last_msg, "rng: getrandom failed");
            return GARY_CODE_PANIC;
        }
        let mut rng2 = ChaCha12Rng::from_seed(seed2);
        let wire = match env.encode_padded_wire(&mut rng2) {
            Ok(w) => w,
            Err(e) => {
                let c = wire_error_code(&e);
                sess.latch_wire(c, wire_error_static_msg(&e));
                return c;
            }
        };

        if wire.len() > out_cap {
            sess.latch_wire(GARY_CODE_BUFFER_TOO_SMALL, "session: relay output buffer too small");
            return sess.last_code;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(wire.as_ptr(), out_buf, wire.len());
            *out_written = wire.len();
        }
        sess.latch_ok();
        GARY_CODE_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            sess.last_code = GARY_CODE_PANIC;
            copy_static_msg(&mut sess.last_msg, "rust panic while preparing relay outbound");
            GARY_CODE_PANIC
        }
    }
}

/// Relay ingress: §6.5 padded relay wire → unwrap → same path as [`gary_ingest_outer`] on `opaque_bytes`.
#[unsafe(no_mangle)]
pub extern "C" fn gary_process_relay_inbound(
    session: *mut SessionHandle,
    buf: *const u8,
    len: usize,
) -> i32 {
    let Some(sess) = (unsafe { session.as_mut() }) else {
        return GARY_CODE_NULL_POINTER;
    };
    if buf.is_null() && len != 0 {
        return GARY_CODE_NULL_POINTER;
    }
    let slice = unsafe { std::slice::from_raw_parts(buf, len) };

    let result = catch_unwind(AssertUnwindSafe(|| {
        let env = match RelayOuterEnvelope::decode_padded_wire(slice) {
            Ok(e) => e,
            Err(e) => {
                let c = wire_error_code(&e);
                sess.latch_wire(c, wire_error_static_msg(&e));
                return c;
            }
        };
        ingest_inner(sess, &env.opaque_bytes)
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            sess.last_code = GARY_CODE_PANIC;
            copy_static_msg(&mut sess.last_msg, "rust panic while processing relay inbound");
            GARY_CODE_PANIC
        }
    }
}

/// NUL-terminated UTF-8 from last successful DATA decrypt (`gary_ingest_outer` → [`GARY_CODE_OK`]).
#[unsafe(no_mangle)]
pub extern "C" fn gary_last_inbound_utf8(session: *const SessionHandle) -> *const c_char {
    let Some(sess) = (unsafe { session.as_ref() }) else {
        return std::ptr::null();
    };
    sess.last_inbound_utf8.as_ptr().cast()
}

/// Release a session from [`gary_session_new`]. `NULL` is a no-op.
#[unsafe(no_mangle)]
pub extern "C" fn gary_session_free(handle: *mut SessionHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(|| unsafe {
        drop(Box::from_raw(handle));
    });
}

/// Ingest one serialized `OuterRecord`. Returns [`GARY_CODE_OK`] or a `GARY_CODE_*` error.
#[unsafe(no_mangle)]
pub extern "C" fn gary_ingest_outer(
    session: *mut SessionHandle,
    buf: *const u8,
    len: usize,
) -> i32 {
    let Some(sess) = (unsafe { session.as_mut() }) else {
        return GARY_CODE_NULL_POINTER;
    };
    if buf.is_null() && len != 0 {
        return GARY_CODE_NULL_POINTER;
    }
    let slice = unsafe { std::slice::from_raw_parts(buf, len) };

    let result = catch_unwind(AssertUnwindSafe(|| ingest_inner(sess, slice)));
    match result {
        Ok(code) => code,
        Err(_) => {
            sess.last_code = GARY_CODE_PANIC;
            copy_static_msg(&mut sess.last_msg, "rust panic while ingesting");
            GARY_CODE_PANIC
        }
    }
}

/// Writes the 32-byte persistence equivalence digest (no-op if `session` or `out32` is NULL).
#[unsafe(no_mangle)]
pub extern "C" fn gary_get_digest(session: *const SessionHandle, out32: *mut u8) {
    let _ = persistence_digest_copy(session, out32);
}

/// NUL-terminated UTF-8 diagnostic for the last ingest outcome (empty if none).
#[unsafe(no_mangle)]
pub extern "C" fn gary_last_error(session: *const SessionHandle) -> *const std::ffi::c_char {
    let Some(sess) = (unsafe { session.as_ref() }) else {
        return std::ptr::null();
    };
    sess.last_msg.as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    const VECTOR001_OUTER_HEX: &str = concat!(
        "0000003f0103000000000601010101010101010101010101010101",
        "00000000000000000202020202020202020202020202020202020202020202020202020202020202"
    );

    const VECTOR001_DIGEST_HEX: &str =
        "ccf1a632cc36524036d11270ee1e8965a5313927db009fafef5acf3ae50425da";

    #[test]
    fn free_null_is_noop() {
        gary_session_free(std::ptr::null_mut());
    }

    #[test]
    fn new_fixture_digest_matches_doc_vector() {
        let p = gary_session_new();
        assert!(!p.is_null());
        let mut d = [0u8; 32];
        assert_eq!(persistence_digest_copy(p, d.as_mut_ptr()), GARY_CODE_OK);
        assert_eq!(hex::encode(d), VECTOR001_DIGEST_HEX);
        gary_session_free(p);
    }

    #[test]
    fn alice_fixture_send_bob_fixture_recv_utf8_roundtrip() {
        let alice = gary_session_new_initiator();
        let bob = gary_session_new();
        assert!(!alice.is_null() && !bob.is_null());

        let msg = b"hello-local-peer";
        let mut wire = [0u8; 8192];
        let mut written = 0usize;
        let code = gary_send_utf8_data_outer(
            alice,
            msg.as_ptr(),
            msg.len(),
            wire.as_mut_ptr(),
            wire.len(),
            &mut written,
        );
        assert_eq!(code, GARY_CODE_OK, "send {:?}", unsafe {
            CStr::from_ptr(gary_last_error(alice))
        });

        let slice = &wire[..written];
        let recv = gary_ingest_outer(bob, slice.as_ptr(), slice.len());
        assert_eq!(recv, GARY_CODE_OK, "ingest {:?}", unsafe {
            CStr::from_ptr(gary_last_error(bob))
        });

        let cstr = unsafe { CStr::from_ptr(gary_last_inbound_utf8(bob)) };
        assert_eq!(cstr.to_str().unwrap(), "hello-local-peer");

        gary_session_free(alice);
        gary_session_free(bob);
    }

    #[test]
    fn relay_prepare_process_utf8_roundtrip() {
        let alice = gary_session_new_initiator();
        let bob = gary_session_new();
        let rt = b"fetch-cap-placeholder";
        let msg = b"relay-wire-path";

        let mut relay = [0u8; 32768];
        let mut relay_written = 0usize;
        let pr = gary_prepare_relay_outbound_utf8(
            alice,
            rt.as_ptr(),
            rt.len(),
            msg.as_ptr(),
            msg.len(),
            relay.as_mut_ptr(),
            relay.len(),
            &mut relay_written,
        );
        assert_eq!(pr, GARY_CODE_OK, "{:?}", unsafe {
            CStr::from_ptr(gary_last_error(alice))
        });

        let ri = gary_process_relay_inbound(bob, relay.as_ptr(), relay_written);
        assert_eq!(ri, GARY_CODE_OK, "{:?}", unsafe {
            CStr::from_ptr(gary_last_error(bob))
        });
        let cstr = unsafe { CStr::from_ptr(gary_last_inbound_utf8(bob)) };
        assert_eq!(cstr.to_str().unwrap(), "relay-wire-path");

        gary_session_free(alice);
        gary_session_free(bob);
    }

    #[test]
    fn ingest_vector001_stale_epoch_and_stable_digest() {
        let p = gary_session_new();
        assert!(!p.is_null());
        let wire = hex::decode(VECTOR001_OUTER_HEX).unwrap();
        let mut d = [0u8; 32];
        persistence_digest_copy(p, d.as_mut_ptr());
        let before = d;

        let code = gary_ingest_outer(p, wire.as_ptr(), wire.len());
        assert_eq!(code, GARY_CODE_SESSION_STALE_EPOCH);

        persistence_digest_copy(p, d.as_mut_ptr());
        assert_eq!(d, before);

        gary_session_free(p);
    }

    #[test]
    fn free_boxed_roundtrip() {
        let okm = [0x77u8; 64];
        let sid = [1u8; 16];
        let anchor = libgary_core::engine::DeviceStateAnchorV1::new_v0(1);
        let sk = [2u8; 32];
        let inner = CoreSession::bootstrap_responder(&okm, sid, 0, sk, None, anchor);
        let b = Box::new(SessionHandle::new(inner));
        let raw = Box::into_raw(b);
        gary_session_free(raw);
    }
}
