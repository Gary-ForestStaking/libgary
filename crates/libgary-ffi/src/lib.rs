//! C ABI façade for [`libgary_core::engine::SessionHandle`].
//!
//! Rules: `docs/session-handle-boundary.md` (opaque pointers, integer errors, no unwind across FFI).
//! This crate intentionally stays tiny — add send/recv/bindings after ABI review.
#![allow(unsafe_code)]

use std::panic::catch_unwind;

pub use libgary_core::engine::SessionHandle;

/// Status codes for future FFI entrypoints (`session_send`, `session_recv`, …).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LibgaryStatus {
    Ok = 0,
    NullPointer = 1,
    /// Rust panic translated — embedding code must treat session as poisoned.
    Panic = 2,
}

/// Opaque heap-owned session. C typedef: `typedef struct LibgaryOpaqueSession LibgaryOpaqueSession;`
#[repr(transparent)]
pub struct LibgaryOpaqueSession(pub(crate) SessionHandle);

impl LibgaryOpaqueSession {
    #[must_use]
    pub fn into_inner(self) -> SessionHandle {
        self.0
    }
}

/// Release a session allocated by future constructors. `NULL` is a no-op.
///
/// Panics in `Drop` are caught so unwind never crosses the FFI edge.
#[unsafe(no_mangle)]
pub extern "C" fn libgary_session_free(handle: *mut LibgaryOpaqueSession) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(|| unsafe {
        drop(Box::from_raw(handle));
    });
}

/// Diagnostic: last operation status (placeholder until threaded TLS error slot exists).
#[unsafe(no_mangle)]
pub extern "C" fn libgary_session_last_status() -> i32 {
    LibgaryStatus::Ok as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_null_is_noop() {
        libgary_session_free(std::ptr::null_mut());
    }

    #[test]
    fn free_boxed_roundtrip() {
        let okm = [0x77u8; 64];
        let sid = [1u8; 16];
        let anchor = libgary_core::engine::DeviceStateAnchorV1::new_v0(1);
        let sk = [2u8; 32];
        let inner = SessionHandle::bootstrap_responder(&okm, sid, 0, sk, None, anchor);
        let b = Box::new(LibgaryOpaqueSession(inner));
        let p = Box::into_raw(b);
        libgary_session_free(p);
    }
}
