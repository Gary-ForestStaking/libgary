//! Ingress-visible session mode (epoch / RESET half-open policy).

/// Logical clock domain for [`SessionMode::ResetPending::drain_until_ticks`] is **caller-defined**
/// (wall-clock ms, message ordinal, etc.). [`crate::engine::SessionHandle::handle_inbound_outer`] compares
/// it only against `drain_until_ticks` when set.
pub const RESET_HALF_OPEN_DEFAULT_DRAIN_TICKS: u64 = 86_400;

/// Policy wrapper over concrete ratchet epoch (`SessionHandle::epoch` / persisted export).
///
/// `Active.epoch` / `Bootstrapping.epoch` must match [`crate::engine::SessionHandle::epoch`] for the
/// discriminant that carries an epoch field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionMode {
    Active { epoch: u32 },
    ResetPending {
        old_epoch: u32,
        new_epoch: u32,
        drain_until_ticks: Option<u64>,
    },
    Bootstrapping { epoch: u32 },
}
