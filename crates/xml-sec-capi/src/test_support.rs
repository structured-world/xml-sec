//! What the crate's unit tests share: the process-wide handle table, its
//! exhaustion switch and the allocation counter.
#![forbid(unsafe_code)]

use parking_lot::{Mutex, MutexGuard};

static SERIAL: Mutex<()> = parking_lot::const_mutex(());

/// Hold the process-wide state for one test, so tests run one at a time
/// whether the runner gives each its own process or threads them in one.
pub(crate) fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock()
}
