use super::*;

/// A handler value for the table; never called by these tests.
extern "C" fn unused(_: *mut c_void, _: *const c_char, _: *const c_char) {}

#[test]
fn each_thread_keeps_its_own_handler() {
    // A handler one thread installs is not another thread's: errors of the
    // other thread keep their own channel, as with libxml2's per-thread
    // handler.
    // SAFETY: a function pointer of one size as another; it is stored and
    // compared, never called.
    let handler: GenericErrorFunc = unsafe {
        std::mem::transmute::<
            extern "C" fn(*mut c_void, *const c_char, *const c_char),
            GenericErrorFunc,
        >(unused)
    };
    // SAFETY: the handler is never called; the context is not read.
    unsafe { xsSetGenericErrorFunc(std::ptr::null_mut(), Some(handler)) };
    assert!(installed().is_some());
    let other = std::thread::spawn(|| installed().is_none())
        .join()
        .expect("the other thread runs");
    assert!(other, "another thread has no handler of this thread");
    // SAFETY: null restores the standard error stream.
    unsafe { xsSetGenericErrorFunc(std::ptr::null_mut(), None) };
    assert!(installed().is_none());
}
