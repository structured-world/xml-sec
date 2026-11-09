//! Test support: loads the system libxml2 into the process the way a C
//! caller's program has it loaded, and resolves functions only tests call.

use std::ffi::{CString, c_void};
use std::sync::Once;

/// The system libxml2 shared library names tried, in order.
const NAMES: [&str; 3] = ["libxml2.2.dylib", "libxml2.so.2", "libxml2.so"];

/// Loads the system libxml2 with global symbol visibility, once.
///
/// # Panics
/// When no system libxml2 can be loaded.
pub fn load_system_libxml2() {
    static LOAD: Once = Once::new();
    LOAD.call_once(|| {
        let loaded = NAMES.iter().any(|name| {
            let name = CString::new(*name).expect("no NUL in a library name");
            // SAFETY: loading a system library by name; its initializers
            // are libxml2's own.
            let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
            !handle.is_null()
        });
        assert!(loaded, "a system libxml2 must be installed for the tests");
    });
}

/// The libxml2 function `name` as `F`, after [`load_system_libxml2`].
///
/// # Safety
/// `F` is the function pointer type of `name`'s C signature.
///
/// # Panics
/// When the loaded libxml2 has no `name`.
pub unsafe fn function<F: Copy>(name: &str) -> F {
    assert_eq!(size_of::<F>(), size_of::<*mut c_void>());
    load_system_libxml2();
    let name = CString::new(name).expect("no NUL in a symbol name");
    // SAFETY: a NUL-terminated name searched in the global scope.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    assert!(!address.is_null(), "libxml2 has {name:?}");
    // SAFETY: `F` is a function pointer of the symbol's signature, by the
    // caller's contract, and has a pointer's size.
    unsafe { std::mem::transmute_copy::<*mut c_void, F>(&address) }
}
