//! Library state: initialization and shutdown racing each other, the version
//! check, the crypto library loaded by name, a report callback that reenters
//! the library, and a panic contained at the boundary. Each test runs in its
//! own process, so the process-wide state it sets is its own.

use super::{xmlSecCheckVersionExt, xmlSecGetDefaultCrypto, xmlSecInit, xmlSecShutdown};
use crate::ffi::buffer::xmlSecBufferInitialize;
use crate::ffi::crypto::{
    xmlSecCryptoAppInit, xmlSecCryptoAppShutdown, xmlSecCryptoDLGetFunctions,
    xmlSecCryptoDLLoadLibrary, xmlSecCryptoInit, xmlSecCryptoShutdown,
    xmlSecTransformSha256GetKlass,
};
use crate::ffi::errors::{ErrorsCallback, R_ASSERTION, R_NOT_IMPLEMENTED, xmlSecErrorsSetCallback};
use crate::ffi::list::xmlSecPtrListGetSize;
use crate::ffi::transforms::xmlSecTransformIdsGet;
use std::ffi::{CStr, c_char, c_int};
use std::sync::Mutex;

/// The reasons of the reports received, in order.
static REASONS: Mutex<Vec<(String, c_int)>> = Mutex::new(Vec::new());

fn take() -> Vec<(String, c_int)> {
    std::mem::take(&mut *REASONS.lock().expect("reasons"))
}

unsafe extern "C" fn record(
    _file: *const c_char,
    _line: c_int,
    func: *const c_char,
    _object: *const c_char,
    _subject: *const c_char,
    reason: c_int,
    _message: *const c_char,
) {
    // SAFETY: the library passes a NUL-terminated function name.
    let func = unsafe { CStr::from_ptr(func) }
        .to_string_lossy()
        .into_owned();
    REASONS.lock().expect("reasons").push((func, reason));
}

/// Initializations and shutdowns racing on several threads leave the
/// registries consistent: after a final shutdown and initialization the
/// transform registry holds libxmlsec1's defaults once.
#[test]
fn racing_init_and_shutdown_leave_consistent_registries() {
    let threads: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                for _ in 0..50 {
                    // SAFETY: no operation runs; init and shutdown serialize.
                    unsafe {
                        assert_eq!(xmlSecInit(), 0);
                        assert_eq!(xmlSecShutdown(), 0);
                    }
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("no thread panics");
    }
    // SAFETY: the threads are done.
    unsafe {
        assert_eq!(xmlSecShutdown(), 0);
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecPtrListGetSize(xmlSecTransformIdsGet()), 12);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// A second initialization without a shutdown in between leaves the
/// registries holding the defaults once and releases the storage of the
/// first, which the leak checker of the sanitizer run verifies.
#[test]
fn repeated_init_releases_the_previous_registries() {
    // SAFETY: init and shutdown run on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecPtrListGetSize(xmlSecTransformIdsGet()), 12);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// The version check accepts this release exactly and any older minor or
/// subminor as ABI compatible, and refuses another major.
#[test]
fn version_check_follows_libxmlsec1() {
    // SAFETY: the version check takes any numbers.
    unsafe {
        assert_eq!(xmlSecCheckVersionExt(1, 3, 13, 0), 1);
        assert_eq!(xmlSecCheckVersionExt(1, 3, 12, 0), 0);
        assert_eq!(xmlSecCheckVersionExt(1, 3, 12, 1), 1);
        assert_eq!(xmlSecCheckVersionExt(1, 2, 40, 1), 1);
        assert_eq!(xmlSecCheckVersionExt(1, 3, 14, 1), 0);
        assert_eq!(xmlSecCheckVersionExt(1, 4, 0, 1), 0);
        assert_eq!(xmlSecCheckVersionExt(2, 3, 13, 1), 0);
    }
}

/// The default crypto name loads the built-in table, whose initialization
/// succeeds; another library's name is refused, and a klass the table lacks
/// reports libxmlsec1's missing-method error.
#[test]
fn default_crypto_loads_the_builtin_table() {
    // SAFETY: the callback has the callback's signature; init and the table
    // calls run on this thread alone.
    unsafe {
        xmlSecErrorsSetCallback(Some(record as ErrorsCallback));
        assert_eq!(xmlSecInit(), 0);
        let name = CStr::from_ptr(xmlSecGetDefaultCrypto().cast());
        assert_eq!(name.to_bytes(), b"rustcrypto");
        assert!(xmlSecCryptoDLGetFunctions().is_null());
        assert_eq!(xmlSecCryptoDLLoadLibrary(c"openssl".as_ptr().cast()), -1);
        assert!(xmlSecCryptoDLGetFunctions().is_null());
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert!(!xmlSecCryptoDLGetFunctions().is_null());
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(c"/etc/config".as_ptr()), -1);
        assert_eq!(xmlSecCryptoInit(), 0);
        take();
        assert!(xmlSecTransformSha256GetKlass().is_null());
        assert_eq!(
            take(),
            [(
                "xmlSecTransformSha256GetKlass".to_owned(),
                R_NOT_IMPLEMENTED
            )]
        );
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// How many reports the reentering callback has handled.
static DEPTH: Mutex<u32> = Mutex::new(0);

unsafe extern "C" fn reentering(
    file: *const c_char,
    line: c_int,
    func: *const c_char,
    object: *const c_char,
    subject: *const c_char,
    reason: c_int,
    message: *const c_char,
) {
    // SAFETY: forwarding the library's arguments.
    unsafe { record(file, line, func, object, subject, reason, message) };
    let nested = {
        let mut depth = DEPTH.lock().expect("depth");
        *depth += 1;
        *depth == 1
    };
    if nested {
        // SAFETY: a failing call of the library from inside its report.
        let initialized = unsafe { xmlSecBufferInitialize(std::ptr::null_mut(), 0) };
        assert_eq!(initialized, -1);
    }
}

/// A report callback may call the library again: the nested call reports
/// through the same callback, after the outer report was delivered.
#[test]
fn report_callback_may_reenter_the_library() {
    // SAFETY: the callback has the callback's signature.
    unsafe {
        xmlSecErrorsSetCallback(Some(reentering as ErrorsCallback));
        assert_eq!(xmlSecBufferInitialize(std::ptr::null_mut(), 0), -1);
    }
    assert_eq!(
        take(),
        [
            ("xmlSecBufferInitialize".to_owned(), R_ASSERTION),
            ("xmlSecBufferInitialize".to_owned(), R_ASSERTION),
        ]
    );
}

/// The report callback is process-global, as libxmlsec1's is: one set on
/// this thread receives the reports of a call on another thread.
#[test]
fn report_callback_is_process_global() {
    // SAFETY: the callback has the callback's signature.
    unsafe { xmlSecErrorsSetCallback(Some(record as ErrorsCallback)) };
    std::thread::spawn(|| {
        // SAFETY: a failing call of the library.
        let initialized = unsafe { xmlSecBufferInitialize(std::ptr::null_mut(), 0) };
        assert_eq!(initialized, -1);
    })
    .join()
    .expect("the thread does not panic");
    assert_eq!(take(), [("xmlSecBufferInitialize".to_owned(), R_ASSERTION)]);
}

/// A panic inside an entry point's body is reported as an internal error
/// and returns the fallback instead of unwinding into C.
#[test]
fn panic_is_contained_and_reported() {
    // SAFETY: the callback has the callback's signature.
    unsafe { xmlSecErrorsSetCallback(Some(record as ErrorsCallback)) };
    let result = crate::ffi::contain(-7, || -> c_int { panic!("boundary") });
    assert_eq!(result, -7);
    assert_eq!(take(), [("contain".to_owned(), 1)]);
}
