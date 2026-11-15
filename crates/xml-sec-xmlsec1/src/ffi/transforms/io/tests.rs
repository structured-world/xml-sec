//! The input-URI transform's policy bounds: a resource read through the
//! caller's callbacks is refused once it passes the policy's per-resource
//! size, and read whole when it is exactly that size. libxmlsec1 bounds
//! neither, so the differential C program cannot cover them. Each test that
//! fills the callback list checks that it runs in its own process, so the
//! list is its own.

use crate::ffi::tests::own_process;

use super::{UriTypeSet, admits, xmlSecIOInit, xmlSecIORegisterCallbacks, xmlSecIOShutdown};
use crate::ffi::buffer::xmlSecBufferGetSize;
use crate::ffi::policy;
use crate::ffi::transforms::OPERATION_SIGN;
use crate::ffi::transforms::ctx::{
    xmlSecTransformCtxCreate, xmlSecTransformCtxCreateAndAppend, xmlSecTransformCtxDestroy,
    xmlSecTransformCtxUriExecute,
};
use crate::ffi::transforms::digests::sha256;
use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

/// The octets the resource still holds; `usize::MAX` for an endless one.
static LEFT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn matches(_uri: *const c_char) -> c_int {
    1
}

unsafe extern "C" fn open(_uri: *const c_char) -> *mut c_void {
    std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
}

unsafe extern "C" fn read(_context: *mut c_void, buffer: *mut c_char, len: c_int) -> c_int {
    let wanted = usize::try_from(len).expect("libxml2 passes a non-negative length");
    let left = LEFT.load(Ordering::Relaxed);
    let count = wanted.min(left);
    if left != usize::MAX {
        LEFT.store(left - count, Ordering::Relaxed);
    }
    // SAFETY: the transform passes `len` writable bytes.
    unsafe { buffer.cast::<u8>().write_bytes(b'x', count) };
    c_int::try_from(count).expect("at most `len` octets")
}

unsafe extern "C" fn close(_context: *mut c_void) -> c_int {
    0
}

/// Executes a context on one URI read by the test's callbacks; the result's
/// size, or `None` when the execution fails.
fn read_resource() -> Option<usize> {
    own_process();
    // SAFETY: the callback list and the context are used by this test alone.
    unsafe {
        assert_eq!(xmlSecIOInit(), 0);
        let registered =
            xmlSecIORegisterCallbacks(Some(matches), Some(open), Some(read), Some(close));
        assert_eq!(registered, 0);
        let ctx = xmlSecTransformCtxCreate();
        assert!(!ctx.is_null());
        let executed = xmlSecTransformCtxUriExecute(ctx, c"test:resource".as_ptr().cast());
        let size = (executed == 0).then(|| xmlSecBufferGetSize((*ctx).result));
        xmlSecTransformCtxDestroy(ctx);
        xmlSecIOShutdown();
        size
    }
}

fn per_resource_limit() -> usize {
    policy::verification()
        .expect("the library policy compiles")
        .resources
        .max_external_resource_bytes
}

/// The reference URI permission gates the read: a same-document permission
/// refuses an external URI before any callback opens it and admits the
/// empty and same-document classes.
#[test]
fn reference_permission_gates_the_uri_class() {
    assert!(!admits(UriTypeSet::SAME_DOCUMENT, b"example:thing"));
    assert!(admits(UriTypeSet::SAME_DOCUMENT, b"#id"));
    assert!(admits(UriTypeSet::SAME_DOCUMENT, b""));
    assert!(admits(UriTypeSet::ALL, b"example:thing"));
}

/// The library's policy admits external reference URIs, which it resolves
/// only through the caller's callbacks, and leaves the key retrieval
/// permissions of the profile as they are.
#[test]
fn library_policy_admits_external_references_only() {
    let policy = policy::verification().expect("the library policy compiles");
    assert_eq!(policy.uris.references, UriTypeSet::ALL);
    assert_eq!(policy.uris.retrieval_methods, UriTypeSet::SAME_DOCUMENT);
    assert_eq!(policy.uris.key_info_references, UriTypeSet::SAME_DOCUMENT);
}

/// The signing snapshot admits the same external references: a chain whose
/// digest signs reads the resource through the caller's callbacks, as a
/// detached reference is digested when it is signed.
#[test]
fn a_signing_chain_reads_an_external_reference() {
    own_process();
    LEFT.store(16, Ordering::Relaxed);
    // SAFETY: the callback list and the context are used by this test alone.
    unsafe {
        assert_eq!(xmlSecIOInit(), 0);
        let registered =
            xmlSecIORegisterCallbacks(Some(matches), Some(open), Some(read), Some(close));
        assert_eq!(registered, 0);
        let ctx = xmlSecTransformCtxCreate();
        let digest = xmlSecTransformCtxCreateAndAppend(ctx, sha256());
        (*digest).operation = OPERATION_SIGN;
        assert_eq!(
            xmlSecTransformCtxUriExecute(ctx, c"test:resource".as_ptr().cast()),
            0
        );
        assert_eq!(xmlSecBufferGetSize((*ctx).result), 32);
        xmlSecTransformCtxDestroy(ctx);
        xmlSecIOShutdown();
    }
}

/// An endless resource stops the run at the per-resource limit instead of
/// reading on.
#[test]
fn endless_resource_stops_at_the_policy_limit() {
    LEFT.store(usize::MAX, Ordering::Relaxed);
    assert_eq!(read_resource(), None);
}

/// A resource of exactly the per-resource limit is read whole; one octet
/// more is refused.
#[test]
fn resource_of_the_limit_is_read_and_one_more_refused() {
    let limit = per_resource_limit();
    LEFT.store(limit, Ordering::Relaxed);
    assert_eq!(read_resource(), Some(limit));
    LEFT.store(limit + 1, Ordering::Relaxed);
    assert_eq!(read_resource(), None);
}
