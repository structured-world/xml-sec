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
    self, ResourceScope, xmlSecTransformCtxCreate, xmlSecTransformCtxCreateAndAppend,
    xmlSecTransformCtxDestroy, xmlSecTransformCtxUriExecute,
};
use crate::ffi::transforms::digests::sha256;
use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};

/// The octets the resource still holds; `usize::MAX` for an endless one.
static LEFT: AtomicUsize = AtomicUsize::new(0);
/// How many times a callback opened a resource.
static OPENED: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn matches(_uri: *const c_char) -> c_int {
    1
}

unsafe extern "C" fn open(_uri: *const c_char) -> *mut c_void {
    OPENED.fetch_add(1, Ordering::Relaxed);
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

/// Reads `size` octets of one external resource for the operation `scope`,
/// as a signature or decryption context reads each resource it hands the
/// core; the octets read, or `None` when the read is refused.
fn read_for(scope: &mut ResourceScope<'_>, size: usize) -> Option<usize> {
    const DOCUMENT: &str = "<Envelope xmlns=\"urn:envelope\"/>";
    LEFT.store(size, Ordering::Relaxed);
    // SAFETY: the callback list, the document and the context are used by
    // this test alone and released here.
    unsafe {
        assert_eq!(xmlSecIOInit(), 0);
        let registered =
            xmlSecIORegisterCallbacks(Some(matches), Some(open), Some(read), Some(close));
        assert_eq!(registered, 0);
        let doc = xsReadMemory(
            DOCUMENT.as_ptr().cast(),
            c_int::try_from(DOCUMENT.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let prefs = xmlSecTransformCtxCreate();
        // The caller enables every URI type, `xmlSecTransformUriTypeAny`, so
        // the operation's policy alone decides.
        (*prefs).enabled_uris = 0xFFFF;
        let bytes = ctx::read_resource(
            prefs,
            b"test:resource",
            xsDocGetRootElement(doc),
            doc,
            scope,
        );
        xmlSecTransformCtxDestroy(prefs);
        xsFreeDoc(doc);
        xmlSecIOShutdown();
        bytes.map(|bytes| bytes.len())
    }
}

/// The current revision with `edit` applied, as one operation pins it.
fn pinned_with(edit: impl FnOnce(&mut policy::Pinned)) -> policy::Pinned {
    let mut pinned = policy::Pinned::current(crate::ffi::errors::here!("test"))
        .expect("the library policy compiles");
    edit(&mut pinned);
    pinned
}

/// The resources one operation reads share its total allowance: a second
/// read stops where the operation's total is spent instead of starting a
/// fresh count, so the operation never collects more than the total.
#[test]
fn reads_of_one_operation_share_its_total_allowance() {
    own_process();
    let pinned = pinned_with(|pinned| {
        std::sync::Arc::make_mut(&mut pinned.verification)
            .resources
            .max_external_resource_total_bytes = 24;
    });
    let mut scope = ResourceScope {
        pinned: &pinned,
        side: policy::Side::Verify,
        spent: policy::Spent::default(),
    };
    assert_eq!(read_for(&mut scope, 16), Some(16));
    assert_eq!(read_for(&mut scope, 16), None);
}

/// A read runs under the revision its operation pinned: a republish after
/// the operation began, here one that refuses external references, does not
/// change what the operation's reads admit.
#[test]
fn a_read_runs_under_its_operations_revision() {
    own_process();
    let pinned = pinned_with(|_| {});
    policy::republish(
        |verification| verification.uris.references = UriTypeSet::SAME_DOCUMENT,
        |_| {},
    )
    .expect("the library policy compiles");
    let mut scope = ResourceScope {
        pinned: &pinned,
        side: policy::Side::Verify,
        spent: policy::Spent::default(),
    };
    assert_eq!(read_for(&mut scope, 16), Some(16));
}

/// A signing operation reads its detached references under the signing
/// policy: a resource signing admits is read even when verification refuses
/// external references.
#[test]
fn a_signing_read_admits_what_signing_admits() {
    own_process();
    policy::republish(
        |verification| verification.uris.references = UriTypeSet::SAME_DOCUMENT,
        |signing| signing.uris.references = UriTypeSet::ALL,
    )
    .expect("the library policy compiles");
    let pinned = pinned_with(|_| {});
    let mut scope = ResourceScope {
        pinned: &pinned,
        side: policy::Side::Sign,
        spent: policy::Spent::default(),
    };
    assert_eq!(read_for(&mut scope, 16), Some(16));
}

/// A `CipherReference` is read under the decryption policy: a URI class
/// decryption refuses is refused before any callback opens it, whatever
/// verification admits.
#[test]
fn a_decryption_read_is_refused_before_a_callback_opens_it() {
    own_process();
    let pinned = pinned_with(|pinned| {
        std::sync::Arc::make_mut(&mut pinned.decryption)
            .uris
            .references = UriTypeSet::SAME_DOCUMENT;
    });
    let mut scope = ResourceScope {
        pinned: &pinned,
        side: policy::Side::Decrypt,
        spent: policy::Spent::default(),
    };
    assert_eq!(read_for(&mut scope, 16), None);
    assert_eq!(OPENED.load(Ordering::Relaxed), 0);
}
