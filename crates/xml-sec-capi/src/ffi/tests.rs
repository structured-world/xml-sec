use super::{
    XsBytes, XsCompileContext, XsDocument, XsError, XsKeys, XsPolicy, XsPolicyStore, XsProvider,
    contain, keys as hold_keys, policy as hold_policy, provider as hold_provider,
    xs_document_parse, xs_error_destroy, xs_error_message, xs_error_policy_violation,
    xs_error_status, xs_keys_add_symmetric, xs_keys_destroy, xs_keys_new, xs_policy_destroy,
    xs_policy_store_destroy, xs_policy_store_load, xs_policy_store_new, xs_provider_destroy,
    xs_provider_new_rustcrypto,
};
use crate::objects::Failure;
use crate::status::{
    XS_BUSY, XS_CONFIGURATION, XS_DOCUMENT, XS_INTERNAL, XS_INVALID_ARGUMENT, XS_OK, XS_POLICY,
    XsStatus,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Write as _;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The system allocator, recording the largest single request, so a test can
/// show an input was refused before the library copied it. Every test runs
/// in its own process, so no other test's allocations interleave.
struct Largest;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every request is forwarded unchanged to the system allocator.
unsafe impl GlobalAlloc for Largest {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        // SAFETY: forwarded caller contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded caller contract.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        // SAFETY: forwarded caller contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Largest = Largest;

fn bytes(text: &str) -> XsBytes {
    XsBytes {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

const MODERN: &str = "schema_version = 1\n[profiles.app]\nbase = 'Modern'\n";

/// A provider and a policy compiled from the Modern profile.
fn policy() -> (XsProvider, XsPolicyStore, XsPolicy) {
    policy_from(MODERN)
}

/// A provider and the `app` profile of `configuration`.
fn policy_from(configuration: &str) -> (XsProvider, XsPolicyStore, XsPolicy) {
    let mut provider = XsProvider::default();
    let mut store = XsPolicyStore::default();
    let mut policy = XsPolicy::default();
    let context = XsCompileContext {
        external_resources: 0,
        target_evidence: 1,
    };
    // SAFETY: every pointer names a live local of the declared type.
    unsafe {
        assert_eq!(
            xs_provider_new_rustcrypto(&raw mut provider, std::ptr::null_mut()),
            XS_OK
        );
        assert_eq!(
            xs_policy_store_new(
                bytes(configuration),
                bytes("app"),
                provider,
                &raw const context,
                std::ptr::null(),
                &raw mut store,
                std::ptr::null_mut(),
            ),
            XS_OK
        );
        assert_eq!(
            xs_policy_store_load(store, &raw mut policy, std::ptr::null_mut()),
            XS_OK
        );
    }
    (provider, store, policy)
}

fn release((provider, store, policy): (XsProvider, XsPolicyStore, XsPolicy)) {
    assert_eq!(xs_policy_destroy(policy), XS_OK);
    assert_eq!(xs_policy_store_destroy(store), XS_OK);
    assert_eq!(xs_provider_destroy(provider), XS_OK);
}

/// The status and message an error handle carries; the handle is destroyed.
fn take_error(error: XsError) -> (XsStatus, String) {
    let mut status = 0;
    let mut message = XsBytes {
        ptr: std::ptr::null(),
        len: 0,
    };
    // SAFETY: the outputs are live locals; the message is copied before the
    // handle that owns it is destroyed.
    let text = unsafe {
        assert_eq!(xs_error_status(error, &raw mut status), XS_OK);
        assert_eq!(xs_error_message(error, &raw mut message), XS_OK);
        String::from_utf8(std::slice::from_raw_parts(message.ptr, message.len).to_vec()).unwrap()
    };
    assert_eq!(xs_error_destroy(error), XS_OK);
    (status, text)
}

#[test]
fn a_panic_becomes_an_internal_status_and_error() {
    // No unwinding may cross into C: the panic is contained and reported.
    let mut error = MaybeUninit::uninit();
    let status = contain(Some(&mut error), || panic!("contained"));
    assert_eq!(status, XS_INTERNAL);
    // SAFETY: `contain` writes the error slot on every path.
    let (status, message) = take_error(unsafe { error.assume_init() });
    assert_eq!(status, XS_INTERNAL);
    assert_eq!(message, "internal error");
}

#[test]
fn success_clears_the_error_slot() {
    // A caller reusing one error variable never sees a previous failure.
    let mut error = MaybeUninit::new(XsError { value: 7 });
    assert_eq!(contain(Some(&mut error), || Ok(())), XS_OK);
    // SAFETY: initialized above and rewritten by `contain`.
    assert_eq!(unsafe { error.assume_init() }.value, 0);
    assert_eq!(
        contain(None, || Err(Failure::new(XS_DOCUMENT, "x"))),
        XS_DOCUMENT
    );
}

#[test]
fn invalid_pointers_and_lengths_are_refused_before_any_work() {
    // A length without bytes, a length past the address space, invalid UTF-8
    // and a null output are argument errors, never dereferenced.
    let handles = policy();
    let mut document = XsDocument::default();
    let invalid_utf8 = [0xff_u8, 0xfe];
    for xml in [
        XsBytes {
            ptr: std::ptr::null(),
            len: 3,
        },
        XsBytes {
            ptr: invalid_utf8.as_ptr(),
            len: usize::MAX,
        },
        XsBytes {
            ptr: invalid_utf8.as_ptr(),
            len: invalid_utf8.len(),
        },
    ] {
        let mut error = XsError::default();
        // SAFETY: the byte strings are rejected before being read, or name a
        // live array; the outputs are live locals.
        let status =
            unsafe { xs_document_parse(handles.2, 1, xml, &raw mut document, &raw mut error) };
        assert_eq!(status, XS_INVALID_ARGUMENT);
        assert_eq!(take_error(error).0, XS_INVALID_ARGUMENT);
        assert_eq!(document.value, 0);
    }
    // SAFETY: a null output is reported, not written.
    let status = unsafe {
        xs_document_parse(
            handles.2,
            1,
            bytes("<a/>"),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, XS_INVALID_ARGUMENT);
    release(handles);
}

#[test]
fn a_document_beyond_a_policy_limit_is_a_typed_policy_refusal() {
    // Byte, depth, parse-work, node and namespace-binding ceilings of the
    // compiled policy refuse a document as policy, with the resource-limit
    // violation, not as malformed XML.
    let deep = "<a><b><c><d><e><f/></e></d></c></b></a>";
    let large = format!("<a>{}</a>", "x".repeat(256));
    let wide = format!("<a>{}</a>", "<b/>".repeat(64));
    // Bindings in scope at once, all declared on one element.
    let mut bound = String::from("<a");
    for n in 0..16 {
        write!(bound, " xmlns:p{n}='urn:{n}'").expect("a String accepts every write");
    }
    bound.push_str("/>");
    for (limit, xml) in [
        ("max_xml_document_bytes = 64", large.as_str()),
        ("max_xml_depth = 2", deep),
        ("max_xml_parse_work_bytes = 64", large.as_str()),
        ("max_xml_nodes = 8", wide.as_str()),
        ("max_xml_namespace_bindings = 4", bound.as_str()),
    ] {
        let handles = policy_from(&format!(
            "{MODERN}[profiles.app.verification.resources]\n{limit}\n"
        ));
        let mut document = XsDocument::default();
        let mut error = XsError::default();
        // SAFETY: the byte string names a live string; the outputs are live locals.
        let status = unsafe {
            xs_document_parse(handles.2, 1, bytes(xml), &raw mut document, &raw mut error)
        };
        let mut violation = 0;
        // SAFETY: the output is a live local.
        let read = unsafe { xs_error_policy_violation(error, &raw mut violation) };
        assert_eq!(read, XS_OK);
        let (error_status, message) = take_error(error);
        assert_eq!(
            (status, error_status, violation),
            (XS_POLICY, XS_POLICY, 8),
            "{limit}: {message}"
        );
        release(handles);
    }
}

/// A key manager under `[profiles.app.verification.resources]` `limits`.
fn keys_under(limits: &str) -> ((XsProvider, XsPolicyStore, XsPolicy), XsKeys) {
    let handles = policy_from(&format!(
        "{MODERN}[profiles.app.verification.resources]\n{limits}\n"
    ));
    let mut keys = XsKeys::default();
    // SAFETY: the output is a live local.
    let status = unsafe { xs_keys_new(handles.2, 1, &raw mut keys, std::ptr::null_mut()) };
    assert_eq!(status, XS_OK);
    (handles, keys)
}

#[test]
fn input_beyond_a_policy_limit_is_refused_before_it_is_copied() {
    // A caller's bytes past the compiled ceiling are refused without the
    // library allocating their size, so an oversized input cannot exhaust
    // memory and abort the process before the refusal.
    let (handles, keys) = keys_under("max_external_resource_bytes = 64");
    let key = vec![7_u8; 1 << 20];
    let large = format!("<a>{}</a>", "x".repeat(1 << 20));
    let parse_handles = policy_from(&format!(
        "{MODERN}[profiles.app.verification.resources]\nmax_xml_document_bytes = 64\n"
    ));
    LARGEST.store(0, Ordering::Relaxed);
    let mut error = XsError::default();
    // SAFETY: the byte strings name live buffers; the output is a live local.
    let status = unsafe {
        xs_keys_add_symmetric(
            keys,
            bytes("hmac"),
            1,
            XsBytes {
                ptr: key.as_ptr(),
                len: key.len(),
            },
            1,
            &raw mut error,
        )
    };
    assert_eq!(status, XS_POLICY);
    assert_eq!(take_error(error).0, XS_POLICY);
    let mut document = XsDocument::default();
    // SAFETY: as above.
    let status = unsafe {
        xs_document_parse(
            parse_handles.2,
            1,
            bytes(&large),
            &raw mut document,
            &raw mut error,
        )
    };
    assert_eq!(status, XS_POLICY);
    assert_eq!(take_error(error).0, XS_POLICY);
    assert!(LARGEST.load(Ordering::Relaxed) < 1 << 20);
    assert_eq!(xs_keys_destroy(keys), XS_OK);
    release(handles);
    release(parse_handles);
}

#[test]
fn a_held_object_is_busy_until_the_call_that_holds_it_ends() {
    // A call keeps the provider, policy and key handles it reads in use for
    // its whole length, so destroying them meanwhile reports busy.
    let (handles, keys_handle) = keys_under("");
    let (Ok(held_provider), Ok(held_policy), Ok(held_keys)) = (
        hold_provider(handles.0),
        hold_policy(handles.2),
        hold_keys(keys_handle),
    ) else {
        panic!("live handles must be held");
    };
    assert_eq!(xs_provider_destroy(handles.0), XS_BUSY);
    assert_eq!(xs_policy_destroy(handles.2), XS_BUSY);
    assert_eq!(xs_keys_destroy(keys_handle), XS_BUSY);
    drop((held_provider, held_policy, held_keys));
    assert_eq!(xs_keys_destroy(keys_handle), XS_OK);
    release(handles);
}

#[test]
fn configuration_and_document_failures_carry_their_class() {
    // The status names the failing layer, and the message comes with it.
    let handles = policy();
    let context = XsCompileContext {
        external_resources: 0,
        target_evidence: 0,
    };
    let mut store = XsPolicyStore::default();
    let mut error = XsError::default();
    // SAFETY: every pointer names a live local of the declared type.
    let status = unsafe {
        xs_policy_store_new(
            bytes("schema_version = 1\n[profiles.app\n"),
            bytes("app"),
            handles.0,
            &raw const context,
            std::ptr::null(),
            &raw mut store,
            &raw mut error,
        )
    };
    assert_eq!(status, XS_CONFIGURATION);
    assert_eq!(store.value, 0);
    let (status, message) = take_error(error);
    assert_eq!(status, XS_CONFIGURATION);
    assert_ne!(message, "");

    let mut document = XsDocument::default();
    // SAFETY: as above.
    let status = unsafe {
        xs_document_parse(
            handles.2,
            1,
            bytes("<broken"),
            &raw mut document,
            &raw mut error,
        )
    };
    assert_eq!(status, XS_DOCUMENT);
    assert_eq!(take_error(error).0, XS_DOCUMENT);
    release(handles);
}
