use super::{
    XsBytes, XsCompileContext, XsDocument, XsError, XsPolicy, XsPolicyStore, XsProvider, contain,
    xs_document_parse, xs_error_destroy, xs_error_message, xs_error_status, xs_policy_destroy,
    xs_policy_store_destroy, xs_policy_store_load, xs_policy_store_new, xs_provider_destroy,
    xs_provider_new_rustcrypto,
};
use crate::objects::Failure;
use crate::status::{
    XS_CONFIGURATION, XS_DOCUMENT, XS_INTERNAL, XS_INVALID_ARGUMENT, XS_OK, XsStatus,
};
use std::mem::MaybeUninit;

fn bytes(text: &str) -> XsBytes {
    XsBytes {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

/// A provider and a policy compiled from the Modern profile.
fn policy() -> (XsProvider, XsPolicyStore, XsPolicy) {
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
                bytes("schema_version = 1\n[profiles.app]\nbase = 'Modern'\n"),
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
