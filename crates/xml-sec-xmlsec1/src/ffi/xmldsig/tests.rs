use super::*;

use std::sync::Arc;

use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};

use crate::ffi::crypto::{
    xmlSecCryptoAppInit, xmlSecCryptoAppShutdown, xmlSecCryptoDLLoadLibrary, xmlSecCryptoInit,
    xmlSecCryptoShutdown,
};
use crate::ffi::keys::xmlSecKeyCreate;
use crate::ffi::keysdata::xmlSecKeyDataBinRead;
use crate::ffi::library::{xmlSecInit, xmlSecShutdown};
use crate::ffi::list::{xmlSecPtrListGetItem, xmlSecPtrListGetSize};
use crate::ffi::symkeys;
use crate::ffi::tests::own_process;
use crate::ffi::xmltree::{xmlSecAddIDs, xmlSecFindNode};

/// An HMAC-SHA256 signature of `#data` libxmlsec1 wrote with the secret
/// `secret-of-thirty-two-octets-long`, its value replaced.
const TAMPERED: &str = concat!(
    "<Envelope xmlns=\"urn:envelope\"><Data Id=\"data\">payload</Data>",
    "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
    "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
    "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
    "<Reference URI=\"#data\"><Transforms>",
    "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>",
    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms>",
    "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
    "<DigestValue>wFIbO8Tk9pDpGXaiAtlgRAKPJ6BFdyxSkyGlEOhZm/M=</DigestValue>",
    "</Reference></SignedInfo>",
    "<SignatureValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</SignatureValue>",
    "</Signature></Envelope>"
);

#[test]
fn a_failed_signature_value_leaves_its_references_undereferenced() {
    // The core checks the signature value before it dereferences anything a
    // signer did not authenticate; libxmlsec1 digests the references first
    // and reports them OK.
    own_process();
    let secret = b"secret-of-thirty-two-octets-long";
    // SAFETY: the library, a document, a key and a context set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsReadMemory(
            TAMPERED.as_ptr().cast(),
            i32::try_from(TAMPERED.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ids = [c"Id".as_ptr().cast::<u8>(), std::ptr::null()];
        xmlSecAddIDs(doc, std::ptr::null_mut(), ids.as_ptr());
        let signature = xmlSecFindNode(
            xsDocGetRootElement(doc),
            c"Signature".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        let key = xmlSecKeyCreate();
        assert_eq!(
            xmlSecKeyDataBinRead(
                symkeys::hmac(),
                key.cast(),
                secret.as_ptr(),
                secret.len(),
                (&raw mut (*ctx).key_info_read_ctx).cast(),
            ),
            0
        );
        (*ctx).sign_key = key;
        assert_eq!(xmlSecDSigCtxVerify(ctx, signature), 0);
        assert_eq!((*ctx).status, STATUS_INVALID);
        assert_eq!((*ctx).failure_reason, FAILURE_SIGNATURE);
        let reference = xmlSecPtrListGetItem(&raw mut (*ctx).signed_info_references, 0)
            .cast::<XmlSecDSigReferenceCtx>();
        assert_eq!((*reference).status, STATUS_UNKNOWN);
        xmlSecDSigCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// The verification snapshot the key lookup found pinned in its read
/// context, by address; zero when none was pinned.
static LOOKUP_PIN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A key manager's lookup that records the revision pinned for it and hands
/// back the HMAC key of [`TAMPERED`].
unsafe extern "C" fn recording_lookup(
    _node: *mut XmlNode,
    ctx: *mut crate::ffi::keyinfo::XmlSecKeyInfoCtx,
) -> *mut crate::ffi::keys::XmlSecKey {
    // SAFETY: the read context the operation passes.
    let pinned = unsafe { crate::ffi::policy::pinned((*ctx).reserved0) };
    LOOKUP_PIN.store(
        pinned.map_or(0, |pinned| Arc::as_ptr(&pinned.verification).addr()),
        std::sync::atomic::Ordering::Relaxed,
    );
    let secret = b"secret-of-thirty-two-octets-long";
    // SAFETY: a key and a read context created here; the HMAC klass reads
    // the key.
    unsafe {
        let read = crate::ffi::keyinfo::xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        let key = xmlSecKeyCreate();
        assert_eq!(
            xmlSecKeyDataBinRead(
                symkeys::hmac(),
                key.cast(),
                secret.as_ptr(),
                secret.len(),
                read.cast(),
            ),
            0
        );
        crate::ffi::keyinfo::xmlSecKeyInfoCtxDestroy(read);
        key
    }
}

#[test]
fn the_signature_key_is_looked_up_under_the_operations_revision() {
    // The key manager's lookup reads KeyInfo for the operation: it finds the
    // revision the operation pinned at its start, not whatever revision is
    // current when the lookup runs.
    own_process();
    let entry = crate::ffi::policy::verification().expect("the library policy compiles");
    // SAFETY: the library, a document, a manager and a context set up and
    // torn down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsReadMemory(
            TAMPERED.as_ptr().cast(),
            i32::try_from(TAMPERED.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let signature = xmlSecFindNode(
            xsDocGetRootElement(doc),
            c"Signature".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        let mngr = crate::ffi::keysmngr::xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(recording_lookup);
        let ctx = xmlSecDSigCtxCreate(mngr);
        assert_eq!(xmlSecDSigCtxVerify(ctx, signature), 0);
        assert_eq!(
            LOOKUP_PIN.load(std::sync::atomic::Ordering::Relaxed),
            Arc::as_ptr(&entry).addr()
        );
        xmlSecDSigCtxDestroy(ctx);
        crate::ffi::keysmngr::xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// How many times the detached resource was opened.
static DETACHED_OPENS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Octets of the detached resource already served by the current open.
static DETACHED_SENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// What the detached resource holds when first opened; a later open serves
/// [`DETACHED_LATER`].
const DETACHED_FIRST: &[u8] = b"the bytes that were signed";
const DETACHED_LATER: &[u8] = b"bytes served on a later open";

unsafe extern "C" fn detached_matches(_uri: *const std::ffi::c_char) -> std::ffi::c_int {
    1
}

unsafe extern "C" fn detached_open(_uri: *const std::ffi::c_char) -> *mut std::ffi::c_void {
    let opens = DETACHED_OPENS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    DETACHED_SENT.store(0, std::sync::atomic::Ordering::Relaxed);
    let content = if opens == 0 {
        DETACHED_FIRST
    } else {
        DETACHED_LATER
    };
    content.as_ptr().cast_mut().cast()
}

unsafe extern "C" fn detached_read(
    context: *mut std::ffi::c_void,
    buffer: *mut std::ffi::c_char,
    len: std::ffi::c_int,
) -> std::ffi::c_int {
    let served = if context.cast_const() == DETACHED_FIRST.as_ptr().cast() {
        DETACHED_FIRST
    } else {
        DETACHED_LATER
    };
    let sent = DETACHED_SENT.load(std::sync::atomic::Ordering::Relaxed);
    let rest = &served[sent..];
    let count = rest
        .len()
        .min(usize::try_from(len).expect("a non-negative length"));
    // SAFETY: the transform passes `len` writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(rest.as_ptr(), buffer.cast(), count) };
    DETACHED_SENT.store(sent + count, std::sync::atomic::Ordering::Relaxed);
    std::ffi::c_int::try_from(count).expect("at most `len` octets")
}

unsafe extern "C" fn detached_close(_context: *mut std::ffi::c_void) -> std::ffi::c_int {
    0
}

#[test]
fn a_forged_signature_opens_none_of_its_external_references() {
    // The SignatureValue is checked before any reference is dereferenced:
    // a forgery naming an external URI makes the caller's callbacks open
    // nothing, where libxmlsec1 reads every reference first.
    own_process();
    let document = TAMPERED.replace(
        "</SignedInfo>",
        concat!(
            "<Reference URI=\"test:detached\">",
            "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
            "<DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>",
            "</Reference></SignedInfo>"
        ),
    );
    let secret = b"secret-of-thirty-two-octets-long";
    // SAFETY: the library, a document, a key and a context set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        assert_eq!(
            crate::ffi::transforms::io::xmlSecIORegisterCallbacks(
                Some(detached_matches),
                Some(detached_open),
                Some(detached_read),
                Some(detached_close),
            ),
            0
        );
        let doc = xsReadMemory(
            document.as_ptr().cast(),
            i32::try_from(document.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let signature = xmlSecFindNode(
            xsDocGetRootElement(doc),
            c"Signature".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        let key = xmlSecKeyCreate();
        assert_eq!(
            xmlSecKeyDataBinRead(
                symkeys::hmac(),
                key.cast(),
                secret.as_ptr(),
                secret.len(),
                (&raw mut (*ctx).key_info_read_ctx).cast(),
            ),
            0
        );
        (*ctx).sign_key = key;
        (*ctx).enabled_reference_uris = 0xFFFF;
        assert_eq!(xmlSecDSigCtxVerify(ctx, signature), 0);
        assert_eq!((*ctx).status, STATUS_INVALID);
        assert_eq!((*ctx).failure_reason, FAILURE_SIGNATURE);
        assert_eq!(DETACHED_OPENS.load(std::sync::atomic::Ordering::Relaxed), 0);
        xmlSecDSigCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn a_stored_pre_digest_holds_the_bytes_that_were_signed() {
    // A detached reference is read once for signing; the kept pre-digest
    // buffer holds those bytes, not what a second read of the URI returns.
    own_process();
    let template = concat!(
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"test:detached\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/></Signature>"
    );
    let secret = b"secret-of-thirty-two-octets-long";
    // SAFETY: the library, a document, a key and a context set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        assert_eq!(
            crate::ffi::transforms::io::xmlSecIORegisterCallbacks(
                Some(detached_matches),
                Some(detached_open),
                Some(detached_read),
                Some(detached_close),
            ),
            0
        );
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            i32::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        let key = xmlSecKeyCreate();
        assert_eq!(
            xmlSecKeyDataBinRead(
                symkeys::hmac(),
                key.cast(),
                secret.as_ptr(),
                secret.len(),
                (&raw mut (*ctx).key_info_read_ctx).cast(),
            ),
            0
        );
        (*ctx).sign_key = key;
        (*ctx).enabled_reference_uris = 0xFFFF;
        (*ctx).flags |= FLAGS_STORE_SIGNEDINFO_REFERENCES;
        assert_eq!(xmlSecDSigCtxSign(ctx, xsDocGetRootElement(doc)), 0);
        let reference = xmlSecPtrListGetItem(&raw mut (*ctx).signed_info_references, 0)
            .cast::<XmlSecDSigReferenceCtx>();
        let kept = crate::ffi::transforms::builtin::xmlSecTransformMemBufGetBuffer(
            (*reference).pre_digest_mem_buf_method,
        );
        assert_eq!(
            std::slice::from_raw_parts(
                crate::ffi::buffer::xmlSecBufferGetData(kept),
                crate::ffi::buffer::xmlSecBufferGetSize(kept),
            ),
            DETACHED_FIRST
        );
        assert_eq!(DETACHED_OPENS.load(std::sync::atomic::Ordering::Relaxed), 1);
        xmlSecDSigCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn stored_buffers_come_from_the_signing_and_spend_nothing_beyond_it() {
    // The Base64 output limit is cumulative for one operation. With the
    // storage flags set, the pre-digest bytes and the canonical SignedInfo
    // come from the core's one run under that limit, decoded to exactly
    // its size here; the reference's own chain does not run again on a
    // fresh allowance and decode them a second time.
    own_process();
    // `MDEyMzQ1Njc4OWFiY2RlZg==` decodes to sixteen octets.
    let template = concat!(
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"#encoded\"><Transforms>",
        "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#base64\"/></Transforms>",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/>",
        "<Object Id=\"encoded\">MDEyMzQ1Njc4OWFiY2RlZg==</Object></Signature>"
    );
    let secret = b"secret-of-thirty-two-octets-long";
    crate::ffi::policy::republish(
        |_| {},
        |signing| signing.resources.max_base64_transform_output_bytes = 16,
    )
    .expect("the library policy compiles");
    // SAFETY: the library, a document, a key and a context set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            i32::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ids = [c"Id".as_ptr().cast::<u8>(), std::ptr::null()];
        xmlSecAddIDs(doc, std::ptr::null_mut(), ids.as_ptr());
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        let key = xmlSecKeyCreate();
        assert_eq!(
            xmlSecKeyDataBinRead(
                symkeys::hmac(),
                key.cast(),
                secret.as_ptr(),
                secret.len(),
                (&raw mut (*ctx).key_info_read_ctx).cast(),
            ),
            0
        );
        (*ctx).sign_key = key;
        (*ctx).flags |= FLAGS_STORE_SIGNATURE | FLAGS_STORE_SIGNEDINFO_REFERENCES;
        assert_eq!(xmlSecDSigCtxSign(ctx, xsDocGetRootElement(doc)), 0);
        let reference = xmlSecPtrListGetItem(&raw mut (*ctx).signed_info_references, 0)
            .cast::<XmlSecDSigReferenceCtx>();
        let kept = crate::ffi::transforms::builtin::xmlSecTransformMemBufGetBuffer(
            (*reference).pre_digest_mem_buf_method,
        );
        assert_eq!(
            std::slice::from_raw_parts(
                crate::ffi::buffer::xmlSecBufferGetData(kept),
                crate::ffi::buffer::xmlSecBufferGetSize(kept),
            ),
            b"0123456789abcdef"
        );
        let signed_info = crate::ffi::transforms::builtin::xmlSecTransformMemBufGetBuffer(
            (*ctx).pre_sign_mem_buf_method,
        );
        assert!(crate::ffi::buffer::xmlSecBufferGetSize(signed_info) > 16);
        // Nothing was decoded outside the operation's own count.
        assert_eq!(
            crate::ffi::transforms::ctx::run_spent(&raw mut (*reference).transform_ctx)
                .base64_output,
            0
        );
        xmlSecDSigCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn storing_signed_info_alone_keeps_no_reference_bytes() {
    // FLAGS_STORE_SIGNATURE keeps the canonical SignedInfo only: a detached
    // reference's bytes are not retained, so they do not count against the
    // canonicalized-bytes limit, while asking for them does count.
    own_process();
    let template = concat!(
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"test:detached\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/></Signature>"
    );
    let limit = |bytes: usize| {
        crate::ffi::policy::republish(
            |verification| verification.resources.max_canonicalized_bytes = bytes,
            |signing| signing.resources.max_canonicalized_bytes = bytes,
        )
        .expect("the library policy compiles");
    };
    // SAFETY: the library, documents, keys and contexts set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        serve_constant();
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            i32::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let run = |sign: bool, flags: std::ffi::c_uint| {
            let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
            (*ctx).sign_key = hmac_key(ctx);
            (*ctx).enabled_reference_uris = 0xFFFF;
            (*ctx).flags |= flags;
            let status = if sign {
                xmlSecDSigCtxSign(ctx, xsDocGetRootElement(doc))
            } else {
                xmlSecDSigCtxVerify(ctx, xsDocGetRootElement(doc))
            };
            let kept = crate::ffi::transforms::builtin::xmlSecTransformMemBufGetBuffer(
                (*ctx).pre_sign_mem_buf_method,
            );
            let size = crate::ffi::buffer::xmlSecBufferGetSize(kept);
            xmlSecDSigCtxDestroy(ctx);
            (status, size)
        };
        let (status, signed_info) = run(true, FLAGS_STORE_SIGNATURE);
        assert_eq!(status, 0);
        // The SignedInfo fits; it and the reference's bytes do not.
        limit(signed_info + CONSTANT.len() - 1);
        for sign in [true, false] {
            assert_eq!(run(sign, FLAGS_STORE_SIGNATURE).0, 0, "sign: {sign}");
            assert_eq!(
                run(
                    sign,
                    FLAGS_STORE_SIGNATURE | FLAGS_STORE_SIGNEDINFO_REFERENCES
                )
                .0,
                -1,
                "sign: {sign}, the reference's bytes kept too"
            );
        }
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// A pre-execute callback that appends a Base64 decoder to the chain.
unsafe extern "C" fn appending(
    ctx: *mut crate::ffi::transforms::XmlSecTransformCtx,
) -> std::ffi::c_int {
    // SAFETY: the operation's live chain.
    let added = unsafe {
        crate::ffi::transforms::ctx::xmlSecTransformCtxCreateAndAppend(
            ctx,
            crate::ffi::transforms::builtin::base64(),
        )
    };
    if added.is_null() { -1 } else { 0 }
}

/// A pre-execute callback that moves the first transform's `here` node to
/// another live node of the document.
unsafe extern "C" fn moving_here(
    ctx: *mut crate::ffi::transforms::XmlSecTransformCtx,
) -> std::ffi::c_int {
    // SAFETY: the operation's live chain and nodes.
    unsafe {
        let Some(first) = (*ctx).first.as_mut() else {
            return -1;
        };
        first.here_node = crate::ffi::tree::nodes::parent(first.here_node);
    }
    0
}

#[test]
fn a_chain_changed_by_a_pre_execute_callback_fails_the_operation() {
    // The core runs a Reference's transforms from the document, so a
    // callback inserting a transform into the C chain, or pointing one at
    // another `here` node, would be lost: the operation fails instead of
    // signing data the chain no longer describes.
    own_process();
    let template = concat!(
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"#o\"><Transforms>",
        "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms>",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/>",
        "<Object Id=\"o\">c2lnbmVk</Object></Signature>"
    );
    // SAFETY: the library, a document, a key and a context set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        for (callback, signed) in [
            (None, true),
            (Some(appending as _), false),
            (Some(moving_here as _), false),
        ] {
            let doc = xsReadMemory(
                template.as_ptr().cast(),
                i32::try_from(template.len()).expect("a short document"),
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
            assert!(!doc.is_null());
            let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
            (*ctx).sign_key = hmac_key(ctx);
            (*ctx).reference_pre_execute_callback = callback;
            assert_eq!(
                xmlSecDSigCtxSign(ctx, xsDocGetRootElement(doc)) == 0,
                signed,
                "callback changing the chain: {}",
                !signed
            );
            xmlSecDSigCtxDestroy(ctx);
            xsFreeDoc(doc);
        }
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// The reasons reported during [`reported`], in order.
static REASONS: std::sync::Mutex<Vec<std::ffi::c_int>> = std::sync::Mutex::new(Vec::new());

unsafe extern "C" fn record(
    _file: *const std::ffi::c_char,
    _line: std::ffi::c_int,
    func: *const std::ffi::c_char,
    _object: *const std::ffi::c_char,
    _subject: *const std::ffi::c_char,
    reason: std::ffi::c_int,
    message: *const std::ffi::c_char,
) {
    let text = |text: *const std::ffi::c_char| {
        // SAFETY: the library passes null or NUL-terminated strings.
        unsafe { text.as_ref() }.map_or_else(String::new, |_| {
            // SAFETY: as above.
            unsafe { std::ffi::CStr::from_ptr(text) }
                .to_string_lossy()
                .into_owned()
        })
    };
    // Shown with a failing assertion's output.
    eprintln!("{}: {reason}: {}", text(func), text(message));
    REASONS.lock().expect("one test thread").push(reason);
}

/// `run`'s result and the reasons reported while it ran.
fn reported<T>(run: impl FnOnce() -> T) -> (T, Vec<std::ffi::c_int>) {
    REASONS.lock().expect("one test thread").clear();
    // SAFETY: the callback has the callback's signature.
    unsafe {
        crate::ffi::errors::xmlSecErrorsSetCallback(Some(
            record as crate::ffi::errors::ErrorsCallback,
        ));
    }
    let result = run();
    // SAFETY: restores the default callback.
    unsafe { crate::ffi::errors::xmlSecErrorsSetCallback(None) };
    (result, REASONS.lock().expect("one test thread").clone())
}

#[test]
fn the_legacy_relationship_flag_refuses_a_relationship_reference() {
    // The core runs the Relationship transform as ISO/IEC 29500-2 specifies
    // it, not libxmlsec1's historical variant: a context asking for that
    // variant over a Reference that has the transform is refused rather than
    // signed in the other one. Without the flag the same template signs.
    own_process();
    let template = concat!(
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">",
        "<Relationship Id=\"rId1\" Type=\"urn:t:a\" Target=\"a.xml\"/>",
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"\"><Transforms>",
        "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>",
        "<Transform Algorithm=\"http://schemas.openxmlformats.org/package/2006/RelationshipTransform\">",
        "<m:RelationshipReference ",
        "xmlns:m=\"http://schemas.openxmlformats.org/package/2006/digital-signature\" ",
        "SourceId=\"rId1\"/></Transform>",
        "<Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>",
        "</Transforms>",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/>",
        "</Signature></Relationships>"
    );
    // SAFETY: the library, documents, keys and contexts set up and torn down
    // here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        for (flags, signed) in [(0, true), (FLAGS_RELATIONSHIP_LEGACY, false)] {
            let doc = xsReadMemory(
                template.as_ptr().cast(),
                i32::try_from(template.len()).expect("a short document"),
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
            assert!(!doc.is_null());
            let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
            (*ctx).sign_key = hmac_key(ctx);
            (*ctx).flags |= flags;
            let signature = xmlSecFindNode(
                xsDocGetRootElement(doc),
                c"Signature".as_ptr().cast(),
                c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
            );
            let (status, reasons) = reported(|| xmlSecDSigCtxSign(ctx, signature));
            if signed {
                assert_eq!(status, 0, "{reasons:?}");
            } else {
                assert_eq!(status, -1, "{reasons:?}");
                assert!(
                    reasons.contains(&crate::ffi::errors::R_NOT_IMPLEMENTED),
                    "{reasons:?}"
                );
            }
            xmlSecDSigCtxDestroy(ctx);
            xsFreeDoc(doc);
        }
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn a_fragment_of_an_external_reference_is_refused_before_it_is_read() {
    // An external resource reaches the core as octets, which select no
    // fragment: a Reference naming part of one fails the operation instead
    // of signing the whole resource, and nothing is read for it.
    own_process();
    let template = concat!(
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"test:detached#chapter1\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/></Signature>"
    );
    // SAFETY: the library, a document, a key and a context set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        serve_constant();
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            i32::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).sign_key = hmac_key(ctx);
        (*ctx).enabled_reference_uris = 0xFFFF;
        assert_eq!(xmlSecDSigCtxSign(ctx, xsDocGetRootElement(doc)), -1);
        assert_eq!(
            CONSTANT_OPENS.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "nothing was read for the fragment"
        );
        xmlSecDSigCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// What the constant resource serves on every open.
const CONSTANT: &[u8] = b"one payload under every base";
/// Octets of [`CONSTANT`] already served by the current open.
static CONSTANT_SENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// How many times the constant resource was opened.
static CONSTANT_OPENS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The URIs the constant resource was opened under, in order.
static CONSTANT_OPENED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

unsafe extern "C" fn constant_open(uri: *const std::ffi::c_char) -> *mut std::ffi::c_void {
    // SAFETY: the transform passes a NUL-terminated URI.
    let uri = unsafe { std::ffi::CStr::from_ptr(uri) }
        .to_string_lossy()
        .into_owned();
    CONSTANT_OPENED.lock().expect("opened URIs").push(uri);
    CONSTANT_OPENS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    CONSTANT_SENT.store(0, std::sync::atomic::Ordering::Relaxed);
    CONSTANT.as_ptr().cast_mut().cast()
}

unsafe extern "C" fn constant_read(
    _context: *mut std::ffi::c_void,
    buffer: *mut std::ffi::c_char,
    len: std::ffi::c_int,
) -> std::ffi::c_int {
    let sent = CONSTANT_SENT.load(std::sync::atomic::Ordering::Relaxed);
    let rest = &CONSTANT[sent..];
    let count = rest
        .len()
        .min(usize::try_from(len).expect("a non-negative length"));
    // SAFETY: the transform passes `len` writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(rest.as_ptr(), buffer.cast(), count) };
    CONSTANT_SENT.store(sent + count, std::sync::atomic::Ordering::Relaxed);
    std::ffi::c_int::try_from(count).expect("at most `len` octets")
}

/// Registers the constant resource as the input callbacks of every URI.
///
/// # Safety
/// The library is initialized.
unsafe fn serve_constant() {
    // SAFETY: by the caller's contract.
    let registered = unsafe {
        crate::ffi::transforms::io::xmlSecIORegisterCallbacks(
            Some(detached_matches),
            Some(constant_open),
            Some(constant_read),
            Some(detached_close),
        )
    };
    assert_eq!(registered, 0);
}

/// The HMAC key of [`TAMPERED`], read for `ctx`.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn hmac_key(ctx: *mut XmlSecDSigCtx) -> *mut crate::ffi::keys::XmlSecKey {
    let secret = b"secret-of-thirty-two-octets-long";
    // SAFETY: a key created here, read through the context's read context.
    unsafe {
        let key = xmlSecKeyCreate();
        assert_eq!(
            xmlSecKeyDataBinRead(
                symkeys::hmac(),
                key.cast(),
                secret.as_ptr(),
                secret.len(),
                (&raw mut (*ctx).key_info_read_ctx).cast(),
            ),
            0
        );
        key
    }
}

#[test]
fn a_reference_context_holds_its_digest_after_the_operation() {
    // As libxmlsec1 leaves them: after signing a reference's result is the
    // Base64 digest written into its DigestValue; after verifying there is
    // none, as libxmlsec1's checking digest transform outputs nothing.
    own_process();
    let template = concat!(
        "<Envelope xmlns=\"urn:envelope\"><Data Id=\"data\">payload</Data>",
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"#data\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/>",
        "</Signature></Envelope>"
    );
    let result_of = |ctx: *mut XmlSecDSigCtx| {
        // SAFETY: the context's first SignedInfo reference and its buffer.
        unsafe {
            let reference = xmlSecPtrListGetItem(&raw mut (*ctx).signed_info_references, 0)
                .cast::<XmlSecDSigReferenceCtx>();
            let result = (*reference).result;
            assert!(!result.is_null(), "the reference holds its digest");
            std::slice::from_raw_parts(
                crate::ffi::buffer::xmlSecBufferGetData(result),
                crate::ffi::buffer::xmlSecBufferGetSize(result),
            )
            .to_vec()
        }
    };
    // SAFETY: the library, a document, keys and contexts set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            i32::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ids = [c"Id".as_ptr().cast::<u8>(), std::ptr::null()];
        xmlSecAddIDs(doc, std::ptr::null_mut(), ids.as_ptr());
        let signature = xmlSecFindNode(
            xsDocGetRootElement(doc),
            c"Signature".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).sign_key = hmac_key(ctx);
        assert_eq!(xmlSecDSigCtxSign(ctx, signature), 0);
        let digest_value = xmlSecFindNode(
            signature,
            c"DigestValue".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        let written = crate::ffi::tree::nodes::content(digest_value).expect("a written digest");
        assert_eq!(result_of(ctx), written.as_bytes());
        xmlSecDSigCtxDestroy(ctx);

        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).sign_key = hmac_key(ctx);
        assert_eq!(xmlSecDSigCtxVerify(ctx, signature), 0);
        assert_eq!((*ctx).status, STATUS_SUCCEEDED);
        let reference = xmlSecPtrListGetItem(&raw mut (*ctx).signed_info_references, 0)
            .cast::<XmlSecDSigReferenceCtx>();
        assert!(
            (*reference).result.is_null(),
            "a verified reference has no result"
        );
        xmlSecDSigCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn one_uri_under_two_bases_names_two_resources() {
    // `payload.bin` resolves against each Reference's own XML Base (RFC 3986
    // section 5.2): the two references name two resources, each read and
    // signed, and both verify. Each is opened under the URI its element
    // writes, as libxmlsec1 opens it, once per reference and operation.
    own_process();
    let template = concat!(
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference xml:base=\"test:one/\" URI=\"payload.bin\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference>",
        "<Reference xml:base=\"test:two/\" URI=\"payload.bin\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/></Signature>"
    );
    // SAFETY: the library, a document, keys and contexts set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        serve_constant();
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            i32::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).sign_key = hmac_key(ctx);
        (*ctx).enabled_reference_uris = 0xFFFF;
        assert_eq!(xmlSecDSigCtxSign(ctx, xsDocGetRootElement(doc)), 0);
        xmlSecDSigCtxDestroy(ctx);

        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).sign_key = hmac_key(ctx);
        (*ctx).enabled_reference_uris = 0xFFFF;
        assert_eq!(xmlSecDSigCtxVerify(ctx, xsDocGetRootElement(doc)), 0);
        assert_eq!((*ctx).status, STATUS_SUCCEEDED);
        xmlSecDSigCtxDestroy(ctx);
        assert_eq!(
            *CONSTANT_OPENED.lock().expect("opened URIs"),
            ["payload.bin"; 4],
            "two opens when signing, two when verifying"
        );
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// Octets a key lookup charges as read from an external key reference.
const KEY_READ_OCTETS: usize = 16;

/// A key manager's lookup that charges [`KEY_READ_OCTETS`] to the
/// operation's external-resource allowance, as a `KeyInfo` read dereferencing
/// an external key reference does, and hands back the HMAC key of
/// [`TAMPERED`].
unsafe extern "C" fn charging_lookup(
    node: *mut XmlNode,
    ctx: *mut crate::ffi::keyinfo::XmlSecKeyInfoCtx,
) -> *mut crate::ffi::keys::XmlSecKey {
    // SAFETY: the read context the operation passes.
    if let Some(spent) = unsafe { crate::ffi::policy::spent((*ctx).reserved0) } {
        spent.set(crate::ffi::policy::Spent {
            external_resources: KEY_READ_OCTETS,
            ..crate::ffi::policy::Spent::default()
        });
    }
    // SAFETY: by this callback's contract.
    unsafe { recording_lookup(node, ctx) }
}

#[test]
fn a_key_read_and_the_references_share_one_allowance() {
    // The KeyInfo read and the signature's references belong to one
    // operation: what the key read spent counts against the references'
    // reads, so the two together cannot pass the aggregate limit.
    own_process();
    let template = concat!(
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"test:payload\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/></Signature>"
    );
    let total = KEY_READ_OCTETS + CONSTANT.len();
    // SAFETY: the library, documents, a manager and contexts set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        serve_constant();
        let mngr = crate::ffi::keysmngr::xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(charging_lookup);
        // One octet short fails; the exact total signs, so the refusal is the
        // shared allowance and nothing is counted twice.
        for (limit, signed) in [(total - 1, -1), (total, 0)] {
            crate::ffi::policy::republish(
                |_| {},
                |signing| {
                    signing.resources.max_external_resource_bytes = CONSTANT.len();
                    signing.resources.max_external_resource_total_bytes = limit;
                },
            )
            .expect("the library policy compiles");
            let doc = xsReadMemory(
                template.as_ptr().cast(),
                i32::try_from(template.len()).expect("a short document"),
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
            assert!(!doc.is_null());
            let ctx = xmlSecDSigCtxCreate(mngr);
            (*ctx).enabled_reference_uris = 0xFFFF;
            assert_eq!(
                xmlSecDSigCtxSign(ctx, xsDocGetRootElement(doc)),
                signed,
                "{total} octets under {limit}"
            );
            xmlSecDSigCtxDestroy(ctx);
            xsFreeDoc(doc);
        }
        crate::ffi::keysmngr::xmlSecKeysMngrDestroy(mngr);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn a_key_read_past_the_operations_limit_fails_the_signing() {
    // What the key read spent is checked against the signing's own aggregate
    // limit even when every reference is in the document: no later read
    // would check it.
    own_process();
    let template = concat!(
        "<Envelope xmlns=\"urn:envelope\"><Data Id=\"data\">payload</Data>",
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"#data\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/>",
        "</Signature></Envelope>"
    );
    // SAFETY: the library, documents, a manager and contexts set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let mngr = crate::ffi::keysmngr::xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(charging_lookup);
        for (limit, signed) in [(KEY_READ_OCTETS - 1, -1), (KEY_READ_OCTETS, 0)] {
            crate::ffi::policy::republish(
                |_| {},
                |signing| signing.resources.max_external_resource_total_bytes = limit,
            )
            .expect("the library policy compiles");
            let doc = xsReadMemory(
                template.as_ptr().cast(),
                i32::try_from(template.len()).expect("a short document"),
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
            assert!(!doc.is_null());
            let ids = [c"Id".as_ptr().cast::<u8>(), std::ptr::null()];
            xmlSecAddIDs(doc, std::ptr::null_mut(), ids.as_ptr());
            let signature = xmlSecFindNode(
                xsDocGetRootElement(doc),
                c"Signature".as_ptr().cast(),
                c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
            );
            let ctx = xmlSecDSigCtxCreate(mngr);
            assert_eq!(xmlSecDSigCtxSign(ctx, signature), signed, "under {limit}");
            xmlSecDSigCtxDestroy(ctx);
            xsFreeDoc(doc);
        }
        crate::ffi::keysmngr::xmlSecKeysMngrDestroy(mngr);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// A key manager's lookup whose read had a resource refused by a limit, as a
/// `KeyInfo` read refused an external key reference, and that still hands
/// back the HMAC key of [`TAMPERED`].
unsafe extern "C" fn refused_lookup(
    node: *mut XmlNode,
    ctx: *mut crate::ffi::keyinfo::XmlSecKeyInfoCtx,
) -> *mut crate::ffi::keys::XmlSecKey {
    // SAFETY: the read context the operation passes.
    if let Some(spent) = unsafe { crate::ffi::policy::spent((*ctx).reserved0) } {
        spent.set(crate::ffi::policy::Spent {
            refused_by: Some(crate::ffi::transforms::ctx::Limit {
                name: "max_external_resource_total_bytes",
                max: 0,
            }),
            ..spent.get()
        });
    }
    // SAFETY: by this callback's contract.
    unsafe { recording_lookup(node, ctx) }
}

#[test]
fn a_key_read_refused_by_a_limit_fails_the_operation() {
    // A resource limit that refused a read of the KeyInfo ends the operation
    // even when the key it looks up is found and every reference is in the
    // document, so no later read would see the refusal.
    own_process();
    let template = concat!(
        "<Envelope xmlns=\"urn:envelope\"><Data Id=\"data\">payload</Data>",
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"#data\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/>",
        "</Signature></Envelope>"
    );
    // SAFETY: the library, documents, a manager and contexts set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        crate::ffi::policy::republish(|_| {}, |_| {}).expect("the library policy compiles");
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            i32::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ids = [c"Id".as_ptr().cast::<u8>(), std::ptr::null()];
        xmlSecAddIDs(doc, std::ptr::null_mut(), ids.as_ptr());
        let signature = xmlSecFindNode(
            xsDocGetRootElement(doc),
            c"Signature".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        let mngr = crate::ffi::keysmngr::xmlSecKeysMngrCreate();
        // Control: the same lookup without the refusal signs and verifies.
        (*mngr).get_key = Some(recording_lookup);
        let ctx = xmlSecDSigCtxCreate(mngr);
        assert_eq!(xmlSecDSigCtxSign(ctx, signature), 0);
        xmlSecDSigCtxDestroy(ctx);
        (*mngr).get_key = Some(refused_lookup);
        let ctx = xmlSecDSigCtxCreate(mngr);
        assert_eq!(xmlSecDSigCtxSign(ctx, signature), -1, "signing");
        xmlSecDSigCtxDestroy(ctx);
        let ctx = xmlSecDSigCtxCreate(mngr);
        assert_eq!(xmlSecDSigCtxVerify(ctx, signature), -1, "verification");
        assert_ne!((*ctx).status, STATUS_SUCCEEDED);
        xmlSecDSigCtxDestroy(ctx);
        crate::ffi::keysmngr::xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// Octets a key lookup charges as decoded by a Base64 transform of its read.
const KEY_READ_DECODED: usize = 16;

/// A key manager's lookup that charges [`KEY_READ_DECODED`] to the
/// operation's Base64 output allowance, as a `KeyInfo` read decoding an
/// `EncryptedKey` does, and hands back the HMAC key of [`TAMPERED`].
unsafe extern "C" fn decoding_lookup(
    node: *mut XmlNode,
    ctx: *mut crate::ffi::keyinfo::XmlSecKeyInfoCtx,
) -> *mut crate::ffi::keys::XmlSecKey {
    // SAFETY: the read context the operation passes.
    if let Some(spent) = unsafe { crate::ffi::policy::spent((*ctx).reserved0) } {
        spent.set(crate::ffi::policy::Spent {
            base64_output: KEY_READ_DECODED,
            ..spent.get()
        });
    }
    // SAFETY: by this callback's contract.
    unsafe { recording_lookup(node, ctx) }
}

#[test]
fn a_key_read_and_the_signing_share_one_base64_allowance() {
    // The Base64 output limit is cumulative per operation: what the key read
    // decoded counts against the Base64 transform the core runs for a
    // reference, rather than the core starting a fresh allowance.
    own_process();
    // `MDEyMzQ1Njc4OWFiY2RlZg==` decodes to sixteen octets.
    let template = concat!(
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"#encoded\"><Transforms>",
        "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#base64\"/></Transforms>",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/>",
        "<Object Id=\"encoded\">MDEyMzQ1Njc4OWFiY2RlZg==</Object></Signature>"
    );
    let decoded = 16;
    // SAFETY: the library, documents, a manager and contexts set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let mngr = crate::ffi::keysmngr::xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(decoding_lookup);
        let total = KEY_READ_DECODED + decoded;
        for (limit, signed) in [(total - 1, -1), (total, 0)] {
            crate::ffi::policy::republish(
                |_| {},
                |signing| signing.resources.max_base64_transform_output_bytes = limit,
            )
            .expect("the library policy compiles");
            let doc = xsReadMemory(
                template.as_ptr().cast(),
                i32::try_from(template.len()).expect("a short document"),
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
            assert!(!doc.is_null());
            let ids = [c"Id".as_ptr().cast::<u8>(), std::ptr::null()];
            xmlSecAddIDs(doc, std::ptr::null_mut(), ids.as_ptr());
            let ctx = xmlSecDSigCtxCreate(mngr);
            assert_eq!(
                xmlSecDSigCtxSign(ctx, xsDocGetRootElement(doc)),
                signed,
                "{total} octets decoded under {limit}"
            );
            xmlSecDSigCtxDestroy(ctx);
            xsFreeDoc(doc);
        }
        crate::ffi::keysmngr::xmlSecKeysMngrDestroy(mngr);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn an_ignored_manifest_reads_none_of_its_resources() {
    // The operation's policy ignores Manifests: their references are never
    // dereferenced, so an authentic signature signs and verifies while the
    // caller's callbacks open nothing its Manifest names.
    own_process();
    let template = concat!(
        "<Envelope xmlns=\"urn:envelope\"><Data Id=\"data\">payload</Data>",
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"#data\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/>",
        "<Object><Manifest><Reference URI=\"test:manifest\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue>AAAA</DigestValue></Reference></Manifest></Object>",
        "</Signature></Envelope>"
    );
    crate::ffi::policy::republish(
        |verification| {
            verification.manifest_processing = xml_sec::policy::ManifestProcessing::Ignore;
        },
        |signing| signing.manifest_processing = xml_sec::policy::ManifestProcessing::Ignore,
    )
    .expect("the library policy compiles");
    // SAFETY: the library, a document, keys and contexts set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        serve_constant();
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            i32::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ids = [c"Id".as_ptr().cast::<u8>(), std::ptr::null()];
        xmlSecAddIDs(doc, std::ptr::null_mut(), ids.as_ptr());
        let signature = xmlSecFindNode(
            xsDocGetRootElement(doc),
            c"Signature".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        // The caller admits every reference URI type, so only the policy
        // decides what is read.
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).sign_key = hmac_key(ctx);
        (*ctx).enabled_reference_uris = 0xFFFF;
        assert_eq!(xmlSecDSigCtxSign(ctx, signature), 0);
        xmlSecDSigCtxDestroy(ctx);
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).sign_key = hmac_key(ctx);
        (*ctx).enabled_reference_uris = 0xFFFF;
        assert_eq!(xmlSecDSigCtxVerify(ctx, signature), 0);
        assert_eq!((*ctx).status, STATUS_SUCCEEDED);
        assert_eq!(CONSTANT_OPENS.load(std::sync::atomic::Ordering::Relaxed), 0);
        xmlSecDSigCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn a_manifest_the_policy_ignores_is_not_read() {
    // The policy ignores Manifests while the context's flag is unset: no
    // Manifest reference is parsed, so one with a DigestMethod nothing
    // implements does not fail an operation that never processes it.
    own_process();
    let template = concat!(
        "<Envelope xmlns=\"urn:envelope\"><Data Id=\"data\">payload</Data>",
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"#data\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/>",
        "<Object><Manifest><Reference URI=\"#data\">",
        "<DigestMethod Algorithm=\"urn:unimplemented-digest\"/>",
        "<DigestValue>AAAA</DigestValue></Reference></Manifest></Object>",
        "</Signature></Envelope>"
    );
    crate::ffi::policy::republish(
        |verification| {
            verification.manifest_processing = xml_sec::policy::ManifestProcessing::Ignore;
        },
        |signing| signing.manifest_processing = xml_sec::policy::ManifestProcessing::Ignore,
    )
    .expect("the library policy compiles");
    // SAFETY: the library, a document, keys and contexts set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            i32::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ids = [c"Id".as_ptr().cast::<u8>(), std::ptr::null()];
        xmlSecAddIDs(doc, std::ptr::null_mut(), ids.as_ptr());
        let signature = xmlSecFindNode(
            xsDocGetRootElement(doc),
            c"Signature".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).sign_key = hmac_key(ctx);
        assert_eq!(xmlSecDSigCtxSign(ctx, signature), 0);
        assert_eq!(xmlSecPtrListGetSize(&raw mut (*ctx).manifest_references), 0);
        xmlSecDSigCtxDestroy(ctx);
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).sign_key = hmac_key(ctx);
        assert_eq!(xmlSecDSigCtxVerify(ctx, signature), 0);
        assert_eq!((*ctx).status, STATUS_SUCCEEDED);
        assert_eq!(xmlSecPtrListGetSize(&raw mut (*ctx).manifest_references), 0);
        xmlSecDSigCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn a_resource_past_its_limit_fails_the_verification() {
    // A resource read on demand passes the policy's aggregate limit: the
    // core treats an exhausted budget as a refusal of the whole operation,
    // so the call fails rather than completing with an invalid status.
    own_process();
    let template = concat!(
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"test:payload\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/></Signature>"
    );
    // SAFETY: the library, a document, keys and contexts set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        serve_constant();
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            i32::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).sign_key = hmac_key(ctx);
        (*ctx).enabled_reference_uris = 0xFFFF;
        assert_eq!(xmlSecDSigCtxSign(ctx, xsDocGetRootElement(doc)), 0);
        xmlSecDSigCtxDestroy(ctx);
        crate::ffi::policy::republish(
            |verification| {
                verification.resources.max_external_resource_total_bytes = CONSTANT.len() - 1;
            },
            |_| {},
        )
        .expect("the library policy compiles");
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).sign_key = hmac_key(ctx);
        (*ctx).enabled_reference_uris = 0xFFFF;
        assert_eq!(xmlSecDSigCtxVerify(ctx, xsDocGetRootElement(doc)), -1);
        assert_eq!((*ctx).status, STATUS_UNKNOWN);
        xmlSecDSigCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// A key manager's lookup that republishes snapshots refusing any
/// canonicalization longer than sixteen octets while it answers, then hands
/// back the HMAC key of [`TAMPERED`].
unsafe extern "C" fn narrowing_lookup(
    node: *mut XmlNode,
    ctx: *mut crate::ffi::keyinfo::XmlSecKeyInfoCtx,
) -> *mut crate::ffi::keys::XmlSecKey {
    crate::ffi::policy::republish(
        |verification| verification.resources.max_canonicalized_bytes = 16,
        |signing| signing.resources.max_canonicalized_bytes = 16,
    )
    .expect("the library policy compiles");
    // SAFETY: by this callback's contract.
    unsafe { recording_lookup(node, ctx) }
}

#[test]
fn the_kept_signed_info_is_canonicalized_under_the_operations_revision() {
    // A republish while the key is looked up takes effect for later
    // operations: this signing keeps the revision it began with, for the
    // core's run and for the SignedInfo it keeps for the caller alike.
    own_process();
    let template = concat!(
        "<Envelope xmlns=\"urn:envelope\"><Data Id=\"data\">payload</Data>",
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"#data\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/>",
        "</Signature></Envelope>"
    );
    // SAFETY: the library, a document, a manager and a context set up and
    // torn down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            i32::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ids = [c"Id".as_ptr().cast::<u8>(), std::ptr::null()];
        xmlSecAddIDs(doc, std::ptr::null_mut(), ids.as_ptr());
        let signature = xmlSecFindNode(
            xsDocGetRootElement(doc),
            c"Signature".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        let mngr = crate::ffi::keysmngr::xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(narrowing_lookup);
        let ctx = xmlSecDSigCtxCreate(mngr);
        (*ctx).flags |= FLAGS_STORE_SIGNATURE | FLAGS_STORE_SIGNEDINFO_REFERENCES;
        assert_eq!(xmlSecDSigCtxSign(ctx, signature), 0);
        let kept = crate::ffi::transforms::builtin::xmlSecTransformMemBufGetBuffer(
            (*ctx).pre_sign_mem_buf_method,
        );
        assert!(
            crate::ffi::buffer::xmlSecBufferGetSize(kept) > 16,
            "the whole SignedInfo was kept"
        );
        xmlSecDSigCtxDestroy(ctx);
        crate::ffi::keysmngr::xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// A key manager's lookup that republishes snapshots admitting only
/// SHA-512 digests while it answers, then hands back the HMAC key of
/// [`TAMPERED`].
unsafe extern "C" fn digest_narrowing_lookup(
    node: *mut XmlNode,
    ctx: *mut crate::ffi::keyinfo::XmlSecKeyInfoCtx,
) -> *mut crate::ffi::keys::XmlSecKey {
    let only_sha512 = || {
        Some(std::collections::BTreeSet::from([
            xml_sec::xmldsig::DigestAlgorithm::Sha512,
        ]))
    };
    crate::ffi::policy::republish(
        |verification| verification.digest_algorithms = only_sha512(),
        |signing| signing.digest_algorithms = only_sha512(),
    )
    .expect("the library policy compiles");
    // SAFETY: by this callback's contract.
    unsafe { recording_lookup(node, ctx) }
}

#[test]
fn references_read_after_the_key_keep_the_operations_revision() {
    // The references are read after the key is looked up; a republish during
    // that lookup, here one refusing their SHA-256 digest, takes effect for
    // later operations, not for this one's references.
    own_process();
    let template = concat!(
        "<Envelope xmlns=\"urn:envelope\"><Data Id=\"data\">payload</Data>",
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>",
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
        "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        "<Reference URI=\"#data\">",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue/></Reference></SignedInfo><SignatureValue/>",
        "</Signature></Envelope>"
    );
    // SAFETY: the library, a document, a manager and a context set up and
    // torn down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsReadMemory(
            template.as_ptr().cast(),
            i32::try_from(template.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ids = [c"Id".as_ptr().cast::<u8>(), std::ptr::null()];
        xmlSecAddIDs(doc, std::ptr::null_mut(), ids.as_ptr());
        let signature = xmlSecFindNode(
            xsDocGetRootElement(doc),
            c"Signature".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        let mngr = crate::ffi::keysmngr::xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(digest_narrowing_lookup);
        let ctx = xmlSecDSigCtxCreate(mngr);
        assert_eq!(xmlSecDSigCtxSign(ctx, signature), 0);
        xmlSecDSigCtxDestroy(ctx);
        crate::ffi::keysmngr::xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn references_beyond_the_policy_limit_are_refused_before_their_contexts_exist() {
    // An untrusted signature names more references than the operation
    // admits: the read stops at the limit instead of building a context and
    // a transform chain for every one and leaving the refusal to the core.
    own_process();
    let reference = concat!(
        "<Reference URI=\"#data\"><Transforms>",
        "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms>",
        "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
        "<DigestValue>AAAA</DigestValue></Reference>"
    );
    let document = format!(
        "{}{}{}{}{}",
        "<Envelope xmlns=\"urn:envelope\"><Data Id=\"data\">payload</Data>\
         <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>\
         <CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
         <SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>",
        reference,
        reference,
        "</SignedInfo><SignatureValue>AAAA</SignatureValue>",
        "</Signature></Envelope>"
    );
    crate::ffi::policy::republish(
        |verification| verification.resources.max_references = 1,
        |_| {},
    )
    .expect("the library policy compiles");
    // SAFETY: the library, a document, a key and a context set up and torn
    // down here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsReadMemory(
            document.as_ptr().cast(),
            i32::try_from(document.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let signature = xmlSecFindNode(
            xsDocGetRootElement(doc),
            c"Signature".as_ptr().cast(),
            c"http://www.w3.org/2000/09/xmldsig#".as_ptr().cast(),
        );
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        let secret = b"secret-of-thirty-two-octets-long";
        let key = xmlSecKeyCreate();
        assert_eq!(
            xmlSecKeyDataBinRead(
                symkeys::hmac(),
                key.cast(),
                secret.as_ptr(),
                secret.len(),
                (&raw mut (*ctx).key_info_read_ctx).cast(),
            ),
            0
        );
        (*ctx).sign_key = key;
        assert_eq!(xmlSecDSigCtxVerify(ctx, signature), -1);
        assert_eq!(
            crate::ffi::list::xmlSecPtrListGetSize(&raw mut (*ctx).signed_info_references),
            1
        );
        xmlSecDSigCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn status_and_failure_strings_are_libxmlsec1s() {
    // The strings applications print and compare.
    assert_eq!(status_string(STATUS_SUCCEEDED), c"OK");
    assert_eq!(status_string(STATUS_INVALID), c"FAILED");
    assert_eq!(status_string(STATUS_UNKNOWN), c"ERROR");
    assert_eq!(status_string(42), c"ERROR");
    assert_eq!(failure_string(FAILURE_REFERENCE), c"REFERENCE");
    assert_eq!(failure_string(FAILURE_SIGNATURE), c"SIGNATURE");
    assert_eq!(failure_string(FAILURE_KEY_NOT_FOUND), c"KEY-NOT-FOUND");
    assert_eq!(failure_string(FAILURE_UNKNOWN), c"UNKNOWN");
    assert_eq!(failure_string(-1), c"UNKNOWN");
}

#[test]
fn a_created_context_has_libxmlsec1s_defaults_and_finalizes_to_zero() {
    // SAFETY: a context created and destroyed here; a stack context
    // initialized and finalized here.
    unsafe {
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        assert!(!ctx.is_null());
        let context = &*ctx;
        assert_eq!(context.enabled_reference_uris, REFERENCE_URIS_DEFAULT);
        assert_eq!(context.key_info_read_ctx.mode, MODE_READ);
        assert_eq!(context.key_info_write_ctx.mode, MODE_WRITE);
        assert_eq!(context.key_info_write_ctx.key_req.key_type, TYPE_PUBLIC);
        assert_eq!(context.status, STATUS_UNKNOWN);
        assert!(xmlSecDSigCtxGetPreSignBuffer(ctx).is_null());
        xmlSecDSigCtxDestroy(ctx);

        let mut stack = std::mem::MaybeUninit::<XmlSecDSigCtx>::uninit();
        assert_eq!(
            xmlSecDSigCtxInitialize(stack.as_mut_ptr(), std::ptr::null_mut()),
            0
        );
        xmlSecDSigCtxFinalize(stack.as_mut_ptr());
        let bytes =
            std::slice::from_raw_parts(stack.as_ptr().cast::<u8>(), size_of::<XmlSecDSigCtx>());
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn enabling_transforms_needs_a_klass_and_a_fresh_context() {
    // SAFETY: a context created and destroyed here; the klass is static.
    unsafe {
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        let klass = super::super::transforms::builtin::xmlSecTransformBase64GetKlass();
        assert_eq!(xmlSecDSigCtxEnableReferenceTransform(ctx, klass), 0);
        assert_eq!(xmlSecDSigCtxEnableSignatureTransform(ctx, klass), 0);
        assert_eq!(
            xmlSecDSigCtxEnableReferenceTransform(ctx, std::ptr::null()),
            -1
        );
        // A context holding a result has run: its transforms are fixed.
        let mut buffer = std::mem::zeroed::<XmlSecBuffer>();
        (*ctx).result = &raw mut buffer;
        assert_eq!(xmlSecDSigCtxEnableReferenceTransform(ctx, klass), -1);
        (*ctx).result = std::ptr::null_mut();
        xmlSecDSigCtxDestroy(ctx);
    }
}

#[test]
fn a_reference_context_inherits_the_signature_contexts_settings() {
    // SAFETY: contexts created and destroyed here.
    unsafe {
        let ctx = xmlSecDSigCtxCreate(std::ptr::null_mut());
        (*ctx).flags = FLAGS_USE_VISA3D_HACK | FLAGS_ALLOW_EMPTY_INPUT_DSIG;
        (*ctx).enabled_reference_uris = 0x0004;
        let mut marker = 7_u8;
        (*ctx).user_data = (&raw mut marker).cast();
        let reference = xmlSecDSigReferenceCtxCreate(ctx, ORIGIN_MANIFEST);
        assert!(!reference.is_null());
        let context = &*reference;
        assert_eq!(context.origin, ORIGIN_MANIFEST);
        assert_eq!(context.transform_ctx.enabled_uris, 0x0004);
        assert_eq!(context.transform_ctx.user_data, (&raw mut marker).cast());
        assert_eq!(
            context.transform_ctx.flags,
            TRANSFORMCTX_VISA3D | FLAGS_ALLOW_EMPTY_INPUT
        );
        assert!(xmlSecDSigReferenceCtxGetPreDigestBuffer(reference).is_null());
        xmlSecDSigReferenceCtxDestroy(reference);
        xmlSecDSigCtxDestroy(ctx);
    }
}
