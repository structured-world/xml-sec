use super::*;

use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};

use crate::ffi::crypto::{
    xmlSecCryptoAppInit, xmlSecCryptoAppShutdown, xmlSecCryptoDLLoadLibrary, xmlSecCryptoInit,
    xmlSecCryptoShutdown,
};
use crate::ffi::keys::xmlSecKeyCreate;
use crate::ffi::keysdata::xmlSecKeyDataBinRead;
use crate::ffi::library::{xmlSecInit, xmlSecShutdown};
use crate::ffi::list::xmlSecPtrListGetItem;
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
