use super::*;

use xml_sec::xmlenc::DataEncryptionAlgorithm;
use xml_sec_libxml2::ffi::tree::{xsDocSetRootElement, xsFreeDoc, xsNewDoc};

use crate::ffi::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use crate::ffi::crypto::{
    xmlSecCryptoAppInit, xmlSecCryptoAppShutdown, xmlSecCryptoDLLoadLibrary, xmlSecCryptoInit,
    xmlSecCryptoShutdown,
};
use crate::ffi::keyinfo::XmlSecKeyInfoCtx;
use crate::ffi::keys::xmlSecKeyCreate;
use crate::ffi::keysdata::xmlSecKeyDataBinRead;
use crate::ffi::keysmngr::{xmlSecKeysMngrCreate, xmlSecKeysMngrDestroy};
use crate::ffi::library::{xmlSecInit, xmlSecShutdown};
use crate::ffi::symkeys;
use crate::ffi::templates::{xmlSecTmplEncDataCreate, xmlSecTmplEncDataEnsureCipherValue};
use crate::ffi::tests::own_process;
use crate::ffi::transforms::ciphers::aes128_cbc;

/// An AES key of sixteen `0x5a` octets.
fn aes_key() -> *mut XmlSecKey {
    let bytes = [0x5a_u8; 16];
    // SAFETY: a key and a read context created here; the AES klass reads
    // the key.
    unsafe {
        let read = crate::ffi::keyinfo::xmlSecKeyInfoCtxCreate(std::ptr::null_mut());
        let key = xmlSecKeyCreate();
        assert_eq!(
            xmlSecKeyDataBinRead(
                symkeys::aes(),
                key.cast(),
                bytes.as_ptr(),
                bytes.len(),
                read.cast(),
            ),
            0
        );
        crate::ffi::keyinfo::xmlSecKeyInfoCtxDestroy(read);
        key
    }
}

/// A key manager's lookup that republishes a policy refusing AES-128-CBC
/// while it answers, then hands back the key.
unsafe extern "C" fn republishing_lookup(
    _node: *mut XmlNode,
    _ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    xml_sec_libxml2::policy::republish_encryption(
        |_| {},
        |decryption| {
            if let Some(allowed) = decryption.data_algorithms.as_mut() {
                allowed.remove(&DataEncryptionAlgorithm::Aes128Cbc);
            }
        },
    )
    .expect("the library policy compiles");
    aes_key()
}

#[test]
fn one_decryption_runs_under_the_revision_its_key_was_read_under() {
    // A republish while the key is looked up takes effect for later
    // operations; this one keeps the revision that admitted its key.
    own_process();
    let plaintext = b"one revision";
    // SAFETY: the library, a document, contexts, keys and a manager set up
    // and released here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsNewDoc(c"1.0".as_ptr().cast());
        let tmpl = xmlSecTmplEncDataCreate(
            doc,
            aes128_cbc(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        xsDocSetRootElement(doc, tmpl);
        assert!(!xmlSecTmplEncDataEnsureCipherValue(tmpl).is_null());
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        assert_eq!(
            xmlSecEncCtxBinaryEncrypt(ctx, tmpl, plaintext.as_ptr(), plaintext.len()),
            0
        );
        xmlSecEncCtxDestroy(ctx);
        let mngr = xmlSecKeysMngrCreate();
        (*mngr).get_key = Some(republishing_lookup);
        let ctx = xmlSecEncCtxCreate(mngr);
        let result = xmlSecEncCtxDecryptToBuffer(ctx, tmpl);
        assert!(!result.is_null(), "decryption kept its revision");
        assert_eq!(
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result)),
            plaintext
        );
        xmlSecEncCtxDestroy(ctx);
        xmlSecKeysMngrDestroy(mngr);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// The ciphertext the test's input callbacks serve.
static SERVED: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
/// Octets of [`SERVED`] already read.
static SERVED_SENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn served_matches(_uri: *const std::ffi::c_char) -> std::ffi::c_int {
    1
}

unsafe extern "C" fn served_open(_uri: *const std::ffi::c_char) -> *mut std::ffi::c_void {
    SERVED_SENT.store(0, std::sync::atomic::Ordering::Relaxed);
    std::ptr::NonNull::<u8>::dangling().as_ptr().cast()
}

unsafe extern "C" fn served_read(
    _context: *mut std::ffi::c_void,
    buffer: *mut std::ffi::c_char,
    len: std::ffi::c_int,
) -> std::ffi::c_int {
    let served = SERVED.lock().expect("one test thread");
    let sent = SERVED_SENT.load(std::sync::atomic::Ordering::Relaxed);
    let rest = &served[sent..];
    let count = rest
        .len()
        .min(usize::try_from(len).expect("a non-negative length"));
    // SAFETY: the transform passes `len` writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(rest.as_ptr(), buffer.cast(), count) };
    SERVED_SENT.store(sent + count, std::sync::atomic::Ordering::Relaxed);
    std::ffi::c_int::try_from(count).expect("at most `len` octets")
}

unsafe extern "C" fn served_close(_context: *mut std::ffi::c_void) -> std::ffi::c_int {
    0
}

#[test]
fn a_cipher_reference_is_found_under_the_uri_the_core_resolves() {
    // `test:dir/../cipher` resolves to `test:cipher` (RFC 3986 section
    // 5.2.2): the callback is asked for the URI as written, as libxmlsec1
    // asks, and the core finds the octets under the resolved one.
    own_process();
    let plaintext = b"referenced ciphertext";
    // SAFETY: the library, documents, contexts and keys set up and released
    // here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        assert_eq!(
            crate::ffi::transforms::io::xmlSecIORegisterCallbacks(
                Some(served_matches),
                Some(served_open),
                Some(served_read),
                Some(served_close),
            ),
            0
        );
        let doc = xsNewDoc(c"1.0".as_ptr().cast());
        let tmpl = xmlSecTmplEncDataCreate(
            doc,
            aes128_cbc(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        xsDocSetRootElement(doc, tmpl);
        let cipher_value = xmlSecTmplEncDataEnsureCipherValue(tmpl);
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        assert_eq!(
            xmlSecEncCtxBinaryEncrypt(ctx, tmpl, plaintext.as_ptr(), plaintext.len()),
            0
        );
        xmlSecEncCtxDestroy(ctx);
        let text = xml_sec_libxml2::ffi::tree::xsNodeGetContent(cipher_value.cast());
        let mut size = 0;
        assert_eq!(
            crate::ffi::base64::xmlSecBase64DecodeInPlace(text, &raw mut size),
            0,
            "the cipher value decodes"
        );
        *SERVED.lock().expect("one test thread") = std::slice::from_raw_parts(text, size).to_vec();
        crate::ffi::free(text.cast());
        xsFreeDoc(doc);

        let referenced = concat!(
            "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">",
            "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>",
            "<CipherData><CipherReference URI=\"test:dir/../cipher\"/></CipherData>",
            "</EncryptedData>"
        );
        let doc = xml_sec_libxml2::ffi::tree::xsReadMemory(
            referenced.as_ptr().cast(),
            std::ffi::c_int::try_from(referenced.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        (*ctx).transform_ctx.enabled_uris = 0xFFFF;
        let result =
            xmlSecEncCtxDecryptToBuffer(ctx, xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc));
        assert!(!result.is_null(), "the referenced ciphertext was found");
        assert_eq!(
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result)),
            plaintext
        );
        xmlSecEncCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

/// A pre-execute callback that refuses every chain.
unsafe extern "C" fn veto(
    _ctx: *mut crate::ffi::transforms::XmlSecTransformCtx,
) -> std::ffi::c_int {
    -1
}

#[test]
fn a_pre_execute_veto_stops_decryption_before_the_document_changes() {
    // libxmlsec1 runs the context's pre-execute callback when it prepares the
    // decryption chain: a negative return refuses the operation, so the
    // EncryptedData stays in the document.
    own_process();
    let plaintext = b"<Data>kept encrypted</Data>";
    // SAFETY: the library, a document, contexts and keys set up and released
    // here, on this thread alone.
    unsafe {
        assert_eq!(xmlSecInit(), 0);
        assert_eq!(xmlSecCryptoDLLoadLibrary(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoAppInit(std::ptr::null()), 0);
        assert_eq!(xmlSecCryptoInit(), 0);
        let doc = xsNewDoc(c"1.0".as_ptr().cast());
        let tmpl = xmlSecTmplEncDataCreate(
            doc,
            aes128_cbc(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        xsDocSetRootElement(doc, tmpl);
        assert!(!xmlSecTmplEncDataEnsureCipherValue(tmpl).is_null());
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        assert_eq!(
            xmlSecEncCtxBinaryEncrypt(ctx, tmpl, plaintext.as_ptr(), plaintext.len()),
            0
        );
        xmlSecEncCtxDestroy(ctx);
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        (*ctx).enc_key = aes_key();
        (*ctx).transform_ctx.pre_exec_callback = Some(veto);
        assert_eq!(xmlSecEncCtxDecrypt(ctx, tmpl), -1);
        assert_eq!((*ctx).result_replaced, 0);
        assert_eq!(xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc), tmpl);
        xmlSecEncCtxDestroy(ctx);
        xsFreeDoc(doc);
        assert_eq!(xmlSecCryptoShutdown(), 0);
        assert_eq!(xmlSecCryptoAppShutdown(), 0);
        assert_eq!(xmlSecShutdown(), 0);
    }
}

#[test]
fn failure_strings_are_libxmlsec1s() {
    assert_eq!(failure_string(FAILURE_KEY_NOT_FOUND), c"KEY-NOT-FOUND");
    assert_eq!(failure_string(FAILURE_UNKNOWN), c"UNKNOWN");
    assert_eq!(failure_string(7), c"UNKNOWN");
}

#[test]
fn a_context_initializes_with_libxmlsec1s_defaults_and_finalizes_to_zero() {
    // SAFETY: contexts created, initialized and released here.
    unsafe {
        let ctx = xmlSecEncCtxCreate(std::ptr::null_mut());
        assert!(!ctx.is_null());
        assert_eq!((*ctx).mode, MODE_ENCRYPTED_DATA);
        assert_eq!((*ctx).key_info_read_ctx.mode, MODE_READ);
        assert_eq!((*ctx).key_info_write_ctx.mode, MODE_WRITE);
        assert_eq!((*ctx).key_info_write_ctx.key_req.key_type, TYPE_PUBLIC);
        // A reset keeps the user settings and the defaults.
        (*ctx).flags = FLAGS_RETURN_REPLACED_NODE;
        (*ctx).mode = MODE_ENCRYPTED_KEY;
        xmlSecEncCtxReset(ctx);
        assert_eq!((*ctx).flags, FLAGS_RETURN_REPLACED_NODE);
        assert_eq!((*ctx).mode, MODE_ENCRYPTED_KEY);
        assert_eq!((*ctx).key_info_write_ctx.key_req.key_type, TYPE_PUBLIC);
        let copy = xmlSecEncCtxCreate(std::ptr::null_mut());
        assert_eq!(xmlSecEncCtxCopyUserPref(copy, ctx), 0);
        assert_eq!((*copy).flags, FLAGS_RETURN_REPLACED_NODE);
        assert_eq!((*copy).mode, MODE_ENCRYPTED_KEY);
        xmlSecEncCtxDestroy(copy);
        xmlSecEncCtxDestroy(ctx);

        let mut stack = std::mem::MaybeUninit::<XmlSecEncCtx>::uninit();
        assert_eq!(
            xmlSecEncCtxInitialize(stack.as_mut_ptr(), std::ptr::null_mut()),
            0
        );
        xmlSecEncCtxFinalize(stack.as_mut_ptr());
        let bytes =
            std::slice::from_raw_parts(stack.as_ptr().cast::<u8>(), size_of::<XmlSecEncCtx>());
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
}
