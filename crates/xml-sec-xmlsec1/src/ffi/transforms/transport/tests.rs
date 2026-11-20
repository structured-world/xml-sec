use super::super::super::app::key_load_memory;
use super::super::super::buffer::{xmlSecBufferAppend, xmlSecBufferIsSecure};
use super::super::super::keys::xmlSecKeyDestroy;
use super::super::ctx::{
    xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxCreate, xmlSecTransformCtxCreateAndAppend,
    xmlSecTransformCtxDestroy,
};
use super::super::{xmlSecTransformExecute, xmlSecTransformSetKey};
use super::*;

/// `xmlSecKeyDataFormatPem`.
const FORMAT_PEM: c_int = 2;

/// The RSA fixture key, private and public.
fn rsa_key() -> *mut XmlSecKey {
    let pem = include_bytes!("../../../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem");
    // SAFETY: the fixture's bytes; no password is needed.
    let key = unsafe {
        key_load_memory(
            pem.as_ptr(),
            pem.len(),
            FORMAT_PEM,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert!(!key.is_null(), "the fixture loads");
    key.cast()
}

#[test]
fn oaep_parameters_beyond_the_metadata_limit_are_refused() {
    // The operation's policy bounds encryption metadata at 64 octets: an
    // OAEP label longer than that is refused as the core's policy-aware
    // parser refuses it, not admitted up to the hard ceiling.
    let label = "A".repeat(128);
    let method = format!(
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" \
         Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\">\
         <OAEPparams>{label}</OAEPparams></EncryptionMethod>"
    );
    let mut pinned = super::super::super::policy::Pinned::current(here!("test"))
        .expect("the library policy compiles");
    std::sync::Arc::make_mut(&mut pinned.decryption)
        .resources
        .max_encryption_metadata_bytes = 64;
    // SAFETY: a document, a context and its transform, created and released
    // here.
    unsafe {
        let doc = xml_sec_libxml2::ffi::tree::xsReadMemory(
            method.as_ptr().cast(),
            c_int::try_from(method.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ctx = xmlSecTransformCtxCreate();
        super::super::ctx::pin_run(ctx, &pinned);
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_oaep());
        let node = xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc);
        assert_eq!(read_node(transform, node, ctx), -1);
        xmlSecTransformCtxDestroy(ctx);
        xml_sec_libxml2::ffi::tree::xsFreeDoc(doc);
    }
}

/// The Base64 text of `len` zero octets.
fn zeros_base64(len: usize) -> String {
    let mut text = "AAAA".repeat(len / 3);
    match len % 3 {
        1 => text.push_str("AA=="),
        2 => text.push_str("AAA="),
        _ => {}
    }
    text
}

/// `read_node` of an RSA-OAEP transform of `operation` on an
/// `EncryptionMethod` whose label decodes to `label_len` octets, under
/// `pinned`.
fn read_oaep_label(
    operation: c_int,
    label_len: usize,
    pinned: &super::super::super::policy::Pinned,
) -> c_int {
    let label = zeros_base64(label_len);
    let method = format!(
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" \
         Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\">\
         <OAEPparams>{label}</OAEPparams></EncryptionMethod>"
    );
    // SAFETY: a document, a context and its transform, created and released
    // here.
    unsafe {
        let doc = xml_sec_libxml2::ffi::tree::xsReadMemory(
            method.as_ptr().cast(),
            c_int::try_from(method.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let ctx = xmlSecTransformCtxCreate();
        super::super::ctx::pin_run(ctx, pinned);
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_oaep());
        (*transform).operation = operation;
        let node = xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc);
        let read = read_node(transform, node, ctx);
        xmlSecTransformCtxDestroy(ctx);
        xml_sec_libxml2::ffi::tree::xsFreeDoc(doc);
        read
    }
}

#[test]
fn encryption_reads_oaep_parameters_under_the_encryption_policy() {
    // The two policies bound encryption metadata separately, in decoded
    // octets: an encrypting transform reads its label under the encryption
    // policy, whichever way the decryption policy differs from it. A label of
    // the limit is read and one octet more is refused by the limited side
    // alone.
    let mut pinned = super::super::super::policy::Pinned::current(here!("test"))
        .expect("the library policy compiles");
    std::sync::Arc::make_mut(&mut pinned.decryption)
        .resources
        .max_encryption_metadata_bytes = 64;
    assert_eq!(read_oaep_label(OPERATION_ENCRYPT, 65, &pinned), 0);
    assert_eq!(read_oaep_label(OPERATION_DECRYPT, 64, &pinned), 0);
    assert_eq!(read_oaep_label(OPERATION_DECRYPT, 65, &pinned), -1);

    let mut pinned = super::super::super::policy::Pinned::current(here!("test"))
        .expect("the library policy compiles");
    std::sync::Arc::make_mut(&mut pinned.encryption)
        .resources
        .max_encryption_metadata_bytes = 64;
    assert_eq!(read_oaep_label(OPERATION_ENCRYPT, 64, &pinned), 0);
    assert_eq!(read_oaep_label(OPERATION_ENCRYPT, 65, &pinned), -1);
    assert_eq!(read_oaep_label(OPERATION_DECRYPT, 65, &pinned), 0);
}

#[test]
fn an_unknown_oaep_digest_is_refused_when_the_method_is_read() {
    // libxmlsec1's reader resolves an OAEP method's DigestMethod as it reads
    // it: an unknown identifier is refused there, before the caller sets the
    // transform up, rather than when it runs. A known one is read.
    let pinned = super::super::super::policy::Pinned::current(here!("test"))
        .expect("the library policy compiles");
    for (digest, read) in [
        ("http://www.w3.org/2001/04/xmlenc#sha256", 0),
        ("urn:example:unknown-digest", -1),
    ] {
        let method = format!(
            "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" \
             Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\">\
             <DigestMethod xmlns=\"http://www.w3.org/2000/09/xmldsig#\" \
             Algorithm=\"{digest}\"/></EncryptionMethod>"
        );
        // SAFETY: a document, a context and its transform, created and
        // released here.
        unsafe {
            let doc = xml_sec_libxml2::ffi::tree::xsReadMemory(
                method.as_ptr().cast(),
                c_int::try_from(method.len()).expect("a short document"),
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
            assert!(!doc.is_null());
            let ctx = xmlSecTransformCtxCreate();
            super::super::ctx::pin_run(ctx, &pinned);
            let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_oaep_enc11());
            (*transform).operation = OPERATION_DECRYPT;
            let node = xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc);
            assert_eq!(read_node(transform, node, ctx), read, "{digest}");
            xmlSecTransformCtxDestroy(ctx);
            xml_sec_libxml2::ffi::tree::xsFreeDoc(doc);
        }
    }
}

#[test]
fn a_label_read_before_the_operation_is_known_is_bounded_when_encrypting() {
    // A standalone chain reads its method before its operation is set; an
    // encryption still refuses a label beyond the encryption policy's
    // metadata limit when it transports the key. The same flow under the
    // unchanged policy transports it, so the limit alone refuses.
    let label = "A".repeat(96);
    let method = format!(
        "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" \
         Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\">\
         <OAEPparams>{label}</OAEPparams></EncryptionMethod>"
    );
    let unchanged = super::super::super::policy::Pinned::current(here!("test"))
        .expect("the library policy compiles");
    let mut limited = unchanged.clone();
    std::sync::Arc::make_mut(&mut limited.encryption)
        .resources
        .max_encryption_metadata_bytes = 64;
    let key = rsa_key();
    for (pinned, expected) in [(&unchanged, 0), (&limited, -1)] {
        // SAFETY: a document, a context and its transform, created and
        // released here, and the key.
        unsafe {
            let doc = xml_sec_libxml2::ffi::tree::xsReadMemory(
                method.as_ptr().cast(),
                c_int::try_from(method.len()).expect("a short document"),
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
            assert!(!doc.is_null());
            let ctx = xmlSecTransformCtxCreate();
            super::super::ctx::pin_run(ctx, pinned);
            let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_oaep());
            let node = xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc);
            assert_eq!(read_node(transform, node, ctx), 0);
            (*transform).operation = OPERATION_ENCRYPT;
            assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
            let content_key = [0x42_u8; 16];
            assert_eq!(
                xmlSecTransformCtxBinaryExecute(ctx, content_key.as_ptr(), content_key.len()),
                expected
            );
            xmlSecTransformCtxDestroy(ctx);
            xml_sec_libxml2::ffi::tree::xsFreeDoc(doc);
        }
    }
    // SAFETY: the key created above.
    unsafe { xmlSecKeyDestroy(key) };
}

#[test]
fn input_after_a_finished_transport_is_refused() {
    // A transport that has produced its output takes no more input: bytes
    // left in its input buffer would be dropped while the chain succeeds.
    let key = rsa_key();
    // SAFETY: a context, its transform and the key, created and released
    // here.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_oaep());
        (*transform).operation = OPERATION_ENCRYPT;
        assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
        let content_key = [0x42_u8; 16];
        assert_eq!(
            xmlSecTransformCtxBinaryExecute(ctx, content_key.as_ptr(), content_key.len()),
            0
        );
        assert_eq!((*transform).status, STATUS_FINISHED);
        // An empty call still succeeds, so a pump can drain the output.
        assert_eq!(xmlSecTransformExecute(transform, 1, ctx), 0);
        assert_eq!(
            xmlSecBufferAppend(&raw mut (*transform).in_buf, [0_u8].as_ptr(), 1),
            0
        );
        assert_eq!(xmlSecTransformExecute(transform, 1, ctx), -1);
        xmlSecTransformCtxDestroy(ctx);
        xmlSecKeyDestroy(key);
    }
}

#[test]
fn a_recovered_key_is_written_to_a_secure_buffer() {
    // libxmlsec1 marks the output of a key transport decryption as holding
    // a secret; the encryption's output, a ciphertext, stays unmarked.
    let key = rsa_key();
    let content_key = [0x42_u8; 16];
    // SAFETY: two contexts, their transforms and the key, created and
    // released here; the result buffer belongs to the first context.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_oaep());
        (*transform).operation = OPERATION_ENCRYPT;
        assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
        assert_eq!(
            xmlSecTransformCtxBinaryExecute(ctx, content_key.as_ptr(), content_key.len()),
            0
        );
        assert_eq!(xmlSecBufferIsSecure(&raw mut (*transform).out_buf), 0);
        let result = (*ctx).result;
        assert!(!result.is_null(), "the encryption has a result");
        let ciphertext =
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result))
                .to_vec();
        xmlSecTransformCtxDestroy(ctx);

        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_oaep());
        (*transform).operation = OPERATION_DECRYPT;
        assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
        assert_eq!(
            xmlSecTransformCtxBinaryExecute(ctx, ciphertext.as_ptr(), ciphertext.len()),
            0
        );
        let result = (*ctx).result;
        assert_eq!(
            std::slice::from_raw_parts(xmlSecBufferGetData(result), xmlSecBufferGetSize(result)),
            content_key
        );
        assert_eq!(xmlSecBufferIsSecure(&raw mut (*transform).out_buf), 1);
        xmlSecTransformCtxDestroy(ctx);
        xmlSecKeyDestroy(key);
    }
}
