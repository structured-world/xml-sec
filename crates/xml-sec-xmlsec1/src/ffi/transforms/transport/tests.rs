use super::super::super::app::key_load_memory;
use super::super::super::buffer::xmlSecBufferAppend;
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
