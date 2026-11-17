use super::*;

use crate::ffi::buffer::{XmlSecBuffer, xmlSecBufferGetData, xmlSecBufferGetSize};
use crate::ffi::keys::{xmlSecKeyCreate, xmlSecKeyDestroy, xmlSecKeySetValue};
use crate::ffi::keysdata::{xmlSecKeyDataBinaryValueSetBuffer, xmlSecKeyDataCreate};
use crate::ffi::transforms::ctx::{
    xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxCreate, xmlSecTransformCtxCreateAndAppend,
    xmlSecTransformCtxDestroy,
};
use crate::ffi::transforms::{xmlSecTransformSetKey, xmlSecTransformSetKeyReq};

/// A key of the AES family holding `bytes`.
fn aes_key(bytes: &[u8]) -> *mut XmlSecKey {
    // SAFETY: a key and key data created here.
    unsafe {
        let data = xmlSecKeyDataCreate(symkeys::aes());
        assert_eq!(
            xmlSecKeyDataBinaryValueSetBuffer(data, bytes.as_ptr(), bytes.len()),
            0
        );
        let key = xmlSecKeyCreate();
        assert_eq!(xmlSecKeySetValue(key, data), 0);
        key
    }
}

/// The bytes of `buffer`.
fn bytes(buffer: *mut XmlSecBuffer) -> Vec<u8> {
    // SAFETY: a live buffer.
    unsafe {
        if xmlSecBufferGetData(buffer).is_null() {
            return Vec::new();
        }
        std::slice::from_raw_parts(xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer))
            .to_vec()
    }
}

/// Runs a chain of the cipher `id` with `operation` and `key` over `input`;
/// `None` when it fails.
fn run(
    id: *const XmlSecTransformKlass,
    operation: c_int,
    key: *mut XmlSecKey,
    input: &[u8],
) -> Option<Vec<u8>> {
    // SAFETY: a context created and destroyed here.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, id);
        (*transform).operation = operation;
        let result = (xmlSecTransformSetKey(transform, key.cast()) == 0
            && xmlSecTransformCtxBinaryExecute(ctx, input.as_ptr(), input.len()) == 0)
            .then(|| bytes((*ctx).result));
        xmlSecTransformCtxDestroy(ctx);
        result
    }
}

#[test]
fn a_cipher_value_round_trips_and_carries_its_iv() {
    // XMLEnc frames a CBC cipher value as IV || ciphertext with XMLEnc
    // padding; the provider's decryption takes that frame back.
    let key = aes_key(&[0x11; 16]);
    let plaintext = b"The quick brown fox jumps over the lazy dog";
    let encrypted = run(aes128_cbc(), OPERATION_ENCRYPT, key, plaintext).expect("encrypts");
    // 16-octet IV and the plaintext padded to whole blocks.
    assert_eq!(encrypted.len(), 16 + plaintext.len().div_ceil(16) * 16);
    let decrypted = run(aes128_cbc(), OPERATION_DECRYPT, key, &encrypted).expect("decrypts");
    assert_eq!(decrypted, plaintext);
    // SAFETY: the key created above.
    unsafe { xmlSecKeyDestroy(key) };
}

#[test]
fn gcm_refuses_a_tampered_cipher_value() {
    let key = aes_key(&[0x22; 32]);
    let mut encrypted = run(aes256_gcm(), OPERATION_ENCRYPT, key, b"payload").expect("encrypts");
    let last = encrypted.len() - 1;
    encrypted[last] ^= 0x01;
    assert_eq!(run(aes256_gcm(), OPERATION_DECRYPT, key, &encrypted), None);
    // SAFETY: the key created above.
    unsafe { xmlSecKeyDestroy(key) };
}

#[test]
fn a_short_key_is_refused_and_requirements_name_the_family_and_size() {
    // SAFETY: a context, a transform and a key created and destroyed here.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, aes256_cbc());
        (*transform).operation = OPERATION_DECRYPT;
        let mut req = std::mem::zeroed::<XmlSecKeyReq>();
        assert_eq!(xmlSecTransformSetKeyReq(transform, &raw mut req), 0);
        assert_eq!(req.key_id, symkeys::aes().cast());
        assert_eq!(req.key_type, TYPE_SYMMETRIC);
        assert_eq!(req.key_usage, KEY_USAGE_DECRYPT);
        assert_eq!(req.key_bits_size, 256);
        let short = aes_key(&[0x33; 16]);
        assert_eq!(xmlSecTransformSetKey(transform, short.cast()), -1);
        xmlSecKeyDestroy(short);
        xmlSecTransformCtxDestroy(ctx);
    }
}
