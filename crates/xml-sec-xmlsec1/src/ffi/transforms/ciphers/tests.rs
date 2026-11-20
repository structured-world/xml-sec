use super::*;

use crate::ffi::buffer::{
    XmlSecBuffer, xmlSecBufferGetData, xmlSecBufferGetSize, xmlSecBufferIsSecure,
};
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

/// The reasons the library reported, in order.
static REASONS: std::sync::Mutex<Vec<c_int>> = std::sync::Mutex::new(Vec::new());

unsafe extern "C" fn record(
    _file: *const std::ffi::c_char,
    _line: c_int,
    _func: *const std::ffi::c_char,
    _object: *const std::ffi::c_char,
    _subject: *const std::ffi::c_char,
    reason: c_int,
    _message: *const std::ffi::c_char,
) {
    REASONS.lock().expect("one test thread").push(reason);
}

#[test]
fn gcm_refuses_a_tampered_cipher_value() {
    // The untouched value decrypts under the same key and setup, so the
    // refusal of the changed tag is GCM's authentication failing, reported
    // as a cryptographic failure, not a broken fixture. The error callback is
    // process-wide.
    crate::ffi::tests::own_process();
    let key = aes_key(&[0x22; 32]);
    let mut encrypted = run(aes256_gcm(), OPERATION_ENCRYPT, key, b"payload").expect("encrypts");
    assert_eq!(
        run(aes256_gcm(), OPERATION_DECRYPT, key, &encrypted).as_deref(),
        Some(&b"payload"[..])
    );
    let last = encrypted.len() - 1;
    encrypted[last] ^= 0x01;
    // SAFETY: the callback has the callback's signature.
    unsafe {
        crate::ffi::errors::xmlSecErrorsSetCallback(Some(
            record as crate::ffi::errors::ErrorsCallback,
        ));
    }
    assert_eq!(run(aes256_gcm(), OPERATION_DECRYPT, key, &encrypted), None);
    // SAFETY: restores the default callback.
    unsafe { crate::ffi::errors::xmlSecErrorsSetCallback(None) };
    assert_eq!(
        REASONS.lock().expect("one test thread").first(),
        Some(&crate::ffi::errors::R_CRYPTO_FAILED)
    );
    // SAFETY: the key created above.
    unsafe { xmlSecKeyDestroy(key) };
}

/// Whether the cipher `id` run with `operation` and `key` over `input` marks
/// its output buffer as holding a secret; `None` when it fails.
fn marks_output_secure(
    id: *const XmlSecTransformKlass,
    operation: c_int,
    key: *mut XmlSecKey,
    input: &[u8],
) -> Option<bool> {
    // SAFETY: a context created and destroyed here.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, id);
        (*transform).operation = operation;
        let marked = (xmlSecTransformSetKey(transform, key.cast()) == 0
            && xmlSecTransformCtxBinaryExecute(ctx, input.as_ptr(), input.len()) == 0)
            .then(|| xmlSecBufferIsSecure(&raw mut (*transform).out_buf) == 1);
        xmlSecTransformCtxDestroy(ctx);
        marked
    }
}

#[test]
fn an_unwrapped_key_is_written_to_a_secure_buffer() {
    // libxmlsec1 marks the output of a key unwrap as holding a secret; the
    // wrap's output and a data decryption's output stay unmarked.
    let key = aes_key(&[0x22; 16]);
    let content_key = [0x33_u8; 16];
    let wrapped = run(kw_aes128(), OPERATION_ENCRYPT, key, &content_key).expect("wraps");
    assert_eq!(
        run(kw_aes128(), OPERATION_DECRYPT, key, &wrapped).as_deref(),
        Some(&content_key[..])
    );
    assert_eq!(
        marks_output_secure(kw_aes128(), OPERATION_ENCRYPT, key, &content_key),
        Some(false)
    );
    assert_eq!(
        marks_output_secure(kw_aes128(), OPERATION_DECRYPT, key, &wrapped),
        Some(true)
    );
    let encrypted = run(aes128_cbc(), OPERATION_ENCRYPT, key, b"data").expect("encrypts");
    assert_eq!(
        marks_output_secure(aes128_cbc(), OPERATION_DECRYPT, key, &encrypted),
        Some(false)
    );
    // SAFETY: the key created above.
    unsafe { xmlSecKeyDestroy(key) };
}

#[test]
fn decryption_refuses_plaintext_beyond_the_policy_limit() {
    // A GCM value adds 28 octets of nonce and tag, inside the input framing
    // allowance, so only a check of the recovered plaintext keeps one octet
    // over the limit out. Republishing runs in this test's own process.
    crate::ffi::tests::own_process();
    let key = aes_key(&[0x44; 16]);
    let encrypted = run(aes128_gcm(), OPERATION_ENCRYPT, key, &[0x55; 17]).expect("encrypts");
    xml_sec_libxml2::policy::republish_encryption(
        |_| {},
        |decryption| decryption.resources.max_encryption_plaintext_bytes = 16,
    )
    .expect("the library policy compiles");
    assert_eq!(run(aes128_gcm(), OPERATION_DECRYPT, key, &encrypted), None);
    xml_sec_libxml2::policy::republish_encryption(
        |_| {},
        |decryption| decryption.resources.max_encryption_plaintext_bytes = 17,
    )
    .expect("the library policy compiles");
    assert_eq!(
        run(aes128_gcm(), OPERATION_DECRYPT, key, &encrypted),
        Some(vec![0x55; 17])
    );
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
