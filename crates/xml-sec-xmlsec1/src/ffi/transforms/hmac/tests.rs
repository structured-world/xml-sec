//! The HMAC klasses enforce the library policy of their operation when a key
//! is set: the method, the secret length and the output length. A test that
//! republishes the library policy runs in a process of its own, so no other
//! test observes its snapshot.

use std::ffi::c_int;

use crate::ffi::tests::own_process;

use super::super::super::buffer::xmlSecBufferSetData;
use super::super::super::keys::{xmlSecKeyCreate, xmlSecKeyDestroy, xmlSecKeySetValue};
use super::super::super::keysdata::{xmlSecKeyDataBinaryValueGetBuffer, xmlSecKeyDataCreate};
use super::super::super::policy;
use super::super::super::symkeys;
use super::super::ctx::{
    xmlSecTransformCtxCreate, xmlSecTransformCtxCreateAndAppend, xmlSecTransformCtxDestroy,
};
use super::super::{OPERATION_SIGN, OPERATION_VERIFY, xmlSecTransformSetKey};
use super::{hmac_sha256, xmlSecTransformHmacSetMinOutputBitsSize};
use xml_sec::xmldsig::SignatureAlgorithm;

/// `setKey` of an HMAC-SHA256 transform of `operation` with `secret`.
fn set_key(operation: c_int, secret: &[u8]) -> c_int {
    // SAFETY: every object is created and released here.
    unsafe {
        let key = xmlSecKeyCreate();
        let data = xmlSecKeyDataCreate(symkeys::hmac());
        assert_eq!(
            xmlSecBufferSetData(
                xmlSecKeyDataBinaryValueGetBuffer(data),
                secret.as_ptr(),
                secret.len()
            ),
            0
        );
        assert_eq!(xmlSecKeySetValue(key, data), 0);
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, hmac_sha256());
        (*transform).operation = operation;
        let result = xmlSecTransformSetKey(transform, key.cast());
        xmlSecTransformCtxDestroy(ctx);
        xmlSecKeyDestroy(key);
        result
    }
}

#[test]
fn a_secret_below_the_policy_minimum_is_refused() {
    // The policy's minimum HMAC key length holds for both operations; a
    // compliant secret is accepted.
    for operation in [OPERATION_SIGN, OPERATION_VERIFY] {
        assert_eq!(set_key(operation, &[0x42]), -1, "operation {operation}");
        assert_eq!(set_key(operation, &[0x42; 32]), 0, "operation {operation}");
    }
}

#[test]
fn a_method_the_policy_excludes_is_refused() {
    // The method must be admitted by the policy of the operation, as for the
    // asymmetric signature methods.
    own_process();
    let without = |methods: &mut Option<std::collections::BTreeSet<SignatureAlgorithm>>| {
        if let Some(methods) = methods {
            methods.remove(&SignatureAlgorithm::HmacSha256);
        }
    };
    policy::republish(
        |verification| without(&mut verification.signature_algorithms),
        |signing| without(&mut signing.signature_algorithms),
    )
    .expect("the library policy compiles");
    for operation in [OPERATION_SIGN, OPERATION_VERIFY] {
        assert_eq!(set_key(operation, &[0x42; 32]), -1, "operation {operation}");
    }
}

#[test]
fn the_full_output_meets_the_minimum_output_length() {
    // Without HMACOutputLength the full MAC is the output, and it too must
    // reach the configured minimum.
    own_process();
    xmlSecTransformHmacSetMinOutputBitsSize(512);
    for operation in [OPERATION_SIGN, OPERATION_VERIFY] {
        assert_eq!(set_key(operation, &[0x42; 32]), -1, "operation {operation}");
    }
}
