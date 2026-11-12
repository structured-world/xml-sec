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
    xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxCreate, xmlSecTransformCtxCreateAndAppend,
    xmlSecTransformCtxDestroy,
};
use super::super::{OPERATION_SIGN, OPERATION_VERIFY, xmlSecTransformSetKey};
use super::{hmac_sha256, read_node, xmlSecTransformHmacSetMinOutputBitsSize};
use xml_sec::policy::{Instant, PolicyValidity};
use xml_sec::xmldsig::SignatureAlgorithm;
use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};

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
fn an_hmac_key_under_an_expired_policy_is_refused() {
    // A snapshot whose authorized lifetime has ended admits no key, as a core
    // operation checks the lifetime at entry.
    own_process();
    let expired = || {
        Some(PolicyValidity {
            authorization_id: "test".to_owned(),
            authority: "test".to_owned(),
            reason: "an ended authorization".to_owned(),
            not_before: Instant::new(0, 0).expect("the epoch"),
            expires_at: Instant::new(1, 0).expect("one second later"),
        })
    };
    policy::republish(
        |verification| verification.validity = expired(),
        |signing| signing.validity = expired(),
    )
    .expect("the library policy compiles");
    for operation in [OPERATION_SIGN, OPERATION_VERIFY] {
        assert_eq!(set_key(operation, &[0x42; 32]), -1, "operation {operation}");
    }
}

#[test]
fn a_verification_key_needs_the_preset_key_source() {
    // A key set on a verifying transform is one the caller resolved: a
    // verification policy without that source refuses it, as the asymmetric
    // signature transforms do. Signing has no key-source rule.
    own_process();
    policy::republish(
        |verification| {
            verification
                .key_sources
                .remove(xml_sec::policy::KeySourceKind::PresetKey);
        },
        |_| {},
    )
    .expect("the library policy compiles");
    assert_eq!(set_key(OPERATION_VERIFY, &[0x42; 32]), -1);
    assert_eq!(set_key(OPERATION_SIGN, &[0x42; 32]), 0);
}

/// `readNode` of an HMAC-SHA256 transform of `operation` over a signature
/// method truncated to `bits`.
fn read_output_length(operation: c_int, bits: usize) -> c_int {
    let xml = format!(
        "<SignatureMethod xmlns=\"http://www.w3.org/2000/09/xmldsig#\" \
         Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\">\
         <HMACOutputLength>{bits}</HMACOutputLength></SignatureMethod>"
    );
    // SAFETY: every object is created and released here.
    unsafe {
        let doc = xsReadMemory(
            xml.as_ptr().cast(),
            c_int::try_from(xml.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null(), "the document parses");
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, hmac_sha256());
        (*transform).operation = operation;
        let result = read_node(transform, xsDocGetRootElement(doc).cast(), ctx);
        xmlSecTransformCtxDestroy(ctx);
        xsFreeDoc(doc);
        result
    }
}

#[test]
fn an_output_length_is_read_under_the_policy_of_the_operation() {
    // A signing transform takes its output length from the signing policy:
    // a length the verification policy admits but the signing policy does
    // not is refused when signing and still read when verifying.
    own_process();
    // Half the SHA-256 output, the shortest truncation the method permits.
    let bits = 128;
    policy::republish(|_| {}, |signing| signing.hmac.minimum_output_bits = 256)
        .expect("the library policy compiles");
    assert_eq!(read_output_length(OPERATION_VERIFY, bits), 0);
    assert_eq!(read_output_length(OPERATION_SIGN, bits), -1);
}

#[test]
fn a_run_admits_the_key_again_under_its_own_policy() {
    // A key admitted when it was set is admitted again under the revision
    // the run starts with: a minimum raised in between refuses the run.
    own_process();
    for operation in [OPERATION_SIGN, OPERATION_VERIFY] {
        // SAFETY: every object is created and released here.
        unsafe {
            let key = xmlSecKeyCreate();
            let data = xmlSecKeyDataCreate(symkeys::hmac());
            let secret = [0x42_u8; 32];
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
            assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
            xmlSecTransformHmacSetMinOutputBitsSize(512);
            assert_eq!(
                xmlSecTransformCtxBinaryExecute(ctx, b"data".as_ptr(), 4),
                -1,
                "operation {operation}"
            );
            xmlSecTransformHmacSetMinOutputBitsSize(0);
            xmlSecTransformCtxDestroy(ctx);
            xmlSecKeyDestroy(key);
        }
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
