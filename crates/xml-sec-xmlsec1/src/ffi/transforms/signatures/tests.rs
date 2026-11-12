//! The signature klasses bound the signed bytes they collect by the library
//! policy, and sign and verify any message, the empty one included. A test
//! that republishes the library policy runs in a process of its own.

use std::ffi::c_int;

use crate::ffi::tests::own_process;

use super::super::super::app::key_load_memory;
use super::super::super::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize};
use super::super::super::keys::{XmlSecKey, xmlSecKeyDestroy};
use super::super::super::policy;
use super::super::ctx::{
    xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxCreate, xmlSecTransformCtxCreateAndAppend,
    xmlSecTransformCtxDestroy,
};
use super::super::{
    OPERATION_SIGN, OPERATION_VERIFY, STATUS_OK, xmlSecTransformPushBin, xmlSecTransformSetKey,
    xmlSecTransformVerify,
};
use super::rsa_sha256;
use xml_sec::policy::{Instant, PolicyValidity};
use xml_sec::xmldsig::SignatureAlgorithm;

/// `xmlSecKeyDataFormatPem`.
const FORMAT_PEM: c_int = 2;

/// The key a PEM fixture holds.
fn key(pem: &[u8]) -> *mut XmlSecKey {
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

fn private_key() -> *mut XmlSecKey {
    key(include_bytes!(
        "../../../../../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
    ))
}

fn public_key() -> *mut XmlSecKey {
    key(include_bytes!(
        "../../../../../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"
    ))
}

/// Runs RSA-SHA256 in `operation` with `key` over `input`; the signature
/// value when signing, the status when verifying `value`.
fn run(
    operation: c_int,
    key: *mut XmlSecKey,
    input: &[u8],
    value: &[u8],
) -> Result<Vec<u8>, c_int> {
    // SAFETY: every object is created and released here.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_sha256());
        (*transform).operation = operation;
        let mut result = Err(-1);
        if xmlSecTransformSetKey(transform, key.cast()) == 0
            && xmlSecTransformCtxBinaryExecute(ctx, input.as_ptr(), input.len()) == 0
        {
            result = if operation == OPERATION_SIGN {
                let output = (*ctx).result;
                Ok(std::slice::from_raw_parts(
                    xmlSecBufferGetData(output),
                    xmlSecBufferGetSize(output),
                )
                .to_vec())
            } else if xmlSecTransformVerify(transform, value.as_ptr(), value.len(), ctx) == 0 {
                Err((*transform).status)
            } else {
                Err(-1)
            };
        }
        xmlSecTransformCtxDestroy(ctx);
        xmlSecKeyDestroy(key);
        result
    }
}

#[test]
fn the_signed_bytes_are_bounded_by_the_policy() {
    // Collected input beyond the policy's canonicalized-bytes limit is
    // refused before the buffer grows.
    own_process();
    policy::republish(
        |verification| verification.resources.max_canonicalized_bytes = 8,
        |signing| signing.resources.max_canonicalized_bytes = 8,
    )
    .expect("the library policy compiles");
    assert_eq!(
        run(OPERATION_SIGN, private_key(), &[0x41; 16], &[]),
        Err(-1)
    );
    assert_eq!(
        run(OPERATION_VERIFY, public_key(), &[0x41; 16], &[0; 256]),
        Err(-1)
    );
}

#[test]
fn a_run_keeps_the_policy_it_started_under() {
    // A policy republished between two chunks of one verifying run reaches
    // neither the bound on the collected bytes nor the verification: the run
    // finishes under the snapshot it took at its first chunk.
    own_process();
    let value = run(OPERATION_SIGN, private_key(), &[0x41; 16], &[]).expect("the message signs");
    let key = public_key();
    // SAFETY: every object is created and released here.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_sha256());
        (*transform).operation = OPERATION_VERIFY;
        assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
        let half = [0x41_u8; 8];
        assert_eq!(
            xmlSecTransformPushBin(transform, half.as_ptr(), half.len(), 0, ctx),
            0
        );
        policy::republish(
            |verification| {
                verification.resources.max_canonicalized_bytes = 8;
                if let Some(methods) = verification.signature_algorithms.as_mut() {
                    methods.remove(&SignatureAlgorithm::RsaSha256);
                }
            },
            |_| {},
        )
        .expect("the library policy compiles");
        assert_eq!(
            xmlSecTransformPushBin(transform, half.as_ptr(), half.len(), 1, ctx),
            0
        );
        assert_eq!(
            xmlSecTransformVerify(transform, value.as_ptr(), value.len(), ctx),
            0
        );
        assert_eq!((*transform).status, STATUS_OK);
        xmlSecTransformCtxDestroy(ctx);
        xmlSecKeyDestroy(key);
    }
}

#[test]
fn a_run_under_a_policy_not_in_force_takes_no_input() {
    // A run whose policy has expired is refused at its first chunk, before
    // any byte is collected, as a digest run is.
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
    for (operation, key) in [
        (OPERATION_SIGN, private_key()),
        (OPERATION_VERIFY, public_key()),
    ] {
        // SAFETY: every object is created and released here.
        unsafe {
            let ctx = xmlSecTransformCtxCreate();
            let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_sha256());
            (*transform).operation = operation;
            assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
            let chunk = [0x41_u8; 8];
            assert_eq!(
                xmlSecTransformPushBin(transform, chunk.as_ptr(), chunk.len(), 0, ctx),
                -1,
                "operation {operation}"
            );
            xmlSecTransformCtxDestroy(ctx);
            xmlSecKeyDestroy(key);
        }
    }
}

#[test]
fn a_signature_over_the_empty_message_verifies() {
    // The empty message is signed and its signature verifies, as libxmlsec1
    // accepts it.
    let value = run(OPERATION_SIGN, private_key(), &[], &[]).expect("the empty message signs");
    assert_eq!(
        run(OPERATION_VERIFY, public_key(), &[], &value),
        Err(STATUS_OK)
    );
}
