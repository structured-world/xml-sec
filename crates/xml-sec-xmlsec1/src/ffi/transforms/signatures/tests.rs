//! The signature klasses bound the signed bytes they collect by the library
//! policy, and sign and verify any message, the empty one included. A test
//! that republishes the library policy runs in a process of its own.

use std::ffi::c_int;

use crate::ffi::tests::own_process;

use super::super::super::app::key_load_memory;
use super::super::super::buffer::{xmlSecBufferAppend, xmlSecBufferGetData, xmlSecBufferGetSize};
use super::super::super::keys::{XmlSecKey, xmlSecKeyDestroy};
use super::super::super::policy;
use super::super::ctx::{
    xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxCreate, xmlSecTransformCtxCreateAndAppend,
    xmlSecTransformCtxDestroy,
};
use super::super::{
    OPERATION_SIGN, OPERATION_VERIFY, STATUS_OK, xmlSecTransformExecute, xmlSecTransformPushBin,
    xmlSecTransformSetKey, xmlSecTransformVerify,
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
    run_with_flags(0, operation, key, input, value)
}

/// [`run`] in a context with the transform context flags `flags`.
fn run_with_flags(
    flags: std::ffi::c_uint,
    operation: c_int,
    key: *mut XmlSecKey,
    input: &[u8],
    value: &[u8],
) -> Result<Vec<u8>, c_int> {
    // SAFETY: every object is created and released here.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        (*ctx).flags = flags;
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
fn a_signing_chain_runs_under_the_signing_policy() {
    // The chain's shared limits come from the operation it serves: with a
    // signing limit of one transform and a verification limit of sixteen, a
    // two-transform chain is refused when it signs and runs when it verifies.
    own_process();
    policy::republish(
        |verification| verification.resources.max_transforms_per_reference = 16,
        |signing| signing.resources.max_transforms_per_reference = 1,
    )
    .expect("the library policy compiles");
    let input = b"QUFB";
    for (operation, key, expected) in [
        (OPERATION_SIGN, private_key(), -1),
        (OPERATION_VERIFY, public_key(), 0),
    ] {
        // SAFETY: every object is created and released here.
        unsafe {
            let ctx = xmlSecTransformCtxCreate();
            let base64 = xmlSecTransformCtxCreateAndAppend(
                ctx,
                super::super::builtin::xmlSecTransformBase64GetKlass(),
            );
            (*base64).operation = super::super::OPERATION_DECODE;
            let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_sha256());
            (*transform).operation = operation;
            assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
            assert_eq!(
                xmlSecTransformCtxBinaryExecute(ctx, input.as_ptr(), input.len()),
                expected,
                "operation {operation}"
            );
            xmlSecTransformCtxDestroy(ctx);
            xmlSecKeyDestroy(key);
        }
    }
}

#[test]
fn a_verification_key_drops_the_private_key_set_before() {
    // The last key set is the transform's key: a public key installed after
    // a private one leaves nothing to sign with, so switching the operation
    // back cannot sign with the earlier key.
    let (private, public) = (private_key(), public_key());
    // SAFETY: every object is created and released here.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_sha256());
        (*transform).operation = OPERATION_SIGN;
        assert_eq!(xmlSecTransformSetKey(transform, private.cast()), 0);
        (*transform).operation = OPERATION_VERIFY;
        assert_eq!(xmlSecTransformSetKey(transform, public.cast()), 0);
        (*transform).operation = OPERATION_SIGN;
        let input = [0x41_u8; 16];
        assert_eq!(
            xmlSecTransformCtxBinaryExecute(ctx, input.as_ptr(), input.len()),
            -1
        );
        xmlSecTransformCtxDestroy(ctx);
        xmlSecKeyDestroy(private);
        xmlSecKeyDestroy(public);
    }
}

#[test]
fn a_signing_key_the_policy_refuses_takes_no_input() {
    // The key is admitted under the run's policy before the first chunk: an
    // RSA-2048 key under a 4096-bit minimum is refused there, not after the
    // input was collected.
    own_process();
    policy::republish(
        |_| {},
        |signing| signing.rsa_keys.minimum_modulus_bits = 4096,
    )
    .expect("the library policy compiles");
    let key = private_key();
    // SAFETY: every object is created and released here.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_sha256());
        (*transform).operation = OPERATION_SIGN;
        assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
        let chunk = [0x41_u8; 8];
        assert_eq!(
            xmlSecTransformPushBin(transform, chunk.as_ptr(), chunk.len(), 0, ctx),
            -1
        );
        xmlSecTransformCtxDestroy(ctx);
        xmlSecKeyDestroy(key);
    }
}

#[test]
fn a_key_set_while_signing_leaves_the_run_its_key() {
    // As libxmlsec1 binds the key to its signing context when a run starts,
    // a key set between two chunks of a run reaches the next run, not this
    // one: the run still signs with the key it was admitted with.
    let (first, second) = (private_key(), private_key());
    let input = [0x41_u8; 16];
    // SAFETY: every object is created and released here.
    let value = unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_sha256());
        (*transform).operation = OPERATION_SIGN;
        // The value passes on to a memory buffer, as a pushed run's output
        // leaves its transform.
        let sink = xmlSecTransformCtxCreateAndAppend(
            ctx,
            super::super::builtin::xmlSecTransformMemBufGetKlass(),
        );
        assert_eq!(xmlSecTransformSetKey(transform, first.cast()), 0);
        assert_eq!(
            xmlSecTransformPushBin(transform, input.as_ptr(), 8, 0, ctx),
            0
        );
        assert_eq!(xmlSecTransformSetKey(transform, second.cast()), 0);
        assert_eq!(
            xmlSecTransformPushBin(transform, input[8..].as_ptr(), 8, 1, ctx),
            0,
            "the run signs"
        );
        let output = super::super::builtin::xmlSecTransformMemBufGetBuffer(sink);
        let value =
            std::slice::from_raw_parts(xmlSecBufferGetData(output), xmlSecBufferGetSize(output))
                .to_vec();
        xmlSecTransformCtxDestroy(ctx);
        xmlSecKeyDestroy(first);
        xmlSecKeyDestroy(second);
        value
    };
    assert_eq!(
        run(OPERATION_VERIFY, public_key(), &input, &value),
        Err(STATUS_OK)
    );
}

#[test]
fn a_key_set_while_verifying_leaves_the_run_its_key() {
    // A verifying run checks the value with the key it started with, as
    // libxmlsec1 binds it to its verification context: a key set between
    // two chunks, or after the last one, changes nothing the run accepts.
    let input = [0x41_u8; 16];
    let value = run(OPERATION_SIGN, private_key(), &input, &[]).expect("the message signs");
    let (first, other, late) = (
        public_key(),
        key(include_bytes!(
            "../../../../../../tests/fixtures/keys/rsa/rsa-4096-pubkey.pem"
        )),
        key(include_bytes!(
            "../../../../../../tests/fixtures/keys/rsa/rsa-4096-pubkey.pem"
        )),
    );
    // SAFETY: every object is created and released here.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_sha256());
        (*transform).operation = OPERATION_VERIFY;
        assert_eq!(xmlSecTransformSetKey(transform, first.cast()), 0);
        assert_eq!(
            xmlSecTransformPushBin(transform, input.as_ptr(), 8, 0, ctx),
            0
        );
        assert_eq!(xmlSecTransformSetKey(transform, other.cast()), 0);
        assert_eq!(
            xmlSecTransformPushBin(transform, input[8..].as_ptr(), 8, 1, ctx),
            0
        );
        assert_eq!(xmlSecTransformSetKey(transform, late.cast()), 0);
        assert_eq!(
            xmlSecTransformVerify(transform, value.as_ptr(), value.len(), ctx),
            0
        );
        assert_eq!((*transform).status, STATUS_OK, "the run's own key verifies");
        xmlSecTransformCtxDestroy(ctx);
        for key in [first, other, late] {
            xmlSecKeyDestroy(key);
        }
    }
}

#[test]
fn an_ecdsa_value_follows_the_signing_policy_encoding() {
    // The transform writes the representation the signing policy selects, as
    // document signing does: fixed-width r || s by default, an ASN.1 DER
    // SEQUENCE when the policy asks for it.
    own_process();
    let sign = || {
        let key = key(include_bytes!(
            "../../../../../../tests/fixtures/keys/ec/ec-prime256v1-key.pem"
        ));
        // SAFETY: every object is created and released here.
        unsafe {
            let ctx = xmlSecTransformCtxCreate();
            let transform = xmlSecTransformCtxCreateAndAppend(ctx, super::ecdsa_sha256());
            (*transform).operation = OPERATION_SIGN;
            assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
            let input = [0x41_u8; 16];
            assert_eq!(
                xmlSecTransformCtxBinaryExecute(ctx, input.as_ptr(), input.len()),
                0
            );
            let output = (*ctx).result;
            let value = std::slice::from_raw_parts(
                xmlSecBufferGetData(output),
                xmlSecBufferGetSize(output),
            )
            .to_vec();
            xmlSecTransformCtxDestroy(ctx);
            xmlSecKeyDestroy(key);
            value
        }
    };
    assert_eq!(sign().len(), 64, "r || s of P-256");
    policy::republish(
        |_| {},
        |signing| {
            signing.ecdsa_signature_value_encoding =
                xml_sec::policy::EcdsaSignatureValueEncoding::XmlSecAsn1Der;
        },
    )
    .expect("the library policy compiles");
    assert_eq!(sign().first(), Some(&0x30), "a DER SEQUENCE");
}

#[test]
fn the_empty_message_is_signed_only_when_the_context_allows_it() {
    // Signing or verifying nothing is refused by default; a context with
    // XMLSEC_TRANSFORMCTX_FLAGS_ALLOW_EMPTY_INPUT signs the empty message and
    // its signature verifies.
    assert_eq!(run(OPERATION_SIGN, private_key(), &[], &[]), Err(-1));
    assert_eq!(run(OPERATION_VERIFY, public_key(), &[], &[0; 256]), Err(-1));
    let allow = crate::ffi::transforms::ctx::FLAGS_ALLOW_EMPTY_INPUT;
    let value = run_with_flags(allow, OPERATION_SIGN, private_key(), &[], &[])
        .expect("the empty message signs");
    assert_eq!(
        run_with_flags(allow, OPERATION_VERIFY, public_key(), &[], &value),
        Err(STATUS_OK)
    );
}

#[test]
fn a_policy_refusing_empty_digest_input_overrides_the_contexts_permission() {
    // The context flag allows the empty message only while the operation's
    // policy accepts empty digest input: a policy that refuses it refuses
    // signing and verifying nothing even in a context that allows it.
    own_process();
    let refuse = xml_sec::policy::EmptyDigestInput::Refuse;
    policy::republish(
        |verification| verification.transforms.empty_digest_input = refuse,
        |signing| signing.transforms.empty_digest_input = refuse,
    )
    .expect("the library policy compiles");
    let allow = crate::ffi::transforms::ctx::FLAGS_ALLOW_EMPTY_INPUT;
    assert_eq!(
        run_with_flags(allow, OPERATION_SIGN, private_key(), &[], &[]),
        Err(-1)
    );
    assert_eq!(
        run_with_flags(allow, OPERATION_VERIFY, public_key(), &[], &[0; 256]),
        Err(-1)
    );
    assert!(run(OPERATION_SIGN, private_key(), b"data", &[]).is_ok());
}

#[test]
fn input_a_caller_buffered_itself_is_not_empty() {
    // Bytes appended to the transform's input buffer and executed as the
    // last chunk are input like pushed bytes: they are signed, not refused
    // as empty, and give the signature pushing them gives.
    let message = b"buffered by the caller";
    let pushed = run(OPERATION_SIGN, private_key(), message, &[]).expect("pushed bytes sign");
    // SAFETY: every object is created and released here.
    let buffered = unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, rsa_sha256());
        (*transform).operation = OPERATION_SIGN;
        let key = private_key();
        assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
        assert_eq!(
            xmlSecBufferAppend(
                &raw mut (*transform).in_buf,
                message.as_ptr(),
                message.len()
            ),
            0
        );
        let executed = xmlSecTransformExecute(transform, 1, ctx);
        let output = &raw mut (*transform).out_buf;
        let signature = if executed == 0 {
            std::slice::from_raw_parts(xmlSecBufferGetData(output), xmlSecBufferGetSize(output))
                .to_vec()
        } else {
            Vec::new()
        };
        xmlSecTransformCtxDestroy(ctx);
        xmlSecKeyDestroy(key);
        assert_eq!(executed, 0, "buffered input is not empty");
        signature
    };
    assert_eq!(buffered, pushed);
}
