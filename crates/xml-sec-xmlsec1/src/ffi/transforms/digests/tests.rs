//! The digest klasses run only under a policy that admits them: the method
//! must be one the operation's policy allows, and the snapshot itself must be
//! in force. A test that republishes the library policy runs in a process of
//! its own.

use std::collections::BTreeSet;
use std::ffi::c_int;

use xml_sec::policy::{Instant, PolicyValidity};
use xml_sec::xmldsig::DigestAlgorithm;

use crate::ffi::tests::own_process;

use super::super::super::policy;
use super::super::ctx::{
    xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxCreate, xmlSecTransformCtxCreateAndAppend,
    xmlSecTransformCtxDestroy,
};
use super::super::{OPERATION_SIGN, OPERATION_VERIFY};
use super::sha256;

/// Runs SHA-256 in `operation` over a short message.
fn run(operation: c_int) -> c_int {
    // SAFETY: every object is created and released here.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, sha256());
        (*transform).operation = operation;
        let status = xmlSecTransformCtxBinaryExecute(ctx, b"message".as_ptr(), 7);
        xmlSecTransformCtxDestroy(ctx);
        status
    }
}

#[test]
fn a_digest_the_policy_excludes_is_refused() {
    // A provider able to hash SHA-256 is not enough: the operation's policy
    // must list the method, as the core refuses a Reference digest it omits.
    own_process();
    for operation in [OPERATION_SIGN, OPERATION_VERIFY] {
        assert_eq!(run(operation), 0, "operation {operation}");
    }
    let only_sha512 = || Some(BTreeSet::from([DigestAlgorithm::Sha512]));
    policy::republish(
        |verification| verification.digest_algorithms = only_sha512(),
        |signing| signing.digest_algorithms = only_sha512(),
    )
    .expect("the library policy compiles");
    for operation in [OPERATION_SIGN, OPERATION_VERIFY] {
        assert_eq!(run(operation), -1, "operation {operation}");
    }
}

#[test]
fn a_digest_under_an_expired_policy_is_refused() {
    // A snapshot whose authorized lifetime has ended admits nothing, as a
    // core operation checks the lifetime at entry.
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
        assert_eq!(run(operation), -1, "operation {operation}");
    }
}
