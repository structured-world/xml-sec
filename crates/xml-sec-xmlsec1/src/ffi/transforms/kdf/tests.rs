use super::super::super::buffer::{xmlSecBufferAppend, xmlSecBufferIsSecure};
use super::super::super::keys::{xmlSecKeyDestroy, xmlSecKeyReadMemory};
use super::super::super::policy::Pinned;
use super::super::ctx::{
    pin_run, run_spent, seed_run, xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxCreate,
    xmlSecTransformCtxCreateAndAppend, xmlSecTransformCtxDestroy,
};
use super::super::{xmlSecTransformCreate, xmlSecTransformDestroy, xmlSecTransformSetKey};
use super::*;
use xml_sec::provider::{CryptoProvider, KdfContext, KdfParameters, RUST_CRYPTO_PROVIDER};

const PBKDF2_SHA256: &str = "<KeyDerivationMethod xmlns=\"http://www.w3.org/2009/xmlenc11#\" \
     Algorithm=\"http://www.w3.org/2009/xmlenc11#pbkdf2\"><PBKDF2-params><Salt>\
     <Specified>c2FsdA==</Specified></Salt><IterationCount>2</IterationCount>\
     <KeyLength>32</KeyLength>\
     <PRF Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>\
     </PBKDF2-params></KeyDerivationMethod>";

/// `PBKDF2_SHA256` at one iteration: cheaper than it.
const PBKDF2_ONE_ITERATION: &str = "<KeyDerivationMethod \
     xmlns=\"http://www.w3.org/2009/xmlenc11#\" \
     Algorithm=\"http://www.w3.org/2009/xmlenc11#pbkdf2\"><PBKDF2-params><Salt>\
     <Specified>c2FsdA==</Specified></Salt><IterationCount>1</IterationCount>\
     <KeyLength>32</KeyLength>\
     <PRF Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256\"/>\
     </PBKDF2-params></KeyDerivationMethod>";

const SECRET: &[u8] = b"the master key";

/// The PBKDF2 key `PBKDF2_SHA256` names, computed by the provider itself.
fn expected_pbkdf2() -> Vec<u8> {
    RUST_CRYPTO_PROVIDER
        .derive_key(
            &KdfParameters {
                algorithm: "http://www.w3.org/2009/xmlenc11#pbkdf2",
                digest: Some("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"),
                salt: b"salt",
                info: KdfContext::Octets(&[]),
                iterations: 2,
                output_len: 32,
            },
            SECRET,
        )
        .expect("the provider derives")
}

/// What one derivation by the `klass` transform on `method` yields, with the
/// transform's key built from `secret` of `key_id`: the derived octets, or
/// `None` when it fails. `prepare` adjusts the context and transform before
/// the run.
fn derive_with(
    klass: *const XmlSecTransformKlass,
    key_id: *const XmlSecKeyDataKlass,
    method: &str,
    secret: &[u8],
    prepare: impl FnOnce(*mut XmlSecTransformCtx, *mut XmlSecTransform),
) -> Option<(Vec<u8>, bool)> {
    // SAFETY: a document, a key, a context and its transform, created and
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
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, klass);
        (*transform).operation = OPERATION_DECRYPT;
        (*transform).expected_output_size = 32;
        prepare(ctx, transform);
        let node = xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc);
        let key = xmlSecKeyReadMemory(key_id, secret.as_ptr(), secret.len());
        assert!(!key.is_null(), "the key reads");
        let mut result = None;
        if read_node(transform, node, ctx) == 0
            && xmlSecTransformSetKey(transform, key.cast()) == 0
            && xmlSecTransformCtxBinaryExecute(ctx, std::ptr::null(), 0) == 0
        {
            let out = (*ctx).result;
            result = Some((
                std::slice::from_raw_parts(xmlSecBufferGetData(out), xmlSecBufferGetSize(out))
                    .to_vec(),
                xmlSecBufferIsSecure(&raw mut (*transform).out_buf) != 0,
            ));
        }
        xmlSecKeyDestroy(key);
        xmlSecTransformCtxDestroy(ctx);
        xml_sec_libxml2::ffi::tree::xsFreeDoc(doc);
        result
    }
}

#[test]
fn a_derivation_yields_the_providers_key_in_a_secure_buffer() {
    // The klass derives what the core's PBKDF2 derives from the same
    // parameters and key, and holds it in a buffer marked secret, as
    // libxmlsec1 marks a derivation's buffers.
    let (derived, secure) = derive_with(
        pbkdf2(),
        symkeys::pbkdf2(),
        PBKDF2_SHA256,
        SECRET,
        |_, _| {},
    )
    .expect("the derivation runs");
    assert_eq!(derived, expected_pbkdf2());
    assert!(secure);
}

#[test]
fn a_derivation_needs_the_width_its_reader_expects() {
    // libxmlsec1 refuses a derivation whose reader named no width, and one
    // whose width differs from the method's KeyLength: the consuming
    // algorithm decides the key's width, never the method.
    for width in [0, 16] {
        assert!(
            derive_with(
                pbkdf2(),
                symkeys::pbkdf2(),
                PBKDF2_SHA256,
                SECRET,
                |_, transform| {
                    // SAFETY: the run's live transform.
                    unsafe { (*transform).expected_output_size = width };
                },
            )
            .is_none(),
            "width {width}"
        );
    }
}

#[test]
fn a_derivation_takes_no_input() {
    // Data pushed into a derivation is the caller's error: the derivation
    // fails rather than ignoring it.
    let refused = derive_with(
        pbkdf2(),
        symkeys::pbkdf2(),
        PBKDF2_SHA256,
        SECRET,
        |_, transform| {
            // SAFETY: the run's live transform and its input buffer.
            unsafe {
                assert_eq!(
                    xmlSecBufferAppend(&raw mut (*transform).in_buf, b"x".as_ptr(), 1),
                    0
                );
            }
        },
    );
    assert!(refused.is_none());
}

#[test]
fn a_key_of_another_klass_is_refused() {
    // A PBKDF2 derivation takes a PBKDF2 key, as libxmlsec1 asserts; an
    // HKDF key with the same bytes is not set.
    assert!(derive_with(pbkdf2(), symkeys::hkdf(), PBKDF2_SHA256, SECRET, |_, _| {}).is_none());
}

#[test]
fn the_policy_decides_whether_a_derivation_runs() {
    // The run's policy admits the derivation algorithm: one it does not list
    // is refused before the provider derives anything.
    let mut pinned = Pinned::current(here!("test")).expect("the library policy compiles");
    std::sync::Arc::make_mut(&mut pinned.decryption)
        .key_establishment
        .derivation_algorithms = Some(std::collections::BTreeSet::new());
    let refused = derive_with(
        pbkdf2(),
        symkeys::pbkdf2(),
        PBKDF2_SHA256,
        SECRET,
        |ctx, _| {
            // SAFETY: the run's live context.
            unsafe { pin_run(ctx, &pinned) };
        },
    );
    assert!(refused.is_none());
}

#[test]
fn one_operation_spends_one_derivation_allowance() {
    // An operation that derives in several parts carries its reservations
    // from one part to the next: what the first part's run spent, seeded into
    // the second part's run, leaves the second derivation no allowance.
    let mut pinned = Pinned::current(here!("test")).expect("the library policy compiles");
    // PBKDF2 at two iterations costs six hash blocks for a 32-octet SHA-256
    // key: the allowance admits one such derivation.
    std::sync::Arc::make_mut(&mut pinned.decryption)
        .key_establishment
        .max_hash_blocks = 6;
    // SAFETY: contexts created and released here.
    unsafe {
        let first = xmlSecTransformCtxCreate();
        pin_run(first, &pinned);
        assert_eq!(execute_once(first, PBKDF2_SHA256), 0);
        let earlier = run_spent(first);
        xmlSecTransformCtxDestroy(first);
        let second = xmlSecTransformCtxCreate();
        seed_run(
            second,
            &pinned,
            crate::ffi::policy::Side::Decrypt,
            None,
            earlier,
        );
        assert_eq!(execute_once(second, PBKDF2_SHA256), -1);
        assert_eq!(
            run_spent(second).refused_by.map(|limit| limit.name),
            Some("key establishment hash blocks")
        );
        xmlSecTransformCtxDestroy(second);
    }
}

#[test]
fn a_refused_operation_derives_nothing_more() {
    // A refusal ends the operation: a later derivation on the same context
    // is refused too, though it is cheap enough that a fresh context admits
    // it.
    let mut pinned = Pinned::current(here!("test")).expect("the library policy compiles");
    std::sync::Arc::make_mut(&mut pinned.decryption)
        .key_establishment
        .max_hash_blocks = 5;
    // SAFETY: contexts created and released here.
    unsafe {
        let fresh = xmlSecTransformCtxCreate();
        pin_run(fresh, &pinned);
        assert_eq!(execute_once(fresh, PBKDF2_ONE_ITERATION), 0);
        xmlSecTransformCtxDestroy(fresh);
        let ctx = xmlSecTransformCtxCreate();
        pin_run(ctx, &pinned);
        assert_eq!(execute_once(ctx, PBKDF2_SHA256), -1);
        assert_eq!(execute_once(ctx, PBKDF2_ONE_ITERATION), -1);
        xmlSecTransformCtxDestroy(ctx);
    }
}

#[test]
fn a_derivation_read_before_its_chain_runs_under_its_operation() {
    // A reader that names the operation reads the method before it appends
    // the transform, so the chain is still empty: the derivation runs under
    // the policy of that operation, here a decryption admitting none, not
    // under verification's.
    let mut pinned = Pinned::current(here!("test")).expect("the library policy compiles");
    std::sync::Arc::make_mut(&mut pinned.decryption)
        .key_establishment
        .derivation_algorithms = Some(std::collections::BTreeSet::new());
    // SAFETY: a context created and released here.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        pin_run(ctx, &pinned);
        assert_eq!(execute_once(ctx, PBKDF2_SHA256), -1);
        xmlSecTransformCtxDestroy(ctx);
    }
}

#[test]
fn a_refused_allowance_ends_the_operation() {
    // The limit that refused a derivation is the operation's: the run
    // records it, so its later reads fail naming it.
    let mut pinned = Pinned::current(here!("test")).expect("the library policy compiles");
    std::sync::Arc::make_mut(&mut pinned.decryption)
        .key_establishment
        .max_hash_blocks = 5;
    // SAFETY: a context created and released here.
    let recorded = unsafe {
        let ctx = xmlSecTransformCtxCreate();
        pin_run(ctx, &pinned);
        let doc = xml_sec_libxml2::ffi::tree::xsReadMemory(
            PBKDF2_SHA256.as_ptr().cast(),
            c_int::try_from(PBKDF2_SHA256.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        let transform = xmlSecTransformCtxCreateAndAppend(ctx, pbkdf2());
        (*transform).operation = OPERATION_DECRYPT;
        (*transform).expected_output_size = 32;
        let key = xmlSecKeyReadMemory(symkeys::pbkdf2(), SECRET.as_ptr(), SECRET.len());
        let node = xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc);
        assert_eq!(read_node(transform, node, ctx), 0);
        assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
        assert_eq!(
            xmlSecTransformCtxBinaryExecute(ctx, std::ptr::null(), 0),
            -1
        );
        let recorded = run_spent(ctx).refused_by.map(|limit| limit.name);
        xmlSecKeyDestroy(key);
        xmlSecTransformCtxDestroy(ctx);
        xml_sec_libxml2::ffi::tree::xsFreeDoc(doc);
        recorded
    };
    assert_eq!(recorded, Some("key establishment hash blocks"));
}

/// What one decrypting PBKDF2 derivation of `method` from [`SECRET`] returns
/// as a part of the run of `ctx`, its method read the way a reader naming the
/// operation reads it: before the transform joins any chain.
///
/// # Safety
/// `ctx` is an initialized context.
unsafe fn execute_once(ctx: *mut XmlSecTransformCtx, method: &str) -> c_int {
    // SAFETY: by the caller's contract; a document, a key and a transform
    // created and released here.
    unsafe {
        let doc = xml_sec_libxml2::ffi::tree::xsReadMemory(
            method.as_ptr().cast(),
            c_int::try_from(method.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        assert!(!doc.is_null());
        let transform = xmlSecTransformCreate(pbkdf2());
        (*transform).operation = OPERATION_DECRYPT;
        (*transform).expected_output_size = 32;
        let key = xmlSecKeyReadMemory(symkeys::pbkdf2(), SECRET.as_ptr(), SECRET.len());
        let node = xml_sec_libxml2::ffi::tree::xsDocGetRootElement(doc);
        // Reading the method and taking the key never consult the
        // derivation's allowance: a failure here is a broken setup, not the
        // refusal the callers assert.
        assert_eq!(read_node(transform, node, ctx), 0);
        assert_eq!(xmlSecTransformSetKey(transform, key.cast()), 0);
        let done = execute(transform, 1, ctx);
        xmlSecKeyDestroy(key);
        xmlSecTransformDestroy(transform);
        xml_sec_libxml2::ffi::tree::xsFreeDoc(doc);
        done
    }
}
