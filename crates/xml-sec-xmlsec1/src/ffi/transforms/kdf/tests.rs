use super::super::super::buffer::{xmlSecBufferAppend, xmlSecBufferIsSecure};
use super::super::super::keys::{xmlSecKeyDestroy, xmlSecKeyReadMemory};
use super::super::super::policy::Pinned;
use super::super::ctx::{
    pin_run, run_spent, seed_run, xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxCreate,
    xmlSecTransformCtxCreateAndAppend, xmlSecTransformCtxDestroy,
};
use super::super::xmlSecTransformSetKey;
use super::*;
use xml_sec::provider::{CryptoProvider, KdfContext, KdfParameters, RUST_CRYPTO_PROVIDER};

const PBKDF2_SHA256: &str = "<KeyDerivationMethod xmlns=\"http://www.w3.org/2009/xmlenc11#\" \
     Algorithm=\"http://www.w3.org/2009/xmlenc11#pbkdf2\"><PBKDF2-params><Salt>\
     <Specified>c2FsdA==</Specified></Salt><IterationCount>2</IterationCount>\
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
    // from one part to the next: the second derivation is refused once the
    // first spent the allowance, and the refusal ends the operation.
    let mut pinned = Pinned::current(here!("test")).expect("the library policy compiles");
    // PBKDF2 at two iterations costs six hash blocks for a 32-octet SHA-256
    // key: the allowance admits one such derivation.
    std::sync::Arc::make_mut(&mut pinned.decryption)
        .key_establishment
        .max_hash_blocks = 6;
    let earlier = crate::ffi::policy::Spent {
        key_establishment: derived_usage(&pinned),
        ..crate::ffi::policy::Spent::default()
    };
    let run = |spent: crate::ffi::policy::Spent| {
        derive_with(
            pbkdf2(),
            symkeys::pbkdf2(),
            PBKDF2_SHA256,
            SECRET,
            |ctx, _| {
                // SAFETY: the run's live context.
                unsafe { seed_run(ctx, &pinned, crate::ffi::policy::Side::Decrypt, None, spent) };
            },
        )
    };
    assert!(run(crate::ffi::policy::Spent::default()).is_some());
    assert!(run(earlier).is_none());
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

/// What one PBKDF2 derivation of `PBKDF2_SHA256` reserves under `pinned`.
fn derived_usage(pinned: &Pinned) -> xml_sec::key_establishment::KeyEstablishmentUsage {
    let document = xml_sec::Document::parse(PBKDF2_SHA256).expect("the method parses");
    let method =
        KeyDerivationMethod::from_element(document.root_element(), &pinned.decryption.resources)
            .expect("the method reads");
    let mut usage = xml_sec::key_establishment::KeyEstablishmentUsage::default();
    derive(
        &method,
        32,
        SECRET,
        &pinned.decryption.key_establishment,
        &mut usage,
    )
    .expect("one derivation fits");
    usage
}
