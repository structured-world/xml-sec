//! CRL checking in the X.509 store needs the caller's UTC history: without
//! it a CRL that applies to a path refuses the path; with it the path is
//! checked against the CRL.

use xml_sec_libxml2::ffi::tree::{xsDocGetRootElement, xsFreeDoc, xsReadMemory};

use super::load::{
    TYPE_TRUSTED, default_keys_mngr_adopt_key, default_keys_mngr_init, key_from_certificate,
    keys_mngr_cert_load_memory, keys_mngr_crl_load_memory, keys_mngr_init,
    xsKeysMngrUtcFactsLoadMemory,
};
use super::{FORMAT_DER, FORMAT_PEM, mngr_state, verify, x509_data};
use crate::ffi::errors::here;
use crate::ffi::keyinfo::{xmlSecKeyInfoCtxCreate, xmlSecKeyInfoCtxDestroy, xmlSecKeyInfoNodeRead};
use crate::ffi::keys::{xmlSecKeyCreate, xmlSecKeyDestroy, xmlSecKeyGetValue};
use crate::ffi::keysmngr::{xmlSecKeysMngrCreate, xmlSecKeysMngrDestroy};
use crate::ffi::list::xmlSecPtrListAdd;
use crate::ffi::policy;

const ROOT: &[u8] = include_bytes!("../../../../../tests/fixtures/x509/delta-crl/ca.der");
const LEAF: &[u8] = include_bytes!("../../../../../tests/fixtures/x509/delta-crl/leaf.der");
/// A complete CRL of the root listing no certificate.
const CRL: &[u8] = include_bytes!("../../../../../tests/fixtures/x509/delta-crl/complete.crl");
/// A leap-seconds.list covering 2017-01-01 to 2100-01-01.
const LEAP_SECONDS: &[u8] = b"#@ 6311433600\n3692217600 37\n";
/// 2026-03-20T00:00:00Z, inside the validity of the certificates and CRL.
const AT: i64 = 1_773_964_800;

/// Whether the leaf verifies through the store of `mngr` at [`AT`].
///
/// # Safety
/// `mngr` is a keys manager with an X.509 store.
unsafe fn leaf_verifies(mngr: *mut crate::ffi::keysmngr::XmlSecKeysMngr) -> bool {
    let here = here!("test");
    let policy = policy::verification_at(here).expect("the library policy");
    // SAFETY: by the caller's contract; the context is destroyed here.
    unsafe {
        let ctx = xmlSecKeyInfoCtxCreate(mngr);
        (*ctx).certs_verification_time = super::time_of(AT).expect("a representable time");
        let state = mngr_state(mngr).expect("an X.509 store");
        let verified = verify(here, state, &[LEAF.to_vec()], &[], &*ctx, &policy)
            .expect("verification proceeds");
        xmlSecKeyInfoCtxDestroy(ctx);
        verified.is_some()
    }
}

#[test]
fn an_applicable_crl_needs_the_callers_utc_history() {
    // libxmlsec1 reads the system clock; this library takes the caller's
    // list, refusing the path until it has one and accepting a certificate
    // the CRL does not list once it has.
    // SAFETY: objects created and destroyed here; the slices outlive the calls.
    unsafe {
        let mngr = xmlSecKeysMngrCreate();
        assert_eq!(keys_mngr_init(mngr.cast()), 0);
        assert_eq!(
            keys_mngr_cert_load_memory(
                mngr.cast(),
                ROOT.as_ptr(),
                ROOT.len(),
                FORMAT_DER,
                TYPE_TRUSTED
            ),
            0
        );
        assert_eq!(
            keys_mngr_crl_load_memory(mngr.cast(), CRL.as_ptr(), CRL.len(), FORMAT_DER),
            0
        );
        assert!(!leaf_verifies(mngr));
        // A malformed list is refused and leaves the store without one.
        let malformed = b"3692217600 37\n";
        assert_eq!(
            xsKeysMngrUtcFactsLoadMemory(mngr, malformed.as_ptr(), malformed.len()),
            -1
        );
        assert!(mngr_state(mngr).expect("a store").utc_facts.is_none());
        assert_eq!(
            xsKeysMngrUtcFactsLoadMemory(mngr, LEAP_SECONDS.as_ptr(), LEAP_SECONDS.len()),
            0
        );
        assert!(leaf_verifies(mngr));
        xmlSecKeysMngrDestroy(mngr);
    }
}

#[test]
fn reloading_the_key_certificate_keeps_it_the_key_certificate() {
    // libxmlsec1 holds the key's certificate by identity: loading it again
    // moves it after the others, still the key's certificate.
    let (leaf, intermediate) = (b"leaf".to_vec(), b"intermediate".to_vec());
    let mut state = super::data::X509State::default();
    state.add_cert(leaf.clone(), true);
    state.add_cert(intermediate.clone(), false);
    state.add_cert(leaf.clone(), false);
    assert_eq!(state.certs, vec![intermediate.clone(), leaf.clone()]);
    assert_eq!(state.key_cert.map(|index| &state.certs[index]), Some(&leaf));
    // Another certificate moving keeps the key's certificate too.
    state.add_cert(intermediate.clone(), false);
    assert_eq!(state.key_cert.map(|index| &state.certs[index]), Some(&leaf));
}

#[test]
fn a_store_search_by_certificate_spends_the_candidate_allowance() {
    // Each stored key a certificate lookup inspects is a key candidate of
    // the read: with an allowance of one, the second key is never reached.
    const OTHER: &[u8] = include_bytes!("../../../../../tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    const WANTED: &[u8] =
        include_bytes!("../../../../../tests/fixtures/keys/rsa/rsa-2048-cert.pem");
    const XML: &str = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data>\
        <X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library \
        (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName>\
        </X509Data></KeyInfo>";
    crate::ffi::tests::own_process();
    let read = |max: usize| -> bool {
        policy::republish(
            |verification| verification.resources.max_key_candidates = max,
            |_| {},
        )
        .expect("the library policy compiles");
        // SAFETY: objects created and destroyed here; the key loader hands
        // its keys to the manager.
        unsafe {
            let here = here!("test");
            let mngr = xmlSecKeysMngrCreate();
            assert_eq!(default_keys_mngr_init(mngr.cast()), 0);
            for pem in [OTHER, WANTED] {
                let key = key_from_certificate(here, pem, FORMAT_PEM);
                assert!(!key.is_null(), "a key from the certificate");
                assert_eq!(default_keys_mngr_adopt_key(mngr.cast(), key), 0);
            }
            let ctx = xmlSecKeyInfoCtxCreate(mngr);
            let enabled = &raw mut (*ctx).enabled_key_data;
            assert_eq!(xmlSecPtrListAdd(enabled, x509_data().cast_mut().cast()), 0);
            let doc = xsReadMemory(
                XML.as_ptr().cast(),
                i32::try_from(XML.len()).expect("a short document"),
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
            let key = xmlSecKeyCreate();
            xmlSecKeyInfoNodeRead(xsDocGetRootElement(doc), key, ctx);
            let found = !xmlSecKeyGetValue(key).is_null();
            xmlSecKeyDestroy(key);
            xsFreeDoc(doc);
            xmlSecKeyInfoCtxDestroy(ctx);
            xmlSecKeysMngrDestroy(mngr);
            found
        }
    };
    assert!(read(2), "two candidates reach the wanted key");
    assert!(!read(1), "one candidate does not");
}

#[test]
fn every_carried_certificate_is_a_key_candidate() {
    // Certificates the document carries are charged like key values: an
    // X509Data with the leaf and its root needs an allowance of two.
    crate::ffi::tests::own_process();
    let encode = |der: &[u8]| -> String {
        // SAFETY: the encoder returns a NUL-terminated string it allocated,
        // copied and released here.
        unsafe {
            let text = crate::ffi::base64::xmlSecBase64Encode(der.as_ptr(), der.len(), 0);
            assert!(!text.is_null(), "the bytes encode");
            let owned = std::ffi::CStr::from_ptr(text.cast())
                .to_str()
                .expect("Base64 text")
                .to_owned();
            xml_sec_libxml2::ffi::memory::xsFree(text.cast());
            owned
        }
    };
    let xml = format!(
        "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data>\
         <X509Certificate>{}</X509Certificate><X509Certificate>{}</X509Certificate>\
         </X509Data></KeyInfo>",
        encode(LEAF),
        encode(ROOT)
    );
    let read = |max: usize| -> bool {
        policy::republish(
            |verification| verification.resources.max_key_candidates = max,
            |_| {},
        )
        .expect("the library policy compiles");
        // SAFETY: objects created and destroyed here.
        unsafe {
            let mngr = xmlSecKeysMngrCreate();
            assert_eq!(keys_mngr_init(mngr.cast()), 0);
            assert_eq!(
                keys_mngr_cert_load_memory(
                    mngr.cast(),
                    ROOT.as_ptr(),
                    ROOT.len(),
                    FORMAT_DER,
                    TYPE_TRUSTED
                ),
                0
            );
            let ctx = xmlSecKeyInfoCtxCreate(mngr);
            (*ctx).certs_verification_time = super::time_of(AT).expect("a representable time");
            let enabled = &raw mut (*ctx).enabled_key_data;
            assert_eq!(xmlSecPtrListAdd(enabled, x509_data().cast_mut().cast()), 0);
            let doc = xsReadMemory(
                xml.as_ptr().cast(),
                i32::try_from(xml.len()).expect("a short document"),
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
            let key = xmlSecKeyCreate();
            xmlSecKeyInfoNodeRead(xsDocGetRootElement(doc), key, ctx);
            let found = !xmlSecKeyGetValue(key).is_null();
            xmlSecKeyDestroy(key);
            xsFreeDoc(doc);
            xmlSecKeyInfoCtxDestroy(ctx);
            xmlSecKeysMngrDestroy(mngr);
            found
        }
    };
    assert!(read(2), "two candidates admit both certificates");
    assert!(!read(1), "one candidate does not");
}

#[test]
fn the_policy_decides_whether_a_crl_child_is_an_unknown_certificate() {
    // With XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT, libxmlsec1
    // stops on an X509CRL child, which names no certificate; its header
    // documents the flag for certificate references only. The policy picks.
    use xml_sec::policy::UnknownX509CertificateSemantics;
    const STOP_ON_UNKNOWN_CERT: std::ffi::c_uint = 0x0000_0400;
    crate::ffi::tests::own_process();
    let encode = |der: &[u8]| -> String {
        // SAFETY: the encoder returns a NUL-terminated string it allocated,
        // copied and released here.
        unsafe {
            let text = crate::ffi::base64::xmlSecBase64Encode(der.as_ptr(), der.len(), 0);
            assert!(!text.is_null(), "the bytes encode");
            let owned = std::ffi::CStr::from_ptr(text.cast())
                .to_str()
                .expect("Base64 text")
                .to_owned();
            xml_sec_libxml2::ffi::memory::xsFree(text.cast());
            owned
        }
    };
    let xml = format!(
        "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data>\
         <X509Certificate>{}</X509Certificate><X509CRL>{}</X509CRL>\
         </X509Data></KeyInfo>",
        encode(LEAF),
        encode(CRL)
    );
    let read = |semantics: UnknownX509CertificateSemantics| -> (std::ffi::c_int, bool) {
        policy::republish(
            |verification| verification.key_trust.unknown_x509_certificate = semantics,
            |_| {},
        )
        .expect("the library policy compiles");
        // SAFETY: objects created and destroyed here.
        unsafe {
            let mngr = xmlSecKeysMngrCreate();
            assert_eq!(keys_mngr_init(mngr.cast()), 0);
            assert_eq!(
                keys_mngr_cert_load_memory(
                    mngr.cast(),
                    ROOT.as_ptr(),
                    ROOT.len(),
                    FORMAT_DER,
                    TYPE_TRUSTED
                ),
                0
            );
            assert_eq!(
                xsKeysMngrUtcFactsLoadMemory(mngr, LEAP_SECONDS.as_ptr(), LEAP_SECONDS.len()),
                0
            );
            let ctx = xmlSecKeyInfoCtxCreate(mngr);
            (*ctx).flags = STOP_ON_UNKNOWN_CERT;
            (*ctx).certs_verification_time = super::time_of(AT).expect("a representable time");
            let enabled = &raw mut (*ctx).enabled_key_data;
            assert_eq!(xmlSecPtrListAdd(enabled, x509_data().cast_mut().cast()), 0);
            let doc = xsReadMemory(
                xml.as_ptr().cast(),
                i32::try_from(xml.len()).expect("a short document"),
                std::ptr::null(),
                std::ptr::null(),
                0,
            );
            let key = xmlSecKeyCreate();
            let result = xmlSecKeyInfoNodeRead(xsDocGetRootElement(doc), key, ctx);
            let found = !xmlSecKeyGetValue(key).is_null();
            xmlSecKeyDestroy(key);
            xsFreeDoc(doc);
            xmlSecKeyInfoCtxDestroy(ctx);
            xmlSecKeysMngrDestroy(mngr);
            (result, found)
        }
    };
    assert_eq!(
        read(UnknownX509CertificateSemantics::Libxmlsec1),
        (-1, false),
        "libxmlsec1 stops on the CRL"
    );
    assert_eq!(
        read(UnknownX509CertificateSemantics::References),
        (0, true),
        "the documented flag reads past it and the leaf verifies"
    );
}

/// Reads the `KeyInfo` of `xml` with `mngr` at [`AT`] under the current
/// library policy: the read's result and whether the key got a value.
///
/// # Safety
/// `mngr` is a keys manager.
unsafe fn read_key_info(
    mngr: *mut crate::ffi::keysmngr::XmlSecKeysMngr,
    xml: &str,
) -> (std::ffi::c_int, bool) {
    // SAFETY: by the caller's contract; the objects made here are released.
    unsafe {
        let ctx = xmlSecKeyInfoCtxCreate(mngr);
        (*ctx).certs_verification_time = super::time_of(AT).expect("a representable time");
        let enabled = &raw mut (*ctx).enabled_key_data;
        assert_eq!(xmlSecPtrListAdd(enabled, x509_data().cast_mut().cast()), 0);
        let doc = xsReadMemory(
            xml.as_ptr().cast(),
            i32::try_from(xml.len()).expect("a short document"),
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        let key = xmlSecKeyCreate();
        let result = xmlSecKeyInfoNodeRead(xsDocGetRootElement(doc), key, ctx);
        let found = !xmlSecKeyGetValue(key).is_null();
        xmlSecKeyDestroy(key);
        xsFreeDoc(doc);
        xmlSecKeyInfoCtxDestroy(ctx);
        (result, found)
    }
}

/// Sets the read's `max_key_candidates` and `max_external_resource_bytes`.
fn limits(candidates: usize, resource_bytes: usize) {
    policy::republish(
        |verification| {
            verification.resources.max_key_candidates = candidates;
            verification.resources.max_external_resource_bytes = resource_bytes;
        },
        |_| {},
    )
    .expect("the library policy compiles");
}

/// The default keys manager with [`ROOT`] trusted and `untrusted` loaded.
///
/// # Safety
/// Callable at any time; the caller destroys the manager.
unsafe fn default_manager(untrusted: &[&[u8]]) -> *mut crate::ffi::keysmngr::XmlSecKeysMngr {
    // SAFETY: a manager created here.
    unsafe {
        let mngr = xmlSecKeysMngrCreate();
        assert_eq!(default_keys_mngr_init(mngr.cast()), 0);
        assert_eq!(
            keys_mngr_cert_load_memory(
                mngr.cast(),
                ROOT.as_ptr(),
                ROOT.len(),
                FORMAT_DER,
                TYPE_TRUSTED
            ),
            0
        );
        for der in untrusted {
            assert_eq!(
                keys_mngr_cert_load_memory(mngr.cast(), der.as_ptr(), der.len(), FORMAT_DER, 0),
                0
            );
        }
        mngr
    }
}

/// [`LEAF`] in an `X509Certificate`.
fn carried_leaf() -> String {
    // SAFETY: the encoder returns a NUL-terminated string it allocated,
    // copied and released here.
    let text = unsafe {
        let text = crate::ffi::base64::xmlSecBase64Encode(LEAF.as_ptr(), LEAF.len(), 0);
        assert!(!text.is_null(), "the bytes encode");
        let owned = std::ffi::CStr::from_ptr(text.cast())
            .to_str()
            .expect("Base64 text")
            .to_owned();
        xml_sec_libxml2::ffi::memory::xsFree(text.cast());
        owned
    };
    format!(
        "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data>\
         <X509Certificate>{text}</X509Certificate></X509Data></KeyInfo>"
    )
}

#[test]
fn a_carried_certificate_does_not_search_the_stored_keys() {
    // A carried certificate names no certificate to look up: the stored keys
    // are no candidates, and an allowance of one admits the certificate.
    const OTHER: &[u8] = include_bytes!("../../../../../tests/fixtures/keys/rsa/rsa-4096-cert.pem");
    crate::ffi::tests::own_process();
    limits(1, 1 << 20);
    // SAFETY: a manager created and destroyed here.
    unsafe {
        let mngr = default_manager(&[]);
        let key = key_from_certificate(here!("test"), OTHER, FORMAT_PEM);
        assert_eq!(default_keys_mngr_adopt_key(mngr.cast(), key), 0);
        assert_eq!(read_key_info(mngr, &carried_leaf()), (0, true));
        xmlSecKeysMngrDestroy(mngr);
    }
}

#[test]
fn a_certificate_store_search_spends_the_candidate_allowance() {
    // Each untrusted store certificate a selector lookup inspects is a key
    // candidate of the read: the leaf, second in the store, needs two.
    const OTHER: &[u8] = include_bytes!("../../../../../tests/fixtures/x509/delta-crl/ca.der");
    const XML: &str = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data>\
        <X509SubjectName>CN=xml-sec Test Delta Leaf</X509SubjectName></X509Data></KeyInfo>";
    crate::ffi::tests::own_process();
    for (allowance, expected) in [(2, true), (1, false)] {
        limits(allowance, 1 << 20);
        // SAFETY: a manager created and destroyed here.
        unsafe {
            let mngr = default_manager(&[OTHER, LEAF]);
            assert_eq!(read_key_info(mngr, XML).1, expected, "{allowance}");
            xmlSecKeysMngrDestroy(mngr);
        }
    }
}

#[test]
fn an_x509_data_blob_beyond_the_resource_limit_is_refused_before_decoding() {
    // A key identifier larger than the per-resource limit is refused when it
    // is read, before it is decoded and copied.
    crate::ffi::tests::own_process();
    let ski = "A".repeat(400);
    let xml = format!(
        "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data>\
         <X509SKI>{ski}</X509SKI></X509Data></KeyInfo>"
    );
    limits(64, 1 << 20);
    // SAFETY: a manager created and destroyed here.
    unsafe {
        let mngr = default_manager(&[]);
        limits(64, 100);
        assert_eq!(read_key_info(mngr, &xml).0, -1);
        xmlSecKeysMngrDestroy(mngr);
    }
}

#[test]
fn a_crl_that_does_not_read_is_not_stored() {
    // A CRL the store cannot read would fail every path check it applies
    // to; it is refused at loading, and the store keeps none.
    // SAFETY: objects created and destroyed here.
    unsafe {
        let mngr = xmlSecKeysMngrCreate();
        assert_eq!(keys_mngr_init(mngr.cast()), 0);
        let malformed = b"not a CRL";
        assert_eq!(
            keys_mngr_crl_load_memory(mngr.cast(), malformed.as_ptr(), malformed.len(), FORMAT_DER),
            -1
        );
        assert_eq!(mngr_state(mngr).expect("a store").crls.len(), 0);
        assert_eq!(
            keys_mngr_crl_load_memory(mngr.cast(), CRL.as_ptr(), CRL.len(), FORMAT_DER),
            0
        );
        assert_eq!(mngr_state(mngr).expect("a store").crls.len(), 1);
        xmlSecKeysMngrDestroy(mngr);
    }
}

#[test]
fn utc_history_needs_a_manager_and_bytes() {
    // The loader asserts its arguments like libxmlsec1's memory loaders.
    // SAFETY: null arguments are refused before any use.
    unsafe {
        assert_eq!(
            xsKeysMngrUtcFactsLoadMemory(
                std::ptr::null_mut(),
                LEAP_SECONDS.as_ptr(),
                LEAP_SECONDS.len()
            ),
            -1
        );
        let mngr = xmlSecKeysMngrCreate();
        assert_eq!(xsKeysMngrUtcFactsLoadMemory(mngr, std::ptr::null(), 4), -1);
        assert_eq!(
            xsKeysMngrUtcFactsLoadMemory(mngr, LEAP_SECONDS.as_ptr(), 0),
            -1
        );
        // A manager without an X.509 store has nowhere to keep the list.
        assert_eq!(
            xsKeysMngrUtcFactsLoadMemory(mngr, LEAP_SECONDS.as_ptr(), LEAP_SECONDS.len()),
            -1
        );
        xmlSecKeysMngrDestroy(mngr);
    }
}
