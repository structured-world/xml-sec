//! CRL checking in the X.509 store needs the caller's UTC history: without
//! it a CRL that applies to a path refuses the path; with it the path is
//! checked against the CRL.

use super::load::{
    TYPE_TRUSTED, keys_mngr_cert_load_memory, keys_mngr_crl_load_memory, keys_mngr_init,
    xsKeysMngrUtcFactsLoadMemory,
};
use super::{FORMAT_DER, mngr_state, verify};
use crate::ffi::errors::here;
use crate::ffi::keyinfo::{xmlSecKeyInfoCtxCreate, xmlSecKeyInfoCtxDestroy};
use crate::ffi::keysmngr::{xmlSecKeysMngrCreate, xmlSecKeysMngrDestroy};
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
