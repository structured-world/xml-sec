//! The built-in provider's X.509 support (`xmlSecX509StoreId`, the
//! `X509Data` and raw-certificate key-data klasses): the certificate store a
//! keys manager holds and the verification of the certificates a `KeyInfo`
//! carries against it.
//!
//! The store keeps the caller's trusted and untrusted certificates and its
//! CRLs as DER. A certificate's key reaches a key only through the core's
//! path validation (`verify_x509_certificate`) to a trusted certificate of
//! the store, under the library policy's key trust; parsing alone never
//! yields a key. The `KeyInfo` context's verification time and depth are
//! request inputs inside that policy.

use std::ffi::{c_int, c_uint, c_void};

use xml_sec::policy::{Instant, PolicyViolation, ResourcePolicy, VerificationPolicy};
use xml_sec::xmldsig::{
    LeapSecondsList, ParsedX509Certificate, X509ChainError, X509ChainOptions, X509DataInfo,
    parse_x509_certificate_with_resources, verify_x509_certificate,
    x509_find_certificate_by_selectors, x509_leaf_certificates,
};

use super::contain;
use super::errors::{self, Here, here};
use super::keyinfo::{XmlSecKeyInfoCtx, charge_candidate};
use super::keysdata::{XmlSecKeyDataStore, XmlSecKeyDataStoreKlass, store_valid};
use super::keysmngr::{XmlSecKeysMngr, xmlSecKeysMngrGetDataStore};
use super::strings::xmlSecNameX509Store;

pub(crate) mod data;
pub(crate) mod load;
#[cfg(test)]
mod tests;

pub(crate) use data::{raw_x509_cert, x509_data};

/// `XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS`.
pub(crate) const FLAGS_DONT_VERIFY_CERTS: c_uint = 0x0000_0200;
/// `XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CERT`.
pub(crate) const FLAGS_STOP_ON_UNKNOWN_CERT: c_uint = 0x0000_0400;
/// `XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_INVALID_CERT`.
pub(crate) const FLAGS_STOP_ON_INVALID_CERT: c_uint = 0x0000_0800;

/// `XMLSEC_ERRORS_R_CERT_VERIFY_FAILED`.
pub(crate) const R_CERT_VERIFY_FAILED: c_int = 71;
/// `XMLSEC_ERRORS_R_CERT_NOT_FOUND`.
pub(crate) const R_CERT_NOT_FOUND: c_int = 72;
/// `XMLSEC_ERRORS_R_CERT_REVOKED`.
const R_CERT_REVOKED: c_int = 73;
/// `XMLSEC_ERRORS_R_CERT_NOT_YET_VALID`.
const R_CERT_NOT_YET_VALID: c_int = 75;
/// `XMLSEC_ERRORS_R_CERT_HAS_EXPIRED`.
const R_CERT_HAS_EXPIRED: c_int = 76;

/// The certificates and CRLs of an X.509 store, as DER.
#[derive(Default)]
pub(crate) struct StoreState {
    /// Certificates the caller trusts as anchors.
    pub(crate) trusted: Vec<Vec<u8>>,
    /// Certificates that may continue a path, trusted for nothing.
    pub(crate) untrusted: Vec<Vec<u8>>,
    /// CRLs applied to every path the store validates.
    pub(crate) crls: Vec<Vec<u8>>,
    /// The UTC history the caller supplied for CRL checking
    /// (`xsKeysMngrUtcFactsLoadMemory`); without it an applicable CRL
    /// refuses the path.
    pub(crate) utc_facts: Option<LeapSecondsList>,
}

/// An X.509 store object: the data store and its state.
#[repr(C)]
struct StoreObject {
    store: XmlSecKeyDataStore,
    state: *mut StoreState,
}

static STORE: XmlSecKeyDataStoreKlass = XmlSecKeyDataStoreKlass {
    klass_size: size_of::<XmlSecKeyDataStoreKlass>(),
    obj_size: size_of::<StoreObject>(),
    name: xmlSecNameX509Store.as_ptr(),
    initialize: Some(store_initialize),
    finalize: Some(store_finalize),
    reserved0: std::ptr::null_mut(),
    reserved1: std::ptr::null_mut(),
};

/// `x509StoreGetKlass` of the built-in table.
pub(crate) unsafe extern "C" fn x509_store() -> *const XmlSecKeyDataStoreKlass {
    &raw const STORE
}

/// The state of `store` when it is an X.509 store of this module.
///
/// # Safety
/// `store` is null or a data store.
unsafe fn store_state<'a>(store: *mut XmlSecKeyDataStore) -> Option<&'a mut StoreState> {
    // SAFETY: by the caller's contract; a valid store of this klass has the
    // object layout, and its state is null or the object's own.
    unsafe {
        (store_valid(store) && std::ptr::eq((*store).id, &raw const STORE))
            .then(|| (*store.cast::<StoreObject>()).state.as_mut())
            .flatten()
    }
}

/// The X.509 store state of `mngr`, `None` when it holds no X.509 store.
///
/// # Safety
/// `mngr` is a keys manager.
pub(crate) unsafe fn mngr_state<'a>(mngr: *mut XmlSecKeysMngr) -> Option<&'a mut StoreState> {
    // SAFETY: by the caller's contract.
    unsafe {
        let store = xmlSecKeysMngrGetDataStore(mngr, (&raw const STORE).cast::<c_void>());
        store_state(store)
    }
}

unsafe extern "C" fn store_initialize(store: *mut XmlSecKeyDataStore) -> c_int {
    contain(-1, || {
        // SAFETY: the store protocol passes a store of this klass with its
        // object size; the state slot is set here first.
        unsafe {
            if !store_valid(store) || !std::ptr::eq((*store).id, &raw const STORE) {
                errors::assertion(
                    here!("xmlSecKeyDataStoreInitialize"),
                    c"xmlSecKeyDataStoreCheckId(store, xmlSecX509StoreId)",
                );
                return -1;
            }
            (*store.cast::<StoreObject>()).state = Box::into_raw(Box::default());
        }
        0
    })
}

unsafe extern "C" fn store_finalize(store: *mut XmlSecKeyDataStore) {
    contain((), || {
        // SAFETY: as for `store_initialize`; a non-null state was boxed there.
        unsafe {
            if store_valid(store) && std::ptr::eq((*store).id, &raw const STORE) {
                let object = store.cast::<StoreObject>();
                if !(*object).state.is_null() {
                    drop(Box::from_raw((*object).state));
                    (*object).state = std::ptr::null_mut();
                }
            }
        }
    });
}

/// The key a certificate offers, and the window of its validity.
pub(crate) struct CertificateKey {
    /// The position of the certificate among those verified.
    pub(crate) index: usize,
    /// Its `SubjectPublicKeyInfo` DER.
    pub(crate) spki: Vec<u8>,
    pub(crate) not_before: Instant,
    pub(crate) not_after: Instant,
}

/// The time certificates are verified at: the context's
/// `certsVerificationTime` when it sets one, else the policy's verification
/// time, else now.
fn verification_time(ctx: &XmlSecKeyInfoCtx, policy: &VerificationPolicy) -> Option<Instant> {
    if ctx.certs_verification_time > 0 {
        return Instant::new(seconds_of(ctx.certs_verification_time), 0);
    }
    policy
        .key_trust
        .verification_time
        .or_else(|| xml_sec::policy::instant_from_system_time(std::time::SystemTime::now()))
}

/// The seconds of a C `time_t`, which is 32 or 64 bits wide by target.
pub(crate) fn seconds_of<T: Into<i64>>(time: T) -> i64 {
    time.into()
}

/// `seconds` as a C `time_t`, `None` when the target's `time_t` is too
/// narrow to hold it.
pub(crate) fn time_of<T: TryFrom<i64>>(seconds: i64) -> Option<T> {
    T::try_from(seconds).ok()
}

/// The longest path the context permits, anchor included: libxmlsec1's
/// `certsVerificationDepth` counts the intermediates between the leaf and
/// the anchor (OpenSSL's `X509_VERIFY_PARAM_set_depth`); the policy's own
/// maximum bounds it.
fn chain_depth(ctx: &XmlSecKeyInfoCtx, policy: &VerificationPolicy) -> usize {
    let maximum = policy.key_trust.max_x509_chain_depth;
    usize::try_from(ctx.certs_verification_depth)
        .ok()
        .and_then(|depth| depth.checked_add(2))
        .map_or(maximum, |depth| depth.min(maximum))
}

/// Whether `error` ends verification for every certificate rather than
/// refusing one: a resource limit or a failing provider.
fn terminal(error: &X509ChainError) -> bool {
    matches!(
        error,
        X509ChainError::Policy(
            PolicyViolation::ResourceLimit { .. } | PolicyViolation::ResourceLimitExceeded { .. }
        ) | X509ChainError::Provider(_)
    ) || matches!(error, X509ChainError::Processing(error) if error.is_resource())
}

/// Reports why the certificate `parsed` failed verification at `at`, with
/// libxmlsec1's reason for the failure.
fn report_refusal(here: Here, parsed: &ParsedX509Certificate, at: Instant, error: &X509ChainError) {
    // A path that reaches no trusted certificate is OpenSSL's
    // `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY`, which libxmlsec1 reports
    // as a failed verification like every error it does not single out.
    let reason = match error {
        X509ChainError::CertificateNotValid(0) if at < parsed.not_before => R_CERT_NOT_YET_VALID,
        X509ChainError::CertificateNotValid(0) => R_CERT_HAS_EXPIRED,
        X509ChainError::Revoked(_) => R_CERT_REVOKED,
        _ => R_CERT_VERIFY_FAILED,
    };
    errors::report(
        here,
        std::ptr::null(),
        std::ptr::null(),
        reason,
        &format!(
            "subject={}; issuer={}; msg={error}",
            parsed.subject_dn, parsed.issuer_dn
        ),
    );
}

/// The first certificate of `certs` that issues no other certificate of
/// `certs` or of the store and whose path validates to a trusted
/// certificate of the store, with `crls` and the store's CRLs applied, as
/// libxmlsec1's store verifies an `X509Data`. With
/// `XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS` the first such
/// certificate, unverified. `Ok(None)` when none validates; `Err` after a
/// report when verification cannot proceed.
pub(crate) fn verify(
    here: Here,
    state: &StoreState,
    certs: &[Vec<u8>],
    crls: &[Vec<u8>],
    ctx: &XmlSecKeyInfoCtx,
    policy: &VerificationPolicy,
) -> Result<Option<CertificateKey>, ()> {
    let leaves =
        x509_leaf_certificates(certs, &state.untrusted, &policy.resources).map_err(|error| {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"x509_leaf_certificates",
                &error.to_string(),
            );
        })?;
    for index in leaves {
        if let Some(key) = check(here, state, certs, crls, index, ctx, policy)? {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

/// Whether the key certificate `certs[index]` of a key's X.509 data
/// validates to a trusted certificate of the store with the data's other
/// certificates and `crls`, as libxmlsec1's `X509StoreVerifyKey`.
pub(crate) fn verify_target(
    here: Here,
    state: &StoreState,
    data: &data::X509State,
    index: usize,
    ctx: &XmlSecKeyInfoCtx,
    policy: &VerificationPolicy,
) -> Result<bool, ()> {
    check(here, state, &data.certs, &data.crls, index, ctx, policy).map(|key| key.is_some())
}

/// The key of `certs[index]` when its path validates to a trusted
/// certificate of the store, the other certificates of `certs` and the
/// store's untrusted ones continuing it, `crls` and the store's applied;
/// with `XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS` its key as it is.
/// `Ok(None)` after the refusal's report; `Err` when verification cannot
/// proceed.
fn check(
    here: Here,
    state: &StoreState,
    certs: &[Vec<u8>],
    crls: &[Vec<u8>],
    index: usize,
    ctx: &XmlSecKeyInfoCtx,
    policy: &VerificationPolicy,
) -> Result<Option<CertificateKey>, ()> {
    let resources = &policy.resources;
    let Some(at) = verification_time(ctx, policy) else {
        errors::report(
            here,
            std::ptr::null(),
            std::ptr::null(),
            errors::R_INVALID_DATA,
            "the verification time is outside the representable range",
        );
        return Err(());
    };
    // The data's and the store's certificates and CRLs are passed borrowed:
    // validation admits them against the operation's limits before it
    // copies anything.
    let intermediates: Vec<&[u8]> = certs
        .iter()
        .chain(&state.untrusted)
        .map(Vec::as_slice)
        .collect();
    let all_crls: Vec<&[u8]> = crls.iter().chain(&state.crls).map(Vec::as_slice).collect();
    let options = X509ChainOptions {
        trusted_certs: &state.trusted,
        utc_facts: state.utc_facts.as_ref().map(LeapSecondsList::table),
        verification_time: at,
        max_chain_depth: chain_depth(ctx, policy),
        // CRLs the caller supplies only ever refuse a path.
        check_crls: !all_crls.is_empty(),
        allowed_extended_key_usages: Some(&policy.key_trust.allowed_extended_key_usages),
        rsa_keys: policy.key_trust.rsa_keys,
        dsa_keys: policy.key_trust.dsa_keys,
        certificate_signature_algorithms: policy
            .key_trust
            .certificate_signature_algorithms
            .as_ref(),
        validity_model: policy.key_trust.validity_model,
    };
    let target = &certs[index];
    let parsed = parse_x509_certificate_with_resources(target, resources).map_err(|error| {
        errors::internal_with(
            here,
            std::ptr::null(),
            c"parse_x509_certificate_with_resources",
            &error.to_string(),
        );
    })?;
    if ctx.flags & FLAGS_DONT_VERIFY_CERTS != 0 {
        return Ok(Some(CertificateKey {
            index,
            spki: parsed.subject_public_key_info,
            not_before: parsed.not_before,
            not_after: parsed.not_after,
        }));
    }
    match verify_x509_certificate(
        target,
        &intermediates,
        &all_crls,
        &options,
        policy.key_trust.max_x509_candidate_paths,
        resources,
        xml_sec::provider::default_provider(),
    ) {
        Ok(verified) => Ok(Some(CertificateKey {
            index,
            spki: verified.subject_public_key_info,
            not_before: verified.not_before,
            not_after: verified.not_after,
        })),
        Err(error) if terminal(&error) => {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"verify_x509_certificate",
                &error.to_string(),
            );
            Err(())
        }
        Err(error) => {
            report_refusal(here, &parsed, at, &error);
            Ok(None)
        }
    }
}

/// The selectors of one `X509Data` child: a subject name, an issuer and
/// serial number, a key identifier or a digest of the certificate.
#[derive(Default)]
pub(crate) struct Selectors {
    pub(crate) subject: Option<String>,
    pub(crate) issuer_serial: Option<(String, String)>,
    pub(crate) ski: Option<Vec<u8>>,
    pub(crate) digest: Option<(String, Vec<u8>)>,
}

impl Selectors {
    /// Whether no selector names a certificate.
    pub(crate) fn is_empty(&self) -> bool {
        self.subject.is_none()
            && self.issuer_serial.is_none()
            && self.ski.is_none()
            && self.digest.is_none()
    }
}

/// The untrusted certificate of the store the `selectors` name, as
/// libxmlsec1's store finds one by value; `Ok(None)` when none matches or
/// there are no selectors.
///
/// # Safety
/// `ctx` is the context of the read the search serves.
pub(crate) unsafe fn find(
    here: Here,
    state: &StoreState,
    selectors: &Selectors,
    ctx: *mut XmlSecKeyInfoCtx,
    resources: &ResourcePolicy,
) -> Result<Option<Vec<u8>>, ()> {
    if selectors.is_empty() {
        return Ok(None);
    }
    // Each certificate inspected is a key candidate of the read, charged to
    // the allowance its searches share; the search stops when it is spent,
    // and a search the allowance cut short without a match fails the read
    // (after the charge's report) rather than reading as an unknown
    // certificate.
    let refused = core::cell::Cell::new(false);
    let candidates = state.untrusted.iter().map_while(|der| {
        // SAFETY: by the caller's contract.
        let charged = unsafe { charge_candidate(ctx, here, xmlSecNameX509Store.as_ptr().cast()) };
        refused.set(!charged);
        charged.then_some(der.as_slice())
    });
    match first_named(here, selectors, candidates, resources)? {
        Some(position) => Ok(Some(state.untrusted[position].clone())),
        None if refused.get() => Err(()),
        None => Ok(None),
    }
}

/// The position of the first of `candidates` that `selectors` name, all
/// compared under the operation's `resources` in one session; never one
/// for empty selectors.
pub(crate) fn first_named<'c>(
    here: Here,
    selectors: &Selectors,
    candidates: impl IntoIterator<Item = &'c [u8]>,
    resources: &ResourcePolicy,
) -> Result<Option<usize>, ()> {
    let mut info = X509DataInfo::default();
    info.subject_names.extend(selectors.subject.clone());
    info.issuer_serials.extend(selectors.issuer_serial.clone());
    info.skis.extend(selectors.ski.clone());
    info.digests.extend(selectors.digest.clone());
    x509_find_certificate_by_selectors(
        &info,
        candidates,
        xml_sec::provider::default_provider(),
        resources,
    )
    .map_err(|error| {
        errors::internal_with(
            here,
            std::ptr::null(),
            c"x509_find_certificate_by_selectors",
            &error.to_string(),
        );
    })
}

/// The DER of a certificate or CRL in `bytes` of `format` (`label` names the
/// PEM block), checked to read as one.
pub(crate) fn der_of(
    bytes: &[u8],
    format: c_int,
    label: &str,
    resources: &xml_sec::policy::ResourcePolicy,
) -> Result<Option<Vec<u8>>, String> {
    match format {
        FORMAT_PEM | FORMAT_CERT_PEM => {
            xml_sec::key_manager::pem_block_der(bytes, label, resources)
                .map(Some)
                .map_err(|error| error.to_string())
        }
        // The per-resource limit holds before the bytes are copied, as the
        // PEM reader holds it before decoding.
        FORMAT_DER | FORMAT_CERT_DER if bytes.len() > resources.max_external_resource_bytes => {
            Err(format!(
                "{} bytes exceed max_external_resource_bytes={}",
                bytes.len(),
                resources.max_external_resource_bytes
            ))
        }
        FORMAT_DER | FORMAT_CERT_DER => Ok(Some(bytes.to_vec())),
        _ => Ok(None),
    }
}

/// `xmlSecKeyDataFormatPem`.
pub(crate) const FORMAT_PEM: c_int = 2;
/// `xmlSecKeyDataFormatDer`.
pub(crate) const FORMAT_DER: c_int = 3;
/// `xmlSecKeyDataFormatCertPem`.
pub(crate) const FORMAT_CERT_PEM: c_int = 7;
/// `xmlSecKeyDataFormatCertDer`.
pub(crate) const FORMAT_CERT_DER: c_int = 8;

/// A certificate's DER after it reads as a certificate under `resources`;
/// the reason it does not otherwise.
pub(crate) fn certificate(
    der: Vec<u8>,
    resources: &xml_sec::policy::ResourcePolicy,
) -> Result<Vec<u8>, String> {
    parse_x509_certificate_with_resources(&der, resources)
        .map(|_| der)
        .map_err(|error| error.to_string())
}
