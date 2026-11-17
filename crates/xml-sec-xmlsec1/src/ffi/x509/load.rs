//! The built-in crypto table's X.509 loading (`xmlsec/app.h`): certificates
//! and CRLs from memory into a keys manager's X.509 store or a key's X.509
//! data, the keys manager's X.509 store, and the default keys manager with
//! its key verification. The table reads no file: the caller passes the
//! bytes.

use std::ffi::{c_int, c_uint, c_void};

use xml_sec::xmldsig::{
    KeyValueInfo, LeapSecondsList, parse_x509_certificate_with_resources, validate_x509_crl,
};

use super::super::asymkeys::{self, Material};
use super::super::errors::{self, Here, here};
use super::super::keyinfo::{XmlSecKeyInfoCtx, read_policy};
use std::cell::Cell;

use super::super::keys::{XmlSecKey, xmlSecKeyEnsureData, xmlSecKeyGetData, xmlSecKeyGetValue};
use super::super::keys::{xmlSecKeyDuplicate, xmlSecKeyMatch};
use super::super::keysdata::{xmlSecKeyDataStoreCreate, xmlSecKeyDataStoreDestroy};
use super::super::keysmngr::{
    XmlSecKeyStore, XmlSecKeyStoreKlass, XmlSecKeysMngr, xmlSecKeyStoreCreate,
    xmlSecKeyStoreDestroy, xmlSecKeyStoreFindKey, xmlSecKeysMngrAdoptDataStore,
    xmlSecKeysMngrAdoptKeysStore, xmlSecKeysMngrGetKey, xmlSecKeysMngrGetKeysStore,
    xmlSecSimpleKeysStoreAdoptKey, xmlSecSimpleKeysStoreGetKeys, xmlSecSimpleKeysStoreGetKlass,
};
use super::super::list::{xmlSecPtrListGetItem, xmlSecPtrListGetSize};
use super::super::{contain, policy};
use super::data::{self, X509State, state_of};
use super::{StoreState, certificate, der_of, mngr_state, x509_store};

/// `xmlSecKeyDataTypeTrusted`.
pub(crate) const TYPE_TRUSTED: c_uint = 0x0100;

/// The default keys manager's key store: a simple keys store holding the
/// keys, which also finds a key whose certificate an `X509Data` names, as
/// libxmlsec1's crypto libraries wrap the simple store.
#[repr(C)]
struct KeysStore {
    store: XmlSecKeyStore,
    inner: *mut XmlSecKeyStore,
}

static KEYS_STORE: XmlSecKeyStoreKlass = XmlSecKeyStoreKlass {
    klass_size: size_of::<XmlSecKeyStoreKlass>(),
    obj_size: size_of::<KeysStore>(),
    name: c"x509-keys-store".as_ptr().cast(),
    initialize: Some(keys_store_initialize),
    finalize: Some(keys_store_finalize),
    find_key: Some(keys_store_find_key),
    find_key_from_x509_data: Some(keys_store_find_key_from_x509_data),
    reserved0: std::ptr::null_mut(),
};

/// The simple store inside `store` when it is a key store of this klass.
///
/// # Safety
/// `store` is null or a key store.
unsafe fn inner_store(store: *mut XmlSecKeyStore) -> *mut XmlSecKeyStore {
    // SAFETY: by the caller's contract; a store of this klass has its layout.
    unsafe {
        match store.as_ref() {
            Some(held) if std::ptr::eq(held.id, &raw const KEYS_STORE) => {
                (*store.cast::<KeysStore>()).inner
            }
            _ => std::ptr::null_mut(),
        }
    }
}

unsafe extern "C" fn keys_store_initialize(store: *mut XmlSecKeyStore) -> c_int {
    contain(-1, || {
        let here = here!("xmlSecKeyStoreInitialize");
        // SAFETY: the store protocol passes a store of this klass at its
        // size; the inner slot is set here first.
        unsafe {
            if store.is_null() || !std::ptr::eq((*store).id, &raw const KEYS_STORE) {
                errors::assertion(here, c"xmlSecKeyStoreCheckId(store, xmlSecKeysStoreId)");
                return -1;
            }
            let inner = xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreGetKlass());
            (*store.cast::<KeysStore>()).inner = inner;
            if inner.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyStoreCreate");
                return -1;
            }
        }
        0
    })
}

unsafe extern "C" fn keys_store_finalize(store: *mut XmlSecKeyStore) {
    contain((), || {
        // SAFETY: as for `keys_store_initialize`; the inner store is ours.
        unsafe {
            let inner = inner_store(store);
            if !inner.is_null() {
                xmlSecKeyStoreDestroy(inner);
                (*store.cast::<KeysStore>()).inner = std::ptr::null_mut();
            }
        }
    });
}

unsafe extern "C" fn keys_store_find_key(
    store: *mut XmlSecKeyStore,
    name: *const u8,
    ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    // SAFETY: a store of this klass; the simple store finds by name.
    contain(std::ptr::null_mut(), || unsafe {
        xmlSecKeyStoreFindKey(inner_store(store), name, ctx)
    })
}

/// `findKeyFromX509Data`: a copy of the first key the request's
/// requirements accept whose certificate the value's selectors name.
unsafe extern "C" fn keys_store_find_key_from_x509_data(
    store: *mut XmlSecKeyStore,
    value: *mut c_void,
    ctx: *mut XmlSecKeyInfoCtx,
) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecKeysStoreFindKeyFromX509Data");
        if value.is_null() || ctx.is_null() {
            errors::assertion(here, c"x509Data != NULL && keyInfoCtx != NULL");
            return std::ptr::null_mut();
        }
        // SAFETY: a store of this klass, a value the KeyInfo read built and
        // its context.
        unsafe {
            let keys = xmlSecSimpleKeysStoreGetKeys(inner_store(store));
            if keys.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecSimpleKeysStoreGetKeys");
                return std::ptr::null_mut();
            }
            let Some(pinned) = read_policy(ctx, here) else {
                return std::ptr::null_mut();
            };
            let max = pinned.verification.resources.max_key_candidates;
            // Every entry inspected is a key candidate of the read, charged to
            // the allowance all its searches share, as the simple store
            // charges a search by name.
            let shared = policy::key_candidates((*ctx).reserved0);
            let mut tally = shared.map_or_default(Cell::get);
            let mut eligible: Vec<(*mut XmlSecKey, &[u8])> = Vec::new();
            for position in 0..xmlSecPtrListGetSize(keys) {
                if !tally.charge(max, here, (*(*store).id).name.cast()) {
                    break;
                }
                let key = xmlSecPtrListGetItem(keys, position).cast::<XmlSecKey>();
                // A key the request cannot use is passed over, so a usable
                // key with the same certificate further on is still found.
                if key.is_null()
                    || xmlSecKeyMatch(key, std::ptr::null(), &raw mut (*ctx).key_req) != 1
                {
                    continue;
                }
                let Some(state) = state_of(xmlSecKeyGetData(key, data::x509_data())) else {
                    continue;
                };
                if let Some(index) = state.key_cert {
                    eligible.push((key, &state.certs[index]));
                }
            }
            if let Some(shared) = shared {
                shared.set(tally);
            }
            let selectors = data::selectors_of(value);
            let Ok(found) = super::first_named(
                here,
                &selectors,
                eligible.iter().map(|(_, cert)| *cert),
                &pinned.verification.resources,
            ) else {
                return std::ptr::null_mut();
            };
            let Some(position) = found else {
                return std::ptr::null_mut();
            };
            let copy = xmlSecKeyDuplicate(eligible[position].0);
            if copy.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyDuplicate");
            }
            copy
        }
    })
}

/// The certificate in `bytes` of `format`, read under the library policy;
/// `None` after a report at `here`.
fn read_certificate(here: Here, bytes: &[u8], format: c_int) -> Option<Vec<u8>> {
    let policy = policy::verification_at(here)?;
    let der = match der_of(bytes, format, "CERTIFICATE", &policy.resources) {
        Ok(Some(der)) => der,
        Ok(None) => {
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_INVALID_FORMAT,
                &format!("format={format}"),
            );
            return None;
        }
        Err(error) => {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecOpenSSLX509CertLoadBIO",
                &error,
            );
            return None;
        }
    };
    certificate(der, &policy.resources)
        .inspect_err(|error| {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecOpenSSLX509CertLoadBIO",
                error,
            );
        })
        .ok()
}

/// The X.509 store of `mngr`, reported at `here` when it has none.
///
/// # Safety
/// `mngr` is a keys manager.
unsafe fn store_of<'a>(here: Here, mngr: *mut XmlSecKeysMngr) -> Option<&'a mut StoreState> {
    // SAFETY: by the caller's contract.
    let store = unsafe { mngr_state(mngr) };
    if store.is_none() {
        errors::internal(here, std::ptr::null(), c"xmlSecKeysMngrGetDataStore");
    }
    store
}

/// `cryptoKeysMngrInit` of the built-in table: gives `mngr` an X.509 store
/// when it has none.
pub(crate) unsafe extern "C" fn keys_mngr_init(mngr: *mut c_void) -> c_int {
    let mngr = mngr.cast::<XmlSecKeysMngr>();
    contain(-1, || {
        let here = here!("xmlSecOpenSSLKeysMngrInit");
        if mngr.is_null() {
            errors::assertion(here, c"mngr != NULL");
            return -1;
        }
        // SAFETY: a keys manager, which adopts the new store.
        unsafe {
            if mngr_state(mngr).is_some() {
                return 0;
            }
            let store = xmlSecKeyDataStoreCreate(x509_store());
            if store.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyDataStoreCreate");
                return -1;
            }
            if xmlSecKeysMngrAdoptDataStore(mngr, store) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecKeysMngrAdoptDataStore");
                xmlSecKeyDataStoreDestroy(store);
                return -1;
            }
        }
        0
    })
}

/// `cryptoAppKeysMngrCertLoadMemory` of the built-in table: the certificate
/// as a trusted or untrusted certificate of the manager's X.509 store.
pub(crate) unsafe extern "C" fn keys_mngr_cert_load_memory(
    mngr: *mut c_void,
    data: *const u8,
    size: usize,
    format: c_int,
    kind: c_uint,
) -> c_int {
    let mngr = mngr.cast::<XmlSecKeysMngr>();
    contain(-1, || {
        let here = here!("xmlSecOpenSSLAppKeysMngrCertLoadMemory");
        for (failed, expression) in [
            (mngr.is_null(), c"mngr != NULL"),
            (data.is_null(), c"data != NULL"),
            (size == 0, c"dataSize > 0"),
            (format == 0, c"format != xmlSecKeyDataFormatUnknown"),
        ] {
            if failed {
                errors::assertion(here, expression);
                return -1;
            }
        }
        // SAFETY: the caller's `size` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(data, size) };
        let Some(cert) = read_certificate(here, bytes, format) else {
            return -1;
        };
        // SAFETY: a keys manager.
        let Some(store) = (unsafe { store_of(here, mngr) }) else {
            return -1;
        };
        if kind & TYPE_TRUSTED != 0 {
            store.trusted.push(cert);
        } else {
            store.untrusted.push(cert);
        }
        0
    })
}

/// `cryptoAppKeysMngrCrlLoadMemory` of the built-in table: the CRL into the
/// manager's X.509 store, where it applies to every path the store
/// validates; it is authenticated by the path it applies to.
pub(crate) unsafe extern "C" fn keys_mngr_crl_load_memory(
    mngr: *mut c_void,
    data: *const u8,
    size: usize,
    format: c_int,
) -> c_int {
    let mngr = mngr.cast::<XmlSecKeysMngr>();
    contain(-1, || {
        let here = here!("xmlSecOpenSSLAppKeysMngrCrlLoadMemory");
        for (failed, expression) in [
            (mngr.is_null(), c"mngr != NULL"),
            (data.is_null(), c"data != NULL"),
            (size == 0, c"dataSize > 0"),
            (format == 0, c"format != xmlSecKeyDataFormatUnknown"),
        ] {
            if failed {
                errors::assertion(here, expression);
                return -1;
            }
        }
        let Some(policy) = policy::verification_at(here) else {
            return -1;
        };
        // SAFETY: the caller's `size` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(data, size) };
        let der = match der_of(bytes, format, "X509 CRL", &policy.resources) {
            Ok(Some(der)) => der,
            Ok(None) => {
                errors::report(
                    here,
                    std::ptr::null(),
                    std::ptr::null(),
                    errors::R_INVALID_FORMAT,
                    &format!("format={format}"),
                );
                return -1;
            }
            Err(error) => {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecOpenSSLX509CrlLoadBIO",
                    &error,
                );
                return -1;
            }
        };
        // A CRL that does not read would fail every later check the store
        // applies it to; it is refused here, leaving the store as it was.
        if let Err(error) = validate_x509_crl(&der, &policy.resources) {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecOpenSSLX509CrlLoadBIO",
                &error.to_string(),
            );
            return -1;
        }
        // SAFETY: a keys manager.
        let Some(store) = (unsafe { store_of(here, mngr) }) else {
            return -1;
        };
        store.crls.push(der);
        0
    })
}

/// `xsKeysMngrUtcFactsLoadMemory`: the UTC history the X.509 store of
/// `mngr` checks CRLs with, from the `dataSize` bytes of a
/// `leap-seconds.list` at `data`; it replaces any list loaded before.
/// libxmlsec1 reads the system clock instead, which this library does not:
/// without a list, a CRL that applies to a path refuses it. Returns 0, or -1
/// after a report.
///
/// # Safety
/// `mngr` is a keys manager and `data` holds `size` bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xsKeysMngrUtcFactsLoadMemory(
    mngr: *mut XmlSecKeysMngr,
    data: *const u8,
    size: usize,
) -> c_int {
    contain(-1, || {
        let here = here!("xsKeysMngrUtcFactsLoadMemory");
        for (failed, expression) in [
            (mngr.is_null(), c"mngr != NULL"),
            (data.is_null(), c"data != NULL"),
            (size == 0, c"dataSize > 0"),
        ] {
            if failed {
                errors::assertion(here, expression);
                return -1;
            }
        }
        let Some(policy) = policy::verification_at(here) else {
            return -1;
        };
        // SAFETY: the caller's `size` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(data, size) };
        let list = match LeapSecondsList::parse(bytes, &policy.resources) {
            Ok(list) => list,
            Err(error) => {
                errors::report(
                    here,
                    std::ptr::null(),
                    std::ptr::null(),
                    errors::R_INVALID_DATA,
                    &error.to_string(),
                );
                return -1;
            }
        };
        // SAFETY: a keys manager.
        let Some(store) = (unsafe { store_of(here, mngr) }) else {
            return -1;
        };
        store.utc_facts = Some(list);
        0
    })
}

/// Whether the certificate `cert` holds the public key of `key`'s value.
///
/// # Safety
/// `key` is a key.
unsafe fn certifies_key(
    key: *mut XmlSecKey,
    cert: &[u8],
    resources: &xml_sec::policy::ResourcePolicy,
) -> bool {
    // SAFETY: by the caller's contract.
    let Some(value) = (unsafe { asymkeys::value_of(xmlSecKeyGetValue(key)) }) else {
        return false;
    };
    parse_x509_certificate_with_resources(cert, resources)
        .ok()
        .and_then(|parsed| {
            KeyValueInfo::from_spki_der(&parsed.subject_public_key_info, resources).ok()
        })
        .is_some_and(|certified| certified == *value)
}

/// Adds the certificate `cert` to the X.509 data of `key`, as its key
/// certificate when the key has none yet and `cert` holds its public key.
///
/// # Safety
/// `key` is a key.
pub(crate) unsafe fn adopt_key_cert(
    here: Here,
    key: *mut XmlSecKey,
    cert: Vec<u8>,
    resources: &xml_sec::policy::ResourcePolicy,
) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        let data = xmlSecKeyEnsureData(key, data::x509_data());
        let Some(state) = state_of(data) else {
            errors::internal(here, std::ptr::null(), c"xmlSecKeyEnsureData");
            return false;
        };
        let key_cert = state.key_cert.is_none() && certifies_key(key, &cert, resources);
        state.add_cert(cert, key_cert);
    }
    true
}

/// `cryptoAppKeyCertLoadMemory` of the built-in table: the certificate into
/// the key's X.509 data.
pub(crate) unsafe extern "C" fn key_cert_load_memory(
    key: *mut c_void,
    data: *const u8,
    size: usize,
    format: c_int,
) -> c_int {
    let key = key.cast::<XmlSecKey>();
    contain(-1, || {
        let here = here!("xmlSecOpenSSLAppKeyCertLoadMemory");
        for (failed, expression) in [
            (key.is_null(), c"key != NULL"),
            (data.is_null(), c"data != NULL"),
            (size == 0, c"dataSize > 0"),
            (format == 0, c"format != xmlSecKeyDataFormatUnknown"),
        ] {
            if failed {
                errors::assertion(here, expression);
                return -1;
            }
        }
        // A PKCS#8 format names the container of the key it came with; its
        // certificate is PEM or DER.
        let format = match format {
            4 => super::FORMAT_PEM,
            5 => super::FORMAT_DER,
            other => other,
        };
        // SAFETY: the caller's `size` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(data, size) };
        let Some(cert) = read_certificate(here, bytes, format) else {
            return -1;
        };
        let Some(policy) = policy::verification_at(here) else {
            return -1;
        };
        // SAFETY: a key.
        if unsafe { adopt_key_cert(here, key, cert, &policy.resources) } {
            0
        } else {
            -1
        }
    })
}

/// A key whose value is the public key of the certificate in `bytes`, the
/// certificate its key certificate, as libxmlsec1 loads a key from a
/// certificate format; null after a report at `here`.
pub(crate) fn key_from_certificate(here: Here, bytes: &[u8], format: c_int) -> *mut c_void {
    let null = std::ptr::null_mut();
    let Some(cert) = read_certificate(here, bytes, format) else {
        return null;
    };
    let Some(policy) = policy::verification_at(here) else {
        return null;
    };
    let parsed = match parse_x509_certificate_with_resources(&cert, &policy.resources) {
        Ok(parsed) => parsed,
        Err(error) => {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecOpenSSLX509CertGetKey",
                &error.to_string(),
            );
            return null;
        }
    };
    let value =
        match KeyValueInfo::from_spki_der(&parsed.subject_public_key_info, &policy.resources) {
            Ok(value) => value,
            Err(error) => {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecOpenSSLX509CertGetKey",
                    &error.to_string(),
                );
                return null;
            }
        };
    let mut state = X509State::default();
    state.add_cert(cert, true);
    super::super::app::key_with(
        here,
        Material {
            value,
            private: None,
        },
        Some(state),
    )
}

/// `cryptoAppDefaultKeysMngrInit` of the built-in table: a simple keys
/// store when `mngr` has no key store, its X.509 store, and libxmlsec1's
/// key lookup.
pub(crate) unsafe extern "C" fn default_keys_mngr_init(mngr: *mut c_void) -> c_int {
    let raw = mngr.cast::<XmlSecKeysMngr>();
    contain(-1, || {
        let here = here!("xmlSecOpenSSLAppDefaultKeysMngrInit");
        if raw.is_null() {
            errors::assertion(here, c"mngr != NULL");
            return -1;
        }
        // SAFETY: a keys manager, which adopts the new store.
        unsafe {
            if xmlSecKeysMngrGetKeysStore(raw).is_null() {
                let store = xmlSecKeyStoreCreate(&raw const KEYS_STORE);
                if store.is_null() {
                    errors::internal(here, std::ptr::null(), c"xmlSecKeyStoreCreate");
                    return -1;
                }
                if xmlSecKeysMngrAdoptKeysStore(raw, store) < 0 {
                    errors::internal(here, std::ptr::null(), c"xmlSecKeysMngrAdoptKeysStore");
                    xmlSecKeyStoreDestroy(store);
                    return -1;
                }
            }
            if keys_mngr_init(mngr) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecOpenSSLKeysMngrInit");
                return -1;
            }
            (*raw).get_key = Some(xmlSecKeysMngrGetKey);
        }
        0
    })
}

/// `cryptoAppDefaultKeysMngrAdoptKey` of the built-in table: `key` into the
/// manager's key store.
pub(crate) unsafe extern "C" fn default_keys_mngr_adopt_key(
    mngr: *mut c_void,
    key: *mut c_void,
) -> c_int {
    let mngr = mngr.cast::<XmlSecKeysMngr>();
    contain(-1, || {
        let here = here!("xmlSecOpenSSLAppDefaultKeysMngrAdoptKey");
        for (failed, expression) in [
            (mngr.is_null(), c"mngr != NULL"),
            (key.is_null(), c"key != NULL"),
        ] {
            if failed {
                errors::assertion(here, expression);
                return -1;
            }
        }
        // SAFETY: a keys manager and a key it may own.
        unsafe {
            let store = xmlSecKeysMngrGetKeysStore(mngr);
            if store.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecKeysMngrGetKeysStore");
                return -1;
            }
            // The default manager's store, as libxmlsec1 adopts only into
            // its crypto library's own.
            let inner = inner_store(store);
            if inner.is_null() {
                errors::assertion(here, c"xmlSecKeyStoreCheckId(store, xmlSecKeysStoreId)");
                return -1;
            }
            xmlSecSimpleKeysStoreAdoptKey(inner, key.cast())
        }
    })
}

/// `cryptoAppDefaultKeysMngrVerifyKey` of the built-in table: 1 when the
/// key's certificate validates to a trusted certificate of the manager's
/// X.509 store with the key's other certificates and CRLs, 0 when it does
/// not or the key has no certificate.
pub(crate) unsafe extern "C" fn default_keys_mngr_verify_key(
    mngr: *mut c_void,
    key: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    let (mngr, key, ctx) = (
        mngr.cast::<XmlSecKeysMngr>(),
        key.cast::<XmlSecKey>(),
        ctx.cast::<XmlSecKeyInfoCtx>(),
    );
    contain(-1, || {
        let here = here!("xmlSecOpenSSLX509StoreVerifyKey");
        for (failed, expression) in [
            (mngr.is_null(), c"mngr != NULL"),
            (key.is_null(), c"key != NULL"),
            (ctx.is_null(), c"keyInfoCtx != NULL"),
        ] {
            if failed {
                errors::assertion(here, expression);
                return -1;
            }
        }
        // SAFETY: a keys manager, a key and a context.
        unsafe {
            let Some(store) = store_of(here, mngr) else {
                return -1;
            };
            let Some(state) = state_of(xmlSecKeyGetData(key, data::x509_data())) else {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyGetData");
                return -1;
            };
            let Some(index) = state.key_cert else {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecOpenSSLKeyDataX509GetKeyCert",
                );
                return 0;
            };
            let Some(pinned) = read_policy(ctx, here) else {
                return -1;
            };
            match super::verify_target(here, store, state, index, &*ctx, &pinned.verification) {
                Ok(true) => 1,
                Ok(false) => 0,
                Err(()) => -1,
            }
        }
    })
}
