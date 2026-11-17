//! The `X509Data` key-data klass (`xmlSecKeyDataX509Id`) and the raw
//! certificate klass (`xmlSecKeyDataRawX509CertId`), as libxmlsec1's crypto
//! libraries define them.
//!
//! An object holds certificates and CRLs as DER and, once one verified, the
//! position of the certificate that supplied the key. Reading an `X509Data`
//! element collects what each child names: a carried certificate or CRL, or
//! a certificate of the X.509 store the child's selectors name. Without a
//! key from the keys manager, the store verifies the certificates and the
//! verified certificate's key becomes the key's value.

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::fmt::Write as _;

use xml_sec::xmldsig::{KeyValueInfo, parse_x509_certificate_with_resources};

use super::super::asymkeys::{self, Material};
use super::super::base64::{
    xmlSecBase64DecodeInPlace, xmlSecBase64Encode, xmlSecBase64GetDefaultLineSize,
};
use super::super::buffer::{
    XmlSecBuffer, xmlSecBufferFinalize, xmlSecBufferGetData, xmlSecBufferGetSize,
    xmlSecBufferInitialize, xmlSecBufferSetData,
};
use super::super::errors::{self, Here, here};
use super::super::keyinfo::{XmlSecKeyInfoCtx, read_policy};
use super::super::keys::{
    TYPE_PUBLIC, XmlSecKey, xmlSecKeyAdoptData, xmlSecKeyDestroy, xmlSecKeyGetData,
    xmlSecKeyGetValue, xmlSecKeySwap,
};
use super::super::keysdata::{
    USAGE_KEY_INFO_NODE, USAGE_READ_FROM_FILE, USAGE_RETRIEVAL_METHOD_NODE_XML, XmlSecKeyData,
    XmlSecKeyDataKlass, data_valid, xmlSecKeyDataCreate, xmlSecKeyDataDestroy,
};
use super::super::keysmngr::xmlSecKeysMngrFindKeyFromX509Data;
use super::super::strings::{
    xmlSecAttrAlgorithm, xmlSecDSig11Ns, xmlSecDSigNs, xmlSecHrefRawX509Cert, xmlSecHrefX509Data,
    xmlSecNameRawX509Cert, xmlSecNameX509Data, xmlSecNodeX509CRL, xmlSecNodeX509Certificate,
    xmlSecNodeX509Data, xmlSecNodeX509Digest, xmlSecNodeX509IssuerName, xmlSecNodeX509IssuerSerial,
    xmlSecNodeX509SKI, xmlSecNodeX509SerialNumber, xmlSecNodeX509SubjectName,
};
use super::super::tree::{XmlNode, c_text, nodes};
use super::super::xmltree::{
    xmlSecCheckNodeName, xmlSecEnsureEmptyChild, xmlSecGetDefaultLineFeed, xmlSecGetNextElementNode,
};
use super::super::{contain, free, malloc, write_stream};
use super::{
    FLAGS_STOP_ON_INVALID_CERT, FLAGS_STOP_ON_UNKNOWN_CERT, R_CERT_NOT_FOUND, Selectors, find,
    mngr_state, verify,
};

/// `xmlSecKeyDataUsageRetrievalMethodNodeBin`.
const USAGE_RETRIEVAL_METHOD_NODE_BIN: c_uint = 0x0020;
/// `XMLSEC_KEYINFO_FLAGS_X509DATA_STOP_ON_UNKNOWN_CHILD`.
const FLAGS_STOP_ON_UNKNOWN_CHILD: c_uint = 0x0000_0100;
/// `XMLSEC_KEYINFO_FLAGS_STOP_ON_EMPTY_NODE`.
const FLAGS_STOP_ON_EMPTY_NODE: c_uint = 0x0000_2000;

/// The `XMLSEC_X509DATA_*` node kinds of an `X509Data` template.
const CERTIFICATE_NODE: c_int = 0x01;
const SUBJECT_NAME_NODE: c_int = 0x02;
const ISSUER_SERIAL_NODE: c_int = 0x04;
const SKI_NODE: c_int = 0x08;
const CRL_NODE: c_int = 0x10;
const DIGEST_NODE: c_int = 0x20;
/// The kinds a template without children writes.
const DEFAULT_CONTENT: c_int = CERTIFICATE_NODE | CRL_NODE;
/// The shift of a kind's bit when the template's node of it has content.
const SHIFT_IF_NOT_EMPTY: c_int = 16;

/// The certificates and CRLs an object holds.
#[derive(Clone, Default)]
pub(crate) struct X509State {
    pub(crate) certs: Vec<Vec<u8>>,
    pub(crate) crls: Vec<Vec<u8>>,
    /// The position of the certificate that supplied the key's value.
    pub(crate) key_cert: Option<usize>,
}

impl X509State {
    /// Adds `cert`, the key's certificate first, a certificate already held
    /// moving to its new place, as libxmlsec1 adds one.
    pub(crate) fn add_cert(&mut self, cert: Vec<u8>, key_cert: bool) {
        if let Some(position) = self.certs.iter().position(|held| *held == cert) {
            self.certs.remove(position);
            if let Some(key) = self.key_cert.as_mut()
                && *key > position
            {
                *key -= 1;
            }
        }
        if key_cert {
            self.certs.insert(0, cert);
            self.key_cert = Some(0);
        } else {
            self.certs.push(cert);
        }
    }
}

/// An `X509Data` object: the key data and its state.
#[repr(C)]
struct X509Object {
    data: XmlSecKeyData,
    state: *mut X509State,
}

static X509: XmlSecKeyDataKlass = XmlSecKeyDataKlass {
    klass_size: size_of::<XmlSecKeyDataKlass>(),
    obj_size: size_of::<X509Object>(),
    name: xmlSecNameX509Data.as_ptr(),
    usage: USAGE_READ_FROM_FILE | USAGE_KEY_INFO_NODE | USAGE_RETRIEVAL_METHOD_NODE_XML,
    href: xmlSecHrefX509Data.as_ptr(),
    data_node_name: xmlSecNodeX509Data.as_ptr(),
    data_node_ns: xmlSecDSigNs.as_ptr(),
    initialize: Some(initialize),
    duplicate: Some(duplicate),
    finalize: Some(finalize),
    generate: None,
    get_type: None,
    get_size: None,
    deprecated0: std::ptr::null_mut(),
    xml_read: Some(xml_read),
    xml_write: Some(xml_write),
    bin_read: None,
    bin_write: None,
    debug_dump: Some(debug_dump),
    debug_xml_dump: Some(debug_xml_dump),
    reserved0: std::ptr::null_mut(),
    reserved1: std::ptr::null_mut(),
};

static RAW: XmlSecKeyDataKlass = XmlSecKeyDataKlass {
    klass_size: size_of::<XmlSecKeyDataKlass>(),
    obj_size: size_of::<XmlSecKeyData>(),
    name: xmlSecNameRawX509Cert.as_ptr(),
    usage: USAGE_READ_FROM_FILE | USAGE_RETRIEVAL_METHOD_NODE_BIN,
    href: xmlSecHrefRawX509Cert.as_ptr(),
    data_node_name: std::ptr::null(),
    data_node_ns: xmlSecDSigNs.as_ptr(),
    initialize: None,
    duplicate: None,
    finalize: None,
    generate: None,
    get_type: None,
    get_size: None,
    deprecated0: std::ptr::null_mut(),
    xml_read: None,
    xml_write: None,
    bin_read: Some(raw_bin_read),
    bin_write: None,
    debug_dump: None,
    debug_xml_dump: None,
    reserved0: std::ptr::null_mut(),
    reserved1: std::ptr::null_mut(),
};

/// `keyDataX509GetKlass` of the built-in table.
pub(crate) unsafe extern "C" fn x509_data() -> *const XmlSecKeyDataKlass {
    &raw const X509
}

/// `keyDataRawX509CertGetKlass` of the built-in table.
pub(crate) unsafe extern "C" fn raw_x509_cert() -> *const XmlSecKeyDataKlass {
    &raw const RAW
}

/// The state of `data` when it is `X509Data` key data of this module.
///
/// # Safety
/// `data` is null or a key-data object.
pub(crate) unsafe fn state_of<'a>(data: *mut XmlSecKeyData) -> Option<&'a mut X509State> {
    // SAFETY: by the caller's contract; a valid object of this klass has the
    // object layout and its state is null or its own.
    unsafe {
        (data_valid(data) && std::ptr::eq((*data).id, &raw const X509))
            .then(|| (*data.cast::<X509Object>()).state.as_mut())
            .flatten()
    }
}

/// New `X509Data` key data holding `state`; null after a report at `here`.
pub(crate) fn create(here: Here, state: X509State) -> *mut XmlSecKeyData {
    // SAFETY: a klass of this module.
    unsafe {
        let data = xmlSecKeyDataCreate(&raw const X509);
        match state_of(data) {
            Some(held) => *held = state,
            None => errors::internal(here, std::ptr::null(), c"xmlSecKeyDataCreate"),
        }
        data
    }
}

/// The name of the X.509 klass for a report object.
fn x509_name() -> *const c_char {
    xmlSecNameX509Data.as_ptr().cast()
}

unsafe extern "C" fn initialize(data: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        // SAFETY: the registry passes key data of this klass at its size.
        unsafe {
            if !data_valid(data) || !std::ptr::eq((*data).id, &raw const X509) {
                errors::assertion(
                    here!("xmlSecKeyDataInitialize"),
                    c"xmlSecKeyDataCheckId(data, xmlSecKeyDataX509Id)",
                );
                return -1;
            }
            (*data.cast::<X509Object>()).state = Box::into_raw(Box::default());
        }
        0
    })
}

unsafe extern "C" fn duplicate(dst: *mut XmlSecKeyData, src: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        // SAFETY: the registry passes key data of this klass.
        let (Some(target), Some(source)) = (unsafe { state_of(dst) }, unsafe { state_of(src) })
        else {
            errors::assertion(
                here!("xmlSecKeyDataDuplicate"),
                c"xmlSecKeyDataCheckId(dst, xmlSecKeyDataX509Id) && xmlSecKeyDataCheckId(src, xmlSecKeyDataX509Id)",
            );
            return -1;
        };
        *target = source.clone();
        0
    })
}

unsafe extern "C" fn finalize(data: *mut XmlSecKeyData) {
    contain((), || {
        // SAFETY: as for `initialize`; a non-null state was boxed there.
        unsafe {
            if data_valid(data) && std::ptr::eq((*data).id, &raw const X509) {
                let object = data.cast::<X509Object>();
                if !(*object).state.is_null() {
                    drop(Box::from_raw((*object).state));
                    (*object).state = std::ptr::null_mut();
                }
            }
        }
    });
}

/// `xmlSecKeyX509DataValue`: what one `X509Data` child holds, as libxmlsec1
/// passes it to a key store's `findKeyFromX509Data`.
#[repr(C)]
struct X509DataValue {
    cert: XmlSecBuffer,
    crl: XmlSecBuffer,
    ski: XmlSecBuffer,
    subject: *mut u8,
    issuer_name: *mut u8,
    issuer_serial: *mut u8,
    digest_algorithm: *mut u8,
    digest: XmlSecBuffer,
}

/// One `X509Data` child read: its value in libxmlsec1's layout, released
/// when dropped.
struct ChildValue {
    value: X509DataValue,
}

impl ChildValue {
    /// An empty value; `None` after a report when a buffer fails.
    fn new(here: Here) -> Option<Self> {
        // SAFETY: zeroed buffers and null strings are an uninitialized
        // value; each buffer is initialized before use.
        let mut value: X509DataValue = unsafe { std::mem::zeroed() };
        for buffer in [
            &raw mut value.cert,
            &raw mut value.crl,
            &raw mut value.ski,
            &raw mut value.digest,
        ] {
            // SAFETY: an uninitialized buffer of the value.
            if unsafe { xmlSecBufferInitialize(buffer, 128) } < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecBufferInitialize");
                return None;
            }
        }
        Some(Self { value })
    }

    /// The bytes of `buffer`.
    fn bytes(buffer: &XmlSecBuffer) -> Vec<u8> {
        let buffer = std::ptr::from_ref(buffer).cast_mut();
        // SAFETY: an initialized buffer of the value.
        unsafe {
            let size = xmlSecBufferGetSize(buffer);
            let data = xmlSecBufferGetData(buffer);
            if data.is_null() || size == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(data, size).to_vec()
            }
        }
    }

    /// The selectors this value holds.
    fn selectors(&self) -> Selectors {
        // SAFETY: an initialized value of this reader.
        unsafe { selectors_of((&raw const self.value).cast_mut().cast()) }
    }
}

/// The selectors of the `xmlSecKeyX509DataValue` `value`, as a key store's
/// `findKeyFromX509Data` receives it.
///
/// # Safety
/// `value` is an initialized value whose strings are null or NUL-terminated.
pub(crate) unsafe fn selectors_of(value: *mut c_void) -> Selectors {
    // SAFETY: by the caller's contract.
    let value = unsafe { &*value.cast::<X509DataValue>() };
    let ski = ChildValue::bytes(&value.ski);
    let digest = ChildValue::bytes(&value.digest);
    // SAFETY: by the caller's contract.
    let (subject, issuer_name, issuer_serial, algorithm) = unsafe {
        (
            c_text(value.subject),
            c_text(value.issuer_name),
            c_text(value.issuer_serial),
            c_text(value.digest_algorithm),
        )
    };
    Selectors {
        subject: subject.map(str::to_owned),
        issuer_serial: issuer_name
            .zip(issuer_serial)
            .map(|(name, serial)| (name.to_owned(), serial.to_owned())),
        ski: (!ski.is_empty()).then_some(ski),
        digest: algorithm
            .filter(|_| !digest.is_empty())
            .map(|algorithm| (algorithm.to_owned(), digest)),
    }
}

impl Drop for ChildValue {
    fn drop(&mut self) {
        // SAFETY: initialized buffers and strings of libxml2's allocator.
        unsafe {
            for buffer in [
                &raw mut self.value.cert,
                &raw mut self.value.crl,
                &raw mut self.value.ski,
                &raw mut self.value.digest,
            ] {
                xmlSecBufferFinalize(buffer);
            }
            for text in [
                self.value.subject,
                self.value.issuer_name,
                self.value.issuer_serial,
                self.value.digest_algorithm,
            ] {
                if !text.is_null() {
                    free(text.cast());
                }
            }
        }
    }
}

/// `text` as a string of libxml2's allocator, null after a report.
fn give(here: Here, text: &str) -> *mut u8 {
    let size = text.len() + 1;
    let copy = malloc(size).cast::<u8>();
    if copy.is_null() {
        errors::malloc_failed(here, std::ptr::null(), size);
        return copy;
    }
    // SAFETY: a fresh allocation of the text and its terminator.
    unsafe {
        std::ptr::copy_nonoverlapping(text.as_ptr(), copy, text.len());
        *copy.add(text.len()) = 0;
    }
    copy
}

/// The trimmed text of `node`.
fn trimmed(node: *mut XmlNode) -> String {
    nodes::content(node).map_or_else(String::new, |text| {
        text.trim_matches(|c: char| c.is_ascii_whitespace())
            .to_owned()
    })
}

/// Whether `node` is the element `name` in `ns`.
fn is(node: *mut XmlNode, name: &[u8], ns: &[u8]) -> bool {
    // SAFETY: a live element and static names.
    unsafe { xmlSecCheckNodeName(node, name.as_ptr(), ns.as_ptr()) != 0 }
}

/// Reads the Base64 of `node` into `buffer`; empty text is skipped unless
/// the context stops on empty nodes.
///
/// # Safety
/// `buffer` is initialized; `node` a live element.
unsafe fn read_blob(
    here: Here,
    buffer: *mut XmlSecBuffer,
    node: *mut XmlNode,
    flags: c_uint,
) -> bool {
    let text = trimmed(node);
    if text.is_empty() {
        if flags & FLAGS_STOP_ON_EMPTY_NODE != 0 {
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_INVALID_NODE_CONTENT,
                "empty",
            );
            return false;
        }
        return true;
    }
    // libxmlsec1 decodes the trimmed text in place.
    let mut decoded = text.into_bytes();
    decoded.push(0);
    let mut size = 0;
    // SAFETY: a NUL-terminated copy the decoder may overwrite.
    if unsafe { xmlSecBase64DecodeInPlace(decoded.as_mut_ptr(), &raw mut size) } < 0 {
        errors::internal(here, std::ptr::null(), c"xmlSecBase64DecodeInPlace");
        return false;
    }
    // SAFETY: by the caller's contract; `size` decoded bytes lead the copy.
    if unsafe { xmlSecBufferSetData(buffer, decoded.as_ptr(), size) } < 0 {
        errors::internal(here, std::ptr::null(), c"xmlSecBufferSetData");
        return false;
    }
    true
}

/// Reads the trimmed text of `node` into `slot`; empty text leaves it null
/// unless the context stops on empty nodes.
fn read_string(here: Here, slot: &mut *mut u8, node: *mut XmlNode, flags: c_uint) -> bool {
    let text = trimmed(node);
    if text.is_empty() {
        if flags & FLAGS_STOP_ON_EMPTY_NODE != 0 {
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_INVALID_NODE_CONTENT,
                "empty",
            );
            return false;
        }
        return true;
    }
    *slot = give(here, &text);
    !slot.is_null()
}

/// Reads `node`, one `X509Data` child, into `value`, as libxmlsec1's
/// `xmlSecKeyX509DataValueXmlRead`.
///
/// # Safety
/// `node` is a live element.
unsafe fn read_child(
    here: Here,
    value: &mut X509DataValue,
    node: *mut XmlNode,
    flags: c_uint,
) -> bool {
    // SAFETY: by the caller's contract; the value's buffers are initialized.
    unsafe {
        if is(node, &xmlSecNodeX509Certificate, &xmlSecDSigNs) {
            read_blob(here, &raw mut value.cert, node, flags)
        } else if is(node, &xmlSecNodeX509CRL, &xmlSecDSigNs) {
            read_blob(here, &raw mut value.crl, node, flags)
        } else if is(node, &xmlSecNodeX509SKI, &xmlSecDSigNs) {
            read_blob(here, &raw mut value.ski, node, flags)
        } else if is(node, &xmlSecNodeX509SubjectName, &xmlSecDSigNs) {
            read_string(here, &mut value.subject, node, flags)
        } else if is(node, &xmlSecNodeX509IssuerSerial, &xmlSecDSigNs) {
            read_issuer_serial(here, value, node, flags)
        } else if is(node, &xmlSecNodeX509Digest, &xmlSecDSig11Ns) {
            let Some(algorithm) = nodes::property(node, "Algorithm") else {
                errors::report(
                    here,
                    std::ptr::null(),
                    xmlSecAttrAlgorithm.as_ptr().cast(),
                    errors::R_INVALID_NODE_ATTRIBUTE,
                    "empty",
                );
                return false;
            };
            value.digest_algorithm = give(here, &algorithm);
            !value.digest_algorithm.is_null() && read_blob(here, &raw mut value.digest, node, flags)
        } else if flags & FLAGS_STOP_ON_UNKNOWN_CHILD != 0 {
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_UNEXPECTED_NODE,
                &format!(
                    "node={}",
                    nodes::name(node).unwrap_or_else(|| "NULL".to_owned())
                ),
            );
            false
        } else {
            true
        }
    }
}

/// Reads an `X509IssuerSerial` element: `X509IssuerName` then
/// `X509SerialNumber` and nothing else.
fn read_issuer_serial(
    here: Here,
    value: &mut X509DataValue,
    node: *mut XmlNode,
    flags: c_uint,
) -> bool {
    let missing = |name: &str| {
        errors::report(
            here,
            std::ptr::null(),
            std::ptr::null(),
            errors::R_INVALID_NODE,
            &format!("expected={name}"),
        );
        false
    };
    // SAFETY: a live element.
    let first = unsafe { xmlSecGetNextElementNode(nodes_children(node)) };
    if first.is_null() {
        if flags & FLAGS_STOP_ON_EMPTY_NODE != 0 {
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_NODE_NOT_FOUND,
                "X509IssuerName",
            );
            return false;
        }
        return true;
    }
    if !is(first, &xmlSecNodeX509IssuerName, &xmlSecDSigNs) {
        return missing("X509IssuerName");
    }
    if !read_string(here, &mut value.issuer_name, first, flags) {
        return false;
    }
    // SAFETY: a live element.
    let second = unsafe { xmlSecGetNextElementNode(nodes::next(first)) };
    if second.is_null() || !is(second, &xmlSecNodeX509SerialNumber, &xmlSecDSigNs) {
        return missing("X509SerialNumber");
    }
    if !read_string(here, &mut value.issuer_serial, second, flags) {
        return false;
    }
    // SAFETY: a live element.
    let rest = unsafe { xmlSecGetNextElementNode(nodes::next(second)) };
    if !rest.is_null() {
        errors::report(
            here,
            std::ptr::null(),
            std::ptr::null(),
            errors::R_UNEXPECTED_NODE,
            &format!(
                "node={}",
                nodes::name(rest).unwrap_or_else(|| "NULL".to_owned())
            ),
        );
        return false;
    }
    true
}

/// The first child of `node`.
fn nodes_children(node: *mut XmlNode) -> *mut XmlNode {
    // SAFETY: a live node; the accessor validates the handle.
    unsafe { xml_sec_libxml2::ffi::tree::xsNodeGetChildren(node) }
}

/// Adds what `value` carries to `state`, or the store's certificate its
/// selectors name, as libxmlsec1's `xmlSecOpenSSLKeyDataX509Read`.
///
/// # Safety
/// `ctx` is a context with a keys manager.
unsafe fn collect(
    here: Here,
    state: &mut X509State,
    child: &ChildValue,
    ctx: *mut XmlSecKeyInfoCtx,
    resources: &xml_sec::policy::ResourcePolicy,
) -> bool {
    let cert = ChildValue::bytes(&child.value.cert);
    let crl = ChildValue::bytes(&child.value.crl);
    let cert = if cert.is_empty() {
        // SAFETY: by the caller's contract.
        let Some(store) = (unsafe { mngr_state((*ctx).keys_mngr) }) else {
            errors::internal(here, x509_name(), c"xmlSecKeysMngrGetDataStore");
            return false;
        };
        let Ok(found) = find(here, store, &child.selectors()) else {
            return false;
        };
        // SAFETY: a context.
        if found.is_none() && unsafe { (*ctx).flags } & FLAGS_STOP_ON_UNKNOWN_CERT != 0 {
            errors::report(
                here,
                x509_name(),
                std::ptr::null(),
                R_CERT_NOT_FOUND,
                "cert lookup",
            );
            return false;
        }
        found
    } else {
        if let Err(error) = parse_x509_certificate_with_resources(&cert, resources) {
            errors::internal_with(
                here,
                x509_name(),
                c"xmlSecOpenSSLX509CertDerRead",
                &error.to_string(),
            );
            return false;
        }
        Some(cert)
    };
    if let Some(cert) = cert {
        state.add_cert(cert, false);
    }
    if !crl.is_empty() {
        state.crls.push(crl);
    }
    true
}

/// Verifies the certificates of `data` against the X.509 store of the
/// context's keys manager and makes the verified certificate's key the
/// value of `key`, which then adopts `data`. `Ok(true)` when `key` adopted
/// `data`; `Ok(false)` when no certificate verified and the context does
/// not stop on that.
///
/// # Safety
/// `key` is a key without a value; `data` `X509Data` key data it may adopt;
/// `ctx` a context.
pub(crate) unsafe fn verify_and_adopt(
    here: Here,
    key: *mut XmlSecKey,
    data: *mut XmlSecKeyData,
    ctx: *mut XmlSecKeyInfoCtx,
) -> Result<bool, ()> {
    // SAFETY: by the caller's contract.
    unsafe {
        let mngr = (*ctx).keys_mngr;
        if mngr.is_null() {
            return Ok(false);
        }
        let Some(state) = state_of(data) else {
            errors::internal(here, x509_name(), c"xmlSecKeyDataCheckId");
            return Err(());
        };
        if state.certs.is_empty() || !xmlSecKeyGetValue(key).is_null() {
            return Ok(false);
        }
        let Some(store) = mngr_state(mngr) else {
            errors::internal(here, x509_name(), c"xmlSecKeysMngrGetDataStore");
            return Err(());
        };
        let Some(pinned) = read_policy(ctx, here) else {
            return Err(());
        };
        let policy = &*pinned.verification;
        let Some(verified) = verify(here, store, &state.certs, &state.crls, &*ctx, policy)? else {
            if (*ctx).flags & FLAGS_STOP_ON_INVALID_CERT != 0 {
                errors::report(here, x509_name(), std::ptr::null(), R_CERT_NOT_FOUND, "");
                return Err(());
            }
            return Ok(false);
        };
        let value = match KeyValueInfo::from_spki_der(&verified.spki, &policy.resources) {
            Ok(value) => value,
            Err(error) => {
                errors::internal_with(
                    here,
                    x509_name(),
                    c"xmlSecOpenSSLX509CertGetKey",
                    &error.to_string(),
                );
                return Err(());
            }
        };
        // libxmlsec1 keeps a copy of the verified certificate as the key's
        // certificate beside the one it verified.
        let cert = state.certs[verified.index].clone();
        state.certs.insert(0, cert);
        state.key_cert = Some(0);
        let value = asymkeys::adopt(Material {
            value,
            private: None,
        });
        if value.is_null() {
            errors::internal(here, x509_name(), c"xmlSecOpenSSLX509CertGetKey");
            return Err(());
        }
        // A verified certificate whose key the requirements refuse fails the
        // read, as libxmlsec1 refuses it after verification.
        if super::super::keys::xmlSecKeyReqMatchKeyValue(&raw mut (*ctx).key_req, value) != 1 {
            errors::internal(here, x509_name(), c"xmlSecKeyReqMatchKeyValue");
            xmlSecKeyDataDestroy(value);
            return Err(());
        }
        // A validity the target's `time_t` cannot hold fails the read, as
        // libxmlsec1's conversion of the certificate's times fails it.
        let (Some(not_before), Some(not_after)) = (
            super::time_of(verified.not_before.seconds()),
            super::time_of(verified.not_after.seconds()),
        ) else {
            errors::internal(here, x509_name(), c"xmlSecOpenSSLX509Asn1TimeToTime");
            xmlSecKeyDataDestroy(value);
            return Err(());
        };
        if super::super::keys::xmlSecKeySetValue(key, value) < 0 {
            errors::internal(here, x509_name(), c"xmlSecKeySetValue");
            xmlSecKeyDataDestroy(value);
            return Err(());
        }
        let (before, after) = ((*key).not_valid_before, (*key).not_valid_after);
        (*key).not_valid_before = not_before;
        (*key).not_valid_after = not_after;
        if xmlSecKeyAdoptData(key, data) < 0 {
            errors::internal(here, x509_name(), c"xmlSecKeyAdoptData");
            super::super::keys::xmlSecKeySetValue(key, std::ptr::null_mut());
            (*key).not_valid_before = before;
            (*key).not_valid_after = after;
            return Err(());
        }
        Ok(true)
    }
}

/// `xmlRead`: an `X509Data` element read into `key`.
unsafe extern "C" fn xml_read(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    node: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    let (key, node, ctx) = (
        key.cast::<XmlSecKey>(),
        node.cast::<XmlNode>(),
        ctx.cast::<XmlSecKeyInfoCtx>(),
    );
    contain(-1, || {
        let here = here!("xmlSecKeyDataX509XmlRead");
        for (failed, expression) in [
            (
                !std::ptr::eq(id, &raw const X509),
                c"id == xmlSecOpenSSLKeyDataX509Id",
            ),
            (key.is_null(), c"key != NULL"),
            (node.is_null(), c"node != NULL"),
            (ctx.is_null(), c"keyInfoCtx != NULL"),
        ] {
            if failed {
                errors::assertion(here, expression);
                return -1;
            }
        }
        // SAFETY: a context.
        let Some(pinned) = (unsafe { read_policy(ctx, here) }) else {
            return -1;
        };
        let data = create(here, X509State::default());
        // SAFETY: new key data of this klass.
        let Some(state) = (unsafe { state_of(data) }) else {
            return -1;
        };
        // SAFETY: a key, a live element and a context.
        let read =
            unsafe { read_children(here, key, node, ctx, state, &pinned.verification.resources) };
        // SAFETY: a key; the data is ours until the key adopts it.
        unsafe {
            if !read {
                xmlSecKeyDataDestroy(data);
                return -1;
            }
            if !xmlSecKeyGetValue(key).is_null() {
                xmlSecKeyDataDestroy(data);
                return 0;
            }
            match verify_and_adopt(here, key, data, ctx) {
                Ok(true) => 0,
                Ok(false) => {
                    xmlSecKeyDataDestroy(data);
                    0
                }
                Err(()) => {
                    xmlSecKeyDataDestroy(data);
                    -1
                }
            }
        }
    })
}

/// Reads each child of the `X509Data` element `node`: the keys manager's
/// key for the first child naming one, else the certificates and CRLs the
/// children carry or name.
///
/// # Safety
/// `key` is a key, `node` a live element, `ctx` a context.
unsafe fn read_children(
    here: Here,
    key: *mut XmlSecKey,
    node: *mut XmlNode,
    ctx: *mut XmlSecKeyInfoCtx,
    state: &mut X509State,
    resources: &xml_sec::policy::ResourcePolicy,
) -> bool {
    let mut key_found = false;
    // SAFETY: by the caller's contract.
    unsafe {
        let mut cur = xmlSecGetNextElementNode(nodes_children(node));
        while !cur.is_null() {
            let Some(mut child) = ChildValue::new(here) else {
                return false;
            };
            if !read_child(here, &mut child.value, cur, (*ctx).flags) {
                return false;
            }
            let mngr = (*ctx).keys_mngr;
            if !key_found && !mngr.is_null() {
                let found =
                    xmlSecKeysMngrFindKeyFromX509Data(mngr, (&raw mut child.value).cast(), ctx);
                if !found.is_null() {
                    let swapped = xmlSecKeySwap(key, found);
                    xmlSecKeyDestroy(found);
                    if swapped < 0 {
                        errors::internal(here, x509_name(), c"xmlSecKeySwap");
                        return false;
                    }
                    key_found = true;
                }
            }
            if !key_found && !mngr.is_null() && !collect(here, state, &child, ctx, resources) {
                return false;
            }
            cur = xmlSecGetNextElementNode(nodes::next(cur));
        }
    }
    true
}

/// The kinds of node the `X509Data` template `node` holds, each empty one
/// as its bit and each with content shifted, and the algorithm of its first
/// `X509Digest`.
fn template_content(here: Here, node: *mut XmlNode) -> Result<(c_int, Option<String>), ()> {
    let mut content = 0;
    let mut algorithm = None;
    // SAFETY: a live element.
    let mut cur = unsafe { xmlSecGetNextElementNode(nodes_children(node)) };
    while !cur.is_null() {
        let kind = [
            (
                &xmlSecNodeX509Certificate[..],
                &xmlSecDSigNs[..],
                CERTIFICATE_NODE,
            ),
            (&xmlSecNodeX509SubjectName, &xmlSecDSigNs, SUBJECT_NAME_NODE),
            (
                &xmlSecNodeX509IssuerSerial,
                &xmlSecDSigNs,
                ISSUER_SERIAL_NODE,
            ),
            (&xmlSecNodeX509SKI, &xmlSecDSigNs, SKI_NODE),
            (&xmlSecNodeX509Digest, &xmlSecDSig11Ns, DIGEST_NODE),
            (&xmlSecNodeX509CRL, &xmlSecDSigNs, CRL_NODE),
        ]
        .into_iter()
        .find_map(|(name, ns, kind)| is(cur, name, ns).then_some(kind));
        if let Some(kind) = kind {
            // SAFETY: a live element.
            let empty = unsafe { super::super::xmltree::xmlSecIsEmptyNode(cur) };
            if empty < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecIsEmptyNode");
                return Err(());
            }
            content |= if empty == 1 {
                kind
            } else {
                kind << SHIFT_IF_NOT_EMPTY
            };
            if kind == DIGEST_NODE && algorithm.is_none() {
                let Some(found) = nodes::property(cur, "Algorithm") else {
                    errors::report(
                        here,
                        std::ptr::null(),
                        xmlSecAttrAlgorithm.as_ptr().cast(),
                        errors::R_INVALID_NODE_ATTRIBUTE,
                        "empty",
                    );
                    return Err(());
                };
                algorithm = Some(found);
            }
        }
        // SAFETY: a live element.
        cur = unsafe { xmlSecGetNextElementNode(nodes::next(cur)) };
    }
    Ok((content, algorithm))
}

/// Writes `bytes` as the Base64 content of the child `name` in `ns` of
/// `node`, between line feeds, emptying the child first.
///
/// # Safety
/// `node` is a live element.
unsafe fn write_blob(
    node: *mut XmlNode,
    name: &[u8],
    ns: &[u8],
    bytes: &[u8],
) -> Result<*mut XmlNode, &'static CStr> {
    // SAFETY: by the caller's contract; the encoded text is freed here.
    unsafe {
        let text = xmlSecBase64Encode(
            bytes.as_ptr(),
            bytes.len(),
            xmlSecBase64GetDefaultLineSize(),
        );
        if text.is_null() {
            return Err(c"xmlSecBase64Encode");
        }
        let encoded = c_text(text).unwrap_or_default().to_owned();
        free(text.cast());
        let child = xmlSecEnsureEmptyChild(node, name.as_ptr(), ns.as_ptr());
        if child.is_null() {
            return Err(c"xmlSecEnsureEmptyChild");
        }
        let line_feed = c_text(xmlSecGetDefaultLineFeed()).unwrap_or_default();
        nodes::set_content(child, &format!("{line_feed}{encoded}{line_feed}"))
            .map_err(|_| c"xmlNodeSetContent")?;
        Ok(child)
    }
}

/// Writes `text` as the content of the child `name` in `ns` of `node`,
/// emptying the child first.
///
/// # Safety
/// `node` is a live element.
unsafe fn write_string(
    node: *mut XmlNode,
    name: &[u8],
    ns: &[u8],
    text: &str,
) -> Result<*mut XmlNode, &'static CStr> {
    // SAFETY: by the caller's contract.
    let child = unsafe { xmlSecEnsureEmptyChild(node, name.as_ptr(), ns.as_ptr()) };
    if child.is_null() {
        return Err(c"xmlSecEnsureEmptyChild");
    }
    nodes::set_content(child, text).map_err(|_| c"xmlNodeSetContent")?;
    Ok(child)
}

/// Writes the certificate `der` into `node` for each kind `content` asks for
/// with an empty node, as libxmlsec1's `xmlSecOpenSSLKeyDataX509Write`.
///
/// # Safety
/// `node` is a live element.
unsafe fn write_certificate(
    node: *mut XmlNode,
    der: &[u8],
    content: c_int,
    algorithm: Option<&str>,
    resources: &xml_sec::policy::ResourcePolicy,
) -> Result<(), &'static CStr> {
    let wants = |kind: c_int| content & kind != 0;
    let parsed = if wants(SUBJECT_NAME_NODE | ISSUER_SERIAL_NODE | SKI_NODE) {
        Some(
            parse_x509_certificate_with_resources(der, resources)
                .map_err(|_| c"xmlSecOpenSSLX509CertDerRead")?,
        )
    } else {
        None
    };
    // SAFETY: by the caller's contract.
    unsafe {
        if wants(CERTIFICATE_NODE) {
            write_blob(node, &xmlSecNodeX509Certificate, &xmlSecDSigNs, der)?;
        }
        if let Some(parsed) = &parsed {
            if wants(SKI_NODE) {
                let ski = parsed
                    .subject_key_identifier
                    .as_deref()
                    .ok_or(c"xmlSecOpenSSLX509SKIWrite")?;
                write_blob(node, &xmlSecNodeX509SKI, &xmlSecDSigNs, ski)?;
            }
            if wants(SUBJECT_NAME_NODE) {
                write_string(
                    node,
                    &xmlSecNodeX509SubjectName,
                    &xmlSecDSigNs,
                    &parsed.subject_dn,
                )?;
            }
            if wants(ISSUER_SERIAL_NODE) {
                let issuer_serial = xmlSecEnsureEmptyChild(
                    node,
                    xmlSecNodeX509IssuerSerial.as_ptr(),
                    xmlSecDSigNs.as_ptr(),
                );
                if issuer_serial.is_null() {
                    return Err(c"xmlSecEnsureEmptyChild");
                }
                write_string(
                    issuer_serial,
                    &xmlSecNodeX509IssuerName,
                    &xmlSecDSigNs,
                    &parsed.issuer_dn,
                )?;
                write_string(
                    issuer_serial,
                    &xmlSecNodeX509SerialNumber,
                    &xmlSecDSigNs,
                    &parsed.serial_number_decimal,
                )?;
            }
        }
        if let Some(algorithm) = algorithm.filter(|_| wants(DIGEST_NODE)) {
            let digest = xml_sec::xmldsig::DigestAlgorithm::from_uri(algorithm)
                .ok_or(c"xmlSecOpenSSLX509GetDigestFromAlgorithm")?;
            let failed = |_| c"xmlSecOpenSSLX509DigestWrite";
            let mut state = xml_sec::xmldsig::IncrementalDigest::begin(
                xml_sec::provider::default_provider(),
                digest,
            )
            .map_err(failed)?;
            state.update(der).map_err(failed)?;
            let value = state.finish().map_err(failed)?;
            let child = write_blob(node, &xmlSecNodeX509Digest, &xmlSecDSig11Ns, value.as_ref())?;
            let name = std::ffi::CString::new(algorithm).map_err(|_| c"xmlSetProp")?;
            if xml_sec_libxml2::ffi::tree::xsSetProp(
                child,
                xmlSecAttrAlgorithm.as_ptr(),
                name.as_ptr().cast(),
            )
            .is_null()
            {
                return Err(c"xmlSetProp");
            }
        }
    }
    Ok(())
}

/// `xmlWrite`: the certificates and CRLs of the key's X.509 data into the
/// `X509Data` element `node`, for the kinds of node its template names, by
/// default the certificates and CRLs.
unsafe extern "C" fn xml_write(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    node: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    let (key, node, ctx) = (
        key.cast::<XmlSecKey>(),
        node.cast::<XmlNode>(),
        ctx.cast::<XmlSecKeyInfoCtx>(),
    );
    contain(-1, || {
        let here = here!("xmlSecKeyDataX509XmlWrite");
        for (failed, expression) in [
            (
                !std::ptr::eq(id, &raw const X509),
                c"id == xmlSecOpenSSLKeyDataX509Id",
            ),
            (key.is_null(), c"key != NULL"),
            (node.is_null(), c"node != NULL"),
            (ctx.is_null(), c"keyInfoCtx != NULL"),
        ] {
            if failed {
                errors::assertion(here, expression);
                return -1;
            }
        }
        // SAFETY: a key and a context.
        let (data, key_type) = unsafe { (xmlSecKeyGetData(key, id), (*ctx).key_req.key_type) };
        // SAFETY: the key's data.
        let Some(state) = (unsafe { state_of(data) }) else {
            return 0;
        };
        // Only a public key's certificates are written.
        if key_type & TYPE_PUBLIC == 0 {
            return 0;
        }
        // SAFETY: a context.
        let Some(pinned) = (unsafe { read_policy(ctx, here) }) else {
            return -1;
        };
        let Ok((mut content, algorithm)) = template_content(here, node) else {
            return -1;
        };
        if content == 0 {
            content = DEFAULT_CONTENT;
        }
        let resources = &pinned.verification.resources;
        for der in &state.certs {
            // SAFETY: a live element.
            let written =
                unsafe { write_certificate(node, der, content, algorithm.as_deref(), resources) };
            if let Err(failed) = written {
                errors::internal(here, x509_name(), failed);
                return -1;
            }
        }
        if content & CRL_NODE != 0 {
            for der in &state.crls {
                // SAFETY: a live element.
                let written = unsafe { write_blob(node, &xmlSecNodeX509CRL, &xmlSecDSigNs, der) };
                if let Err(failed) = written {
                    errors::internal(here, x509_name(), failed);
                    return -1;
                }
            }
        }
        0
    })
}

/// The subject, issuer and serial number lines of the certificate `der`, as
/// libxmlsec1's OpenSSL debug dumps print them.
fn certificate_lines(der: &[u8]) -> (String, String, String) {
    match parse_x509_certificate_with_resources(der, &xml_sec::policy::ResourcePolicy::default()) {
        Ok(parsed) => (
            parsed.subject_dn,
            parsed.issuer_dn,
            parsed.serial_number_hex,
        ),
        Err(_) => ("unknown".into(), "unknown".into(), "unknown".into()),
    }
}

unsafe extern "C" fn debug_dump(data: *mut XmlSecKeyData, output: *mut c_void) {
    contain((), || {
        // SAFETY: the registry passes key data of this klass.
        let Some(state) = (unsafe { state_of(data) }) else {
            return;
        };
        let mut text = String::from("=== X509 Data:\n");
        let mut certificate = |label: &str, der: &[u8]| {
            let (subject, issuer, serial) = certificate_lines(der);
            let _written = write!(
                text,
                "==== {label}:\n==== Subject Name: {subject}\n==== Issuer Name: {issuer}\n==== Issuer Serial: {serial}\n"
            );
        };
        if let Some(key) = state.key_cert {
            certificate("Key Certificate", &state.certs[key]);
        }
        for der in &state.certs {
            certificate("Certificate", der);
        }
        // SAFETY: the caller's `FILE*`.
        unsafe { write_stream(output, &text) };
    });
}

unsafe extern "C" fn debug_xml_dump(data: *mut XmlSecKeyData, output: *mut c_void) {
    contain((), || {
        // SAFETY: the registry passes key data of this klass.
        let Some(state) = (unsafe { state_of(data) }) else {
            return;
        };
        let escape = |text: &str| {
            text.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
        };
        let mut text = String::from("<X509Data>\n");
        let mut certificate = |element: &str, der: &[u8]| {
            let (subject, issuer, serial) = certificate_lines(der);
            let _written = write!(
                text,
                "<{element}>\n<SubjectName>{}</SubjectName>\n<IssuerName>{}</IssuerName>\n<SerialNumber>{serial}</SerialNumber>\n</{element}>\n",
                escape(&subject),
                escape(&issuer)
            );
        };
        if let Some(key) = state.key_cert {
            certificate("KeyCertificate", &state.certs[key]);
        }
        for der in &state.certs {
            certificate("Certificate", der);
        }
        text.push_str("</X509Data>\n");
        // SAFETY: the caller's `FILE*`.
        unsafe { write_stream(output, &text) };
    });
}

/// `binRead` of the raw certificate klass: the DER certificate `buf` as the
/// X.509 data of `key`, its key the key's value once the store verifies it.
unsafe extern "C" fn raw_bin_read(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    buf: *const u8,
    size: usize,
    ctx: *mut c_void,
) -> c_int {
    let (key, ctx) = (key.cast::<XmlSecKey>(), ctx.cast::<XmlSecKeyInfoCtx>());
    contain(-1, || {
        let here = here!("xmlSecOpenSSLKeyDataRawX509CertBinRead");
        for (failed, expression) in [
            (
                !std::ptr::eq(id, &raw const RAW),
                c"id == xmlSecOpenSSLKeyDataRawX509CertId",
            ),
            (key.is_null(), c"key != NULL"),
            (buf.is_null(), c"buf != NULL"),
            (size == 0, c"bufSize > 0"),
            (ctx.is_null(), c"keyInfoCtx != NULL"),
        ] {
            if failed {
                errors::assertion(here, expression);
                return -1;
            }
        }
        // SAFETY: a context.
        let Some(pinned) = (unsafe { read_policy(ctx, here) }) else {
            return -1;
        };
        // SAFETY: the caller's `size` bytes.
        let der = unsafe { std::slice::from_raw_parts(buf, size) }.to_vec();
        if let Err(error) =
            parse_x509_certificate_with_resources(&der, &pinned.verification.resources)
        {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecOpenSSLX509CertDerRead",
                &error.to_string(),
            );
            return -1;
        }
        let mut state = X509State::default();
        state.add_cert(der, false);
        let data = create(here, state);
        if data.is_null() {
            return -1;
        }
        // SAFETY: a key, our data and a context.
        unsafe {
            match verify_and_adopt(here, key, data, ctx) {
                Ok(true) => 0,
                Ok(false) => {
                    xmlSecKeyDataDestroy(data);
                    0
                }
                Err(()) => {
                    xmlSecKeyDataDestroy(data);
                    -1
                }
            }
        }
    })
}
