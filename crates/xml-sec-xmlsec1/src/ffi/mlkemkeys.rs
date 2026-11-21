//! The built-in provider's ML-KEM key-data klass (FIPS 203 keys, RFC 9935
//! encodings), member of the built-in crypto table.
//!
//! As libxmlsec1's, the klass has no `KeyValue` element: its keys come from
//! key files, read by the core's key importer, and serve key encapsulation
//! only. An object holds the public key as its `SubjectPublicKeyInfo`, the
//! parameter set the core read from it and, for a private key, the PKCS#8
//! the importer normalized it to.

use std::ffi::{c_int, c_uint, c_void};

use xml_sec::provider::{KeyEncapsulationAlgorithm, KeyEncapsulationKey, RustCryptoMlKemPublicKey};
use zeroize::Zeroizing;

use super::errors::{self, here};
use super::keys::{TYPE_PRIVATE, TYPE_PUBLIC, TYPE_UNKNOWN};
use super::keysdata::{
    USAGE_READ_FROM_FILE, USAGE_RETRIEVAL_METHOD_NODE_XML, XmlSecKeyData, XmlSecKeyDataKlass,
    data_valid, xmlSecKeyDataCreate, xmlSecKeyDataGetSize,
};
use super::strings::xmlSecNameMLKEMKeyValue;
use super::transforms::klass_text;
use super::{contain, write_stream};

/// An ML-KEM key: its parameter set, public key and, when held, private key.
#[derive(Clone)]
pub(crate) struct MlKemKey {
    /// The parameter set of the key.
    pub(crate) algorithm: KeyEncapsulationAlgorithm,
    /// The DER `SubjectPublicKeyInfo` of the public key.
    pub(crate) spki: Vec<u8>,
    /// The PKCS#8 DER of the private key, when the key holds one.
    pub(crate) private: Option<Zeroizing<Vec<u8>>>,
}

/// The parameter set of the ML-KEM `SubjectPublicKeyInfo` `spki`, as the
/// core reads it (RFC 9935 section 4); `None` for any other key.
pub(crate) fn algorithm_of(spki: &[u8]) -> Option<KeyEncapsulationAlgorithm> {
    RustCryptoMlKemPublicKey::from_spki_der(spki)
        .ok()
        .map(|key| key.algorithm())
}

/// An ML-KEM key-data object: the key data and its key, null until one is
/// set.
#[repr(C)]
struct MlKemData {
    data: XmlSecKeyData,
    key: *mut MlKemKey,
}

static MLKEM: XmlSecKeyDataKlass = XmlSecKeyDataKlass {
    klass_size: size_of::<XmlSecKeyDataKlass>(),
    obj_size: size_of::<MlKemData>(),
    name: xmlSecNameMLKEMKeyValue.as_ptr(),
    usage: USAGE_READ_FROM_FILE | USAGE_RETRIEVAL_METHOD_NODE_XML,
    // libxmlsec1 names no href for the klass.
    href: std::ptr::null(),
    data_node_name: std::ptr::null(),
    data_node_ns: std::ptr::null(),
    initialize: Some(initialize),
    duplicate: Some(duplicate),
    finalize: Some(finalize),
    // Key generation is not a capability of the built-in table.
    generate: None,
    get_type: Some(get_type),
    get_size: Some(get_size),
    deprecated0: std::ptr::null_mut(),
    xml_read: None,
    xml_write: None,
    bin_read: None,
    bin_write: None,
    debug_dump: Some(debug_dump),
    debug_xml_dump: Some(debug_xml_dump),
    reserved0: std::ptr::null_mut(),
    reserved1: std::ptr::null_mut(),
};

/// The built-in table's ML-KEM klass.
pub(crate) extern "C" fn mlkem() -> *const XmlSecKeyDataKlass {
    &raw const MLKEM
}

/// The object of valid key data of this klass.
///
/// # Safety
/// `data` is null or a key-data object.
unsafe fn object<'a>(data: *mut XmlSecKeyData) -> Option<&'a mut MlKemData> {
    // SAFETY: by the caller's contract; a valid object of the klass has the
    // ML-KEM layout.
    unsafe {
        (data_valid(data) && std::ptr::eq((*data).id, &raw const MLKEM))
            .then(|| &mut *data.cast::<MlKemData>())
    }
}

/// The key `data` holds, if it is ML-KEM key data holding one.
///
/// # Safety
/// As for [`object`].
pub(crate) unsafe fn key_of<'a>(data: *mut XmlSecKeyData) -> Option<&'a MlKemKey> {
    // SAFETY: by the caller's contract; a non-null key is the object's.
    unsafe { object(data).and_then(|object| object.key.as_ref()) }
}

/// New ML-KEM key data holding `key`; null when it cannot be created.
pub(crate) fn adopt(key: MlKemKey) -> *mut XmlSecKeyData {
    // SAFETY: the klass of this module.
    unsafe {
        let data = xmlSecKeyDataCreate(&raw const MLKEM);
        if let Some(object) = object(data) {
            replace(object, key);
        }
        data
    }
}

/// Makes `key` the key of `object`, releasing the previous one.
fn replace(object: &mut MlKemData, key: MlKemKey) {
    release(object);
    object.key = Box::into_raw(Box::new(key));
}

/// Releases the key of `object`; a private key is zeroized.
fn release(object: &mut MlKemData) {
    if !object.key.is_null() {
        // SAFETY: a non-null key was boxed by `replace` and is owned here.
        drop(unsafe { Box::from_raw(object.key) });
        object.key = std::ptr::null_mut();
    }
}

unsafe extern "C" fn initialize(data: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        // SAFETY: the registry passes key data of this klass.
        let Some(object) = (unsafe { object(data) }) else {
            errors::assertion(
                here!("xmlSecKeyDataInitialize"),
                c"xmlSecKeyDataIsValid(data)",
            );
            return -1;
        };
        object.key = std::ptr::null_mut();
        0
    })
}

unsafe extern "C" fn duplicate(dst: *mut XmlSecKeyData, src: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        // SAFETY: the registry passes key data of this klass.
        let (Some(target), Some(source)) = (unsafe { object(dst) }, unsafe { object(src) }) else {
            errors::assertion(
                here!("xmlSecKeyDataDuplicate"),
                c"xmlSecKeyDataIsValid(dst) && xmlSecKeyDataIsValid(src)",
            );
            return -1;
        };
        // SAFETY: a non-null key is the source's own.
        if let Some(key) = unsafe { source.key.as_ref() } {
            replace(target, key.clone());
        }
        0
    })
}

unsafe extern "C" fn finalize(data: *mut XmlSecKeyData) {
    contain((), || {
        // SAFETY: the registry passes key data of this klass.
        if let Some(object) = unsafe { object(data) } {
            release(object);
        }
    });
}

/// `getType`: a public key, with its private key when the object holds one.
unsafe extern "C" fn get_type(data: *mut XmlSecKeyData) -> c_uint {
    contain(TYPE_UNKNOWN, || {
        // SAFETY: the registry passes key data of this klass.
        match unsafe { key_of(data) } {
            Some(MlKemKey {
                private: Some(_), ..
            }) => TYPE_PUBLIC | TYPE_PRIVATE,
            Some(_) => TYPE_PUBLIC,
            None => TYPE_UNKNOWN,
        }
    })
}

/// `getSize`: the parameter set's size, 512, 768 or 1024.
unsafe extern "C" fn get_size(data: *mut XmlSecKeyData) -> usize {
    contain(0, || {
        // SAFETY: the registry passes key data of this klass.
        unsafe { key_of(data) }.map_or(0, |key| match key.algorithm {
            KeyEncapsulationAlgorithm::MlKem512 => 512,
            KeyEncapsulationAlgorithm::MlKem768 => 768,
            KeyEncapsulationAlgorithm::MlKem1024 => 1024,
        })
    })
}

/// `debugDump`: the klass name and key size; the key itself is not printed.
unsafe extern "C" fn debug_dump(data: *mut XmlSecKeyData, output: *mut c_void) {
    contain((), || {
        // SAFETY: the dispatcher passes valid key data and a C stream.
        unsafe {
            let name = klass_text((*(*data).id).name);
            let size = xmlSecKeyDataGetSize(data);
            write_stream(output, &format!("=== {name} key: size = {size}\n"));
        }
    });
}

/// `debugXmlDump`: the klass name and key size as an XML element.
unsafe extern "C" fn debug_xml_dump(data: *mut XmlSecKeyData, output: *mut c_void) {
    contain((), || {
        // SAFETY: the dispatcher passes valid key data and a C stream.
        unsafe {
            let name = klass_text((*(*data).id).name);
            let size = xmlSecKeyDataGetSize(data);
            write_stream(output, &format!("<{name} size=\"{size}\"/>\n"));
        }
    });
}
