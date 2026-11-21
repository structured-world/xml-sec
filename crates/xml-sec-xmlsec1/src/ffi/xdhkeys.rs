//! The built-in provider's XDH key-data klass: X25519 and X448 keys (RFC
//! 8410), member of the built-in crypto table.
//!
//! As libxmlsec1's, the klass has no `KeyValue` element: its keys come from
//! key files, read by the core's key importer, and serve key agreement only.
//! An object holds the public key as its `SubjectPublicKeyInfo` and, for a
//! private key, the PKCS#8 the importer normalized it to.

use std::ffi::{c_int, c_uint, c_void};

use zeroize::Zeroizing;

use super::errors::{self, here};
use super::keys::{TYPE_PRIVATE, TYPE_PUBLIC, TYPE_UNKNOWN};
use super::keysdata::{
    USAGE_READ_FROM_FILE, USAGE_RETRIEVAL_METHOD_NODE_XML, XmlSecKeyData, XmlSecKeyDataKlass,
    data_valid, xmlSecKeyDataCreate, xmlSecKeyDataGetSize,
};
use super::strings::{xmlSecHrefXDHKeyValue, xmlSecNameXDHKeyValue};
use super::transforms::klass_text;
use super::{contain, write_stream};

/// The DER prefix of an id-X25519 `SubjectPublicKeyInfo` before its 32-octet
/// key: RFC 8410 sections 3 and 4 fix the encoding, absent parameters
/// included.
const X25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
];
/// The DER prefix of an id-X448 `SubjectPublicKeyInfo` before its 56-octet
/// key (RFC 8410 sections 3 and 4).
const X448_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x42, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6f, 0x03, 0x39, 0x00,
];

/// The curve of an XDH key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Curve {
    X25519,
    X448,
}

/// An XDH key: its public key and, when held, its private key.
#[derive(Clone)]
pub(crate) struct XdhKey {
    /// The DER `SubjectPublicKeyInfo` of the public key.
    pub(crate) spki: Vec<u8>,
    /// The PKCS#8 DER of the private key, when the key holds one.
    pub(crate) private: Option<Zeroizing<Vec<u8>>>,
}

/// The curve and raw public key (RFC 7748 u-coordinate) of the X25519 or
/// X448 `SubjectPublicKeyInfo` `spki`; `None` for any other key.
pub(crate) fn public_of(spki: &[u8]) -> Option<(Curve, &[u8])> {
    if let Some(key) = spki.strip_prefix(&X25519_SPKI_PREFIX[..])
        && key.len() == 32
    {
        return Some((Curve::X25519, key));
    }
    let key = spki.strip_prefix(&X448_SPKI_PREFIX[..])?;
    (key.len() == 56).then_some((Curve::X448, key))
}

impl XdhKey {
    /// The curve and raw public key of the key.
    pub(crate) fn public(&self) -> Option<(Curve, &[u8])> {
        public_of(&self.spki)
    }
}

/// An XDH key-data object: the key data and its key, null until one is set.
#[repr(C)]
struct XdhData {
    data: XmlSecKeyData,
    key: *mut XdhKey,
}

static XDH: XmlSecKeyDataKlass = XmlSecKeyDataKlass {
    klass_size: size_of::<XmlSecKeyDataKlass>(),
    obj_size: size_of::<XdhData>(),
    name: xmlSecNameXDHKeyValue.as_ptr(),
    usage: USAGE_READ_FROM_FILE | USAGE_RETRIEVAL_METHOD_NODE_XML,
    href: xmlSecHrefXDHKeyValue.as_ptr(),
    data_node_name: std::ptr::null(),
    data_node_ns: std::ptr::null(),
    initialize: Some(initialize),
    duplicate: Some(duplicate),
    finalize: Some(finalize),
    // Key generation is not a capability of the built-in provider.
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

/// The built-in table's XDH klass.
pub(crate) extern "C" fn xdh() -> *const XmlSecKeyDataKlass {
    &raw const XDH
}

/// The object of valid key data of this klass.
///
/// # Safety
/// `data` is null or a key-data object.
unsafe fn object<'a>(data: *mut XmlSecKeyData) -> Option<&'a mut XdhData> {
    // SAFETY: by the caller's contract; a valid object of the klass has the
    // XDH layout.
    unsafe {
        (data_valid(data) && std::ptr::eq((*data).id, &raw const XDH))
            .then(|| &mut *data.cast::<XdhData>())
    }
}

/// The key `data` holds, if it is XDH key data holding one.
///
/// # Safety
/// As for [`object`].
pub(crate) unsafe fn key_of<'a>(data: *mut XmlSecKeyData) -> Option<&'a XdhKey> {
    // SAFETY: by the caller's contract; a non-null key is the object's.
    unsafe { object(data).and_then(|object| object.key.as_ref()) }
}

/// New XDH key data holding `key`; null when it cannot be created.
pub(crate) fn adopt(key: XdhKey) -> *mut XmlSecKeyData {
    // SAFETY: the klass of this module.
    unsafe {
        let data = xmlSecKeyDataCreate(&raw const XDH);
        if let Some(object) = object(data) {
            replace(object, key);
        }
        data
    }
}

/// Makes `key` the key of `object`, releasing the previous one.
fn replace(object: &mut XdhData, key: XdhKey) {
    release(object);
    object.key = Box::into_raw(Box::new(key));
}

/// Releases the key of `object`; a private key is zeroized.
fn release(object: &mut XdhData) {
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
            Some(XdhKey {
                private: Some(_), ..
            }) => TYPE_PUBLIC | TYPE_PRIVATE,
            Some(_) => TYPE_PUBLIC,
            None => TYPE_UNKNOWN,
        }
    })
}

/// `getSize`: the curve's security size in bits as OpenSSL counts it
/// (`EVP_PKEY_bits`): 253 for X25519, 448 for X448.
unsafe extern "C" fn get_size(data: *mut XmlSecKeyData) -> usize {
    contain(0, || {
        // SAFETY: the registry passes key data of this klass.
        match unsafe { key_of(data) }.and_then(XdhKey::public) {
            Some((Curve::X25519, _)) => 253,
            Some((Curve::X448, _)) => 448,
            None => 0,
        }
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
