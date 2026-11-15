//! The built-in provider's symmetric key-data klasses: AES, Camellia,
//! `ChaCha20`, DES and HMAC keys in their `KeyValue` children, and the
//! `ConcatKDF`, PBKDF2 and HKDF derivation keys, which are read only from
//! files. Each is a binary value whose bytes the built-in provider
//! generates; the klasses are the members of the built-in crypto table.

use std::ffi::{c_int, c_uint};

use super::buffer::{xmlSecBufferGetData, xmlSecBufferGetSize, xmlSecBufferSetSize};
use super::contain;
use super::errors::{self, check, here};
use super::keys::{TYPE_SYMMETRIC, TYPE_UNKNOWN};
use super::keysdata::{
    USAGE_KEY_VALUE_NODE, USAGE_READ_FROM_FILE, USAGE_RETRIEVAL_METHOD_NODE_XML, XmlMethod,
    XmlSecKeyData, XmlSecKeyDataKlass, data_valid, value_bin_read, value_bin_write,
    value_debug_dump, value_debug_xml_dump, value_duplicate, value_finalize, value_initialize,
    value_xml_read, value_xml_write, xmlSecKeyDataBinaryValueGetBuffer,
    xmlSecKeyDataBinaryValueGetSize,
};
use super::strings::{
    xmlSecHrefAESKeyValue, xmlSecHrefCamelliaKeyValue, xmlSecHrefChaCha20KeyValue,
    xmlSecHrefConcatKdf, xmlSecHrefDESKeyValue, xmlSecHrefHMACKeyValue, xmlSecHrefHkdf,
    xmlSecHrefPbkdf2, xmlSecNameAESKeyValue, xmlSecNameCamelliaKeyValue,
    xmlSecNameChaCha20KeyValue, xmlSecNameConcatKdf, xmlSecNameDESKeyValue, xmlSecNameHMACKeyValue,
    xmlSecNameHkdf, xmlSecNamePbkdf2, xmlSecNodeAESKeyValue, xmlSecNodeCamelliaKeyValue,
    xmlSecNodeChaCha20KeyValue, xmlSecNodeDESKeyValue, xmlSecNodeHMACKeyValue, xmlSecNs,
};

/// A symmetric klass: a binary value of the built-in provider.
const fn klass(
    name: *const u8,
    href: *const u8,
    usage: c_uint,
    node: *const u8,
    ns: *const u8,
    xml_read: XmlMethod,
    xml_write: XmlMethod,
) -> XmlSecKeyDataKlass {
    XmlSecKeyDataKlass {
        klass_size: size_of::<XmlSecKeyDataKlass>(),
        obj_size: super::keysdata::BINARY_SIZE,
        name,
        usage,
        href,
        data_node_name: node,
        data_node_ns: ns,
        initialize: Some(initialize),
        duplicate: Some(duplicate),
        finalize: Some(finalize),
        generate: Some(generate),
        get_type: Some(get_type),
        get_size: Some(get_size),
        deprecated0: std::ptr::null_mut(),
        xml_read,
        xml_write,
        bin_read: Some(value_bin_read),
        bin_write: Some(value_bin_write),
        debug_dump: Some(value_debug_dump),
        debug_xml_dump: Some(value_debug_xml_dump),
        reserved0: std::ptr::null_mut(),
        reserved1: std::ptr::null_mut(),
    }
}

/// A symmetric klass carried in its own `KeyValue` child.
const fn key_value(name: *const u8, href: *const u8, node: *const u8) -> XmlSecKeyDataKlass {
    klass(
        name,
        href,
        USAGE_READ_FROM_FILE | USAGE_KEY_VALUE_NODE | USAGE_RETRIEVAL_METHOD_NODE_XML,
        node,
        xmlSecNs.as_ptr(),
        Some(value_xml_read),
        Some(value_xml_write),
    )
}

/// A derivation-key klass, read only from files.
const fn file_only(name: *const u8, href: *const u8) -> XmlSecKeyDataKlass {
    klass(
        name,
        href,
        USAGE_READ_FROM_FILE,
        std::ptr::null(),
        std::ptr::null(),
        None,
        None,
    )
}

static AES: XmlSecKeyDataKlass = key_value(
    xmlSecNameAESKeyValue.as_ptr(),
    xmlSecHrefAESKeyValue.as_ptr(),
    xmlSecNodeAESKeyValue.as_ptr(),
);
static CAMELLIA: XmlSecKeyDataKlass = key_value(
    xmlSecNameCamelliaKeyValue.as_ptr(),
    xmlSecHrefCamelliaKeyValue.as_ptr(),
    xmlSecNodeCamelliaKeyValue.as_ptr(),
);
static CHACHA20: XmlSecKeyDataKlass = key_value(
    xmlSecNameChaCha20KeyValue.as_ptr(),
    xmlSecHrefChaCha20KeyValue.as_ptr(),
    xmlSecNodeChaCha20KeyValue.as_ptr(),
);
static CONCAT_KDF: XmlSecKeyDataKlass =
    file_only(xmlSecNameConcatKdf.as_ptr(), xmlSecHrefConcatKdf.as_ptr());
static DES: XmlSecKeyDataKlass = key_value(
    xmlSecNameDESKeyValue.as_ptr(),
    xmlSecHrefDESKeyValue.as_ptr(),
    xmlSecNodeDESKeyValue.as_ptr(),
);
static HMAC: XmlSecKeyDataKlass = key_value(
    xmlSecNameHMACKeyValue.as_ptr(),
    xmlSecHrefHMACKeyValue.as_ptr(),
    xmlSecNodeHMACKeyValue.as_ptr(),
);
static PBKDF2: XmlSecKeyDataKlass = file_only(xmlSecNamePbkdf2.as_ptr(), xmlSecHrefPbkdf2.as_ptr());
static HKDF: XmlSecKeyDataKlass = file_only(xmlSecNameHkdf.as_ptr(), xmlSecHrefHkdf.as_ptr());

/// Valid key data of one of the symmetric klasses.
///
/// # Safety
/// `data` is null or a key-data object.
unsafe fn symmetric(data: *mut XmlSecKeyData) -> bool {
    // SAFETY: by the caller's contract.
    unsafe { data_valid(data) && is_symmetric((*data).id) }
}

/// `klass` is one of the symmetric klasses.
fn is_symmetric(klass: *const XmlSecKeyDataKlass) -> bool {
    [
        &AES,
        &CAMELLIA,
        &CHACHA20,
        &CONCAT_KDF,
        &DES,
        &HMAC,
        &PBKDF2,
        &HKDF,
    ]
    .into_iter()
    .any(|known| std::ptr::eq(known, klass))
}

unsafe extern "C" fn initialize(data: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        // SAFETY: the registry passes key data of this klass.
        let valid = unsafe { symmetric(data) };
        check!(
            valid,
            "xmlSecSymKeyDataInitialize",
            c"xmlSecSymKeyDataCheckId(data)",
            -1
        );
        // SAFETY: valid binary key data.
        unsafe { value_initialize(data) }
    })
}

unsafe extern "C" fn duplicate(dst: *mut XmlSecKeyData, src: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        // SAFETY: the registry passes key data of this klass.
        let valid = unsafe { symmetric(dst) && symmetric(src) && (*dst).id == (*src).id };
        check!(
            valid,
            "xmlSecSymKeyDataDuplicate",
            c"xmlSecSymKeyDataCheckId(dst) && xmlSecSymKeyDataCheckId(src) && dst->id == src->id",
            -1
        );
        // SAFETY: valid binary key data of one klass.
        unsafe { value_duplicate(dst, src) }
    })
}

unsafe extern "C" fn finalize(data: *mut XmlSecKeyData) {
    contain((), || {
        // SAFETY: the registry passes key data of this klass.
        let valid = unsafe { symmetric(data) };
        check!(
            valid,
            "xmlSecSymKeyDataFinalize",
            c"xmlSecSymKeyDataCheckId(data)"
        );
        // SAFETY: valid binary key data.
        unsafe { value_finalize(data) };
    });
}

/// `generate`: `size_bits` rounded up to whole bytes of the built-in
/// provider's randomness; the requested type does not matter for a
/// symmetric key.
unsafe extern "C" fn generate(data: *mut XmlSecKeyData, size_bits: usize, _kind: c_uint) -> c_int {
    contain(-1, || {
        // SAFETY: the registry passes key data of this klass.
        let valid = unsafe { symmetric(data) };
        check!(
            valid,
            "xmlSecSymKeyDataGenerate",
            c"xmlSecSymKeyDataCheckId(data)",
            -1
        );
        check!(
            size_bits > 0,
            "xmlSecSymKeyDataGenerate",
            c"sizeBits > 0",
            -1
        );
        let here = here!("xmlSecSymKeyDataGenerate");
        let size = size_bits.div_ceil(8);
        // SAFETY: valid binary key data; after the resize its buffer holds
        // `size` bytes.
        unsafe {
            let buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
            if xmlSecBufferSetSize(buffer, size) < 0 {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecBufferSetSize",
                    &format!("size={size}"),
                );
                return -1;
            }
            let bytes = std::slice::from_raw_parts_mut(xmlSecBufferGetData(buffer), size);
            if let Err(error) = xml_sec::provider::default_provider().fill_random(bytes) {
                errors::report(
                    here,
                    std::ptr::null(),
                    c"fill_random".as_ptr(),
                    errors::R_CRYPTO_FAILED,
                    &error.to_string(),
                );
                return -1;
            }
        }
        0
    })
}

/// `getType`: symmetric once the value holds bytes.
unsafe extern "C" fn get_type(data: *mut XmlSecKeyData) -> c_uint {
    contain(TYPE_UNKNOWN, || {
        // SAFETY: the registry passes key data of this klass.
        let valid = unsafe { symmetric(data) };
        check!(
            valid,
            "xmlSecSymKeyDataGetType",
            c"xmlSecSymKeyDataCheckId(data)",
            TYPE_UNKNOWN
        );
        // SAFETY: valid binary key data and its value buffer.
        if unsafe { xmlSecBufferGetSize(xmlSecKeyDataBinaryValueGetBuffer(data)) } > 0 {
            TYPE_SYMMETRIC
        } else {
            TYPE_UNKNOWN
        }
    })
}

unsafe extern "C" fn get_size(data: *mut XmlSecKeyData) -> usize {
    contain(0, || {
        // SAFETY: the registry passes key data of this klass.
        let valid = unsafe { symmetric(data) };
        check!(
            valid,
            "xmlSecSymKeyDataGetSize",
            c"xmlSecSymKeyDataCheckId(data)",
            0
        );
        // SAFETY: valid binary key data.
        unsafe { xmlSecKeyDataBinaryValueGetSize(data) }
    })
}

macro_rules! getters {
    ($($name:ident => $klass:ident;)*) => {
        $(
            #[doc = concat!("The built-in table's `", stringify!($klass), "` klass.")]
            pub(crate) extern "C" fn $name() -> *const XmlSecKeyDataKlass {
                &raw const $klass
            }
        )*
    };
}

getters! {
    aes => AES;
    camellia => CAMELLIA;
    chacha20 => CHACHA20;
    concat_kdf => CONCAT_KDF;
    des => DES;
    hmac => HMAC;
    pbkdf2 => PBKDF2;
    hkdf => HKDF;
}
