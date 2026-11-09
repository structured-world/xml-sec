//! `xmlsec/keysdata.h`: key-data klasses and objects, the global registry
//! of key-data klasses with its enabled subset, the key-data and klass lists,
//! key-data stores and the binary key-data value.
//!
//! A key-data klass is the address of a static `xmlSecKeyDataKlass`; objects
//! are allocated with libxml2's allocator at the klass's object size and
//! driven through its methods, so a caller's klass works as with libxmlsec1.
//! The built-in `KeyInfo` child klasses keep libxmlsec1's identities and
//! registration; their reading and writing of keys belongs to the key
//! objects and `KeyInfo` processing that use them.

use std::ffi::{c_int, c_uint, c_void};
use std::sync::atomic::{AtomicI32, Ordering};

use super::buffer::{XmlSecBuffer, xmlSecBufferGetSize, xmlSecBufferSetData};
use super::list::{
    XmlSecPtrList, XmlSecPtrListKlass, xmlSecPtrListAdd, xmlSecPtrListFinalize,
    xmlSecPtrListGetItem, xmlSecPtrListGetSize, xmlSecPtrListInitialize,
};
use super::strings::{
    xmlSecDSig11Ns, xmlSecDSigNs, xmlSecEnc11Ns, xmlSecEncNs, xmlSecExperimental202512Ns,
    xmlSecHrefAgreementMethod, xmlSecHrefDerivedKey, xmlSecHrefEncapsulationMechanism,
    xmlSecHrefEncryptedKey, xmlSecNameAgreementMethod, xmlSecNameDerivedKey,
    xmlSecNameEncapsulationMechanism, xmlSecNameEncryptedKey, xmlSecNameKeyInfoReference,
    xmlSecNameKeyName, xmlSecNameKeyValue, xmlSecNameRetrievalMethod, xmlSecNodeAgreementMethod,
    xmlSecNodeDerivedKey, xmlSecNodeEncapsulationMechanism, xmlSecNodeEncryptedKey,
    xmlSecNodeKeyInfoReference, xmlSecNodeKeyName, xmlSecNodeKeyValue, xmlSecNodeRetrievalMethod,
};
use super::transforms::{Global, klass_text, xml_text, zero_list};
use super::tree::xmlStrEqual;
use super::{contain, free, malloc, write_stream};

#[cfg(test)]
mod tests;

/// `xmlSecKeyDataUsage` bits of the `KeyInfo` child klasses.
const USAGE_KEY_INFO_NODE: c_uint = 0x0003;
const USAGE_RETRIEVAL_METHOD_NODE_XML: c_uint = 0x0010;
/// `xmlSecKeyDataTypeUnknown`.
const TYPE_UNKNOWN: c_uint = 0;

/// An opaque `xmlSecKeyPtr` or `xmlSecKeyInfoCtxPtr`, passed through.
type Opaque = *mut c_void;

/// `xmlSecKeyData`.
#[repr(C)]
pub(crate) struct XmlSecKeyData {
    pub(crate) id: *const XmlSecKeyDataKlass,
    pub(crate) reserved0: *mut c_void,
    pub(crate) reserved1: *mut c_void,
}

/// `xmlSecKeyDataKlass`.
#[repr(C)]
pub(crate) struct XmlSecKeyDataKlass {
    pub(crate) klass_size: usize,
    pub(crate) obj_size: usize,
    pub(crate) name: *const u8,
    pub(crate) usage: c_uint,
    pub(crate) href: *const u8,
    pub(crate) data_node_name: *const u8,
    pub(crate) data_node_ns: *const u8,
    pub(crate) initialize: Option<unsafe extern "C" fn(*mut XmlSecKeyData) -> c_int>,
    pub(crate) duplicate:
        Option<unsafe extern "C" fn(*mut XmlSecKeyData, *mut XmlSecKeyData) -> c_int>,
    pub(crate) finalize: Option<unsafe extern "C" fn(*mut XmlSecKeyData)>,
    pub(crate) generate: Option<unsafe extern "C" fn(*mut XmlSecKeyData, usize, c_uint) -> c_int>,
    pub(crate) get_type: Option<unsafe extern "C" fn(*mut XmlSecKeyData) -> c_uint>,
    pub(crate) get_size: Option<unsafe extern "C" fn(*mut XmlSecKeyData) -> usize>,
    pub(crate) deprecated0: *mut c_void,
    pub(crate) xml_read: Option<
        unsafe extern "C" fn(*const XmlSecKeyDataKlass, Opaque, *mut c_void, Opaque) -> c_int,
    >,
    pub(crate) xml_write: Option<
        unsafe extern "C" fn(*const XmlSecKeyDataKlass, Opaque, *mut c_void, Opaque) -> c_int,
    >,
    pub(crate) bin_read: Option<
        unsafe extern "C" fn(*const XmlSecKeyDataKlass, Opaque, *const u8, usize, Opaque) -> c_int,
    >,
    pub(crate) bin_write: Option<
        unsafe extern "C" fn(
            *const XmlSecKeyDataKlass,
            Opaque,
            *mut *mut u8,
            *mut usize,
            Opaque,
        ) -> c_int,
    >,
    pub(crate) debug_dump: Option<unsafe extern "C" fn(*mut XmlSecKeyData, *mut c_void)>,
    pub(crate) debug_xml_dump: Option<unsafe extern "C" fn(*mut XmlSecKeyData, *mut c_void)>,
    pub(crate) reserved0: *mut c_void,
    pub(crate) reserved1: *mut c_void,
}

// SAFETY: a klass is immutable static data: names with static storage and
// function pointers.
unsafe impl Sync for XmlSecKeyDataKlass {}

/// `xmlSecKeyDataStore`.
#[repr(C)]
pub(crate) struct XmlSecKeyDataStore {
    pub(crate) id: *const XmlSecKeyDataStoreKlass,
    pub(crate) reserved0: *mut c_void,
    pub(crate) reserved1: *mut c_void,
}

/// `xmlSecKeyDataStoreKlass`.
#[repr(C)]
pub(crate) struct XmlSecKeyDataStoreKlass {
    pub(crate) klass_size: usize,
    pub(crate) obj_size: usize,
    pub(crate) name: *const u8,
    pub(crate) initialize: Option<unsafe extern "C" fn(*mut XmlSecKeyDataStore) -> c_int>,
    pub(crate) finalize: Option<unsafe extern "C" fn(*mut XmlSecKeyDataStore)>,
    pub(crate) reserved0: *mut c_void,
    pub(crate) reserved1: *mut c_void,
}

/// A binary key-data object: the key data and its value buffer.
#[repr(C)]
struct XmlSecKeyDataBinary {
    data: XmlSecKeyData,
    buffer: XmlSecBuffer,
}

/// `xmlSecKeyDataIsValid`: the klass is complete and named.
///
/// # Safety
/// `data` is null or points to a key-data object whose `id` is null or a
/// klass.
unsafe fn valid<'a>(data: *mut XmlSecKeyData) -> Option<&'a XmlSecKeyDataKlass> {
    // SAFETY: by the caller's contract.
    unsafe {
        let klass = data.as_ref()?.id.as_ref()?;
        (klass.klass_size >= size_of::<XmlSecKeyDataKlass>()
            && klass.obj_size >= size_of::<XmlSecKeyData>()
            && !klass.name.is_null())
        .then_some(klass)
    }
}

// ----------------------------------------------------------------------------
// The registry

static ALL_KEY_DATA_IDS: Global<XmlSecPtrList> = Global::new(zero_list());
static ENABLED_KEY_DATA_IDS: Global<XmlSecPtrList> = Global::new(zero_list());
static IMPORT_PERSIST_KEY: AtomicI32 = AtomicI32::new(0);

/// `xmlSecKeyDataIdsGet`: every registered key-data klass.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdsGet() -> *mut XmlSecPtrList {
    ALL_KEY_DATA_IDS.get()
}

/// `xmlSecKeyDataIdsGetEnabled`: the registered klasses enabled by default.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdsGetEnabled() -> *mut XmlSecPtrList {
    ENABLED_KEY_DATA_IDS.get()
}

/// `xmlSecKeyDataIdsInit`: empty registries holding libxmlsec1's defaults.
///
/// # Safety
/// Called during initialization, while nothing reads the registries.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdsInit() -> c_int {
    contain(-1, || {
        // SAFETY: the registries have fixed addresses and are not in use.
        unsafe {
            if xmlSecPtrListInitialize(xmlSecKeyDataIdsGet(), xmlSecKeyDataIdListGetKlass()) < 0
                || xmlSecPtrListInitialize(
                    xmlSecKeyDataIdsGetEnabled(),
                    xmlSecKeyDataIdListGetKlass(),
                ) < 0
            {
                return -1;
            }
            xmlSecKeyDataIdsRegisterDefault()
        }
    })
}

/// `xmlSecKeyDataIdsShutdown`: empties both registries.
///
/// # Safety
/// Called during shutdown, while nothing reads the registries.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdsShutdown() {
    contain((), || {
        // SAFETY: the registries have fixed addresses and are not in use.
        unsafe {
            xmlSecPtrListFinalize(xmlSecKeyDataIdsGet());
            xmlSecPtrListFinalize(xmlSecKeyDataIdsGetEnabled());
        }
    });
}

/// `xmlSecKeyDataIdsRegister`: registers `id` and enables it.
///
/// # Safety
/// Called during initialization; `id` is a klass that outlives the
/// registration.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdsRegister(id: *const XmlSecKeyDataKlass) -> c_int {
    contain(-1, || {
        if id.is_null() {
            return -1;
        }
        // SAFETY: the registries have fixed addresses; the klass is static.
        unsafe {
            if xmlSecPtrListAdd(xmlSecKeyDataIdsGet(), id.cast_mut().cast()) < 0
                || xmlSecPtrListAdd(xmlSecKeyDataIdsGetEnabled(), id.cast_mut().cast()) < 0
            {
                return -1;
            }
        }
        0
    })
}

/// `xmlSecKeyDataIdsRegisterDisabled`: registers `id` without enabling it.
///
/// # Safety
/// As [`xmlSecKeyDataIdsRegister`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdsRegisterDisabled(
    id: *const XmlSecKeyDataKlass,
) -> c_int {
    contain(-1, || {
        if id.is_null() {
            return -1;
        }
        // SAFETY: the registry has a fixed address; the klass is static.
        let added = unsafe { xmlSecPtrListAdd(xmlSecKeyDataIdsGet(), id.cast_mut().cast()) };
        if added < 0 { -1 } else { 0 }
    })
}

/// `xmlSecKeyDataIdsRegisterDefault`: the `KeyInfo` child klasses in
/// libxmlsec1's order; `KeyValue` and the experimental encapsulation
/// mechanism are registered disabled.
///
/// # Safety
/// As [`xmlSecKeyDataIdsRegister`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdsRegisterDefault() -> c_int {
    contain(-1, || {
        let enabled = [
            &raw const NAME,
            &raw const RETRIEVAL_METHOD,
            &raw const KEY_INFO_REFERENCE,
            &raw const ENCRYPTED_KEY,
            &raw const AGREEMENT_METHOD,
            &raw const DERIVED_KEY,
        ];
        // SAFETY: registering static klasses.
        unsafe {
            for id in enabled {
                if xmlSecKeyDataIdsRegister(id) < 0 {
                    return -1;
                }
            }
            if xmlSecKeyDataIdsRegisterDisabled(&raw const ENCAPSULATION_MECHANISM) < 0
                || xmlSecKeyDataIdsRegisterDisabled(&raw const VALUE) < 0
            {
                return -1;
            }
        }
        0
    })
}

// ----------------------------------------------------------------------------
// Key data objects

/// `xmlSecKeyDataCreate`: a zeroed object of the klass's size, initialized.
///
/// # Safety
/// `id` is null or a klass.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataCreate(
    id: *const XmlSecKeyDataKlass,
) -> *mut XmlSecKeyData {
    contain(std::ptr::null_mut(), || {
        // SAFETY: by the caller's contract; the object is the klass's size.
        unsafe {
            let Some(klass) = id.as_ref() else {
                return std::ptr::null_mut();
            };
            if klass.klass_size < size_of::<XmlSecKeyDataKlass>()
                || klass.obj_size < size_of::<XmlSecKeyData>()
                || klass.name.is_null()
            {
                return std::ptr::null_mut();
            }
            let data = malloc(klass.obj_size).cast::<XmlSecKeyData>();
            if data.is_null() {
                return data;
            }
            data.cast::<u8>().write_bytes(0, klass.obj_size);
            (*data).id = id;
            if let Some(initialize) = klass.initialize
                && initialize(data) < 0
            {
                xmlSecKeyDataDestroy(data);
                return std::ptr::null_mut();
            }
            data
        }
    })
}

/// `xmlSecKeyDataDuplicate`: a new object of the same klass, copied by its
/// duplicate method.
///
/// # Safety
/// `data` is null or a key-data object.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataDuplicate(
    data: *mut XmlSecKeyData,
) -> *mut XmlSecKeyData {
    contain(std::ptr::null_mut(), || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(duplicate) = valid(data).and_then(|klass| klass.duplicate) else {
                return std::ptr::null_mut();
            };
            let copy = xmlSecKeyDataCreate((*data).id);
            if copy.is_null() {
                return copy;
            }
            if duplicate(copy, data) < 0 {
                xmlSecKeyDataDestroy(copy);
                return std::ptr::null_mut();
            }
            copy
        }
    })
}

/// `xmlSecKeyDataDestroy`: finalizes and frees the object.
///
/// # Safety
/// `data` is null or a key-data object not used afterwards.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataDestroy(data: *mut XmlSecKeyData) {
    contain((), || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(klass) = valid(data) else {
                return;
            };
            let size = klass.obj_size;
            if let Some(finalize) = klass.finalize {
                finalize(data);
            }
            data.cast::<u8>().write_bytes(0, size);
            free(data.cast());
        }
    });
}

/// `xmlSecKeyDataGenerate`: new key material by the klass's method.
///
/// # Safety
/// `data` is null or a key-data object.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataGenerate(
    data: *mut XmlSecKeyData,
    size_bits: usize,
    kind: c_uint,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            match valid(data).and_then(|klass| klass.generate) {
                Some(generate) if generate(data, size_bits, kind) >= 0 => 0,
                _ => -1,
            }
        }
    })
}

/// `xmlSecKeyDataGetType`: the klass's answer, unknown without a method.
///
/// # Safety
/// `data` is null or a key-data object.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataGetType(data: *mut XmlSecKeyData) -> c_uint {
    contain(TYPE_UNKNOWN, || {
        // SAFETY: by the caller's contract.
        unsafe {
            match valid(data).and_then(|klass| klass.get_type) {
                Some(get_type) => get_type(data),
                None => TYPE_UNKNOWN,
            }
        }
    })
}

/// `xmlSecKeyDataGetSize`: the klass's size in bits, 0 without a method.
///
/// # Safety
/// `data` is null or a key-data object.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataGetSize(data: *mut XmlSecKeyData) -> usize {
    contain(0, || {
        // SAFETY: by the caller's contract.
        unsafe {
            match valid(data).and_then(|klass| klass.get_size) {
                Some(get_size) => get_size(data),
                None => 0,
            }
        }
    })
}

/// `xmlSecKeyDataGetIdentifier`: deprecated, always null.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataGetIdentifier(_data: *mut XmlSecKeyData) -> *const u8 {
    std::ptr::null()
}

/// `xmlSecKeyDataDebugDump`.
///
/// # Safety
/// `data` is null or a key-data object; `output` is null or a C stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataDebugDump(
    data: *mut XmlSecKeyData,
    output: *mut c_void,
) {
    contain((), || {
        // SAFETY: by the caller's contract.
        unsafe {
            if let Some(dump) = valid(data).and_then(|klass| klass.debug_dump)
                && !output.is_null()
            {
                dump(data, output);
            }
        }
    });
}

/// `xmlSecKeyDataDebugXmlDump`.
///
/// # Safety
/// `data` is null or a key-data object; `output` is null or a C stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataDebugXmlDump(
    data: *mut XmlSecKeyData,
    output: *mut c_void,
) {
    contain((), || {
        // SAFETY: by the caller's contract.
        unsafe {
            if let Some(dump) = valid(data).and_then(|klass| klass.debug_xml_dump)
                && !output.is_null()
            {
                dump(data, output);
            }
        }
    });
}

/// `xmlSecKeyDataXmlRead`: the klass reads `node` into `key`.
///
/// # Safety
/// `id` is null or a klass; `key`, `node` and `ctx` are what its method
/// expects.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataXmlRead(
    id: *const XmlSecKeyDataKlass,
    key: Opaque,
    node: *mut c_void,
    ctx: Opaque,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            match id.as_ref().and_then(|klass| klass.xml_read) {
                Some(read) if !key.is_null() && !node.is_null() => read(id, key, node, ctx),
                _ => -1,
            }
        }
    })
}

/// `xmlSecKeyDataXmlWrite`: the klass writes `key` into `node`.
///
/// # Safety
/// As [`xmlSecKeyDataXmlRead`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataXmlWrite(
    id: *const XmlSecKeyDataKlass,
    key: Opaque,
    node: *mut c_void,
    ctx: Opaque,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            match id.as_ref().and_then(|klass| klass.xml_write) {
                Some(write) if !key.is_null() && !node.is_null() => write(id, key, node, ctx),
                _ => -1,
            }
        }
    })
}

/// `xmlSecKeyDataBinRead`: the klass reads `size` bytes into `key`.
///
/// # Safety
/// `id` is null or a klass; `buf` holds `size` bytes; `key` and `ctx` are
/// what its method expects.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataBinRead(
    id: *const XmlSecKeyDataKlass,
    key: Opaque,
    buf: *const u8,
    size: usize,
    ctx: Opaque,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            match id.as_ref().and_then(|klass| klass.bin_read) {
                Some(read) if !key.is_null() && !buf.is_null() => read(id, key, buf, size, ctx),
                _ => -1,
            }
        }
    })
}

/// `xmlSecKeyDataBinWrite`: the klass writes `key` to a new buffer.
///
/// # Safety
/// `id` is null or a klass; `buf` and `size` are writable; `key` and `ctx`
/// are what its method expects.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataBinWrite(
    id: *const XmlSecKeyDataKlass,
    key: Opaque,
    buf: *mut *mut u8,
    size: *mut usize,
    ctx: Opaque,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            match id.as_ref().and_then(|klass| klass.bin_write) {
                Some(write) if !key.is_null() && !buf.is_null() => write(id, key, buf, size, ctx),
                _ => -1,
            }
        }
    })
}

// ----------------------------------------------------------------------------
// Binary key data

/// The value buffer of a binary key-data object.
///
/// # Safety
/// `data` is null or a key-data object.
unsafe fn binary_buffer(data: *mut XmlSecKeyData) -> *mut XmlSecBuffer {
    // SAFETY: a valid object at least the binary layout's size starts with
    // that layout.
    unsafe {
        match valid(data) {
            Some(klass) if klass.obj_size >= size_of::<XmlSecKeyDataBinary>() => {
                &raw mut (*data.cast::<XmlSecKeyDataBinary>()).buffer
            }
            _ => std::ptr::null_mut(),
        }
    }
}

/// `xmlSecKeyDataBinaryValueGetSize`: the value's size in bits.
///
/// # Safety
/// `data` is null or a key-data object.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataBinaryValueGetSize(data: *mut XmlSecKeyData) -> usize {
    contain(0, || {
        // SAFETY: by the caller's contract.
        unsafe {
            let buffer = binary_buffer(data);
            if buffer.is_null() {
                return 0;
            }
            // libxmlsec1 computes `8 * size` in `xmlSecSize`, which wraps for
            // a value of more than `SIZE_MAX / 8` bytes; the same number here.
            xmlSecBufferGetSize(buffer).wrapping_mul(8)
        }
    })
}

/// `xmlSecKeyDataBinaryValueGetBuffer`: the value buffer.
///
/// # Safety
/// `data` is null or a key-data object.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataBinaryValueGetBuffer(
    data: *mut XmlSecKeyData,
) -> *mut XmlSecBuffer {
    // SAFETY: by the caller's contract.
    contain(std::ptr::null_mut(), || unsafe { binary_buffer(data) })
}

/// `xmlSecKeyDataBinaryValueSetBuffer`: replaces the value with `size`
/// bytes.
///
/// # Safety
/// `data` is null or a key-data object; `buf` holds `size` bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataBinaryValueSetBuffer(
    data: *mut XmlSecKeyData,
    buf: *const u8,
    size: usize,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            let buffer = binary_buffer(data);
            if buffer.is_null() || buf.is_null() || size == 0 {
                return -1;
            }
            xmlSecBufferSetData(buffer, buf, size)
        }
    })
}

// ----------------------------------------------------------------------------
// Lists

unsafe extern "C" fn duplicate_item(item: *mut c_void) -> *mut c_void {
    // SAFETY: the items of a key-data list are key-data objects.
    unsafe { xmlSecKeyDataDuplicate(item.cast()).cast() }
}

unsafe extern "C" fn destroy_item(item: *mut c_void) {
    // SAFETY: as above.
    unsafe { xmlSecKeyDataDestroy(item.cast()) }
}

unsafe extern "C" fn dump_item(item: *mut c_void, output: *mut c_void) {
    // SAFETY: as above.
    unsafe { xmlSecKeyDataDebugDump(item.cast(), output) }
}

unsafe extern "C" fn xml_dump_item(item: *mut c_void, output: *mut c_void) {
    // SAFETY: as above.
    unsafe { xmlSecKeyDataDebugXmlDump(item.cast(), output) }
}

unsafe extern "C" fn destroy_store(item: *mut c_void) {
    // SAFETY: the items of a store list are stores.
    unsafe { xmlSecKeyDataStoreDestroy(item.cast()) }
}

static KEY_DATA_LIST_KLASS: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"key-data-list".as_ptr().cast(),
    duplicate_item: Some(duplicate_item),
    destroy_item: Some(destroy_item),
    debug_dump_item: Some(dump_item),
    debug_xml_dump_item: Some(xml_dump_item),
};

static KEY_DATA_ID_LIST_KLASS: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"key-data-ids-list".as_ptr().cast(),
    duplicate_item: None,
    destroy_item: None,
    debug_dump_item: None,
    debug_xml_dump_item: None,
};

static STORE_LIST_KLASS: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"keys-data-store-list".as_ptr().cast(),
    duplicate_item: None,
    destroy_item: Some(destroy_store),
    debug_dump_item: None,
    debug_xml_dump_item: None,
};

/// `xmlSecKeyDataListGetKlass`: a list owning key-data objects.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataListGetKlass() -> *const XmlSecPtrListKlass {
    &raw const KEY_DATA_LIST_KLASS
}

/// `xmlSecKeyDataIdListGetKlass`: a list of key-data klasses.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdListGetKlass() -> *const XmlSecPtrListKlass {
    &raw const KEY_DATA_ID_LIST_KLASS
}

/// `xmlSecKeyDataStorePtrListGetKlass`: a list owning stores.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataStorePtrListGetKlass() -> *const XmlSecPtrListKlass {
    &raw const STORE_LIST_KLASS
}

/// The klasses of a key-data klass list, or `None` for another list.
///
/// # Safety
/// `list` is null or a list.
unsafe fn id_list<'a>(list: *mut XmlSecPtrList) -> Option<Vec<&'a XmlSecKeyDataKlass>> {
    // SAFETY: by the caller's contract; a klass list holds klasses.
    unsafe {
        if !std::ptr::eq(list.as_ref()?.id, &raw const KEY_DATA_ID_LIST_KLASS) {
            return None;
        }
        (0..xmlSecPtrListGetSize(list))
            .map(|pos| {
                xmlSecPtrListGetItem(list, pos)
                    .cast::<XmlSecKeyDataKlass>()
                    .as_ref()
            })
            .collect()
    }
}

/// `xmlSecKeyDataIdListFind`: 1 when `id` is listed, 0 otherwise.
///
/// # Safety
/// `list` is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdListFind(
    list: *mut XmlSecPtrList,
    id: *const XmlSecKeyDataKlass,
) -> c_int {
    contain(0, || {
        // SAFETY: by the caller's contract.
        let Some(klasses) = (unsafe { id_list(list) }) else {
            return 0;
        };
        c_int::from(!id.is_null() && klasses.iter().any(|klass| std::ptr::eq(*klass, id)))
    })
}

/// The first listed klass usable for `usage` that `matches`, or null.
///
/// # Safety
/// `list` is null or a list.
unsafe fn find(
    list: *mut XmlSecPtrList,
    usage: c_uint,
    matches: impl Fn(&XmlSecKeyDataKlass) -> bool,
) -> *const XmlSecKeyDataKlass {
    // SAFETY: by the caller's contract.
    let Some(klasses) = (unsafe { id_list(list) }) else {
        return std::ptr::null();
    };
    klasses
        .into_iter()
        .find(|klass| usage & klass.usage != 0 && matches(klass))
        .map_or(std::ptr::null(), std::ptr::from_ref)
}

/// `xmlSecKeyDataIdListFindByNode`: the klass of a `KeyInfo` child.
///
/// # Safety
/// `list` is null or a list; the names are null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdListFindByNode(
    list: *mut XmlSecPtrList,
    node_name: *const u8,
    node_ns: *const u8,
    usage: c_uint,
) -> *const XmlSecKeyDataKlass {
    contain(std::ptr::null(), || {
        if node_name.is_null() {
            return std::ptr::null();
        }
        // SAFETY: by the caller's contract; libxml2 compares null equal to
        // null only.
        unsafe {
            find(list, usage, |klass| {
                xmlStrEqual(node_name, klass.data_node_name) != 0
                    && xmlStrEqual(node_ns, klass.data_node_ns) != 0
            })
        }
    })
}

/// `xmlSecKeyDataIdListFindByHref`: the klass with this href.
///
/// # Safety
/// `list` is null or a list; `href` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdListFindByHref(
    list: *mut XmlSecPtrList,
    href: *const u8,
    usage: c_uint,
) -> *const XmlSecKeyDataKlass {
    contain(std::ptr::null(), || {
        if href.is_null() {
            return std::ptr::null();
        }
        // SAFETY: by the caller's contract.
        unsafe {
            find(list, usage, |klass| {
                !klass.href.is_null() && xmlStrEqual(href, klass.href) != 0
            })
        }
    })
}

/// `xmlSecKeyDataIdListFindByName`: the klass with this name.
///
/// # Safety
/// `list` is null or a list; `name` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdListFindByName(
    list: *mut XmlSecPtrList,
    name: *const u8,
    usage: c_uint,
) -> *const XmlSecKeyDataKlass {
    contain(std::ptr::null(), || {
        if name.is_null() {
            return std::ptr::null();
        }
        // SAFETY: by the caller's contract.
        unsafe {
            find(list, usage, |klass| {
                !klass.name.is_null() && xmlStrEqual(name, klass.name) != 0
            })
        }
    })
}

/// `xmlSecKeyDataIdListDebugDump`: the quoted names, comma-separated.
///
/// # Safety
/// `list` is null or a list; `output` is null or a C stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdListDebugDump(
    list: *mut XmlSecPtrList,
    output: *mut c_void,
) {
    contain((), || {
        // SAFETY: by the caller's contract.
        let Some(klasses) = (unsafe { id_list(list) }) else {
            return;
        };
        if output.is_null() {
            return;
        }
        let names: Vec<String> = klasses
            .iter()
            // SAFETY: klass names are NUL-terminated.
            .map(|klass| format!("\"{}\"", unsafe { klass_text(klass.name) }))
            .collect();
        // SAFETY: `output` is a live stream.
        unsafe { write_stream(output, &format!("{}\n", names.join(","))) };
    });
}

/// `xmlSecKeyDataIdListDebugXmlDump`.
///
/// # Safety
/// `list` is null or a list; `output` is null or a C stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataIdListDebugXmlDump(
    list: *mut XmlSecPtrList,
    output: *mut c_void,
) {
    contain((), || {
        // SAFETY: by the caller's contract.
        let Some(klasses) = (unsafe { id_list(list) }) else {
            return;
        };
        if output.is_null() {
            return;
        }
        let mut text = String::from("<KeyDataIdsList>\n");
        for klass in klasses {
            // SAFETY: klass names are NUL-terminated.
            let name = xml_text(&unsafe { klass_text(klass.name) });
            text.push_str("<DataId name=\"");
            text.push_str(&name);
            text.push_str("\"/>");
        }
        text.push_str("</KeyDataIdsList>\n");
        // SAFETY: `output` is a live stream.
        unsafe { write_stream(output, &text) };
    });
}

// ----------------------------------------------------------------------------
// Stores

/// `xmlSecKeyDataStoreCreate`: a zeroed store of the klass's size,
/// initialized.
///
/// # Safety
/// `id` is null or a store klass.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataStoreCreate(
    id: *const XmlSecKeyDataStoreKlass,
) -> *mut XmlSecKeyDataStore {
    contain(std::ptr::null_mut(), || {
        // SAFETY: by the caller's contract; the object is the klass's size.
        unsafe {
            let Some(klass) = id.as_ref() else {
                return std::ptr::null_mut();
            };
            if klass.obj_size == 0 {
                return std::ptr::null_mut();
            }
            let store = malloc(klass.obj_size).cast::<XmlSecKeyDataStore>();
            if store.is_null() {
                return store;
            }
            store.cast::<u8>().write_bytes(0, klass.obj_size);
            (*store).id = id;
            if let Some(initialize) = klass.initialize
                && initialize(store) < 0
            {
                xmlSecKeyDataStoreDestroy(store);
                return std::ptr::null_mut();
            }
            store
        }
    })
}

/// `xmlSecKeyDataStoreDestroy`: finalizes and frees the store.
///
/// # Safety
/// `store` is null or a store not used afterwards.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataStoreDestroy(store: *mut XmlSecKeyDataStore) {
    contain((), || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(klass) = store.as_ref().and_then(|store| store.id.as_ref()) else {
                return;
            };
            let size = klass.obj_size;
            if size == 0 {
                return;
            }
            if let Some(finalize) = klass.finalize {
                finalize(store);
            }
            store.cast::<u8>().write_bytes(0, size);
            free(store.cast());
        }
    });
}

/// `xmlSecImportSetPersistKey`: keys imported from now on persist (a
/// Windows crypto-store setting the generic library only records).
///
/// # Safety
/// Callable during initialization.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecImportSetPersistKey() {
    IMPORT_PERSIST_KEY.store(1, Ordering::Relaxed);
}

/// `xmlSecImportGetPersistKey`.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecImportGetPersistKey() -> c_int {
    IMPORT_PERSIST_KEY.load(Ordering::Relaxed)
}

// ----------------------------------------------------------------------------
// The KeyInfo child klasses

/// A `KeyInfo` child klass: plain key-data objects identified by their
/// element.
const fn key_info_child(
    name: *const u8,
    href: *const u8,
    node: *const u8,
    ns: *const u8,
) -> XmlSecKeyDataKlass {
    XmlSecKeyDataKlass {
        klass_size: size_of::<XmlSecKeyDataKlass>(),
        obj_size: size_of::<XmlSecKeyData>(),
        name,
        usage: USAGE_KEY_INFO_NODE | USAGE_RETRIEVAL_METHOD_NODE_XML,
        href,
        data_node_name: node,
        data_node_ns: ns,
        initialize: None,
        duplicate: None,
        finalize: None,
        generate: None,
        get_type: None,
        get_size: None,
        deprecated0: std::ptr::null_mut(),
        xml_read: None,
        xml_write: None,
        bin_read: None,
        bin_write: None,
        debug_dump: None,
        debug_xml_dump: None,
        reserved0: std::ptr::null_mut(),
        reserved1: std::ptr::null_mut(),
    }
}

static NAME: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameKeyName.as_ptr(),
    std::ptr::null(),
    xmlSecNodeKeyName.as_ptr(),
    xmlSecDSigNs.as_ptr(),
);
static VALUE: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameKeyValue.as_ptr(),
    std::ptr::null(),
    xmlSecNodeKeyValue.as_ptr(),
    xmlSecDSigNs.as_ptr(),
);
static RETRIEVAL_METHOD: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameRetrievalMethod.as_ptr(),
    std::ptr::null(),
    xmlSecNodeRetrievalMethod.as_ptr(),
    xmlSecDSigNs.as_ptr(),
);
static KEY_INFO_REFERENCE: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameKeyInfoReference.as_ptr(),
    std::ptr::null(),
    xmlSecNodeKeyInfoReference.as_ptr(),
    xmlSecDSig11Ns.as_ptr(),
);
static ENCRYPTED_KEY: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameEncryptedKey.as_ptr(),
    xmlSecHrefEncryptedKey.as_ptr(),
    xmlSecNodeEncryptedKey.as_ptr(),
    xmlSecEncNs.as_ptr(),
);
static DERIVED_KEY: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameDerivedKey.as_ptr(),
    xmlSecHrefDerivedKey.as_ptr(),
    xmlSecNodeDerivedKey.as_ptr(),
    xmlSecEnc11Ns.as_ptr(),
);
static AGREEMENT_METHOD: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameAgreementMethod.as_ptr(),
    xmlSecHrefAgreementMethod.as_ptr(),
    xmlSecNodeAgreementMethod.as_ptr(),
    xmlSecEncNs.as_ptr(),
);
static ENCAPSULATION_MECHANISM: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameEncapsulationMechanism.as_ptr(),
    xmlSecHrefEncapsulationMechanism.as_ptr(),
    xmlSecNodeEncapsulationMechanism.as_ptr(),
    xmlSecExperimental202512Ns.as_ptr(),
);

macro_rules! key_data_getter {
    ($($name:ident => $klass:ident;)*) => {
        $(
            #[doc = concat!("`", stringify!($name), "`.")]
            ///
            /// # Safety
            /// Callable at any time.
            #[unsafe(no_mangle)]
            pub(crate) unsafe extern "C" fn $name() -> *const XmlSecKeyDataKlass {
                &raw const $klass
            }
        )*
    };
}

key_data_getter! {
    xmlSecKeyDataNameGetKlass => NAME;
    xmlSecKeyDataValueGetKlass => VALUE;
    xmlSecKeyDataRetrievalMethodGetKlass => RETRIEVAL_METHOD;
    xmlSecKeyDataKeyInfoReferenceGetKlass => KEY_INFO_REFERENCE;
    xmlSecKeyDataEncryptedKeyGetKlass => ENCRYPTED_KEY;
    xmlSecKeyDataDerivedKeyGetKlass => DERIVED_KEY;
    xmlSecKeyDataAgreementMethodGetKlass => AGREEMENT_METHOD;
    xmlSecKeyDataEncapsulationMechanismGetKlass => ENCAPSULATION_MECHANISM;
}
