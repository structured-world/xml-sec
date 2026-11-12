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

use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::sync::atomic::{AtomicI32, Ordering};

use super::buffer::XmlSecBuffer;
use super::errors::{self, check, here};
use super::keys::TYPE_UNKNOWN;
use super::list::{
    XmlSecPtrList, XmlSecPtrListKlass, xmlSecPtrListAdd, xmlSecPtrListFinalize,
    xmlSecPtrListInitialize,
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
use super::{contain, free, keyinfo, malloc, write_stream};

#[cfg(test)]
mod tests;

/// `xmlSecKeyDataUsage` bits of the `KeyInfo` child klasses.
pub(crate) const USAGE_KEY_INFO_NODE: c_uint = 0x0003;
pub(crate) const USAGE_RETRIEVAL_METHOD_NODE_XML: c_uint = 0x0010;
/// `xmlSecKeyDataUsageKeyValueNode`.
pub(crate) const USAGE_KEY_VALUE_NODE: c_uint = 0x000C;
/// `xmlSecKeyDataUsageReadFromFile`.
pub(crate) const USAGE_READ_FROM_FILE: c_uint = 0x0040;

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

/// `xmlSecKeyDataBinarySize`: the object size of a binary klass.
pub(crate) const BINARY_SIZE: usize = size_of::<XmlSecKeyDataBinary>();

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

/// libxmlsec1's `xmlSecKeyDataIsValid` for callers outside this module.
///
/// # Safety
/// `data` is null or a key-data object whose `id` is null or a klass.
pub(crate) unsafe fn data_valid(data: *mut XmlSecKeyData) -> bool {
    // SAFETY: by the caller's contract.
    unsafe { valid(data) }.is_some()
}

/// libxmlsec1's `xmlSecKeyDataCheckId`: valid key data of klass `id`.
///
/// # Safety
/// As for [`data_valid`].
pub(crate) unsafe fn check_id(data: *mut XmlSecKeyData, id: *const XmlSecKeyDataKlass) -> bool {
    // SAFETY: by the caller's contract.
    unsafe { valid(data) }.is_some_and(|klass| std::ptr::eq(klass, id))
}

/// The klass of a valid key-data object `$data`, after libxmlsec1's
/// `xmlSecKeyDataIsValid(data)` assertion inside the entry point `$func`, or
/// `$ret` (nothing, without `$ret`).
macro_rules! key_data_or {
    ($data:expr, $func:literal $(, $ret:expr)?) => {{
        // SAFETY: the caller passes null or a key-data object.
        let klass = unsafe { valid($data) };
        check!(klass.is_some(), $func, c"xmlSecKeyDataIsValid(data)" $(, $ret)?);
        let Some(klass) = klass else { return $($ret)? };
        klass
    }};
}

/// The name of a key-data klass for a report.
fn name_of(klass: &XmlSecKeyDataKlass) -> *const c_char {
    klass.name.cast()
}

// Declared after `key_data_or!`, which it uses.
mod binary;
#[cfg(test)]
pub(crate) use binary::xmlSecKeyDataBinaryValueSetBuffer;
pub(crate) use binary::{
    value_bin_read, value_bin_write, value_debug_dump, value_debug_xml_dump, value_duplicate,
    value_finalize, value_initialize, value_xml_read, value_xml_write,
    xmlSecKeyDataBinaryValueGetBuffer, xmlSecKeyDataBinaryValueGetSize,
};

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
        let here = here!("xmlSecKeyDataIdsInit");
        // SAFETY: the registries have fixed addresses and are not in use.
        unsafe {
            for registry in [xmlSecKeyDataIdsGet(), xmlSecKeyDataIdsGetEnabled()] {
                if xmlSecPtrListInitialize(registry, xmlSecKeyDataIdListGetKlass()) < 0 {
                    errors::internal(
                        here,
                        std::ptr::null(),
                        c"xmlSecPtrListInitialize(xmlSecKeyDataIdListId)",
                    );
                    return -1;
                }
            }
            if xmlSecKeyDataIdsRegisterDefault() < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyDataIdsRegisterDefault");
                return -1;
            }
        }
        0
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
        check!(
            !id.is_null(),
            "xmlSecKeyDataIdsRegister",
            c"id != xmlSecKeyDataIdUnknown",
            -1
        );
        let here = here!("xmlSecKeyDataIdsRegister");
        // SAFETY: the registries have fixed addresses; the klass is static.
        unsafe {
            let name = (*id).name.cast();
            if xmlSecPtrListAdd(xmlSecKeyDataIdsGet(), id.cast_mut().cast()) < 0 {
                errors::internal(here, name, c"xmlSecPtrListAdd(&xmlSecAllKeyDataIds)");
                return -1;
            }
            if xmlSecPtrListAdd(xmlSecKeyDataIdsGetEnabled(), id.cast_mut().cast()) < 0 {
                errors::internal(here, name, c"xmlSecPtrListAdd(&xmlSecEnabledKeyDataIds)");
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
        check!(
            !id.is_null(),
            "xmlSecKeyDataIdsRegisterDisabled",
            c"id != xmlSecKeyDataIdUnknown",
            -1
        );
        // SAFETY: the registry has a fixed address; the klass is static.
        unsafe {
            if xmlSecPtrListAdd(xmlSecKeyDataIdsGet(), id.cast_mut().cast()) < 0 {
                errors::internal(
                    here!("xmlSecKeyDataIdsRegisterDisabled"),
                    (*id).name.cast(),
                    c"xmlSecPtrListAdd(&xmlSecAllKeyDataIds)",
                );
                return -1;
            }
        }
        0
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
        // libxmlsec1's order, with the step each failure names; the
        // unterminated parentheses are libxmlsec1's own text.
        let registrations: [(*const XmlSecKeyDataKlass, bool, &CStr); 8] = [
            (
                &raw const NAME,
                true,
                c"xmlSecKeyDataIdsRegister(xmlSecKeyDataNameId)",
            ),
            (
                &raw const RETRIEVAL_METHOD,
                true,
                c"xmlSecKeyDataIdsRegister(xmlSecKeyDataRetrievalMethodId",
            ),
            (
                &raw const KEY_INFO_REFERENCE,
                true,
                c"xmlSecKeyDataIdsRegister(xmlSecKeyDataKeyInfoReferenceId",
            ),
            (
                &raw const ENCRYPTED_KEY,
                true,
                c"xmlSecKeyDataIdsRegister(xmlSecKeyDataEncryptedKeyId)",
            ),
            (
                &raw const AGREEMENT_METHOD,
                true,
                c"xmlSecKeyDataIdsRegister(xmlSecKeyDataAgreementMethodId)",
            ),
            (
                &raw const DERIVED_KEY,
                true,
                c"xmlSecKeyDataIdsRegister(xmlSecKeyDataDerivedKeyId)",
            ),
            (
                &raw const ENCAPSULATION_MECHANISM,
                false,
                c"xmlSecKeyDataIdsRegister(xmlSecKeyDataEncapsulationMechanismId)",
            ),
            (
                &raw const VALUE,
                false,
                c"xmlSecKeyDataIdsRegister(xmlSecKeyDataValueId)",
            ),
        ];
        for (id, enabled, step) in registrations {
            // SAFETY: registering static klasses.
            let registered = unsafe {
                if enabled {
                    xmlSecKeyDataIdsRegister(id)
                } else {
                    xmlSecKeyDataIdsRegisterDisabled(id)
                }
            };
            if registered < 0 {
                errors::internal(
                    here!("xmlSecKeyDataIdsRegisterDefault"),
                    std::ptr::null(),
                    step,
                );
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
        let null = std::ptr::null_mut();
        check!(!id.is_null(), "xmlSecKeyDataCreate", c"id != NULL", null);
        // SAFETY: a klass by the caller's contract.
        let klass = unsafe { &*id };
        check!(
            klass.klass_size >= size_of::<XmlSecKeyDataKlass>(),
            "xmlSecKeyDataCreate",
            c"id->klassSize >= sizeof(xmlSecKeyDataKlass)",
            null
        );
        check!(
            klass.obj_size >= size_of::<XmlSecKeyData>(),
            "xmlSecKeyDataCreate",
            c"id->objSize >= sizeof(xmlSecKeyData)",
            null
        );
        check!(
            !klass.name.is_null(),
            "xmlSecKeyDataCreate",
            c"id->name != NULL",
            null
        );
        let here = here!("xmlSecKeyDataCreate");
        // SAFETY: the object is the klass's size.
        unsafe {
            let data = malloc(klass.obj_size).cast::<XmlSecKeyData>();
            if data.is_null() {
                errors::malloc_failed(here, name_of(klass), klass.obj_size);
                return data;
            }
            data.cast::<u8>().write_bytes(0, klass.obj_size);
            (*data).id = id;
            if let Some(initialize) = klass.initialize
                && initialize(data) < 0
            {
                errors::internal(here, name_of(klass), c"id->initialize");
                xmlSecKeyDataDestroy(data);
                return null;
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
        let null = std::ptr::null_mut();
        let klass = key_data_or!(data, "xmlSecKeyDataDuplicate", null);
        let Some(duplicate) = klass.duplicate else {
            errors::assertion(
                here!("xmlSecKeyDataDuplicate"),
                c"data->id->duplicate != NULL",
            );
            return null;
        };
        let here = here!("xmlSecKeyDataDuplicate");
        // SAFETY: by the caller's contract.
        unsafe {
            let copy = xmlSecKeyDataCreate((*data).id);
            if copy.is_null() {
                errors::internal(here, name_of(klass), c"xmlSecKeyDataCreate");
                return copy;
            }
            if duplicate(copy, data) < 0 {
                errors::internal(here, name_of(klass), c"id->duplicate");
                xmlSecKeyDataDestroy(copy);
                return null;
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
        let klass = key_data_or!(data, "xmlSecKeyDataDestroy");
        let size = klass.obj_size;
        let finalize = klass.finalize;
        // SAFETY: by the caller's contract.
        unsafe {
            if let Some(finalize) = finalize {
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
        let klass = key_data_or!(data, "xmlSecKeyDataGenerate", -1);
        let Some(generate) = klass.generate else {
            errors::assertion(
                here!("xmlSecKeyDataGenerate"),
                c"data->id->generate != NULL",
            );
            return -1;
        };
        // SAFETY: by the caller's contract.
        if unsafe { generate(data, size_bits, kind) } < 0 {
            errors::internal_with(
                here!("xmlSecKeyDataGenerate"),
                name_of(klass),
                c"id->generate",
                &format!("size={size_bits}"),
            );
            return -1;
        }
        0
    })
}

/// `xmlSecKeyDataGetType`: the klass's answer, unknown without a method.
///
/// # Safety
/// `data` is null or a key-data object.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataGetType(data: *mut XmlSecKeyData) -> c_uint {
    contain(TYPE_UNKNOWN, || {
        let klass = key_data_or!(data, "xmlSecKeyDataGetType", TYPE_UNKNOWN);
        match klass.get_type {
            // SAFETY: by the caller's contract.
            Some(get_type) => unsafe { get_type(data) },
            None => TYPE_UNKNOWN,
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
        let klass = key_data_or!(data, "xmlSecKeyDataGetSize", 0);
        match klass.get_size {
            // SAFETY: by the caller's contract.
            Some(get_size) => unsafe { get_size(data) },
            None => 0,
        }
    })
}

/// `xmlSecKeyDataGetIdentifier`: deprecated, always null.
///
/// # Safety
/// `data` is null or a key-data object.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataGetIdentifier(data: *mut XmlSecKeyData) -> *const u8 {
    contain(std::ptr::null(), || {
        key_data_or!(data, "xmlSecKeyDataGetIdentifier", std::ptr::null());
        errors::not_implemented(
            here!("xmlSecKeyDataGetIdentifier"),
            "Key data identifier method is deprecated",
        );
        std::ptr::null()
    })
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
        let klass = key_data_or!(data, "xmlSecKeyDataDebugDump");
        let Some(dump) = klass.debug_dump else {
            errors::assertion(
                here!("xmlSecKeyDataDebugDump"),
                c"data->id->debugDump != NULL",
            );
            return;
        };
        check!(
            !output.is_null(),
            "xmlSecKeyDataDebugDump",
            c"output != NULL"
        );
        // SAFETY: by the caller's contract.
        unsafe { dump(data, output) };
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
        let klass = key_data_or!(data, "xmlSecKeyDataDebugXmlDump");
        let Some(dump) = klass.debug_xml_dump else {
            errors::assertion(
                here!("xmlSecKeyDataDebugXmlDump"),
                c"data->id->debugXmlDump != NULL",
            );
            return;
        };
        check!(
            !output.is_null(),
            "xmlSecKeyDataDebugXmlDump",
            c"output != NULL"
        );
        // SAFETY: by the caller's contract.
        unsafe { dump(data, output) };
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
        check!(!id.is_null(), "xmlSecKeyDataXmlRead", c"id != NULL", -1);
        // SAFETY: a klass by the caller's contract.
        let Some(read) = (unsafe { (*id).xml_read }) else {
            errors::assertion(here!("xmlSecKeyDataXmlRead"), c"id->xmlRead != NULL");
            return -1;
        };
        check!(!key.is_null(), "xmlSecKeyDataXmlRead", c"key != NULL", -1);
        check!(!node.is_null(), "xmlSecKeyDataXmlRead", c"node != NULL", -1);
        let info = ctx.cast::<super::keyinfo::XmlSecKeyInfoCtx>();
        if info.is_null() {
            // SAFETY: by the caller's contract; the klass checks the context.
            return unsafe { read(id, key, node, ctx) };
        }
        let here = here!("xmlSecKeyDataXmlRead");
        // SAFETY: a KeyInfo context by the caller's contract; its reserved
        // slot holds this read's policy revision while the guard lives.
        unsafe {
            let Some(_pin) = super::policy::SlotPin::hold(&raw mut (*info).reserved0, here) else {
                return -1;
            };
            // The verification policy decides which document key sources a
            // read may use, whatever klasses the context enables.
            if super::policy::pinned((*info).reserved0)
                .is_some_and(|pinned| super::keyinfo::source_refused(id, pinned, here))
            {
                return -1;
            }
            read(id, key, node, ctx)
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
        check!(!id.is_null(), "xmlSecKeyDataXmlWrite", c"id != NULL", -1);
        // SAFETY: a klass by the caller's contract.
        let Some(write) = (unsafe { (*id).xml_write }) else {
            errors::assertion(here!("xmlSecKeyDataXmlWrite"), c"id->xmlWrite != NULL");
            return -1;
        };
        check!(!key.is_null(), "xmlSecKeyDataXmlWrite", c"key != NULL", -1);
        check!(
            !node.is_null(),
            "xmlSecKeyDataXmlWrite",
            c"node != NULL",
            -1
        );
        // SAFETY: by the caller's contract.
        unsafe { write(id, key, node, ctx) }
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
        check!(!id.is_null(), "xmlSecKeyDataBinRead", c"id != NULL", -1);
        // SAFETY: a klass by the caller's contract.
        let Some(read) = (unsafe { (*id).bin_read }) else {
            errors::assertion(here!("xmlSecKeyDataBinRead"), c"id->binRead != NULL");
            return -1;
        };
        check!(!key.is_null(), "xmlSecKeyDataBinRead", c"key != NULL", -1);
        check!(!buf.is_null(), "xmlSecKeyDataBinRead", c"buf != NULL", -1);
        // SAFETY: by the caller's contract.
        unsafe { read(id, key, buf, size, ctx) }
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
        check!(!id.is_null(), "xmlSecKeyDataBinWrite", c"id != NULL", -1);
        // SAFETY: a klass by the caller's contract.
        let Some(write) = (unsafe { (*id).bin_write }) else {
            errors::assertion(here!("xmlSecKeyDataBinWrite"), c"id->binWrite != NULL");
            return -1;
        };
        check!(!key.is_null(), "xmlSecKeyDataBinWrite", c"key != NULL", -1);
        check!(!buf.is_null(), "xmlSecKeyDataBinWrite", c"buf != NULL", -1);
        // SAFETY: by the caller's contract.
        unsafe { write(id, key, buf, size, ctx) }
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

/// The items of a key-data klass list; otherwise reports libxmlsec1's
/// failed list check from the entry point at `here`.
///
/// # Safety
/// `list` is null or a list.
unsafe fn klass_items<'a>(
    list: *mut XmlSecPtrList,
    here: errors::Here,
) -> Option<&'a [*const XmlSecKeyDataKlass]> {
    // SAFETY: by the caller's contract.
    let Some(owner) = (unsafe { list.as_ref() })
        .filter(|owner| std::ptr::eq(owner.id, &raw const KEY_DATA_ID_LIST_KLASS))
    else {
        errors::assertion(here, c"xmlSecPtrListCheckId(list, xmlSecKeyDataIdListId)");
        return None;
    };
    if owner.used == 0 || owner.data.is_null() {
        return Some(&[]);
    }
    // SAFETY: a list's first `used` items are its entries; a klass list's
    // entries are klass pointers.
    Some(unsafe { std::slice::from_raw_parts(owner.data.cast(), owner.used) })
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
        let Some(items) = (unsafe { klass_items(list, here!("xmlSecKeyDataIdListFind")) }) else {
            return 0;
        };
        check!(
            !id.is_null(),
            "xmlSecKeyDataIdListFind",
            c"dataId != NULL",
            0
        );
        c_int::from(items.iter().any(|item| std::ptr::eq(*item, id)))
    })
}

/// The first listed klass usable for `usage` that `matches`, or null; a
/// null entry reached first is reported from the entry point at `here`.
///
/// # Safety
/// `items` are null or klasses.
unsafe fn find(
    items: &[*const XmlSecKeyDataKlass],
    usage: c_uint,
    matches: impl Fn(&XmlSecKeyDataKlass) -> bool,
    here: errors::Here,
) -> *const XmlSecKeyDataKlass {
    for &item in items {
        // SAFETY: by the caller's contract.
        let Some(klass) = (unsafe { item.as_ref() }) else {
            errors::assertion(here, c"dataId != xmlSecKeyDataIdUnknown");
            return std::ptr::null();
        };
        if usage & klass.usage != 0 && matches(klass) {
            return item;
        }
    }
    std::ptr::null()
}

/// The klass of `$list` usable for `$usage` whose `$key` field equals the
/// required `$value` (named `$text` in libxmlsec1's assertion), searched for
/// the entry point `$func`.
macro_rules! find_by {
    ($list:expr, $value:expr, $usage:expr, $func:literal, $text:literal, $matches:expr) => {{
        let null = std::ptr::null();
        let here = here!($func);
        // SAFETY: by the caller's contract.
        let Some(items) = (unsafe { klass_items($list, here) }) else {
            return null;
        };
        check!(!$value.is_null(), $func, $text, null);
        let matches = $matches;
        // SAFETY: a klass list holds klasses.
        unsafe { find(items, $usage, matches, here) }
    }};
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
        find_by!(
            list,
            node_name,
            usage,
            "xmlSecKeyDataIdListFindByNode",
            c"nodeName != NULL",
            |klass: &XmlSecKeyDataKlass| {
                // SAFETY: the names are null or NUL-terminated; libxml2
                // compares null equal to null only.
                unsafe {
                    xmlStrEqual(node_name, klass.data_node_name) != 0
                        && xmlStrEqual(node_ns, klass.data_node_ns) != 0
                }
            }
        )
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
        find_by!(
            list,
            href,
            usage,
            "xmlSecKeyDataIdListFindByHref",
            c"href != NULL",
            |klass: &XmlSecKeyDataKlass| {
                // SAFETY: the hrefs are NUL-terminated.
                !klass.href.is_null() && unsafe { xmlStrEqual(href, klass.href) } != 0
            }
        )
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
        find_by!(
            list,
            name,
            usage,
            "xmlSecKeyDataIdListFindByName",
            c"name != NULL",
            |klass: &XmlSecKeyDataKlass| {
                // SAFETY: the names are NUL-terminated.
                !klass.name.is_null() && unsafe { xmlStrEqual(name, klass.name) } != 0
            }
        )
    })
}

/// The names of `items` for a dump, each passed to `write`; a null entry or
/// name stops the dump with libxmlsec1's assertion, from `here`.
///
/// # Safety
/// `items` are null or klasses.
unsafe fn dump_names(
    items: &[*const XmlSecKeyDataKlass],
    here: errors::Here,
    mut write: impl FnMut(usize, String),
) -> Option<()> {
    for (position, &item) in items.iter().enumerate() {
        // SAFETY: by the caller's contract.
        let Some(klass) = (unsafe { item.as_ref() }) else {
            errors::assertion(here, c"dataId != NULL");
            return None;
        };
        if klass.name.is_null() {
            errors::assertion(here, c"dataId->name != NULL");
            return None;
        }
        // SAFETY: a klass name is NUL-terminated.
        write(position, unsafe { klass_text(klass.name) });
    }
    Some(())
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
        let here = here!("xmlSecKeyDataIdListDebugDump");
        // SAFETY: by the caller's contract.
        let Some(items) = (unsafe { klass_items(list, here) }) else {
            return;
        };
        check!(
            !output.is_null(),
            "xmlSecKeyDataIdListDebugDump",
            c"output != NULL"
        );
        let mut text = String::new();
        // SAFETY: a klass list holds klasses.
        let complete = unsafe {
            dump_names(items, here, |position, name| {
                if position > 0 {
                    text.push(',');
                }
                text.push('"');
                text.push_str(&name);
                text.push('"');
            })
        };
        if complete.is_some() {
            text.push('\n');
        }
        // SAFETY: `output` is a live stream.
        unsafe { write_stream(output, &text) };
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
        let here = here!("xmlSecKeyDataIdListDebugXmlDump");
        // SAFETY: by the caller's contract.
        let Some(items) = (unsafe { klass_items(list, here) }) else {
            return;
        };
        check!(
            !output.is_null(),
            "xmlSecKeyDataIdListDebugXmlDump",
            c"output != NULL"
        );
        let mut text = String::from("<KeyDataIdsList>\n");
        // SAFETY: a klass list holds klasses.
        let complete = unsafe {
            dump_names(items, here, |_, name| {
                text.push_str("<DataId name=\"");
                text.push_str(&xml_text(&name));
                text.push_str("\"/>");
            })
        };
        if complete.is_some() {
            text.push_str("</KeyDataIdsList>\n");
        }
        // SAFETY: `output` is a live stream.
        unsafe { write_stream(output, &text) };
    });
}

// ----------------------------------------------------------------------------
// Stores

/// libxmlsec1's `xmlSecKeyDataStoreIsValid`: a store with a klass.
///
/// # Safety
/// `store` is null or a store.
pub(crate) unsafe fn store_valid(store: *mut XmlSecKeyDataStore) -> bool {
    // SAFETY: by the caller's contract.
    unsafe { store.as_ref() }.is_some_and(|store| !store.id.is_null())
}

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
        let null = std::ptr::null_mut();
        check!(
            !id.is_null(),
            "xmlSecKeyDataStoreCreate",
            c"id != NULL",
            null
        );
        // SAFETY: a store klass by the caller's contract.
        let klass = unsafe { &*id };
        check!(
            klass.obj_size > 0,
            "xmlSecKeyDataStoreCreate",
            c"id->objSize > 0",
            null
        );
        let here = here!("xmlSecKeyDataStoreCreate");
        let name = klass.name.cast();
        // SAFETY: the object is the klass's size.
        unsafe {
            let store = malloc(klass.obj_size).cast::<XmlSecKeyDataStore>();
            if store.is_null() {
                errors::malloc_failed(here, name, klass.obj_size);
                return store;
            }
            store.cast::<u8>().write_bytes(0, klass.obj_size);
            (*store).id = id;
            if let Some(initialize) = klass.initialize
                && initialize(store) < 0
            {
                errors::internal(here, name, c"id->initialize");
                xmlSecKeyDataStoreDestroy(store);
                return null;
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
        let klass = unsafe { store.as_ref().and_then(|store| store.id.as_ref()) };
        check!(
            klass.is_some(),
            "xmlSecKeyDataStoreDestroy",
            c"xmlSecKeyDataStoreIsValid(store)"
        );
        let Some(klass) = klass else { return };
        let size = klass.obj_size;
        check!(
            size > 0,
            "xmlSecKeyDataStoreDestroy",
            c"store->id->objSize > 0"
        );
        // SAFETY: a store of the klass's size.
        unsafe {
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

/// The `xmlRead`/`xmlWrite` method type of a key-data klass.
pub(crate) type XmlMethod =
    Option<unsafe extern "C" fn(*const XmlSecKeyDataKlass, Opaque, *mut c_void, Opaque) -> c_int>;

/// A `KeyInfo` child klass: plain key-data objects identified by their
/// element, read and written by `xml_read` and `xml_write`.
const fn key_info_child(
    name: *const u8,
    href: *const u8,
    node: *const u8,
    ns: *const u8,
    xml_read: XmlMethod,
    xml_write: XmlMethod,
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
        xml_read,
        xml_write,
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
    Some(keyinfo::name_xml_read),
    Some(keyinfo::name_xml_write),
);
static VALUE: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameKeyValue.as_ptr(),
    std::ptr::null(),
    xmlSecNodeKeyValue.as_ptr(),
    xmlSecDSigNs.as_ptr(),
    Some(keyinfo::value_xml_read),
    Some(keyinfo::value_xml_write),
);
static RETRIEVAL_METHOD: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameRetrievalMethod.as_ptr(),
    std::ptr::null(),
    xmlSecNodeRetrievalMethod.as_ptr(),
    xmlSecDSigNs.as_ptr(),
    Some(keyinfo::retrieval_xml_read),
    Some(keyinfo::retrieval_xml_write),
);
static KEY_INFO_REFERENCE: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameKeyInfoReference.as_ptr(),
    std::ptr::null(),
    xmlSecNodeKeyInfoReference.as_ptr(),
    xmlSecDSig11Ns.as_ptr(),
    Some(keyinfo::reference_xml_read),
    Some(keyinfo::reference_xml_write),
);
static ENCRYPTED_KEY: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameEncryptedKey.as_ptr(),
    xmlSecHrefEncryptedKey.as_ptr(),
    xmlSecNodeEncryptedKey.as_ptr(),
    xmlSecEncNs.as_ptr(),
    None,
    None,
);
static DERIVED_KEY: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameDerivedKey.as_ptr(),
    xmlSecHrefDerivedKey.as_ptr(),
    xmlSecNodeDerivedKey.as_ptr(),
    xmlSecEnc11Ns.as_ptr(),
    None,
    None,
);
static AGREEMENT_METHOD: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameAgreementMethod.as_ptr(),
    xmlSecHrefAgreementMethod.as_ptr(),
    xmlSecNodeAgreementMethod.as_ptr(),
    xmlSecEncNs.as_ptr(),
    None,
    None,
);
static ENCAPSULATION_MECHANISM: XmlSecKeyDataKlass = key_info_child(
    xmlSecNameEncapsulationMechanism.as_ptr(),
    xmlSecHrefEncapsulationMechanism.as_ptr(),
    xmlSecNodeEncapsulationMechanism.as_ptr(),
    xmlSecExperimental202512Ns.as_ptr(),
    None,
    None,
);

macro_rules! key_data_getter {
    ($($name:ident => $klass:ident;)*) => {
        $(
            #[doc = concat!("`", stringify!($name), "`.")]
            ///
            /// # Safety
            /// Callable at any time.
            #[unsafe(no_mangle)]
            pub(crate) extern "C" fn $name() -> *const XmlSecKeyDataKlass {
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
