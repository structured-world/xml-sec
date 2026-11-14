//! `xmlsec/keys.h`: keys, key requirements and key use-with records.
//!
//! A key holds a value (one key-data object of a value klass), a list of
//! further key data, a name, a usage mask and a validity interval, all
//! owned by the key as in libxmlsec1. The structure lives on the library's
//! heap with libxmlsec1's layout, and every operation on its data goes
//! through the key-data klass methods.

use std::ffi::{CStr, c_int, c_uint, c_void};

use super::errors::{self, check, here};
use super::keysdata::{
    XmlSecKeyData, XmlSecKeyDataKlass, xmlSecKeyDataCreate, xmlSecKeyDataDebugDump,
    xmlSecKeyDataDebugXmlDump, xmlSecKeyDataDestroy, xmlSecKeyDataDuplicate, xmlSecKeyDataGenerate,
    xmlSecKeyDataGetSize, xmlSecKeyDataGetType, xmlSecKeyDataIdListFindByName, xmlSecKeyDataIdsGet,
    xmlSecKeyDataListGetKlass, xmlSecKeyDataValueGetKlass,
};
use super::list::{
    XmlSecPtrList, XmlSecPtrListKlass, xmlSecPtrListAdd, xmlSecPtrListCopy, xmlSecPtrListCreate,
    xmlSecPtrListDebugDump, xmlSecPtrListDebugXmlDump, xmlSecPtrListDestroy,
    xmlSecPtrListDuplicate, xmlSecPtrListEmpty, xmlSecPtrListFinalize, xmlSecPtrListGetItem,
    xmlSecPtrListGetSize, xmlSecPtrListInitialize, xmlSecPtrListSet,
};
use super::transforms::zero_list;
use super::tree::xmlStrEqual;
use super::xmltree::xmlSecPrintXmlString;
use super::{contain, duplicate, free, malloc, write_stream};

/// `xmlSecKeyUsageAny`.
pub(crate) const USAGE_ANY: c_uint = 0xFFFF_FFFF;
/// `xmlSecKeyDataTypeUnknown`.
pub(crate) const TYPE_UNKNOWN: c_uint = 0;
/// `xmlSecKeyDataTypePublic`.
pub(crate) const TYPE_PUBLIC: c_uint = 0x0001;
/// `xmlSecKeyDataTypePrivate`.
pub(crate) const TYPE_PRIVATE: c_uint = 0x0002;
/// `xmlSecKeyDataTypeSymmetric`.
pub(crate) const TYPE_SYMMETRIC: c_uint = 0x0004;
/// `xmlSecKeyDataUsageUnknown`.
const DATA_USAGE_UNKNOWN: c_uint = 0;
/// `xmlSecKeyDataUsageAny`.
const DATA_USAGE_ANY: c_uint = 0xFFFFF;
/// `XMLSEC_ERRORS_R_KEY_DATA_NOT_FOUND`.
const R_KEY_DATA_NOT_FOUND: c_int = 42;

/// `xmlSecKeyUseWith`.
#[repr(C)]
pub(crate) struct XmlSecKeyUseWith {
    pub(crate) application: *mut u8,
    pub(crate) identifier: *mut u8,
    pub(crate) reserved1: *mut c_void,
    pub(crate) reserved2: *mut c_void,
}

/// `xmlSecKeyReq`.
#[repr(C)]
pub(crate) struct XmlSecKeyReq {
    pub(crate) key_id: *const XmlSecKeyDataKlass,
    pub(crate) key_type: c_uint,
    pub(crate) key_usage: c_uint,
    pub(crate) key_bits_size: usize,
    pub(crate) key_use_with_list: XmlSecPtrList,
    pub(crate) reserved1: *mut c_void,
    pub(crate) reserved2: *mut c_void,
}

/// `xmlSecKey`.
#[repr(C)]
pub(crate) struct XmlSecKey {
    pub(crate) name: *mut u8,
    pub(crate) value: *mut XmlSecKeyData,
    pub(crate) data_list: *mut XmlSecPtrList,
    pub(crate) usage: c_uint,
    pub(crate) not_valid_before: libc::time_t,
    pub(crate) not_valid_after: libc::time_t,
}

impl XmlSecKey {
    /// A key with nothing in it.
    const EMPTY: Self = Self {
        name: std::ptr::null_mut(),
        value: std::ptr::null_mut(),
        data_list: std::ptr::null_mut(),
        usage: 0,
        not_valid_before: 0,
        not_valid_after: 0,
    };
}

/// libxmlsec1's `xmlSecKeyIsValid`: a key with a value of some klass.
///
/// # Safety
/// `key` is null or a key.
pub(crate) unsafe fn key_valid(key: *mut XmlSecKey) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        key.as_ref()
            .and_then(|key| key.value.as_ref())
            .is_some_and(|value| !value.id.is_null())
    }
}

/// A NUL-terminated string for a report or dump, `NULL` when null.
fn text(value: *const u8) -> String {
    if value.is_null() {
        "NULL".to_owned()
    } else {
        // SAFETY: a non-null string here is NUL-terminated.
        unsafe { CStr::from_ptr(value.cast()) }
            .to_string_lossy()
            .into_owned()
    }
}

/// The name of the klass `id`, as `xmlSecKeyDataKlassGetName`.
///
/// # Safety
/// `id` is null or a klass.
unsafe fn klass_name(id: *const XmlSecKeyDataKlass) -> *const u8 {
    // SAFETY: by the caller's contract.
    unsafe { id.as_ref() }.map_or(std::ptr::null(), |klass| klass.name)
}

/// A copy of `value` in libxml2's allocator, null for null; `Err` after
/// libxmlsec1's report when the copy fails.
///
/// # Safety
/// `value` is null or NUL-terminated.
unsafe fn copy_of(value: *const u8, here: errors::Here) -> Result<*mut u8, ()> {
    if value.is_null() {
        return Ok(std::ptr::null_mut());
    }
    // SAFETY: by the caller's contract.
    let bytes = unsafe { CStr::from_ptr(value.cast()) }.to_bytes();
    let copy = duplicate(bytes);
    if copy.is_null() {
        errors::strdup_failed(here, std::ptr::null(), bytes);
        return Err(());
    }
    Ok(copy)
}

/// Replaces the string at `slot` with a copy of `value` (or nothing for
/// null); false with libxmlsec1's report when the copy fails. The copy is
/// made first, so `value` may be the string at `slot` or a part of it.
///
/// # Safety
/// `slot` holds null or a string of libxml2's allocator; `value` is null or
/// NUL-terminated.
unsafe fn replace(slot: &mut *mut u8, value: *const u8, here: errors::Here) -> bool {
    // SAFETY: by the caller's contract.
    let Ok(copy) = (unsafe { copy_of(value, here) }) else {
        return false;
    };
    if !slot.is_null() {
        // SAFETY: a string of libxml2's allocator, no longer read.
        unsafe { free(slot.cast()) };
    }
    *slot = copy;
    true
}

// ----------------------------------------------------------------------------
// xmlSecKeyUseWith

/// `xmlSecKeyUseWithInitialize`: an empty record.
///
/// # Safety
/// `key_use_with` is null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyUseWithInitialize(
    key_use_with: *mut XmlSecKeyUseWith,
) -> c_int {
    contain(-1, || {
        check!(
            !key_use_with.is_null(),
            "xmlSecKeyUseWithInitialize",
            c"keyUseWith != NULL",
            -1
        );
        // SAFETY: writable.
        unsafe { key_use_with.write_bytes(0, 1) };
        0
    })
}

/// `xmlSecKeyUseWithFinalize`: releases the strings and zeroes the record.
///
/// # Safety
/// `key_use_with` is null or an initialized record.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyUseWithFinalize(key_use_with: *mut XmlSecKeyUseWith) {
    contain((), || {
        check!(
            !key_use_with.is_null(),
            "xmlSecKeyUseWithFinalize",
            c"keyUseWith != NULL"
        );
        // SAFETY: an initialized record.
        unsafe {
            xmlSecKeyUseWithReset(key_use_with);
            key_use_with.write_bytes(0, 1);
        }
    });
}

/// `xmlSecKeyUseWithReset`: clears the application and identifier.
///
/// # Safety
/// `key_use_with` is null or an initialized record.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyUseWithReset(key_use_with: *mut XmlSecKeyUseWith) {
    contain((), || {
        check!(
            !key_use_with.is_null(),
            "xmlSecKeyUseWithReset",
            c"keyUseWith != NULL"
        );
        // SAFETY: an initialized record.
        unsafe { xmlSecKeyUseWithSet(key_use_with, std::ptr::null(), std::ptr::null()) };
    });
}

/// `xmlSecKeyUseWithCopy`: copies the strings of `src` into `dst`.
///
/// # Safety
/// `dst` and `src` are null or initialized records.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyUseWithCopy(
    dst: *mut XmlSecKeyUseWith,
    src: *mut XmlSecKeyUseWith,
) -> c_int {
    contain(-1, || {
        check!(!dst.is_null(), "xmlSecKeyUseWithCopy", c"dst != NULL", -1);
        check!(!src.is_null(), "xmlSecKeyUseWithCopy", c"src != NULL", -1);
        // A record copied onto itself is already the copy; the setter would
        // free the strings it is given before reading them.
        if std::ptr::eq(dst, src) {
            return 0;
        }
        // SAFETY: initialized records.
        unsafe { xmlSecKeyUseWithSet(dst, (*src).application, (*src).identifier) }
    })
}

/// `xmlSecKeyUseWithCreate`: a new record, released with
/// [`xmlSecKeyUseWithDestroy`].
///
/// # Safety
/// `application` and `identifier` are null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyUseWithCreate(
    application: *const u8,
    identifier: *const u8,
) -> *mut XmlSecKeyUseWith {
    contain(std::ptr::null_mut(), || {
        let here = here!("xmlSecKeyUseWithCreate");
        let record = malloc(size_of::<XmlSecKeyUseWith>()).cast::<XmlSecKeyUseWith>();
        if record.is_null() {
            errors::malloc_failed(here, std::ptr::null(), size_of::<XmlSecKeyUseWith>());
            return record;
        }
        // SAFETY: a fresh allocation of the record's size.
        unsafe {
            record.write_bytes(0, 1);
            if xmlSecKeyUseWithSet(record, application, identifier) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyUseWithSet");
                xmlSecKeyUseWithDestroy(record);
                return std::ptr::null_mut();
            }
        }
        record
    })
}

/// `xmlSecKeyUseWithDuplicate`: a new copy of `key_use_with`.
///
/// # Safety
/// `key_use_with` is null or an initialized record.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyUseWithDuplicate(
    key_use_with: *mut XmlSecKeyUseWith,
) -> *mut XmlSecKeyUseWith {
    contain(std::ptr::null_mut(), || {
        check!(
            !key_use_with.is_null(),
            "xmlSecKeyUseWithDuplicate",
            c"keyUseWith != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecKeyUseWithDuplicate");
        // SAFETY: an initialized record.
        unsafe {
            let copy = xmlSecKeyUseWithCreate(std::ptr::null(), std::ptr::null());
            if copy.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyUseWithCreate");
                return copy;
            }
            if xmlSecKeyUseWithCopy(copy, key_use_with) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyUseWithCopy");
                xmlSecKeyUseWithDestroy(copy);
                return std::ptr::null_mut();
            }
            copy
        }
    })
}

/// `xmlSecKeyUseWithDestroy`: releases a record from
/// [`xmlSecKeyUseWithCreate`].
///
/// # Safety
/// `key_use_with` is null or a created record.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyUseWithDestroy(key_use_with: *mut XmlSecKeyUseWith) {
    contain((), || {
        check!(
            !key_use_with.is_null(),
            "xmlSecKeyUseWithDestroy",
            c"keyUseWith != NULL"
        );
        // SAFETY: a created record.
        unsafe {
            xmlSecKeyUseWithFinalize(key_use_with);
            free(key_use_with.cast());
        }
    });
}

/// `xmlSecKeyUseWithSet`: replaces the application and identifier with
/// copies of the arguments.
///
/// # Safety
/// `key_use_with` is null or an initialized record; the strings null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyUseWithSet(
    key_use_with: *mut XmlSecKeyUseWith,
    application: *const u8,
    identifier: *const u8,
) -> c_int {
    contain(-1, || {
        check!(
            !key_use_with.is_null(),
            "xmlSecKeyUseWithSet",
            c"keyUseWith != NULL",
            -1
        );
        let here = here!("xmlSecKeyUseWithSet");
        // SAFETY: an initialized record. Both inputs are copied before
        // either string of the record is released, since an input may be
        // one of them; on a failed copy the record keeps nothing, as
        // libxmlsec1's leaves it.
        unsafe {
            let record = &mut *key_use_with;
            let application = copy_of(application, here);
            let identifier = copy_of(identifier, here);
            for old in [record.application, record.identifier] {
                if !old.is_null() {
                    free(old.cast());
                }
            }
            record.application = std::ptr::null_mut();
            record.identifier = std::ptr::null_mut();
            match (application, identifier) {
                (Ok(application), Ok(identifier)) => {
                    record.application = application;
                    record.identifier = identifier;
                }
                (application, identifier) => {
                    for copy in [application, identifier].into_iter().flatten() {
                        if !copy.is_null() {
                            free(copy.cast());
                        }
                    }
                    return -1;
                }
            }
        }
        0
    })
}

/// `xmlSecKeyUseWithDebugDump`: prints the record.
///
/// # Safety
/// `key_use_with` is null or an initialized record; `output` null or a
/// live C stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyUseWithDebugDump(
    key_use_with: *mut XmlSecKeyUseWith,
    output: *mut c_void,
) {
    contain((), || {
        check!(
            !key_use_with.is_null(),
            "xmlSecKeyUseWithDebugDump",
            c"keyUseWith != NULL"
        );
        check!(
            !output.is_null(),
            "xmlSecKeyUseWithDebugDump",
            c"output != NULL"
        );
        // SAFETY: an initialized record and a live stream.
        unsafe {
            let shown = |value: *mut u8| {
                if value.is_null() {
                    String::new()
                } else {
                    text(value)
                }
            };
            write_stream(
                output,
                &format!(
                    "=== KeyUseWith: application=\"{}\",identifier=\"{}\"\n",
                    shown((*key_use_with).application),
                    shown((*key_use_with).identifier)
                ),
            );
        }
    });
}

/// `xmlSecKeyUseWithDebugXmlDump`: prints the record as XML.
///
/// # Safety
/// As for [`xmlSecKeyUseWithDebugDump`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyUseWithDebugXmlDump(
    key_use_with: *mut XmlSecKeyUseWith,
    output: *mut c_void,
) {
    contain((), || {
        check!(
            !key_use_with.is_null(),
            "xmlSecKeyUseWithDebugXmlDump",
            c"keyUseWith != NULL"
        );
        check!(
            !output.is_null(),
            "xmlSecKeyUseWithDebugXmlDump",
            c"output != NULL"
        );
        // SAFETY: an initialized record and a live stream.
        unsafe {
            write_stream(output, "<KeyUseWith>\n<Application>");
            xmlSecPrintXmlString(output, (*key_use_with).application);
            write_stream(output, "</Application><Identifier>");
            xmlSecPrintXmlString(output, (*key_use_with).identifier);
            write_stream(output, "</Identifier></KeyUseWith>\n");
        }
    });
}

unsafe extern "C" fn use_with_duplicate(item: *mut c_void) -> *mut c_void {
    // SAFETY: the list holds use-with records.
    unsafe { xmlSecKeyUseWithDuplicate(item.cast()).cast() }
}

unsafe extern "C" fn use_with_destroy(item: *mut c_void) {
    // SAFETY: as above.
    unsafe { xmlSecKeyUseWithDestroy(item.cast()) }
}

unsafe extern "C" fn use_with_dump(item: *mut c_void, output: *mut c_void) {
    // SAFETY: as above.
    unsafe { xmlSecKeyUseWithDebugDump(item.cast(), output) }
}

unsafe extern "C" fn use_with_xml_dump(item: *mut c_void, output: *mut c_void) {
    // SAFETY: as above.
    unsafe { xmlSecKeyUseWithDebugXmlDump(item.cast(), output) }
}

static KEY_USE_WITH_LIST: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"key-use-with-list".as_ptr().cast(),
    duplicate_item: Some(use_with_duplicate),
    destroy_item: Some(use_with_destroy),
    debug_dump_item: Some(use_with_dump),
    debug_xml_dump_item: Some(use_with_xml_dump),
};

/// `xmlSecKeyUseWithPtrListGetKlass`: the klass of a list of use-with
/// records.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn xmlSecKeyUseWithPtrListGetKlass() -> *const XmlSecPtrListKlass {
    &raw const KEY_USE_WITH_LIST
}

// ----------------------------------------------------------------------------
// xmlSecKeyReq

/// `xmlSecKeyReqInitialize`: requirements any key meets, with an empty
/// use-with list.
///
/// # Safety
/// `key_req` is null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyReqInitialize(key_req: *mut XmlSecKeyReq) -> c_int {
    contain(-1, || {
        check!(
            !key_req.is_null(),
            "xmlSecKeyReqInitialize",
            c"keyReq != NULL",
            -1
        );
        // SAFETY: writable.
        unsafe {
            key_req.write(XmlSecKeyReq {
                key_id: std::ptr::null(),
                key_type: 0,
                key_usage: USAGE_ANY,
                key_bits_size: 0,
                key_use_with_list: zero_list(),
                reserved1: std::ptr::null_mut(),
                reserved2: std::ptr::null_mut(),
            });
            if xmlSecPtrListInitialize(
                &raw mut (*key_req).key_use_with_list,
                &raw const KEY_USE_WITH_LIST,
            ) < 0
            {
                errors::internal(
                    here!("xmlSecKeyReqInitialize"),
                    std::ptr::null(),
                    c"xmlSecPtrListInitialize",
                );
                return -1;
            }
        }
        0
    })
}

/// `xmlSecKeyReqFinalize`: releases the use-with list and zeroes the
/// requirements.
///
/// # Safety
/// `key_req` is null or initialized requirements.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyReqFinalize(key_req: *mut XmlSecKeyReq) {
    contain((), || {
        check!(
            !key_req.is_null(),
            "xmlSecKeyReqFinalize",
            c"keyReq != NULL"
        );
        // SAFETY: initialized requirements.
        unsafe {
            xmlSecPtrListFinalize(&raw mut (*key_req).key_use_with_list);
            key_req.write_bytes(0, 1);
        }
    });
}

/// `xmlSecKeyReqReset`: requirements any key meets again.
///
/// # Safety
/// `key_req` is null or initialized requirements.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyReqReset(key_req: *mut XmlSecKeyReq) {
    contain((), || {
        check!(!key_req.is_null(), "xmlSecKeyReqReset", c"keyReq != NULL");
        // SAFETY: initialized requirements.
        unsafe {
            xmlSecPtrListEmpty(&raw mut (*key_req).key_use_with_list);
            let req = &mut *key_req;
            req.key_id = std::ptr::null();
            req.key_type = 0;
            req.key_usage = USAGE_ANY;
            req.key_bits_size = 0;
        }
    });
}

/// `xmlSecKeyReqCopy`: copies the requirements and use-with records of
/// `src` into `dst`.
///
/// # Safety
/// `dst` and `src` are null or initialized requirements.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyReqCopy(
    dst: *mut XmlSecKeyReq,
    src: *mut XmlSecKeyReq,
) -> c_int {
    contain(-1, || {
        check!(!dst.is_null(), "xmlSecKeyReqCopy", c"dst != NULL", -1);
        check!(!src.is_null(), "xmlSecKeyReqCopy", c"src != NULL", -1);
        // Requirements copied onto themselves are already the copy; copying
        // a list into itself would append to it while reading it. Distinct
        // requirements replace the destination's use-with records, as
        // libxmlsec1 1.3.13 empties the list before copying.
        if std::ptr::eq(dst, src) {
            return 0;
        }
        // SAFETY: initialized requirements.
        unsafe {
            xmlSecPtrListEmpty(&raw mut (*dst).key_use_with_list);
            (*dst).key_id = (*src).key_id;
            (*dst).key_type = (*src).key_type;
            (*dst).key_usage = (*src).key_usage;
            (*dst).key_bits_size = (*src).key_bits_size;
            if xmlSecPtrListCopy(
                &raw mut (*dst).key_use_with_list,
                &raw mut (*src).key_use_with_list,
            ) < 0
            {
                errors::internal(
                    here!("xmlSecKeyReqCopy"),
                    std::ptr::null(),
                    c"xmlSecPtrListCopy",
                );
                return -1;
            }
        }
        0
    })
}

/// `xmlSecKeyReqMatchKey`: 1 when `key` has a type, usage and value the
/// requirements accept, otherwise 0.
///
/// # Safety
/// `key_req` is null or initialized requirements; `key` null or a key.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyReqMatchKey(
    key_req: *mut XmlSecKeyReq,
    key: *mut XmlSecKey,
) -> c_int {
    contain(-1, || {
        check!(
            !key_req.is_null(),
            "xmlSecKeyReqMatchKey",
            c"keyReq != NULL",
            -1
        );
        // SAFETY: null or a key.
        let valid = unsafe { key_valid(key) };
        check!(valid, "xmlSecKeyReqMatchKey", c"xmlSecKeyIsValid(key)", -1);
        // SAFETY: valid requirements and key.
        unsafe {
            let req = &*key_req;
            if req.key_type != TYPE_UNKNOWN && xmlSecKeyGetType(key) & req.key_type == 0 {
                return 0;
            }
            if req.key_usage != DATA_USAGE_UNKNOWN && req.key_usage & (*key).usage == 0 {
                return 0;
            }
            xmlSecKeyReqMatchKeyValue(key_req, (*key).value)
        }
    })
}

/// `xmlSecKeyReqMatchKeyValue`: 1 when `value` has the required klass and
/// at least the required size (an unknown size passes), otherwise 0.
///
/// # Safety
/// `key_req` is null or initialized requirements; `value` null or key data.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyReqMatchKeyValue(
    key_req: *mut XmlSecKeyReq,
    value: *mut XmlSecKeyData,
) -> c_int {
    contain(-1, || {
        check!(
            !key_req.is_null(),
            "xmlSecKeyReqMatchKeyValue",
            c"keyReq != NULL",
            -1
        );
        check!(
            !value.is_null(),
            "xmlSecKeyReqMatchKeyValue",
            c"value != NULL",
            -1
        );
        // SAFETY: valid requirements and key data.
        unsafe {
            let req = &*key_req;
            if !req.key_id.is_null() && !super::keysdata::check_id(value, req.key_id) {
                return 0;
            }
            if req.key_bits_size > 0 {
                let size = xmlSecKeyDataGetSize(value);
                if size > 0 && size < req.key_bits_size {
                    return 0;
                }
            }
        }
        1
    })
}

/// `xmlSecKeyReqDebugDump`: prints the requirements.
///
/// # Safety
/// `key_req` is null or initialized requirements; `output` null or a live C
/// stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyReqDebugDump(
    key_req: *mut XmlSecKeyReq,
    output: *mut c_void,
) {
    contain((), || {
        check!(
            !key_req.is_null(),
            "xmlSecKeyReqDebugDump",
            c"keyReq != NULL"
        );
        check!(
            !output.is_null(),
            "xmlSecKeyReqDebugDump",
            c"output != NULL"
        );
        // SAFETY: initialized requirements and a live stream.
        unsafe {
            let req = &mut *key_req;
            write_stream(
                output,
                &format!(
                    "=== KeyReq:\n==== keyId: {}\n==== keyType: 0x{:08x}\n==== keyUsage: 0x{:08x}\n==== keyBitsSize: {}\n",
                    text(klass_name(req.key_id)),
                    req.key_type,
                    req.key_usage,
                    req.key_bits_size
                ),
            );
            xmlSecPtrListDebugDump(&raw mut req.key_use_with_list, output);
        }
    });
}

/// `xmlSecKeyReqDebugXmlDump`: prints the requirements as XML.
///
/// # Safety
/// As for [`xmlSecKeyReqDebugDump`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyReqDebugXmlDump(
    key_req: *mut XmlSecKeyReq,
    output: *mut c_void,
) {
    contain((), || {
        check!(
            !key_req.is_null(),
            "xmlSecKeyReqDebugXmlDump",
            c"keyReq != NULL"
        );
        check!(
            !output.is_null(),
            "xmlSecKeyReqDebugXmlDump",
            c"output != NULL"
        );
        // SAFETY: initialized requirements and a live stream.
        unsafe {
            let req = &mut *key_req;
            write_stream(output, "<KeyReq>\n<KeyId>");
            xmlSecPrintXmlString(output, klass_name(req.key_id));
            write_stream(
                output,
                &format!(
                    "</KeyId>\n<KeyType>0x{:08x}</KeyType>\n<KeyUsage>0x{:08x}</KeyUsage>\n<KeyBitsSize>{}</KeyBitsSize>\n",
                    req.key_type, req.key_usage, req.key_bits_size
                ),
            );
            xmlSecPtrListDebugXmlDump(&raw mut req.key_use_with_list, output);
            write_stream(output, "</KeyReq>\n");
        }
    });
}

// ----------------------------------------------------------------------------
// xmlSecKey

/// `xmlSecKeyCreate`: an empty key usable for anything, released with
/// [`xmlSecKeyDestroy`].
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyCreate() -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        let key = malloc(size_of::<XmlSecKey>()).cast::<XmlSecKey>();
        if key.is_null() {
            errors::malloc_failed(
                here!("xmlSecKeyCreate"),
                std::ptr::null(),
                size_of::<XmlSecKey>(),
            );
            return key;
        }
        // SAFETY: a fresh allocation of the key's size.
        unsafe {
            key.write(XmlSecKey {
                usage: USAGE_ANY,
                ..XmlSecKey::EMPTY
            });
        }
        key
    })
}

/// `xmlSecKeyEmpty`: releases the value, name and data list and zeroes the
/// key, its usage included.
///
/// # Safety
/// `key` is null or a key.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyEmpty(key: *mut XmlSecKey) {
    contain((), || {
        check!(!key.is_null(), "xmlSecKeyEmpty", c"key != NULL");
        // SAFETY: a key owning its members.
        unsafe {
            let owned = &mut *key;
            if !owned.value.is_null() {
                xmlSecKeyDataDestroy(owned.value);
            }
            if !owned.name.is_null() {
                free(owned.name.cast());
            }
            if !owned.data_list.is_null() {
                xmlSecPtrListDestroy(owned.data_list);
            }
            key.write(XmlSecKey::EMPTY);
        }
    });
}

/// `xmlSecKeyDestroy`: releases a key from [`xmlSecKeyCreate`].
///
/// # Safety
/// `key` is null or a created key.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDestroy(key: *mut XmlSecKey) {
    contain((), || {
        check!(!key.is_null(), "xmlSecKeyDestroy", c"key != NULL");
        // SAFETY: a created key.
        unsafe {
            xmlSecKeyEmpty(key);
            free(key.cast());
        }
    });
}

/// `xmlSecKeyCopy`: empties `key_dst` and copies `key_src` into it, its
/// value and data duplicated.
///
/// # Safety
/// `key_dst` and `key_src` are null or keys.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyCopy(
    key_dst: *mut XmlSecKey,
    key_src: *mut XmlSecKey,
) -> c_int {
    contain(-1, || {
        check!(!key_dst.is_null(), "xmlSecKeyCopy", c"keyDst != NULL", -1);
        check!(!key_src.is_null(), "xmlSecKeyCopy", c"keySrc != NULL", -1);
        let here = here!("xmlSecKeyCopy");
        // A key copied onto itself is already the copy; emptying the
        // destination would destroy the source.
        if std::ptr::eq(key_dst, key_src) {
            return 0;
        }
        // SAFETY: keys owning their members.
        unsafe {
            xmlSecKeyEmpty(key_dst);
            let (dst, src) = (&mut *key_dst, &*key_src);
            if !src.name.is_null() && !replace(&mut dst.name, src.name, here) {
                return -1;
            }
            if !src.value.is_null() {
                dst.value = xmlSecKeyDataDuplicate(src.value);
                if dst.value.is_null() {
                    errors::internal(here, std::ptr::null(), c"xmlSecKeyDataDuplicate");
                    return -1;
                }
            }
            if !src.data_list.is_null() {
                dst.data_list = xmlSecPtrListDuplicate(src.data_list);
                if dst.data_list.is_null() {
                    errors::internal(here, std::ptr::null(), c"xmlSecPtrListDuplicate");
                    return -1;
                }
            }
            dst.usage = src.usage;
            dst.not_valid_before = src.not_valid_before;
            dst.not_valid_after = src.not_valid_after;
        }
        0
    })
}

/// `xmlSecKeySwap`: exchanges the contents of two keys.
///
/// # Safety
/// `key1` and `key2` are null or keys.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeySwap(key1: *mut XmlSecKey, key2: *mut XmlSecKey) -> c_int {
    contain(-1, || {
        check!(!key1.is_null(), "xmlSecKeySwap", c"key1 != NULL", -1);
        check!(!key2.is_null(), "xmlSecKeySwap", c"key2 != NULL", -1);
        // SAFETY: two keys; the same key twice swaps with itself.
        unsafe { std::ptr::swap(key1, key2) };
        0
    })
}

/// `xmlSecKeyDuplicate`: a new copy of `key`.
///
/// # Safety
/// `key` is null or a key.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDuplicate(key: *mut XmlSecKey) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        check!(
            !key.is_null(),
            "xmlSecKeyDuplicate",
            c"key != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecKeyDuplicate");
        // SAFETY: a key.
        unsafe {
            let copy = xmlSecKeyCreate();
            if copy.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyCreate");
                return copy;
            }
            if xmlSecKeyCopy(copy, key) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecKeyCopy");
                xmlSecKeyDestroy(copy);
                return std::ptr::null_mut();
            }
            copy
        }
    })
}

/// `xmlSecKeyMatch`: 1 when `key` has the name `name` (any for null) and
/// meets `key_req`, otherwise 0.
///
/// # Safety
/// `key` is null or a key; `name` null or NUL-terminated; `key_req` null or
/// initialized requirements.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyMatch(
    key: *mut XmlSecKey,
    name: *const u8,
    key_req: *mut XmlSecKeyReq,
) -> c_int {
    contain(-1, || {
        // SAFETY: null or a key.
        let valid = unsafe { key_valid(key) };
        check!(valid, "xmlSecKeyMatch", c"xmlSecKeyIsValid(key)", -1);
        check!(!key_req.is_null(), "xmlSecKeyMatch", c"keyReq != NULL", -1);
        // SAFETY: a valid key and requirements.
        unsafe {
            if !name.is_null() && xmlStrEqual((*key).name, name) == 0 {
                return 0;
            }
            xmlSecKeyReqMatchKey(key_req, key)
        }
    })
}

/// `xmlSecKeyGetType`: the type of the key's value, unknown without one.
///
/// # Safety
/// `key` is null or a key.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyGetType(key: *mut XmlSecKey) -> c_uint {
    contain(TYPE_UNKNOWN, || {
        check!(
            !key.is_null(),
            "xmlSecKeyGetType",
            c"key != NULL",
            TYPE_UNKNOWN
        );
        // SAFETY: a key.
        unsafe {
            let value = (*key).value;
            if value.is_null() {
                TYPE_UNKNOWN
            } else {
                xmlSecKeyDataGetType(value)
            }
        }
    })
}

/// `xmlSecKeyGetName`: the key's name.
///
/// # Safety
/// `key` is null or a key.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyGetName(key: *mut XmlSecKey) -> *const u8 {
    contain(std::ptr::null(), || {
        check!(
            !key.is_null(),
            "xmlSecKeyGetName",
            c"key != NULL",
            std::ptr::null()
        );
        // SAFETY: a key.
        unsafe { (*key).name }
    })
}

/// `xmlSecKeySetName`: replaces the key's name with a copy of `name`.
///
/// # Safety
/// `key` is null or a key; `name` null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeySetName(key: *mut XmlSecKey, name: *const u8) -> c_int {
    contain(-1, || {
        check!(!key.is_null(), "xmlSecKeySetName", c"key != NULL", -1);
        // SAFETY: a key.
        if unsafe { replace(&mut (*key).name, name, here!("xmlSecKeySetName")) } {
            0
        } else {
            -1
        }
    })
}

/// `xmlSecKeySetNameEx`: replaces the key's name with the first
/// `name_size` bytes of `name` (up to a NUL), or none for an empty name.
///
/// # Safety
/// `key` is null or a key; `name` null or holding `name_size` bytes or a
/// NUL before them.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeySetNameEx(
    key: *mut XmlSecKey,
    name: *const u8,
    name_size: usize,
) -> c_int {
    contain(-1, || {
        check!(!key.is_null(), "xmlSecKeySetNameEx", c"key != NULL", -1);
        let here = here!("xmlSecKeySetNameEx");
        // SAFETY: a key; `name` holds `name_size` bytes or a NUL before
        // them, so the scan reads no further than the first of the two.
        // libxml2's `xmlStrndup` stops at a NUL too. The copy is made before
        // the old name is released: `name` may point into it.
        unsafe {
            let owned = &mut *key;
            let copy = if name.is_null() || name_size == 0 {
                std::ptr::null_mut()
            } else {
                if c_int::try_from(name_size).is_err() {
                    errors::size_to_int_impossible(here, name_size);
                    return -1;
                }
                let end = (0..name_size)
                    .find(|&at| *name.add(at) == 0)
                    .unwrap_or(name_size);
                let bytes = std::slice::from_raw_parts(name, end);
                let copy = duplicate(bytes);
                if copy.is_null() {
                    errors::strdup_failed(here, std::ptr::null(), bytes);
                    return -1;
                }
                copy
            };
            if !owned.name.is_null() {
                free(owned.name.cast());
            }
            owned.name = copy;
        }
        0
    })
}

/// `xmlSecKeyGetValue`: the key's value.
///
/// # Safety
/// `key` is null or a key.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyGetValue(key: *mut XmlSecKey) -> *mut XmlSecKeyData {
    contain(std::ptr::null_mut(), || {
        check!(
            !key.is_null(),
            "xmlSecKeyGetValue",
            c"key != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: a key.
        unsafe { (*key).value }
    })
}

/// `xmlSecKeySetValue`: makes `value` the key's value, releasing the old
/// one; the key adopts `value`.
///
/// # Safety
/// `key` is null or a key; `value` null or key data the key may own.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeySetValue(
    key: *mut XmlSecKey,
    value: *mut XmlSecKeyData,
) -> c_int {
    contain(-1, || {
        check!(!key.is_null(), "xmlSecKeySetValue", c"key != NULL", -1);
        // SAFETY: a key owning its value.
        unsafe {
            let owned = &mut *key;
            // The value set again stays; destroying it would leave the key
            // holding freed data.
            if std::ptr::eq(owned.value, value) {
                return 0;
            }
            if !owned.value.is_null() {
                xmlSecKeyDataDestroy(owned.value);
            }
            owned.value = value;
        }
        0
    })
}

/// `xmlSecKeyGetSize`: the size of the key's value in bits, 0 without one.
///
/// # Safety
/// `key` is null or a key.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyGetSize(key: *mut XmlSecKey) -> usize {
    contain(0, || {
        check!(!key.is_null(), "xmlSecKeyGetSize", c"key != NULL", 0);
        // SAFETY: a key.
        unsafe {
            let value = (*key).value;
            if value.is_null() {
                0
            } else {
                xmlSecKeyDataGetSize(value)
            }
        }
    })
}

/// The data of klass `data_id` in the key's list, or null.
///
/// # Safety
/// `key` is a key.
unsafe fn find_data(key: *mut XmlSecKey, data_id: *const XmlSecKeyDataKlass) -> Option<usize> {
    // SAFETY: by the caller's contract; the list holds key data.
    unsafe {
        let list = (*key).data_list;
        if list.is_null() {
            return None;
        }
        (0..xmlSecPtrListGetSize(list)).find(|&pos| {
            xmlSecPtrListGetItem(list, pos)
                .cast::<XmlSecKeyData>()
                .as_ref()
                .is_some_and(|data| std::ptr::eq(data.id, data_id))
        })
    }
}

/// `xmlSecKeyGetData`: the key's value for the value klass, otherwise the
/// key data of klass `data_id` in its list, or null.
///
/// # Safety
/// `key` is null or a key; `data_id` null or a klass.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyGetData(
    key: *mut XmlSecKey,
    data_id: *const XmlSecKeyDataKlass,
) -> *mut XmlSecKeyData {
    contain(std::ptr::null_mut(), || {
        check!(
            !key.is_null(),
            "xmlSecKeyGetData",
            c"key != NULL",
            std::ptr::null_mut()
        );
        check!(
            !data_id.is_null(),
            "xmlSecKeyGetData",
            c"dataId != xmlSecKeyDataIdUnknown",
            std::ptr::null_mut()
        );
        // SAFETY: a key.
        unsafe {
            if std::ptr::eq(data_id, xmlSecKeyDataValueGetKlass()) {
                return (*key).value;
            }
            find_data(key, data_id).map_or(std::ptr::null_mut(), |pos| {
                xmlSecPtrListGetItem((*key).data_list, pos).cast()
            })
        }
    })
}

/// `xmlSecKeyEnsureData`: the key data of klass `data_id`, created and
/// adopted when the key has none.
///
/// # Safety
/// `key` is null or a key; `data_id` null or a klass.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyEnsureData(
    key: *mut XmlSecKey,
    data_id: *const XmlSecKeyDataKlass,
) -> *mut XmlSecKeyData {
    contain(std::ptr::null_mut(), || {
        check!(
            !key.is_null(),
            "xmlSecKeyEnsureData",
            c"key != NULL",
            std::ptr::null_mut()
        );
        check!(
            !data_id.is_null(),
            "xmlSecKeyEnsureData",
            c"dataId != xmlSecKeyDataIdUnknown",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecKeyEnsureData");
        // SAFETY: a key and a klass.
        unsafe {
            let found = xmlSecKeyGetData(key, data_id);
            if !found.is_null() {
                return found;
            }
            let detail = format!("dataId={}", text(klass_name(data_id)));
            let data = xmlSecKeyDataCreate(data_id);
            if data.is_null() {
                errors::internal_with(here, std::ptr::null(), c"xmlSecKeyDataCreate", &detail);
                return data;
            }
            if xmlSecKeyAdoptData(key, data) < 0 {
                errors::internal_with(here, std::ptr::null(), c"xmlSecKeyAdoptData", &detail);
                xmlSecKeyDataDestroy(data);
                return std::ptr::null_mut();
            }
            data
        }
    })
}

/// `xmlSecKeyAdoptData`: makes `data` the key's value when it is of the
/// value klass, otherwise puts it in the key's list in place of the data of
/// its klass; the key owns `data` on success.
///
/// # Safety
/// `key` is null or a key; `data` null or key data the key may own.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyAdoptData(
    key: *mut XmlSecKey,
    data: *mut XmlSecKeyData,
) -> c_int {
    contain(-1, || {
        check!(!key.is_null(), "xmlSecKeyAdoptData", c"key != NULL", -1);
        // SAFETY: null or key data.
        let valid = unsafe { super::keysdata::data_valid(data) };
        check!(
            valid,
            "xmlSecKeyAdoptData",
            c"xmlSecKeyDataIsValid(data)",
            -1
        );
        // SAFETY: a key and valid key data.
        unsafe {
            // Data the key already owns stays where it is: adopting it again
            // would make two owners of one allocation or destroy it in place.
            if std::ptr::eq((*key).value, data)
                || find_data(key, (*data).id).is_some_and(|pos| {
                    std::ptr::eq(xmlSecPtrListGetItem((*key).data_list, pos), data.cast())
                })
            {
                return 0;
            }
            if std::ptr::eq((*data).id, xmlSecKeyDataValueGetKlass()) {
                let owned = &mut *key;
                if !owned.value.is_null() {
                    xmlSecKeyDataDestroy(owned.value);
                }
                owned.value = data;
                return 0;
            }
            if (*key).data_list.is_null() {
                (*key).data_list = xmlSecPtrListCreate(xmlSecKeyDataListGetKlass());
                if (*key).data_list.is_null() {
                    errors::internal(
                        here!("xmlSecKeyAdoptData"),
                        std::ptr::null(),
                        c"xmlSecPtrListCreate",
                    );
                    return -1;
                }
            }
            match find_data(key, (*data).id) {
                Some(pos) => xmlSecPtrListSet((*key).data_list, data.cast(), pos),
                None => xmlSecPtrListAdd((*key).data_list, data.cast()),
            }
        }
    })
}

/// The kind of a key's value as the dumps name it.
///
/// # Safety
/// `key` is a key.
unsafe fn kind(key: *mut XmlSecKey) -> &'static str {
    // SAFETY: by the caller's contract.
    let key_type = unsafe { xmlSecKeyGetType(key) };
    if key_type & TYPE_SYMMETRIC != 0 {
        "Symmetric"
    } else if key_type & TYPE_PRIVATE != 0 {
        "Private"
    } else if key_type & TYPE_PUBLIC != 0 {
        "Public"
    } else {
        "Unknown"
    }
}

/// `xmlSecKeyDebugDump`: prints the key, its value and data.
///
/// # Safety
/// `key` is null or a key; `output` null or a live C stream.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDebugDump(key: *mut XmlSecKey, output: *mut c_void) {
    contain((), || {
        // SAFETY: null or a key.
        let valid = unsafe { key_valid(key) };
        check!(valid, "xmlSecKeyDebugDump", c"xmlSecKeyIsValid(key)");
        check!(!output.is_null(), "xmlSecKeyDebugDump", c"output != NULL");
        // SAFETY: a valid key and a live stream.
        unsafe {
            let owned = &*key;
            let out = format!(
                "== KEY\n=== method: {}\n=== key type: {}\n",
                text(
                    (*owned.value.cast_const())
                        .id
                        .as_ref()
                        .map_or(std::ptr::null(), |klass| klass.data_node_name)
                ),
                kind(key)
            );
            write_stream(output, &out);
            if !owned.name.is_null() {
                write_stream(output, &format!("=== key name: {}\n", text(owned.name)));
            }
            write_stream(output, &format!("=== key usage: {}\n", owned.usage));
            if owned.not_valid_before < owned.not_valid_after {
                write_stream(
                    output,
                    &format!(
                        "=== key not valid before: {}\n=== key not valid after: {}\n",
                        owned.not_valid_before, owned.not_valid_after
                    ),
                );
            }
            xmlSecKeyDataDebugDump(owned.value, output);
            if !owned.data_list.is_null() {
                xmlSecPtrListDebugDump(owned.data_list, output);
            }
        }
    });
}

/// `xmlSecKeyDebugXmlDump`: prints the key, its value and data as XML.
///
/// # Safety
/// As for [`xmlSecKeyDebugDump`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDebugXmlDump(key: *mut XmlSecKey, output: *mut c_void) {
    contain((), || {
        // SAFETY: null or a key.
        let valid = unsafe { key_valid(key) };
        check!(valid, "xmlSecKeyDebugXmlDump", c"xmlSecKeyIsValid(key)");
        check!(
            !output.is_null(),
            "xmlSecKeyDebugXmlDump",
            c"output != NULL"
        );
        // SAFETY: a valid key and a live stream.
        unsafe {
            let owned = &*key;
            write_stream(output, "<KeyInfo>\n<KeyMethod>");
            xmlSecPrintXmlString(
                output,
                (*owned.value)
                    .id
                    .as_ref()
                    .map_or(std::ptr::null(), |klass| klass.data_node_name),
            );
            write_stream(
                output,
                &format!(
                    "</KeyMethod>\n<KeyType>{}\n</KeyType>\n<KeyName>",
                    kind(key)
                ),
            );
            xmlSecPrintXmlString(output, owned.name);
            write_stream(output, "</KeyName>\n");
            if owned.not_valid_before < owned.not_valid_after {
                write_stream(
                    output,
                    &format!(
                        "<KeyValidity notValidBefore=\"{}\" notValidAfter=\"{}\"/>\n",
                        owned.not_valid_before, owned.not_valid_after
                    ),
                );
            }
            xmlSecKeyDataDebugXmlDump(owned.value, output);
            if !owned.data_list.is_null() {
                xmlSecPtrListDebugXmlDump(owned.data_list, output);
            }
            write_stream(output, "</KeyInfo>\n");
        }
    });
}

/// `xmlSecKeyGenerate`: a new key whose value of klass `data_id` the
/// klass generates at `size_bits` of `key_type`.
///
/// # Safety
/// `data_id` is null or a klass.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyGenerate(
    data_id: *const XmlSecKeyDataKlass,
    size_bits: usize,
    key_type: c_uint,
) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        check!(
            !data_id.is_null(),
            "xmlSecKeyGenerate",
            c"dataId != xmlSecKeyDataIdUnknown",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecKeyGenerate");
        // SAFETY: a klass; the data is released on every failure.
        unsafe {
            let name = klass_name(data_id).cast();
            let data = xmlSecKeyDataCreate(data_id);
            if data.is_null() {
                errors::internal(here, name, c"xmlSecKeyDataCreate");
                return std::ptr::null_mut();
            }
            if xmlSecKeyDataGenerate(data, size_bits, key_type) < 0 {
                errors::internal_with(
                    here,
                    name,
                    c"xmlSecKeyDataGenerate",
                    &format!("size={size_bits};type={key_type}"),
                );
                xmlSecKeyDataDestroy(data);
                return std::ptr::null_mut();
            }
            let key = xmlSecKeyCreate();
            if key.is_null() {
                errors::internal(here, name, c"xmlSecKeyCreate");
                xmlSecKeyDataDestroy(data);
                return key;
            }
            (*key).value = data;
            key
        }
    })
}

/// `xmlSecKeyGenerateByName`: [`xmlSecKeyGenerate`] for the registered
/// klass named `name`.
///
/// # Safety
/// `name` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyGenerateByName(
    name: *const u8,
    size_bits: usize,
    key_type: c_uint,
) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        check!(
            !name.is_null(),
            "xmlSecKeyGenerateByName",
            c"name != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `name` is NUL-terminated; the registry has a fixed
        // address.
        unsafe {
            let data_id =
                xmlSecKeyDataIdListFindByName(xmlSecKeyDataIdsGet(), name, DATA_USAGE_ANY);
            if data_id.is_null() {
                errors::other(
                    here!("xmlSecKeyGenerateByName"),
                    R_KEY_DATA_NOT_FOUND,
                    name.cast(),
                    None,
                );
                return std::ptr::null_mut();
            }
            xmlSecKeyGenerate(data_id, size_bits, key_type)
        }
    })
}

/// `xmlSecKeyReadBuffer`: a new key whose value the klass `data_id` reads
/// from the binary contents of `buffer`, with any key type accepted.
///
/// # Safety
/// `data_id` is null or a klass; `buffer` null or a buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyReadBuffer(
    data_id: *const XmlSecKeyDataKlass,
    buffer: *mut super::buffer::XmlSecBuffer,
) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        check!(
            !data_id.is_null(),
            "xmlSecKeyReadBuffer",
            c"dataId != xmlSecKeyDataIdUnknown",
            std::ptr::null_mut()
        );
        check!(
            !buffer.is_null(),
            "xmlSecKeyReadBuffer",
            c"buffer != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecKeyReadBuffer");
        // SAFETY: a klass and a buffer; the key and context are released on
        // every failure.
        unsafe {
            let name = klass_name(data_id).cast();
            let key = xmlSecKeyCreate();
            if key.is_null() {
                errors::internal(here, name, c"xmlSecKeyCreate");
                return key;
            }
            let mut ctx = std::mem::MaybeUninit::<super::keyinfo::XmlSecKeyInfoCtx>::uninit();
            let ctx = ctx.as_mut_ptr();
            if super::keyinfo::xmlSecKeyInfoCtxInitialize(ctx, std::ptr::null_mut()) < 0 {
                errors::internal(here, name, c"xmlSecKeyInfoCtxInitialize");
                xmlSecKeyDestroy(key);
                return std::ptr::null_mut();
            }
            // xmlSecKeyDataTypeAny.
            (*ctx).key_req.key_type = 0xFFFF;
            let read = super::keysdata::xmlSecKeyDataBinRead(
                data_id,
                key.cast(),
                super::buffer::xmlSecBufferGetData(buffer),
                super::buffer::xmlSecBufferGetSize(buffer),
                ctx.cast(),
            );
            super::keyinfo::xmlSecKeyInfoCtxFinalize(ctx);
            if read < 0 {
                errors::internal(here, name, c"xmlSecKeyDataBinRead");
                xmlSecKeyDestroy(key);
                return std::ptr::null_mut();
            }
            key
        }
    })
}

/// `xmlSecKeyReadMemory`: [`xmlSecKeyReadBuffer`] of `data_size` bytes of
/// `data`.
///
/// # Safety
/// `data_id` is null or a klass; `data` null or holding `data_size` bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyReadMemory(
    data_id: *const XmlSecKeyDataKlass,
    data: *const u8,
    data_size: usize,
) -> *mut XmlSecKey {
    contain(std::ptr::null_mut(), || {
        check!(
            !data_id.is_null(),
            "xmlSecKeyReadMemory",
            c"dataId != xmlSecKeyDataIdUnknown",
            std::ptr::null_mut()
        );
        check!(
            !data.is_null(),
            "xmlSecKeyReadMemory",
            c"data != NULL",
            std::ptr::null_mut()
        );
        check!(
            data_size > 0,
            "xmlSecKeyReadMemory",
            c"dataSize > 0",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecKeyReadMemory");
        // SAFETY: a klass and `data_size` bytes; the buffer is finalized on
        // every path.
        unsafe {
            let name = klass_name(data_id).cast();
            let mut buffer = std::mem::MaybeUninit::<super::buffer::XmlSecBuffer>::uninit();
            let buffer = buffer.as_mut_ptr();
            if super::buffer::xmlSecBufferInitialize(buffer, 0) < 0 {
                errors::internal(here, name, c"xmlSecBufferInitialize");
                return std::ptr::null_mut();
            }
            if super::buffer::xmlSecBufferAppend(buffer, data, data_size) < 0 {
                errors::internal(here, name, c"xmlSecBufferAppend");
                super::buffer::xmlSecBufferFinalize(buffer);
                return std::ptr::null_mut();
            }
            let key = xmlSecKeyReadBuffer(data_id, buffer);
            if key.is_null() {
                errors::internal(here, name, c"xmlSecKeyReadBuffer");
            }
            super::buffer::xmlSecBufferFinalize(buffer);
            key
        }
    })
}

unsafe extern "C" fn key_duplicate(item: *mut c_void) -> *mut c_void {
    // SAFETY: the list holds keys.
    unsafe { xmlSecKeyDuplicate(item.cast()).cast() }
}

unsafe extern "C" fn key_destroy(item: *mut c_void) {
    // SAFETY: as above.
    unsafe { xmlSecKeyDestroy(item.cast()) }
}

unsafe extern "C" fn key_dump(item: *mut c_void, output: *mut c_void) {
    // SAFETY: as above.
    unsafe { xmlSecKeyDebugDump(item.cast(), output) }
}

unsafe extern "C" fn key_xml_dump(item: *mut c_void, output: *mut c_void) {
    // SAFETY: as above.
    unsafe { xmlSecKeyDebugXmlDump(item.cast(), output) }
}

static KEY_LIST: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"keys-list".as_ptr().cast(),
    duplicate_item: Some(key_duplicate),
    destroy_item: Some(key_destroy),
    debug_dump_item: Some(key_dump),
    debug_xml_dump_item: Some(key_xml_dump),
};

/// `xmlSecKeyPtrListGetKlass`: the klass of a list of keys.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn xmlSecKeyPtrListGetKlass() -> *const XmlSecPtrListKlass {
    &raw const KEY_LIST
}

#[cfg(test)]
mod tests;
