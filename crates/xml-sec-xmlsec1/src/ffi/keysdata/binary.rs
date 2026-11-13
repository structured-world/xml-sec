//! The binary key-data value of `xmlsec/keysdata.h`: a key-data object that
//! holds its key as a byte buffer, and the klass methods libxmlsec1's
//! symmetric klasses are made of.
//!
//! Only the size, buffer and setter are exported, as `keysdata.h` declares
//! them. libxmlsec1 also exports the methods, from a header it does not
//! install, for its crypto libraries alone; a crypto library of libxmlsec1's
//! would parse keys and verify certificates itself, outside the core's trust
//! transition, so the methods stay internal to this library's own klasses.

use std::ffi::{c_char, c_int, c_void};

use super::{
    XmlSecKeyData, XmlSecKeyDataBinary, XmlSecKeyDataKlass, check_id, data_valid, name_of, valid,
    xmlSecKeyDataCreate, xmlSecKeyDataDestroy, xmlSecKeyDataGetSize,
};
use crate::ffi::base64::{xmlSecBase64DecodeInPlace, xmlSecBase64Encode};
use crate::ffi::buffer::{
    XmlSecBuffer, xmlSecBufferFinalize, xmlSecBufferGetData, xmlSecBufferGetSize,
    xmlSecBufferInitialize, xmlSecBufferSetData, xmlSecMemEqual,
};
use crate::ffi::errors::{self, Here, check, here};
use crate::ffi::keyinfo::XmlSecKeyInfoCtx;
use crate::ffi::keys::{
    TYPE_SYMMETRIC, XmlSecKey, XmlSecKeyReq, xmlSecKeyGetValue, xmlSecKeyReqMatchKeyValue,
    xmlSecKeySetValue,
};
use crate::ffi::transforms::klass_text;
use crate::ffi::tree::{XmlNode, c_text, nodes};
use crate::ffi::xmltree::xmlSecGetNodeContentAndTrim;
use crate::ffi::{contain, free, malloc, write_stream};

/// The klass of the binary key-data object `$data`, after libxmlsec1's
/// assertions inside the entry point `$func`, or `$ret`.
macro_rules! binary_klass_or {
    ($data:expr, $func:literal $(, $ret:expr)?) => {{
        let klass = key_data_or!($data, $func $(, $ret)?);
        check!(
            klass.obj_size >= size_of::<XmlSecKeyDataBinary>(),
            $func,
            c"xmlSecKeyDataCheckSize(data, xmlSecKeyDataBinarySize)"
            $(, $ret)?
        );
        klass
    }};
}

/// The value buffer of the binary key-data object `$data`, after
/// libxmlsec1's assertions inside the entry point `$func`, or `$ret`.
macro_rules! binary_buffer_or {
    ($data:expr, $func:literal $(, $ret:expr)?) => {{
        binary_klass_or!($data, $func $(, $ret)?);
        // SAFETY: a valid object at least the binary layout's size starts
        // with that layout.
        unsafe { &raw mut (*$data.cast::<XmlSecKeyDataBinary>()).buffer }
    }};
}

/// The name of klass `id` for a report, null for no klass.
///
/// # Safety
/// `id` is null or a klass.
unsafe fn klass_name(id: *const XmlSecKeyDataKlass) -> *const c_char {
    // SAFETY: by the caller's contract.
    unsafe { id.as_ref() }.map_or(std::ptr::null(), name_of)
}

/// The name of the klass of `data` for a report (`xmlSecKeyDataGetName`).
///
/// # Safety
/// `data` is a key-data object.
unsafe fn data_name(data: *mut XmlSecKeyData) -> *const c_char {
    // SAFETY: by the caller's contract.
    unsafe { klass_name((*data).id) }
}

/// `xmlSecKeyDataBinaryValueInitialize`: an empty value buffer.
///
/// # Safety
/// `data` is null or a key-data object.
pub(crate) unsafe extern "C" fn value_initialize(data: *mut XmlSecKeyData) -> c_int {
    contain(-1, || {
        let buffer = binary_buffer_or!(data, "xmlSecKeyDataBinaryValueInitialize", -1);
        // SAFETY: the object's value buffer.
        if unsafe { xmlSecBufferInitialize(buffer, 0) } < 0 {
            // SAFETY: a valid object.
            let object = unsafe { data_name(data) };
            errors::internal(
                here!("xmlSecKeyDataBinaryValueInitialize"),
                object,
                c"xmlSecBufferInitialize",
            );
            return -1;
        }
        0
    })
}

/// `xmlSecKeyDataBinaryValueDuplicate`: copies the value of `src` into
/// `dst`.
///
/// # Safety
/// `dst` and `src` are null or key-data objects.
pub(crate) unsafe extern "C" fn value_duplicate(
    dst: *mut XmlSecKeyData,
    src: *mut XmlSecKeyData,
) -> c_int {
    contain(-1, || {
        binary_klass_or!(dst, "xmlSecKeyDataBinaryValueDuplicate", -1);
        let buffer = binary_buffer_or!(src, "xmlSecKeyDataBinaryValueDuplicate", -1);
        // SAFETY: both are binary key data.
        unsafe {
            if xmlSecKeyDataBinaryValueSetBuffer(
                dst,
                xmlSecBufferGetData(buffer),
                xmlSecBufferGetSize(buffer),
            ) < 0
            {
                errors::internal(
                    here!("xmlSecKeyDataBinaryValueDuplicate"),
                    data_name(dst),
                    c"xmlSecKeyDataBinaryValueSetBuffer",
                );
                return -1;
            }
        }
        0
    })
}

/// `xmlSecKeyDataBinaryValueFinalize`: releases the value buffer.
///
/// # Safety
/// `data` is null or a key-data object.
pub(crate) unsafe extern "C" fn value_finalize(data: *mut XmlSecKeyData) {
    contain((), || {
        let buffer = binary_buffer_or!(data, "xmlSecKeyDataBinaryValueFinalize");
        // SAFETY: the object's value buffer.
        unsafe { xmlSecBufferFinalize(buffer) };
    });
}

/// libxmlsec1's assertions on the klass and key of a binary value's read or
/// write method inside the entry point `$func`.
macro_rules! method_arguments {
    ($func:literal, $id:expr, $key:expr) => {
        check!(!$id.is_null(), $func, c"id != xmlSecKeyDataIdUnknown", -1);
        check!(!$key.is_null(), $func, c"key != NULL", -1);
    };
}

/// Makes `size` bytes at `bytes` the value of `key` as a new object of
/// klass `id`, as libxmlsec1's binary readers do: an existing value of the
/// same klass must hold exactly these bytes, any other value refuses them,
/// and the new value must satisfy `key_req`.
///
/// # Safety
/// `id` is a klass with the binary layout; `key` is a key; `bytes` holds
/// `size` bytes; `key_req` is initialized requirements.
unsafe fn adopt_value(
    here: Here,
    id: *const XmlSecKeyDataKlass,
    key: *mut XmlSecKey,
    bytes: *const u8,
    size: usize,
    key_req: *mut XmlSecKeyReq,
) -> c_int {
    // SAFETY: by the caller's contract.
    unsafe {
        let object = klass_name(id);
        let existing = xmlSecKeyGetValue(key);
        if !existing.is_null() {
            let existing_name = data_name(existing);
            // libxmlsec1's formatted `xmlSecOtherError2/3` print the text
            // alone, without the `details=` of `xmlSecOtherError`.
            if !check_id(existing, id) {
                errors::report(
                    here,
                    existing_name,
                    std::ptr::null(),
                    errors::R_KEY_DATA_ALREADY_EXIST,
                    &format!("id={}", klass_text(object.cast())),
                );
                return -1;
            }
            let buffer = xmlSecKeyDataBinaryValueGetBuffer(existing);
            if !buffer.is_null() {
                let current = xmlSecBufferGetSize(buffer);
                if current != size {
                    errors::report(
                        here,
                        existing_name,
                        std::ptr::null(),
                        errors::R_KEY_DATA_ALREADY_EXIST,
                        &format!("cur-data-size={current}; new-data-size={size}"),
                    );
                    return -1;
                }
                let equal = xmlSecMemEqual(xmlSecBufferGetData(buffer), bytes, size);
                if equal < 0 {
                    errors::internal(here, existing_name, c"xmlSecMemEqual");
                    return -1;
                }
                if equal == 0 {
                    errors::other(
                        here,
                        errors::R_KEY_DATA_ALREADY_EXIST,
                        existing_name,
                        Some("key already has a different value"),
                    );
                    return -1;
                }
                return 0;
            }
        }
        let data = xmlSecKeyDataCreate(id);
        if data.is_null() {
            errors::internal(here, object, c"xmlSecKeyDataCreate");
            return -1;
        }
        let failed = if xmlSecKeyDataBinaryValueSetBuffer(data, bytes, size) < 0 {
            errors::internal_with(
                here,
                object,
                c"xmlSecKeyDataBinaryValueSetBuffer",
                &format!("size={size}"),
            );
            true
        } else if xmlSecKeyReqMatchKeyValue(key_req, data) != 1 {
            errors::internal(here, object, c"xmlSecKeyReqMatchKeyValue");
            true
        } else if xmlSecKeySetValue(key, data) < 0 {
            errors::internal(here, object, c"xmlSecKeySetValue");
            true
        } else {
            false
        };
        if failed {
            xmlSecKeyDataDestroy(data);
            return -1;
        }
        0
    }
}

/// `xmlSecKeyDataBinaryValueXmlRead`: the Base64 content of `node` as the
/// value of `key`.
///
/// # Safety
/// `id` is null or a klass with the binary layout; `key` is null or a key;
/// `node` is null or a live node; `ctx` is null or a `KeyInfo` context.
pub(crate) unsafe extern "C" fn value_xml_read(
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
        method_arguments!("xmlSecKeyDataBinaryValueXmlRead", id, key);
        check!(
            !node.is_null(),
            "xmlSecKeyDataBinaryValueXmlRead",
            c"node != NULL",
            -1
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeyDataBinaryValueXmlRead",
            c"keyInfoCtx != NULL",
            -1
        );
        let here = here!("xmlSecKeyDataBinaryValueXmlRead");
        // SAFETY: a klass, a key, a live node and a context; the content is
        // decoded in place and freed here.
        unsafe {
            let object = klass_name(id);
            let text = xmlSecGetNodeContentAndTrim(node);
            if text.is_null() {
                errors::invalid_node_content(here, node, object, "empty");
                return -1;
            }
            // The text and the bytes decoded over it are the secret: the
            // whole string is wiped before the allocation is released.
            let length = std::ffi::CStr::from_ptr(text.cast()).count_bytes();
            let mut size = 0;
            let result = if xmlSecBase64DecodeInPlace(text, &raw mut size) < 0 {
                errors::internal(here, object, c"xmlSecBase64Decode_ex");
                -1
            } else {
                adopt_value(here, id, key, text, size, &raw mut (*ctx).key_req)
            };
            zeroize::Zeroize::zeroize(std::slice::from_raw_parts_mut(text, length));
            free(text.cast());
            result
        }
    })
}

/// `xmlSecKeyDataBinaryValueXmlWrite`: the value of `key` as the Base64
/// content of `node`, when the context asks for a symmetric key.
///
/// # Safety
/// As for [`value_xml_read`]; the key's value is binary
/// key data.
pub(crate) unsafe extern "C" fn value_xml_write(
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
        method_arguments!("xmlSecKeyDataBinaryValueXmlWrite", id, key);
        check!(
            !node.is_null(),
            "xmlSecKeyDataBinaryValueXmlWrite",
            c"node != NULL",
            -1
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeyDataBinaryValueXmlWrite",
            c"keyInfoCtx != NULL",
            -1
        );
        // SAFETY: a context.
        if unsafe { (*ctx).key_req.key_type } & TYPE_SYMMETRIC == 0 {
            return 0;
        }
        // SAFETY: a key.
        let value = unsafe { xmlSecKeyGetValue(key) };
        // SAFETY: null or the key's key data.
        let valid_value = unsafe { data_valid(value) };
        check!(
            valid_value,
            "xmlSecKeyDataBinaryValueXmlWrite",
            c"xmlSecKeyDataIsValid(value)",
            -1
        );
        // A writer called directly with another klass would write one key
        // type's bytes as another's.
        // SAFETY: valid key data and a klass.
        let own = unsafe { check_id(value, id) };
        check!(
            own,
            "xmlSecKeyDataBinaryValueXmlWrite",
            c"xmlSecKeyDataCheckId(value, id)",
            -1
        );
        // SAFETY: valid key data.
        let buffer = unsafe { xmlSecKeyDataBinaryValueGetBuffer(value) };
        check!(
            !buffer.is_null(),
            "xmlSecKeyDataBinaryValueXmlWrite",
            c"buffer != NULL",
            -1
        );
        // SAFETY: the value buffer, a context and a live node; the text is
        // freed here.
        unsafe {
            let text = xmlSecBase64Encode(
                xmlSecBufferGetData(buffer),
                xmlSecBufferGetSize(buffer),
                (*ctx).base64_line_size,
            );
            if text.is_null() {
                errors::internal(
                    here!("xmlSecKeyDataBinaryValueXmlWrite"),
                    klass_name(id),
                    c"xmlSecBase64Encode",
                );
                return -1;
            }
            // Base64 holds no markup. A refused edit fails the write rather
            // than passing for one with no key written.
            let set = c_text(text).is_some_and(|content| nodes::set_content(node, content).is_ok());
            // The text is the secret in Base64: it is wiped before it is
            // released, as the read path wipes what it decodes.
            let length = std::ffi::CStr::from_ptr(text.cast()).count_bytes();
            zeroize::Zeroize::zeroize(std::slice::from_raw_parts_mut(text, length));
            free(text.cast());
            if !set {
                errors::xml_failed(
                    here!("xmlSecKeyDataBinaryValueXmlWrite"),
                    klass_name(id),
                    c"xmlNodeSetContent",
                );
                return -1;
            }
        }
        0
    })
}

/// `xmlSecKeyDataBinaryValueBinRead`: `size` bytes as the value of `key`.
///
/// # Safety
/// `id` is null or a klass with the binary layout; `key` is null or a key;
/// `buf` holds `size` bytes; `ctx` is null or a `KeyInfo` context.
pub(crate) unsafe extern "C" fn value_bin_read(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    buf: *const u8,
    size: usize,
    ctx: *mut c_void,
) -> c_int {
    let (key, ctx) = (key.cast::<XmlSecKey>(), ctx.cast::<XmlSecKeyInfoCtx>());
    contain(-1, || {
        method_arguments!("xmlSecKeyDataBinaryValueBinRead", id, key);
        check!(
            !buf.is_null(),
            "xmlSecKeyDataBinaryValueBinRead",
            c"buf != NULL",
            -1
        );
        check!(
            size > 0,
            "xmlSecKeyDataBinaryValueBinRead",
            c"bufSize > 0",
            -1
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeyDataBinaryValueBinRead",
            c"keyInfoCtx != NULL",
            -1
        );
        // SAFETY: a klass, a key, the caller's bytes and a context.
        unsafe {
            adopt_value(
                here!("xmlSecKeyDataBinaryValueBinRead"),
                id,
                key,
                buf,
                size,
                &raw mut (*ctx).key_req,
            )
        }
    })
}

/// `xmlSecKeyDataBinaryValueBinWrite`: a copy of the value of `key` in
/// libxml2's memory, when the context asks for a symmetric key.
///
/// # Safety
/// `id` is null or a klass; `key` is null or a key whose value is binary
/// key data; `buf` and `size` are null or writable; `ctx` is null or a
/// `KeyInfo` context.
pub(crate) unsafe extern "C" fn value_bin_write(
    id: *const XmlSecKeyDataKlass,
    key: *mut c_void,
    buf: *mut *mut u8,
    size: *mut usize,
    ctx: *mut c_void,
) -> c_int {
    let (key, ctx) = (key.cast::<XmlSecKey>(), ctx.cast::<XmlSecKeyInfoCtx>());
    contain(-1, || {
        method_arguments!("xmlSecKeyDataBinaryValueBinWrite", id, key);
        check!(
            !buf.is_null(),
            "xmlSecKeyDataBinaryValueBinWrite",
            c"buf != NULL",
            -1
        );
        check!(
            !size.is_null(),
            "xmlSecKeyDataBinaryValueBinWrite",
            c"bufSize != NULL",
            -1
        );
        check!(
            !ctx.is_null(),
            "xmlSecKeyDataBinaryValueBinWrite",
            c"keyInfoCtx != NULL",
            -1
        );
        // SAFETY: a context.
        if unsafe { (*ctx).key_req.key_type } & TYPE_SYMMETRIC == 0 {
            return 0;
        }
        // SAFETY: a key.
        let value = unsafe { xmlSecKeyGetValue(key) };
        // SAFETY: null or the key's key data.
        let valid_value = unsafe { data_valid(value) };
        check!(
            valid_value,
            "xmlSecKeyDataBinaryValueBinWrite",
            c"xmlSecKeyDataIsValid(value)",
            -1
        );
        // As for the XML writer: only the value's own klass exports it.
        // SAFETY: valid key data and a klass.
        let own = unsafe { check_id(value, id) };
        check!(
            own,
            "xmlSecKeyDataBinaryValueBinWrite",
            c"xmlSecKeyDataCheckId(value, id)",
            -1
        );
        // SAFETY: valid key data.
        let buffer = unsafe { xmlSecKeyDataBinaryValueGetBuffer(value) };
        check!(
            !buffer.is_null(),
            "xmlSecKeyDataBinaryValueBinWrite",
            c"buffer != NULL",
            -1
        );
        // SAFETY: the value buffer holds `length` bytes; the copy is the
        // caller's, in libxml2's memory.
        unsafe {
            let length = xmlSecBufferGetSize(buffer);
            *size = length;
            let copy = malloc(length).cast::<u8>();
            *buf = copy;
            if copy.is_null() {
                errors::malloc_failed(
                    here!("xmlSecKeyDataBinaryValueBinWrite"),
                    klass_name(id),
                    length,
                );
                return -1;
            }
            // An empty value may have no data pointer, which a copy, even of
            // nothing, must not read.
            if length > 0 {
                copy.copy_from_nonoverlapping(xmlSecBufferGetData(buffer), length);
            }
        }
        0
    })
}

/// The element name of the binary value `$data` for a debug dump to
/// `$output`, after libxmlsec1's assertions inside the entry point `$func`.
/// Only the name and size are printed: the key bytes are secret.
macro_rules! dump_name_or {
    ($data:expr, $output:expr, $func:literal) => {{
        let node = binary_klass_or!($data, $func).data_node_name;
        check!(!node.is_null(), $func, c"data->id->dataNodeName != NULL");
        check!(!$output.is_null(), $func, c"output != NULL");
        // SAFETY: the klass's NUL-terminated element name.
        unsafe { klass_text(node) }
    }};
}

/// `xmlSecKeyDataBinaryValueDebugDump`: the element name and size.
///
/// # Safety
/// `data` is null or a key-data object; `output` is null or a C stream.
pub(crate) unsafe extern "C" fn value_debug_dump(data: *mut XmlSecKeyData, output: *mut c_void) {
    contain((), || {
        let name = dump_name_or!(data, output, "xmlSecKeyDataBinaryValueDebugDump");
        // SAFETY: a valid object and a C stream.
        unsafe {
            let size = xmlSecKeyDataGetSize(data);
            write_stream(output, &format!("=== {name}: size={size}\n"));
        }
    });
}

/// `xmlSecKeyDataBinaryValueDebugXmlDump`: the element name and size as an
/// XML element.
///
/// # Safety
/// `data` is null or a key-data object; `output` is null or a C stream.
pub(crate) unsafe extern "C" fn value_debug_xml_dump(
    data: *mut XmlSecKeyData,
    output: *mut c_void,
) {
    contain((), || {
        let name = dump_name_or!(data, output, "xmlSecKeyDataBinaryValueDebugXmlDump");
        // SAFETY: a valid object and a C stream.
        unsafe {
            let size = xmlSecKeyDataGetSize(data);
            write_stream(output, &format!("<{name} size=\"{size}\" />\n"));
        }
    });
}

/// `xmlSecKeyDataBinaryValueGetSize`: the value's size in bits.
///
/// # Safety
/// `data` is null or a key-data object.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecKeyDataBinaryValueGetSize(data: *mut XmlSecKeyData) -> usize {
    contain(0, || {
        let buffer = binary_buffer_or!(data, "xmlSecKeyDataBinaryValueGetSize", 0);
        // libxmlsec1 computes `8 * size` in `xmlSecSize`, which wraps for a
        // value of more than `SIZE_MAX / 8` bytes; the same number here.
        // SAFETY: the object's value buffer.
        unsafe { xmlSecBufferGetSize(buffer) }.wrapping_mul(8)
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
    contain(std::ptr::null_mut(), || {
        binary_buffer_or!(
            data,
            "xmlSecKeyDataBinaryValueGetBuffer",
            std::ptr::null_mut()
        )
    })
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
        let buffer = binary_buffer_or!(data, "xmlSecKeyDataBinaryValueSetBuffer", -1);
        check!(
            !buf.is_null(),
            "xmlSecKeyDataBinaryValueSetBuffer",
            c"buf != NULL",
            -1
        );
        check!(
            size > 0,
            "xmlSecKeyDataBinaryValueSetBuffer",
            c"bufSize > 0",
            -1
        );
        // SAFETY: the object's value buffer; `buf` holds `size` bytes.
        unsafe { xmlSecBufferSetData(buffer, buf, size) }
    })
}
