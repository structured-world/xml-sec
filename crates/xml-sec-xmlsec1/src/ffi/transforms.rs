//! `xmlsec/transforms.h`: transform objects, their klasses, the default
//! push/pop methods, chain connection and the registry of klasses.
//!
//! A transform is a C object of its klass's `objSize`: the public
//! `xmlSecTransform` followed by the klass's own context. Data moves through
//! a chain by libxmlsec1's push/pop protocol, and the default methods keep
//! its chunking, final-call and buffer semantics, so a klass written for
//! libxmlsec1 runs unchanged.

use std::ffi::{c_int, c_uint, c_void};

use xml_sec_libxml2::ffi::XmlNode;

use super::buffer::{
    XmlSecBuffer, xmlSecBufferAppend, xmlSecBufferFinalize, xmlSecBufferGetData,
    xmlSecBufferGetSize, xmlSecBufferInitialize, xmlSecBufferRemoveHead, xmlSecBufferSetMaxSize,
    xmlSecBufferSetSize,
};
use super::list::{
    XmlSecPtrList, XmlSecPtrListKlass, xmlSecPtrListAdd, xmlSecPtrListFinalize,
    xmlSecPtrListGetItem, xmlSecPtrListGetSize, xmlSecPtrListInitialize,
};
use super::nodeset::{XmlSecNodeSet, xmlSecNodeSetDestroy};
use super::tree::xmlStrEqual;
use super::{contain, free, malloc, write_stream};

pub(crate) mod builtin;
pub(crate) mod ctx;
pub(crate) mod io;
pub(crate) mod parser;
pub(crate) mod relationship;
pub(crate) mod xpath;

#[cfg(test)]
mod tests;

pub(crate) use ctx::XmlSecTransformCtx;

/// `xmlSecTransformStatusNone`.
pub(crate) const STATUS_NONE: c_int = 0;
/// `xmlSecTransformStatusWorking`.
pub(crate) const STATUS_WORKING: c_int = 1;
/// `xmlSecTransformStatusFinished`.
pub(crate) const STATUS_FINISHED: c_int = 2;

/// `xmlSecTransformModePush`.
pub(crate) const MODE_PUSH: c_int = 1;
/// `xmlSecTransformModePop`.
pub(crate) const MODE_POP: c_int = 2;

/// `xmlSecTransformOperationEncode`.
pub(crate) const OPERATION_ENCODE: c_int = 1;
/// `xmlSecTransformOperationDecode`.
pub(crate) const OPERATION_DECODE: c_int = 2;

/// `xmlSecTransformDataTypeUnknown`.
pub(crate) const DATA_UNKNOWN: u8 = 0;
/// `xmlSecTransformDataTypeBin`.
pub(crate) const DATA_BIN: u8 = 1;
/// `xmlSecTransformDataTypeXml`.
pub(crate) const DATA_XML: u8 = 2;

/// `xmlSecTransformUsageDSigTransform`.
pub(crate) const USAGE_DSIG_TRANSFORM: c_uint = 0x0001;
/// `xmlSecTransformUsageC14NMethod`.
pub(crate) const USAGE_C14N_METHOD: c_uint = 0x0002;

/// `XMLSEC_TRANSFORM_FLAGS_USER_SPECIFIED`.
pub(crate) const FLAGS_USER_SPECIFIED: usize = 0x0001;

/// `xmlSecKeyUsageAny`.
const KEY_USAGE_ANY: c_uint = 0xFFFF_FFFF;

/// `xmlSecKeyReq`, written by [`xmlSecTransformSetKeyReq`].
#[repr(C)]
pub(crate) struct XmlSecKeyReq {
    pub(crate) key_id: *const c_void,
    pub(crate) key_type: c_uint,
    pub(crate) key_usage: c_uint,
    pub(crate) key_bits_size: usize,
    pub(crate) key_use_with_list: XmlSecPtrList,
    pub(crate) reserved1: *mut c_void,
    pub(crate) reserved2: *mut c_void,
}

pub(crate) type InitializeMethod = Option<unsafe extern "C" fn(*mut XmlSecTransform) -> c_int>;
pub(crate) type FinalizeMethod = Option<unsafe extern "C" fn(*mut XmlSecTransform)>;
pub(crate) type NodeReadMethod = Option<
    unsafe extern "C" fn(*mut XmlSecTransform, *mut XmlNode, *mut XmlSecTransformCtx) -> c_int,
>;
pub(crate) type SetKeyReqMethod =
    Option<unsafe extern "C" fn(*mut XmlSecTransform, *mut XmlSecKeyReq) -> c_int>;
pub(crate) type SetKeyMethod =
    Option<unsafe extern "C" fn(*mut XmlSecTransform, *mut c_void) -> c_int>;
pub(crate) type VerifyMethod = Option<
    unsafe extern "C" fn(*mut XmlSecTransform, *const u8, usize, *mut XmlSecTransformCtx) -> c_int,
>;
pub(crate) type GetDataTypeMethod =
    Option<unsafe extern "C" fn(*mut XmlSecTransform, c_int, *mut XmlSecTransformCtx) -> u8>;
pub(crate) type PushBinMethod = Option<
    unsafe extern "C" fn(
        *mut XmlSecTransform,
        *const u8,
        usize,
        c_int,
        *mut XmlSecTransformCtx,
    ) -> c_int,
>;
pub(crate) type PopBinMethod = Option<
    unsafe extern "C" fn(
        *mut XmlSecTransform,
        *mut u8,
        usize,
        *mut usize,
        *mut XmlSecTransformCtx,
    ) -> c_int,
>;
pub(crate) type PushXmlMethod = Option<
    unsafe extern "C" fn(
        *mut XmlSecTransform,
        *mut XmlSecNodeSet,
        *mut XmlSecTransformCtx,
    ) -> c_int,
>;
pub(crate) type PopXmlMethod = Option<
    unsafe extern "C" fn(
        *mut XmlSecTransform,
        *mut *mut XmlSecNodeSet,
        *mut XmlSecTransformCtx,
    ) -> c_int,
>;
pub(crate) type ExecuteMethod =
    Option<unsafe extern "C" fn(*mut XmlSecTransform, c_int, *mut XmlSecTransformCtx) -> c_int>;

/// `xmlSecTransformKlass`.
#[repr(C)]
pub(crate) struct XmlSecTransformKlass {
    pub(crate) klass_size: usize,
    pub(crate) obj_size: usize,
    pub(crate) name: *const u8,
    pub(crate) href: *const u8,
    pub(crate) usage: c_uint,
    pub(crate) initialize: InitializeMethod,
    pub(crate) finalize: FinalizeMethod,
    pub(crate) read_node: NodeReadMethod,
    pub(crate) write_node: NodeReadMethod,
    pub(crate) set_key_req: SetKeyReqMethod,
    pub(crate) set_key: SetKeyMethod,
    pub(crate) verify: VerifyMethod,
    pub(crate) get_data_type: GetDataTypeMethod,
    pub(crate) push_bin: PushBinMethod,
    pub(crate) pop_bin: PopBinMethod,
    pub(crate) push_xml: PushXmlMethod,
    pub(crate) pop_xml: PopXmlMethod,
    pub(crate) execute: ExecuteMethod,
    pub(crate) reserved0: *mut c_void,
    pub(crate) reserved1: *mut c_void,
}

// SAFETY: a klass is immutable static data: strings with static storage and
// function pointers.
unsafe impl Sync for XmlSecTransformKlass {}

/// `xmlSecTransform`.
#[repr(C)]
pub(crate) struct XmlSecTransform {
    pub(crate) id: *const XmlSecTransformKlass,
    pub(crate) operation: c_int,
    pub(crate) status: c_int,
    pub(crate) here_node: *mut XmlNode,
    pub(crate) next: *mut XmlSecTransform,
    pub(crate) prev: *mut XmlSecTransform,
    pub(crate) in_buf: XmlSecBuffer,
    pub(crate) out_buf: XmlSecBuffer,
    pub(crate) in_nodes: *mut XmlSecNodeSet,
    pub(crate) out_nodes: *mut XmlSecNodeSet,
    pub(crate) expected_output_size: usize,
    pub(crate) flags: usize,
    pub(crate) reserved0: *mut c_void,
}

/// A transform object with its klass's context in the tail, as libxmlsec1's
/// `XMLSEC_TRANSFORM_DECLARE` lays it out.
#[repr(C)]
pub(crate) struct WithContext<T> {
    pub(crate) transform: XmlSecTransform,
    pub(crate) context: T,
}

/// The klass of a valid transform, as `xmlSecTransformIsValid` checks it:
/// non-null, with sizes at least those of the public structures and a name.
///
/// # Safety
/// `transform` is null or points to a transform whose klass, when non-null,
/// outlives it.
pub(crate) unsafe fn valid<'a>(
    transform: *mut XmlSecTransform,
) -> Option<(&'a mut XmlSecTransform, &'a XmlSecTransformKlass)> {
    // SAFETY: by the caller's contract.
    unsafe {
        let transform = transform.as_mut()?;
        let klass = transform.id.as_ref()?;
        (klass.klass_size >= size_of::<XmlSecTransformKlass>()
            && klass.obj_size >= size_of::<XmlSecTransform>()
            && !klass.name.is_null())
        .then_some((transform, klass))
    }
}

/// The context in the tail of a transform of klass `klass`, when the object
/// is large enough to hold it (`xmlSecTransformCheckSize`).
///
/// # Safety
/// `transform` is null or a valid transform whose tail, when its klass's
/// object size allows, holds a `T`.
pub(crate) unsafe fn context<'a, T>(
    transform: *mut XmlSecTransform,
    klass: *const XmlSecTransformKlass,
) -> Option<&'a mut T> {
    // SAFETY: by the caller's contract.
    unsafe {
        let (object, id) = valid(transform)?;
        (std::ptr::eq(id, klass) && id.obj_size >= size_of::<WithContext<T>>())
            .then(|| &mut (*std::ptr::from_mut(object).cast::<WithContext<T>>()).context)
    }
}

/// A C object with a fixed address that the library and its callers change
/// through pointers, as libxmlsec1's process-global registries are.
pub(crate) struct Global<T>(std::cell::UnsafeCell<T>);

// SAFETY: libxmlsec1's contract for its globals: they are changed during
// initialization and shutdown, before and after operations run, never
// concurrently with their readers.
unsafe impl<T> Sync for Global<T> {}

impl<T> Global<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(std::cell::UnsafeCell::new(value))
    }

    pub(crate) const fn get(&self) -> *mut T {
        self.0.get()
    }
}

/// An empty list without a klass, as a zero-initialized C static is.
pub(crate) const fn zero_list() -> XmlSecPtrList {
    XmlSecPtrList {
        id: std::ptr::null(),
        data: std::ptr::null_mut(),
        used: 0,
        max: 0,
        alloc_mode: 0,
    }
}

/// Every registered transform klass.
static ALL_TRANSFORM_IDS: Global<XmlSecPtrList> = Global::new(zero_list());

/// The transform-ids list klass: items are klasses, neither duplicated nor
/// destroyed.
static TRANSFORM_ID_LIST_KLASS: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"transform-ids-list".as_ptr().cast(),
    duplicate_item: None,
    destroy_item: None,
    debug_dump_item: None,
    debug_xml_dump_item: None,
};

/// `xmlSecTransformIdListGetKlass`.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformIdListGetKlass() -> *const XmlSecPtrListKlass {
    &raw const TRANSFORM_ID_LIST_KLASS
}

/// The klasses of a transform-ids list, or `None` for another list.
///
/// # Safety
/// `list` is null or a list.
unsafe fn id_list<'a>(list: *mut XmlSecPtrList) -> Option<Vec<&'a XmlSecTransformKlass>> {
    // SAFETY: by the caller's contract; a transform-ids list holds klasses.
    unsafe {
        let checked = list.as_ref()?;
        if !std::ptr::eq(checked.id, &raw const TRANSFORM_ID_LIST_KLASS) {
            return None;
        }
        (0..xmlSecPtrListGetSize(list))
            .map(|pos| {
                xmlSecPtrListGetItem(list, pos)
                    .cast::<XmlSecTransformKlass>()
                    .as_ref()
            })
            .collect()
    }
}

/// `xmlSecTransformIdListFind`: 1 when `id` is in the list, 0 when not, -1
/// for a list of another klass.
///
/// # Safety
/// `list` is null or a list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformIdListFind(
    list: *mut XmlSecPtrList,
    id: *const XmlSecTransformKlass,
) -> c_int {
    contain(-1, || {
        if id.is_null() {
            return -1;
        }
        // SAFETY: by the caller's contract.
        match unsafe { id_list(list) } {
            Some(klasses) => c_int::from(klasses.iter().any(|klass| std::ptr::eq(*klass, id))),
            None => -1,
        }
    })
}

/// The first klass of `list` whose `field` (name or href) equals `value`
/// and whose usage shares a bit with `usage`.
///
/// # Safety
/// `list` is null or a list; `value` is null or NUL-terminated.
unsafe fn find_by(
    list: *mut XmlSecPtrList,
    value: *const u8,
    usage: c_uint,
    field: fn(&XmlSecTransformKlass) -> *const u8,
) -> *const XmlSecTransformKlass {
    if value.is_null() {
        return std::ptr::null();
    }
    // SAFETY: by the caller's contract.
    let Some(klasses) = (unsafe { id_list(list) }) else {
        return std::ptr::null();
    };
    for klass in klasses {
        let candidate = field(klass);
        if (usage & klass.usage) == 0 || candidate.is_null() {
            continue;
        }
        // SAFETY: klass strings are NUL-terminated with static storage.
        if unsafe { xmlStrEqual(value, candidate) } != 0 {
            return klass;
        }
    }
    std::ptr::null()
}

/// `xmlSecTransformIdListFindByHref`: the first registered klass with the
/// algorithm URI `href` and a usage shared with `usage`.
///
/// # Safety
/// `list` is null or a list; `href` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformIdListFindByHref(
    list: *mut XmlSecPtrList,
    href: *const u8,
    usage: c_uint,
) -> *const XmlSecTransformKlass {
    // SAFETY: by the caller's contract.
    contain(std::ptr::null(), || unsafe {
        find_by(list, href, usage, |klass| klass.href)
    })
}

/// `xmlSecTransformIdListFindByName`: as by href, by the klass name.
///
/// # Safety
/// As for [`xmlSecTransformIdListFindByHref`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformIdListFindByName(
    list: *mut XmlSecPtrList,
    name: *const u8,
    usage: c_uint,
) -> *const XmlSecTransformKlass {
    // SAFETY: by the caller's contract.
    contain(std::ptr::null(), || unsafe {
        find_by(list, name, usage, |klass| klass.name)
    })
}

/// A klass string for display.
///
/// # Safety
/// `text` is null or NUL-terminated.
pub(crate) unsafe fn klass_text(text: *const u8) -> String {
    if text.is_null() {
        return "NULL".to_owned();
    }
    // SAFETY: by the caller's contract.
    unsafe { std::ffi::CStr::from_ptr(text.cast()) }
        .to_string_lossy()
        .into_owned()
}

/// `text` with XML's special characters escaped, as libxmlsec1's
/// `xmlSecPrintXmlString` writes it.
pub(crate) fn xml_text(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '&' => "&amp;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&apos;".to_owned(),
            _ => ch.to_string(),
        })
        .collect()
}

/// `xmlSecTransformIdListDebugDump`.
///
/// # Safety
/// `list` is null or a list; `output` is null or a C `FILE*`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformIdListDebugDump(
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
            .map(|klass| {
                // SAFETY: klass names are NUL-terminated.
                let name = unsafe { klass_text(klass.name) };
                format!("\"{name}\"")
            })
            .collect();
        // SAFETY: `output` is a live stream.
        unsafe { write_stream(output, &format!("{}\n", names.join(","))) };
    });
}

/// `xmlSecTransformIdListDebugXmlDump`.
///
/// # Safety
/// As for [`xmlSecTransformIdListDebugDump`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformIdListDebugXmlDump(
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
        let mut text = String::from("<TransformIdsList>\n");
        for klass in klasses {
            // SAFETY: klass names are NUL-terminated.
            let name = xml_text(&unsafe { klass_text(klass.name) });
            text.push_str("<TransformId name=\"");
            text.push_str(&name);
            text.push_str("\" />");
        }
        text.push_str("</TransformIdsList>\n");
        // SAFETY: `output` is a live stream.
        unsafe { write_stream(output, &text) };
    });
}

/// `xmlSecTransformIdsGet`: the list of registered klasses.
///
/// # Safety
/// Callable at any time; the list is valid after [`xmlSecTransformIdsInit`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformIdsGet() -> *mut XmlSecPtrList {
    ALL_TRANSFORM_IDS.get()
}

/// `xmlSecTransformIdsInit`: initializes the registry with the built-in
/// klasses. Called by `xmlSecInit`.
///
/// # Safety
/// Called once, before transforms are read from XML, or after
/// [`xmlSecTransformIdsShutdown`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformIdsInit() -> c_int {
    contain(-1, || {
        // SAFETY: the registry has a fixed address and is not in use.
        unsafe {
            if xmlSecPtrListInitialize(xmlSecTransformIdsGet(), xmlSecTransformIdListGetKlass()) < 0
            {
                return -1;
            }
            xmlSecTransformIdsRegisterDefault()
        }
    })
}

/// `xmlSecTransformIdsShutdown`: empties the registry.
///
/// # Safety
/// No transform is read from XML concurrently.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformIdsShutdown() {
    // SAFETY: the registry has a fixed address.
    contain((), || unsafe {
        xmlSecPtrListFinalize(xmlSecTransformIdsGet());
    });
}

/// `xmlSecTransformIdsRegister`: adds `id` at the end of the registry.
///
/// # Safety
/// `id` is null or a klass that outlives its registration; the registry is
/// not read concurrently.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformIdsRegister(
    id: *const XmlSecTransformKlass,
) -> c_int {
    contain(-1, || {
        if id.is_null() {
            return -1;
        }
        // SAFETY: the registry has a fixed address; items are klasses.
        unsafe { xmlSecPtrListAdd(xmlSecTransformIdsGet(), id.cast_mut().cast()) }
    })
}

/// `xmlSecTransformIdsRegisterDefault`: registers libxmlsec1's own klasses
/// in its order.
///
/// # Safety
/// As for [`xmlSecTransformIdsRegister`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformIdsRegisterDefault() -> c_int {
    contain(-1, || {
        for id in builtin::defaults() {
            // SAFETY: built-in klasses are statics.
            if unsafe { xmlSecTransformIdsRegister(id) } < 0 {
                return -1;
            }
        }
        0
    })
}

/// `xmlSecTransformUriTypeCheck`: 1 when the type of `uri` (empty, same
/// document, `file://` or remote) is among `kind`'s bits.
///
/// # Safety
/// `uri` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformUriTypeCheck(kind: c_uint, uri: *const u8) -> c_int {
    contain(0, || {
        let text: &[u8] = if uri.is_null() {
            &[]
        } else {
            // SAFETY: a NUL-terminated string.
            unsafe { std::ffi::CStr::from_ptr(uri.cast()) }.to_bytes()
        };
        let uri_type: c_uint = if text.is_empty() {
            0x0001
        } else if text[0] == b'#' {
            0x0002
        } else if text.starts_with(b"file://") {
            0x0004
        } else {
            0x0008
        };
        c_int::from(uri_type & kind != 0)
    })
}

/// `xmlSecTransformCreate`: a new transform of klass `id`, initialized by the
/// klass; released with [`xmlSecTransformDestroy`].
///
/// # Safety
/// `id` is null or a klass that outlives the transform, whose methods keep
/// libxmlsec1's contract.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCreate(
    id: *const XmlSecTransformKlass,
) -> *mut XmlSecTransform {
    contain(std::ptr::null_mut(), || {
        // SAFETY: the caller passes null or a klass.
        let Some(klass) = (unsafe { id.as_ref() }) else {
            return std::ptr::null_mut();
        };
        if klass.klass_size < size_of::<XmlSecTransformKlass>()
            || klass.obj_size < size_of::<XmlSecTransform>()
            || klass.name.is_null()
        {
            return std::ptr::null_mut();
        }
        let transform = malloc(klass.obj_size).cast::<XmlSecTransform>();
        if transform.is_null() {
            return transform;
        }
        // SAFETY: a fresh allocation of the klass's object size, zeroed
        // before the klass initializes its tail.
        unsafe {
            transform.cast::<u8>().write_bytes(0, klass.obj_size);
            (*transform).id = id;
            if let Some(initialize) = klass.initialize
                && initialize(transform) < 0
            {
                xmlSecTransformDestroy(transform);
                return std::ptr::null_mut();
            }
            if xmlSecBufferInitialize(&raw mut (*transform).in_buf, 0) < 0
                || xmlSecBufferInitialize(&raw mut (*transform).out_buf, 0) < 0
            {
                xmlSecTransformDestroy(transform);
                return std::ptr::null_mut();
            }
        }
        transform
    })
}

/// `xmlSecTransformDestroy`: unlinks the transform from its chain, releases
/// its buffers and output nodes (never its input nodes), lets the klass
/// finalize its context, and frees it.
///
/// # Safety
/// `transform` is null or came from [`xmlSecTransformCreate`] and was not
/// destroyed.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformDestroy(transform: *mut XmlSecTransform) {
    contain((), || {
        // SAFETY: the caller passes null or a created transform.
        let Some((object, klass)) = (unsafe { valid(transform) }) else {
            return;
        };
        if klass.obj_size == 0 {
            return;
        }
        let size = klass.obj_size;
        let finalize = klass.finalize;
        // SAFETY: the transform is live until freed at the end.
        unsafe {
            xmlSecTransformRemove(transform);
            xmlSecBufferFinalize(&raw mut object.in_buf);
            xmlSecBufferFinalize(&raw mut object.out_buf);
            if !object.out_nodes.is_null() && object.out_nodes != object.in_nodes {
                xmlSecNodeSetDestroy(object.out_nodes);
            }
            if let Some(finalize) = finalize {
                finalize(transform);
            }
            transform.cast::<u8>().write_bytes(0, size);
            free(transform.cast::<c_void>());
        }
    });
}

/// `xmlSecTransformSetKey`: hands `key` to the klass, if it takes keys.
///
/// # Safety
/// `transform` is null or a valid transform; `key` is null or an
/// `xmlSecKey`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformSetKey(
    transform: *mut XmlSecTransform,
    key: *mut c_void,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((_, klass)) = (unsafe { valid(transform) }) else {
            return -1;
        };
        if key.is_null() {
            return -1;
        }
        // SAFETY: the klass method keeps libxmlsec1's contract.
        klass
            .set_key
            .map_or(0, |set_key| unsafe { set_key(transform, key) })
    })
}

/// `xmlSecTransformSetKeyReq`: resets `key_req` to "any key" and lets the
/// klass state its requirements.
///
/// # Safety
/// `transform` is null or a valid transform; `key_req` is null or an
/// initialized `xmlSecKeyReq`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformSetKeyReq(
    transform: *mut XmlSecTransform,
    key_req: *mut XmlSecKeyReq,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((_, klass)) = (unsafe { valid(transform) }) else {
            return -1;
        };
        // SAFETY: the caller passes null or a key requirement.
        let Some(req) = (unsafe { key_req.as_mut() }) else {
            return -1;
        };
        req.key_id = std::ptr::null();
        req.key_type = 0;
        req.key_usage = KEY_USAGE_ANY;
        req.key_bits_size = 0;
        // SAFETY: the klass method keeps libxmlsec1's contract.
        klass
            .set_key_req
            .map_or(0, |set_key_req| unsafe { set_key_req(transform, key_req) })
    })
}

/// `xmlSecTransformVerify`: lets a digest or signature klass compare its
/// result with `data`, recording the verdict in `status`.
///
/// # Safety
/// `transform` is null or a valid transform; `data` is null or readable for
/// `size` bytes; `ctx` is null or a transform context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformVerify(
    transform: *mut XmlSecTransform,
    data: *const u8,
    size: usize,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((_, klass)) = (unsafe { valid(transform) }) else {
            return -1;
        };
        match klass.verify {
            // SAFETY: the klass method keeps libxmlsec1's contract.
            Some(verify) if !ctx.is_null() => unsafe { verify(transform, data, size, ctx) },
            _ => -1,
        }
    })
}

/// `xmlSecTransformGetDataType`: what the transform takes (push) or gives
/// (pop): binary, XML or both.
///
/// # Safety
/// `transform` is null or a valid transform; `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformGetDataType(
    transform: *mut XmlSecTransform,
    mode: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> u8 {
    contain(DATA_UNKNOWN, || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((_, klass)) = (unsafe { valid(transform) }) else {
            return DATA_UNKNOWN;
        };
        // SAFETY: the klass method keeps libxmlsec1's contract.
        klass
            .get_data_type
            .map_or(DATA_UNKNOWN, |get_data_type| unsafe {
                get_data_type(transform, mode, ctx)
            })
    })
}

/// `xmlSecTransformPushBin`: dispatches to the klass's binary push.
///
/// # Safety
/// `transform` is null or a valid transform; `data` is null or readable for
/// `size` bytes; `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformPushBin(
    transform: *mut XmlSecTransform,
    data: *const u8,
    size: usize,
    is_final: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((_, klass)) = (unsafe { valid(transform) }) else {
            return -1;
        };
        match klass.push_bin {
            // SAFETY: the klass method keeps libxmlsec1's contract.
            Some(push) if !ctx.is_null() => unsafe { push(transform, data, size, is_final, ctx) },
            _ => -1,
        }
    })
}

/// `xmlSecTransformPopBin`: dispatches to the klass's binary pop.
///
/// # Safety
/// `transform` is null or a valid transform; `data` is null or writable for
/// `max_size` bytes; `size` is null or writable; `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformPopBin(
    transform: *mut XmlSecTransform,
    data: *mut u8,
    max_size: usize,
    size: *mut usize,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((_, klass)) = (unsafe { valid(transform) }) else {
            return -1;
        };
        match klass.pop_bin {
            Some(pop) if !data.is_null() && !size.is_null() && !ctx.is_null() => {
                // SAFETY: the klass method keeps libxmlsec1's contract.
                unsafe { pop(transform, data, max_size, size, ctx) }
            }
            _ => -1,
        }
    })
}

/// `xmlSecTransformPushXml`: dispatches to the klass's node-set push.
///
/// # Safety
/// `transform` is null or a valid transform; `nodes` is null or a node set;
/// `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformPushXml(
    transform: *mut XmlSecTransform,
    nodes: *mut XmlSecNodeSet,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((_, klass)) = (unsafe { valid(transform) }) else {
            return -1;
        };
        match klass.push_xml {
            // SAFETY: the klass method keeps libxmlsec1's contract.
            Some(push) if !ctx.is_null() => unsafe { push(transform, nodes, ctx) },
            _ => -1,
        }
    })
}

/// `xmlSecTransformPopXml`: dispatches to the klass's node-set pop.
///
/// # Safety
/// `transform` is null or a valid transform; `nodes` is null or writable;
/// `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformPopXml(
    transform: *mut XmlSecTransform,
    nodes: *mut *mut XmlSecNodeSet,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((_, klass)) = (unsafe { valid(transform) }) else {
            return -1;
        };
        match klass.pop_xml {
            // SAFETY: the klass method keeps libxmlsec1's contract.
            Some(pop) if !ctx.is_null() => unsafe { pop(transform, nodes, ctx) },
            _ => -1,
        }
    })
}

/// `xmlSecTransformExecute`: dispatches to the klass's processing step.
///
/// # Safety
/// `transform` is null or a valid transform; `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformExecute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((_, klass)) = (unsafe { valid(transform) }) else {
            return -1;
        };
        match klass.execute {
            // SAFETY: the klass method keeps libxmlsec1's contract.
            Some(execute) if !ctx.is_null() => unsafe { execute(transform, last, ctx) },
            _ => -1,
        }
    })
}

/// `xmlSecTransformDebugDump`.
///
/// # Safety
/// `transform` is null or a valid transform; `output` is null or a C
/// `FILE*`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformDebugDump(
    transform: *mut XmlSecTransform,
    output: *mut c_void,
) {
    contain((), || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((_, klass)) = (unsafe { valid(transform) }) else {
            return;
        };
        if output.is_null() {
            return;
        }
        // SAFETY: klass strings are NUL-terminated; `output` is live.
        unsafe {
            let text = format!(
                "=== Transform: {} (href={})\n",
                klass_text(klass.name),
                klass_text(klass.href)
            );
            write_stream(output, &text);
        }
    });
}

/// `xmlSecTransformDebugXmlDump`.
///
/// # Safety
/// As for [`xmlSecTransformDebugDump`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformDebugXmlDump(
    transform: *mut XmlSecTransform,
    output: *mut c_void,
) {
    contain((), || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((_, klass)) = (unsafe { valid(transform) }) else {
            return;
        };
        if output.is_null() {
            return;
        }
        // SAFETY: klass strings are NUL-terminated; `output` is live. A null
        // string prints nothing, as libxmlsec1's string printer does.
        unsafe {
            let shown = |text: *const u8| {
                if text.is_null() {
                    String::new()
                } else {
                    xml_text(&klass_text(text))
                }
            };
            let text = format!(
                "<Transform name=\"{}\" href=\"{}\" />\n",
                shown(klass.name),
                shown(klass.href)
            );
            write_stream(output, &text);
        }
    });
}

/// `xmlSecTransformConnect`: links `left` to `right`, inserting the XML
/// parser before a binary-to-XML boundary, and before an XML-to-binary
/// boundary inclusive C14N 1.0, or the tag-removing conversion when `right`
/// is the Base64 transform (`XMLDSig` section 6.6.2).
///
/// # Safety
/// Each transform is null or valid; `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformConnect(
    left: *mut XmlSecTransform,
    right: *mut XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or valid transforms.
        let (Some(_), Some((_, right_klass))) = (unsafe { valid(left) }, unsafe { valid(right) })
        else {
            return -1;
        };
        if ctx.is_null() {
            return -1;
        }
        // SAFETY: valid transforms and a context.
        let (left_type, right_type) = unsafe {
            (
                xmlSecTransformGetDataType(left, MODE_POP, ctx),
                xmlSecTransformGetDataType(right, MODE_PUSH, ctx),
            )
        };
        let middle_id = if (left_type & DATA_BIN != 0 && right_type & DATA_BIN != 0)
            || (left_type & DATA_XML != 0 && right_type & DATA_XML != 0)
        {
            // SAFETY: both transforms are valid.
            unsafe {
                (*left).next = right;
                (*right).prev = left;
            }
            return 0;
        } else if left_type & DATA_BIN != 0 && right_type & DATA_XML != 0 {
            parser::xml_parser()
        } else if left_type & DATA_XML != 0 && right_type & DATA_BIN != 0 {
            if std::ptr::eq(right_klass, builtin::base64()) {
                builtin::remove_xml_tags_c14n()
            } else {
                builtin::incl_c14n()
            }
        } else {
            return -1;
        };
        // SAFETY: a built-in klass; the transforms are valid.
        unsafe {
            let middle = xmlSecTransformCreate(middle_id);
            if middle.is_null() {
                return -1;
            }
            (*left).next = middle;
            (*middle).prev = left;
            (*middle).next = right;
            (*right).prev = middle;
        }
        0
    })
}

/// `xmlSecTransformRemove`: unlinks the transform from its chain.
///
/// # Safety
/// `transform` is null or a valid transform whose neighbours are valid.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformRemove(transform: *mut XmlSecTransform) {
    contain((), || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((object, _)) = (unsafe { valid(transform) }) else {
            return;
        };
        // SAFETY: the neighbours are live transforms of the same chain.
        unsafe {
            if let Some(next) = object.next.as_mut() {
                next.prev = object.prev;
            }
            if let Some(prev) = object.prev.as_mut() {
                prev.next = object.next;
            }
        }
        object.next = std::ptr::null_mut();
        object.prev = std::ptr::null_mut();
    });
}

/// `xmlSecTransformPump`: pops everything `left` produces and pushes it into
/// `right`, as node sets or in binary chunks of the context's size.
///
/// # Safety
/// Each transform is null or valid; `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformPump(
    left: *mut XmlSecTransform,
    right: *mut XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or valid transforms and context.
        unsafe {
            if valid(left).is_none() || valid(right).is_none() {
                return -1;
            }
            let Some(context) = ctx.as_ref() else {
                return -1;
            };
            let chunk = context.binary_chunk_size;
            if chunk == 0 {
                return -1;
            }
            let left_type = xmlSecTransformGetDataType(left, MODE_POP, ctx);
            let right_type = xmlSecTransformGetDataType(right, MODE_PUSH, ctx);
            if left_type & DATA_XML != 0 && right_type & DATA_XML != 0 {
                let mut nodes = std::ptr::null_mut();
                if xmlSecTransformPopXml(left, &raw mut nodes, ctx) < 0
                    || xmlSecTransformPushXml(right, nodes, ctx) < 0
                {
                    return -1;
                }
                return 0;
            }
            if left_type & DATA_BIN == 0 || right_type & DATA_BIN == 0 {
                return -1;
            }
            let buffer = malloc(chunk).cast::<u8>();
            if buffer.is_null() {
                return -1;
            }
            let result = loop {
                let mut size = 0;
                if xmlSecTransformPopBin(left, buffer, chunk, &raw mut size, ctx) < 0 {
                    break -1;
                }
                let is_final = c_int::from(size == 0);
                if xmlSecTransformPushBin(right, buffer, size, is_final, ctx) < 0 {
                    break -1;
                }
                if is_final != 0 {
                    break 0;
                }
            };
            free(buffer.cast::<c_void>());
            result
        }
    })
}

/// `xmlSecTransformDefaultGetDataType`: binary and/or XML according to the
/// klass's push or pop methods.
///
/// # Safety
/// `transform` is null or a valid transform; `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformDefaultGetDataType(
    transform: *mut XmlSecTransform,
    mode: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> u8 {
    contain(DATA_UNKNOWN, || {
        // SAFETY: the caller passes null or a valid transform.
        let Some((_, klass)) = (unsafe { valid(transform) }) else {
            return DATA_UNKNOWN;
        };
        if ctx.is_null() {
            return DATA_UNKNOWN;
        }
        let (binary, xml) = match mode {
            MODE_PUSH => (klass.push_bin.is_some(), klass.push_xml.is_some()),
            MODE_POP => (klass.pop_bin.is_some(), klass.pop_xml.is_some()),
            _ => return DATA_UNKNOWN,
        };
        (if binary { DATA_BIN } else { DATA_UNKNOWN }) | (if xml { DATA_XML } else { DATA_UNKNOWN })
    })
}

/// `xmlSecTransformDefaultPushBin`: appends the data to the input buffer in
/// chunks of the context's size, runs `execute`, and pushes the output to the
/// next transform, until all data and output are consumed.
///
/// # Safety
/// `transform` is null or a valid transform; `data` is null or readable for
/// `size` bytes; `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformDefaultPushBin(
    transform: *mut XmlSecTransform,
    data: *const u8,
    size: usize,
    is_final: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller's contract; every buffer belongs to the live
        // transform and `data` advances within its `size` bytes.
        unsafe {
            let Some((object, _)) = valid(transform) else {
                return -1;
            };
            let Some(context) = ctx.as_ref() else {
                return -1;
            };
            let chunk = context.binary_chunk_size;
            let (mut data, mut remaining) = (data, size);
            loop {
                if remaining > 0 {
                    if data.is_null() {
                        return -1;
                    }
                    let part = remaining.min(chunk);
                    if xmlSecBufferAppend(&raw mut object.in_buf, data, part) < 0 {
                        return -1;
                    }
                    remaining -= part;
                    data = data.add(part);
                }
                let mut final_data = c_int::from(remaining == 0 && is_final != 0);
                if xmlSecTransformExecute(transform, final_data, ctx) < 0 {
                    return -1;
                }
                let in_size = xmlSecBufferGetSize(&raw mut object.in_buf);
                let mut out_size = xmlSecBufferGetSize(&raw mut object.out_buf);
                if in_size > 0 {
                    final_data = 0;
                }
                if out_size > chunk {
                    out_size = chunk;
                    final_data = 0;
                }
                if !object.next.is_null()
                    && (out_size > 0 || final_data != 0)
                    && xmlSecTransformPushBin(
                        object.next,
                        xmlSecBufferGetData(&raw mut object.out_buf),
                        out_size,
                        final_data,
                        ctx,
                    ) < 0
                {
                    return -1;
                }
                if out_size > 0 && xmlSecBufferRemoveHead(&raw mut object.out_buf, out_size) < 0 {
                    return -1;
                }
                if remaining == 0 && out_size == 0 {
                    return 0;
                }
            }
        }
    })
}

/// `xmlSecTransformDefaultPopBin`: pulls chunks from the previous transform
/// and runs `execute` until output is available or the input ends, then
/// returns up to `max_size` bytes (and no more than one chunk).
///
/// # Safety
/// `transform` is null or a valid transform; `data` is null or writable for
/// `max_size` bytes; `size` is null or writable; `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformDefaultPopBin(
    transform: *mut XmlSecTransform,
    data: *mut u8,
    max_size: usize,
    size: *mut usize,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller's contract; every buffer belongs to the live
        // transform, and the previous transform writes at most one chunk into
        // the space reserved for it.
        unsafe {
            let Some((object, _)) = valid(transform) else {
                return -1;
            };
            let Some(context) = ctx.as_ref() else {
                return -1;
            };
            if data.is_null() || size.is_null() {
                return -1;
            }
            let chunk = context.binary_chunk_size;
            let mut is_final = false;
            while xmlSecBufferGetSize(&raw mut object.out_buf) == 0 && !is_final {
                if object.prev.is_null() {
                    // Without a previous transform the input never grows.
                    is_final = true;
                } else {
                    let in_size = xmlSecBufferGetSize(&raw mut object.in_buf);
                    let Some(room) = in_size.checked_add(chunk) else {
                        return -1;
                    };
                    if xmlSecBufferSetMaxSize(&raw mut object.in_buf, room) < 0 {
                        return -1;
                    }
                    let mut got = chunk;
                    let target = xmlSecBufferGetData(&raw mut object.in_buf).add(in_size);
                    if xmlSecTransformPopBin(object.prev, target, chunk, &raw mut got, ctx) < 0 {
                        return -1;
                    }
                    if got > 0 {
                        if xmlSecBufferSetSize(&raw mut object.in_buf, in_size + got) < 0 {
                            return -1;
                        }
                    } else {
                        is_final = true;
                    }
                }
                if xmlSecTransformExecute(transform, c_int::from(is_final), ctx) < 0 {
                    return -1;
                }
            }
            let out_size = xmlSecBufferGetSize(&raw mut object.out_buf)
                .min(max_size)
                .min(chunk);
            if out_size > 0 {
                let output = xmlSecBufferGetData(&raw mut object.out_buf);
                if output.is_null() {
                    return -1;
                }
                output.copy_to(data, out_size);
                if xmlSecBufferRemoveHead(&raw mut object.out_buf, out_size) < 0 {
                    return -1;
                }
            }
            size.write(out_size);
            0
        }
    })
}

/// `xmlSecTransformDefaultPushXml`: runs `execute` on `nodes` and pushes the
/// output nodes to the next transform.
///
/// # Safety
/// `transform` is null or a valid transform; `nodes` is null or a node set;
/// `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformDefaultPushXml(
    transform: *mut XmlSecTransform,
    nodes: *mut XmlSecNodeSet,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid transform and context.
        unsafe {
            let Some((object, _)) = valid(transform) else {
                return -1;
            };
            if !object.in_nodes.is_null() || !object.out_nodes.is_null() || ctx.is_null() {
                return -1;
            }
            object.in_nodes = nodes;
            if xmlSecTransformExecute(transform, 1, ctx) < 0 {
                return -1;
            }
            if !object.next.is_null()
                && xmlSecTransformPushXml(object.next, object.out_nodes, ctx) < 0
            {
                return -1;
            }
        }
        0
    })
}

/// `xmlSecTransformDefaultPopXml`: pops the previous transform's nodes, runs
/// `execute`, and returns the output nodes when `nodes` is non-null.
///
/// # Safety
/// `transform` is null or a valid transform; `nodes` is null or writable;
/// `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformDefaultPopXml(
    transform: *mut XmlSecTransform,
    nodes: *mut *mut XmlSecNodeSet,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid transform and context.
        unsafe {
            let Some((object, _)) = valid(transform) else {
                return -1;
            };
            if !object.in_nodes.is_null() || !object.out_nodes.is_null() || ctx.is_null() {
                return -1;
            }
            if !object.prev.is_null()
                && xmlSecTransformPopXml(object.prev, &raw mut object.in_nodes, ctx) < 0
            {
                return -1;
            }
            if xmlSecTransformExecute(transform, 1, ctx) < 0 {
                return -1;
            }
            if !nodes.is_null() {
                nodes.write(object.out_nodes);
            }
        }
        0
    })
}
