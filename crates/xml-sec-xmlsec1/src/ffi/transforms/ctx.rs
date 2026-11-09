//! `xmlSecTransformCtx`: a chain of transforms and the state of one run.

use std::ffi::{CStr, c_int, c_uint, c_void};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use xml_sec_libxml2::ffi::{XmlDoc, XmlNode};

use super::super::buffer::XmlSecBuffer;
use super::super::list::{
    XmlSecPtrList, xmlSecPtrListCopy, xmlSecPtrListDestroy, xmlSecPtrListFinalize,
    xmlSecPtrListGetSize, xmlSecPtrListInitialize,
};
use super::super::nodeset::{
    NORMAL, XmlSecNodeSet, xmlSecNodeSetCreate, xmlSecNodeSetDestroy, xmlSecNodeSetGetChildren,
};
use super::super::strings::{xmlSecAttrAlgorithm, xmlSecDSigNs, xmlSecNodeTransform};
use super::super::tree::readable;
use super::super::xmltree::{xmlSecCheckNodeName, xmlSecGetNextElementNode};
use super::super::{contain, free, malloc, write_stream};
use super::{
    DATA_BIN, DATA_UNKNOWN, DATA_XML, FLAGS_USER_SPECIFIED, MODE_PUSH, STATUS_FINISHED,
    STATUS_NONE, STATUS_WORKING, XmlSecTransform, XmlSecTransformKlass, builtin, klass_text, valid,
    xml_text, xmlSecTransformConnect, xmlSecTransformCreate, xmlSecTransformDebugDump,
    xmlSecTransformDebugXmlDump, xmlSecTransformDestroy, xmlSecTransformGetDataType,
    xmlSecTransformIdListDebugDump, xmlSecTransformIdListDebugXmlDump, xmlSecTransformIdListFind,
    xmlSecTransformIdListFindByHref, xmlSecTransformIdListGetKlass, xmlSecTransformIdsGet,
    xmlSecTransformPump, xmlSecTransformPushBin, xmlSecTransformPushXml,
};

/// `xmlSecTransformCtxPreExecuteCallback`.
pub(crate) type PreExecuteCallback = Option<unsafe extern "C" fn(*mut XmlSecTransformCtx) -> c_int>;

/// `XMLSEC_TRANSFORMCTX_FLAGS_USE_VISA3D_HACK`.
const FLAGS_USE_VISA3D_HACK: c_uint = 0x0001;
/// `xmlSecTransformUriTypeAny`.
const URI_TYPE_ANY: c_uint = 0xFFFF;
/// `xmlSecNodeSetTree`.
const TREE: c_int = 2;
/// `xmlSecNodeSetTreeWithoutComments`.
const TREE_WITHOUT_COMMENTS: c_int = 3;

/// `xmlSecTransformCtx`.
#[repr(C)]
pub(crate) struct XmlSecTransformCtx {
    pub(crate) user_data: *mut c_void,
    pub(crate) flags: c_uint,
    pub(crate) max_depth: c_uint,
    pub(crate) binary_chunk_size: usize,
    pub(crate) enabled_uris: c_uint,
    pub(crate) enabled_transforms: XmlSecPtrList,
    pub(crate) pre_exec_callback: PreExecuteCallback,
    pub(crate) parent_key_info_ctx: *mut c_void,
    pub(crate) result: *mut XmlSecBuffer,
    pub(crate) status: c_int,
    pub(crate) uri: *mut u8,
    pub(crate) xptr_expr: *mut u8,
    pub(crate) first: *mut XmlSecTransform,
    pub(crate) last: *mut XmlSecTransform,
    pub(crate) extra_key_data: *mut XmlSecPtrList,
    pub(crate) reserved0: *mut c_void,
}

/// The binary chunk size of contexts initialized from now on (64 KiB).
static DEFAULT_CHUNK_SIZE: AtomicUsize = AtomicUsize::new(64 * 1024);
/// The maximum transform depth of contexts initialized from now on.
static DEFAULT_MAX_DEPTH: AtomicU32 = AtomicU32::new(16);

/// `xmlSecTransformCtxGetDefaultBinaryChunkSize`.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxGetDefaultBinaryChunkSize() -> usize {
    DEFAULT_CHUNK_SIZE.load(Ordering::Relaxed)
}

/// `xmlSecTransformCtxSetDefaultBinaryChunkSize`: a zero size is refused.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxSetDefaultBinaryChunkSize(size: usize) {
    if size > 0 {
        DEFAULT_CHUNK_SIZE.store(size, Ordering::Relaxed);
    }
}

/// `xmlSecTransformCtxGetDefaultMaxDepth`.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxGetDefaultMaxDepth() -> c_uint {
    DEFAULT_MAX_DEPTH.load(Ordering::Relaxed)
}

/// `xmlSecTransformCtxSetDefaultMaxDepth`: 0 disables the depth check.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxSetDefaultMaxDepth(depth: c_uint) {
    DEFAULT_MAX_DEPTH.store(depth, Ordering::Relaxed);
}

/// `xmlSecTransformCtxCreate`: a new context, released with
/// [`xmlSecTransformCtxDestroy`].
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxCreate() -> *mut XmlSecTransformCtx {
    contain(std::ptr::null_mut(), || {
        let ctx = malloc(size_of::<XmlSecTransformCtx>()).cast::<XmlSecTransformCtx>();
        if ctx.is_null() {
            return ctx;
        }
        // SAFETY: a fresh allocation of a context's size.
        if unsafe { xmlSecTransformCtxInitialize(ctx) } < 0 {
            // SAFETY: initialization left a finalizable context.
            unsafe { xmlSecTransformCtxDestroy(ctx) };
            return std::ptr::null_mut();
        }
        ctx
    })
}

/// `xmlSecTransformCtxDestroy`.
///
/// # Safety
/// `ctx` is null or came from [`xmlSecTransformCtxCreate`] and was not
/// destroyed.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxDestroy(ctx: *mut XmlSecTransformCtx) {
    contain((), || {
        if ctx.is_null() {
            return;
        }
        // SAFETY: a live created context, finalized then freed.
        unsafe {
            xmlSecTransformCtxFinalize(ctx);
            free(ctx.cast::<c_void>());
        }
    });
}

/// `xmlSecTransformCtxInitialize`: an empty chain that enables every
/// registered transform and URI type, with the default chunk size and depth.
///
/// # Safety
/// `ctx` is null or writable memory of a context's size.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxInitialize(
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        if ctx.is_null() {
            return -1;
        }
        // SAFETY: `ctx` is writable; it is zeroed before any field is read.
        unsafe {
            ctx.write_bytes(0, 1);
            if xmlSecPtrListInitialize(
                &raw mut (*ctx).enabled_transforms,
                xmlSecTransformIdListGetKlass(),
            ) < 0
            {
                return -1;
            }
            (*ctx).enabled_uris = URI_TYPE_ANY;
            (*ctx).binary_chunk_size = xmlSecTransformCtxGetDefaultBinaryChunkSize();
            (*ctx).max_depth = xmlSecTransformCtxGetDefaultMaxDepth();
        }
        0
    })
}

/// `xmlSecTransformCtxFinalize`: resets the context and zeroes it.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxFinalize(ctx: *mut XmlSecTransformCtx) {
    contain((), || {
        if ctx.is_null() {
            return;
        }
        // SAFETY: an initialized context.
        unsafe {
            xmlSecTransformCtxReset(ctx);
            xmlSecPtrListFinalize(&raw mut (*ctx).enabled_transforms);
            ctx.write_bytes(0, 1);
        }
    });
}

/// `xmlSecTransformCtxReset`: destroys the chain, the URI, the extra key
/// data and the result, keeping the user settings.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxReset(ctx: *mut XmlSecTransformCtx) {
    contain((), || {
        // SAFETY: an initialized context whose chain, strings and lists it
        // owns.
        unsafe {
            let Some(context) = ctx.as_mut() else {
                return;
            };
            context.result = std::ptr::null_mut();
            context.status = STATUS_NONE;
            if !context.extra_key_data.is_null() {
                xmlSecPtrListDestroy(context.extra_key_data);
                context.extra_key_data = std::ptr::null_mut();
            }
            free(context.uri.cast::<c_void>());
            context.uri = std::ptr::null_mut();
            free(context.xptr_expr.cast::<c_void>());
            context.xptr_expr = std::ptr::null_mut();
            let mut transform = context.first;
            while !transform.is_null() {
                let next = (*transform).next;
                xmlSecTransformDestroy(transform);
                transform = next;
            }
            context.first = std::ptr::null_mut();
            context.last = std::ptr::null_mut();
        }
    });
}

/// `xmlSecTransformCtxCopyUserPref`: copies the user settings (user data,
/// flags, depth, enabled URIs and transforms, pre-execute callback).
///
/// # Safety
/// Each pointer is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxCopyUserPref(
    dst: *mut XmlSecTransformCtx,
    src: *mut XmlSecTransformCtx,
) -> c_int {
    contain(-1, || {
        // SAFETY: initialized contexts.
        unsafe {
            let (Some(target), Some(source)) = (dst.as_mut(), src.as_mut()) else {
                return -1;
            };
            target.user_data = source.user_data;
            target.flags = source.flags;
            target.max_depth = source.max_depth;
            target.enabled_uris = source.enabled_uris;
            target.pre_exec_callback = source.pre_exec_callback;
            xmlSecPtrListCopy(
                &raw mut target.enabled_transforms,
                &raw mut source.enabled_transforms,
            )
        }
    })
}

/// The context when it is still building its chain.
///
/// # Safety
/// `ctx` is null or an initialized context.
unsafe fn building<'a>(ctx: *mut XmlSecTransformCtx) -> Option<&'a mut XmlSecTransformCtx> {
    // SAFETY: by the caller's contract.
    unsafe { ctx.as_mut() }.filter(|context| context.status == STATUS_NONE)
}

/// `xmlSecTransformCtxAppend`: connects `transform` after the last one.
///
/// # Safety
/// `ctx` is null or an initialized context; `transform` is null or a valid
/// transform the context now owns.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxAppend(
    ctx: *mut XmlSecTransformCtx,
    transform: *mut XmlSecTransform,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(context) = building(ctx) else {
                return -1;
            };
            if valid(transform).is_none() {
                return -1;
            }
            if context.last.is_null() {
                if !context.first.is_null() {
                    return -1;
                }
                context.first = transform;
            } else if xmlSecTransformConnect(context.last, transform, ctx) < 0 {
                return -1;
            }
            context.last = transform;
        }
        0
    })
}

/// `xmlSecTransformCtxPrepend`: connects `transform` before the first one.
///
/// # Safety
/// As for [`xmlSecTransformCtxAppend`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxPrepend(
    ctx: *mut XmlSecTransformCtx,
    transform: *mut XmlSecTransform,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(context) = building(ctx) else {
                return -1;
            };
            if valid(transform).is_none() {
                return -1;
            }
            if context.first.is_null() {
                if !context.last.is_null() {
                    return -1;
                }
                context.last = transform;
            } else if xmlSecTransformConnect(transform, context.first, ctx) < 0 {
                return -1;
            }
            context.first = transform;
        }
        0
    })
}

/// Creates a transform of `id` and adds it at one end of the chain.
///
/// # Safety
/// `ctx` is null or an initialized context; `id` is null or a klass.
unsafe fn create_and_add(
    ctx: *mut XmlSecTransformCtx,
    id: *const XmlSecTransformKlass,
    add: unsafe extern "C" fn(*mut XmlSecTransformCtx, *mut XmlSecTransform) -> c_int,
) -> *mut XmlSecTransform {
    // SAFETY: by the caller's contract.
    unsafe {
        if building(ctx).is_none() || id.is_null() {
            return std::ptr::null_mut();
        }
        let transform = xmlSecTransformCreate(id);
        if valid(transform).is_none() {
            return std::ptr::null_mut();
        }
        if add(ctx, transform) < 0 {
            xmlSecTransformDestroy(transform);
            return std::ptr::null_mut();
        }
        transform
    }
}

/// `xmlSecTransformCtxCreateAndAppend`.
///
/// # Safety
/// `ctx` is null or an initialized context; `id` is null or a klass.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxCreateAndAppend(
    ctx: *mut XmlSecTransformCtx,
    id: *const XmlSecTransformKlass,
) -> *mut XmlSecTransform {
    // SAFETY: by the caller's contract.
    contain(std::ptr::null_mut(), || unsafe {
        create_and_add(ctx, id, xmlSecTransformCtxAppend)
    })
}

/// `xmlSecTransformCtxCreateAndPrepend`.
///
/// # Safety
/// As for [`xmlSecTransformCtxCreateAndAppend`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxCreateAndPrepend(
    ctx: *mut XmlSecTransformCtx,
    id: *const XmlSecTransformKlass,
) -> *mut XmlSecTransform {
    // SAFETY: by the caller's contract.
    contain(std::ptr::null_mut(), || unsafe {
        create_and_add(ctx, id, xmlSecTransformCtxPrepend)
    })
}

unsafe extern "C" {
    fn xmlGetProp(node: *mut XmlNode, name: *const u8) -> *mut u8;
}

/// `xmlSecTransformNodeRead`: creates the registered transform named by the
/// node's `Algorithm` attribute for `usage`, if the context enables it, and
/// lets the klass read its parameters from the node.
///
/// # Safety
/// `node` is null or a live element; `ctx` is null or an initialized
/// context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformNodeRead(
    node: *mut XmlNode,
    usage: c_uint,
    ctx: *mut XmlSecTransformCtx,
) -> *mut XmlSecTransform {
    contain(std::ptr::null_mut(), || {
        if node.is_null() || ctx.is_null() || !readable() {
            return std::ptr::null_mut();
        }
        // SAFETY: a live element and an initialized context; the attribute
        // value is a libxml2 string released with `xmlFree`.
        unsafe {
            let href = xmlGetProp(node, xmlSecAttrAlgorithm.as_ptr());
            if href.is_null() {
                return std::ptr::null_mut();
            }
            let transform = read_algorithm(node, href, usage, ctx);
            free(href.cast::<c_void>());
            transform
        }
    })
}

/// The transform for algorithm `href` read from `node`.
///
/// # Safety
/// As for [`xmlSecTransformNodeRead`]; `href` is NUL-terminated.
unsafe fn read_algorithm(
    node: *mut XmlNode,
    href: *const u8,
    usage: c_uint,
    ctx: *mut XmlSecTransformCtx,
) -> *mut XmlSecTransform {
    // SAFETY: by the caller's contract.
    unsafe {
        let id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), href, usage);
        if id.is_null() {
            return std::ptr::null_mut();
        }
        let enabled = &raw mut (*ctx).enabled_transforms;
        if xmlSecPtrListGetSize(enabled) > 0 && xmlSecTransformIdListFind(enabled, id) != 1 {
            return std::ptr::null_mut();
        }
        let transform = xmlSecTransformCreate(id);
        let Some((_, klass)) = valid(transform) else {
            return std::ptr::null_mut();
        };
        if let Some(read_node) = klass.read_node
            && read_node(transform, node, ctx) < 0
        {
            xmlSecTransformDestroy(transform);
            return std::ptr::null_mut();
        }
        (*transform).here_node = node;
        transform
    }
}

/// `xmlSecTransformCtxNodeRead`: reads a transform from `node` and appends it.
///
/// # Safety
/// `ctx` is null or an initialized context; `node` is null or a live
/// element.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxNodeRead(
    ctx: *mut XmlSecTransformCtx,
    node: *mut XmlNode,
    usage: c_uint,
) -> *mut XmlSecTransform {
    contain(std::ptr::null_mut(), || {
        // SAFETY: by the caller's contract.
        unsafe {
            if building(ctx).is_none() || node.is_null() {
                return std::ptr::null_mut();
            }
            let transform = xmlSecTransformNodeRead(node, usage, ctx);
            if transform.is_null() {
                return transform;
            }
            if xmlSecTransformCtxAppend(ctx, transform) < 0 {
                xmlSecTransformDestroy(transform);
                return std::ptr::null_mut();
            }
            transform
        }
    })
}

/// `xmlSecTransformCtxNodesListRead`: reads every `dsig:Transform` child of
/// `node` in order and appends it, marked as specified by the document; any
/// other element child fails the read.
///
/// # Safety
/// As for [`xmlSecTransformCtxNodeRead`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxNodesListRead(
    ctx: *mut XmlSecTransformCtx,
    node: *mut XmlNode,
    usage: c_uint,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract; the children of a live element
        // are live.
        unsafe {
            if building(ctx).is_none() || node.is_null() || !readable() {
                return -1;
            }
            let mut current = xmlSecGetNextElementNode((*node).children);
            while !current.is_null()
                && xmlSecCheckNodeName(current, xmlSecNodeTransform.as_ptr(), xmlSecDSigNs.as_ptr())
                    != 0
            {
                let transform = xmlSecTransformNodeRead(current, usage, ctx);
                if transform.is_null() {
                    return -1;
                }
                (*transform).flags |= FLAGS_USER_SPECIFIED;
                if xmlSecTransformCtxAppend(ctx, transform) < 0 {
                    xmlSecTransformDestroy(transform);
                    return -1;
                }
                current = xmlSecGetNextElementNode((*current).next);
            }
            if current.is_null() { 0 } else { -1 }
        }
    })
}

/// A libxml2-allocated copy of `bytes` with a NUL.
fn duplicate(bytes: &[u8]) -> *mut u8 {
    let copy = malloc(bytes.len() + 1).cast::<u8>();
    if !copy.is_null() {
        // SAFETY: `copy` holds `bytes.len() + 1` bytes.
        unsafe {
            bytes.as_ptr().copy_to(copy, bytes.len());
            copy.add(bytes.len()).write(0);
        }
    }
    copy
}

/// `xmlSecTransformCtxSetUri`: records the URI of the chain's input and,
/// for a fragment, prepends the transform that selects it: `XPointer` for
/// `#xpointer(...)`, `#xmlns(...)` and bare names (as `xpointer(id('...'))`
/// without comments), or the `Visa3D` id lookup when the context asks for it.
///
/// # Safety
/// `ctx` is null or an initialized context; `uri` is null or
/// NUL-terminated; `here` is null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxSetUri(
    ctx: *mut XmlSecTransformCtx,
    uri: *const u8,
    here: *mut XmlNode,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(context) = building(ctx) else {
                return -1;
            };
            if !context.uri.is_null() || !context.xptr_expr.is_null() || here.is_null() {
                return -1;
            }
            if super::xmlSecTransformUriTypeCheck(context.enabled_uris, uri) != 1 {
                return -1;
            }
            let text = if uri.is_null() {
                &[][..]
            } else {
                CStr::from_ptr(uri.cast()).to_bytes()
            };
            if text.is_empty() {
                return 0;
            }
            let Some(hash) = text.iter().position(|&byte| byte == b'#') else {
                context.uri = duplicate(text);
                return if context.uri.is_null() { -1 } else { 0 };
            };
            if text == b"#xpointer(/)" {
                context.xptr_expr = duplicate(text);
                return if context.xptr_expr.is_null() { -1 } else { 0 };
            }
            context.uri = duplicate(&text[..hash]);
            context.xptr_expr = duplicate(&text[hash..]);
            if context.uri.is_null() || context.xptr_expr.is_null() {
                return -1;
            }
            let fragment = &text[hash..];
            select_fragment(ctx, fragment, here)
        }
    })
}

/// Prepends the transform that selects `fragment` (starting with `#`).
///
/// # Safety
/// `ctx` is an initialized context still building; `here` is a live node.
unsafe fn select_fragment(
    ctx: *mut XmlSecTransformCtx,
    fragment: &[u8],
    here: *mut XmlNode,
) -> c_int {
    // SAFETY: by the caller's contract.
    unsafe {
        let visa3d = (*ctx).flags & FLAGS_USE_VISA3D_HACK != 0;
        let (expression, kind) =
            if fragment.starts_with(b"#xpointer(") || fragment.starts_with(b"#xmlns(") {
                (fragment[1..].to_vec(), TREE)
            } else if visa3d {
                let transform = xmlSecTransformCtxCreateAndPrepend(ctx, builtin::visa3d_hack());
                if valid(transform).is_none() {
                    return -1;
                }
                let id = duplicate(&fragment[1..]);
                let result = builtin::xmlSecTransformVisa3DHackSetID(transform, id);
                free(id.cast::<c_void>());
                return result;
            } else {
                // A bare name is an id reference; `xpointer(id('...'))` handles
                // numeric and other names an XPointer shorthand cannot.
                let mut expression = b"xpointer(id('".to_vec();
                expression.extend_from_slice(&fragment[1..]);
                expression.extend_from_slice(b"'))");
                (expression, TREE_WITHOUT_COMMENTS)
            };
        let transform = xmlSecTransformCtxCreateAndPrepend(ctx, builtin::xpointer());
        if valid(transform).is_none() {
            return -1;
        }
        let expression = duplicate(&expression);
        let result = builtin::xmlSecTransformXPointerSetExpr(transform, expression, kind, here);
        free(expression.cast::<c_void>());
        result
    }
}

/// `xmlSecTransformCtxPrepare`: appends the memory-buffer terminal that
/// becomes `result`, prepends the XML parser or inclusive C14N when the
/// first transform cannot take `input_type`, runs the pre-execute callback,
/// and starts the run.
///
/// # Safety
/// `ctx` is null or an initialized context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxPrepare(
    ctx: *mut XmlSecTransformCtx,
    input_type: u8,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(context) = building(ctx) else {
                return -1;
            };
            if !context.result.is_null() {
                return -1;
            }
            let terminal = xmlSecTransformCtxCreateAndAppend(ctx, builtin::mem_buf());
            if valid(terminal).is_none() {
                return -1;
            }
            (*ctx).result = builtin::xmlSecTransformMemBufGetBuffer(terminal);
            if (*ctx).result.is_null() {
                return -1;
            }
            let first_type = xmlSecTransformGetDataType((*ctx).first, MODE_PUSH, ctx);
            if first_type & DATA_BIN == 0 && input_type & DATA_BIN != 0 {
                if xmlSecTransformCtxCreateAndPrepend(ctx, builtin::xml_parser()).is_null() {
                    return -1;
                }
            } else if first_type & DATA_XML == 0
                && input_type & DATA_XML != 0
                && xmlSecTransformCtxCreateAndPrepend(ctx, builtin::incl_c14n()).is_null()
            {
                return -1;
            }
            if let Some(callback) = (*ctx).pre_exec_callback
                && callback(ctx) < 0
            {
                return -1;
            }
            (*ctx).status = STATUS_WORKING;
        }
        0
    })
}

/// `xmlSecTransformCtxBinaryExecute`: runs the chain on `size` bytes.
///
/// # Safety
/// `ctx` is null or an initialized context; `data` is null or readable for
/// `size` bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxBinaryExecute(
    ctx: *mut XmlSecTransformCtx,
    data: *const u8,
    size: usize,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(context) = building(ctx) else {
                return -1;
            };
            if !context.result.is_null() || !context.uri.is_null() {
                return -1;
            }
            if xmlSecTransformCtxPrepare(ctx, DATA_BIN) < 0
                || xmlSecTransformPushBin((*ctx).first, data, size, 1, ctx) < 0
            {
                return -1;
            }
            (*ctx).status = STATUS_FINISHED;
        }
        0
    })
}

/// `xmlSecTransformCtxUriExecute`: runs the chain on the resource `uri`
/// names, read through the URI input transform.
///
/// # Safety
/// `ctx` is null or an initialized context; `uri` is null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxUriExecute(
    ctx: *mut XmlSecTransformCtx,
    uri: *const u8,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(context) = building(ctx) else {
                return -1;
            };
            if uri.is_null() {
                return -1;
            }
            if !context.uri.is_null()
                && uri != context.uri.cast_const()
                && super::super::tree::xmlStrEqual(uri, context.uri) == 0
            {
                return -1;
            }
            let input = xmlSecTransformCtxCreateAndPrepend(ctx, builtin::input_uri());
            if input.is_null() || builtin::xmlSecTransformInputURIOpen(input, uri) < 0 {
                return -1;
            }
            if xmlSecTransformCtxPrepare(ctx, DATA_UNKNOWN) < 0
                || xmlSecTransformPump(input, (*input).next, ctx) < 0
                || builtin::xmlSecTransformInputURIClose(input) < 0
            {
                return -1;
            }
            (*ctx).status = STATUS_FINISHED;
        }
        0
    })
}

/// `xmlSecTransformCtxXmlExecute`: runs the chain on the node set `nodes`.
///
/// # Safety
/// `ctx` is null or an initialized context; `nodes` is null or a node set.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxXmlExecute(
    ctx: *mut XmlSecTransformCtx,
    nodes: *mut XmlSecNodeSet,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(context) = building(ctx) else {
                return -1;
            };
            if !context.result.is_null() || nodes.is_null() {
                return -1;
            }
            if !context.uri.is_null() && !CStr::from_ptr(context.uri.cast()).is_empty() {
                return -1;
            }
            if xmlSecTransformCtxPrepare(ctx, DATA_XML) < 0
                || xmlSecTransformPushXml((*ctx).first, nodes, ctx) < 0
            {
                return -1;
            }
            (*ctx).status = STATUS_FINISHED;
        }
        0
    })
}

/// `xmlSecTransformCtxExecute`: runs the chain on `doc`: the whole document
/// without comments for an empty URI, the `XPointer` selection for a
/// same-document fragment, or the resource for any other URI.
///
/// # Safety
/// `ctx` is null or an initialized context; `doc` is null or a live
/// document.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxExecute(
    ctx: *mut XmlSecTransformCtx,
    doc: *mut XmlDoc,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(context) = building(ctx) else {
                return -1;
            };
            if !context.result.is_null() || doc.is_null() {
                return -1;
            }
            let empty = |text: *mut u8| text.is_null() || CStr::from_ptr(text.cast()).is_empty();
            if !empty(context.uri) {
                return xmlSecTransformCtxUriExecute(ctx, context.uri);
            }
            // The XPointer transform selects its own nodes from the document.
            let nodes = if empty(context.xptr_expr) {
                xmlSecNodeSetGetChildren(doc, std::ptr::null_mut(), 0, 0)
            } else {
                xmlSecNodeSetCreate(doc, std::ptr::null_mut(), NORMAL)
            };
            if nodes.is_null() {
                return -1;
            }
            let result = xmlSecTransformCtxXmlExecute(ctx, nodes);
            xmlSecNodeSetDestroy(nodes);
            result
        }
    })
}

/// The C string or `NULL` for display.
///
/// # Safety
/// `text` is null or NUL-terminated.
unsafe fn or_null(text: *const u8) -> String {
    // SAFETY: by the caller's contract.
    unsafe { klass_text(text) }
}

/// `xmlSecTransformCtxDebugDump`.
///
/// # Safety
/// `ctx` is null or an initialized context; `output` is null or a C
/// `FILE*`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxDebugDump(
    ctx: *mut XmlSecTransformCtx,
    output: *mut c_void,
) {
    contain((), || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(context) = ctx.as_mut() else {
                return;
            };
            if output.is_null() {
                return;
            }
            write_stream(
                output,
                &format!(
                    "== TRANSFORMS CTX (status={})\n== flags: 0x{:08x}\n== maxDepth: {}\n",
                    context.status, context.flags, context.max_depth
                ),
            );
            if xmlSecPtrListGetSize(&raw mut context.enabled_transforms) > 0 {
                write_stream(output, "== enabled transforms: ");
                xmlSecTransformIdListDebugDump(&raw mut context.enabled_transforms, output);
            } else {
                write_stream(output, "== enabled transforms: all\n");
            }
            write_stream(
                output,
                &format!(
                    "=== uri: {}\n=== uri xpointer expr: {}\n",
                    or_null(context.uri),
                    or_null(context.xptr_expr)
                ),
            );
            let mut transform = context.first;
            while !transform.is_null() {
                xmlSecTransformDebugDump(transform, output);
                transform = (*transform).next;
            }
        }
    });
}

/// `xmlSecTransformCtxDebugXmlDump`.
///
/// # Safety
/// As for [`xmlSecTransformCtxDebugDump`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxDebugXmlDump(
    ctx: *mut XmlSecTransformCtx,
    output: *mut c_void,
) {
    contain((), || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(context) = ctx.as_mut() else {
                return;
            };
            if output.is_null() {
                return;
            }
            write_stream(
                output,
                &format!(
                    "<TransformCtx status=\"{}\">\n<Flags>{:08x}</Flags>\n<maxDepth>{}</maxDepth>\n",
                    context.status, context.flags, context.max_depth
                ),
            );
            if xmlSecPtrListGetSize(&raw mut context.enabled_transforms) > 0 {
                write_stream(output, "<EnabledTransforms>\n");
                xmlSecTransformIdListDebugXmlDump(&raw mut context.enabled_transforms, output);
                write_stream(output, "</EnabledTransforms>\n");
            } else {
                write_stream(output, "<EnabledTransforms>all</EnabledTransforms>\n");
            }
            let printed = |text: *mut u8| {
                if text.is_null() {
                    String::new()
                } else {
                    xml_text(&klass_text(text))
                }
            };
            write_stream(
                output,
                &format!(
                    "<Uri>{}</Uri>\n<UriXPointer>{}</UriXPointer>\n",
                    printed(context.uri),
                    printed(context.xptr_expr)
                ),
            );
            let mut transform = context.first;
            while !transform.is_null() {
                xmlSecTransformDebugXmlDump(transform, output);
                transform = (*transform).next;
            }
            write_stream(output, "</TransformCtx>\n");
        }
    });
}
