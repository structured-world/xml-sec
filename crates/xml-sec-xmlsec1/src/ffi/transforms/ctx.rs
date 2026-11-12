//! `xmlSecTransformCtx`: a chain of transforms and the state of one run.

use std::ffi::{CStr, c_int, c_uint, c_void};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use super::super::buffer::XmlSecBuffer;
use super::super::errors::{self, check, here};
use super::super::keysdata::{
    XmlSecKeyData, XmlSecKeyDataKlass, xmlSecKeyDataCreate, xmlSecKeyDataDestroy,
    xmlSecKeyDataListGetKlass,
};
use super::super::list::{
    XmlSecPtrList, xmlSecPtrListAdd, xmlSecPtrListCopy, xmlSecPtrListCreate, xmlSecPtrListDestroy,
    xmlSecPtrListFinalize, xmlSecPtrListGetItem, xmlSecPtrListGetSize, xmlSecPtrListInitialize,
};
use super::super::nodeset::{
    NORMAL, XmlSecNodeSet, xmlSecNodeSetCreate, xmlSecNodeSetDestroy, xmlSecNodeSetGetChildren,
};
use super::super::strings::{xmlSecAttrAlgorithm, xmlSecDSigNs, xmlSecNodeTransform};
use super::super::tree::{XmlDoc, XmlNode, c_text, name_for_report, nodes};
use super::super::xmltree::{next_element, xmlSecCheckNodeName, xmlSecPrintXmlString};
use super::super::{contain, free, malloc, policy, write_stream};
use super::{
    DATA_BIN, DATA_UNKNOWN, DATA_XML, FLAGS_USER_SPECIFIED, MODE_PUSH, STATUS_FINISHED,
    STATUS_NONE, STATUS_WORKING, XmlSecTransform, XmlSecTransformKlass, builtin, io, klass_text,
    parser, valid, valid_or, xmlSecTransformConnect, xmlSecTransformCreate,
    xmlSecTransformDebugDump, xmlSecTransformDebugXmlDump, xmlSecTransformDestroy,
    xmlSecTransformGetDataType, xmlSecTransformIdListDebugDump, xmlSecTransformIdListDebugXmlDump,
    xmlSecTransformIdListFind, xmlSecTransformIdListFindByHref, xmlSecTransformIdListGetKlass,
    xmlSecTransformIdsGet, xmlSecTransformPump, xmlSecTransformPushBin, xmlSecTransformPushXml,
    xpath,
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

/// One run of a context: the policy it runs under and what it has spent of
/// the policy's per-chain budgets. Every transform of the chain charges the
/// same budget under the same policy revision, as the core charges one
/// budget across a reference's transforms; the context's `reserved0` holds
/// it from its first use until the context is reset.
#[derive(Default)]
pub(crate) struct RunBudget {
    pub(crate) base64_input: usize,
    pub(crate) base64_output: usize,
    /// Octets read from external resources through the input callbacks.
    pub(crate) external_resources: usize,
    /// The policy revision of the run, pinned at its first read or handed
    /// down by the `KeyInfo` read that runs the chain.
    policy: Option<policy::Pinned>,
}

/// The policy revision the run of `ctx` runs under, pinned at its first
/// read; reported at `here` when the profile is unavailable.
///
/// # Safety
/// `ctx` is an initialized context.
pub(crate) unsafe fn run_policy(
    ctx: *mut XmlSecTransformCtx,
    here: errors::Here,
) -> Option<policy::Pinned> {
    // SAFETY: by the caller's contract.
    let run = unsafe { run_budget(ctx) };
    if run.policy.is_none() {
        run.policy = Some(policy::Pinned::current(here)?);
    }
    run.policy.clone()
}

/// Makes `pinned` the policy of the run of `ctx` unless the run has one, so
/// a chain a `KeyInfo` read runs reads the revision of that read.
///
/// # Safety
/// `ctx` is an initialized context.
pub(crate) unsafe fn seed_policy(ctx: *mut XmlSecTransformCtx, pinned: &policy::Pinned) {
    // SAFETY: by the caller's contract.
    let run = unsafe { run_budget(ctx) };
    if run.policy.is_none() {
        run.policy = Some(pinned.clone());
    }
}

/// The run budget of `ctx`, created on first use.
///
/// # Safety
/// `ctx` is an initialized context.
pub(crate) unsafe fn run_budget<'a>(ctx: *mut XmlSecTransformCtx) -> &'a mut RunBudget {
    // SAFETY: by the caller's contract; `reserved0` is null or the budget
    // this function created, which only reset frees.
    unsafe {
        if (*ctx).reserved0.is_null() {
            (*ctx).reserved0 = Box::into_raw(Box::<RunBudget>::default()).cast();
        }
        &mut *(*ctx).reserved0.cast::<RunBudget>()
    }
}

/// A policy limit as a charge names it in its report.
#[derive(Clone, Copy)]
pub(crate) struct Limit {
    pub(crate) name: &'static str,
    pub(crate) max: usize,
}

/// Charges `amount` to `spent` within `limit`; refused, and reported for
/// `object` at `here`, once the total would pass it.
pub(crate) fn charge(
    spent: &mut usize,
    amount: usize,
    limit: Limit,
    here: errors::Here,
    object: *const std::ffi::c_char,
) -> Option<()> {
    let Some(total) = spent
        .checked_add(amount)
        .filter(|total| *total <= limit.max)
    else {
        errors::limit_exceeded(here, object, limit.name, limit.max);
        return None;
    };
    *spent = total;
    Some(())
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

/// `xmlSecTransformCtxExtraKeyDataGet`: the context's extra key data of
/// klass `id`, or null.
///
/// # Safety
/// `ctx` is null or a context; `id` is null or a key-data klass.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxExtraKeyDataGet(
    ctx: *mut XmlSecTransformCtx,
    id: *const XmlSecKeyDataKlass,
) -> *mut XmlSecKeyData {
    contain(std::ptr::null_mut(), || {
        let null = std::ptr::null_mut();
        check!(
            !ctx.is_null(),
            "xmlSecTransformCtxExtraKeyDataGet",
            c"ctx != NULL",
            null
        );
        check!(
            !id.is_null(),
            "xmlSecTransformCtxExtraKeyDataGet",
            c"dataId != xmlSecKeyDataIdUnknown",
            null
        );
        // SAFETY: by the caller's contract; the list holds key data.
        unsafe {
            let list = (*ctx).extra_key_data;
            if list.is_null() {
                return null;
            }
            (0..xmlSecPtrListGetSize(list))
                .map(|pos| xmlSecPtrListGetItem(list, pos).cast::<XmlSecKeyData>())
                .find(|data| !data.is_null() && std::ptr::eq((**data).id, id))
                .unwrap_or(std::ptr::null_mut())
        }
    })
}

/// The context's extra key-data list, created on first use; null after
/// reporting the failure as the entry point at `here`.
///
/// # Safety
/// `ctx` is a context.
unsafe fn extra_key_data(ctx: *mut XmlSecTransformCtx, here: errors::Here) -> *mut XmlSecPtrList {
    // SAFETY: by the caller's contract; the context owns the list.
    unsafe {
        if (*ctx).extra_key_data.is_null() {
            (*ctx).extra_key_data = xmlSecPtrListCreate(xmlSecKeyDataListGetKlass());
            if (*ctx).extra_key_data.is_null() {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecPtrListCreate(xmlSecKeyDataListId)",
                );
            }
        }
        (*ctx).extra_key_data
    }
}

/// `xmlSecTransformCtxExtraKeyDataEnsure`: the context's extra key data of
/// klass `id`, created and owned by the context when missing.
///
/// # Safety
/// `ctx` is null or a context; `id` is null or a key-data klass.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxExtraKeyDataEnsure(
    ctx: *mut XmlSecTransformCtx,
    id: *const XmlSecKeyDataKlass,
) -> *mut XmlSecKeyData {
    contain(std::ptr::null_mut(), || {
        // SAFETY: by the caller's contract; a new object is destroyed when
        // the list does not take it.
        unsafe {
            let null = std::ptr::null_mut();
            check!(
                !ctx.is_null(),
                "xmlSecTransformCtxExtraKeyDataEnsure",
                c"ctx != NULL",
                null
            );
            check!(
                !id.is_null(),
                "xmlSecTransformCtxExtraKeyDataEnsure",
                c"dataId != xmlSecKeyDataIdUnknown",
                null
            );
            let here = here!("xmlSecTransformCtxExtraKeyDataEnsure");
            let existing = xmlSecTransformCtxExtraKeyDataGet(ctx, id);
            if !existing.is_null() {
                return existing;
            }
            let list = extra_key_data(ctx, here);
            if list.is_null() {
                return null;
            }
            let data = xmlSecKeyDataCreate(id);
            if data.is_null() {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecKeyDataCreate",
                    &format!("dataId={}", klass_text((*id).name)),
                );
                return data;
            }
            if xmlSecPtrListAdd(list, data.cast()) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecPtrListAdd");
                xmlSecKeyDataDestroy(data);
                return null;
            }
            data
        }
    })
}

/// `xmlSecTransformCtxExtraKeyDataAdopt`: the context takes `data`, unless
/// it already holds key data of the same klass.
///
/// # Safety
/// `ctx` is null or a context; `data` is null or a key-data object the
/// caller gives up on success.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCtxExtraKeyDataAdopt(
    ctx: *mut XmlSecTransformCtx,
    data: *mut XmlSecKeyData,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            check!(
                !ctx.is_null(),
                "xmlSecTransformCtxExtraKeyDataAdopt",
                c"ctx != NULL",
                -1
            );
            check!(
                !data.is_null(),
                "xmlSecTransformCtxExtraKeyDataAdopt",
                c"data != NULL",
                -1
            );
            check!(
                !(*data).id.is_null(),
                "xmlSecTransformCtxExtraKeyDataAdopt",
                c"data->id != xmlSecKeyDataIdUnknown",
                -1
            );
            let here = here!("xmlSecTransformCtxExtraKeyDataAdopt");
            if !xmlSecTransformCtxExtraKeyDataGet(ctx, (*data).id).is_null() {
                errors::invalid_data(
                    here,
                    std::ptr::null(),
                    &format!(
                        "extra key data of type '{}' already exists",
                        klass_text((*(*data).id).name)
                    ),
                );
                return -1;
            }
            let list = extra_key_data(ctx, here);
            if list.is_null() {
                return -1;
            }
            if xmlSecPtrListAdd(list, data.cast()) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecPtrListAdd");
                return -1;
            }
            0
        }
    })
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
            errors::malloc_failed(
                here!("xmlSecTransformCtxCreate"),
                std::ptr::null(),
                size_of::<XmlSecTransformCtx>(),
            );
            return ctx;
        }
        // SAFETY: a fresh allocation of a context's size.
        if unsafe { xmlSecTransformCtxInitialize(ctx) } < 0 {
            errors::internal(
                here!("xmlSecTransformCtxCreate"),
                std::ptr::null(),
                c"xmlSecTransformCtxInitialize",
            );
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
        check!(!ctx.is_null(), "xmlSecTransformCtxDestroy", c"ctx != NULL",);
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
        check!(
            !ctx.is_null(),
            "xmlSecTransformCtxInitialize",
            c"ctx != NULL",
            -1
        );
        // SAFETY: `ctx` is writable; it is zeroed before any field is read.
        unsafe {
            ctx.write_bytes(0, 1);
            if xmlSecPtrListInitialize(
                &raw mut (*ctx).enabled_transforms,
                xmlSecTransformIdListGetKlass(),
            ) < 0
            {
                errors::internal(
                    here!("xmlSecTransformCtxInitialize"),
                    std::ptr::null(),
                    c"xmlSecPtrListInitialize(xmlSecTransformIdListId)",
                );
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
        check!(!ctx.is_null(), "xmlSecTransformCtxFinalize", c"ctx != NULL",);
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
        check!(!ctx.is_null(), "xmlSecTransformCtxReset", c"ctx != NULL",);
        // SAFETY: an initialized context whose chain, strings and lists it
        // owns.
        unsafe {
            let context = &mut *ctx;
            context.result = std::ptr::null_mut();
            context.status = STATUS_NONE;
            if !context.reserved0.is_null() {
                drop(Box::from_raw(context.reserved0.cast::<RunBudget>()));
                context.reserved0 = std::ptr::null_mut();
            }
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
        check!(
            !dst.is_null(),
            "xmlSecTransformCtxCopyUserPref",
            c"dst != NULL",
            -1
        );
        check!(
            !src.is_null(),
            "xmlSecTransformCtxCopyUserPref",
            c"src != NULL",
            -1
        );
        // SAFETY: initialized contexts.
        unsafe {
            let (target, source) = (&mut *dst, &mut *src);
            target.user_data = source.user_data;
            target.flags = source.flags;
            target.max_depth = source.max_depth;
            target.enabled_uris = source.enabled_uris;
            target.pre_exec_callback = source.pre_exec_callback;
            if xmlSecPtrListCopy(
                &raw mut target.enabled_transforms,
                &raw mut source.enabled_transforms,
            ) < 0
            {
                errors::internal(
                    here!("xmlSecTransformCtxCopyUserPref"),
                    std::ptr::null(),
                    c"xmlSecPtrListCopy(enabledTransforms)",
                );
                return -1;
            }
        }
        0
    })
}

/// The context `$ctx` still building its chain, after libxmlsec1's
/// assertions inside the entry point `$func`, or `$ret`.
macro_rules! building_or {
    ($ctx:expr, $func:literal, $ret:expr) => {{
        check!(!$ctx.is_null(), $func, c"ctx != NULL", $ret);
        // SAFETY: the caller passes an initialized context.
        let context = unsafe { &mut *$ctx };
        check!(
            context.status == STATUS_NONE,
            $func,
            c"ctx->status == xmlSecTransformStatusNone",
            $ret
        );
        context
    }};
}

/// As [`building_or`], for a context that has no result yet, with the
/// assertions in libxmlsec1's order.
macro_rules! fresh_or {
    ($ctx:expr, $func:literal, $ret:expr) => {{
        check!(!$ctx.is_null(), $func, c"ctx != NULL", $ret);
        // SAFETY: the caller passes an initialized context.
        let context = unsafe { &mut *$ctx };
        check!(
            context.result.is_null(),
            $func,
            c"ctx->result == NULL",
            $ret
        );
        check!(
            context.status == STATUS_NONE,
            $func,
            c"ctx->status == xmlSecTransformStatusNone",
            $ret
        );
        context
    }};
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
        let context = building_or!(ctx, "xmlSecTransformCtxAppend", -1);
        let (_, klass) = valid_or!(transform, "xmlSecTransformCtxAppend", -1);
        if context.last.is_null() {
            check!(
                context.first.is_null(),
                "xmlSecTransformCtxAppend",
                c"ctx->first == NULL",
                -1
            );
            context.first = transform;
        // SAFETY: by the caller's contract.
        } else if unsafe { xmlSecTransformConnect(context.last, transform, ctx) } < 0 {
            errors::internal(
                here!("xmlSecTransformCtxAppend"),
                klass.name.cast(),
                c"xmlSecTransformConnect",
            );
            return -1;
        }
        context.last = transform;
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
        let context = building_or!(ctx, "xmlSecTransformCtxPrepend", -1);
        let (_, klass) = valid_or!(transform, "xmlSecTransformCtxPrepend", -1);
        if context.first.is_null() {
            check!(
                context.last.is_null(),
                "xmlSecTransformCtxPrepend",
                c"ctx->last == NULL",
                -1
            );
            context.last = transform;
        // SAFETY: by the caller's contract.
        } else if unsafe { xmlSecTransformConnect(transform, context.first, ctx) } < 0 {
            errors::internal(
                here!("xmlSecTransformCtxPrepend"),
                klass.name.cast(),
                c"xmlSecTransformConnect",
            );
            return -1;
        }
        context.first = transform;
        0
    })
}

/// Creates a transform of `id` and adds it at one end of the chain with
/// `add`, named `added` in reports from the entry point at `here`.
///
/// # Safety
/// `ctx` is a context still building; `id` is a klass.
unsafe fn create_and_add(
    ctx: *mut XmlSecTransformCtx,
    id: *const XmlSecTransformKlass,
    (add, added): (
        unsafe extern "C" fn(*mut XmlSecTransformCtx, *mut XmlSecTransform) -> c_int,
        &CStr,
    ),
    here: errors::Here,
) -> *mut XmlSecTransform {
    // SAFETY: by the caller's contract.
    unsafe {
        let name = (*id).name.cast();
        let transform = xmlSecTransformCreate(id);
        if valid(transform).is_none() {
            errors::internal(here, name, c"xmlSecTransformCreate");
            return std::ptr::null_mut();
        }
        if add(ctx, transform) < 0 {
            errors::internal(here, name, added);
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
    contain(std::ptr::null_mut(), || {
        let null = std::ptr::null_mut();
        building_or!(ctx, "xmlSecTransformCtxCreateAndAppend", null);
        check!(
            !id.is_null(),
            "xmlSecTransformCtxCreateAndAppend",
            c"id != xmlSecTransformIdUnknown",
            null
        );
        // SAFETY: a building context and a klass.
        unsafe {
            create_and_add(
                ctx,
                id,
                (xmlSecTransformCtxAppend, c"xmlSecTransformCtxAppend"),
                here!("xmlSecTransformCtxCreateAndAppend"),
            )
        }
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
    contain(std::ptr::null_mut(), || {
        let null = std::ptr::null_mut();
        building_or!(ctx, "xmlSecTransformCtxCreateAndPrepend", null);
        check!(
            !id.is_null(),
            "xmlSecTransformCtxCreateAndPrepend",
            c"id != xmlSecTransformIdUnknown",
            null
        );
        // SAFETY: a building context and a klass.
        unsafe {
            create_and_add(
                ctx,
                id,
                (xmlSecTransformCtxPrepend, c"xmlSecTransformCtxPrepend"),
                here!("xmlSecTransformCtxCreateAndPrepend"),
            )
        }
    })
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
        let null = std::ptr::null_mut();
        check!(
            !node.is_null(),
            "xmlSecTransformNodeRead",
            c"node != NULL",
            null
        );
        check!(
            !ctx.is_null(),
            "xmlSecTransformNodeRead",
            c"transformCtx != NULL",
            null
        );
        let here = here!("xmlSecTransformNodeRead");
        // SAFETY: the attribute name is a NUL-terminated constant.
        let href = unsafe { c_text(xmlSecAttrAlgorithm.as_ptr()) }
            .and_then(|attribute| nodes::property(node, attribute))
            .and_then(|href| std::ffi::CString::new(href).ok());
        let Some(href) = href else {
            // SAFETY: a report about the caller's node.
            unsafe {
                errors::invalid_node_attribute(here, node, c"Algorithm", std::ptr::null(), "empty");
            }
            return null;
        };
        // SAFETY: an initialized context; the value is NUL-terminated.
        unsafe { read_algorithm(node, href.as_ptr().cast(), usage, ctx) }
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
        let here = here!("xmlSecTransformNodeRead");
        let algorithm = || format!("href={}", klass_text(href));
        let id = xmlSecTransformIdListFindByHref(xmlSecTransformIdsGet(), href, usage);
        if id.is_null() {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecTransformIdListFindByHref",
                &algorithm(),
            );
            return std::ptr::null_mut();
        }
        let name = (*id).name.cast();
        let enabled = &raw mut (*ctx).enabled_transforms;
        if xmlSecPtrListGetSize(enabled) > 0 && xmlSecTransformIdListFind(enabled, id) != 1 {
            errors::report(
                here,
                name,
                std::ptr::null(),
                errors::R_TRANSFORM_DISABLED,
                &algorithm(),
            );
            return std::ptr::null_mut();
        }
        let transform = xmlSecTransformCreate(id);
        let Some((_, klass)) = valid(transform) else {
            errors::internal(here, name, c"xmlSecTransformCreate(id)");
            return std::ptr::null_mut();
        };
        if let Some(read_node) = klass.read_node
            && read_node(transform, node, ctx) < 0
        {
            errors::internal(here, name, c"readNode");
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
        let null = std::ptr::null_mut();
        building_or!(ctx, "xmlSecTransformCtxNodeRead", null);
        check!(
            !node.is_null(),
            "xmlSecTransformCtxNodeRead",
            c"node != NULL",
            null
        );
        let here = here!("xmlSecTransformCtxNodeRead");
        // SAFETY: by the caller's contract.
        unsafe {
            let transform = xmlSecTransformNodeRead(node, usage, ctx);
            if transform.is_null() {
                let name = name_for_report(node);
                errors::internal(here, name.as_ptr(), c"xmlSecTransformNodeRead");
                return transform;
            }
            if xmlSecTransformCtxAppend(ctx, transform) < 0 {
                errors::internal(
                    here,
                    (*(*transform).id).name.cast(),
                    c"xmlSecTransformCtxAppend",
                );
                xmlSecTransformDestroy(transform);
                return null;
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
        building_or!(ctx, "xmlSecTransformCtxNodesListRead", -1);
        check!(
            !node.is_null(),
            "xmlSecTransformCtxNodesListRead",
            c"node != NULL",
            -1
        );
        let here = here!("xmlSecTransformCtxNodesListRead");
        // SAFETY: by the caller's contract.
        unsafe {
            let mut current = next_element(nodes::first_child(node));
            while !current.is_null()
                && xmlSecCheckNodeName(current, xmlSecNodeTransform.as_ptr(), xmlSecDSigNs.as_ptr())
                    != 0
            {
                let transform = xmlSecTransformNodeRead(current, usage, ctx);
                if transform.is_null() {
                    let name = name_for_report(current);
                    errors::internal(here, name.as_ptr(), c"xmlSecTransformNodeRead");
                    return -1;
                }
                (*transform).flags |= FLAGS_USER_SPECIFIED;
                if xmlSecTransformCtxAppend(ctx, transform) < 0 {
                    errors::internal(
                        here,
                        (*(*transform).id).name.cast(),
                        c"xmlSecTransformCtxAppend",
                    );
                    xmlSecTransformDestroy(transform);
                    return -1;
                }
                current = next_element(nodes::next(current));
            }
            if current.is_null() {
                0
            } else {
                errors::unexpected_node(here, current, std::ptr::null());
                -1
            }
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
        check!(
            !ctx.is_null(),
            "xmlSecTransformCtxSetUri",
            c"ctx != NULL",
            -1
        );
        // SAFETY: the caller passes an initialized context.
        let context = unsafe { &mut *ctx };
        check!(
            context.uri.is_null(),
            "xmlSecTransformCtxSetUri",
            c"ctx->uri == NULL",
            -1
        );
        check!(
            context.xptr_expr.is_null(),
            "xmlSecTransformCtxSetUri",
            c"ctx->xptrExpr == NULL",
            -1
        );
        check!(
            context.status == STATUS_NONE,
            "xmlSecTransformCtxSetUri",
            c"ctx->status == xmlSecTransformStatusNone",
            -1
        );
        check!(
            !here.is_null(),
            "xmlSecTransformCtxSetUri",
            c"hereNode != NULL",
            -1
        );
        let location = here!("xmlSecTransformCtxSetUri");
        // SAFETY: by the caller's contract.
        unsafe {
            let text = if uri.is_null() {
                &[][..]
            } else {
                CStr::from_ptr(uri.cast()).to_bytes()
            };
            if super::xmlSecTransformUriTypeCheck(context.enabled_uris, uri) != 1 {
                // libxmlsec1 reports this refusal with the key-data-size
                // reason; a drop-in reports the same code.
                errors::report(
                    location,
                    std::ptr::null(),
                    std::ptr::null(),
                    errors::R_INVALID_KEY_DATA_SIZE,
                    &format!("uri={}", text_or_null(uri, text)),
                );
                return -1;
            }
            if text.is_empty() {
                return 0;
            }
            let Some(hash) = text.iter().position(|&byte| byte == b'#') else {
                context.uri = duplicate(text);
                return stored(context.uri, location, text);
            };
            if text == b"#xpointer(/)" {
                context.xptr_expr = duplicate(text);
                return stored(context.xptr_expr, location, text);
            }
            context.uri = duplicate(&text[..hash]);
            if stored(context.uri, location, text) < 0 {
                return -1;
            }
            context.xptr_expr = duplicate(&text[hash..]);
            if stored(context.xptr_expr, location, &text[hash..]) < 0 {
                return -1;
            }
            let fragment = &text[hash..];
            select_fragment(ctx, fragment, here)
        }
    })
}

/// `uri` for a report: its text, or `NULL` as libxmlsec1's
/// `xmlSecErrorsSafeString` writes a null string.
fn text_or_null(uri: *const u8, text: &[u8]) -> std::borrow::Cow<'_, str> {
    if uri.is_null() {
        "NULL".into()
    } else {
        String::from_utf8_lossy(text)
    }
}

/// 0 when `copy` holds the copy of `text`, otherwise reports libxmlsec1's
/// `xmlSecStrdupError` and returns -1.
fn stored(copy: *mut u8, here: errors::Here, text: &[u8]) -> c_int {
    if copy.is_null() {
        errors::strdup_failed(here, std::ptr::null(), text);
        -1
    } else {
        0
    }
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
    let location = here!("xmlSecTransformCtxSetUri");
    // SAFETY: by the caller's contract.
    unsafe {
        let visa3d = (*ctx).flags & FLAGS_USE_VISA3D_HACK != 0;
        let (expression, kind) =
            if fragment.starts_with(b"#xpointer(") || fragment.starts_with(b"#xmlns(") {
                (fragment[1..].to_vec(), TREE)
            } else if visa3d {
                let transform = xmlSecTransformCtxCreateAndPrepend(ctx, xpath::visa3d_hack());
                let Some((_, klass)) = valid(transform) else {
                    errors::internal(
                        location,
                        std::ptr::null(),
                        c"xmlSecTransformCtxCreateAndPrepend(xmlSecTransformVisa3DHackId)",
                    );
                    return -1;
                };
                let id = duplicate(&fragment[1..]);
                let result = xpath::xmlSecTransformVisa3DHackSetID(transform, id);
                free(id.cast::<c_void>());
                if result < 0 {
                    errors::internal(
                        location,
                        klass.name.cast(),
                        c"xmlSecTransformVisa3DHackSetID",
                    );
                }
                return result;
            } else {
                // A bare name is an id reference; `xpointer(id('...'))` handles
                // numeric and other names an XPointer shorthand cannot. The
                // name is the content of an XPath string literal inside
                // XPointer scheme data, so a quote would end the literal, and
                // a parenthesis or circumflex would change the scheme data
                // (XPointer Framework section 3.1, `escaped`); libxmlsec1
                // copies it unchecked and selects whatever it then spells.
                if fragment[1..]
                    .iter()
                    .any(|byte| matches!(byte, b'\'' | b'(' | b')' | b'^'))
                {
                    errors::invalid_data(
                        location,
                        std::ptr::null(),
                        &format!(
                            "id={}; reason=not an XPointer string literal",
                            String::from_utf8_lossy(&fragment[1..])
                        ),
                    );
                    return -1;
                }
                let mut expression = b"xpointer(id('".to_vec();
                expression.extend_from_slice(&fragment[1..]);
                expression.extend_from_slice(b"'))");
                (expression, TREE_WITHOUT_COMMENTS)
            };
        let transform = xmlSecTransformCtxCreateAndPrepend(ctx, xpath::xpointer());
        let Some((_, klass)) = valid(transform) else {
            errors::internal(
                location,
                std::ptr::null(),
                c"xmlSecTransformCtxCreateAndPrepend(xmlSecTransformXPointerId)",
            );
            return -1;
        };
        let copy = duplicate(&expression);
        if copy.is_null() {
            errors::malloc_failed(location, std::ptr::null(), expression.len() + 1);
            return -1;
        }
        let result = xpath::xmlSecTransformXPointerSetExpr(transform, copy, kind, here);
        free(copy.cast::<c_void>());
        if result < 0 {
            errors::internal(
                location,
                klass.name.cast(),
                c"xmlSecTransformXPointerSetExpr",
            );
        }
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
        let context = fresh_or!(ctx, "xmlSecTransformCtxPrepare", -1);
        let here = here!("xmlSecTransformCtxPrepare");
        // The chain is bounded by the policy as a core reference's is:
        // every execution passes here, before any transform runs, and
        // the bound also limits the push recursion through the chain.
        // SAFETY: an initialized context, reached through its borrow.
        let Some(pinned) = (unsafe { run_policy(&raw mut *context, here) }) else {
            return -1;
        };
        let max = pinned.verification.resources.max_transforms_per_reference;
        let mut length = 0usize;
        let mut current = context.first;
        while !current.is_null() {
            length += 1;
            if length > max {
                errors::limit_exceeded(here, std::ptr::null(), "max_transforms_per_reference", max);
                return -1;
            }
            // SAFETY: the chain's transforms are live.
            current = unsafe { (*current).next };
        }
        // SAFETY: a building context; its transforms are live.
        unsafe {
            let terminal = xmlSecTransformCtxCreateAndAppend(ctx, builtin::mem_buf());
            let Some((_, klass)) = valid(terminal) else {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxCreateAndAppend(xmlSecTransformMemBufId)",
                );
                return -1;
            };
            (*ctx).result = builtin::xmlSecTransformMemBufGetBuffer(terminal);
            if (*ctx).result.is_null() {
                errors::internal(
                    here,
                    klass.name.cast(),
                    c"xmlSecTransformMemBufGetBuffer(xmlSecTransformMemBufId)",
                );
                return -1;
            }
            let first_type = xmlSecTransformGetDataType((*ctx).first, MODE_PUSH, ctx);
            if first_type & DATA_BIN == 0 && input_type & DATA_BIN != 0 {
                if xmlSecTransformCtxCreateAndPrepend(ctx, parser::xml_parser()).is_null() {
                    errors::internal(
                        here,
                        std::ptr::null(),
                        c"xmlSecTransformCtxCreateAndPrepend(xmlSecTransformXmlParserId)",
                    );
                    return -1;
                }
            } else if first_type & DATA_XML == 0 && input_type & DATA_XML != 0 {
                // Base64 reads the text of a node set (XMLDSig 1.1 section 6.6.2),
                // as Connect gives it after a node-set transform; libxmlsec1
                // canonicalizes here, which feeds markup to the decoder.
                let adapter = if std::ptr::eq((*(*ctx).first).id, builtin::base64()) {
                    builtin::remove_xml_tags_c14n()
                } else {
                    builtin::incl_c14n()
                };
                if xmlSecTransformCtxCreateAndPrepend(ctx, adapter).is_null() {
                    errors::internal(
                        here,
                        std::ptr::null(),
                        c"xmlSecTransformCtxCreateAndPrepend(xmlSecTransformInclC14NId)",
                    );
                    return -1;
                }
            }
            if let Some(callback) = (*ctx).pre_exec_callback
                && callback(ctx) < 0
            {
                errors::internal(here, std::ptr::null(), c"ctx->preExecCallback");
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
        let context = fresh_or!(ctx, "xmlSecTransformCtxBinaryExecute", -1);
        check!(
            context.uri.is_null(),
            "xmlSecTransformCtxBinaryExecute",
            c"ctx->uri == NULL",
            -1
        );
        let here = here!("xmlSecTransformCtxBinaryExecute");
        // SAFETY: by the caller's contract.
        unsafe {
            if xmlSecTransformCtxPrepare(ctx, DATA_BIN) < 0 {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxPrepare(TypeBin)",
                );
                return -1;
            }
            if xmlSecTransformPushBin((*ctx).first, data, size, 1, ctx) < 0 {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformPushBin",
                    &format!("dataSize={size}"),
                );
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
        let context = building_or!(ctx, "xmlSecTransformCtxUriExecute", -1);
        check!(
            !uri.is_null(),
            "xmlSecTransformCtxUriExecute",
            c"uri != NULL",
            -1
        );
        check!(
            context.uri.is_null()
                || uri == context.uri.cast_const()
                // SAFETY: both strings are NUL-terminated.
                || unsafe { super::super::tree::xmlStrEqual(uri, context.uri) } != 0,
            "xmlSecTransformCtxUriExecute",
            c"(ctx->uri == NULL) || (uri == ctx->uri) || xmlStrEqual(uri, ctx->uri)",
            -1
        );
        let here = here!("xmlSecTransformCtxUriExecute");
        // SAFETY: by the caller's contract.
        unsafe {
            let input = xmlSecTransformCtxCreateAndPrepend(ctx, io::input_uri());
            if input.is_null() {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxCreateAndPrepend(xmlSecTransformInputURIId)",
                );
                return -1;
            }
            let name = (*(*input).id).name.cast();
            // The URI is admitted under the run's policy revision.
            let Some(pinned) = run_policy(ctx, here) else {
                return -1;
            };
            if io::open(input, uri, Some(&pinned)) < 0 {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformInputURIOpen",
                    &format!("uri={}", klass_text(uri)),
                );
                return -1;
            }
            if xmlSecTransformCtxPrepare(ctx, DATA_UNKNOWN) < 0 {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxPrepare(TypeUnknown)",
                );
                return -1;
            }
            if xmlSecTransformPump(input, (*input).next, ctx) < 0 {
                errors::internal(here, name, c"xmlSecTransformPump");
                return -1;
            }
            if io::xmlSecTransformInputURIClose(input) < 0 {
                errors::internal(here, name, c"xmlSecTransformInputURIClose");
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
        let context = fresh_or!(ctx, "xmlSecTransformCtxXmlExecute", -1);
        check!(
            !nodes.is_null(),
            "xmlSecTransformCtxXmlExecute",
            c"nodes != NULL",
            -1
        );
        check!(
            // SAFETY: a context's URI is null or NUL-terminated.
            context.uri.is_null() || unsafe { CStr::from_ptr(context.uri.cast()) }.is_empty(),
            "xmlSecTransformCtxXmlExecute",
            c"(ctx->uri == NULL) || (xmlStrlen(ctx->uri) == 0)",
            -1
        );
        let here = here!("xmlSecTransformCtxXmlExecute");
        // SAFETY: by the caller's contract.
        unsafe {
            if xmlSecTransformCtxPrepare(ctx, DATA_XML) < 0 {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxPrepare(TypeXml)",
                );
                return -1;
            }
            if xmlSecTransformPushXml((*ctx).first, nodes, ctx) < 0 {
                errors::internal(
                    here,
                    (*(*(*ctx).first).id).name.cast(),
                    c"xmlSecTransformPushXml",
                );
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
        let context = fresh_or!(ctx, "xmlSecTransformCtxExecute", -1);
        check!(
            !doc.is_null(),
            "xmlSecTransformCtxExecute",
            c"doc != NULL",
            -1
        );
        let here = here!("xmlSecTransformCtxExecute");
        // SAFETY: by the caller's contract.
        unsafe {
            let empty = |text: *mut u8| text.is_null() || CStr::from_ptr(text.cast()).is_empty();
            if !empty(context.uri) {
                let result = xmlSecTransformCtxUriExecute(ctx, context.uri);
                if result < 0 {
                    errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxUriExecute");
                }
                return result;
            }
            // The XPointer transform selects its own nodes from the document.
            let (nodes, built) = if empty(context.xptr_expr) {
                (
                    xmlSecNodeSetGetChildren(doc, std::ptr::null_mut(), 0, 0),
                    c"xmlSecNodeSetGetChildren",
                )
            } else {
                (
                    xmlSecNodeSetCreate(doc, std::ptr::null_mut(), NORMAL),
                    c"xmlSecNodeSetCreate",
                )
            };
            if nodes.is_null() {
                errors::internal(here, std::ptr::null(), built);
                return -1;
            }
            let result = xmlSecTransformCtxXmlExecute(ctx, nodes);
            if result < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxXmlExecute");
            }
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
        check!(
            !ctx.is_null(),
            "xmlSecTransformCtxDebugDump",
            c"ctx != NULL",
        );
        check!(
            !output.is_null(),
            "xmlSecTransformCtxDebugDump",
            c"output != NULL",
        );
        // SAFETY: by the caller's contract.
        unsafe {
            let context = &mut *ctx;
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
        check!(
            !ctx.is_null(),
            "xmlSecTransformCtxDebugXmlDump",
            c"ctx != NULL",
        );
        check!(
            !output.is_null(),
            "xmlSecTransformCtxDebugXmlDump",
            c"output != NULL",
        );
        // SAFETY: by the caller's contract.
        unsafe {
            let context = &mut *ctx;
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
            // libxmlsec1 prints both through xmlSecPrintXmlString, which
            // writes `NULL` for an unset one.
            write_stream(output, "<Uri>");
            xmlSecPrintXmlString(output, context.uri);
            write_stream(output, "</Uri>\n<UriXPointer>");
            xmlSecPrintXmlString(output, context.xptr_expr);
            write_stream(output, "</UriXPointer>\n");
            let mut transform = context.first;
            while !transform.is_null() {
                xmlSecTransformDebugXmlDump(transform, output);
                transform = (*transform).next;
            }
            write_stream(output, "</TransformCtx>\n");
        }
    });
}
