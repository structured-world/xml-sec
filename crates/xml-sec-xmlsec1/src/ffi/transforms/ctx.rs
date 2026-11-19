//! `xmlSecTransformCtx`: a chain of transforms and the state of one run.

use std::ffi::{CStr, c_int, c_uint, c_void};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use xml_sec::xmldsig::UriTypeSet;

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
/// `XMLSEC_TRANSFORMCTX_FLAGS_ALLOW_EMPTY_INPUT`.
pub(crate) const FLAGS_ALLOW_EMPTY_INPUT: c_uint = 0x0008;
/// `xmlSecTransformUriTypeEmpty | xmlSecTransformUriTypeSameDocument`: the
/// URIs a context dereferences until the caller enables more.
///
/// This is the documented initial value of the caller-owned `enabledUris`
/// field of the libxmlsec1 ABI (`transforms.h`), not a deployment default.
/// It never widens the compiled policy: a dereference needs both the
/// caller's mask and the policy's URI classes, so a program written for
/// libxmlsec1 that leaves the mask alone keeps its opt-in for external URIs.
const URI_TYPES_DEFAULT: c_uint = 0x0001 | 0x0002;
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
    /// The first limit that refused work of the run: an external-resource
    /// read, a Base64 charge, a cipher's plaintext size or an `XPath`
    /// expression count. The operation's budget is spent, which ends the
    /// operation rather than one reference, and a later read is refused
    /// naming this limit.
    pub(crate) refused_by: Option<Limit>,
    /// Whether the keys the run's transports recovered were recovered
    /// validly, consulted only once the operation's content work is done.
    pub(crate) recovery: xml_sec::provider::RecoveryValidity,
    /// The side of the operation that uses the keys the run's transports
    /// recover, handed down by the `KeyInfo` read that runs the chain.
    pub(crate) serves: Option<policy::Side>,
    /// The key candidates the operation's `KeyInfo` work has inspected, of
    /// `max_key_candidates`, carried from one `KeyInfo` read to the next.
    pub(crate) key_candidates: policy::KeyCandidates,
    /// Octets handed to the XML parser, of `max_xml_parse_work_bytes`.
    pub(crate) xml_parse: usize,
    /// `XPath` expressions evaluated, of `max_xpath_expressions`.
    pub(crate) xpath_expressions: usize,
    /// The run's method carries a key, as an `EncryptedKey`'s does, so a
    /// block cipher of it is admitted as a key wrap rather than as content
    /// (XML Encryption 1.1 section 3.4).
    pub(crate) wraps_key: bool,
    /// The policy revision of the run, pinned at its first read or handed
    /// down by the `KeyInfo` read that runs the chain.
    policy: Option<policy::Pinned>,
    /// The URI classes a `KeyInfo` read admits for the key reference the run
    /// dereferences; a run of its own opens the classes of a signature's
    /// references.
    uris: Option<UriTypeSet>,
    /// The operation the run serves, fixed with its policy revision: a
    /// `KeyInfo` read verifies, any other run serves the operation one of its
    /// transforms performs.
    side: Option<policy::Side>,
}

/// The side of a transform operation that is not verification's: signing,
/// encryption or decryption.
pub(crate) const fn operation_side(operation: c_int) -> Option<policy::Side> {
    match operation {
        super::OPERATION_SIGN => Some(policy::Side::Sign),
        super::OPERATION_ENCRYPT => Some(policy::Side::Encrypt),
        super::OPERATION_DECRYPT => Some(policy::Side::Decrypt),
        _ => None,
    }
}

/// The operation the chain of `ctx` serves: the first of its transforms that
/// signs, encrypts or decrypts names it, verification otherwise.
///
/// # Safety
/// `ctx` is an initialized context whose chain is live.
unsafe fn chain_side(ctx: *mut XmlSecTransformCtx) -> policy::Side {
    // SAFETY: by the caller's contract.
    let mut current = unsafe { (*ctx).first };
    while !current.is_null() {
        // SAFETY: the chain's transforms are live.
        unsafe {
            if let Some(side) = operation_side((*current).operation) {
                return side;
            }
            current = (*current).next;
        }
    }
    policy::Side::Verify
}

/// The policy revision the run of `ctx` runs under and the side of it that
/// governs the chain's shared work (budgets, URIs, parsing, canonicalization
/// and selection), fixed at its first read; reported at `here` when the
/// profile is unavailable.
///
/// # Safety
/// `ctx` is an initialized context whose chain is live.
pub(crate) unsafe fn run_scope(
    ctx: *mut XmlSecTransformCtx,
    here: errors::Here,
) -> Option<(policy::Pinned, policy::Side)> {
    // SAFETY: by the caller's contract.
    unsafe {
        let pinned = run_policy(ctx, here)?;
        let side = chain_side(ctx);
        let run = run_budget(ctx);
        Some((pinned, *run.side.get_or_insert(side)))
    }
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

/// Forgets the run of `ctx`, its policy revision and what it spent, so an
/// operation beginning afresh on the context pins its own.
///
/// # Safety
/// `ctx` is an initialized context.
pub(crate) unsafe fn forget_run(ctx: *mut XmlSecTransformCtx) {
    // SAFETY: by the caller's contract; the slot is null or the run.
    unsafe {
        let run = (*ctx).reserved0;
        if !run.is_null() {
            drop(Box::from_raw(run.cast::<RunBudget>()));
            (*ctx).reserved0 = std::ptr::null_mut();
        }
    }
}

/// Starts the run of `ctx` afresh under `pinned` for an operation beginning
/// on it: an earlier call refused before it read anything may have pinned
/// another revision and spent part of its budgets.
///
/// # Safety
/// `ctx` is an initialized context.
pub(crate) unsafe fn restart_run(ctx: *mut XmlSecTransformCtx, pinned: &policy::Pinned) {
    // SAFETY: by the caller's contract.
    unsafe {
        forget_run(ctx);
        pin_run(ctx, pinned);
    }
}

/// Makes `pinned` the revision of the fresh run of `ctx`, leaving its side to
/// its chain.
///
/// # Safety
/// `ctx` is an initialized context.
pub(crate) unsafe fn pin_run(ctx: *mut XmlSecTransformCtx, pinned: &policy::Pinned) {
    // SAFETY: by the caller's contract.
    let run = unsafe { run_budget(ctx) };
    if run.policy.is_none() {
        run.policy = Some(pinned.clone());
    }
}

/// Starts the fresh run of `ctx` for a part of an operation: under its
/// revision `pinned` and `side` whatever the chain's transforms say, with
/// `spent` already charged. A chain a `KeyInfo` read runs opens its URI
/// under the classes `uris` the read admits for that key reference; with
/// `None` the run opens the classes of `side`'s references.
///
/// # Safety
/// `ctx` is an initialized context.
pub(crate) unsafe fn seed_run(
    ctx: *mut XmlSecTransformCtx,
    pinned: &policy::Pinned,
    side: policy::Side,
    uris: Option<UriTypeSet>,
    spent: policy::Spent,
) {
    // SAFETY: by the caller's contract.
    let run = unsafe { run_budget(ctx) };
    if run.policy.is_none() {
        run.policy = Some(pinned.clone());
    }
    run.side = Some(side);
    run.uris = uris;
    // SAFETY: by the caller's contract.
    unsafe { take_spent(ctx, spent) };
}

/// What the run of `ctx` has spent; nothing when no run has started.
///
/// # Safety
/// `ctx` is an initialized context.
pub(crate) unsafe fn run_spent(ctx: *mut XmlSecTransformCtx) -> policy::Spent {
    // SAFETY: by the caller's contract; the slot is null or the run.
    match unsafe { (*ctx).reserved0.cast::<RunBudget>().as_ref() } {
        Some(run) => policy::Spent {
            base64_input: run.base64_input,
            base64_output: run.base64_output,
            external_resources: run.external_resources,
            xml_parse: run.xml_parse,
            xpath_expressions: run.xpath_expressions,
            refused_by: run.refused_by,
            recovery: run.recovery,
            serves: run.serves,
        },
        None => policy::Spent::default(),
    }
}

/// Takes into the run of `ctx`, the chain of an operation, what the
/// operation has spent of its per-operation budgets and key candidates once
/// its `KeyInfo` read or write is done, held in the pin in that `KeyInfo` context's slot
/// `key_info_slot`: the `KeyInfo` work counted on from what the chain had
/// spent ([`run_spent`]), and the operation's later work counts on from its
/// total, so the key's work and the operation's share one allowance. The
/// `KeyInfo` work ran under its own parts' limits, so the total is checked
/// against the operation's `resources`; `false` after a report at `here`
/// when it exceeds one, and `false` when a limit refused one of its reads.
///
/// # Safety
/// `ctx` is an initialized context; `key_info_slot` is null or a pin.
pub(crate) unsafe fn charge_key_info(
    ctx: *mut XmlSecTransformCtx,
    key_info_slot: *mut c_void,
    resources: &xml_sec::policy::ResourcePolicy,
    here: errors::Here,
) -> bool {
    // SAFETY: by the caller's contract.
    if let Some(candidates) = unsafe { policy::key_candidates(key_info_slot) } {
        // SAFETY: by the caller's contract.
        unsafe { run_budget(ctx) }.key_candidates = candidates.get();
    }
    // SAFETY: by the caller's contract.
    let Some(spent) = (unsafe { policy::spent(key_info_slot) }).map(std::cell::Cell::get) else {
        return true;
    };
    for (value, limit) in [
        (
            spent.external_resources,
            Limit {
                name: "max_external_resource_total_bytes",
                max: resources.max_external_resource_total_bytes,
            },
        ),
        (
            spent.base64_input,
            Limit {
                name: "max_base64_transform_input_bytes",
                max: resources.max_base64_transform_input_bytes,
            },
        ),
        (
            spent.base64_output,
            Limit {
                name: "max_base64_transform_output_bytes",
                max: resources.max_base64_transform_output_bytes,
            },
        ),
        (
            spent.xml_parse,
            Limit {
                name: "max_xml_parse_work_bytes",
                max: resources.max_xml_parse_work_bytes,
            },
        ),
        (
            spent.xpath_expressions,
            Limit {
                name: "max_xpath_expressions",
                max: resources.max_xpath_expressions,
            },
        ),
    ] {
        if value > limit.max {
            errors::limit_exceeded(here, std::ptr::null(), limit.name, limit.max);
            return false;
        }
    }
    // SAFETY: by the caller's contract.
    unsafe { take_spent(ctx, spent) };
    // A read the `KeyInfo` work had refused by a limit ends the operation
    // whatever key the work yielded; the refusal was reported where it
    // happened, and an operation whose references are all in the document
    // reads nothing later that would see it.
    spent.refused_by.is_none()
}

/// Takes what the run of `ctx` has spent of the per-operation budgets off
/// the operation's `resources`, the policy a core operation is handed: the
/// core counts its own work from zero, so the allowance it receives is what
/// the operation's earlier parts (its `KeyInfo` read) left. `false` after a
/// report at `here` when one is already spent past its limit.
///
/// # Safety
/// `ctx` is an initialized context.
pub(crate) unsafe fn leave_unspent(
    ctx: *mut XmlSecTransformCtx,
    resources: &mut xml_sec::policy::ResourcePolicy,
    here: errors::Here,
) -> bool {
    // SAFETY: by the caller's contract.
    let spent = unsafe { run_spent(ctx) };
    for (limit, name, value) in [
        (
            &mut resources.max_external_resource_total_bytes,
            "max_external_resource_total_bytes",
            spent.external_resources,
        ),
        (
            &mut resources.max_base64_transform_input_bytes,
            "max_base64_transform_input_bytes",
            spent.base64_input,
        ),
        (
            &mut resources.max_base64_transform_output_bytes,
            "max_base64_transform_output_bytes",
            spent.base64_output,
        ),
        (
            &mut resources.max_xml_parse_work_bytes,
            "max_xml_parse_work_bytes",
            spent.xml_parse,
        ),
        (
            &mut resources.max_xpath_expressions,
            "max_xpath_expressions",
            spent.xpath_expressions,
        ),
    ] {
        let Some(left) = limit.checked_sub(value) else {
            errors::limit_exceeded(here, std::ptr::null(), name, *limit);
            return false;
        };
        *limit = left;
    }
    true
}

/// Makes `spent` what the run of `ctx` has spent.
///
/// # Safety
/// `ctx` is an initialized context.
pub(crate) unsafe fn take_spent(ctx: *mut XmlSecTransformCtx, spent: policy::Spent) {
    // SAFETY: by the caller's contract.
    let run = unsafe { run_budget(ctx) };
    run.base64_input = spent.base64_input;
    run.base64_output = spent.base64_output;
    run.external_resources = spent.external_resources;
    run.xml_parse = spent.xml_parse;
    run.xpath_expressions = spent.xpath_expressions;
    // A refusal is never taken back by what a part hands over, nor is an
    // invalid recovery: `spent` carries only the recovery of the key the
    // part yields, a failed recipient's being dropped where it is tried.
    run.refused_by = run.refused_by.or(spent.refused_by);
    run.recovery = run.recovery.and(spent.recovery);
    run.serves = run.serves.or(spent.serves);
}

/// What the operation whose chain is `ctx` has spent of its external-resource
/// allowance, to start a read of the operation from.
///
/// # Safety
/// `ctx` is an initialized context.
pub(crate) unsafe fn external_spent(ctx: *mut XmlSecTransformCtx) -> policy::Spent {
    // SAFETY: by the caller's contract.
    let spent = unsafe { run_spent(ctx) };
    policy::Spent {
        external_resources: spent.external_resources,
        // A limit that refused work already ends every later read.
        refused_by: spent.refused_by,
        ..policy::Spent::default()
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
            (*ctx).enabled_uris = URI_TYPES_DEFAULT;
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
/// data and the result and forgets the parent key info context, keeping the
/// user settings.
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
            forget_run(ctx);
            let context = &mut *ctx;
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
            // The parent key info context belongs to the caller that set it
            // for this run.
            context.parent_key_info_ctx = std::ptr::null_mut();
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
        // A context copied onto itself already holds its preferences.
        if dst == src {
            return 0;
        }
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
    // SAFETY: by the caller's contract.
    unsafe { node_read(node, usage, ctx, super::OPERATION_NONE) }
}

/// [`xmlSecTransformNodeRead`] of a transform that reads its node for
/// `operation`, set before the klass reads it, as a caller that knows the
/// operation sets it: an `xmlSecEncCtx` knows it before it reads its method.
///
/// # Safety
/// As for [`xmlSecTransformNodeRead`].
unsafe fn node_read(
    node: *mut XmlNode,
    usage: c_uint,
    ctx: *mut XmlSecTransformCtx,
    operation: c_int,
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
        unsafe { read_algorithm(node, href.as_ptr().cast(), usage, ctx, operation) }
    })
}

/// The transform for algorithm `href` read from `node` for `operation`.
///
/// # Safety
/// As for [`xmlSecTransformNodeRead`]; `href` is NUL-terminated.
unsafe fn read_algorithm(
    node: *mut XmlNode,
    href: *const u8,
    usage: c_uint,
    ctx: *mut XmlSecTransformCtx,
    operation: c_int,
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
        // The public readers name no operation and keep the one the klass's
        // initializer chose (Base64 decodes), as libxmlsec1's reader does.
        if operation != super::OPERATION_NONE {
            (*transform).operation = operation;
        }
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
    // SAFETY: by the caller's contract.
    unsafe { ctx_node_read_for(ctx, node, usage, super::OPERATION_NONE) }
}

/// [`xmlSecTransformCtxNodeRead`] of a transform that reads its node for
/// `operation`, so a klass whose parameters fall under that operation's
/// policy reads them under it.
///
/// # Safety
/// As for [`xmlSecTransformCtxNodeRead`].
pub(crate) unsafe fn ctx_node_read_for(
    ctx: *mut XmlSecTransformCtx,
    node: *mut XmlNode,
    usage: c_uint,
    operation: c_int,
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
            let transform = node_read(node, usage, ctx, operation);
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
                    errors::R_INVALID_URI_TYPE,
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
        let Some((pinned, side)) = (unsafe { run_scope(&raw mut *context, here) }) else {
            return -1;
        };
        let max = pinned.of(side).resources().max_transforms_per_reference;
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
        // SAFETY: by the caller's contract.
        unsafe { execute_on_bytes(ctx, data, size) }
    })
}

/// Runs the fresh chain of `ctx` on `size` bytes, as
/// `xmlSecTransformCtxBinaryExecute` does; a chain whose URI names those
/// bytes runs on them as they were read, without opening the URI again.
///
/// # Safety
/// `ctx` is an initialized, fresh context; `data` is null or readable for
/// `size` bytes.
pub(crate) unsafe fn execute_on_bytes(
    ctx: *mut XmlSecTransformCtx,
    data: *const u8,
    size: usize,
) -> c_int {
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
            // The URI is admitted under the run's policy revision, by the
            // classes of the key reference a KeyInfo read runs it for, or
            // else of the references of the operation the chain serves.
            let Some((pinned, side)) = run_scope(ctx, here) else {
                return -1;
            };
            let classes = run_budget(ctx).uris.unwrap_or(pinned.of(side).references());
            if io::open(input, uri, Some(classes)) < 0 {
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

/// The external resources one operation read, each under the URI its
/// element carries, as the caller's input callbacks were asked for it.
#[derive(Default)]
pub(crate) struct ReadResources {
    read: Vec<ReadResource>,
}

/// One resource of [`ReadResources`].
struct ReadResource {
    /// The element whose URI named the resource.
    origin: xml_sec::document::external::ExternalNode,
    /// The URI as the element carries it.
    uri: String,
    bytes: Vec<u8>,
}

impl ReadResources {
    /// Records the octets `origin`'s URI `uri` named.
    pub(crate) fn push(
        &mut self,
        origin: xml_sec::document::external::ExternalNode,
        uri: String,
        bytes: Vec<u8>,
    ) {
        self.read.push(ReadResource { origin, uri, bytes });
    }

    /// The resources keyed as the core looks them up in `document`, a
    /// tree-backed document of their tree: each URI resolved from its
    /// element against the XML Base it inherits, within `resources`'
    /// limits. The callbacks were handed the URI as written, as libxmlsec1
    /// hands it; the core resolves before it looks a resource up.
    ///
    /// # Errors
    /// The resolution's failure, or an element `document` does not hold.
    pub(crate) fn into_keyed(
        self,
        document: &xml_sec::document::XmlDocument,
        resources: &xml_sec::policy::ResourcePolicy,
    ) -> Result<KeyedResources, String> {
        let keys = resource_keys(
            document,
            self.read
                .iter()
                .map(|resource| (resource.origin, resource.uri.as_str())),
            resources,
        )?;
        let mut keyed = KeyedResources::default();
        for (resource, key) in self.read.into_iter().zip(keys) {
            // Two references to one resource keep the octets read first.
            keyed.by_key.entry(key).or_insert(resource.bytes);
        }
        Ok(keyed)
    }
}

/// The keys the core looks external resources up by in `document`, a
/// tree-backed document of their tree: each URI as its element carries it,
/// resolved from that element against the XML Base it inherits, within
/// `resources`' limits.
///
/// # Errors
/// The resolution's failure, or an element `document` does not hold.
pub(crate) fn resource_keys<'u>(
    document: &xml_sec::document::XmlDocument,
    references: impl Iterator<Item = (xml_sec::document::external::ExternalNode, &'u str)>,
    resources: &xml_sec::policy::ResourcePolicy,
) -> Result<Vec<String>, String> {
    document.with_view(|view| {
        references
            .map(|(origin, uri)| {
                let origin = view
                    .node_of_external(origin)
                    .ok_or("the element of an external reference is not in the document")?;
                xml_sec::xmldsig::uri::UriReferenceResolver::external_resource_key(
                    origin, uri, resources,
                )
                .map_err(|error| error.to_string())
            })
            .collect()
    })
}

/// External resources keyed as the core looks them up.
#[derive(Default)]
pub(crate) struct KeyedResources {
    /// The octets under each resolved key, handed to the core.
    pub(crate) by_key: std::collections::BTreeMap<String, Vec<u8>>,
}

/// The operation an external resource is read for: its pinned revision, the
/// side whose URI classes and limits govern the read, and what its earlier
/// reads spent, so every read of one operation shares one external-resource
/// allowance.
pub(crate) struct ResourceScope<'a> {
    pub(crate) pinned: &'a policy::Pinned,
    pub(crate) side: policy::Side,
    pub(crate) spent: policy::Spent,
    /// The limit that refused a read, which the core treats as a refusal of
    /// the whole operation, not a missing resource.
    pub(crate) refused_by: Option<Limit>,
}

impl<'a> ResourceScope<'a> {
    /// Reads for `side` of the revision `pinned`, counting on from `spent`.
    pub(crate) const fn new(
        pinned: &'a policy::Pinned,
        side: policy::Side,
        spent: policy::Spent,
    ) -> Self {
        Self {
            pinned,
            side,
            spent,
            refused_by: None,
        }
    }
}

/// What a pre-execute callback can change of a chain: its transforms in
/// order, with their klasses, operations, statuses (a transform the
/// callback ran) and `here` nodes (an enveloped signature transform finds
/// the signature it excludes from its node), and its URI selection. A
/// transform's own settings (its key, an expression) live in its klass's
/// context and are watched by [`PreExecuteWatch`].
#[derive(PartialEq, Eq)]
struct ChainShape {
    transforms: Vec<(
        *const XmlSecTransform,
        *const XmlSecTransformKlass,
        c_int,
        c_int,
        *const XmlNode,
    )>,
    uri: Option<Vec<u8>>,
    xptr_expr: Option<Vec<u8>>,
}

std::thread_local! {
    /// The chains whose pre-execute callbacks run on this thread, innermost
    /// last: each chain's transforms and whether a callback changed a
    /// setting of one of them. A callback runs on its operation's thread,
    /// so another thread's work never marks this one's chains.
    static PRE_EXECUTING: std::cell::RefCell<Vec<(Vec<*const XmlSecTransform>, bool)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Watches the settings of a chain's transforms while its pre-execute
/// callback runs, as the entry at `index` of [`PRE_EXECUTING`]; dropping it
/// ends the watch, and those of callbacks nested in it.
struct PreExecuteWatch {
    index: usize,
}

impl PreExecuteWatch {
    /// Starts watching `transforms`.
    fn start(transforms: Vec<*const XmlSecTransform>) -> Self {
        PRE_EXECUTING.with_borrow_mut(|chains| {
            chains.push((transforms, false));
            Self {
                index: chains.len() - 1,
            }
        })
    }

    /// Whether a setting of a watched transform changed.
    fn changed(&self) -> bool {
        PRE_EXECUTING
            .with_borrow(|chains| chains.get(self.index).is_some_and(|(_, changed)| *changed))
    }
}

impl Drop for PreExecuteWatch {
    fn drop(&mut self) {
        PRE_EXECUTING.with_borrow_mut(|chains| chains.truncate(self.index));
    }
}

/// Records that a setting of `transform` changes: a chain whose pre-execute
/// callback is running on this thread and holds it is then refused.
pub(crate) fn note_setting_change(transform: *const XmlSecTransform) {
    PRE_EXECUTING.with_borrow_mut(|chains| {
        for (transforms, changed) in chains.iter_mut() {
            if transforms.contains(&transform) {
                *changed = true;
            }
        }
    });
}

impl ChainShape {
    /// The shape of the chain of `ctx`.
    ///
    /// # Safety
    /// `ctx` is an initialized context.
    unsafe fn of(ctx: *mut XmlSecTransformCtx) -> Self {
        let text = |text: *mut u8| {
            (!text.is_null()).then(|| {
                // SAFETY: a NUL-terminated string of the context.
                unsafe { std::ffi::CStr::from_ptr(text.cast()) }
                    .to_bytes()
                    .to_vec()
            })
        };
        let mut transforms = Vec::new();
        // SAFETY: by the caller's contract; the chain's links are live.
        unsafe {
            let mut transform = (*ctx).first;
            while let Some(current) = transform.as_ref() {
                transforms.push((
                    transform.cast_const(),
                    current.id,
                    current.operation,
                    current.status,
                    current.here_node.cast_const(),
                ));
                transform = current.next;
            }
            Self {
                transforms,
                uri: text((*ctx).uri),
                xptr_expr: text((*ctx).xptr_expr),
            }
        }
    }
}

/// Runs the pre-execute callback of `ctx`, a chain whose operation the core
/// runs from the document: a negative return refuses the operation, and so
/// does a callback that changed the chain or a setting of one of its
/// transforms, such as its key, a change the core would not see (libxmlsec1
/// lets the callback edit the chain it then runs itself). `false` after a
/// report at `here`.
///
/// # Safety
/// `ctx` is an initialized context whose callback is callable with it.
pub(crate) unsafe fn run_pre_execute(ctx: *mut XmlSecTransformCtx, here: errors::Here) -> bool {
    // SAFETY: by the caller's contract.
    unsafe { run_pre_executes(&[ctx], here) }
}

/// Runs the pre-execute callbacks of `chains`, chains of one operation the
/// core runs from the document, in order, as [`run_pre_execute`] runs one:
/// every chain is watched from before the first callback until the last
/// returns, so a callback changing another chain, through state of its own,
/// refuses the operation too. `false` after a report at `here`.
///
/// # Safety
/// `chains` are initialized contexts whose callbacks are callable with them.
pub(crate) unsafe fn run_pre_executes(
    chains: &[*mut XmlSecTransformCtx],
    here: errors::Here,
) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        if chains.iter().all(|&ctx| (*ctx).pre_exec_callback.is_none()) {
            return true;
        }
        let before: Vec<ChainShape> = chains.iter().map(|&ctx| ChainShape::of(ctx)).collect();
        let watch = PreExecuteWatch::start(
            before
                .iter()
                .flat_map(|shape| shape.transforms.iter().map(|&(transform, ..)| transform))
                .collect(),
        );
        for &ctx in chains {
            if let Some(callback) = (*ctx).pre_exec_callback
                && callback(ctx) < 0
            {
                errors::internal(here, std::ptr::null(), c"ctx->preExecCallback");
                return false;
            }
        }
        if watch.changed()
            || chains
                .iter()
                .zip(&before)
                .any(|(&ctx, shape)| ChainShape::of(ctx) != *shape)
        {
            errors::not_implemented(
                here,
                "a pre-execute callback changed a chain the operation runs from the document",
            );
            return false;
        }
    }
    true
}

/// The octets of the external resource `uri` names, read through the
/// caller's input callbacks as a chain with no transform reads it, the
/// whole resource for an empty fragment and refused before any read for a
/// fragment selecting part of it, which octets cannot: under the URI classes
/// `prefs` enables and those of the operation `scope` describes, within what
/// is left of its external-resource budgets, which the read charges. A core
/// operation is handed these octets, as it performs no I/O itself. `None`
/// after a report.
///
/// # Safety
/// `prefs` is an initialized context; `here` a live node of `doc`.
pub(crate) unsafe fn read_resource(
    prefs: *mut XmlSecTransformCtx,
    uri: &[u8],
    here: *mut XmlNode,
    doc: *mut XmlDoc,
    scope: &mut ResourceScope<'_>,
) -> Option<Vec<u8>> {
    let location = here!("xmlSecTransformCtxUriExecute");
    let mut parts = uri.splitn(2, |&byte| byte == b'#');
    let base = parts.next().unwrap_or(uri);
    // XMLDSig 1.1 section 4.4.3.2 leaves fragments of external resources
    // optional; the core refuses them, so nothing is read for one.
    if parts.next().is_some_and(|fragment| !fragment.is_empty()) {
        errors::report(
            location,
            std::ptr::null(),
            std::ptr::null(),
            errors::R_INVALID_URI_TYPE,
            &format!(
                "fragment of an external resource is not supported: uri={}",
                String::from_utf8_lossy(uri)
            ),
        );
        return None;
    }
    // A limit that refused earlier work of the operation, a key lookup's
    // included, spent its budget: nothing more is read, and the refusal
    // names that limit.
    if let Some(limit) = scope.refused_by.or(scope.spent.refused_by) {
        scope.refused_by = Some(limit);
        errors::limit_exceeded(location, std::ptr::null(), limit.name, limit.max);
        return None;
    }
    let Ok(base) = std::ffi::CString::new(base) else {
        errors::invalid_data(location, std::ptr::null(), "a URI holding a NUL octet");
        return None;
    };
    // SAFETY: a context created and destroyed here; the caller's live node
    // and document.
    unsafe {
        let ctx = xmlSecTransformCtxCreate();
        if ctx.is_null() {
            errors::internal(location, std::ptr::null(), c"xmlSecTransformCtxCreate");
            return None;
        }
        (*ctx).enabled_uris = (*prefs).enabled_uris;
        // The read is a part of its operation: that operation's revision and
        // side admit the URI and bound the octets, counted on from what its
        // earlier reads spent.
        seed_run(ctx, scope.pinned, scope.side, None, scope.spent);
        let bytes = (xmlSecTransformCtxSetUri(ctx, base.as_ptr().cast(), here) == 0
            && xmlSecTransformCtxExecute(ctx, doc) == 0)
            .then(|| {
                let result = (*ctx).result;
                let data = super::super::buffer::xmlSecBufferGetData(result);
                if data.is_null() {
                    Vec::new()
                } else {
                    std::slice::from_raw_parts(
                        data,
                        super::super::buffer::xmlSecBufferGetSize(result),
                    )
                    .to_vec()
                }
            });
        scope.spent = run_spent(ctx);
        scope.refused_by = scope.refused_by.or(run_budget(ctx).refused_by);
        xmlSecTransformCtxDestroy(ctx);
        bytes
    }
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
                    "<TransformCtx status=\"{}\">\n<Flags>{:08x}</Flags>\n<MaxDepth>{}</MaxDepth>\n",
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
