//! The built-in transform klasses: the memory-buffer terminal, Base64,
//! canonicalization, the tag-removing conversion and the enveloped-signature
//! transform, with the identities of the others; the `XPath` family lives in
//! [`super::xpath`].
//!
//! Canonicalization takes its semantics from the core: the caller's tree is
//! projected under the library's policy and canonicalized with exactly the
//! nodes, attributes and namespace nodes the input node set contains.

use std::ffi::{CStr, c_int, c_uint};

use xml_sec::c14n::{C14nAlgorithm, C14nMode, SelectedNodes, canonicalize_selected};
use xml_sec::document::external::ExternalNode;
use xml_sec::document::owned_tree::TreeNode;
use xml_sec::{DocumentView, Node};

use super::super::base64::{
    self, XmlSecBase64Ctx, decode_size, encode_size, xmlSecBase64CtxFinal_ex,
    xmlSecBase64CtxInitialize, xmlSecBase64CtxUpdate_ex,
};
use super::super::buffer::{
    XmlSecBuffer, xmlSecBufferAppend, xmlSecBufferFinalize, xmlSecBufferGetData,
    xmlSecBufferGetSize, xmlSecBufferInitialize, xmlSecBufferRemoveHead, xmlSecBufferSetMaxSize,
    xmlSecBufferSetSize,
};
use super::super::errors::{self, check, here};
use super::super::list::{
    XmlSecPtrList, xmlSecPtrListAdd, xmlSecPtrListFinalize, xmlSecPtrListGetSize,
    xmlSecPtrListInitialize, xmlSecStringListGetKlass,
};
use super::super::nodeset::{
    INTERSECTION, XmlSecNodeSet, xmlSecNodeSetAdd, xmlSecNodeSetContains, xmlSecNodeSetDestroy,
    xmlSecNodeSetDumpTextNodes, xmlSecNodeSetGetChildren,
};
use super::super::strings::{
    xmlSecAttrPrefixList, xmlSecDSigNs, xmlSecHrefBase64, xmlSecHrefC14N, xmlSecHrefC14N11,
    xmlSecHrefC14N11WithComments, xmlSecHrefC14NWithComments, xmlSecHrefEnveloped,
    xmlSecHrefExcC14N, xmlSecHrefExcC14NWithComments, xmlSecNameBase64, xmlSecNameC14N,
    xmlSecNameC14N11, xmlSecNameC14N11WithComments, xmlSecNameC14NWithComments,
    xmlSecNameEnveloped, xmlSecNameExcC14N, xmlSecNameExcC14NWithComments, xmlSecNameMemBuf,
    xmlSecNodeInclusiveNamespaces, xmlSecNodeSignature, xmlSecNsExcC14N,
};
use super::super::tree::{XmlNode, c_text, nodes};
use super::super::xmltree::{next_element, xmlSecCheckNodeName, xmlSecFindParent};
use super::super::{contain, free, policy};
use super::ctx::{Limit, charge, run_budget, run_policy};
use super::io::{
    OutputBuffer, xmlOutputBufferClose, xmlOutputBufferWrite, xmlSecBufferCreateOutputBuffer,
    xmlSecTransformCreateOutputBuffer,
};
use super::{
    OPERATION_DECODE, OPERATION_ENCODE, STATUS_FINISHED, STATUS_NONE, STATUS_WORKING,
    USAGE_C14N_METHOD, USAGE_DSIG_TRANSFORM, WithContext, XmlSecTransform, XmlSecTransformCtx,
    XmlSecTransformKlass, context, context_or, valid, xmlSecTransformDefaultGetDataType,
    xmlSecTransformDefaultPopBin, xmlSecTransformDefaultPopXml, xmlSecTransformDefaultPushBin,
    xmlSecTransformDefaultPushXml, xmlSecTransformPopXml,
};
use super::{relationship, xpath};

/// A klass with sizes, name, href and usage, and no methods.
pub(crate) const fn klass(
    obj_size: usize,
    name: *const u8,
    href: *const u8,
    usage: c_uint,
) -> XmlSecTransformKlass {
    XmlSecTransformKlass {
        klass_size: size_of::<XmlSecTransformKlass>(),
        obj_size,
        name,
        href,
        usage,
        initialize: None,
        finalize: None,
        read_node: None,
        write_node: None,
        set_key_req: None,
        set_key: None,
        verify: None,
        get_data_type: Some(xmlSecTransformDefaultGetDataType),
        push_bin: None,
        pop_bin: None,
        push_xml: None,
        pop_xml: None,
        execute: None,
        reserved0: std::ptr::null_mut(),
        reserved1: std::ptr::null_mut(),
    }
}

/// libxmlsec1's own transform klasses in its registration order.
pub(crate) fn defaults() -> [*const XmlSecTransformKlass; 12] {
    [
        base64(),
        &raw const ENVELOPED,
        incl_c14n(),
        &raw const INCL_C14N_WITH_COMMENTS,
        &raw const INCL_C14N11,
        &raw const INCL_C14N11_WITH_COMMENTS,
        &raw const EXCL_C14N,
        &raw const EXCL_C14N_WITH_COMMENTS,
        xpath::xpath(),
        xpath::xpath2(),
        xpath::xpointer(),
        relationship::relationship(),
    ]
}

// ----------------------------------------------------------------------------
// Memory buffer

static MEM_BUF: XmlSecTransformKlass = XmlSecTransformKlass {
    initialize: Some(mem_buf_initialize),
    finalize: Some(mem_buf_finalize),
    push_bin: Some(xmlSecTransformDefaultPushBin),
    pop_bin: Some(xmlSecTransformDefaultPopBin),
    execute: Some(mem_buf_execute),
    ..klass(
        size_of::<WithContext<XmlSecBuffer>>(),
        xmlSecNameMemBuf.as_ptr(),
        std::ptr::null(),
        0,
    )
};

/// The memory-buffer terminal klass.
pub(crate) fn mem_buf() -> *const XmlSecTransformKlass {
    &raw const MEM_BUF
}

/// `xmlSecTransformMemBufGetKlass`.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformMemBufGetKlass() -> *const XmlSecTransformKlass {
    mem_buf()
}

/// `xmlSecTransformMemBufGetBuffer`: the buffer that keeps everything that
/// went through the transform.
///
/// # Safety
/// `transform` is null or a valid transform.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformMemBufGetBuffer(
    transform: *mut XmlSecTransform,
) -> *mut XmlSecBuffer {
    contain(std::ptr::null_mut(), || {
        let buffer = context_or!(
            transform,
            XmlSecBuffer,
            mem_buf(),
            "xmlSecTransformMemBufGetBuffer",
            c"xmlSecTransformCheckId(transform, xmlSecTransformMemBufId)",
            std::ptr::null_mut()
        );
        std::ptr::from_mut(buffer)
    })
}

/// The name of a transform's klass for a report.
///
/// # Safety
/// `transform` is a valid transform.
unsafe fn name_of(transform: *const XmlSecTransform) -> *const std::ffi::c_char {
    // SAFETY: by the caller's contract.
    unsafe { (*(*transform).id).name.cast() }
}

unsafe extern "C" fn mem_buf_initialize(transform: *mut XmlSecTransform) -> c_int {
    let buffer = context_or!(
        transform,
        XmlSecBuffer,
        mem_buf(),
        "xmlSecTransformMemBufInitialize",
        c"xmlSecTransformCheckId(transform, xmlSecTransformMemBufId)",
        -1
    );
    // SAFETY: the tail is writable buffer storage.
    if unsafe { xmlSecBufferInitialize(buffer, 0) } < 0 {
        errors::internal(
            here!("xmlSecTransformMemBufInitialize"),
            // SAFETY: a valid transform.
            unsafe { name_of(transform) },
            c"xmlSecBufferInitialize",
        );
        return -1;
    }
    0
}

unsafe extern "C" fn mem_buf_finalize(transform: *mut XmlSecTransform) {
    let buffer = context_or!(
        transform,
        XmlSecBuffer,
        mem_buf(),
        "xmlSecTransformMemBufFinalize",
        c"xmlSecTransformCheckId(transform, xmlSecTransformMemBufId)"
    );
    // SAFETY: an initialized buffer.
    unsafe { xmlSecBufferFinalize(buffer) };
}

unsafe extern "C" fn mem_buf_execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    let buffer = context_or!(
        transform,
        XmlSecBuffer,
        mem_buf(),
        "xmlSecTransformMemBufExecute",
        c"xmlSecTransformCheckId(transform, xmlSecTransformMemBufId)",
        -1
    );
    check!(
        !ctx.is_null(),
        "xmlSecTransformMemBufExecute",
        c"transformCtx != NULL",
        -1
    );
    let here = here!("xmlSecTransformMemBufExecute");
    // SAFETY: a memory-buffer transform with its own buffers.
    unsafe {
        let name = name_of(transform);
        let object = &mut *transform;
        let input = &raw mut object.in_buf;
        let in_size = xmlSecBufferGetSize(input);
        if object.status == STATUS_NONE {
            object.status = STATUS_WORKING;
        }
        match object.status {
            STATUS_WORKING => {
                let data = xmlSecBufferGetData(input);
                let failed = |step: &CStr| {
                    errors::internal_with(here, name, step, &format!("size={in_size}"));
                };
                if xmlSecBufferAppend(buffer, data, in_size) < 0
                    || xmlSecBufferAppend(&raw mut object.out_buf, data, in_size) < 0
                {
                    failed(c"xmlSecBufferAppend");
                    return -1;
                }
                if xmlSecBufferRemoveHead(input, in_size) < 0 {
                    failed(c"xmlSecBufferRemoveHead");
                    return -1;
                }
                if last != 0 {
                    object.status = STATUS_FINISHED;
                }
                0
            }
            // Only reached without input.
            STATUS_FINISHED => {
                if in_size != 0 {
                    errors::assertion(here, c"inSize == 0");
                    return -1;
                }
                0
            }
            status => {
                errors::invalid_status(here, name, status);
                -1
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Base64

static BASE64: XmlSecTransformKlass = XmlSecTransformKlass {
    initialize: Some(base64_initialize),
    finalize: Some(base64_finalize),
    push_bin: Some(xmlSecTransformDefaultPushBin),
    pop_bin: Some(xmlSecTransformDefaultPopBin),
    execute: Some(base64_execute),
    ..klass(
        size_of::<WithContext<XmlSecBase64Ctx>>(),
        xmlSecNameBase64.as_ptr(),
        xmlSecHrefBase64.as_ptr(),
        USAGE_DSIG_TRANSFORM,
    )
};

/// The Base64 klass.
pub(crate) fn base64() -> *const XmlSecTransformKlass {
    &raw const BASE64
}

/// `xmlSecTransformBase64GetKlass`.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformBase64GetKlass() -> *const XmlSecTransformKlass {
    base64()
}

/// `xmlSecTransformBase64SetLineSize`: the line size of an encoding transform.
///
/// # Safety
/// `transform` is null or a valid transform.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformBase64SetLineSize(
    transform: *mut XmlSecTransform,
    line_size: usize,
) {
    contain((), || {
        let codec = context_or!(
            transform,
            XmlSecBase64Ctx,
            base64(),
            "xmlSecTransformBase64SetLineSize",
            c"xmlSecTransformCheckId(transform, xmlSecTransformBase64Id)"
        );
        codec.columns = line_size;
    });
}

unsafe extern "C" fn base64_initialize(transform: *mut XmlSecTransform) -> c_int {
    let codec = context_or!(
        transform,
        XmlSecBase64Ctx,
        base64(),
        "xmlSecBase64Initialize",
        c"xmlSecTransformCheckId(transform, xmlSecTransformBase64Id)",
        -1
    );
    // SAFETY: a fresh Base64 transform; the tail is its codec context.
    unsafe {
        (*transform).operation = OPERATION_DECODE;
        let columns = base64::xmlSecBase64GetDefaultLineSize();
        if xmlSecBase64CtxInitialize(codec, 0, columns) < 0 {
            errors::internal(
                here!("xmlSecBase64Initialize"),
                name_of(transform),
                c"xmlSecBase64CtxInitialize",
            );
            return -1;
        }
    }
    0
}

unsafe extern "C" fn base64_finalize(transform: *mut XmlSecTransform) {
    let codec = context_or!(
        transform,
        XmlSecBase64Ctx,
        base64(),
        "xmlSecBase64Finalize",
        c"xmlSecTransformCheckId(transform, xmlSecTransformBase64Id)"
    );
    // SAFETY: the codec context is plain data.
    unsafe { std::ptr::from_mut(codec).write_bytes(0, 1) };
}

/// One codec step into `out`: grows it by `reserve` bytes, lets `step` (a
/// libxmlsec1 codec entry point named `stepped`, which reports its own
/// failure) write into the new room, and sets the size to what was written.
///
/// # Safety
/// `out` is a valid buffer of the transform `name` names.
unsafe fn codec_step(
    out: *mut XmlSecBuffer,
    reserve: usize,
    (step, stepped): (impl FnOnce(*mut u8, usize, *mut usize) -> c_int, &CStr),
    here: errors::Here,
    name: *const std::ffi::c_char,
) -> Option<()> {
    // SAFETY: after growing, `out` holds `size + reserve` bytes.
    unsafe {
        let size = xmlSecBufferGetSize(out);
        let Some(total) = size.checked_add(reserve) else {
            errors::internal_with(here, name, c"xmlSecBufferSetMaxSize", "size overflow");
            return None;
        };
        if xmlSecBufferSetMaxSize(out, total) < 0 {
            errors::internal_with(
                here,
                name,
                c"xmlSecBufferSetMaxSize",
                &format!("size={total}"),
            );
            return None;
        }
        let mut written = 0;
        if step(
            xmlSecBufferGetData(out).add(size),
            reserve,
            &raw mut written,
        ) < 0
        {
            errors::internal(here, name, stepped);
            return None;
        }
        if xmlSecBufferSetSize(out, size + written) < 0 {
            errors::internal_with(
                here,
                name,
                c"xmlSecBufferSetSize",
                &format!("size={}", size + written),
            );
            return None;
        }
        Some(())
    }
}

/// One working step of a Base64 transform: codes all of `input` into
/// `output`, and finishes the stream when `last`, within the run's Base64
/// budgets. Failures are reported.
///
/// # Safety
/// `codec`, `input` and `output` belong to a live Base64 transform; `ctx` is
/// its initialized context.
unsafe fn base64_step(
    codec: *mut XmlSecBase64Ctx,
    input: *mut XmlSecBuffer,
    output: *mut XmlSecBuffer,
    last: bool,
    ctx: *mut XmlSecTransformCtx,
) -> Option<()> {
    let here = here!("xmlSecBase64Execute");
    let name = xmlSecNameBase64.as_ptr().cast();
    // SAFETY: by the caller's contract.
    let pinned = unsafe { run_policy(ctx, here) }?;
    let resources = &pinned.verification.resources;
    // SAFETY: by the caller's contract.
    unsafe {
        let budget = run_budget(ctx);
        let before = xmlSecBufferGetSize(output);
        let in_size = xmlSecBufferGetSize(input);
        if in_size > 0 {
            // Input is charged before the codec allocates for it, which
            // bounds that allocation too.
            let limit = Limit {
                name: "max_base64_transform_input_bytes",
                max: resources.max_base64_transform_input_bytes,
            };
            charge(&mut budget.base64_input, in_size, limit, here, name)?;
            let reserve = if (*codec).encode != 0 {
                encode_size((*codec).columns, in_size)
            } else {
                decode_size(in_size)
            };
            let Some(reserve) = reserve else {
                errors::internal_with(here, name, c"xmlSecBufferSetMaxSize", "size overflow");
                return None;
            };
            let data = xmlSecBufferGetData(input);
            let update = |out, out_size, written| {
                xmlSecBase64CtxUpdate_ex(codec, data, in_size, out, out_size, written)
            };
            codec_step(
                output,
                reserve,
                (update, c"xmlSecBase64CtxUpdate_ex"),
                here,
                name,
            )?;
            if xmlSecBufferRemoveHead(input, in_size) < 0 {
                errors::internal_with(
                    here,
                    name,
                    c"xmlSecBufferRemoveHead",
                    &format!("size={in_size}"),
                );
                return None;
            }
        }
        // The last group and padding fit in 16 bytes.
        if last {
            let finish =
                |out, out_size, written| xmlSecBase64CtxFinal_ex(codec, out, out_size, written);
            codec_step(output, 16, (finish, c"xmlSecBase64CtxFinal_ex"), here, name)?;
        }
        // Output is charged before it moves on: a refused step leaves it in
        // this transform's buffer.
        let limit = Limit {
            name: "max_base64_transform_output_bytes",
            max: resources.max_base64_transform_output_bytes,
        };
        let produced = xmlSecBufferGetSize(output) - before;
        charge(&mut budget.base64_output, produced, limit, here, name)
    }
}

unsafe extern "C" fn base64_execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    let codec = context_or!(
        transform,
        XmlSecBase64Ctx,
        base64(),
        "xmlSecBase64Execute",
        c"xmlSecTransformCheckId(transform, xmlSecTransformBase64Id)",
        -1
    );
    // SAFETY: a valid transform.
    let operation = unsafe { (*transform).operation };
    check!(
        operation == OPERATION_ENCODE || operation == OPERATION_DECODE,
        "xmlSecBase64Execute",
        c"(transform->operation == xmlSecTransformOperationEncode) || (transform->operation == xmlSecTransformOperationDecode)",
        -1
    );
    check!(
        !ctx.is_null(),
        "xmlSecBase64Execute",
        c"transformCtx != NULL",
        -1
    );
    let here = here!("xmlSecBase64Execute");
    // SAFETY: a Base64 transform with its own buffers.
    unsafe {
        let name = name_of(transform);
        let codec: *mut XmlSecBase64Ctx = codec;
        let object = &mut *transform;
        let input = &raw mut object.in_buf;
        let output = &raw mut object.out_buf;
        if object.status == STATUS_NONE {
            (*codec).encode = c_int::from(object.operation == OPERATION_ENCODE);
            object.status = STATUS_WORKING;
        }
        match object.status {
            STATUS_WORKING => {
                if base64_step(codec, input, output, last != 0, ctx).is_none() {
                    return -1;
                }
                if last != 0 {
                    object.status = STATUS_FINISHED;
                }
                0
            }
            // Only reached without input.
            STATUS_FINISHED => {
                if xmlSecBufferGetSize(input) != 0 {
                    errors::assertion(here, c"xmlSecBufferGetSize(in) == 0");
                    return -1;
                }
                0
            }
            status => {
                errors::invalid_status(here, name, status);
                -1
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Canonicalization

/// The core algorithm of a C14N klass; `None` for the tag-removing one.
fn algorithm_of(id: *const XmlSecTransformKlass) -> Option<(C14nMode, bool)> {
    [
        (incl_c14n(), C14nMode::Inclusive1_0, false),
        (
            &raw const INCL_C14N_WITH_COMMENTS,
            C14nMode::Inclusive1_0,
            true,
        ),
        (&raw const INCL_C14N11, C14nMode::Inclusive1_1, false),
        (
            &raw const INCL_C14N11_WITH_COMMENTS,
            C14nMode::Inclusive1_1,
            true,
        ),
        (&raw const EXCL_C14N, C14nMode::Exclusive1_0, false),
        (
            &raw const EXCL_C14N_WITH_COMMENTS,
            C14nMode::Exclusive1_0,
            true,
        ),
    ]
    .into_iter()
    .find(|(klass, _, _)| std::ptr::eq(*klass, id))
    .map(|(_, mode, comments)| (mode, comments))
}

/// Whether `id` is one of the C14N-family klasses.
fn is_c14n(id: *const XmlSecTransformKlass) -> bool {
    algorithm_of(id).is_some() || std::ptr::eq(id, &raw const REMOVE_XML_TAGS_C14N)
}

/// The prefix list of a C14N transform, from its context; otherwise reports
/// libxmlsec1's failed `xmlSecTransformC14NCheckId` from the entry point at
/// `here`.
///
/// # Safety
/// `transform` is null or a valid transform.
unsafe fn c14n_list<'a>(
    transform: *mut XmlSecTransform,
    here: errors::Here,
) -> Option<&'a mut XmlSecPtrList> {
    // SAFETY: by the caller's contract; a C14N-family transform's tail is
    // its prefix list.
    let list = unsafe {
        valid(transform)
            .filter(|(_, klass)| is_c14n(*klass))
            .and_then(|(_, klass)| context::<XmlSecPtrList>(transform, klass))
    };
    if list.is_none() {
        errors::assertion(here, c"xmlSecTransformC14NCheckId(transform)");
    }
    list
}

/// A C14N-family klass sharing the prefix list and the push/pop methods.
const fn c14n_klass(name: *const u8, href: *const u8, read_node: bool) -> XmlSecTransformKlass {
    XmlSecTransformKlass {
        initialize: Some(c14n_initialize),
        finalize: Some(c14n_finalize),
        read_node: if read_node {
            Some(c14n_read_node)
        } else {
            None
        },
        pop_bin: Some(c14n_pop_bin),
        push_xml: Some(c14n_push_xml),
        ..klass(
            size_of::<WithContext<XmlSecPtrList>>(),
            name,
            href,
            USAGE_C14N_METHOD | USAGE_DSIG_TRANSFORM,
        )
    }
}

static INCL_C14N: XmlSecTransformKlass =
    c14n_klass(xmlSecNameC14N.as_ptr(), xmlSecHrefC14N.as_ptr(), false);
static INCL_C14N_WITH_COMMENTS: XmlSecTransformKlass = c14n_klass(
    xmlSecNameC14NWithComments.as_ptr(),
    xmlSecHrefC14NWithComments.as_ptr(),
    false,
);
static INCL_C14N11: XmlSecTransformKlass =
    c14n_klass(xmlSecNameC14N11.as_ptr(), xmlSecHrefC14N11.as_ptr(), false);
static INCL_C14N11_WITH_COMMENTS: XmlSecTransformKlass = c14n_klass(
    xmlSecNameC14N11WithComments.as_ptr(),
    xmlSecHrefC14N11WithComments.as_ptr(),
    false,
);
static EXCL_C14N: XmlSecTransformKlass =
    c14n_klass(xmlSecNameExcC14N.as_ptr(), xmlSecHrefExcC14N.as_ptr(), true);
static EXCL_C14N_WITH_COMMENTS: XmlSecTransformKlass = c14n_klass(
    xmlSecNameExcC14NWithComments.as_ptr(),
    xmlSecHrefExcC14NWithComments.as_ptr(),
    true,
);
static REMOVE_XML_TAGS_C14N: XmlSecTransformKlass = c14n_klass(
    c"remove-xml-tags-transform".as_ptr().cast(),
    std::ptr::null(),
    false,
);

/// The inclusive C14N 1.0 klass, also the automatic XML-to-binary adapter.
pub(crate) fn incl_c14n() -> *const XmlSecTransformKlass {
    &raw const INCL_C14N
}

/// The adapter before a Base64 transform that keeps only text.
pub(crate) fn remove_xml_tags_c14n() -> *const XmlSecTransformKlass {
    &raw const REMOVE_XML_TAGS_C14N
}

macro_rules! klass_getter {
    ($($name:ident => $klass:expr;)*) => {
        $(
            #[doc = concat!("`", stringify!($name), "`.")]
            ///
            /// # Safety
            /// Callable at any time.
            #[unsafe(no_mangle)]
            pub(crate) unsafe extern "C" fn $name() -> *const XmlSecTransformKlass {
                $klass
            }
        )*
    };
}

klass_getter! {
    xmlSecTransformInclC14NGetKlass => incl_c14n();
    xmlSecTransformInclC14NWithCommentsGetKlass => &raw const INCL_C14N_WITH_COMMENTS;
    xmlSecTransformInclC14N11GetKlass => &raw const INCL_C14N11;
    xmlSecTransformInclC14N11WithCommentsGetKlass => &raw const INCL_C14N11_WITH_COMMENTS;
    xmlSecTransformExclC14NGetKlass => &raw const EXCL_C14N;
    xmlSecTransformExclC14NWithCommentsGetKlass => &raw const EXCL_C14N_WITH_COMMENTS;
    xmlSecTransformRemoveXmlTagsC14NGetKlass => remove_xml_tags_c14n();
    xmlSecTransformEnvelopedGetKlass => &raw const ENVELOPED;
    xmlSecTransformXPathGetKlass => xpath::xpath();
    xmlSecTransformXPath2GetKlass => xpath::xpath2();
    xmlSecTransformXPointerGetKlass => xpath::xpointer();
    xmlSecTransformVisa3DHackGetKlass => xpath::visa3d_hack();
    xmlSecTransformRelationshipGetKlass => relationship::relationship();
}

unsafe extern "C" fn c14n_initialize(transform: *mut XmlSecTransform) -> c_int {
    let here = here!("xmlSecTransformC14NInitialize");
    // SAFETY: a fresh C14N-family transform.
    let Some(list) = (unsafe { c14n_list(transform, here) }) else {
        return -1;
    };
    // SAFETY: the tail is writable list storage.
    if unsafe { xmlSecPtrListInitialize(list, xmlSecStringListGetKlass()) } < 0 {
        // SAFETY: a valid transform.
        errors::internal(
            here,
            unsafe { name_of(transform) },
            c"xmlSecPtrListInitialize",
        );
        return -1;
    }
    0
}

unsafe extern "C" fn c14n_finalize(transform: *mut XmlSecTransform) {
    // SAFETY: a C14N-family transform being destroyed.
    if let Some(list) = unsafe { c14n_list(transform, here!("xmlSecTransformC14NFinalize")) } {
        // SAFETY: an initialized strings list.
        unsafe { xmlSecPtrListFinalize(list) };
    }
}

/// Reads the optional `ec:InclusiveNamespaces PrefixList` of an exclusive
/// C14N transform into its prefix list, ended with a null item as libxmlsec1
/// keeps it.
unsafe extern "C" fn c14n_read_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    let here = here!("xmlSecTransformC14NNodeRead");
    // SAFETY: the caller passes null or a transform.
    let Some(list) = (unsafe { c14n_list(transform, here) }) else {
        return -1;
    };
    check!(
        !node.is_null(),
        "xmlSecTransformC14NNodeRead",
        c"node != NULL",
        -1
    );
    check!(
        !ctx.is_null(),
        "xmlSecTransformC14NNodeRead",
        c"transformCtx != NULL",
        -1
    );
    check!(
        // SAFETY: an initialized list.
        unsafe { xmlSecPtrListGetSize(list) } == 0,
        "xmlSecTransformC14NNodeRead",
        c"xmlSecPtrListGetSize(nsList) == 0",
        -1
    );
    // SAFETY: an exclusive C14N transform and a live element of its document.
    unsafe {
        let name = name_of(transform);
        let mut current = next_element(nodes::first_child(node));
        if !current.is_null() {
            if xmlSecCheckNodeName(
                current,
                xmlSecNodeInclusiveNamespaces.as_ptr(),
                xmlSecNsExcC14N.as_ptr(),
            ) == 0
            {
                errors::invalid_node(here, current, "InclusiveNamespaces", name);
                return -1;
            }
            let Some(text) = c_text(xmlSecAttrPrefixList.as_ptr())
                .and_then(|attribute| nodes::property(current, attribute))
                .map(String::into_bytes)
            else {
                errors::invalid_node_attribute(here, current, c"PrefixList", name, "empty");
                return -1;
            };
            // Single spaces separate the prefixes, as libxmlsec1 splits
            // them: a space ends a prefix, so two spaces give an empty one
            // and a trailing space none.
            let mut rest = &text[..];
            while !rest.is_empty() {
                let (prefix, after) = match rest.iter().position(|&byte| byte == b' ') {
                    Some(space) => (&rest[..space], &rest[space + 1..]),
                    None => (rest, &[][..]),
                };
                rest = after;
                let copy = super::super::malloc(prefix.len() + 1).cast::<u8>();
                if copy.is_null() {
                    errors::strdup_failed(here, name, prefix);
                    return -1;
                }
                prefix.as_ptr().copy_to(copy, prefix.len());
                copy.add(prefix.len()).write(0);
                if xmlSecPtrListAdd(list, copy.cast()) < 0 {
                    errors::internal(here, name, c"xmlSecPtrListAdd");
                    free(copy.cast());
                    return -1;
                }
            }
            if xmlSecPtrListAdd(list, std::ptr::null_mut()) < 0 {
                errors::internal(here, name, c"xmlSecPtrListAdd");
                return -1;
            }
            current = next_element(nodes::next(current));
        }
        if !current.is_null() {
            errors::unexpected_node(here, current, std::ptr::null());
            return -1;
        }
        0
    }
}

/// The caller's node set read node by node for the core's serializer, over
/// a snapshot of the document in `slot`.
pub(super) struct Selection<'v> {
    pub(super) nodes: *mut XmlSecNodeSet,
    pub(super) view: DocumentView<'v>,
    pub(super) slot: usize,
}

impl Selection<'_> {
    /// The tree node a snapshot node came from, as a handle.
    fn node_of(&self, record: ExternalNode) -> *mut XmlNode {
        TreeNode::try_from(record).map_or(std::ptr::null_mut(), |node| {
            nodes::node_pointer(self.slot, node)
        })
    }

    /// libxmlsec1's visibility test: a membership check that fails (-1)
    /// counts as visible, as the C truth test does.
    fn contains(&self, node: *mut XmlNode, parent: *mut XmlNode) -> bool {
        // SAFETY: the node set is live for the canonicalization, which runs
        // inside the call that owns it.
        unsafe { xmlSecNodeSetContains(self.nodes, node, parent) != 0 }
    }

    fn element(&self, owner: Node<'_, '_>) -> Option<*mut XmlNode> {
        let element = self.node_of(self.view.external_node_of(owner)?);
        (!element.is_null()).then_some(element)
    }
}

impl SelectedNodes for Selection<'_> {
    fn node(&self, node: Node<'_, '_>) -> Option<bool> {
        // Text the tree holds as adjacent nodes (text and CDATA) is one text
        // node of the canonical form (Canonical XML 1.0 section 2.1): it is
        // output when the set holds all of its tree nodes and left out when
        // it holds none. A set holding part of it would need part of that
        // one text, which the canonical form cannot express, so it is
        // refused rather than written whole or dropped.
        if let Some(run) = self.view.external_text_run_of(node) {
            let mut verdict = None;
            for part in run {
                let part = self.node_of((*part)?);
                let contained = self.contains(part, nodes::parent(part));
                match verdict {
                    None => verdict = Some(contained),
                    Some(previous) if previous != contained => return None,
                    Some(_) => {}
                }
            }
            return verdict;
        }
        let node = self.element(node)?;
        Some(self.contains(node, nodes::parent(node)))
    }

    fn attribute(
        &self,
        owner: Node<'_, '_>,
        namespace: Option<&str>,
        local_name: &str,
    ) -> Option<bool> {
        let element = self.element(owner)?;
        let attribute = nodes::attribute(element, local_name, namespace);
        (!attribute.is_null()).then(|| self.contains(attribute.cast(), element))
    }

    fn namespace(&self, owner: Node<'_, '_>, prefix: &str, _uri: &str) -> Option<bool> {
        let element = self.element(owner)?;
        // The binding in scope at the element is the namespace node the
        // canonicalizer tests.
        let prefix = (!prefix.is_empty()).then_some(prefix);
        let namespace = nodes::namespace_node(element, prefix);
        if namespace.is_null() {
            // An undeclared default namespace has no node to test.
            return Some(self.contains(element, nodes::parent(element)));
        }
        Some(self.contains(namespace, element))
    }
}

/// The canonical form of `nodes` under `mode`, or why the tree cannot be
/// read or canonicalized under the library's policy.
///
/// # Safety
/// `nodes` is a live node set.
unsafe fn canonical(
    nodes: *mut XmlSecNodeSet,
    mode: C14nMode,
    comments: bool,
    prefixes: Option<String>,
    policy: &xml_sec::policy::VerificationPolicy,
) -> Result<Vec<u8>, String> {
    // SAFETY: a live node set by the caller's contract.
    let doc = unsafe { (*nodes).doc };
    let (document, slot) =
        xml_sec_libxml2::document::snapshot(doc, policy).map_err(|error| error.to_string())?;
    let mut algorithm = C14nAlgorithm::new(mode, comments);
    if let Some(prefixes) = prefixes {
        algorithm = algorithm.with_prefix_list(&prefixes);
    }
    let mut output = Vec::new();
    document
        .with_view(|view| {
            let selection = Selection { nodes, view, slot };
            canonicalize_selected(view, &selection, &algorithm, &policy.resources, &mut output)
        })
        .map_err(|error| error.to_string())?;
    Ok(output)
}

/// The octets of `nodes` over `view`, a snapshot of the document in `slot`:
/// inclusive C14N 1.0 without comments, the conversion of a node set to
/// octets (`XMLDSig` 1.1 section 4.4.3.2).
///
/// # Safety
/// `nodes` is a live node set over the document `view` reads.
pub(super) unsafe fn selected_octets(
    view: DocumentView<'_>,
    slot: usize,
    nodes: *mut XmlSecNodeSet,
    resources: &xml_sec::policy::ResourcePolicy,
) -> Option<Vec<u8>> {
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let selection = Selection { nodes, view, slot };
    let mut output = Vec::new();
    canonicalize_selected(view, &selection, &algorithm, resources, &mut output).ok()?;
    Some(output)
}

/// Writes the C14N form of `nodes` for klass `id` to the output buffer
/// `out`, under the policy of the run of `ctx`.
///
/// # Safety
/// `nodes` is a live node set; `list` is the transform's prefix list;
/// `out`'s callbacks are callable; `ctx` is null or an initialized context.
unsafe fn c14n_execute(
    id: *const XmlSecTransformKlass,
    nodes: *mut XmlSecNodeSet,
    list: &XmlSecPtrList,
    out: *mut OutputBuffer,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    check!(
        !id.is_null(),
        "xmlSecTransformC14NExecute",
        c"id != xmlSecTransformIdUnknown",
        -1
    );
    check!(
        !nodes.is_null(),
        "xmlSecTransformC14NExecute",
        c"nodes != NULL",
        -1
    );
    check!(
        // SAFETY: a node set.
        !unsafe { (*nodes).doc }.is_null(),
        "xmlSecTransformC14NExecute",
        c"nodes->doc != NULL",
        -1
    );
    check!(
        !out.is_null(),
        "xmlSecTransformC14NExecute",
        c"buf != NULL",
        -1
    );
    let here = here!("xmlSecTransformC14NExecute");
    // SAFETY: by the caller's contract.
    unsafe {
        let name = (*id).name.cast();
        if std::ptr::eq(id, remove_xml_tags_c14n()) {
            let result = xmlSecNodeSetDumpTextNodes(nodes, out);
            if result < 0 {
                errors::xml_failed(here, name, c"xmlC14NExecute");
            }
            return result;
        }
        let Some((mode, comments)) = algorithm_of(id) else {
            errors::other(here, errors::R_INVALID_TRANSFORM, name, None);
            return -1;
        };
        let prefixes = (mode == C14nMode::Exclusive1_0 && list.used > 0).then(|| {
            (0..list.used)
                .map(|index| list.data.add(index).read())
                .filter(|item| !item.is_null())
                .map(|item| {
                    std::ffi::CStr::from_ptr(item.cast())
                        .to_string_lossy()
                        .into_owned()
                })
                .collect::<Vec<_>>()
                .join(" ")
        });
        let pinned = if ctx.is_null() {
            policy::Pinned::current(here)
        } else {
            run_policy(ctx, here)
        };
        let Some(pinned) = pinned else {
            return -1;
        };
        let bytes = match canonical(nodes, mode, comments, prefixes, &pinned.verification) {
            Ok(bytes) => bytes,
            Err(error) => {
                // The core canonicalizes in place of libxml2's
                // `xmlC14NExecute`; its error is the cause.
                errors::report(
                    here,
                    name,
                    c"xmlC14NExecute".as_ptr(),
                    errors::R_XML_FAILED,
                    &error,
                );
                return -1;
            }
        };
        for chunk in bytes.chunks(c_int::MAX.unsigned_abs() as usize) {
            let len = c_int::try_from(chunk.len()).expect("a chunk is at most c_int::MAX bytes");
            if xmlOutputBufferWrite(out, len, chunk.as_ptr().cast()) < 0 {
                errors::xml_failed(here, name, c"xmlOutputBufferWrite");
                return -1;
            }
        }
        0
    }
}

unsafe extern "C" fn c14n_push_xml(
    transform: *mut XmlSecTransform,
    nodes: *mut XmlSecNodeSet,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: the caller passes null or a transform.
    let Some(list) = (unsafe { c14n_list(transform, here!("xmlSecTransformC14NPushXml")) }) else {
        return -1;
    };
    // SAFETY: a valid transform.
    let id = unsafe { (*transform).id };
    let render = |nodes, out| {
        // SAFETY: the node set, the prefix list, the output buffer and the
        // context are live for the call.
        unsafe { c14n_execute(id, nodes, list, out, ctx) }
    };
    // SAFETY: a C14N-family transform, its chain and context.
    unsafe {
        push_rendered(
            transform,
            nodes,
            ctx,
            (render, c"xmlSecTransformC14NExecute"),
            here!("xmlSecTransformC14NPushXml"),
        )
    }
}

/// The push side of a node-set-to-octets klass: on the first push, `render`
/// (named `rendered` in reports) writes the octets of `nodes` to the next
/// transform, or to the object's own output buffer at the end of the chain.
/// Failures are reported from the entry point at `here`.
///
/// # Safety
/// `transform` is a valid transform of its chain; `ctx` is null or its
/// context.
pub(crate) unsafe fn push_rendered(
    transform: *mut XmlSecTransform,
    nodes: *mut XmlSecNodeSet,
    ctx: *mut XmlSecTransformCtx,
    (render, rendered): (
        impl FnOnce(*mut XmlSecNodeSet, *mut OutputBuffer) -> c_int,
        &CStr,
    ),
    here: errors::Here,
) -> c_int {
    if nodes.is_null() {
        errors::assertion(here, c"nodes != NULL");
        return -1;
    }
    // SAFETY: a node set.
    if unsafe { (*nodes).doc }.is_null() {
        errors::assertion(here, c"nodes->doc != NULL");
        return -1;
    }
    if ctx.is_null() {
        errors::assertion(here, c"transformCtx != NULL");
        return -1;
    }
    // SAFETY: by the caller's contract.
    unsafe {
        let name = name_of(transform);
        let object = &mut *transform;
        match object.status {
            STATUS_NONE => object.status = STATUS_WORKING,
            STATUS_WORKING | STATUS_FINISHED => return 0,
            status => {
                errors::invalid_status(here, name, status);
                return -1;
            }
        }
        let out = if object.next.is_null() {
            let out = xmlSecBufferCreateOutputBuffer(&raw mut object.out_buf);
            if out.is_null() {
                errors::internal(here, name, c"xmlSecBufferCreateOutputBuffer");
            }
            out
        } else {
            let out = xmlSecTransformCreateOutputBuffer(object.next, ctx);
            if out.is_null() {
                errors::internal(here, name, c"xmlSecTransformCreateOutputBuffer");
            }
            out
        };
        if out.is_null() {
            return -1;
        }
        if render(nodes, out) < 0 {
            errors::internal(here, name, rendered);
            xmlOutputBufferClose(out);
            return -1;
        }
        if xmlOutputBufferClose(out) < 0 {
            errors::xml_failed(here, name, c"xmlOutputBufferClose");
            return -1;
        }
        object.status = STATUS_FINISHED;
        0
    }
}

unsafe extern "C" fn c14n_pop_bin(
    transform: *mut XmlSecTransform,
    data: *mut u8,
    max_size: usize,
    size: *mut usize,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: the caller passes null or a transform.
    let Some(list) = (unsafe { c14n_list(transform, here!("xmlSecTransformC14NPopBin")) }) else {
        return -1;
    };
    // SAFETY: a valid transform.
    let id = unsafe { (*transform).id };
    let render = |nodes, out| {
        // SAFETY: the node set, the prefix list, the output buffer and the
        // context are live for the call.
        unsafe { c14n_execute(id, nodes, list, out, ctx) }
    };
    let target = PopTarget {
        data,
        max_size,
        size,
    };
    // SAFETY: a C14N-family transform, its chain and context.
    unsafe {
        pop_rendered(
            transform,
            target,
            ctx,
            (render, c"xmlSecTransformC14NExecute"),
            here!("xmlSecTransformC14NPopBin"),
        )
    }
}

/// Where [`pop_rendered`] writes: `max_size` bytes at `data`, the count
/// written to `size`.
#[derive(Clone, Copy)]
pub(crate) struct PopTarget {
    pub(crate) data: *mut u8,
    pub(crate) max_size: usize,
    pub(crate) size: *mut usize,
}

/// The pop side of a node-set-to-octets klass: on the first pop, `render`
/// (named `rendered` in reports) writes the octets of the node set the
/// previous transform pops to the object's output buffer, which then drains
/// in chunks. Failures are reported from the entry point at `here`.
///
/// # Safety
/// `transform` is a valid transform of its chain; `ctx` is null or its
/// context; `target.data` is null or holds `target.max_size` writable bytes;
/// `target.size` is null or writable.
pub(crate) unsafe fn pop_rendered(
    transform: *mut XmlSecTransform,
    target: PopTarget,
    ctx: *mut XmlSecTransformCtx,
    (render, rendered): (
        impl FnOnce(*mut XmlSecNodeSet, *mut OutputBuffer) -> c_int,
        &CStr,
    ),
    here: errors::Here,
) -> c_int {
    let PopTarget {
        data,
        max_size,
        size,
    } = target;
    if data.is_null() {
        errors::assertion(here, c"data != NULL");
        return -1;
    }
    if size.is_null() {
        errors::assertion(here, c"dataSize != NULL");
        return -1;
    }
    if ctx.is_null() {
        errors::assertion(here, c"transformCtx != NULL");
        return -1;
    }
    // SAFETY: by the caller's contract.
    unsafe {
        let name = name_of(transform);
        let chunk_size = (*ctx).binary_chunk_size;
        let object = &mut *transform;
        let out = &raw mut object.out_buf;
        if object.status == STATUS_NONE {
            if !object.in_nodes.is_null() {
                errors::assertion(here, c"transform->inNodes == NULL");
                return -1;
            }
            if object.prev.is_null() {
                size.write(0);
                object.status = STATUS_FINISHED;
                return 0;
            }
            if xmlSecTransformPopXml(object.prev, &raw mut object.in_nodes, ctx) < 0 {
                errors::internal(here, name, c"xmlSecTransformPopXml");
                return -1;
            }
            let buffer = xmlSecBufferCreateOutputBuffer(out);
            if buffer.is_null() {
                errors::internal(here, name, c"xmlSecBufferCreateOutputBuffer");
                return -1;
            }
            if render(object.in_nodes, buffer) < 0 {
                errors::internal(here, name, rendered);
                xmlOutputBufferClose(buffer);
                return -1;
            }
            if xmlOutputBufferClose(buffer) < 0 {
                errors::xml_failed(here, name, c"xmlOutputBufferClose");
                return -1;
            }
            object.status = STATUS_WORKING;
        }
        match object.status {
            STATUS_WORKING => {
                let available = xmlSecBufferGetSize(out);
                let chunk = available.min(max_size).min(chunk_size);
                if chunk > 0 {
                    xmlSecBufferGetData(out).copy_to(data, chunk);
                    if xmlSecBufferRemoveHead(out, chunk) < 0 {
                        errors::internal_with(
                            here,
                            name,
                            c"xmlSecBufferRemoveHead",
                            &format!("size={chunk}"),
                        );
                        return -1;
                    }
                } else if available == 0 {
                    object.status = STATUS_FINISHED;
                }
                size.write(chunk);
                0
            }
            STATUS_FINISHED => {
                if xmlSecBufferGetSize(out) != 0 {
                    errors::assertion(here, c"xmlSecBufferGetSize(out) == 0");
                    return -1;
                }
                size.write(0);
                0
            }
            status => {
                errors::invalid_status(here, name, status);
                -1
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Enveloped signature

static ENVELOPED: XmlSecTransformKlass = XmlSecTransformKlass {
    push_xml: Some(xmlSecTransformDefaultPushXml),
    pop_xml: Some(xmlSecTransformDefaultPopXml),
    execute: Some(enveloped_execute),
    ..klass(
        size_of::<XmlSecTransform>(),
        xmlSecNameEnveloped.as_ptr(),
        xmlSecHrefEnveloped.as_ptr(),
        USAGE_DSIG_TRANSFORM,
    )
};

/// Removes the `dsig:Signature` element containing the transform: the
/// output is the input intersected with everything outside that subtree.
unsafe extern "C" fn enveloped_execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: the caller passes null or a transform.
    let checked =
        unsafe { valid(transform) }.filter(|(_, klass)| std::ptr::eq(*klass, &raw const ENVELOPED));
    check!(
        checked.is_some(),
        "xmlSecTransformEnvelopedExecute",
        c"xmlSecTransformCheckId(transform, xmlSecTransformEnvelopedId)",
        -1
    );
    let Some((object, _)) = checked else {
        return -1;
    };
    check!(
        !object.here_node.is_null(),
        "xmlSecTransformEnvelopedExecute",
        c"transform->hereNode != NULL",
        -1
    );
    check!(
        object.out_nodes.is_null(),
        "xmlSecTransformEnvelopedExecute",
        c"transform->outNodes == NULL",
        -1
    );
    check!(
        last != 0,
        "xmlSecTransformEnvelopedExecute",
        c"last != 0",
        -1
    );
    check!(
        !ctx.is_null(),
        "xmlSecTransformEnvelopedExecute",
        c"transformCtx != NULL",
        -1
    );
    let here = here!("xmlSecTransformEnvelopedExecute");
    // SAFETY: an enveloped transform read from a live `dsig:Transform`.
    unsafe {
        let name = name_of(transform);
        if !object.in_nodes.is_null() && (*object.in_nodes).doc != nodes::doc(object.here_node) {
            errors::other(here, errors::R_TRANSFORM_SAME_DOCUMENT_REQUIRED, name, None);
            return -1;
        }
        let signature = xmlSecFindParent(
            object.here_node,
            xmlSecNodeSignature.as_ptr(),
            xmlSecDSigNs.as_ptr(),
        );
        if signature.is_null() {
            errors::node_not_found(
                here,
                c"xmlSecFindParent",
                object.here_node,
                c"Signature",
                name,
            );
            return -1;
        }
        let outside = xmlSecNodeSetGetChildren(nodes::doc(signature), signature, 1, 1);
        if outside.is_null() {
            errors::internal_with(
                here,
                name,
                c"xmlSecNodeSetGetChildren",
                &format!(
                    "node={}",
                    nodes::name(signature).unwrap_or_else(|| "NULL".to_owned())
                ),
            );
            return -1;
        }
        object.out_nodes = xmlSecNodeSetAdd(object.in_nodes, outside, INTERSECTION);
        if object.out_nodes.is_null() {
            errors::internal(here, name, c"xmlSecNodeSetAdd");
            xmlSecNodeSetDestroy(outside);
            return -1;
        }
        0
    }
}
