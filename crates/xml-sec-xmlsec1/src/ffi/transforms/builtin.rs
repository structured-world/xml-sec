//! The built-in transform klasses: the memory-buffer terminal, Base64,
//! canonicalization, the tag-removing conversion and the enveloped-signature
//! transform, with the identities of the others; the `XPath` family lives in
//! [`super::xpath`].
//!
//! Canonicalization takes its semantics from the core: the caller's tree is
//! projected under the library's policy and canonicalized with exactly the
//! nodes, attributes and namespace nodes the input node set contains.

use std::ffi::{c_int, c_uint, c_void};

use xml_sec::c14n::{C14nAlgorithm, C14nMode, SelectedNodes, canonicalize_selected};
use xml_sec::document::external::ExternalNode;
use xml_sec::{DocumentView, Node, XmlDocument};
use xml_sec_libxml2::ffi::{LibxmlTree, XmlAttr, XmlNode};

use super::super::base64::{self, XmlSecBase64Ctx, decode_size, encode_size};
use super::super::buffer::{
    XmlSecBuffer, xmlSecBufferAppend, xmlSecBufferFinalize, xmlSecBufferGetData,
    xmlSecBufferGetSize, xmlSecBufferInitialize, xmlSecBufferRemoveHead, xmlSecBufferSetMaxSize,
    xmlSecBufferSetSize,
};
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
use super::super::tree::{readable, xmlGetProp, xmlSearchNs};
use super::super::xmltree::{xmlSecCheckNodeName, xmlSecFindParent, xmlSecGetNextElementNode};
use super::super::{contain, free, policy};
use super::ctx::{charge, run_budget};
use super::io::{
    xmlOutputBufferClose, xmlOutputBufferWrite, xmlSecBufferCreateOutputBuffer,
    xmlSecTransformCreateOutputBuffer,
};
use super::{
    OPERATION_DECODE, OPERATION_ENCODE, STATUS_FINISHED, STATUS_NONE, STATUS_WORKING,
    USAGE_C14N_METHOD, USAGE_DSIG_TRANSFORM, WithContext, XmlSecTransform, XmlSecTransformCtx,
    XmlSecTransformKlass, context, valid, xmlSecTransformDefaultGetDataType,
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
        // SAFETY: a memory-buffer transform's tail is its buffer.
        unsafe { context::<XmlSecBuffer>(transform, mem_buf()) }
            .map_or(std::ptr::null_mut(), std::ptr::from_mut)
    })
}

unsafe extern "C" fn mem_buf_initialize(transform: *mut XmlSecTransform) -> c_int {
    // SAFETY: the transform is a fresh memory-buffer transform.
    match unsafe { context::<XmlSecBuffer>(transform, mem_buf()) } {
        // SAFETY: the tail is writable buffer storage.
        Some(buffer) => unsafe { xmlSecBufferInitialize(buffer, 0) },
        None => -1,
    }
}

unsafe extern "C" fn mem_buf_finalize(transform: *mut XmlSecTransform) {
    // SAFETY: the transform is a memory-buffer transform being destroyed.
    if let Some(buffer) = unsafe { context::<XmlSecBuffer>(transform, mem_buf()) } {
        // SAFETY: an initialized buffer.
        unsafe { xmlSecBufferFinalize(buffer) };
    }
}

unsafe extern "C" fn mem_buf_execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: a memory-buffer transform with its own buffers.
    unsafe {
        let Some(buffer) = context::<XmlSecBuffer>(transform, mem_buf()) else {
            return -1;
        };
        if ctx.is_null() {
            return -1;
        }
        let object = &mut *transform;
        let input = &raw mut object.in_buf;
        let in_size = xmlSecBufferGetSize(input);
        if object.status == STATUS_NONE {
            object.status = STATUS_WORKING;
        }
        match object.status {
            STATUS_WORKING => {
                let data = xmlSecBufferGetData(input);
                if xmlSecBufferAppend(buffer, data, in_size) < 0
                    || xmlSecBufferAppend(&raw mut object.out_buf, data, in_size) < 0
                    || xmlSecBufferRemoveHead(input, in_size) < 0
                {
                    return -1;
                }
                if last != 0 {
                    object.status = STATUS_FINISHED;
                }
                0
            }
            // Only reached without input.
            STATUS_FINISHED if in_size == 0 => 0,
            _ => -1,
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
        // SAFETY: a Base64 transform's tail is its codec context.
        if let Some(codec) = unsafe { context::<XmlSecBase64Ctx>(transform, base64()) } {
            codec.columns = line_size;
        }
    });
}

unsafe extern "C" fn base64_initialize(transform: *mut XmlSecTransform) -> c_int {
    // SAFETY: a fresh Base64 transform.
    unsafe {
        let Some(codec) = context::<XmlSecBase64Ctx>(transform, base64()) else {
            return -1;
        };
        (*transform).operation = OPERATION_DECODE;
        let columns = super::super::base64::xmlSecBase64GetDefaultLineSize();
        match base64::initialize(codec, 0, columns) {
            Some(()) => 0,
            None => -1,
        }
    }
}

unsafe extern "C" fn base64_finalize(transform: *mut XmlSecTransform) {
    // SAFETY: a Base64 transform being destroyed.
    if let Some(codec) = unsafe { context::<XmlSecBase64Ctx>(transform, base64()) } {
        // SAFETY: the codec context is plain data.
        unsafe { std::ptr::from_mut(codec).write_bytes(0, 1) };
    }
}

/// Grows `out` by up to `reserve` bytes and lets `step` write into the new
/// room; the size is then set to what was written.
///
/// # Safety
/// `out` is a valid buffer.
unsafe fn write_into(
    out: *mut XmlSecBuffer,
    reserve: usize,
    step: impl FnOnce(&mut [u8]) -> Option<usize>,
) -> Option<()> {
    // SAFETY: after growing, `out` holds `size + reserve` bytes.
    unsafe {
        let size = xmlSecBufferGetSize(out);
        let total = size.checked_add(reserve)?;
        if xmlSecBufferSetMaxSize(out, total) < 0 {
            return None;
        }
        let room = std::slice::from_raw_parts_mut(xmlSecBufferGetData(out).add(size), reserve);
        let written = step(room)?;
        (xmlSecBufferSetSize(out, size + written) >= 0).then_some(())
    }
}

unsafe extern "C" fn base64_execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: a Base64 transform with its own buffers.
    unsafe {
        let Some(codec) = context::<XmlSecBase64Ctx>(transform, base64()) else {
            return -1;
        };
        let object = &mut *transform;
        if (object.operation != OPERATION_ENCODE && object.operation != OPERATION_DECODE)
            || ctx.is_null()
        {
            return -1;
        }
        let input = &raw mut object.in_buf;
        let output = &raw mut object.out_buf;
        if object.status == STATUS_NONE {
            codec.encode = c_int::from(object.operation == OPERATION_ENCODE);
            object.status = STATUS_WORKING;
        }
        match object.status {
            STATUS_WORKING => {
                let Some(policy) = policy::verification() else {
                    return -1;
                };
                let resources = &policy.resources;
                let budget = run_budget(ctx);
                let before = xmlSecBufferGetSize(output);
                let in_size = xmlSecBufferGetSize(input);
                if in_size > 0 {
                    // Input is charged before the codec allocates for it,
                    // which bounds that allocation too.
                    if charge(
                        &mut budget.base64_input,
                        in_size,
                        resources.max_base64_transform_input_bytes,
                    )
                    .is_none()
                    {
                        return -1;
                    }
                    let reserve = if codec.encode != 0 {
                        encode_size(codec.columns, in_size)
                    } else {
                        decode_size(in_size)
                    };
                    let Some(reserve) = reserve else {
                        return -1;
                    };
                    let data = std::slice::from_raw_parts(xmlSecBufferGetData(input), in_size);
                    if write_into(output, reserve, |room| {
                        base64::update(codec, data, room).ok()
                    })
                    .is_none()
                        || xmlSecBufferRemoveHead(input, in_size) < 0
                    {
                        return -1;
                    }
                }
                // The last group and padding fit in 16 bytes.
                if last != 0
                    && write_into(output, 16, |room| base64::finish(codec, room).ok()).is_none()
                {
                    return -1;
                }
                // Output is charged before it moves on: a refused step
                // leaves it in this transform's buffer.
                if charge(
                    &mut budget.base64_output,
                    xmlSecBufferGetSize(output) - before,
                    resources.max_base64_transform_output_bytes,
                )
                .is_none()
                {
                    return -1;
                }
                if last != 0 {
                    object.status = STATUS_FINISHED;
                }
                0
            }
            // Only reached without input.
            STATUS_FINISHED if xmlSecBufferGetSize(input) == 0 => 0,
            _ => -1,
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

/// The prefix list of a C14N transform, from its context.
///
/// # Safety
/// `transform` is null or a valid transform.
unsafe fn c14n_list<'a>(transform: *mut XmlSecTransform) -> Option<&'a mut XmlSecPtrList> {
    // SAFETY: a C14N-family transform's tail is its prefix list.
    unsafe {
        let (_, klass) = valid(transform)?;
        if !is_c14n(klass) {
            return None;
        }
        context::<XmlSecPtrList>(transform, klass)
    }
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
    // SAFETY: a fresh C14N-family transform.
    match unsafe { c14n_list(transform) } {
        // SAFETY: the tail is writable list storage.
        Some(list) => unsafe { xmlSecPtrListInitialize(list, xmlSecStringListGetKlass()) },
        None => -1,
    }
}

unsafe extern "C" fn c14n_finalize(transform: *mut XmlSecTransform) {
    // SAFETY: a C14N-family transform being destroyed.
    if let Some(list) = unsafe { c14n_list(transform) } {
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
    // SAFETY: an exclusive C14N transform and a live element of its document.
    unsafe {
        let Some(list) = c14n_list(transform) else {
            return -1;
        };
        if node.is_null() || ctx.is_null() || xmlSecPtrListGetSize(list) != 0 {
            return -1;
        }
        let mut current = xmlSecGetNextElementNode((*node).children);
        if !current.is_null() {
            if xmlSecCheckNodeName(
                current,
                xmlSecNodeInclusiveNamespaces.as_ptr(),
                xmlSecNsExcC14N.as_ptr(),
            ) == 0
            {
                return -1;
            }
            let prefixes = xmlGetProp(current, xmlSecAttrPrefixList.as_ptr());
            if prefixes.is_null() {
                return -1;
            }
            let text = std::ffi::CStr::from_ptr(prefixes.cast())
                .to_bytes()
                .to_vec();
            free(prefixes.cast());
            // Single spaces separate the prefixes, as libxmlsec1 splits them.
            for prefix in text.split(|&byte| byte == b' ') {
                let copy = super::super::malloc(prefix.len() + 1).cast::<u8>();
                if copy.is_null() {
                    return -1;
                }
                prefix.as_ptr().copy_to(copy, prefix.len());
                copy.add(prefix.len()).write(0);
                if xmlSecPtrListAdd(list, copy.cast()) < 0 {
                    free(copy.cast());
                    return -1;
                }
            }
            if xmlSecPtrListAdd(list, std::ptr::null_mut()) < 0 {
                return -1;
            }
            current = xmlSecGetNextElementNode((*current).next);
        }
        if current.is_null() { 0 } else { -1 }
    }
}

/// The caller's node set read node by node for the core's serializer.
struct Selection<'v> {
    nodes: *mut XmlSecNodeSet,
    view: DocumentView<'v>,
}

/// The libxml2 node an external record names.
fn node_of(record: ExternalNode) -> *mut XmlNode {
    std::ptr::with_exposed_provenance_mut(usize::try_from(record.0).unwrap_or(0))
}

impl Selection<'_> {
    /// libxmlsec1's visibility test: a membership check that fails (-1)
    /// counts as visible, as the C truth test does.
    fn contains(&self, node: *mut XmlNode, parent: *mut XmlNode) -> bool {
        // SAFETY: the node set and the projected tree's nodes are live for the
        // canonicalization, which runs inside the call that owns them.
        unsafe { xmlSecNodeSetContains(self.nodes, node, parent) != 0 }
    }

    fn element(&self, owner: Node<'_, '_>) -> Option<*mut XmlNode> {
        self.view.external_node_of(owner).map(node_of)
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
                let part = node_of((*part)?);
                // SAFETY: a live node of the projected tree.
                let contained = self.contains(part, unsafe { (*part).parent });
                match verdict {
                    None => verdict = Some(contained),
                    Some(previous) if previous != contained => return None,
                    Some(_) => {}
                }
            }
            return verdict;
        }
        let node = self.element(node)?;
        // SAFETY: a live node of the projected tree.
        Some(self.contains(node, unsafe { (*node).parent }))
    }

    fn attribute(
        &self,
        owner: Node<'_, '_>,
        namespace: Option<&str>,
        local_name: &str,
    ) -> Option<bool> {
        let element = self.element(owner)?;
        // SAFETY: the element's attributes, names and namespaces are live.
        unsafe {
            let mut attribute: *mut XmlAttr = (*element).properties;
            while !attribute.is_null() {
                let name = std::ffi::CStr::from_ptr((*attribute).name.cast()).to_bytes();
                let href = (*attribute)
                    .ns
                    .as_ref()
                    .map(|ns| std::ffi::CStr::from_ptr(ns.href.cast()).to_bytes());
                if name == local_name.as_bytes() && href == namespace.map(str::as_bytes) {
                    return Some(self.contains(attribute.cast(), element));
                }
                attribute = (*attribute).next;
            }
        }
        None
    }

    fn namespace(&self, owner: Node<'_, '_>, prefix: &str, _uri: &str) -> Option<bool> {
        let element = self.element(owner)?;
        let prefix = std::ffi::CString::new(prefix).ok()?;
        // SAFETY: a live element of a live document; the nearest declaration
        // of the prefix is the namespace node libxml2's canonicalizer tests.
        unsafe {
            let prefix = if prefix.is_empty() {
                std::ptr::null()
            } else {
                prefix.as_ptr().cast()
            };
            let declaration = xmlSearchNs((*element).doc, element, prefix);
            if declaration.is_null() {
                // An undeclared default namespace has no node to test.
                return Some(self.contains(element, (*element).parent));
            }
            Some(self.contains(declaration.cast(), element))
        }
    }
}

/// The canonical form of `nodes` under `mode`, or `None` when the tree cannot
/// be projected or canonicalized under the library's policy.
///
/// # Safety
/// `nodes` is a live node set over a live document.
unsafe fn canonical(
    nodes: *mut XmlSecNodeSet,
    mode: C14nMode,
    comments: bool,
    prefixes: Option<String>,
) -> Option<Vec<u8>> {
    let policy = policy::verification()?;
    // SAFETY: the node set's document is live for the call.
    let tree = unsafe { LibxmlTree::new((*nodes).doc) }?;
    let document = XmlDocument::from_external_tree(Box::new(tree), policy).ok()?;
    let mut algorithm = C14nAlgorithm::new(mode, comments);
    if let Some(prefixes) = prefixes {
        algorithm = algorithm.with_prefix_list(&prefixes);
    }
    let mut output = Vec::new();
    document
        .with_view(|view| {
            let selection = Selection { nodes, view };
            canonicalize_selected(view, &selection, &algorithm, &policy.resources, &mut output)
        })
        .ok()?;
    Some(output)
}

/// The octets of `nodes` over `view`, its projection: inclusive C14N 1.0
/// without comments, the conversion of a node set to octets (`XMLDSig` 1.1
/// section 4.4.3.2).
///
/// # Safety
/// `nodes` is a live node set over the document `view` projects.
pub(super) unsafe fn selected_octets(
    view: DocumentView<'_>,
    nodes: *mut XmlSecNodeSet,
    resources: &xml_sec::policy::ResourcePolicy,
) -> Option<Vec<u8>> {
    let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
    let selection = Selection { nodes, view };
    let mut output = Vec::new();
    canonicalize_selected(view, &selection, &algorithm, resources, &mut output).ok()?;
    Some(output)
}

/// Writes the C14N form of `nodes` for klass `id` to the libxml2 output
/// buffer `out`.
///
/// # Safety
/// `nodes` is a live node set over a live document; `list` is the
/// transform's prefix list; `out` is a live output buffer.
unsafe fn c14n_execute(
    id: *const XmlSecTransformKlass,
    nodes: *mut XmlSecNodeSet,
    list: &XmlSecPtrList,
    out: *mut c_void,
) -> c_int {
    // SAFETY: by the caller's contract.
    unsafe {
        if nodes.is_null() || (*nodes).doc.is_null() || !readable() {
            return -1;
        }
        if std::ptr::eq(id, remove_xml_tags_c14n()) {
            return xmlSecNodeSetDumpTextNodes(nodes, out);
        }
        let Some((mode, comments)) = algorithm_of(id) else {
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
        let Some(bytes) = canonical(nodes, mode, comments, prefixes) else {
            return -1;
        };
        for chunk in bytes.chunks(c_int::MAX.unsigned_abs() as usize) {
            let Ok(len) = c_int::try_from(chunk.len()) else {
                return -1;
            };
            if xmlOutputBufferWrite(out, len, chunk.as_ptr().cast()) < 0 {
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
    // SAFETY: a C14N-family transform, its chain and context.
    unsafe {
        let Some(list) = c14n_list(transform) else {
            return -1;
        };
        let id = (*transform).id;
        push_rendered(transform, nodes, ctx, |nodes, out| {
            c14n_execute(id, nodes, list, out)
        })
    }
}

/// The push side of a node-set-to-octets klass: on the first push, `render`
/// writes the octets of `nodes` to the next transform, or to the object's
/// own output buffer at the end of the chain.
///
/// # Safety
/// `transform` is a valid transform of its chain; `ctx` is its context.
pub(crate) unsafe fn push_rendered(
    transform: *mut XmlSecTransform,
    nodes: *mut XmlSecNodeSet,
    ctx: *mut XmlSecTransformCtx,
    render: impl FnOnce(*mut XmlSecNodeSet, *mut c_void) -> c_int,
) -> c_int {
    // SAFETY: by the caller's contract.
    unsafe {
        if nodes.is_null() || (*nodes).doc.is_null() || ctx.is_null() {
            return -1;
        }
        let object = &mut *transform;
        match object.status {
            STATUS_NONE => object.status = STATUS_WORKING,
            STATUS_WORKING | STATUS_FINISHED => return 0,
            _ => return -1,
        }
        let out = if object.next.is_null() {
            xmlSecBufferCreateOutputBuffer(&raw mut object.out_buf)
        } else {
            xmlSecTransformCreateOutputBuffer(object.next, ctx)
        };
        if out.is_null() {
            return -1;
        }
        if render(nodes, out) < 0 {
            xmlOutputBufferClose(out);
            return -1;
        }
        if xmlOutputBufferClose(out) < 0 {
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
    // SAFETY: a C14N-family transform, its chain and context.
    unsafe {
        let Some(list) = c14n_list(transform) else {
            return -1;
        };
        let id = (*transform).id;
        pop_rendered(transform, data, max_size, size, ctx, |nodes, out| {
            c14n_execute(id, nodes, list, out)
        })
    }
}

/// The pop side of a node-set-to-octets klass: on the first pop, `render`
/// writes the octets of the node set the previous transform pops to the
/// object's output buffer, which then drains in chunks.
///
/// # Safety
/// `transform` is a valid transform of its chain; `ctx` is its context;
/// `data` holds `max_size` writable bytes.
pub(crate) unsafe fn pop_rendered(
    transform: *mut XmlSecTransform,
    data: *mut u8,
    max_size: usize,
    size: *mut usize,
    ctx: *mut XmlSecTransformCtx,
    render: impl FnOnce(*mut XmlSecNodeSet, *mut c_void) -> c_int,
) -> c_int {
    // SAFETY: by the caller's contract.
    unsafe {
        let Some(context) = ctx.as_ref() else {
            return -1;
        };
        if data.is_null() || size.is_null() {
            return -1;
        }
        let object = &mut *transform;
        let out = &raw mut object.out_buf;
        if object.status == STATUS_NONE {
            if !object.in_nodes.is_null() {
                return -1;
            }
            if object.prev.is_null() {
                size.write(0);
                object.status = STATUS_FINISHED;
                return 0;
            }
            if xmlSecTransformPopXml(object.prev, &raw mut object.in_nodes, ctx) < 0 {
                return -1;
            }
            let buffer = xmlSecBufferCreateOutputBuffer(out);
            if buffer.is_null() {
                return -1;
            }
            if render(object.in_nodes, buffer) < 0 {
                xmlOutputBufferClose(buffer);
                return -1;
            }
            if xmlOutputBufferClose(buffer) < 0 {
                return -1;
            }
            object.status = STATUS_WORKING;
        }
        match object.status {
            STATUS_WORKING => {
                let available = xmlSecBufferGetSize(out);
                let chunk = available.min(max_size).min(context.binary_chunk_size);
                if chunk > 0 {
                    xmlSecBufferGetData(out).copy_to(data, chunk);
                    if xmlSecBufferRemoveHead(out, chunk) < 0 {
                        return -1;
                    }
                } else if available == 0 {
                    object.status = STATUS_FINISHED;
                }
                size.write(chunk);
                0
            }
            STATUS_FINISHED if xmlSecBufferGetSize(out) == 0 => {
                size.write(0);
                0
            }
            _ => -1,
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
    // SAFETY: an enveloped transform read from a live `dsig:Transform`.
    unsafe {
        let Some((object, klass)) = valid(transform) else {
            return -1;
        };
        if !std::ptr::eq(klass, &raw const ENVELOPED)
            || object.here_node.is_null()
            || !object.out_nodes.is_null()
            || last == 0
            || ctx.is_null()
        {
            return -1;
        }
        if !object.in_nodes.is_null() && (*object.in_nodes).doc != (*object.here_node).doc {
            return -1;
        }
        let signature = xmlSecFindParent(
            object.here_node,
            xmlSecNodeSignature.as_ptr(),
            xmlSecDSigNs.as_ptr(),
        );
        if signature.is_null() {
            return -1;
        }
        let outside = xmlSecNodeSetGetChildren((*signature).doc, signature, 1, 1);
        if outside.is_null() {
            return -1;
        }
        object.out_nodes = xmlSecNodeSetAdd(object.in_nodes, outside, INTERSECTION);
        if object.out_nodes.is_null() {
            xmlSecNodeSetDestroy(outside);
            return -1;
        }
        0
    }
}

// ----------------------------------------------------------------------------
// URI input

static INPUT_URI: XmlSecTransformKlass = klass(
    size_of::<XmlSecTransform>(),
    c"input-uri".as_ptr().cast(),
    std::ptr::null(),
    0,
);

/// The URI input klass.
pub(crate) fn input_uri() -> *const XmlSecTransformKlass {
    &raw const INPUT_URI
}

/// `xmlSecTransformInputURIOpen`: opens the resource a URI input transform
/// reads.
///
/// # Safety
/// `transform` is null or a valid transform; `uri` is null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformInputURIOpen(
    _transform: *mut XmlSecTransform,
    _uri: *const u8,
) -> c_int {
    -1
}

/// `xmlSecTransformInputURIClose`: closes the resource of a URI input
/// transform.
///
/// # Safety
/// `transform` is null or a valid transform.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformInputURIClose(
    _transform: *mut XmlSecTransform,
) -> c_int {
    -1
}
