//! Decryption with an encryption context.
//!
//! The `EncryptedData` element is read as libxmlsec1 reads it: its method
//! through the registered klasses, its cipher data, its key through the read
//! `KeyInfo` context. The core then decrypts exactly that element of the
//! caller's tree under the library policy; the plaintext becomes the
//! context's result and, when the element's `Type` asks, replaces it.

use std::ffi::c_int;

use xml_sec::document::external::ExternalNode;
use xml_sec::xmlenc::{
    DataEncryptionAlgorithm, DecryptContext, DecryptedContent, DecryptionKeyResolver,
    SymmetricKeyDecryptor,
};
use zeroize::Zeroizing;

use super::super::buffer::{
    XmlSecBuffer, xmlSecBufferGetData, xmlSecBufferGetSize, xmlSecBufferSetData,
};
use super::super::errors::{self, here};
use super::super::keyinfo::xmlSecKeyInfoNodeWrite;
use super::super::keys::{xmlSecKeyGetValue, xmlSecKeyMatch};
use super::super::keysdata::xmlSecKeyDataBinaryValueGetBuffer;
use super::super::policy::{Pinned, Side, SlotPin};
use super::super::strings;
use super::super::transforms::builtin::xmlSecTransformBase64GetKlass;
use super::super::transforms::ctx::{
    ReadResources, ResourceScope, charge_key_info, external_spent, leave_unspent, operation_side,
    read_resource, run_budget, run_policy, run_pre_execute, run_spent,
    xmlSecTransformCtxBinaryExecute, xmlSecTransformCtxExecute,
};
use super::super::transforms::ctx::{
    ctx_node_read_for, xmlSecTransformCtxCreateAndAppend, xmlSecTransformCtxCreateAndPrepend,
    xmlSecTransformCtxNodesListRead, xmlSecTransformCtxSetUri,
};
use super::super::transforms::{
    OPERATION_DECRYPT, OPERATION_ENCRYPT, USAGE_DSIG_TRANSFORM, USAGE_ENCRYPTION_METHOD,
    xmlSecTransformSetKey, xmlSecTransformSetKeyReq,
};
use super::super::tree::{XmlNode, c_text, give, nodes};
use super::super::xmltree::{
    replace_node_buffer_under, xmlSecAddIDs, xmlSecCheckNodeName, xmlSecGetNextElementNode,
    xmlSecGetNodeContentAndTrim, xmlSecReplaceContentAndReturn, xmlSecReplaceNodeAndReturn,
};
use super::{
    FAILURE_KEY_NOT_FOUND, FAILURE_UNKNOWN, FLAGS_RETURN_REPLACED_NODE, MODE_ENCRYPTED_DATA,
    MODE_ENCRYPTED_KEY, XmlSecEncCtx,
};
use xml_sec_libxml2::ffi::tree::{
    xsAddChild, xsDocCopyNode, xsFreeNode, xsNodeGetChildren, xsNodeGetDoc, xsUnlinkNode,
};

/// A name of libxmlsec1's strings.
macro_rules! name {
    ($name:ident) => {
        strings::$name.as_ptr()
    };
}

/// Whether `node` is the element `name` of the namespace `ns`.
///
/// # Safety
/// `node` is null or a live node.
pub(super) unsafe fn is(node: *mut XmlNode, name: *const u8, ns: *const u8) -> bool {
    // SAFETY: by the caller's contract.
    !node.is_null() && unsafe { xmlSecCheckNodeName(node, name, ns) } != 0
}

/// The first element child of `node`.
///
/// # Safety
/// `node` is a live node.
pub(super) unsafe fn first_element(node: *mut XmlNode) -> *mut XmlNode {
    // SAFETY: by the caller's contract.
    unsafe { xmlSecGetNextElementNode(xsNodeGetChildren(node)) }
}

/// The next element sibling of `node`.
///
/// # Safety
/// `node` is a live node.
pub(super) unsafe fn next_element(node: *mut XmlNode) -> *mut XmlNode {
    // SAFETY: by the caller's contract.
    unsafe { xmlSecGetNextElementNode(nodes::next(node)) }
}

/// The C copy of the attribute `name` of `node`, null when absent.
fn attribute(node: *mut XmlNode, name: &str) -> *mut u8 {
    give(nodes::property(node, name).as_deref())
}

/// Registers the `Id` attributes of `node`'s subtree as IDs, as libxmlsec1
/// registers those of an encryption element.
///
/// # Safety
/// `node` is a live node.
pub(super) unsafe fn add_ids(node: *mut XmlNode) {
    let ids = [name!(xmlSecAttrId), std::ptr::null()];
    // SAFETY: a live node of its document and a null-terminated list.
    unsafe { xmlSecAddIDs(xsNodeGetDoc(node), node, ids.as_ptr()) };
}

/// The template `tmpl` read for an encryption, its `Id` attributes
/// registered, after libxmlsec1's preconditions at `here`; negative after a
/// report.
///
/// # Safety
/// `tmpl` is null or a live node.
unsafe fn begin_encryption(
    ctx: &mut XmlSecEncCtx,
    tmpl: *mut XmlNode,
    here: errors::Here,
) -> c_int {
    if !ctx.result.is_null() {
        errors::assertion(here, c"encCtx->result == NULL");
        return -1;
    }
    if tmpl.is_null() {
        errors::assertion(here, c"tmpl != NULL");
        return -1;
    }
    ctx.operation = OPERATION_ENCRYPT;
    // SAFETY: a live node.
    unsafe {
        add_ids(tmpl);
        if read_enc_data(ctx, tmpl, true) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeRead");
            return -1;
        }
    }
    0
}

/// Runs `encrypt`, which writes an encryption into the template `tmpl` and
/// may put it in the caller's tree, and puts the template back as it was
/// when it fails, as when the document it would leave passes a limit: a
/// refused encryption leaves the caller's template unchanged, and every
/// node of it the caller holds a handle to still in its place.
///
/// # Safety
/// `tmpl` is null or a live node; `encrypt` writes only inside it, or moves
/// it whole.
unsafe fn restoring_template(
    tmpl: *mut XmlNode,
    here: errors::Here,
    encrypt: impl FnOnce() -> c_int,
) -> c_int {
    if tmpl.is_null() {
        return encrypt();
    }
    // SAFETY: a live node of its document.
    let copy = unsafe { xsDocCopyNode(tmpl, xsNodeGetDoc(tmpl), 1) };
    if copy.is_null() {
        errors::internal(here, std::ptr::null(), c"xmlDocCopyNode");
        return -1;
    }
    let pairs = paired_children(tmpl, copy);
    let done = encrypt();
    // SAFETY: the template and its unlinked copy, both live.
    unsafe {
        if done < 0 {
            restore(&pairs);
            add_ids(tmpl);
        }
        xsFreeNode(copy);
    }
    done
}

/// Each element of a template with its children, each child paired with
/// the node in its place in the template's copy.
type ChildPairs = Vec<(*mut XmlNode, Vec<(*mut XmlNode, *mut XmlNode)>)>;

/// The children of each element of `original`'s subtree, each paired with
/// the node of `copy` in its place, a parent before its children.
fn paired_children(original: *mut XmlNode, copy: *mut XmlNode) -> ChildPairs {
    let mut pairs = Vec::new();
    let mut pending = vec![(original, copy)];
    while let Some((parent, copied_parent)) = pending.pop() {
        let mut children = Vec::new();
        let (mut child, mut copied) = (
            nodes::first_child(parent),
            nodes::first_child(copied_parent),
        );
        while !child.is_null() && !copied.is_null() {
            if nodes::is_element(child) {
                pending.push((child, copied));
            }
            children.push((child, copied));
            child = nodes::next(child);
            copied = nodes::next(copied);
        }
        pairs.push((parent, children));
    }
    pairs
}

/// Puts each recorded parent's children back as [`paired_children`] found
/// them: a node still in its place and as it was stays, so a handle to it
/// keeps reaching it; one freed, moved or changed by the encryption gives
/// way to its copy; a node the encryption added is freed.
///
/// # Safety
/// The copied nodes are live and unlinked from the template.
unsafe fn restore(pairs: &ChildPairs) {
    for (parent, children) in pairs {
        // A freed parent gave way to its copy, whose subtree came with it.
        if nodes::tree_node(*parent).is_none() {
            continue;
        }
        let kept: Vec<bool> = children
            .iter()
            .map(|&(child, copied)| nodes::parent(child) == *parent && unchanged(child, copied))
            .collect();
        // SAFETY: live nodes of the template's document.
        unsafe {
            let mut current = Vec::new();
            let mut child = nodes::first_child(*parent);
            while !child.is_null() {
                current.push(child);
                child = nodes::next(child);
            }
            for &child in &current {
                xsUnlinkNode(child);
            }
            for (&(child, copied), &kept) in children.iter().zip(&kept) {
                let node = if kept {
                    child
                } else {
                    xsUnlinkNode(copied);
                    copied
                };
                xsAddChild(*parent, node);
            }
            for child in current {
                if nodes::parent(child).is_null() {
                    xsFreeNode(child);
                }
            }
        }
    }
}

/// Whether `node` is as its copy `copied` was taken: of its kind, an
/// element with its name, attributes and namespace declarations, any other
/// node with its text. An element's children are compared on their own.
fn unchanged(node: *mut XmlNode, copied: *mut XmlNode) -> bool {
    if nodes::kind(node) != nodes::kind(copied) {
        return false;
    }
    if !nodes::is_element(node) {
        return nodes::text(node) == nodes::text(copied);
    }
    let attributes = |element: *mut XmlNode| {
        nodes::attributes(element)
            .into_iter()
            .map(|attribute| {
                (
                    nodes::name(attribute),
                    nodes::namespace(attribute),
                    nodes::content(attribute),
                )
            })
            .collect::<Vec<_>>()
    };
    let declarations = |element: *mut XmlNode| {
        nodes::declarations(element)
            .into_iter()
            .map(|declaration| nodes::binding(declaration))
            .collect::<Vec<_>>()
    };
    nodes::name(node) == nodes::name(copied)
        && nodes::namespace(node) == nodes::namespace(copied)
        && nodes::prefix(node) == nodes::prefix(copied)
        && attributes(node) == attributes(copied)
        && declarations(node) == declarations(copied)
}

/// Encrypts `data` through the context's chain and writes the template.
///
/// # Safety
/// The template was read.
unsafe fn encrypt_bytes(ctx: &mut XmlSecEncCtx, data: &[u8], here: errors::Here) -> c_int {
    let transforms = &raw mut ctx.transform_ctx;
    // SAFETY: the context's own transform context and the caller's bytes.
    unsafe {
        if xmlSecTransformCtxBinaryExecute(transforms, data.as_ptr(), data.len()) < 0 {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecTransformCtxBinaryExecute",
                &format!("dataSize={}", data.len()),
            );
            return -1;
        }
        ctx.result = ctx.transform_ctx.result;
        if ctx.result.is_null() {
            errors::assertion(here, c"encCtx->result != NULL");
            return -1;
        }
        if write_enc_data(ctx) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeWrite");
            return -1;
        }
    }
    0
}

/// What an XML encryption's template takes the place of: the element itself,
/// or its content.
#[derive(Clone, Copy)]
enum Replaced {
    Element(*mut XmlNode),
    Content(*mut XmlNode),
}

/// The octets `replaced` takes in its document's own dump, character
/// references included, measured as the document stands, the written
/// template included. `None` for a node that cannot be written.
///
/// # Safety
/// The node is live.
unsafe fn replaced_octets(replaced: Replaced) -> Option<usize> {
    let node = match replaced {
        Replaced::Element(node) => return nodes::dump_in_document(node).map(|xml| xml.len()),
        Replaced::Content(node) => node,
    };
    let mut total = 0_usize;
    // SAFETY: by the caller's contract.
    let mut child = unsafe { xsNodeGetChildren(node) };
    while !child.is_null() {
        // At most the document's length.
        total += nodes::dump_in_document(child)?.len();
        child = nodes::next(child);
    }
    Some(total)
}

/// Whether the document an encryption leaves fits the operation's
/// `max_xml_document_bytes`, `max_xml_nodes` and `max_xml_depth`, as the
/// core admits the document it writes, after a report at `here`. The
/// written template is that document when it stands alone, or a part of its
/// document when linked into it. When it is to take the place of
/// `replacing`, the document left is that node's: the replaced octets leave
/// it and the template's enter it, unless the template is already a part of
/// its text. A template inside what it replaces is not measured apart: the
/// replacement refuses it, as libxmlsec1 refuses it.
///
/// # Safety
/// `tmpl` is a live node written by the context's encryption; a replaced
/// node is live.
unsafe fn admit_document(
    ctx: &mut XmlSecEncCtx,
    tmpl: *mut XmlNode,
    replacing: Option<Replaced>,
    here: errors::Here,
) -> bool {
    // SAFETY: the context's own transform context and live nodes.
    let (pinned, linked, doc) = unsafe {
        let Some(pinned) = run_policy(&raw mut ctx.transform_ctx, here) else {
            return false;
        };
        (pinned, !nodes::parent(tmpl).is_null(), xsNodeGetDoc(tmpl))
    };
    // Every term is measured as a document's own dump writes it, character
    // references included, so a template's octets are those it adds there.
    let length = |node: *const XmlNode| nodes::dump_in_document(node).map(|xml| xml.len());
    let size = match replacing {
        None if linked => length(doc.cast()),
        None => length(tmpl),
        Some(replaced) => {
            let (Replaced::Element(node) | Replaced::Content(node)) = replaced;
            // SAFETY: live nodes.
            let (destination, measured) =
                unsafe { (xsNodeGetDoc(node), replaced_octets(replaced)) };
            // A written node is a part of its document's text, so its octets
            // never exceed the document's.
            let rest = length(destination.cast())
                .zip(measured)
                .and_then(|(document, octets)| document.checked_sub(octets));
            if linked && doc == destination {
                rest
            } else {
                rest.zip(length(tmpl))
                    .and_then(|(rest, template)| rest.checked_add(template))
            }
        }
    };
    let Some(size) = size else {
        errors::xml_failed(here, std::ptr::null(), c"xmlNodeDumpOutput");
        return false;
    };
    let resources = &pinned.encryption.resources;
    let maximum = resources.max_xml_document_bytes;
    if size > maximum {
        errors::limit_exceeded(here, std::ptr::null(), "max_xml_document_bytes", maximum);
        return false;
    }
    // The nodes and depth of the document left are held to the same policy:
    // the written template's own, or those of the document it is linked
    // into; when it replaces, the replaced node's document without the
    // replaced nodes and wherever the template stood, the template then at
    // the replaced position.
    let (nodes_left, depth) = match replacing {
        None if linked => shape_skipping(doc.cast(), |_| false),
        None => subtree_shape(tmpl),
        Some(replaced) => {
            let (position, skipped) = match replaced {
                Replaced::Element(node) => (nodes::parent(node), node),
                Replaced::Content(node) => (node, node),
            };
            // SAFETY: a live node.
            let destination = unsafe { xsNodeGetDoc(skipped) };
            let element = matches!(replaced, Replaced::Element(_));
            let (rest, _) = shape_skipping(destination.cast(), |node| {
                node == tmpl
                    || if element {
                        node == skipped
                    } else {
                        nodes::parent(node) == skipped
                    }
            });
            let (template_nodes, template_height) = subtree_shape(tmpl);
            // The rest of that document was validated with the source, so
            // only the template at its new position can pass the depth.
            // Within the nodes and depths of two validated trees.
            (
                rest + template_nodes,
                element_depth(position) + template_height,
            )
        }
    };
    if nodes_left > resources.max_xml_nodes {
        errors::limit_exceeded(
            here,
            std::ptr::null(),
            "max_xml_nodes",
            resources.max_xml_nodes,
        );
        return false;
    }
    if depth > resources.max_xml_depth {
        errors::limit_exceeded(
            here,
            std::ptr::null(),
            "max_xml_depth",
            resources.max_xml_depth,
        );
        return false;
    }
    true
}

/// The nodes of `node`'s subtree, `node` included, and the elements on its
/// deepest path, `node` counted when it is one: as the core counts a
/// document's nodes and depth.
pub(super) fn subtree_shape(node: *const XmlNode) -> (usize, usize) {
    shape_skipping(node, |_| false)
}

/// [`subtree_shape`] without the nodes `skip` names, each with its subtree.
fn shape_skipping(node: *const XmlNode, skip: impl Fn(*mut XmlNode) -> bool) -> (usize, usize) {
    let (mut count, mut deepest) = (0_usize, 0_usize);
    let mut pending = vec![(node.cast_mut(), usize::from(nodes::is_element(node)))];
    while let Some((current, depth)) = pending.pop() {
        // At most the nodes and depth of a validated tree.
        count += 1;
        deepest = deepest.max(depth);
        let mut child = nodes::first_child(current);
        while !child.is_null() {
            if !skip(child) {
                pending.push((child, depth + usize::from(nodes::is_element(child))));
            }
            child = nodes::next(child);
        }
    }
    (count, deepest)
}

/// The elements on the path from `node` up to its document, `node` included
/// when it is one.
fn element_depth(node: *const XmlNode) -> usize {
    let mut depth = 0_usize;
    let mut current = node.cast_mut();
    while !current.is_null() {
        // At most the depth of a validated tree.
        depth += usize::from(nodes::is_element(current));
        current = nodes::parent(current);
    }
    depth
}

/// `xmlSecEncCtxBinaryEncrypt` past its first precondition.
///
/// # Safety
/// `tmpl` is null or a live node; `data` holds `size` bytes or is null.
pub(super) unsafe fn binary_encrypt(
    ctx: &mut XmlSecEncCtx,
    tmpl: *mut XmlNode,
    data: *const u8,
    size: usize,
) -> c_int {
    let here = here!("xmlSecEncCtxBinaryEncrypt");
    if data.is_null() && size != 0 {
        errors::assertion(here, c"(data != NULL) || (dataSize == 0)");
        return -1;
    }
    // SAFETY: by the caller's contract.
    unsafe {
        restoring_template(tmpl, here, || {
            if begin_encryption(ctx, tmpl, here) < 0 {
                return -1;
            }
            let data = if data.is_null() {
                &[][..]
            } else {
                std::slice::from_raw_parts(data, size)
            };
            if encrypt_bytes(ctx, data, here) < 0 || !admit_document(ctx, tmpl, None, here) {
                return -1;
            }
            0
        })
    }
}

/// `xmlSecEncCtxXmlEncrypt` past its first precondition: `node` (an
/// `Element` template) or its content (a `Content` one) as libxml2 writes
/// it, encrypted into the template, which then takes its place.
///
/// # Safety
/// `tmpl` and `node` are null or live nodes.
pub(super) unsafe fn xml_encrypt(
    ctx: &mut XmlSecEncCtx,
    tmpl: *mut XmlNode,
    node: *mut XmlNode,
) -> c_int {
    let here = here!("xmlSecEncCtxXmlEncrypt");
    if node.is_null() {
        errors::assertion(here, c"node != NULL");
        return -1;
    }
    // The replacement is a part of what a failure undoes: one it refuses,
    // such as a template inside the element or content it would replace,
    // leaves the template unwritten. It checks before it moves anything.
    // SAFETY: by the caller's contract.
    unsafe {
        restoring_template(tmpl, here, || {
            let mut element = false;
            if encrypt_node(ctx, tmpl, node, &mut element) < 0 {
                return -1;
            }
            let returned = if ctx.flags & FLAGS_RETURN_REPLACED_NODE != 0 {
                &raw mut ctx.replaced_node_list
            } else {
                std::ptr::null_mut()
            };
            let replaced = if element {
                xmlSecReplaceNodeAndReturn(node, tmpl, returned)
            } else {
                xmlSecReplaceContentAndReturn(node, tmpl, returned)
            };
            if replaced < 0 {
                let object = super::super::tree::name_for_report(node);
                errors::internal(here, object.as_ptr(), c"xmlSecReplaceNode");
                return -1;
            }
            ctx.result_replaced = 1;
            0
        })
    }
}

/// [`xml_encrypt`] up to the replacement: `node` (an `Element` template,
/// `element` set) or its content written and encrypted into the template,
/// once the document the replacement leaves is admitted.
///
/// # Safety
/// As for [`xml_encrypt`], with both nodes live.
unsafe fn encrypt_node(
    ctx: &mut XmlSecEncCtx,
    tmpl: *mut XmlNode,
    node: *mut XmlNode,
    element: &mut bool,
) -> c_int {
    let here = here!("xmlSecEncCtxXmlEncrypt");
    // SAFETY: by the caller's contract.
    unsafe {
        if begin_encryption(ctx, tmpl, here) < 0 {
            return -1;
        }
        // libxmlsec1 requires the Type: without it the decryptor could not
        // restore the document (XMLEnc 1.1 section 3.1).
        *element = match c_text(ctx.type_) {
            Some("http://www.w3.org/2001/04/xmlenc#Element") => true,
            Some("http://www.w3.org/2001/04/xmlenc#Content") => false,
            other => {
                // libxmlsec1's xmlSecInvalidStringTypeError.
                errors::report(
                    here,
                    std::ptr::null(),
                    std::ptr::null(),
                    errors::R_INVALID_TYPE,
                    &format!(
                        "invalid type for 'encryption type': actual={}; expected=supported encryption type",
                        other.unwrap_or("NULL")
                    ),
                );
                return -1;
            }
        };
        // The source is held to the encryption policy's XML rules (its DTD,
        // nodes and depth), whatever policy it was parsed under, as the core
        // validates a document it encrypts before reading it.
        let Some(pinned) = run_policy(&raw mut ctx.transform_ctx, here) else {
            return -1;
        };
        if let Err(error) = xml_sec_libxml2::document::snapshot(node, &*pinned.encryption) {
            errors::xml_failed_with(
                here,
                std::ptr::null(),
                c"xmlSecEncCtxXmlEncrypt",
                &error.to_string(),
            );
            return -1;
        }
        let text = if *element {
            nodes::dump(node)
        } else {
            // A child that cannot be written fails the whole content, never
            // a prefix of it.
            let mut text = Some(String::new());
            let mut child = xsNodeGetChildren(node);
            while !child.is_null()
                && let Some(written) = text.as_mut()
            {
                match nodes::dump(child) {
                    Some(dumped) => written.push_str(&dumped),
                    None => text = None,
                }
                child = nodes::next(child);
            }
            text
        };
        // The plaintext is UTF-8, as xmlNodeDumpOutput writes it with no
        // encoding named; what leaves the document is measured once the
        // template is written, as the document's own dump writes it.
        let Some(text) = text else {
            errors::xml_failed(here, std::ptr::null(), c"xmlNodeDumpOutput");
            return -1;
        };
        let replaced = if *element {
            Replaced::Element(node)
        } else {
            Replaced::Content(node)
        };
        if encrypt_bytes(ctx, text.as_bytes(), here) < 0
            || !admit_document(ctx, tmpl, Some(replaced), here)
        {
            return -1;
        }
    }
    0
}

/// `xmlSecTransformUriTypeLocal | xmlSecTransformUriTypeRemote`.
const URI_TYPES_EXTERNAL: std::ffi::c_uint = 0x0004 | 0x0008;

/// `xmlSecEncCtxUriEncrypt` past its first precondition: the resource `uri`
/// names, read through the caller's input callbacks, encrypted into the
/// template `tmpl`.
///
/// # Safety
/// `tmpl` is null or a live node; `uri` null or NUL-terminated.
pub(super) unsafe fn uri_encrypt(
    ctx: &mut XmlSecEncCtx,
    tmpl: *mut XmlNode,
    uri: *const u8,
) -> c_int {
    let here = here!("xmlSecEncCtxUriEncrypt");
    for (holds, expression) in [
        (ctx.result.is_null(), c"encCtx->result == NULL"),
        (!tmpl.is_null(), c"tmpl != NULL"),
        (!uri.is_null(), c"uri != NULL"),
    ] {
        if !holds {
            errors::assertion(here, expression);
            return -1;
        }
    }
    ctx.operation = OPERATION_ENCRYPT;
    let transforms = &raw mut ctx.transform_ctx;
    // SAFETY: a live node, the caller's string and the context's own
    // transform context.
    unsafe {
        add_ids(tmpl);
        // The caller names the resource, so local and remote URIs are
        // enabled for it; the encryption policy, which the chain's cipher
        // selects, bounds what is read.
        let saved = ctx.transform_ctx.enabled_uris;
        ctx.transform_ctx.enabled_uris |= URI_TYPES_EXTERNAL;
        let set = xmlSecTransformCtxSetUri(transforms, uri, tmpl);
        ctx.transform_ctx.enabled_uris = saved;
        if set < 0 {
            let text = c_text(uri).unwrap_or("NULL");
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecTransformCtxSetUri",
                &format!("uri={text}"),
            );
            return -1;
        }
        restoring_template(tmpl, here, || {
            if read_enc_data(ctx, tmpl, true) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeRead");
                return -1;
            }
            if xmlSecTransformCtxExecute(transforms, xsNodeGetDoc(tmpl)) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxExecute");
                return -1;
            }
            ctx.result = ctx.transform_ctx.result;
            if ctx.result.is_null() {
                errors::assertion(here, c"encCtx->result != NULL");
                return -1;
            }
            if write_enc_data(ctx) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeWrite");
                return -1;
            }
            if !admit_document(ctx, tmpl, None, here) {
                return -1;
            }
            0
        })
    }
}

/// libxmlsec1's `xmlSecEncCtxEncDataNodeWrite`: the method's parameters,
/// the cipher value and the `KeyInfo` of the template.
///
/// # Safety
/// The template was read and its result computed.
unsafe fn write_enc_data(ctx: &mut XmlSecEncCtx) -> c_int {
    let here = here!("xmlSecEncCtxEncDataNodeWrite");
    // SAFETY: the context's method, nodes and result.
    unsafe {
        if !ctx.enc_method_node.is_null()
            && let Some(write) = (*(*ctx.enc_method).id).write_node
            && write(
                ctx.enc_method,
                ctx.enc_method_node,
                &raw mut ctx.transform_ctx,
            ) < 0
        {
            let object = super::super::tree::name_for_report(ctx.enc_method_node);
            errors::internal(here, object.as_ptr(), c"writeNode");
            return -1;
        }
        if !ctx.cipher_value_node.is_null() {
            let data = xmlSecBufferGetData(ctx.result);
            let size = xmlSecBufferGetSize(ctx.result);
            let text = if data.is_null() {
                String::new()
            } else {
                String::from_utf8_lossy(std::slice::from_raw_parts(data, size)).into_owned()
            };
            if nodes::set_content(ctx.cipher_value_node, &text).is_err() {
                errors::xml_failed(here, std::ptr::null(), c"xmlNodeSetContentLen");
                return -1;
            }
            ctx.result_replaced = 1;
        }
        if !ctx.key_info_node.is_null() && write_key_info(ctx, here) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecKeyInfoNodeWrite");
            return -1;
        }
    }
    0
}

/// Writes the context's key into its `KeyInfo` as a part of the operation:
/// under its revision, counting on from what it spent, and within its
/// limits, as its key read runs.
///
/// # Safety
/// The context's `KeyInfo` node and key are set.
unsafe fn write_key_info(ctx: &mut XmlSecEncCtx, here: errors::Here) -> c_int {
    let transforms = &raw mut ctx.transform_ctx;
    let write = &raw mut ctx.key_info_write_ctx;
    // SAFETY: the context's own transform and write contexts and nodes.
    unsafe {
        let Some(pinned) = run_policy(transforms, here) else {
            return -1;
        };
        let side = operation_side(ctx.operation).unwrap_or(Side::Encrypt);
        // Each EncryptedKey of the KeyInfo wraps the content key for one
        // recipient; more than the policy admits are refused before any is
        // wrapped, as the core refuses such an envelope.
        if side == Side::Encrypt {
            let maximum = pinned.encryption.resources.max_encryption_recipients;
            let mut recipients = 0_usize;
            let mut child = first_element(ctx.key_info_node);
            while !child.is_null() {
                if is(child, name!(xmlSecNodeEncryptedKey), name!(xmlSecEncNs)) {
                    // At most the children of one element.
                    recipients += 1;
                }
                child = next_element(child);
            }
            if recipients > maximum {
                errors::limit_exceeded(
                    here,
                    std::ptr::null(),
                    "max_encryption_recipients",
                    maximum,
                );
                return -1;
            }
        }
        let _write_pin = SlotPin::hold_pinned(
            &raw mut (*write).reserved0,
            pinned.clone(),
            run_spent(transforms),
            run_budget(transforms)
                .key_candidates
                .within(pinned.of(side).resources().max_key_candidates),
        );
        if xmlSecKeyInfoNodeWrite(ctx.key_info_node, ctx.enc_key, write) < 0
            || !charge_key_info(
                transforms,
                (*write).reserved0,
                pinned.of(side).resources(),
                here,
            )
        {
            return -1;
        }
    }
    0
}

/// `xmlSecEncCtxDecrypt` past its preconditions.
///
/// # Safety
/// `node` is a live node.
pub(super) unsafe fn decrypt(ctx: &mut XmlSecEncCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecEncCtxDecrypt");
    ctx.operation = OPERATION_DECRYPT;
    // SAFETY: a live node.
    let buffer = unsafe { decrypt_to_buffer(ctx, node) };
    if buffer.is_null() {
        errors::internal(here, std::ptr::null(), c"xmlSecEncCtxDecryptToBuffer");
        return -1;
    }
    // SAFETY: the context's result buffer.
    let (data, size) = unsafe { (xmlSecBufferGetData(buffer), xmlSecBufferGetSize(buffer)) };
    let empty = [0_u8; 1];
    let (data, size) = if data.is_null() {
        (empty.as_ptr(), 0)
    } else {
        (data.cast_const(), size)
    };
    // An EncryptedData without a Type stays for the caller, who reads the
    // result as bytes.
    // SAFETY: the context's attribute string.
    let replace = matches!(
        unsafe { c_text(ctx.type_) },
        Some(
            "http://www.w3.org/2001/04/xmlenc#Element" | "http://www.w3.org/2001/04/xmlenc#Content"
        )
    );
    if !replace {
        return 0;
    }
    // The plaintext is parsed as a part of the decryption: under its
    // revision's decryption policy, its work counted on from the parse work
    // the operation spent and added to it. The other budgets bound no parse.
    let transforms = &raw mut ctx.transform_ctx;
    // SAFETY: the context's own transform context.
    let Some(pinned) = (unsafe { run_policy(transforms, here) }) else {
        return -1;
    };
    let destination = if ctx.flags & FLAGS_RETURN_REPLACED_NODE != 0 {
        &raw mut ctx.replaced_node_list
    } else {
        std::ptr::null_mut()
    };
    // SAFETY: the node, the result's bytes, the context's replaced list and
    // its own transform context.
    let replaced = unsafe {
        replace_node_buffer_under(
            node,
            std::slice::from_raw_parts(data, size),
            destination,
            &*pinned.decryption,
            &mut run_budget(transforms).xml_parse,
        )
    };
    if replaced < 0 {
        let object = super::super::tree::name_for_report(node);
        errors::internal(here, object.as_ptr(), c"xmlSecReplaceNodeBuffer");
        return -1;
    }
    ctx.result_replaced = 1;
    0
}

/// `xmlSecEncCtxDecryptToBuffer` past its first precondition.
///
/// # Safety
/// `node` is null or a live node.
pub(super) unsafe fn decrypt_to_buffer(
    ctx: &mut XmlSecEncCtx,
    node: *mut XmlNode,
) -> *mut XmlSecBuffer {
    let here = here!("xmlSecEncCtxDecryptToBuffer");
    ctx.operation = OPERATION_DECRYPT;
    if !ctx.result.is_null() {
        errors::assertion(here, c"encCtx->result == NULL");
        return std::ptr::null_mut();
    }
    if node.is_null() {
        errors::assertion(here, c"node != NULL");
        return std::ptr::null_mut();
    }
    // SAFETY: a live node.
    unsafe {
        if ctx.mode == MODE_ENCRYPTED_KEY {
            return encrypt_or_decrypt_to_buffer(ctx, node);
        }
        add_ids(node);
        if read_enc_data(ctx, node, false) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeRead");
            return std::ptr::null_mut();
        }
        // libxmlsec1 runs the callback when it prepares the decryption chain:
        // before any resource is read or anything decrypted, a negative
        // return, or a change to the chain the core does not run, refuses
        // the operation.
        if !run_pre_execute(
            &raw mut ctx.transform_ctx,
            here!("xmlSecTransformCtxPrepare"),
        ) {
            return std::ptr::null_mut();
        }
        run_decryption(ctx, node)
    }
}

/// libxmlsec1's `xmlSecEncCtxEncryptOrDecryptToBuffer` for an
/// `EncryptedKey`: the element read, then its chain run over the cipher
/// value or the data its `CipherReference` names, in the context's
/// operation. The key's own transport or wrap klass admits the method and
/// the key under the library policy, as a standalone chain does.
///
/// # Safety
/// `node` is a live node.
pub(super) unsafe fn encrypt_or_decrypt_to_buffer(
    ctx: &mut XmlSecEncCtx,
    node: *mut XmlNode,
) -> *mut XmlSecBuffer {
    let here = here!("xmlSecEncCtxEncryptOrDecryptToBuffer");
    if !ctx.result.is_null() {
        errors::assertion(here, c"encCtx->result == NULL");
        return std::ptr::null_mut();
    }
    if node.is_null() {
        errors::assertion(here, c"node != NULL");
        return std::ptr::null_mut();
    }
    let transforms = &raw mut ctx.transform_ctx;
    // SAFETY: a live node, the context's own members and the trimmed copy
    // freed here.
    unsafe {
        add_ids(node);
        if read_enc_data(ctx, node, false) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeRead");
            return std::ptr::null_mut();
        }
        if ctx.cipher_value_node.is_null() {
            // The chain reads a CipherReference itself, after its
            // pre-execute callback, as libxmlsec1 does.
            if xmlSecTransformCtxExecute(transforms, xsNodeGetDoc(node)) < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxExecute");
                return std::ptr::null_mut();
            }
        } else {
            let data = xmlSecGetNodeContentAndTrim(ctx.cipher_value_node);
            if data.is_null() {
                errors::invalid_node_content(
                    here,
                    ctx.cipher_value_node,
                    std::ptr::null(),
                    "empty",
                );
                return std::ptr::null_mut();
            }
            let size = std::ffi::CStr::from_ptr(data.cast()).count_bytes();
            let executed = xmlSecTransformCtxBinaryExecute(transforms, data, size);
            super::super::free(data.cast());
            if executed < 0 {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxBinaryExecute");
                return std::ptr::null_mut();
            }
        }
        ctx.result = ctx.transform_ctx.result;
        if ctx.result.is_null() {
            errors::assertion(here, c"encCtx->result != NULL");
        }
        ctx.result
    }
}

/// libxmlsec1's `xmlSecEncCtxEncryptedKeyXmlWrite` past its preconditions:
/// the `EncryptedKey` template `node` read for an encryption, the key's
/// binary value encrypted through its chain and written into it.
///
/// # Safety
/// `node` is a live node; `key` a valid key; `key_info` the writing
/// `KeyInfo` context.
pub(super) unsafe fn encrypted_key_write(
    ctx: &mut XmlSecEncCtx,
    node: *mut XmlNode,
    key: *mut super::super::keys::XmlSecKey,
    key_info: *mut super::super::keyinfo::XmlSecKeyInfoCtx,
) -> c_int {
    let here = here!("xmlSecEncCtxEncryptedKeyXmlWrite");
    // SAFETY: by the caller's contract.
    unsafe {
        ctx.operation = super::encrypted_key::map_operation((*key_info).operation);
        if ctx.operation == 0 {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"invalid operation",
                &format!("operation={}", (*key_info).operation),
            );
            return -1;
        }
        add_ids(node);
        if read_enc_data(ctx, node, true) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxEncDataNodeRead");
            return -1;
        }
        let Some(value) = super::encrypted_key::key_binary(key, key_info) else {
            errors::internal(
                here,
                std::ptr::null(),
                c"xmlSecEncCtxEncryptedKeyWriteKeyToBinary",
            );
            return -1;
        };
        let written = encrypt_bytes(ctx, &value, here);
        ctx.result = std::ptr::null_mut();
        written
    }
}

/// libxmlsec1's `xmlSecEncCtxEncDataNodeRead`: the attributes, the method,
/// the cipher data and the key of the `EncryptedData` or `EncryptedKey`
/// element `node`, with a Base64 encoder after the method when an
/// encryption writes a `CipherValue` and `add_base64` asks.
///
/// # Safety
/// `node` is a live node.
unsafe fn read_enc_data(ctx: &mut XmlSecEncCtx, node: *mut XmlNode, add_base64: bool) -> c_int {
    let here = here!("xmlSecEncCtxEncDataNodeRead");
    let enc_ns = name!(xmlSecEncNs);
    for (holds, expression) in [
        (
            ctx.operation == OPERATION_ENCRYPT || ctx.operation == OPERATION_DECRYPT,
            c"(encCtx->operation == xmlSecTransformOperationEncrypt) || (encCtx->operation == xmlSecTransformOperationDecrypt)",
        ),
        (ctx.enc_data_node.is_null(), c"encCtx->encDataNode == NULL"),
        (ctx.id.is_null(), c"encCtx->id == NULL"),
        (ctx.type_.is_null(), c"encCtx->type == NULL"),
        (ctx.enc_method_node.is_null(), c"encCtx->encMethodNode == NULL"),
        (ctx.key_info_node.is_null(), c"encCtx->keyInfoNode == NULL"),
        (ctx.enc_method.is_null(), c"encCtx->encMethod == NULL"),
    ] {
        if !holds {
            errors::assertion(here, expression);
            return -1;
        }
    }
    ctx.enc_data_node = node;
    // SAFETY: live nodes of the caller's tree and the context's own members.
    unsafe {
        let (expected, label) = match ctx.mode {
            MODE_ENCRYPTED_KEY => (name!(xmlSecNodeEncryptedKey), "EncryptedKey"),
            _ => (name!(xmlSecNodeEncryptedData), "EncryptedData"),
        };
        if ctx.mode != MODE_ENCRYPTED_DATA && ctx.mode != MODE_ENCRYPTED_KEY {
            errors::unsupported_enum(here, std::ptr::null(), "mode", ctx.mode);
            return -1;
        }
        if !is(node, expected, enc_ns) {
            errors::invalid_node(here, node, label, std::ptr::null());
            return -1;
        }
        ctx.id = attribute(node, "Id");
        ctx.type_ = attribute(node, "Type");
        ctx.mime_type = attribute(node, "MimeType");
        ctx.encoding = attribute(node, "Encoding");
        if ctx.mode == MODE_ENCRYPTED_KEY {
            ctx.recipient = attribute(node, "Recipient");
        }
        let mut cur = first_element(node);
        if is(cur, name!(xmlSecNodeEncryptionMethod), enc_ns) {
            ctx.enc_method_node = cur;
            cur = next_element(cur);
        }
        if is(cur, name!(xmlSecNodeKeyInfo), name!(xmlSecDSigNs)) {
            ctx.key_info_node = cur;
            cur = next_element(cur);
        }
        if !is(cur, name!(xmlSecNodeCipherData), enc_ns) {
            errors::invalid_node(here, cur, "CipherData", std::ptr::null());
            return -1;
        }
        if read_cipher_data(ctx, cur) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecEncCtxCipherDataNodeRead");
            return -1;
        }
        cur = next_element(cur);
        if is(cur, name!(xmlSecNodeEncryptionProperties), enc_ns) {
            cur = next_element(cur);
        }
        if ctx.mode == MODE_ENCRYPTED_KEY {
            if is(cur, name!(xmlSecNodeReferenceList), enc_ns) {
                cur = next_element(cur);
            }
            if is(cur, name!(xmlSecNodeCarriedKeyName), enc_ns) {
                ctx.carried_key_name = xmlSecGetNodeContentAndTrim(cur);
                if ctx.carried_key_name.is_null() {
                    errors::invalid_node_content(here, cur, std::ptr::null(), "empty");
                    return -1;
                }
                cur = next_element(cur);
            }
        }
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return -1;
        }
        read_method_and_key(ctx, add_base64)
    }
}

/// The method and key half of libxmlsec1's `xmlSecEncCtxEncDataNodeRead`:
/// the method from `EncryptionMethod` or the context's default, the key it
/// requires through the read `KeyInfo` context, and the Base64 encoder of
/// an encryption that writes a `CipherValue`.
///
/// # Safety
/// The context's element nodes were read.
unsafe fn read_method_and_key(ctx: &mut XmlSecEncCtx, add_base64: bool) -> c_int {
    let here = here!("xmlSecEncCtxEncDataNodeRead");
    // SAFETY: the context's nodes and its own members.
    unsafe {
        let transforms = &raw mut ctx.transform_ctx;
        if !ctx.enc_method_node.is_null() {
            // The operation is known before the method is read, so a klass
            // reads its parameters under that operation's policy.
            ctx.enc_method = ctx_node_read_for(
                transforms,
                ctx.enc_method_node,
                USAGE_ENCRYPTION_METHOD,
                ctx.operation,
            );
            if ctx.enc_method.is_null() {
                errors::internal(
                    here,
                    c"EncryptionMethod".as_ptr(),
                    c"xmlSecTransformCtxNodeRead",
                );
                return -1;
            }
        } else if !ctx.def_enc_method_id.is_null() {
            ctx.enc_method = xmlSecTransformCtxCreateAndAppend(transforms, ctx.def_enc_method_id);
            if ctx.enc_method.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxCreateAndAppend");
                return -1;
            }
        } else {
            errors::invalid_data(here, std::ptr::null(), "encryption method not specified");
            return -1;
        }
        (*ctx.enc_method).operation = ctx.operation;
        ctx.key_info_read_ctx.operation = ctx.operation;
        ctx.key_info_write_ctx.operation = ctx.operation;
        let method_name = (*(*ctx.enc_method).id).name.cast();
        if ctx.mode == MODE_ENCRYPTED_KEY {
            if !admit_key_method(ctx, here) {
                return -1;
            }
            // The method's cipher is admitted again where it runs, under the
            // same key-wrap permission.
            run_budget(transforms).wraps_key = true;
        }
        if xmlSecTransformSetKeyReq(ctx.enc_method, &raw mut ctx.key_info_read_ctx.key_req) < 0 {
            errors::internal(here, method_name, c"xmlSecTransformSetKeyReq");
            return -1;
        }
        let read = &raw mut ctx.key_info_read_ctx;
        if ctx.enc_key.is_null() {
            // The key is read under the revision the operation runs under,
            // the one its chain and its core decryption use, counting on from
            // what the operation spent.
            let Some(pinned) = run_policy(transforms, here) else {
                return -1;
            };
            let side = operation_side(ctx.operation).unwrap_or(Side::Decrypt);
            let _read_pin = SlotPin::hold_pinned(
                &raw mut (*read).reserved0,
                pinned.clone(),
                run_spent(transforms),
                run_budget(transforms)
                    .key_candidates
                    .within(pinned.of(side).resources().max_key_candidates),
            );
            let mngr = ctx.key_info_read_ctx.keys_mngr;
            if let Some(get_key) = mngr.as_ref().and_then(|mngr| mngr.get_key) {
                ctx.enc_key = get_key(ctx.key_info_node, read);
            }
            if !charge_key_info(
                transforms,
                (*read).reserved0,
                pinned.of(side).resources(),
                here,
            ) {
                return -1;
            }
        }
        if ctx.enc_key.is_null()
            || xmlSecKeyMatch(ctx.enc_key, std::ptr::null(), &raw mut (*read).key_req) == 0
        {
            let method = c_text((*(*ctx.enc_method).id).name).unwrap_or("NULL");
            errors::other(
                here,
                errors::R_KEY_NOT_FOUND,
                std::ptr::null(),
                Some(&format!("encMethod={method}")),
            );
            if ctx.failure_reason == FAILURE_UNKNOWN {
                ctx.failure_reason = FAILURE_KEY_NOT_FOUND;
            }
            return -1;
        }
        if xmlSecTransformSetKey(ctx.enc_method, ctx.enc_key.cast()) < 0 {
            errors::internal(here, method_name, c"xmlSecTransformSetKey");
            return -1;
        }
        if add_base64 && ctx.operation == OPERATION_ENCRYPT && !ctx.cipher_value_node.is_null() {
            let encode =
                xmlSecTransformCtxCreateAndAppend(transforms, xmlSecTransformBase64GetKlass());
            if encode.is_null() {
                errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxCreateAndAppend");
                return -1;
            }
            (*encode).operation = super::super::transforms::OPERATION_ENCODE;
            ctx.result_base64_encoded = 1;
        }
    }
    0
}

/// Whether the operation's policy admits the method of the context's
/// `EncryptedKey` as what it is there, a key transport or a key wrap (XML
/// Encryption 1.1 sections 5.4 and 5.6), as the core admits an
/// `EncryptedKey`'s method: a block cipher wraps a key only as far as the
/// key-wrap permissions allow, whatever content it may decrypt. Refused
/// after a report at `here`.
///
/// # Safety
/// The context's method was read.
unsafe fn admit_key_method(ctx: &mut XmlSecEncCtx, here: errors::Here) -> bool {
    use xml_sec::xmlenc::{KeyTransportAlgorithm, KeyWrapAlgorithm};
    // SAFETY: the method's klass and the context's own transform context.
    let (href, name, pinned) = unsafe {
        let klass = (*ctx.enc_method).id;
        let Some(pinned) = run_policy(&raw mut ctx.transform_ctx, here) else {
            return false;
        };
        (
            c_text((*klass).href).unwrap_or(""),
            (*klass).name.cast(),
            pinned,
        )
    };
    let encrypting = ctx.operation == OPERATION_ENCRYPT;
    let admitted = if let Ok(transport) = KeyTransportAlgorithm::from_uri(href) {
        if encrypting {
            pinned.encryption.check_key_transport_algorithm(transport)
        } else {
            pinned.decryption.check_key_transport_algorithm(transport)
        }
    } else if let Ok(wrap) = KeyWrapAlgorithm::from_uri(href) {
        if encrypting {
            pinned.encryption.check_key_wrap_algorithm(wrap)
        } else {
            pinned.decryption.check_key_wrap_algorithm(wrap)
        }
    } else {
        errors::invalid_data(
            here,
            name,
            "an EncryptedKey's method is neither a key transport nor a key wrap",
        );
        return false;
    };
    if let Err(violation) = admitted {
        errors::report(
            here,
            name,
            std::ptr::null(),
            errors::R_TRANSFORM_DISABLED,
            &violation.to_string(),
        );
        return false;
    }
    // A rejected RSAES-PKCS1-v1_5 recovery yields a random key, and only a
    // decryption's content work consults its validity. A signature or an
    // encryption made with the key, or a key it unwraps for another
    // EncryptedKey (which a recipient may fail to yield, letting the next one
    // be tried), would show whether the padding was accepted; such a use is
    // refused before anything is read, whatever the padding.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-bleichenbacher-attack
    #[cfg(feature = "legacy-algorithms")]
    if !encrypting
        && matches!(
            KeyTransportAlgorithm::from_uri(href),
            Ok(KeyTransportAlgorithm::RsaPkcs1v15)
        )
    {
        // SAFETY: the context's own transform context.
        let serves = unsafe { run_budget(&raw mut ctx.transform_ctx) }.serves;
        let nested = ctx.key_info_read_ctx.cur_encrypted_key_level > 1;
        if nested || matches!(serves, Some(Side::Sign | Side::Encrypt)) {
            errors::report(
                here,
                name,
                std::ptr::null(),
                errors::R_TRANSFORM_DISABLED,
                "an RSAES-PKCS1-v1_5 recovery yields no key for signing, encrypting or \
                 unwrapping another key",
            );
            return false;
        }
    }
    true
}

/// libxmlsec1's `xmlSecEncCtxCipherDataNodeRead`: a `CipherValue`, decoded
/// from Base64 when decrypting, or a `CipherReference` read when decrypting.
///
/// # Safety
/// `node` is a live node.
unsafe fn read_cipher_data(ctx: &mut XmlSecEncCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecEncCtxCipherDataNodeRead");
    let enc_ns = name!(xmlSecEncNs);
    let transforms = &raw mut ctx.transform_ctx;
    // SAFETY: live nodes and the context's own transform context.
    unsafe {
        let mut cur = first_element(node);
        if is(cur, name!(xmlSecNodeCipherValue), enc_ns) {
            if ctx.operation == OPERATION_DECRYPT
                && xmlSecTransformCtxCreateAndPrepend(transforms, xmlSecTransformBase64GetKlass())
                    .is_null()
            {
                errors::internal(
                    here,
                    std::ptr::null(),
                    c"xmlSecTransformCtxCreateAndPrepend",
                );
                return -1;
            }
            ctx.cipher_value_node = cur;
            cur = next_element(cur);
        } else if is(cur, name!(xmlSecNodeCipherReference), enc_ns) {
            if ctx.operation == OPERATION_DECRYPT && read_cipher_reference(ctx, cur) < 0 {
                errors::internal(
                    here,
                    c"CipherReference".as_ptr(),
                    c"xmlSecEncCtxCipherReferenceNodeRead",
                );
                return -1;
            }
            cur = next_element(cur);
        } else if cur.is_null() {
            errors::invalid_data(
                here,
                std::ptr::null(),
                "CipherData node must contain either a CipherValue or a CipherReference node",
            );
            return -1;
        }
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return -1;
        }
    }
    0
}

/// libxmlsec1's `xmlSecEncCtxCipherReferenceNodeRead`: the start URI and
/// the transforms of a `CipherReference`.
///
/// # Safety
/// `node` is a live node.
unsafe fn read_cipher_reference(ctx: &mut XmlSecEncCtx, node: *mut XmlNode) -> c_int {
    let here = here!("xmlSecEncCtxCipherReferenceNodeRead");
    let transforms = &raw mut ctx.transform_ctx;
    let uri = attribute(node, "URI");
    // SAFETY: live nodes, the context's own transform context and the
    // copy freed here.
    unsafe {
        let set = xmlSecTransformCtxSetUri(transforms, uri, node);
        let text = c_text(uri).unwrap_or("NULL").to_owned();
        super::super::free(uri.cast());
        if set < 0 {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecTransformCtxSetUri",
                &format!("uri={text}"),
            );
            return -1;
        }
        let mut cur = first_element(node);
        if is(cur, name!(xmlSecNodeTransforms), name!(xmlSecEncNs)) {
            if xmlSecTransformCtxNodesListRead(transforms, cur, USAGE_DSIG_TRANSFORM) < 0 {
                errors::internal(
                    here,
                    c"Transforms".as_ptr(),
                    c"xmlSecTransformCtxNodesListRead",
                );
                return -1;
            }
            cur = next_element(cur);
        }
        if !cur.is_null() {
            errors::unexpected_node(here, cur, std::ptr::null());
            return -1;
        }
    }
    0
}

/// The content key of the context's key for its method, with the family the
/// core's resolver needs.
///
/// # Safety
/// The context's method and key are set.
unsafe fn content_key(ctx: &XmlSecEncCtx) -> Option<(DataEncryptionAlgorithm, Zeroizing<Vec<u8>>)> {
    // SAFETY: the method's klass and the key's value outlive the call.
    unsafe {
        let href = c_text((*(*ctx.enc_method).id).href)?;
        let algorithm = DataEncryptionAlgorithm::from_uri(href).ok()?;
        let buffer = xmlSecKeyDataBinaryValueGetBuffer(xmlSecKeyGetValue(ctx.enc_key));
        let data = xmlSecBufferGetData(buffer);
        let size = xmlSecBufferGetSize(buffer);
        if data.is_null() || size < algorithm.key_len() {
            return None;
        }
        // libxmlsec1 takes the leading bytes of a longer key.
        let bytes = std::slice::from_raw_parts(data, algorithm.key_len()).to_vec();
        Some((algorithm, Zeroizing::new(bytes)))
    }
}

/// The octets of the external resource an `EncryptedData`'s
/// `CipherReference` names, read through the caller's input callbacks under
/// the decryption policy of the revision `pinned`; empty for a cipher value
/// or a same-document reference, `None` after a report.
///
/// # Safety
/// `node` is the read, live `EncryptedData` element of the context.
unsafe fn cipher_reference_resources(
    ctx: &mut XmlSecEncCtx,
    node: *mut XmlNode,
    pinned: &Pinned,
) -> Option<ReadResources> {
    let mut resources = ReadResources::default();
    // SAFETY: live nodes and the context's own transform context.
    unsafe {
        let mut cur = first_element(node);
        while !cur.is_null() && !is(cur, name!(xmlSecNodeCipherData), name!(xmlSecEncNs)) {
            cur = next_element(cur);
        }
        let reference = if cur.is_null() {
            cur
        } else {
            first_element(cur)
        };
        if !is(
            reference,
            name!(xmlSecNodeCipherReference),
            name!(xmlSecEncNs),
        ) {
            return Some(resources);
        }
        let Some(uri) = nodes::property(reference, "URI") else {
            return Some(resources);
        };
        if uri.is_empty() || uri.starts_with('#') {
            return Some(resources);
        }
        let Some(origin) = nodes::tree_node(reference).map(|(_, tree)| ExternalNode::from(tree))
        else {
            errors::internal(
                here!("xmlSecTransformCtxUriExecute"),
                std::ptr::null(),
                c"node identity",
            );
            return None;
        };
        let bytes = read_resource(
            &raw mut ctx.transform_ctx,
            uri.as_bytes(),
            reference,
            xsNodeGetDoc(node),
            // Counted on from what the key's read spent: one allowance.
            &mut ResourceScope::new(
                pinned,
                Side::Decrypt,
                external_spent(&raw mut ctx.transform_ctx),
            ),
        )?;
        resources.push(origin, uri, bytes);
    }
    Some(resources)
}

/// Takes the core's decryption into the operation whose chain is
/// `transforms`: the parse work it spent (a `CipherReference`'s transforms
/// parsing a resource) joins the operation's, so a plaintext parse counts on
/// from it; the core ran within what the operation left, so the sum stays
/// within the policy's maximum. A key recovered by RSAES-PKCS1-v1_5 may be
/// the random substitute of a rejected recovery, whose validity is consulted
/// only now, after the content work: whatever that work yielded, a rejected
/// recovery fails as a wrong key's content work does, as the core's own
/// decryption fails it, so the outcome reveals nothing of the padding (XML
/// Encryption 1.1 sections 6.1.2 and 6.7).
///
/// # Safety
/// `transforms` is an initialized context.
unsafe fn settle_decryption(
    transforms: *mut super::super::transforms::ctx::XmlSecTransformCtx,
    algorithm: DataEncryptionAlgorithm,
    decrypted: Result<
        (xml_sec::policy::Audited<DecryptedContent>, usize),
        xml_sec::xmlenc::XmlEncError,
    >,
) -> Result<xml_sec::policy::Audited<DecryptedContent>, xml_sec::xmlenc::XmlEncError> {
    // SAFETY: by the caller's contract.
    let run = unsafe { run_budget(transforms) };
    if let Ok((_, spent)) = &decrypted {
        run.xml_parse += spent;
    }
    if !run.recovery.is_valid() {
        if let Ok((audited, _)) = decrypted {
            match audited.output {
                DecryptedContent::Xml(text) => drop(Zeroizing::new(text)),
                DecryptedContent::Bytes(bytes) => drop(Zeroizing::new(bytes)),
            }
        }
        return Err(xml_sec::xmlenc::XmlEncError::rejected_recovery(algorithm));
    }
    decrypted.map(|(audited, _)| audited)
}

/// The content key the context's read `KeyInfo` context found, offered to
/// the core once, whichever source of the element's `KeyInfo` the core asks
/// for it.
///
/// The `KeyInfo` read is this library's, as libxmlsec1's is its own: it
/// took the key from the first child that yields one, a `DerivedKey`
/// derived by its klass under the library policy included (as an
/// `EncryptedKey` recovered by its nested context is). The core then
/// decrypts with that key; it neither consults the `EncryptedKey`s again nor
/// repeats a derivation the read already ran.
struct KeyInfoKey {
    key: SymmetricKeyDecryptor,
    offered: std::cell::Cell<bool>,
}

impl KeyInfoKey {
    fn new(key: SymmetricKeyDecryptor) -> Self {
        Self {
            key,
            offered: std::cell::Cell::new(false),
        }
    }

    /// The key as the one candidate of the operation; later asks find none.
    fn offer(
        &self,
        provider: &dyn xml_sec::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        policy: &xml_sec::policy::DecryptionPolicy,
        budget: &mut xml_sec::xmlenc::KeyCandidateBudget,
    ) -> Result<Vec<xml_sec::provider::RecoveredContentKey>, xml_sec::xmlenc::XmlEncError> {
        if self.offered.replace(true) {
            return Err(xml_sec::xmlenc::XmlEncError::KeyNotFound);
        }
        self.key
            .resolve_content_keys_with_policy(provider, algorithm, None, policy, budget)
    }
}

impl xml_sec::xmlenc::DecryptionKeyResolver for KeyInfoKey {
    fn consults_encrypted_keys(&self) -> bool {
        false
    }

    fn resolve_content_keys_with_policy(
        &self,
        provider: &dyn xml_sec::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&xml_sec::xmlenc::EncryptedKey>,
        policy: &xml_sec::policy::DecryptionPolicy,
        budget: &mut xml_sec::xmlenc::KeyCandidateBudget,
    ) -> Result<Vec<xml_sec::provider::RecoveredContentKey>, xml_sec::xmlenc::XmlEncError> {
        if encrypted_key.is_some() {
            return Err(xml_sec::xmlenc::XmlEncError::KeyNotFound);
        }
        self.offer(provider, algorithm, policy, budget)
    }

    fn resolve_derived_content_keys_with_policy(
        &self,
        provider: &dyn xml_sec::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        _descriptor: &xml_sec::xmlenc::DerivedKey,
        policy: &xml_sec::policy::DecryptionPolicy,
        budget: &mut xml_sec::xmlenc::KeyCandidateBudget,
    ) -> Result<Vec<xml_sec::provider::RecoveredContentKey>, xml_sec::xmlenc::XmlEncError> {
        self.offer(provider, algorithm, policy, budget)
    }

    fn resolve_agreement_content_keys_with_policy(
        &self,
        provider: &dyn xml_sec::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        _descriptor: &xml_sec::xmlenc::AgreementMethod,
        policy: &xml_sec::policy::DecryptionPolicy,
        budget: &mut xml_sec::xmlenc::KeyCandidateBudget,
    ) -> Result<Vec<xml_sec::provider::RecoveredContentKey>, xml_sec::xmlenc::XmlEncError> {
        self.offer(provider, algorithm, policy, budget)
    }

    fn resolve_encapsulation_content_keys_with_policy(
        &self,
        provider: &dyn xml_sec::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        _descriptor: &xml_sec::key_establishment::EncapsulationMechanism,
        policy: &xml_sec::policy::DecryptionPolicy,
        budget: &mut xml_sec::xmlenc::KeyCandidateBudget,
    ) -> Result<Vec<xml_sec::provider::RecoveredContentKey>, xml_sec::xmlenc::XmlEncError> {
        self.offer(provider, algorithm, policy, budget)
    }

    fn resolve_key(
        &self,
        provider: &dyn xml_sec::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        _encrypted_key: Option<&xml_sec::xmlenc::EncryptedKey>,
    ) -> Result<Vec<u8>, xml_sec::xmlenc::XmlEncError> {
        self.key.resolve_key(provider, algorithm, None)
    }
}

/// Runs the core decryption of the `EncryptedData` element `node` and makes
/// the plaintext the context's result, a buffer of its method.
///
/// # Safety
/// `node` is a live node; the context's method and key are set.
unsafe fn run_decryption(ctx: &mut XmlSecEncCtx, node: *mut XmlNode) -> *mut XmlSecBuffer {
    let here = here!("xmlSecEncCtxDecryptToBuffer");
    // The revision the key was read under (`read_method_and_key`).
    // SAFETY: the context's own transform context.
    let Some(pinned) = (unsafe { run_policy(&raw mut ctx.transform_ctx, here) }) else {
        return std::ptr::null_mut();
    };
    // SAFETY: the context's read nodes.
    let Some(resources) = (unsafe { cipher_reference_resources(ctx, node, &pinned) }) else {
        errors::internal(here, std::ptr::null(), c"xmlSecTransformCtxUriExecute");
        return std::ptr::null_mut();
    };
    // SAFETY: the method and key were read.
    let Some((algorithm, key)) = (unsafe { content_key(ctx) }) else {
        errors::internal(here, std::ptr::null(), c"xmlSecKeyGetValue");
        return std::ptr::null_mut();
    };
    let Some(external) = nodes::tree_node(node).map(|(_, tree_node)| ExternalNode::from(tree_node))
    else {
        errors::internal(here, std::ptr::null(), c"node identity");
        return std::ptr::null_mut();
    };
    // The core's run is the rest of the operation the key read began.
    let mut policy = std::sync::Arc::clone(&pinned.decryption);
    // SAFETY: the context's own transform context.
    if !unsafe {
        leave_unspent(
            &raw mut ctx.transform_ctx,
            &mut std::sync::Arc::make_mut(&mut policy).resources,
            here,
        )
    } {
        return std::ptr::null_mut();
    }
    let (document, _) = match xml_sec_libxml2::document::snapshot(node, &*policy) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            errors::xml_failed_with(
                here,
                std::ptr::null(),
                c"xmlSecEncCtxDecryptToBuffer",
                &error.to_string(),
            );
            return std::ptr::null_mut();
        }
    };
    let Some(target) = document.with_view(|view| {
        let found = view.node_of_external(external)?;
        view.identity_of(found).ok()
    }) else {
        errors::internal(here, std::ptr::null(), c"node identity");
        return std::ptr::null_mut();
    };
    let resources = match resources.into_keyed(&document, &policy.resources) {
        Ok(keyed) => keyed,
        Err(error) => {
            errors::invalid_data(here, std::ptr::null(), &error);
            return std::ptr::null_mut();
        }
    };
    let resolver = KeyInfoKey::new(SymmetricKeyDecryptor::with_kind(
        key.to_vec(),
        algorithm.key_kind(),
    ));
    let mut context = DecryptContext::new(&resolver)
        .shared_policy(policy)
        .external_resources(&resources.by_key);
    // An EncryptedData without EncryptionMethod uses the context's default
    // method, which the method was read from (`read_method_and_key`).
    if ctx.enc_method_node.is_null() {
        context = context.default_encryption_method(algorithm);
    }
    let decrypted = context.decrypt_in_document_counting_parse_work(&document, target);
    // SAFETY: the context's own transform context.
    let decrypted = unsafe { settle_decryption(&raw mut ctx.transform_ctx, algorithm, decrypted) };
    let plaintext = match decrypted.map(|audited| audited.output) {
        Ok(DecryptedContent::Xml(text)) => Zeroizing::new(text.into_bytes()),
        Ok(DecryptedContent::Bytes(bytes)) => Zeroizing::new(bytes),
        Err(error) => {
            // libxmlsec1 checks the padding itself and reports it as invalid
            // data; the crypto library reports the rest.
            let reason = if matches!(error, xml_sec::xmlenc::XmlEncError::InvalidPadding) {
                errors::R_INVALID_DATA
            } else {
                errors::R_CRYPTO_FAILED
            };
            errors::report(
                here,
                std::ptr::null(),
                std::ptr::null(),
                reason,
                &error.to_string(),
            );
            return std::ptr::null_mut();
        }
    };
    // The method's output buffer holds the plaintext, owned by the chain as
    // libxmlsec1's result is owned by the chain's last transform.
    // SAFETY: the context's method.
    unsafe {
        let buffer = &raw mut (*ctx.enc_method).out_buf;
        if xmlSecBufferSetData(buffer, plaintext.as_ptr(), plaintext.len()) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecBufferSetData");
            return std::ptr::null_mut();
        }
        // libxmlsec1 publishes the chain's result in both contexts.
        ctx.transform_ctx.result = buffer;
        ctx.result = buffer;
        buffer
    }
}
