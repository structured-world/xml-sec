//! The `XPath`, `XPath` Filter 2.0, `XPointer` and `Visa3D` transform klasses.
//!
//! Each transform keeps libxmlsec1's list of expressions with the node-set
//! type and operation of each. Executing it evaluates every expression with
//! the core's `XPath` engine over the caller's tree, turns the result into a
//! node set of that tree's nodes and combines it with the input as libxmlsec1
//! does, so the combination keeps the donor's node-set algebra.

use std::ffi::{CStr, c_int, c_void};

use xml_sec::XmlDocument;
use xml_sec::document::external::ExternalNode;
use xml_sec::xmldsig::select::{SelectedNode, XPathForm, select_xpath, select_xpointer};
use xml_sec::xmldsig::transforms::XPathExpression;
use xml_sec_libxml2::ffi::{LibxmlTree, XmlAttr, XmlDoc, XmlNode, XmlNodeSet};

use super::super::list::{
    XmlSecPtrList, XmlSecPtrListKlass, xmlSecPtrListAdd, xmlSecPtrListFinalize,
    xmlSecPtrListGetItem, xmlSecPtrListGetSize, xmlSecPtrListInitialize,
};
use super::super::nodeset::{
    INTERSECTION, NORMAL, SUBTRACTION, TREE, TREE_WITHOUT_COMMENTS, UNION, XmlSecNodeSet,
    xmlSecNodeSetAdd, xmlSecNodeSetCreate, xmlSecNodeSetDestroy,
};
use super::super::strings::{
    xmlSecAttrFilter, xmlSecDSigNs, xmlSecNameXPath, xmlSecNameXPath2, xmlSecNameXPointer,
    xmlSecNodeXPath, xmlSecNodeXPath2, xmlSecNodeXPointer, xmlSecXPath2FilterIntersect,
    xmlSecXPath2FilterSubtract, xmlSecXPath2FilterUnion, xmlSecXPath2Ns, xmlSecXPathNs,
    xmlSecXPointerNs,
};
use super::super::tree::{
    readable, xmlGetID, xmlGetProp, xmlNodeGetContent, xmlSearchNs, xmlStrEqual,
    xmlXPathFreeNodeSet, xmlXPathNodeSetAdd, xmlXPathNodeSetAddNs, xmlXPathNodeSetCreate,
};
use super::super::xmltree::{xmlSecCheckNodeName, xmlSecGetNextElementNode};
use super::super::{contain, free, malloc, policy};
use super::builtin::klass;
use super::{
    USAGE_DSIG_TRANSFORM, WithContext, XmlSecTransform, XmlSecTransformCtx, XmlSecTransformKlass,
    context, valid, xmlSecTransformDefaultPopXml, xmlSecTransformDefaultPushXml,
};

/// libxml2's element node type.
const ELEMENT_NODE: c_int = 1;

/// How one expression is evaluated.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// An `XMLDSig` `XPath` filter: a predicate over every node.
    XPath,
    /// An `XPath` Filter 2.0 expression: the node-set it evaluates to.
    XPath2,
    /// An `XPointer`.
    XPointer,
}

/// One expression of a transform, with the node set it makes and how that
/// set combines with the previous one.
struct Data {
    kind: Kind,
    expression: String,
    /// The prefixes declared on the expression's element and its ancestors,
    /// the nearest declaration of each.
    namespaces: Vec<(String, String)>,
    op: c_int,
    node_set_type: c_int,
}

unsafe extern "C" fn destroy_data(item: *mut c_void) {
    if !item.is_null() {
        // SAFETY: every item of a data list is a leaked `Box<Data>`.
        drop(unsafe { Box::from_raw(item.cast::<Data>()) });
    }
}

static DATA_LIST: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"xpath-data-list".as_ptr().cast(),
    duplicate_item: None,
    destroy_item: Some(destroy_data),
    debug_dump_item: None,
    debug_xml_dump_item: None,
};

/// An expression klass of the family, sharing the data list and methods.
const fn expression_klass(
    name: *const u8,
    href: *const u8,
    read_node: unsafe extern "C" fn(
        *mut XmlSecTransform,
        *mut XmlNode,
        *mut XmlSecTransformCtx,
    ) -> c_int,
) -> XmlSecTransformKlass {
    XmlSecTransformKlass {
        initialize: Some(initialize),
        finalize: Some(finalize),
        read_node: Some(read_node),
        push_xml: Some(xmlSecTransformDefaultPushXml),
        pop_xml: Some(xmlSecTransformDefaultPopXml),
        execute: Some(execute),
        ..klass(
            size_of::<WithContext<XmlSecPtrList>>(),
            name,
            href,
            USAGE_DSIG_TRANSFORM,
        )
    }
}

static XPATH: XmlSecTransformKlass = expression_klass(
    xmlSecNameXPath.as_ptr(),
    xmlSecXPathNs.as_ptr(),
    xpath_read_node,
);
static XPATH2: XmlSecTransformKlass = expression_klass(
    xmlSecNameXPath2.as_ptr(),
    xmlSecXPath2Ns.as_ptr(),
    xpath2_read_node,
);
static XPOINTER: XmlSecTransformKlass = expression_klass(
    xmlSecNameXPointer.as_ptr(),
    xmlSecXPointerNs.as_ptr(),
    xpointer_read_node,
);
static VISA3D_HACK: XmlSecTransformKlass = XmlSecTransformKlass {
    finalize: Some(visa3d_finalize),
    push_xml: Some(xmlSecTransformDefaultPushXml),
    pop_xml: Some(xmlSecTransformDefaultPopXml),
    execute: Some(visa3d_execute),
    ..klass(
        size_of::<WithContext<*mut u8>>(),
        c"Visa3DHackTransform".as_ptr().cast(),
        std::ptr::null(),
        USAGE_DSIG_TRANSFORM,
    )
};

/// The `XMLDSig` `XPath` klass.
pub(crate) fn xpath() -> *const XmlSecTransformKlass {
    &raw const XPATH
}

/// The `XPath` Filter 2.0 klass.
pub(crate) fn xpath2() -> *const XmlSecTransformKlass {
    &raw const XPATH2
}

/// The `XPointer` klass, which also selects URI fragments.
pub(crate) fn xpointer() -> *const XmlSecTransformKlass {
    &raw const XPOINTER
}

/// The `Visa3D` id-lookup klass.
pub(crate) fn visa3d_hack() -> *const XmlSecTransformKlass {
    &raw const VISA3D_HACK
}

/// The data list of an expression transform.
///
/// # Safety
/// `transform` is null or a valid transform.
unsafe fn data_list<'a>(transform: *mut XmlSecTransform) -> Option<&'a mut XmlSecPtrList> {
    // SAFETY: an expression transform's tail is its data list.
    unsafe {
        let (_, id) = valid(transform)?;
        if ![xpath(), xpath2(), xpointer()].contains(&std::ptr::from_ref(id)) {
            return None;
        }
        context::<XmlSecPtrList>(transform, id)
    }
}

unsafe extern "C" fn initialize(transform: *mut XmlSecTransform) -> c_int {
    // SAFETY: a fresh expression transform.
    match unsafe { data_list(transform) } {
        // SAFETY: the tail is writable list storage.
        Some(list) => unsafe { xmlSecPtrListInitialize(list, &raw const DATA_LIST) },
        None => -1,
    }
}

unsafe extern "C" fn finalize(transform: *mut XmlSecTransform) {
    // SAFETY: an expression transform being destroyed.
    if let Some(list) = unsafe { data_list(transform) } {
        // SAFETY: an initialized data list.
        unsafe { xmlSecPtrListFinalize(list) };
    }
}

/// A NUL-terminated libxml2 string as text, `None` when it is null or not
/// UTF-8.
///
/// # Safety
/// `text` is null or NUL-terminated.
unsafe fn text_of<'a>(text: *const u8) -> Option<&'a str> {
    if text.is_null() {
        return None;
    }
    // SAFETY: by the caller's contract.
    unsafe { CStr::from_ptr(text.cast()) }.to_str().ok()
}

/// The prefixes in scope at `node`: each prefix's nearest declaration on
/// `node` or an ancestor element; the default namespace is not bound.
///
/// # Safety
/// `node` is a live element.
unsafe fn namespaces_at(node: *mut XmlNode) -> Option<Vec<(String, String)>> {
    let mut namespaces: Vec<(String, String)> = Vec::new();
    let mut current = node;
    // SAFETY: the element and its ancestors are live; only elements carry
    // declarations.
    unsafe {
        while !current.is_null() && (*current).kind == ELEMENT_NODE {
            let mut ns = (*current).ns_def;
            while !ns.is_null() {
                if !(*ns).prefix.is_null() {
                    let prefix = text_of((*ns).prefix)?;
                    if !namespaces.iter().any(|(bound, _)| bound == prefix) {
                        let href = text_of((*ns).href).unwrap_or_default();
                        namespaces.push((prefix.to_owned(), href.to_owned()));
                    }
                }
                ns = (*ns).next;
            }
            current = (*current).parent;
        }
    }
    Some(namespaces)
}

/// The expression of the element `node`: its text content and the
/// namespaces in scope there.
///
/// # Safety
/// `node` is a live element.
unsafe fn read_data(
    kind: Kind,
    node: *mut XmlNode,
    op: c_int,
    node_set_type: c_int,
) -> Option<Data> {
    // SAFETY: by the caller's contract; the content is freed after copying.
    unsafe {
        let namespaces = namespaces_at(node)?;
        let content = xmlNodeGetContent(node);
        let expression = text_of(content).map(str::to_owned);
        free(content.cast());
        Some(Data {
            kind,
            expression: expression?,
            namespaces,
            op,
            node_set_type,
        })
    }
}

/// Adds `data` to `list`, taking ownership of it.
///
/// # Safety
/// `list` is an initialized data list.
unsafe fn add(list: &mut XmlSecPtrList, data: Data) -> c_int {
    let item = Box::into_raw(Box::new(data)).cast::<c_void>();
    // SAFETY: the list owns the item from here; it frees it on failure too.
    unsafe {
        if xmlSecPtrListAdd(list, item) < 0 {
            destroy_data(item);
            return -1;
        }
    }
    0
}

/// Reads the one `dsig:XPath` child of an `XPath` transform's element.
unsafe extern "C" fn xpath_read_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: an `XPath` transform and a live element of its document.
    unsafe {
        let Some(list) = data_list(transform) else {
            return -1;
        };
        if node.is_null() || ctx.is_null() || xmlSecPtrListGetSize(list) != 0 {
            return -1;
        }
        let current = xmlSecGetNextElementNode((*node).children);
        if current.is_null()
            || xmlSecCheckNodeName(current, xmlSecNodeXPath.as_ptr(), xmlSecDSigNs.as_ptr()) == 0
        {
            return -1;
        }
        let Some(data) = read_data(Kind::XPath, current, INTERSECTION, NORMAL) else {
            return -1;
        };
        if add(list, data) < 0 {
            return -1;
        }
        if xmlSecGetNextElementNode((*current).next).is_null() {
            0
        } else {
            -1
        }
    }
}

/// Reads the `dsig-filter2:XPath` children of an `XPath` Filter 2.0
/// transform's element, each with its `Filter` operation.
unsafe extern "C" fn xpath2_read_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: an `XPath` Filter 2.0 transform and a live element of its
    // document.
    unsafe {
        let Some(list) = data_list(transform) else {
            return -1;
        };
        if node.is_null() || ctx.is_null() || xmlSecPtrListGetSize(list) != 0 {
            return -1;
        }
        let mut current = xmlSecGetNextElementNode((*node).children);
        while !current.is_null()
            && xmlSecCheckNodeName(current, xmlSecNodeXPath2.as_ptr(), xmlSecXPath2Ns.as_ptr()) != 0
        {
            let Some(data) = read_data(Kind::XPath2, current, INTERSECTION, TREE) else {
                return -1;
            };
            if add(list, data) < 0 {
                return -1;
            }
            // libxmlsec1 reads the operation after listing the expression.
            let filter = xmlGetProp(current, xmlSecAttrFilter.as_ptr());
            if filter.is_null() {
                return -1;
            }
            let op = [
                (xmlSecXPath2FilterIntersect.as_ptr(), INTERSECTION),
                (xmlSecXPath2FilterSubtract.as_ptr(), SUBTRACTION),
                (xmlSecXPath2FilterUnion.as_ptr(), UNION),
            ]
            .into_iter()
            .find(|(name, _)| xmlStrEqual(filter, *name) != 0)
            .map(|(_, op)| op);
            free(filter.cast());
            let Some(op) = op else {
                return -1;
            };
            // The expression just listed; the list is not empty.
            let newest = xmlSecPtrListGetSize(list) - 1;
            (*xmlSecPtrListGetItem(list, newest).cast::<Data>()).op = op;
            current = xmlSecGetNextElementNode((*current).next);
        }
        if current.is_null() { 0 } else { -1 }
    }
}

/// Reads the one `xptr:XPointer` child of an `XPointer` transform's
/// element.
unsafe extern "C" fn xpointer_read_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: an `XPointer` transform and a live element of its document.
    unsafe {
        let Some(list) = data_list(transform) else {
            return -1;
        };
        if node.is_null() || ctx.is_null() || xmlSecPtrListGetSize(list) != 0 {
            return -1;
        }
        let current = xmlSecGetNextElementNode((*node).children);
        if current.is_null()
            || xmlSecCheckNodeName(
                current,
                xmlSecNodeXPointer.as_ptr(),
                xmlSecXPointerNs.as_ptr(),
            ) == 0
        {
            return -1;
        }
        let Some(data) = read_data(Kind::XPointer, current, INTERSECTION, TREE) else {
            return -1;
        };
        if add(list, data) < 0 {
            return -1;
        }
        if xmlSecGetNextElementNode((*current).next).is_null() {
            0
        } else {
            -1
        }
    }
}

/// `xmlSecTransformXPointerSetExpr`: the `XPointer` a transform selects
/// with, evaluated at `here` and made a node set of type `kind`.
///
/// # Safety
/// `transform` is null or a valid transform; `expr` is null or
/// NUL-terminated; `here` is null or a live node.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformXPointerSetExpr(
    transform: *mut XmlSecTransform,
    expr: *const u8,
    kind: c_int,
    here: *mut XmlNode,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some((object, id)) = valid(transform) else {
                return -1;
            };
            if !std::ptr::eq(id, xpointer())
                || !object.here_node.is_null()
                || expr.is_null()
                || here.is_null()
            {
                return -1;
            }
            object.here_node = here;
            let Some(list) = data_list(transform) else {
                return -1;
            };
            if xmlSecPtrListGetSize(list) != 0 {
                return -1;
            }
            let (Some(namespaces), Some(expression)) = (namespaces_at(here), text_of(expr)) else {
                return -1;
            };
            add(
                list,
                Data {
                    kind: Kind::XPointer,
                    expression: expression.to_owned(),
                    namespaces,
                    op: INTERSECTION,
                    node_set_type: kind,
                },
            )
        }
    })
}

/// The libxml2 node an external record names.
fn node_of(record: ExternalNode) -> *mut XmlNode {
    std::ptr::with_exposed_provenance_mut(usize::try_from(record.0).unwrap_or(0))
}

/// The attribute of `owner` with this name and namespace.
///
/// # Safety
/// `owner` is a live element.
unsafe fn attribute_of(
    owner: *mut XmlNode,
    namespace: Option<&str>,
    local_name: &str,
) -> *mut XmlAttr {
    // SAFETY: the element's attributes, names and namespaces are live.
    unsafe {
        let mut attribute = (*owner).properties;
        while !attribute.is_null() {
            let name = CStr::from_ptr((*attribute).name.cast()).to_bytes();
            let href = (*attribute)
                .ns
                .as_ref()
                .map(|ns| CStr::from_ptr(ns.href.cast()).to_bytes());
            if name == local_name.as_bytes() && href == namespace.map(str::as_bytes) {
                return attribute;
            }
            attribute = (*attribute).next;
        }
    }
    std::ptr::null_mut()
}

/// The `XPath` node set of the tree's nodes `selected` names.
///
/// # Safety
/// The nodes are live nodes of `doc`.
unsafe fn node_set(doc: *mut XmlDoc, selected: &[SelectedNode<'_>]) -> Option<*mut XmlNodeSet> {
    // SAFETY: by the caller's contract; the set is freed on failure.
    unsafe {
        let set = xmlXPathNodeSetCreate(std::ptr::null_mut());
        if set.is_null() {
            return None;
        }
        for member in selected {
            let added = match *member {
                SelectedNode::Node(node) => xmlXPathNodeSetAdd(set, node_of(node)),
                SelectedNode::Attribute {
                    owner,
                    namespace,
                    local_name,
                } => {
                    let attribute = attribute_of(node_of(owner), namespace, local_name);
                    if attribute.is_null() {
                        -1
                    } else {
                        xmlXPathNodeSetAdd(set, attribute.cast())
                    }
                }
                SelectedNode::Namespace { owner, prefix, .. } => {
                    let owner = node_of(owner);
                    let prefix = prefix.map(std::ffi::CString::new).transpose().ok();
                    match prefix {
                        Some(prefix) => {
                            let declaration = xmlSearchNs(
                                doc,
                                owner,
                                prefix
                                    .as_ref()
                                    .map_or(std::ptr::null(), |p| p.as_ptr().cast()),
                            );
                            if declaration.is_null() {
                                -1
                            } else {
                                xmlXPathNodeSetAddNs(set, owner, declaration)
                            }
                        }
                        None => -1,
                    }
                }
            };
            if added < 0 {
                xmlXPathFreeNodeSet(set);
                return None;
            }
        }
        Some(set)
    }
}

/// Evaluates `data` over `document`, the projection of `doc`, at `here`.
///
/// # Safety
/// `doc` is the live document `document` projects.
unsafe fn evaluate(
    data: &Data,
    doc: *mut XmlDoc,
    document: &XmlDocument,
    here: Option<ExternalNode>,
) -> Option<*mut XmlSecNodeSet> {
    let policy = policy::verification()?;
    let selected = document
        .with_view(|view| {
            let mut expression = XPathExpression::new(data.expression.as_str());
            for (prefix, uri) in &data.namespaces {
                expression = expression.with_namespace(prefix.as_str(), uri.as_str());
            }
            match data.kind {
                Kind::XPath => select_xpath(
                    view,
                    &expression,
                    here,
                    XPathForm::EachNode,
                    &[],
                    &policy.resources,
                ),
                Kind::XPath2 => select_xpath(
                    view,
                    &expression,
                    here,
                    XPathForm::NodeSet,
                    &[],
                    &policy.resources,
                ),
                Kind::XPointer => {
                    let namespaces: Vec<(&str, &str)> = data
                        .namespaces
                        .iter()
                        .map(|(prefix, uri)| (prefix.as_str(), uri.as_str()))
                        .collect();
                    select_xpointer(
                        view,
                        &data.expression,
                        &namespaces,
                        here,
                        &[],
                        &policy.resources,
                    )
                }
            }
            .map(|nodes| {
                // SAFETY: the selected nodes are nodes of `doc`.
                unsafe { node_set(doc, &nodes) }
            })
        })
        .ok()??;
    // SAFETY: the node set is the caller's to give up.
    let nodes = unsafe { xmlSecNodeSetCreate(doc, selected, data.node_set_type) };
    if nodes.is_null() {
        // SAFETY: the node set was not adopted.
        unsafe { xmlXPathFreeNodeSet(selected) };
        return None;
    }
    Some(nodes)
}

/// Evaluates the transform's expressions in order, combining each node set
/// with the previous result by its operation, starting from the input.
unsafe extern "C" fn execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: an expression transform read from a live element.
    unsafe {
        let Some(expressions) = data_list(transform) else {
            return -1;
        };
        let object = &mut *transform;
        if object.here_node.is_null()
            || !object.out_nodes.is_null()
            || last == 0
            || ctx.is_null()
            || xmlSecPtrListGetSize(expressions) == 0
            || !readable()
        {
            return -1;
        }
        let doc = if object.in_nodes.is_null() {
            (*object.here_node).doc
        } else {
            (*object.in_nodes).doc
        };
        if doc.is_null() {
            return -1;
        }
        let Some(policy) = policy::verification() else {
            return -1;
        };
        let Some(tree) = LibxmlTree::new(doc) else {
            return -1;
        };
        let Ok(document) = XmlDocument::from_external_tree(Box::new(tree), policy) else {
            return -1;
        };
        // here() is defined only within the transform's own document.
        let here = ((*object.here_node).doc == doc)
            .then(|| ExternalNode(object.here_node.expose_provenance() as u64));
        let input = object.in_nodes;
        let mut result = input;
        for position in 0..xmlSecPtrListGetSize(expressions) {
            let data = &*xmlSecPtrListGetItem(expressions, position).cast::<Data>();
            let Some(nodes) = evaluate(data, doc, &document, here) else {
                if result != input {
                    xmlSecNodeSetDestroy(result);
                }
                return -1;
            };
            let combined = xmlSecNodeSetAdd(result, nodes, data.op);
            if combined.is_null() {
                if result != input {
                    xmlSecNodeSetDestroy(result);
                }
                xmlSecNodeSetDestroy(nodes);
                return -1;
            }
            result = combined;
        }
        object.out_nodes = result;
        0
    }
}

/// The id a `Visa3D` transform selects.
///
/// # Safety
/// `transform` is null or a valid transform.
unsafe fn visa3d_id<'a>(transform: *mut XmlSecTransform) -> Option<&'a mut *mut u8> {
    // SAFETY: a `Visa3D` transform's tail is its id.
    unsafe { context::<*mut u8>(transform, visa3d_hack()) }
}

/// `xmlSecTransformVisa3DHackSetID`: the id a `Visa3D` transform selects.
///
/// # Safety
/// `transform` is null or a valid transform; `id` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformVisa3DHackSetID(
    transform: *mut XmlSecTransform,
    id: *const u8,
) -> c_int {
    contain(-1, || {
        // SAFETY: by the caller's contract.
        unsafe {
            let Some(slot) = visa3d_id(transform) else {
                return -1;
            };
            if id.is_null() || !slot.is_null() {
                return -1;
            }
            let bytes = CStr::from_ptr(id.cast()).to_bytes_with_nul();
            let copy = malloc(bytes.len()).cast::<u8>();
            if copy.is_null() {
                return -1;
            }
            bytes.as_ptr().copy_to(copy, bytes.len());
            *slot = copy;
            0
        }
    })
}

unsafe extern "C" fn visa3d_finalize(transform: *mut XmlSecTransform) {
    // SAFETY: a `Visa3D` transform being destroyed.
    if let Some(slot) = unsafe { visa3d_id(transform) } {
        // SAFETY: the id is null or the copy `SetID` allocated.
        unsafe { free(slot.cast()) };
        *slot = std::ptr::null_mut();
    }
}

/// Selects the element carrying the id, as its subtree without comments.
unsafe extern "C" fn visa3d_execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    // SAFETY: a `Visa3D` transform with its id set.
    unsafe {
        let Some(slot) = visa3d_id(transform) else {
            return -1;
        };
        let id = *slot;
        let object = &mut *transform;
        if !object.out_nodes.is_null() || last == 0 || ctx.is_null() || id.is_null() {
            return -1;
        }
        let doc = if object.in_nodes.is_null() {
            if object.here_node.is_null() {
                return -1;
            }
            (*object.here_node).doc
        } else {
            (*object.in_nodes).doc
        };
        if doc.is_null() || !readable() {
            return -1;
        }
        // The tree's own ID table, which its builder filled.
        let attribute = xmlGetID(doc, id);
        if attribute.is_null() || (*attribute).parent.is_null() {
            return -1;
        }
        let set = xmlXPathNodeSetCreate((*attribute).parent);
        if set.is_null() {
            return -1;
        }
        object.out_nodes = xmlSecNodeSetCreate(doc, set, TREE_WITHOUT_COMMENTS);
        if object.out_nodes.is_null() {
            xmlXPathFreeNodeSet(set);
            return -1;
        }
        0
    }
}
