//! The `XPath`, `XPath` Filter 2.0, `XPointer` and `Visa3D` transform klasses.
//!
//! Each transform keeps libxmlsec1's list of expressions with the node-set
//! type and operation of each. Executing it evaluates every expression with
//! the core's `XPath` engine over the caller's tree, turns the result into a
//! node set of that tree's nodes and combines it with the input through the
//! donor's node-set algebra; Filter 2.0 output is the input intersected with
//! the filter, as its specification requires.

use std::ffi::{CStr, c_char, c_int, c_void};

use xml_sec::XmlDocument;
use xml_sec::document::external::ExternalNode;
use xml_sec::xmldsig::select::{SelectedNode, Selector, XPathForm};
use xml_sec::xmldsig::transforms::XPathExpression;
use xml_sec_libxml2::ffi::{LibxmlTree, XML_NAMESPACE_DECL, XmlAttr, XmlDoc, XmlNode, XmlNodeSet};

use super::super::errors::{self, check, here};
use super::super::list::{
    XmlSecPtrList, XmlSecPtrListKlass, xmlSecPtrListAdd, xmlSecPtrListFinalize,
    xmlSecPtrListGetItem, xmlSecPtrListGetSize, xmlSecPtrListInitialize,
};
use super::super::nodeset::{
    INTERSECTION, NORMAL, SUBTRACTION, TREE, TREE_WITHOUT_COMMENTS, UNION, XmlSecNodeSet,
    xmlSecNodeSetAdd, xmlSecNodeSetCreate, xmlSecNodeSetDestroy, xmlSecNodeSetGetChildren,
    xmlSecNodeSetWalk,
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
    context, context_or, klass_text, valid, xmlSecTransformDefaultPopXml,
    xmlSecTransformDefaultPushXml,
};

#[cfg(test)]
mod tests;

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
    /// The node `here()` returns: the element bearing the expression
    /// (`XMLDSig` 1.1 section 6.6.3), or the node a caller named.
    here: *mut XmlNode,
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

/// The name of a valid transform's klass for a report.
///
/// # Safety
/// `transform` is a valid transform.
unsafe fn name_of(transform: *const XmlSecTransform) -> *const c_char {
    // SAFETY: by the caller's contract.
    unsafe { (*(*transform).id).name.cast() }
}

/// The data list of an expression transform whose klass is one of `klasses`;
/// otherwise reports libxmlsec1's failed assertion `text` from the entry
/// point at `here`.
///
/// # Safety
/// `transform` is null or a valid transform.
unsafe fn data_list<'a>(
    transform: *mut XmlSecTransform,
    klasses: &[*const XmlSecTransformKlass],
    (here, text): (errors::Here, &CStr),
) -> Option<&'a mut XmlSecPtrList> {
    // SAFETY: by the caller's contract; an expression transform's tail is
    // its data list.
    let list = unsafe {
        valid(transform)
            .filter(|(_, id)| klasses.contains(&std::ptr::from_ref(*id)))
            .and_then(|(_, id)| context::<XmlSecPtrList>(transform, id))
    };
    if list.is_none() {
        errors::assertion(here, text);
    }
    list
}

/// The klasses that keep a data list.
fn family() -> [*const XmlSecTransformKlass; 3] {
    [xpath(), xpath2(), xpointer()]
}

unsafe extern "C" fn initialize(transform: *mut XmlSecTransform) -> c_int {
    let here = here!("xmlSecTransformXPathInitialize");
    let checked = (here, c"xmlSecTransformXPathCheckId(transform)");
    // SAFETY: a fresh expression transform.
    let Some(list) = (unsafe { data_list(transform, &family(), checked) }) else {
        return -1;
    };
    // SAFETY: the tail is writable list storage.
    if unsafe { xmlSecPtrListInitialize(list, &raw const DATA_LIST) } < 0 {
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

unsafe extern "C" fn finalize(transform: *mut XmlSecTransform) {
    let here = here!("xmlSecTransformXPathFinalize");
    let checked = (here, c"xmlSecTransformXPathCheckId(transform)");
    // SAFETY: an expression transform being destroyed.
    if let Some(list) = unsafe { data_list(transform, &family(), checked) } {
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
/// `None` when a prefix is not UTF-8.
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
/// namespaces in scope there (libxmlsec1's `xmlSecXPathDataNodeRead`, whose
/// failures it reports).
///
/// # Safety
/// `node` is a live element.
unsafe fn read_data(
    kind: Kind,
    node: *mut XmlNode,
    op: c_int,
    node_set_type: c_int,
) -> Option<Data> {
    let here = here!("xmlSecXPathDataNodeRead");
    // SAFETY: by the caller's contract; the content is freed after copying.
    unsafe {
        let Some(namespaces) = namespaces_at(node) else {
            errors::internal(here, std::ptr::null(), c"xmlSecXPathDataRegisterNamespaces");
            return None;
        };
        let content = xmlNodeGetContent(node);
        if content.is_null() {
            errors::invalid_node_content(here, node, std::ptr::null(), "empty");
            return None;
        }
        let expression = text_of(content).map(str::to_owned);
        free(content.cast());
        let Some(expression) = expression else {
            errors::invalid_node_content(here, node, std::ptr::null(), "not UTF-8");
            return None;
        };
        Some(Data {
            kind,
            expression,
            namespaces,
            here: node,
            op,
            node_set_type,
        })
    }
}

/// Adds `data` to `list`, taking ownership of it; a failure is reported for
/// the transform `name` names at `here`.
///
/// # Safety
/// `list` is an initialized data list.
unsafe fn add(
    list: &mut XmlSecPtrList,
    data: Data,
    here: errors::Here,
    name: *const c_char,
) -> c_int {
    let item = Box::into_raw(Box::new(data)).cast::<c_void>();
    // SAFETY: the list owns the item from here; it frees it on failure too.
    unsafe {
        if xmlSecPtrListAdd(list, item) < 0 {
            errors::internal(here, name, c"xmlSecPtrListAdd");
            destroy_data(item);
            return -1;
        }
    }
    0
}

/// Reads the one expression child `expected` names (in namespace `ns`) of
/// an `XPath` or `XPointer` transform's element as `kind`; reports from the
/// entry point at `here`.
///
/// # Safety
/// `node` is a live element; `list` is the transform's empty data list.
unsafe fn read_single(
    list: &mut XmlSecPtrList,
    node: *mut XmlNode,
    (kind, expected, ns): (Kind, &CStr, &CStr),
    here: errors::Here,
    name: *const c_char,
) -> c_int {
    // SAFETY: by the caller's contract.
    unsafe {
        let current = xmlSecGetNextElementNode((*node).children);
        if current.is_null()
            || xmlSecCheckNodeName(current, expected.as_ptr().cast(), ns.as_ptr().cast()) == 0
        {
            errors::invalid_node(here, current, &expected.to_string_lossy(), name);
            return -1;
        }
        let node_set_type = if kind == Kind::XPath { NORMAL } else { TREE };
        let Some(data) = read_data(kind, current, INTERSECTION, node_set_type) else {
            errors::internal(here, name, c"xmlSecXPathDataNodeRead");
            return -1;
        };
        if add(list, data, here, name) < 0 {
            return -1;
        }
        let next = xmlSecGetNextElementNode((*current).next);
        if !next.is_null() {
            errors::unexpected_node(here, next, name);
            return -1;
        }
        0
    }
}

/// The data list of an expression transform being read, after libxmlsec1's
/// assertions inside the entry point `$func` (`$text` names the klass
/// check), or -1.
macro_rules! reading_or {
    ($transform:expr, $klass:expr, $node:expr, $ctx:expr, $func:literal, $text:literal) => {{
        let list = context_or!($transform, XmlSecPtrList, $klass, $func, $text, -1);
        check!(!$node.is_null(), $func, c"node != NULL", -1);
        check!(!$ctx.is_null(), $func, c"transformCtx != NULL", -1);
        check!(
            // SAFETY: an initialized data list.
            unsafe { xmlSecPtrListGetSize(&raw mut *list) } == 0,
            $func,
            c"xmlSecPtrListGetSize(dataList) == 0",
            -1
        );
        list
    }};
}

/// Reads the one `dsig:XPath` child of an `XPath` transform's element.
unsafe extern "C" fn xpath_read_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    let list = reading_or!(
        transform,
        xpath(),
        node,
        ctx,
        "xmlSecTransformXPathNodeRead",
        c"xmlSecTransformCheckId(transform, xmlSecTransformXPathId)"
    );
    // SAFETY: the namespace and node name constants are NUL-terminated.
    let (ns, expected) = unsafe {
        (
            CStr::from_ptr(xmlSecDSigNs.as_ptr().cast()),
            CStr::from_ptr(xmlSecNodeXPath.as_ptr().cast()),
        )
    };
    // SAFETY: an `XPath` transform and a live element of its document.
    unsafe {
        let here = here!("xmlSecTransformXPathNodeRead");
        read_single(
            list,
            node,
            (Kind::XPath, expected, ns),
            here,
            name_of(transform),
        )
    }
}

/// Reads the `dsig-filter2:XPath` children of an `XPath` Filter 2.0
/// transform's element, each with its `Filter` operation.
unsafe extern "C" fn xpath2_read_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    let list = reading_or!(
        transform,
        xpath2(),
        node,
        ctx,
        "xmlSecTransformXPath2NodeRead",
        c"xmlSecTransformCheckId(transform, xmlSecTransformXPath2Id)"
    );
    let here = here!("xmlSecTransformXPath2NodeRead");
    // SAFETY: an `XPath` Filter 2.0 transform and a live element of its
    // document.
    unsafe {
        let name = name_of(transform);
        let mut current = xmlSecGetNextElementNode((*node).children);
        while !current.is_null()
            && xmlSecCheckNodeName(current, xmlSecNodeXPath2.as_ptr(), xmlSecXPath2Ns.as_ptr()) != 0
        {
            let Some(data) = read_data(Kind::XPath2, current, INTERSECTION, TREE) else {
                errors::internal(here, name, c"xmlSecXPathDataNodeRead");
                return -1;
            };
            if add(list, data, here, name) < 0 {
                return -1;
            }
            // libxmlsec1 reads the operation after listing the expression.
            let filter = xmlGetProp(current, xmlSecAttrFilter.as_ptr());
            if filter.is_null() {
                errors::invalid_node_attribute(here, current, c"Filter", name, "empty");
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
                errors::invalid_node_attribute(here, current, c"Filter", name, "unknown");
                return -1;
            };
            // The expression just listed; the list is not empty.
            let newest = xmlSecPtrListGetSize(list) - 1;
            (*xmlSecPtrListGetItem(list, newest).cast::<Data>()).op = op;
            current = xmlSecGetNextElementNode((*current).next);
        }
        if !current.is_null() {
            errors::unexpected_node(here, current, name);
            return -1;
        }
        0
    }
}

/// Reads the one `xptr:XPointer` child of an `XPointer` transform's
/// element.
unsafe extern "C" fn xpointer_read_node(
    transform: *mut XmlSecTransform,
    node: *mut XmlNode,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    let list = reading_or!(
        transform,
        xpointer(),
        node,
        ctx,
        "xmlSecTransformXPointerNodeRead",
        c"xmlSecTransformCheckId(transform, xmlSecTransformXPointerId)"
    );
    // SAFETY: the namespace and node name constants are NUL-terminated.
    let (ns, expected) = unsafe {
        (
            CStr::from_ptr(xmlSecXPointerNs.as_ptr().cast()),
            CStr::from_ptr(xmlSecNodeXPointer.as_ptr().cast()),
        )
    };
    // SAFETY: an `XPointer` transform and a live element of its document.
    unsafe {
        let here = here!("xmlSecTransformXPointerNodeRead");
        read_single(
            list,
            node,
            (Kind::XPointer, expected, ns),
            here,
            name_of(transform),
        )
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
        let list = context_or!(
            transform,
            XmlSecPtrList,
            xpointer(),
            "xmlSecTransformXPointerSetExpr",
            c"xmlSecTransformCheckId(transform, xmlSecTransformXPointerId)",
            -1
        );
        // SAFETY: a valid transform.
        let object = unsafe { &mut *transform };
        check!(
            object.here_node.is_null(),
            "xmlSecTransformXPointerSetExpr",
            c"transform->hereNode == NULL",
            -1
        );
        check!(
            !expr.is_null(),
            "xmlSecTransformXPointerSetExpr",
            c"expr != NULL",
            -1
        );
        check!(
            !here.is_null(),
            "xmlSecTransformXPointerSetExpr",
            c"hereNode != NULL",
            -1
        );
        object.here_node = here;
        check!(
            // SAFETY: an initialized data list.
            unsafe { xmlSecPtrListGetSize(&raw mut *list) } == 0,
            "xmlSecTransformXPointerSetExpr",
            c"xmlSecPtrListGetSize(dataList) == 0",
            -1
        );
        let location = here!("xmlSecTransformXPointerSetExpr");
        // SAFETY: by the caller's contract.
        unsafe {
            let name = name_of(transform);
            let Some(namespaces) = namespaces_at(here) else {
                errors::internal(location, name, c"xmlSecXPathDataRegisterNamespaces");
                return -1;
            };
            let Some(expression) = text_of(expr) else {
                errors::internal(location, name, c"xmlSecXPathDataSetExpr");
                return -1;
            };
            let data = Data {
                kind: Kind::XPointer,
                expression: expression.to_owned(),
                namespaces,
                here,
                op: INTERSECTION,
                node_set_type: kind,
            };
            add(list, data, location, name)
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

/// Evaluates `data` through `selector`, whose document projects `doc`
/// (libxmlsec1's `xmlSecXPathDataExecute`, whose failures it reports).
///
/// # Safety
/// `doc` is the live document the selector's view projects; `data.here` is
/// a live node.
unsafe fn evaluate(
    data: &Data,
    doc: *mut XmlDoc,
    selector: &mut Selector<'_, '_>,
) -> Option<*mut XmlSecNodeSet> {
    let here = here!("xmlSecXPathDataExecute");
    let (evaluator, form) = match data.kind {
        Kind::XPath => (c"xmlXPathEvalExpression", Some(XPathForm::EachNode)),
        Kind::XPath2 => (c"xmlXPathEvalExpression", Some(XPathForm::NodeSet)),
        Kind::XPointer => (c"xmlXPtrEval", None),
    };
    // The core evaluates in place of libxml2; its error is the cause.
    let failed = |error: &str| {
        errors::report(
            here,
            std::ptr::null(),
            evaluator.as_ptr(),
            errors::R_XML_FAILED,
            &format!("expr={}; {error}", data.expression),
        );
    };
    // here() is defined only within the expression's own document.
    // SAFETY: by the caller's contract.
    let here_node = (!data.here.is_null() && unsafe { (*data.here).doc } == doc)
        .then(|| ExternalNode(data.here.expose_provenance() as u64));
    if let Err(error) = selector.set_here(here_node) {
        failed(&error.to_string());
        return None;
    }
    let mut expression = XPathExpression::new(data.expression.as_str());
    for (prefix, uri) in &data.namespaces {
        expression = expression.with_namespace(prefix.as_str(), uri.as_str());
    }
    let nodes = if let Some(form) = form {
        selector.xpath(&expression, form)
    } else {
        let namespaces: Vec<(&str, &str)> = data
            .namespaces
            .iter()
            .map(|(prefix, uri)| (prefix.as_str(), uri.as_str()))
            .collect();
        selector.xpointer(&data.expression, &namespaces)
    };
    let nodes = match nodes {
        Ok(nodes) => nodes,
        Err(error) => {
            failed(&error.to_string());
            return None;
        }
    };
    // SAFETY: the selected nodes are nodes of `doc`.
    let Some(selected) = (unsafe { node_set(doc, &nodes) }) else {
        errors::xml_failed_with(
            here,
            std::ptr::null(),
            c"xmlXPathNodeSetCreate",
            &format!("expr={}", data.expression),
        );
        return None;
    };
    // SAFETY: the node set is the caller's to give up.
    let nodes = unsafe { xmlSecNodeSetCreate(doc, selected, data.node_set_type) };
    if nodes.is_null() {
        errors::internal_with(
            here,
            std::ptr::null(),
            c"xmlSecNodeSetCreate",
            &format!("type={}", data.node_set_type),
        );
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
    let here = here!("xmlSecTransformXPathExecute");
    let checked = (here, c"xmlSecTransformXPathCheckId(transform)");
    // SAFETY: the caller passes null or a transform.
    let Some(expressions) = (unsafe { data_list(transform, &family(), checked) }) else {
        return -1;
    };
    // SAFETY: a valid transform.
    let object = unsafe { &mut *transform };
    check!(
        !object.here_node.is_null(),
        "xmlSecTransformXPathExecute",
        c"transform->hereNode != NULL",
        -1
    );
    check!(
        object.out_nodes.is_null(),
        "xmlSecTransformXPathExecute",
        c"transform->outNodes == NULL",
        -1
    );
    check!(last != 0, "xmlSecTransformXPathExecute", c"last != 0", -1);
    check!(
        !ctx.is_null(),
        "xmlSecTransformXPathExecute",
        c"transformCtx != NULL",
        -1
    );
    check!(
        // SAFETY: an initialized data list.
        unsafe { xmlSecPtrListGetSize(&raw mut *expressions) } > 0,
        "xmlSecTransformXPathExecute",
        c"xmlSecPtrListGetSize(dataList) > 0",
        -1
    );
    // SAFETY: the input set and the here node are live.
    let doc = unsafe {
        if object.in_nodes.is_null() {
            (*object.here_node).doc
        } else {
            (*object.in_nodes).doc
        }
    };
    check!(
        !doc.is_null(),
        "xmlSecTransformXPathExecute",
        c"doc != NULL",
        -1
    );
    if !readable() {
        errors::no_libxml2(here);
        return -1;
    }
    // SAFETY: an expression transform read from a live element.
    let Some(output) = (unsafe { evaluate_list(expressions, object.in_nodes, doc) }) else {
        // SAFETY: a valid transform.
        let name = unsafe { name_of(transform) };
        errors::internal(here, name, c"xmlSecXPathDataListExecute");
        return -1;
    };
    object.out_nodes = output;
    0
}

/// The node set the expressions of `list` make from `input` over `doc`
/// (libxmlsec1's `xmlSecXPathDataListExecute`, whose failures it reports).
///
/// # Safety
/// `list` is a data list; `input` is null or a live node set over the live
/// document `doc`.
unsafe fn evaluate_list(
    list: &mut XmlSecPtrList,
    input: *mut XmlSecNodeSet,
    doc: *mut XmlDoc,
) -> Option<*mut XmlSecNodeSet> {
    let here = here!("xmlSecXPathDataListExecute");
    let policy = policy::verification_at(here)?;
    // The core projects the tree in place of libxml2's evaluation context.
    let failed = |error: &str| {
        errors::internal_with(here, std::ptr::null(), c"xmlSecXPathDataExecute", error);
    };
    // SAFETY: the document is live for the call.
    let Some(tree) = (unsafe { LibxmlTree::new(doc) }) else {
        failed("the document cannot be read");
        return None;
    };
    let document = match XmlDocument::from_external_tree(Box::new(tree), policy) {
        Ok(document) => document,
        Err(error) => {
            failed(&error.to_string());
            return None;
        }
    };
    // SAFETY: every item of a data list is a `Data`.
    let items: Vec<&Data> = unsafe {
        (0..xmlSecPtrListGetSize(list))
            .map(|position| &*xmlSecPtrListGetItem(list, position).cast::<Data>())
            .collect()
    };
    // One selector for the whole transform: its expressions charge the same
    // budgets, each with its own here().
    document.with_view(|view| {
        let mut selector = match Selector::new(view, None, &[], &policy.resources) {
            Ok(selector) => selector,
            Err(error) => {
                failed(&error.to_string());
                return None;
            }
        };
        // SAFETY: the input is a live set over `doc`, which the view
        // projects.
        unsafe { combined_output(input, &items, doc, &mut selector) }
    })
}

/// The transform's output for `input`.
///
/// # Safety
/// `input` is null or a live node set over `doc`, which the selector's view
/// projects.
unsafe fn combined_output(
    input: *mut XmlSecNodeSet,
    items: &[&Data],
    doc: *mut XmlDoc,
    selector: &mut Selector<'_, '_>,
) -> Option<*mut XmlSecNodeSet> {
    let filter2 = items.iter().any(|data| data.kind == Kind::XPath2);
    // XPath Filter 2.0 section 3.4: the filter starts from the whole
    // document, O = I INTERSECT F. Folding the operations into the input
    // directly computes the same set for intersect and subtract, but a
    // union would add nodes outside I, and with no input the first
    // operation would apply to nothing; libxmlsec1 does both.
    if !(filter2 && (input.is_null() || items.iter().any(|data| data.op == UNION))) {
        // SAFETY: by the caller's contract.
        return unsafe { combine(input, input, items, doc, selector) };
    }
    let here = here!("xmlSecXPathDataListExecute");
    // SAFETY: by the caller's contract; every set made here is released on
    // failure.
    unsafe {
        let whole = xmlSecNodeSetGetChildren(doc, std::ptr::null_mut(), 1, 0);
        if whole.is_null() {
            errors::internal(here, std::ptr::null(), c"xmlSecNodeSetGetChildren");
            return None;
        }
        let filter = combine(whole, std::ptr::null_mut(), items, doc, selector)?;
        if input.is_null() {
            return Some(filter);
        }
        let explicit = materialize(filter, doc);
        xmlSecNodeSetDestroy(filter);
        let explicit = explicit?;
        let output = xmlSecNodeSetAdd(input, explicit, INTERSECTION);
        if output.is_null() {
            errors::internal_with(
                here,
                std::ptr::null(),
                c"xmlSecNodeSetAdd",
                &format!("nodeSetOp={INTERSECTION}"),
            );
            xmlSecNodeSetDestroy(explicit);
            return None;
        }
        Some(output)
    }
}

/// `start` combined with each expression's node set by its operation; on
/// failure every set but `kept` (the caller's input) is destroyed.
///
/// # Safety
/// `start` is null or a live node set over `doc`, which the selector's view
/// projects.
unsafe fn combine(
    start: *mut XmlSecNodeSet,
    kept: *mut XmlSecNodeSet,
    items: &[&Data],
    doc: *mut XmlDoc,
    selector: &mut Selector<'_, '_>,
) -> Option<*mut XmlSecNodeSet> {
    let here = here!("xmlSecXPathDataListExecute");
    let mut result = start;
    // SAFETY: by the caller's contract; failed sets are released here.
    unsafe {
        for data in items {
            let Some(nodes) = evaluate(data, doc, selector) else {
                errors::internal(here, std::ptr::null(), c"xmlSecXPathDataExecute");
                if result != kept {
                    xmlSecNodeSetDestroy(result);
                }
                return None;
            };
            let combined = xmlSecNodeSetAdd(result, nodes, data.op);
            if combined.is_null() {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecNodeSetAdd",
                    &format!("nodeSetOp={}", data.op),
                );
                if result != kept {
                    xmlSecNodeSetDestroy(result);
                }
                xmlSecNodeSetDestroy(nodes);
                return None;
            }
            result = combined;
        }
    }
    Some(result)
}

/// Adds each visited node to the `XPath` node set in `data`; a namespace
/// node is added for its element, as libxml2 represents it.
unsafe extern "C" fn collect(
    _set: *mut XmlSecNodeSet,
    node: *mut XmlNode,
    parent: *mut XmlNode,
    data: *mut c_void,
) -> c_int {
    // SAFETY: the walk passes live nodes and the set `materialize` owns.
    unsafe {
        let set = data.cast::<XmlNodeSet>();
        if (*node).kind == XML_NAMESPACE_DECL {
            xmlXPathNodeSetAddNs(set, parent, node.cast())
        } else {
            xmlXPathNodeSetAdd(set, node)
        }
    }
}

/// A normal node set listing exactly the nodes `set` contains; failures are
/// reported.
///
/// # Safety
/// `set` is a live node set over the live document `doc`.
unsafe fn materialize(set: *mut XmlSecNodeSet, doc: *mut XmlDoc) -> Option<*mut XmlSecNodeSet> {
    let here = here!("xmlSecXPathDataListExecute");
    // SAFETY: by the caller's contract; the XPath set is freed on failure.
    unsafe {
        let nodes = xmlXPathNodeSetCreate(std::ptr::null_mut());
        if nodes.is_null() {
            errors::xml_failed(here, std::ptr::null(), c"xmlXPathNodeSetCreate");
            return None;
        }
        if xmlSecNodeSetWalk(set, Some(collect), nodes.cast()) < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecNodeSetWalk");
            xmlXPathFreeNodeSet(nodes);
            return None;
        }
        let explicit = xmlSecNodeSetCreate(doc, nodes, NORMAL);
        if explicit.is_null() {
            errors::internal(here, std::ptr::null(), c"xmlSecNodeSetCreate");
            xmlXPathFreeNodeSet(nodes);
            return None;
        }
        Some(explicit)
    }
}

/// The id slot of the `Visa3D` transform `$transform`, after libxmlsec1's
/// assertion inside the entry point `$func`, or `$ret` (nothing, without
/// `$ret`).
macro_rules! visa3d_id_or {
    ($transform:expr, $func:literal $(, $ret:expr)?) => {
        context_or!(
            $transform,
            *mut u8,
            visa3d_hack(),
            $func,
            c"xmlSecTransformCheckId(transform, xmlSecTransformVisa3DHackId)"
            $(, $ret)?
        )
    };
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
        let slot = visa3d_id_or!(transform, "xmlSecTransformVisa3DHackSetID", -1);
        check!(
            !id.is_null(),
            "xmlSecTransformVisa3DHackSetID",
            c"id != NULL",
            -1
        );
        check!(
            slot.is_null(),
            "xmlSecTransformVisa3DHackSetID",
            c"(*idPtr) == NULL",
            -1
        );
        // SAFETY: `id` is NUL-terminated; the copy holds its bytes.
        unsafe {
            let bytes = CStr::from_ptr(id.cast()).to_bytes_with_nul();
            let copy = malloc(bytes.len()).cast::<u8>();
            if copy.is_null() {
                errors::strdup_failed(
                    here!("xmlSecTransformVisa3DHackSetID"),
                    name_of(transform),
                    &bytes[..bytes.len() - 1],
                );
                return -1;
            }
            bytes.as_ptr().copy_to(copy, bytes.len());
            *slot = copy;
        }
        0
    })
}

unsafe extern "C" fn visa3d_finalize(transform: *mut XmlSecTransform) {
    let slot = visa3d_id_or!(transform, "xmlSecTransformVisa3DHackFinalize");
    // SAFETY: the id is null or the copy `SetID` allocated.
    unsafe { free(slot.cast()) };
    *slot = std::ptr::null_mut();
}

/// Selects the element carrying the id, as its subtree without comments.
unsafe extern "C" fn visa3d_execute(
    transform: *mut XmlSecTransform,
    last: c_int,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    let slot = visa3d_id_or!(transform, "xmlSecTransformVisa3DHackExecute", -1);
    let id = *slot;
    // SAFETY: a valid transform.
    let object = unsafe { &mut *transform };
    check!(
        object.out_nodes.is_null(),
        "xmlSecTransformVisa3DHackExecute",
        c"transform->outNodes == NULL",
        -1
    );
    check!(
        last != 0,
        "xmlSecTransformVisa3DHackExecute",
        c"last != 0",
        -1
    );
    check!(
        !ctx.is_null(),
        "xmlSecTransformVisa3DHackExecute",
        c"transformCtx != NULL",
        -1
    );
    check!(
        !id.is_null(),
        "xmlSecTransformVisa3DHackExecute",
        c"(*idPtr) != NULL",
        -1
    );
    check!(
        !object.in_nodes.is_null() || !object.here_node.is_null(),
        "xmlSecTransformVisa3DHackExecute",
        c"transform->hereNode != NULL",
        -1
    );
    // SAFETY: the input set or the here node is live.
    let doc = unsafe {
        if object.in_nodes.is_null() {
            (*object.here_node).doc
        } else {
            (*object.in_nodes).doc
        }
    };
    check!(
        !doc.is_null(),
        "xmlSecTransformVisa3DHackExecute",
        c"doc != NULL",
        -1
    );
    let here = here!("xmlSecTransformVisa3DHackExecute");
    if !readable() {
        errors::no_libxml2(here);
        return -1;
    }
    // SAFETY: a `Visa3D` transform with its id set, over a live document.
    unsafe {
        let name = name_of(transform);
        let detail = || format!("id=\"{}\"", klass_text(id));
        // The tree's own ID table, which its builder filled.
        let attribute = xmlGetID(doc, id);
        if attribute.is_null() || (*attribute).parent.is_null() {
            errors::xml_failed_with(here, name, c"xmlGetID", &detail());
            return -1;
        }
        let set = xmlXPathNodeSetCreate((*attribute).parent);
        if set.is_null() {
            errors::xml_failed_with(here, name, c"xmlXPathNodeSetCreate", &detail());
            return -1;
        }
        object.out_nodes = xmlSecNodeSetCreate(doc, set, TREE_WITHOUT_COMMENTS);
        if object.out_nodes.is_null() {
            errors::internal(here, name, c"xmlSecNodeSetCreate");
            xmlXPathFreeNodeSet(set);
            return -1;
        }
        0
    }
}
