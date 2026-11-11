//! `xmlsec/nodeset.h`: libxmlsec1's node sets over the document tree.
//!
//! A node set is a circular list of member sets, each an `XPath` node set
//! read by a type (the listed nodes, their subtrees, with or without
//! comments, or the inverse) and combined with the members before it by an
//! operation. Membership is decided per node, as libxmlsec1 decides it.

use std::ffi::{c_int, c_void};

use super::errors::{self, check, here};
use super::transforms::io::{OutputBuffer, xmlOutputBufferWrite};
use super::tree::{
    XML_ATTRIBUTE_NODE, XML_CDATA_SECTION_NODE, XML_COMMENT_NODE, XML_DOCUMENT_NODE,
    XML_ELEMENT_NODE, XML_NAMESPACE_DECL, XML_TEXT_NODE, XmlDoc, XmlNode, XmlNodeSet, nodes,
};
use super::xmltree::xmlSecDepthFirstTreeWalk;
use super::{contain, free, malloc, write_stream};

#[cfg(test)]
mod tests;

/// `xmlSecNodeSetNormal`: the listed nodes.
pub(crate) const NORMAL: c_int = 0;
/// `xmlSecNodeSetInvert`: every node except the listed ones.
pub(crate) const INVERT: c_int = 1;
/// `xmlSecNodeSetTree`: the listed nodes and their subtrees.
pub(crate) const TREE: c_int = 2;
/// `xmlSecNodeSetTreeWithoutComments`: as `TREE`, without comments.
pub(crate) const TREE_WITHOUT_COMMENTS: c_int = 3;
/// `xmlSecNodeSetTreeInvert`: every node outside the listed subtrees.
pub(crate) const TREE_INVERT: c_int = 4;
/// `xmlSecNodeSetTreeWithoutCommentsInvert`: as `TREE_INVERT`, without
/// comments.
pub(crate) const TREE_WITHOUT_COMMENTS_INVERT: c_int = 5;
/// `xmlSecNodeSetList`: deprecated; membership treats it as unknown.
pub(crate) const LIST: c_int = 6;

/// `xmlSecNodeSetIntersection`.
pub(crate) const INTERSECTION: c_int = 0;
/// `xmlSecNodeSetSubtraction`.
pub(crate) const SUBTRACTION: c_int = 1;
/// `xmlSecNodeSetUnion`.
pub(crate) const UNION: c_int = 2;

/// `xmlSecNodeSet`.
#[repr(C)]
pub(crate) struct XmlSecNodeSet {
    pub(crate) nodes: *mut XmlNodeSet,
    pub(crate) doc: *mut XmlDoc,
    pub(crate) destroy_doc: c_int,
    pub(crate) kind: c_int,
    pub(crate) op: c_int,
    pub(crate) next: *mut XmlSecNodeSet,
    pub(crate) prev: *mut XmlSecNodeSet,
    pub(crate) reserved: *mut c_void,
}

/// `xmlSecNodeSetWalkCallback`.
pub(crate) type WalkCallback = Option<
    unsafe extern "C" fn(*mut XmlSecNodeSet, *mut XmlNode, *mut XmlNode, *mut c_void) -> c_int,
>;

/// Whether `node`, whose parent is `parent`, is listed in `nodes`; a null
/// list contains every node. A namespace node is listed as the namespace
/// node of the element it is rendered on: `parent`, or an attribute
/// parent's element, as libxmlsec1 compares it.
fn listed(set: *mut XmlNodeSet, node: *mut XmlNode, parent: *mut XmlNode) -> bool {
    if set.is_null() {
        return true;
    }
    if nodes::kind(node) != XML_NAMESPACE_DECL {
        return nodes::node_set_contains(set, node);
    }
    let element = if nodes::kind(parent) == XML_ATTRIBUTE_NODE {
        nodes::parent(parent)
    } else {
        parent
    };
    let Some((prefix, _)) = nodes::binding(node) else {
        return false;
    };
    nodes::node_set_contains(set, nodes::namespace_node(element, prefix.as_deref()))
}

/// Whether `node` or one of its element ancestors is listed in `nodes`.
fn listed_or_ancestor(
    set: *mut XmlNodeSet,
    mut node: *mut XmlNode,
    mut parent: *mut XmlNode,
) -> bool {
    if set.is_null() {
        return true;
    }
    while !node.is_null() {
        if listed(set, node, parent) {
            return true;
        }
        // Elements and the document have children, so the walk up reaches
        // the document node: a tree set listing it holds the whole document
        // (XPath Filter 2.0 section 3.4: nodes with an ancestor in the set).
        // libxmlsec1 stops at the root element.
        if !parent.is_null() && matches!(nodes::kind(parent), XML_ELEMENT_NODE | XML_DOCUMENT_NODE)
        {
            node = parent;
            parent = nodes::parent(parent);
        } else {
            node = std::ptr::null_mut();
            parent = std::ptr::null_mut();
        }
    }
    false
}

/// Whether `node` belongs to the member set `set` alone, by its type.
fn member_contains(set: &XmlSecNodeSet, node: *mut XmlNode, parent: *mut XmlNode) -> bool {
    let comment = nodes::kind(node) == XML_COMMENT_NODE;
    match set.kind {
        NORMAL => listed(set.nodes, node, parent),
        INVERT => !listed(set.nodes, node, parent),
        TREE => listed_or_ancestor(set.nodes, node, parent),
        TREE_WITHOUT_COMMENTS => !comment && listed_or_ancestor(set.nodes, node, parent),
        TREE_INVERT => !listed_or_ancestor(set.nodes, node, parent),
        TREE_WITHOUT_COMMENTS_INVERT => !comment && !listed_or_ancestor(set.nodes, node, parent),
        // libxmlsec1 reports an unsupported type and answers 0.
        kind => {
            errors::unsupported_enum(
                here!("xmlSecNodeSetContains"),
                std::ptr::null(),
                "node set type",
                kind,
            );
            false
        }
    }
}

/// `xmlSecNodeSetCreate`: a node set of one member over `nodes`, which it
/// now owns; released with [`xmlSecNodeSetDestroy`].
///
/// # Safety
/// Callable with any pointers; `nodes` is given up.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetCreate(
    doc: *mut XmlDoc,
    nodes: *mut XmlNodeSet,
    kind: c_int,
) -> *mut XmlSecNodeSet {
    contain(std::ptr::null_mut(), || {
        let set = malloc(size_of::<XmlSecNodeSet>()).cast::<XmlSecNodeSet>();
        if set.is_null() {
            errors::malloc_failed(
                here!("xmlSecNodeSetCreate"),
                std::ptr::null(),
                size_of::<XmlSecNodeSet>(),
            );
            return set;
        }
        // SAFETY: `set` is a fresh allocation of a node set's size.
        unsafe {
            set.write(XmlSecNodeSet {
                nodes,
                doc,
                destroy_doc: 0,
                kind,
                op: INTERSECTION,
                next: set,
                prev: set,
                reserved: std::ptr::null_mut(),
            });
        }
        set
    })
}

/// `xmlSecNodeSetDestroy`: frees every member of the list `set` belongs
/// to, their `XPath` node sets, and the document when a member was told to.
///
/// # Safety
/// `set` is null or a node set from [`xmlSecNodeSetCreate`] whose members
/// were not destroyed.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetDestroy(set: *mut XmlSecNodeSet) {
    contain((), || {
        check!(!set.is_null(), "xmlSecNodeSetDestroy", c"nset != NULL");
        let mut current = set;
        let mut destroy_doc: *mut XmlDoc = std::ptr::null_mut();
        while !current.is_null() {
            let member = current;
            // SAFETY: every member of the list is live until freed here; the
            // unlinking keeps the remaining ring consistent.
            unsafe {
                let next = (*member).next;
                if !next.is_null() && next != member {
                    (*next).prev = (*member).prev;
                    (*(*member).prev).next = next;
                    current = next;
                } else {
                    current = std::ptr::null_mut();
                }
                nodes::node_set_free((*member).nodes);
                if !(*member).doc.is_null() && (*member).destroy_doc != 0 {
                    // Freed once, after every member: the others share it.
                    destroy_doc = (*member).doc;
                }
                member.write_bytes(0, 1);
                free(member.cast::<c_void>());
            }
        }
        xml_sec_libxml2::document::free(destroy_doc);
    });
}

/// `xmlSecNodeSetDocDestroy`: the document is freed with the node set.
///
/// # Safety
/// `set` is null or a live node set.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetDocDestroy(set: *mut XmlSecNodeSet) {
    contain((), || {
        check!(!set.is_null(), "xmlSecNodeSetDocDestroy", c"nset != NULL",);
        // SAFETY: the caller passes a live node set.
        unsafe { (*set).destroy_doc = 1 };
    });
}

/// Whether `node` (with parent `parent`) is in the set; `None` for an
/// unknown operation, which is reported.
///
/// # Safety
/// `set` is a live node set.
unsafe fn contains(
    set: *mut XmlSecNodeSet,
    node: *mut XmlNode,
    parent: *mut XmlNode,
) -> Option<bool> {
    let mut status = true;
    let mut current = set;
    loop {
        // SAFETY: the ring's members are live while the set is.
        let member = unsafe { &*current };
        // Each member is checked only when it can change the result.
        match member.op {
            INTERSECTION => {
                if status && !member_contains(member, node, parent) {
                    status = false;
                }
            }
            SUBTRACTION => {
                if status && member_contains(member, node, parent) {
                    status = false;
                }
            }
            UNION => {
                if !status && member_contains(member, node, parent) {
                    status = true;
                }
            }
            op => {
                errors::report(
                    here!("xmlSecNodeSetContains"),
                    std::ptr::null(),
                    std::ptr::null(),
                    errors::R_INVALID_OPERATION,
                    &format!("node set operation={op}"),
                );
                return None;
            }
        }
        current = member.next;
        if current == set {
            break;
        }
    }
    Some(status)
}

/// `xmlSecNodeSetContains`: 1 when `node` (with parent `parent`) is in the
/// set, 0 when not, -1 for an unknown operation; a null set contains every
/// node.
///
/// # Safety
/// `set` is null or a live node set.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetContains(
    set: *mut XmlSecNodeSet,
    node: *mut XmlNode,
    parent: *mut XmlNode,
) -> c_int {
    contain(-1, || {
        check!(!node.is_null(), "xmlSecNodeSetContains", c"node != NULL", 0);
        if set.is_null() {
            return 1;
        }
        // SAFETY: by the caller's contract.
        unsafe { contains(set, node, parent) }.map_or(-1, c_int::from)
    })
}

/// `xmlSecNodeSetAdd`: appends the single-member set `new_set` to `set`
/// with operation `op`; returns the combined set (`new_set` itself when
/// `set` is null), or null when the sets cannot be combined.
///
/// # Safety
/// Each pointer is null or a live node set.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetAdd(
    set: *mut XmlSecNodeSet,
    new_set: *mut XmlSecNodeSet,
    op: c_int,
) -> *mut XmlSecNodeSet {
    contain(std::ptr::null_mut(), || {
        // SAFETY: the caller passes null or live node sets.
        unsafe {
            check!(
                !new_set.is_null(),
                "xmlSecNodeSetAdd",
                c"newNSet != NULL",
                std::ptr::null_mut()
            );
            check!(
                (*new_set).next == new_set,
                "xmlSecNodeSetAdd",
                c"newNSet->next == newNSet",
                std::ptr::null_mut()
            );
            (*new_set).op = op;
            if set.is_null() {
                return new_set;
            }
            // Every member of a combined set belongs to one document.
            check!(
                (*set).doc == (*new_set).doc,
                "xmlSecNodeSetAdd",
                c"nset->doc == newNSet->doc",
                std::ptr::null_mut()
            );
            (*new_set).next = set;
            (*new_set).prev = (*set).prev;
            (*(*set).prev).next = new_set;
            (*set).prev = new_set;
        }
        set
    })
}

/// `xmlSecNodeSetAddList`: deprecated; libxmlsec1 refuses it with null.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetAddList(
    _set: *mut XmlSecNodeSet,
    _new_set: *mut XmlSecNodeSet,
    _op: c_int,
) -> *mut XmlSecNodeSet {
    errors::not_implemented(
        here!("xmlSecNodeSetAddList"),
        "xmlSecNodeSetAddList is deprecated",
    );
    std::ptr::null_mut()
}

/// `xmlSecNodeSetGetChildren`: the subtree of `parent` (the whole document
/// when null), with or without comments, or everything else when `invert`.
///
/// # Safety
/// Callable with any pointers.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetGetChildren(
    doc: *mut XmlDoc,
    parent: *mut XmlNode,
    with_comments: c_int,
    invert: c_int,
) -> *mut XmlSecNodeSet {
    contain(std::ptr::null_mut(), || {
        check!(
            !doc.is_null(),
            "xmlSecNodeSetGetChildren",
            c"doc != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecNodeSetGetChildren");
        let set = nodes::node_set(parent);
        if set.is_null() {
            errors::xml_failed(here, std::ptr::null(), c"xmlXPathNodeSetCreate");
            return std::ptr::null_mut();
        }
        if parent.is_null() {
            let mut current = nodes::first_child(doc);
            while !current.is_null() {
                if (with_comments != 0 || nodes::kind(current) != XML_COMMENT_NODE)
                    && nodes::node_set_add(set, current).is_err()
                {
                    errors::xml_failed(here, std::ptr::null(), c"xmlXPathNodeSetAdd");
                    nodes::node_set_free(set);
                    return std::ptr::null_mut();
                }
                current = nodes::next(current);
            }
        }
        let kind = match (with_comments != 0, invert != 0) {
            (true, true) => TREE_INVERT,
            (true, false) => TREE,
            (false, true) => TREE_WITHOUT_COMMENTS_INVERT,
            (false, false) => TREE_WITHOUT_COMMENTS,
        };
        // SAFETY: `set` is ours to give to the new set.
        let created = unsafe { xmlSecNodeSetCreate(doc, set, kind) };
        if created.is_null() {
            errors::internal(here, std::ptr::null(), c"xmlSecNodeSetCreate");
            nodes::node_set_free(set);
        }
        created
    })
}

/// The state of a walk over a node set.
struct Walk {
    set: *mut XmlSecNodeSet,
    callback:
        unsafe extern "C" fn(*mut XmlSecNodeSet, *mut XmlNode, *mut XmlNode, *mut c_void) -> c_int,
    data: *mut c_void,
}

/// Calls the walk's callback for `node` unless the set excludes it; like
/// libxmlsec1's truth test, a failed membership check counts as contained.
///
/// # Safety
/// `walk.set` is live; the callback is callable with the walk's data.
unsafe fn visit(walk: &Walk, node: *mut XmlNode, parent: *mut XmlNode) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        contains(walk.set, node, parent) == Some(false)
            || (walk.callback)(walk.set, node, parent, walk.data) >= 0
    }
}

/// The tree walk's callback: the node, then for an element or document its
/// attributes and the namespace nodes in scope at it, the nearest
/// declaration of each prefix, as libxmlsec1 visits them; the implicit `xml`
/// binding is not declared, so it is not visited.
unsafe extern "C" fn walk_node(current: *mut XmlNode, data: *mut c_void) -> c_int {
    // SAFETY: `data` is the walk the caller set up.
    let walk = unsafe { &*data.cast::<Walk>() };
    // SAFETY: as above.
    if !unsafe { visit(walk, current, nodes::parent(current)) } {
        return -1;
    }
    let kind = nodes::kind(current);
    if kind != XML_ELEMENT_NODE && kind != XML_DOCUMENT_NODE {
        return 1;
    }
    for attribute in nodes::attributes(current) {
        // SAFETY: as above.
        if !unsafe { visit(walk, attribute.cast(), current) } {
            return -1;
        }
    }
    for namespace in nodes::namespace_nodes(current) {
        if nodes::name(namespace).as_deref() == Some("xml") {
            continue;
        }
        // SAFETY: as above.
        if !unsafe { visit(walk, namespace, current) } {
            return -1;
        }
    }
    1
}

/// Whether no listed node lies inside the subtree of another listed node.
fn disjoint(set: *mut XmlNodeSet) -> bool {
    nodes::node_set_members(set).into_iter().all(|member| {
        let mut ancestor = nodes::parent(member);
        while !ancestor.is_null() {
            if nodes::node_set_contains(set, ancestor) {
                return false;
            }
            ancestor = nodes::parent(ancestor);
        }
        true
    })
}

/// The listed nodes in document order, which a caller-built list need not
/// follow; `None` when the list holds attribute or namespace nodes, which
/// are not ordered among their element's other nodes here, or two nodes
/// cannot be ordered.
fn in_document_order(set: *mut XmlNodeSet) -> Option<Vec<*mut XmlNode>> {
    let mut seeds = nodes::node_set_members(set);
    if seeds
        .iter()
        .any(|&seed| matches!(nodes::kind(seed), XML_ATTRIBUTE_NODE | XML_NAMESPACE_DECL))
    {
        return None;
    }
    let mut unordered = false;
    seeds.sort_by(|&left, &right| {
        nodes::compare_order(left, right).unwrap_or_else(|| {
            unordered = true;
            std::cmp::Ordering::Equal
        })
    });
    (!unordered).then_some(seeds)
}

/// `xmlSecNodeSetWalk`: calls `walk_func` once for every node of the set in
/// document order, stopping at the first negative return.
///
/// # Safety
/// `set` is null or a live node set; `walk_func` is called with `data`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetWalk(
    set: *mut XmlSecNodeSet,
    walk_func: WalkCallback,
    data: *mut c_void,
) -> c_int {
    contain(-1, || {
        check!(!set.is_null(), "xmlSecNodeSetWalk", c"nset != NULL", -1);
        // SAFETY: the caller passes a live node set.
        let member = unsafe { &*set };
        check!(
            !member.doc.is_null(),
            "xmlSecNodeSetWalk",
            c"nset->doc != NULL",
            -1
        );
        let Some(callback) = walk_func else {
            errors::assertion(here!("xmlSecNodeSetWalk"), c"walkFunc != NULL");
            return -1;
        };
        let walk = Walk {
            set,
            callback,
            data,
        };
        let walk_data = (&raw const walk).cast_mut().cast::<c_void>();
        // A lone intersected member listing disjoint subtrees holds nothing
        // outside them, so it is walked from each listed node in document
        // order; any other set over the whole document, so every node is
        // visited once and in order (libxmlsec1 takes the shortcut for any
        // listing member, in list order, and then repeats nested nodes and
        // misses nodes a union or a subtraction holds outside the list).
        let starts = if !member.nodes.is_null()
            && std::ptr::eq(member.next, set)
            && member.op == INTERSECTION
            && matches!(member.kind, NORMAL | TREE | TREE_WITHOUT_COMMENTS)
            && disjoint(member.nodes)
            && let Some(seeds) = in_document_order(member.nodes)
        {
            seeds
        } else {
            let mut top = Vec::new();
            let mut current = nodes::first_child(member.doc);
            while !current.is_null() {
                top.push(current);
                current = nodes::next(current);
            }
            top
        };
        for start in starts {
            // SAFETY: the walk outlives the call.
            if unsafe { xmlSecDepthFirstTreeWalk(start, Some(walk_node), walk_data) } < 0 {
                errors::internal(
                    here!("xmlSecNodeSetWalk"),
                    std::ptr::null(),
                    c"xmlSecNodeSetWalkRecursive",
                );
                return -1;
            }
        }
        0
    })
}

/// Writes a text node's content to the output buffer in `data`.
unsafe extern "C" fn dump_text(
    _set: *mut XmlSecNodeSet,
    node: *mut XmlNode,
    _parent: *mut XmlNode,
    data: *mut c_void,
) -> c_int {
    // CDATA characters are text (XPath 1.0 section 5.7); libxmlsec1 writes
    // only text nodes and drops them.
    if !matches!(nodes::kind(node), XML_TEXT_NODE | XML_CDATA_SECTION_NODE) {
        return 0;
    }
    let text = nodes::text(node).unwrap_or_default();
    let written = c_int::try_from(text.len()).is_ok_and(|length| {
        // SAFETY: `data` is the output buffer the caller passed; `text`
        // holds `length` bytes.
        let result = unsafe {
            xmlOutputBufferWrite(data.cast::<OutputBuffer>(), length, text.as_ptr().cast())
        };
        result >= 0
    });
    if !written {
        errors::xml_failed(
            here!("xmlSecNodeSetDumpTextNodes"),
            std::ptr::null(),
            c"xmlOutputBufferWriteString",
        );
        return -1;
    }
    0
}

/// `xmlSecNodeSetDumpTextNodes`: writes the content of the set's text
/// nodes, in document order, to the output buffer `out`.
///
/// # Safety
/// `set` is null or a live node set; `out`'s callbacks are callable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetDumpTextNodes(
    set: *mut XmlSecNodeSet,
    out: *mut OutputBuffer,
) -> c_int {
    contain(-1, || {
        check!(
            !set.is_null(),
            "xmlSecNodeSetDumpTextNodes",
            c"nset != NULL",
            -1
        );
        check!(
            !out.is_null(),
            "xmlSecNodeSetDumpTextNodes",
            c"out != NULL",
            -1
        );
        // SAFETY: as the caller passes.
        unsafe { xmlSecNodeSetWalk(set, Some(dump_text), out.cast()) }
    })
}

/// A string for display, `null` when absent.
fn shown(text: Option<String>) -> String {
    text.unwrap_or_else(|| "null".to_owned())
}

/// `xmlSecNodeSetDebugDump`: prints the first member's type and listed
/// nodes to the C stream `output`.
///
/// # Safety
/// `set` is null or a live node set; `output` is null or a C `FILE*`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetDebugDump(
    set: *mut XmlSecNodeSet,
    output: *mut c_void,
) {
    contain((), || {
        check!(!set.is_null(), "xmlSecNodeSetDebugDump", c"nset != NULL",);
        check!(
            !output.is_null(),
            "xmlSecNodeSetDebugDump",
            c"output != NULL",
        );
        // SAFETY: the caller passes a live node set.
        let set = unsafe { &*set };
        let kind = match set.kind {
            NORMAL => "(xmlSecNodeSetNormal)\n",
            INVERT => "(xmlSecNodeSetInvert)\n",
            TREE => "(xmlSecNodeSetTree)\n",
            TREE_WITHOUT_COMMENTS => "(xmlSecNodeSetTreeWithoutComments)\n",
            TREE_INVERT => "(xmlSecNodeSetTreeInvert)\n",
            TREE_WITHOUT_COMMENTS_INVERT => "(xmlSecNodeSetTreeWithoutCommentsInvert)\n",
            LIST => "(xmlSecNodeSetList)\n",
            _ => "",
        };
        let mut lines = vec![format!("== Nodes set {kind}")];
        for node in nodes::node_set_members(set.nodes) {
            let kind = nodes::kind(node);
            lines.push(if kind == XML_NAMESPACE_DECL {
                let (prefix, href) = nodes::binding(node).unzip();
                let element = nodes::parent(node);
                format!(
                    "{kind}: {}={} ({}:{})\n",
                    shown(prefix.flatten()),
                    shown(href),
                    shown(nodes::prefix(element)),
                    shown(nodes::name(element)),
                )
            } else {
                format!("{kind}: {}\n", shown(nodes::name(node)))
            });
        }
        // SAFETY: a C stream by the caller's contract.
        unsafe { write_stream(output, &lines.concat()) };
    });
}
