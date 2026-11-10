//! `xmlsec/nodeset.h`: libxmlsec1's node sets over a libxml2 tree.
//!
//! A node set is a circular list of member sets, each a libxml2 `XPath` node
//! set read by a type (the listed nodes, their subtrees, with or without
//! comments, or the inverse) and combined with the members before it by an
//! operation. Membership is decided per node, as libxmlsec1 decides it,
//! through libxml2's own `xmlXPathNodeSetContains`.

use std::ffi::{c_char, c_int, c_void};

use xml_sec_libxml2::ffi::{
    XML_ATTRIBUTE_NODE, XML_CDATA_SECTION_NODE, XML_COMMENT_NODE, XML_DOCUMENT_NODE,
    XML_ELEMENT_NODE, XML_NAMESPACE_DECL, XML_TEXT_NODE, XmlAttr, XmlDoc, XmlNode, XmlNodeSet,
    XmlNs,
};

use super::errors::{self, check, here};
use super::tree::{
    readable, xmlFreeDoc, xmlOutputBufferWriteString, xmlSearchNs, xmlXPathCmpNodes,
    xmlXPathFreeNodeSet, xmlXPathNodeSetAdd, xmlXPathNodeSetContains, xmlXPathNodeSetCreate,
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

/// The parent of a tree node, or the element a namespace node belongs to.
///
/// # Safety
/// `node` is a live node or namespace node of an `XPath` node set.
unsafe fn parent_of(node: *mut XmlNode) -> *mut XmlNode {
    // SAFETY: by the caller's contract; a namespace node's `next` is its
    // element, as libxml2's XPath sets it.
    unsafe {
        if (*node).kind == XML_NAMESPACE_DECL {
            (*node.cast::<XmlNs>()).next.cast::<XmlNode>()
        } else {
            (*node).parent
        }
    }
}

/// Whether `node`, whose parent is `parent`, is listed in `nodes`; a null
/// list contains every node.
///
/// # Safety
/// `nodes` is null or a live `XPath` node set; `node` and `parent` are live.
unsafe fn listed(nodes: *mut XmlNodeSet, node: *mut XmlNode, parent: *mut XmlNode) -> bool {
    if nodes.is_null() {
        return true;
    }
    // SAFETY: the caller passes live nodes.
    unsafe {
        if (*node).kind != XML_NAMESPACE_DECL {
            return xmlXPathNodeSetContains(nodes, node) != 0;
        }
        // libxml2's XPath identifies a namespace node by its prefix and the
        // element in its `next`; libxmlsec1 compares a copy whose `next` is
        // the element the namespace is rendered on (the attribute's owner
        // for an attribute parent). The copy is as large as libxml2's
        // `xmlNs` and only its leading members are read.
        let mut storage = [0usize; 8];
        let copy = storage.as_mut_ptr().cast::<XmlNs>();
        node.cast::<XmlNs>().copy_to_nonoverlapping(copy, 1);
        (*copy).next = if !parent.is_null() && (*parent).kind == XML_ATTRIBUTE_NODE {
            (*parent).parent.cast::<XmlNs>()
        } else {
            parent.cast::<XmlNs>()
        };
        xmlXPathNodeSetContains(nodes, copy.cast::<XmlNode>()) != 0
    }
}

/// Whether `node` or one of its element ancestors is listed in `nodes`.
///
/// # Safety
/// As for [`listed`]; the ancestors of `parent` are live.
unsafe fn listed_or_ancestor(
    nodes: *mut XmlNodeSet,
    mut node: *mut XmlNode,
    mut parent: *mut XmlNode,
) -> bool {
    if nodes.is_null() {
        return true;
    }
    while !node.is_null() {
        // SAFETY: `node` and `parent` are live by the caller's contract.
        unsafe {
            if listed(nodes, node, parent) {
                return true;
            }
            // Elements and the document have children, so the walk up
            // reaches the document node: a tree set listing it holds the
            // whole document (XPath Filter 2.0 section 3.4: nodes with an
            // ancestor in the set). libxmlsec1 stops at the root element.
            if !parent.is_null() && matches!((*parent).kind, XML_ELEMENT_NODE | XML_DOCUMENT_NODE) {
                node = parent;
                parent = (*parent).parent;
            } else {
                node = std::ptr::null_mut();
                parent = std::ptr::null_mut();
            }
        }
    }
    false
}

/// Whether `node` belongs to the member set `set` alone, by its type.
///
/// # Safety
/// `set` is a live member set; `node` and `parent` are live.
unsafe fn member_contains(set: &XmlSecNodeSet, node: *mut XmlNode, parent: *mut XmlNode) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        let comment = (*node).kind == XML_COMMENT_NODE;
        match set.kind {
            NORMAL => listed(set.nodes, node, parent),
            INVERT => !listed(set.nodes, node, parent),
            TREE => listed_or_ancestor(set.nodes, node, parent),
            TREE_WITHOUT_COMMENTS => !comment && listed_or_ancestor(set.nodes, node, parent),
            TREE_INVERT => !listed_or_ancestor(set.nodes, node, parent),
            TREE_WITHOUT_COMMENTS_INVERT => {
                !comment && !listed_or_ancestor(set.nodes, node, parent)
            }
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
}

/// `xmlSecNodeSetCreate`: a node set of one member over `nodes`, which it
/// now owns; released with [`xmlSecNodeSetDestroy`].
///
/// # Safety
/// `nodes` is null or an `XPath` node set the caller gives up.
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
                if !(*member).nodes.is_null() {
                    xmlXPathFreeNodeSet((*member).nodes);
                }
                if !(*member).doc.is_null() && (*member).destroy_doc != 0 {
                    // Freed once, after every member: the others share it.
                    destroy_doc = (*member).doc;
                }
                member.write_bytes(0, 1);
                free(member.cast::<c_void>());
            }
        }
        if !destroy_doc.is_null() {
            // SAFETY: a member owned the document and no member remains.
            unsafe { xmlFreeDoc(destroy_doc) };
        }
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

/// `xmlSecNodeSetContains`: 1 when `node` (with parent `parent`) is in the
/// set, 0 when not, -1 for an unknown operation; a null set contains every
/// node.
///
/// # Safety
/// `set` is null or a live node set; `node` and `parent` are live nodes of
/// its document.
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
        if !readable() {
            errors::no_libxml2(here!("xmlSecNodeSetContains"));
            return -1;
        }
        let inside = |member: &XmlSecNodeSet| {
            // SAFETY: the caller passes live nodes of the set's document.
            unsafe { member_contains(member, node, parent) }
        };
        let mut status = true;
        let mut current = set;
        loop {
            // SAFETY: the ring's members are live while the set is.
            let member = unsafe { &*current };
            // Each member is checked only when it can change the result.
            match member.op {
                INTERSECTION => {
                    if status && !inside(member) {
                        status = false;
                    }
                }
                SUBTRACTION => {
                    if status && inside(member) {
                        status = false;
                    }
                }
                UNION => {
                    if !status && inside(member) {
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
                    return -1;
                }
            }
            current = member.next;
            if current == set {
                break;
            }
        }
        c_int::from(status)
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
/// `doc` is null or a live document; `parent` is null or one of its nodes.
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
        if !readable() {
            errors::no_libxml2(here);
            return std::ptr::null_mut();
        }
        // SAFETY: libxml2 creates a set holding `parent` (none for null).
        let nodes = unsafe { xmlXPathNodeSetCreate(parent) };
        if nodes.is_null() {
            errors::xml_failed(here, std::ptr::null(), c"xmlXPathNodeSetCreate");
            return std::ptr::null_mut();
        }
        if parent.is_null() {
            // SAFETY: the document's top-level nodes are live.
            unsafe {
                let mut current = (*doc).children;
                while !current.is_null() {
                    if with_comments != 0 || (*current).kind != XML_COMMENT_NODE {
                        xmlXPathNodeSetAdd(nodes, current);
                    }
                    current = (*current).next;
                }
            }
        }
        let kind = match (with_comments != 0, invert != 0) {
            (true, true) => TREE_INVERT,
            (true, false) => TREE,
            (false, true) => TREE_WITHOUT_COMMENTS_INVERT,
            (false, false) => TREE_WITHOUT_COMMENTS,
        };
        // SAFETY: `nodes` is ours to give to the new set.
        let set = unsafe { xmlSecNodeSetCreate(doc, nodes, kind) };
        if set.is_null() {
            errors::internal(here, std::ptr::null(), c"xmlSecNodeSetCreate");
            // SAFETY: the set was not created, so `nodes` is still ours.
            unsafe { xmlXPathFreeNodeSet(nodes) };
        }
        set
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
/// libxmlsec1's truth test, a failed membership check (-1) counts as
/// contained.
///
/// # Safety
/// `walk.set` is live; `node` and `parent` are live nodes of its document.
unsafe fn visit(walk: &Walk, node: *mut XmlNode, parent: *mut XmlNode) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        xmlSecNodeSetContains(walk.set, node, parent) == 0
            || (walk.callback)(walk.set, node, parent, walk.data) >= 0
    }
}

/// The tree walk's callback: the node, then for an element or document its
/// attributes and the namespace declarations in scope at it.
unsafe extern "C" fn walk_node(current: *mut XmlNode, data: *mut c_void) -> c_int {
    // SAFETY: `data` is the walk the caller set up; `current` is a live node
    // of the walked tree.
    unsafe {
        let walk = &*data.cast::<Walk>();
        if !visit(walk, current, parent_of(current)) {
            return -1;
        }
        let kind = (*current).kind;
        if kind != XML_ELEMENT_NODE && kind != XML_DOCUMENT_NODE {
            return 1;
        }
        let mut attribute: *mut XmlAttr = (*current).properties;
        while !attribute.is_null() {
            if !visit(walk, attribute.cast::<XmlNode>(), current) {
                return -1;
            }
            attribute = (*attribute).next;
        }
        // A declaration is in scope when the nearest one of its prefix is it.
        let mut scope = current;
        while !scope.is_null() {
            let mut declaration = (*scope).ns_def;
            while !declaration.is_null() {
                let nearest = xmlSearchNs((*walk.set).doc, current, (*declaration).prefix);
                if nearest == declaration && !visit(walk, declaration.cast::<XmlNode>(), current) {
                    return -1;
                }
                declaration = (*declaration).next;
            }
            scope = (*scope).parent;
        }
        1
    }
}

/// Whether no listed node lies inside the subtree of another listed node.
///
/// # Safety
/// `nodes` and its nodes are live.
unsafe fn disjoint(nodes: &XmlNodeSet) -> bool {
    let count = usize::try_from(nodes.node_nr).unwrap_or(0);
    // SAFETY: the table holds `node_nr` live nodes; ancestors are live.
    unsafe {
        (0..count).all(|index| {
            let mut ancestor = parent_of(nodes.node_tab.add(index).read());
            while !ancestor.is_null() {
                if xmlXPathNodeSetContains((&raw const *nodes).cast_mut(), ancestor) != 0 {
                    return false;
                }
                ancestor = parent_of(ancestor);
            }
            true
        })
    }
}

/// The listed nodes in document order, which a caller-built list need not
/// follow; `None` when the list holds attribute or namespace nodes, which
/// `xmlXPathCmpNodes` does not order among their element's other nodes, or
/// libxml2 cannot order two of them.
///
/// # Safety
/// `nodes` and its nodes are live.
unsafe fn in_document_order(nodes: &XmlNodeSet) -> Option<Vec<*mut XmlNode>> {
    let count = usize::try_from(nodes.node_nr).unwrap_or(0);
    // SAFETY: the table holds `node_nr` live nodes.
    let mut seeds: Vec<*mut XmlNode> = (0..count)
        .map(|index| unsafe { nodes.node_tab.add(index).read() })
        .collect();
    if seeds.iter().any(|seed| {
        // SAFETY: live nodes; a namespace member's `type` sits where a
        // node's does.
        let kind = unsafe { (**seed).kind };
        matches!(kind, XML_ATTRIBUTE_NODE | XML_NAMESPACE_DECL)
    }) {
        return None;
    }
    let mut unordered = false;
    seeds.sort_by(|left, right| {
        // SAFETY: live nodes of one document.
        match unsafe { xmlXPathCmpNodes(*left, *right) } {
            1 => std::cmp::Ordering::Less,
            -1 => std::cmp::Ordering::Greater,
            0 => std::cmp::Ordering::Equal,
            _ => {
                unordered = true;
                std::cmp::Ordering::Equal
            }
        }
    });
    (!unordered).then_some(seeds)
}

/// `xmlSecNodeSetWalk`: calls `walk_func` once for every node of the set in
/// document order, stopping at the first negative return.
///
/// # Safety
/// `set` is null or a live node set with a live document; `walk_func` is
/// called with `data`.
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
        if !readable() {
            errors::no_libxml2(here!("xmlSecNodeSetWalk"));
            return -1;
        }
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
        // SAFETY: the set's XPath nodes and document are live.
        unsafe {
            if !member.nodes.is_null()
                && std::ptr::eq(member.next, set)
                && member.op == INTERSECTION
                && matches!(member.kind, NORMAL | TREE | TREE_WITHOUT_COMMENTS)
                && disjoint(&*member.nodes)
                && let Some(seeds) = in_document_order(&*member.nodes)
            {
                for start in seeds {
                    if xmlSecDepthFirstTreeWalk(start, Some(walk_node), walk_data) < 0 {
                        errors::internal(
                            here!("xmlSecNodeSetWalk"),
                            std::ptr::null(),
                            c"xmlSecNodeSetWalkRecursive",
                        );
                        return -1;
                    }
                }
                return 0;
            }
            let mut current = (*member.doc).children;
            while !current.is_null() {
                if xmlSecDepthFirstTreeWalk(current, Some(walk_node), walk_data) < 0 {
                    errors::internal(
                        here!("xmlSecNodeSetWalk"),
                        std::ptr::null(),
                        c"xmlSecNodeSetWalkRecursive",
                    );
                    return -1;
                }
                current = (*current).next;
            }
        }
        0
    })
}

/// Writes a text node's content to the libxml2 output buffer in `data`.
unsafe extern "C" fn dump_text(
    _set: *mut XmlSecNodeSet,
    node: *mut XmlNode,
    _parent: *mut XmlNode,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `node` is a live node of the walked set; `data` is the output
    // buffer the caller passed.
    unsafe {
        // CDATA characters are text (XPath 1.0 section 5.7); libxmlsec1
        // writes only text nodes and drops them.
        if !matches!((*node).kind, XML_TEXT_NODE | XML_CDATA_SECTION_NODE) {
            return 0;
        }
        if xmlOutputBufferWriteString(data, (*node).content.cast::<c_char>()) < 0 {
            errors::xml_failed(
                here!("xmlSecNodeSetDumpTextNodes"),
                std::ptr::null(),
                c"xmlOutputBufferWriteString",
            );
            return -1;
        }
    }
    0
}

/// `xmlSecNodeSetDumpTextNodes`: writes the content of the set's text
/// nodes, in document order, to the libxml2 output buffer `out`.
///
/// # Safety
/// `set` is null or a live node set; `out` is null or a live
/// `xmlOutputBuffer`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetDumpTextNodes(
    set: *mut XmlSecNodeSet,
    out: *mut c_void,
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
        unsafe { xmlSecNodeSetWalk(set, Some(dump_text), out) }
    })
}

/// A NUL-terminated libxml2 string for display, `null` for a null pointer.
///
/// # Safety
/// `text` is null or a NUL-terminated string.
unsafe fn shown(text: *const u8) -> String {
    if text.is_null() {
        return "null".to_owned();
    }
    // SAFETY: by the caller's contract.
    unsafe { std::ffi::CStr::from_ptr(text.cast::<c_char>()) }
        .to_string_lossy()
        .into_owned()
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
        if !readable() {
            errors::no_libxml2(here!("xmlSecNodeSetDebugDump"));
            return;
        }
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
        // SAFETY: the listed nodes are live nodes and namespace nodes of the
        // set's document; a namespace node's `next` is its element.
        unsafe {
            if let Some(nodes) = set.nodes.as_ref() {
                for index in 0..usize::try_from(nodes.node_nr).unwrap_or(0) {
                    let node = nodes.node_tab.add(index).read();
                    let kind = (*node).kind;
                    lines.push(if kind == XML_NAMESPACE_DECL {
                        let ns = &*node.cast::<XmlNs>();
                        let element = &*ns.next.cast::<XmlNode>();
                        let element_prefix =
                            element.ns.as_ref().map_or(std::ptr::null(), |ns| ns.prefix);
                        format!(
                            "{kind}: {}={} ({}:{})\n",
                            shown(ns.prefix),
                            shown(ns.href),
                            shown(element_prefix),
                            shown(element.name),
                        )
                    } else {
                        format!("{kind}: {}\n", shown((*node).name))
                    });
                }
            }
            write_stream(output, &lines.concat());
        }
    });
}
