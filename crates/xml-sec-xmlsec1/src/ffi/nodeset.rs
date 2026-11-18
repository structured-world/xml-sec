//! `xmlsec/nodeset.h`: libxmlsec1's node sets over the document tree.
//!
//! A node set is a circular list of member sets, each an `XPath` node set
//! read by a type (the listed nodes, their subtrees, with or without
//! comments, or the inverse) and combined with the members before it by an
//! operation. Membership is decided per node, as libxmlsec1 decides it.

use std::cell::Cell;
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
/// node of the element it is rendered on (`parent`, or an attribute
/// parent's element) with the same prefix and URI, as libxmlsec1 compares
/// it.
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
    let Some((prefix, uri)) = nodes::binding(node) else {
        return false;
    };
    // The element's own namespace node for the prefix stands for `node` only
    // when it binds the same URI; a nearer redeclaration is another binding.
    let own = nodes::namespace_node(element, prefix.as_deref());
    nodes::binding(own).is_some_and(|(_, bound)| bound == uri) && nodes::node_set_contains(set, own)
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
        // An entity reference passes the walk up to the element holding it:
        // its replacement is that element's content.
        if !parent.is_null()
            && matches!(
                nodes::kind(parent),
                XML_ELEMENT_NODE | XML_DOCUMENT_NODE | nodes::XML_ENTITY_REF_NODE
            )
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

/// Whether `node` (with parent `parent`) is in the set: the first member is
/// the base set and each later one changes it by its operation. An unknown
/// operation is reported and answers `false`, as libxmlsec1 answers 0 for a
/// failure, which a canonicalization reads as not visible.
///
/// # Safety
/// `set` is a live node set.
unsafe fn contains(set: *mut XmlSecNodeSet, node: *mut XmlNode, parent: *mut XmlNode) -> bool {
    // SAFETY: the ring's members are live while the set is.
    let mut status = member_contains(unsafe { &*set }, node, parent);
    // SAFETY: as above.
    let mut current = unsafe { (*set).next };
    while current != set {
        if current.is_null() {
            errors::assertion(here!("xmlSecNodeSetContains"), c"curNset != NULL");
            return false;
        }
        // SAFETY: as above.
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
                return false;
            }
        }
        current = member.next;
    }
    status
}

/// `xmlSecNodeSetContains`: 1 when `node` (with parent `parent`) is in the
/// set, 0 when not or on a failure; a null set contains every node.
///
/// # Safety
/// `set` is null or a live node set.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetContains(
    set: *mut XmlSecNodeSet,
    node: *mut XmlNode,
    parent: *mut XmlNode,
) -> c_int {
    contain(0, || {
        check!(!node.is_null(), "xmlSecNodeSetContains", c"node != NULL", 0);
        if set.is_null() {
            return 1;
        }
        // SAFETY: by the caller's contract.
        c_int::from(unsafe { contains(set, node, parent) })
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
        check!(
            parent.is_null() || nodes::doc(parent) == doc,
            "xmlSecNodeSetGetChildren",
            c"(parent == NULL) || (parent->doc == doc)",
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
    /// Set when the callback stopped the walk.
    interrupted: Cell<bool>,
}

/// Calls the walk's callback for `node` when the set contains it; false when
/// the callback stops the walk.
///
/// # Safety
/// `walk.set` is live; the callback is callable with the walk's data.
unsafe fn visit(walk: &Walk, node: *mut XmlNode, parent: *mut XmlNode) -> bool {
    // SAFETY: by the caller's contract.
    unsafe {
        !contains(walk.set, node, parent) || (walk.callback)(walk.set, node, parent, walk.data) >= 0
    }
}

/// The tree walk's callback: the node, then for an element its attributes
/// and the namespace nodes in scope at it, the nearest declaration of each
/// prefix, as libxmlsec1 visits them; the implicit `xml` binding is not
/// declared, so it is not visited. A callback that stops the walk ends the
/// tree walk (returning 0) and marks the walk interrupted, which is not an
/// error.
unsafe extern "C" fn walk_node(current: *mut XmlNode, data: *mut c_void) -> c_int {
    // SAFETY: `data` is the walk the caller set up.
    let walk = unsafe { &*data.cast::<Walk>() };
    let stop = || {
        walk.interrupted.set(true);
        0
    };
    // SAFETY: as above.
    if !unsafe { visit(walk, current, nodes::parent(current)) } {
        return stop();
    }
    if nodes::kind(current) != XML_ELEMENT_NODE {
        return 1;
    }
    for attribute in nodes::attributes(current) {
        // SAFETY: as above.
        if !unsafe { visit(walk, attribute.cast(), current) } {
            return stop();
        }
    }
    for namespace in nodes::namespace_nodes(current) {
        if nodes::name(namespace).as_deref() == Some("xml") {
            continue;
        }
        // SAFETY: as above.
        if !unsafe { visit(walk, namespace, current) } {
            return stop();
        }
    }
    1
}

/// Whether `set` lists a namespace node.
fn lists_namespace(set: *mut XmlNodeSet) -> bool {
    nodes::node_set_members(set)
        .into_iter()
        .any(|member| nodes::kind(member) == XML_NAMESPACE_DECL)
}

/// The listed nodes a walk of `set` may start from instead of the whole
/// document, as libxmlsec1 takes them: every node of the set must lie in
/// their subtrees. That holds for a lone set listing its nodes or their
/// subtrees, and for a set of intersections only, through the first member
/// that lists nodes (a member without a list is the whole document and gives
/// no starting point). A list holding namespace nodes is never a start.
///
/// # Safety
/// `set` is a live node set.
unsafe fn start_nodes(set: *mut XmlSecNodeSet) -> Option<*mut XmlNodeSet> {
    let starts = |member: &XmlSecNodeSet| {
        (!member.nodes.is_null() && matches!(member.kind, NORMAL | TREE | TREE_WITHOUT_COMMENTS))
            .then_some(member.nodes)
    };
    // SAFETY: the ring's members are live while the set is.
    let first = unsafe { &*set };
    let found = if std::ptr::eq(first.next, set) {
        starts(first)
    } else {
        let mut found = None;
        let mut current = set;
        loop {
            // SAFETY: as above.
            let member = unsafe { &*current };
            // The first member is the base set; its operation is unused.
            if current != set && member.op != INTERSECTION {
                return None;
            }
            if found.is_none() {
                found = starts(member);
            }
            current = member.next;
            if current == set || current.is_null() {
                break;
            }
        }
        found
    };
    found.filter(|&listed| !lists_namespace(listed))
}

/// Whether a strict ancestor of `node` is one of the walk's `starts`, whose
/// walk covers `node`'s subtree already.
fn under_another_start(starts: *mut XmlNodeSet, node: *mut XmlNode) -> bool {
    let mut current = nodes::parent(node);
    while !current.is_null() && nodes::kind(current) != XML_NAMESPACE_DECL {
        if nodes::node_set_contains(starts, current) {
            return true;
        }
        current = nodes::parent(current);
    }
    false
}

/// The children of `parent`, in document order.
fn children<T>(parent: *const T) -> Vec<*mut XmlNode> {
    let mut top = Vec::new();
    let mut current = nodes::first_child(parent);
    while !current.is_null() {
        top.push(current);
        current = nodes::next(current);
    }
    top
}

/// `xmlSecNodeSetWalk`: calls `walk_func` for every node of the set,
/// stopping at the first negative return, which is not an error (the
/// walk still returns 0): from the listed nodes when the
/// set lies in their subtrees (in list order, a start inside another's
/// subtree skipped, a listed document walked from its children), otherwise
/// over the whole document in document order.
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
            interrupted: Cell::new(false),
        };
        let walk_data = (&raw const walk).cast_mut().cast::<c_void>();
        // SAFETY: a live node set.
        let starts = match unsafe { start_nodes(set) } {
            Some(listed) => {
                let mut starts = Vec::new();
                for node in nodes::node_set_members(listed) {
                    if under_another_start(listed, node) {
                        continue;
                    }
                    // The document node is never visited itself: its
                    // children are, as the walk over the whole document
                    // starts at them.
                    if nodes::kind(node) == XML_DOCUMENT_NODE {
                        starts.extend(children(node));
                    } else {
                        starts.push(node);
                    }
                }
                starts
            }
            None => children(member.doc),
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
            if walk.interrupted.get() {
                break;
            }
        }
        0
    })
}

/// A text dump: its output buffer, and whether a write failed. A failed
/// write interrupts the walk, which the walk itself does not report.
struct TextDump {
    out: *mut OutputBuffer,
    failed: Cell<bool>,
}

/// Writes a text node's content to the output buffer of the dump in `data`.
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
    // SAFETY: `data` is the dump the caller set up.
    let dump = unsafe { &*data.cast::<TextDump>() };
    let text = nodes::text(node).unwrap_or_default();
    let written = c_int::try_from(text.len()).is_ok_and(|length| {
        // SAFETY: the dump's output buffer is the one the caller passed;
        // `text` holds `length` bytes.
        let result = unsafe { xmlOutputBufferWrite(dump.out, length, text.as_ptr().cast()) };
        result >= 0
    });
    if !written {
        errors::xml_failed(
            here!("xmlSecNodeSetDumpTextNodesWalkCallback"),
            std::ptr::null(),
            c"xmlOutputBufferWriteString",
        );
        dump.failed.set(true);
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
        let dump = TextDump {
            out,
            failed: Cell::new(false),
        };
        // SAFETY: as the caller passes; the dump outlives the walk.
        let walked =
            unsafe { xmlSecNodeSetWalk(set, Some(dump_text), (&raw const dump).cast_mut().cast()) };
        if walked < 0 {
            errors::internal(
                here!("xmlSecNodeSetDumpTextNodes"),
                std::ptr::null(),
                c"xmlSecNodeSetWalk",
            );
            return -1;
        }
        if dump.failed.get() { -1 } else { 0 }
    })
}

/// `xmlSecNodeSetDebugDump`: prints each member of the set's list to the C
/// stream `output`, its type, the operation combining it with the members
/// before it (none for the first, the base set) and its node count.
///
/// # Safety
/// `set` is null or a live node set; `output` is null or a C `FILE*`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecNodeSetDebugDump(
    set: *mut XmlSecNodeSet,
    output: *mut c_void,
) {
    contain((), || {
        let here = here!("xmlSecNodeSetDebugDump");
        check!(!set.is_null(), "xmlSecNodeSetDebugDump", c"nset != NULL",);
        check!(
            !output.is_null(),
            "xmlSecNodeSetDebugDump",
            c"output != NULL",
        );
        // Written as libxmlsec1 writes it, member by member, so reports
        // between the lines land where its land.
        // SAFETY: a C stream by the caller's contract.
        let write = |text: &str| unsafe { write_stream(output, text) };
        write("== Nodes set\n");
        let mut current = set;
        loop {
            // SAFETY: the ring's members are live while the set is.
            let member = unsafe { &*current };
            match member.kind {
                NORMAL => write("  type: (xmlSecNodeSetNormal)\n"),
                INVERT => write("  type: (xmlSecNodeSetInvert)\n"),
                TREE => write("  type: (xmlSecNodeSetTree)\n"),
                TREE_WITHOUT_COMMENTS => write("  type: (xmlSecNodeSetTreeWithoutComments)\n"),
                TREE_INVERT => write("  type: (xmlSecNodeSetTreeInvert)\n"),
                TREE_WITHOUT_COMMENTS_INVERT => {
                    write("  type: (xmlSecNodeSetTreeWithoutCommentsInvert)\n");
                }
                LIST => {
                    errors::not_implemented(here, "xmlSecNodeSetList is deprecated");
                    write("  type: (xmlSecNodeSetList)\n");
                }
                kind => errors::unsupported_enum(here, std::ptr::null(), "node set type", kind),
            }
            if current == set {
                // The base set's operation is unused.
                write("  operation: (none)\n");
            } else {
                match member.op {
                    UNION => write("  operation: xmlSecNodeSetUnion\n"),
                    INTERSECTION => write("  operation: xmlSecNodeSetIntersection\n"),
                    SUBTRACTION => write("  operation: xmlSecNodeSetSubtraction\n"),
                    op => {
                        errors::unsupported_enum(here, std::ptr::null(), "node set operation", op);
                    }
                }
            }
            if member.nodes.is_null() {
                // A member without a node list is the whole document.
                write("  nodes: (whole document)\n");
            } else {
                let count = nodes::node_set_members(member.nodes).len();
                write(&format!("  nodes: {count}\n"));
            }
            current = member.next;
            if current.is_null() {
                errors::assertion(here, c"curNset != NULL");
                return;
            }
            if current == set {
                return;
            }
        }
    });
}
