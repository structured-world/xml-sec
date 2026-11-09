//! Node set algebra without a document: a member whose node list is null
//! contains every node, so the operations and types decide membership alone.
//! Trees are exercised against libxmlsec1 by the differential C program.

use super::{
    INTERSECTION, INVERT, NORMAL, SUBTRACTION, TREE, TREE_WITHOUT_COMMENTS, UNION, XmlSecNodeSet,
    xmlSecNodeSetAdd, xmlSecNodeSetAddList, xmlSecNodeSetContains, xmlSecNodeSetCreate,
    xmlSecNodeSetDestroy, xmlSecNodeSetGetChildren,
};
use xml_sec_libxml2::ffi::{XML_COMMENT_NODE, XML_ELEMENT_NODE, XmlNode};

/// A detached node of `kind`, read only for its kind and parent.
fn node(kind: i32) -> XmlNode {
    // SAFETY: an all-zero `xmlNode` is a node without links or strings.
    let mut node: XmlNode = unsafe { std::mem::zeroed() };
    node.kind = kind;
    node
}

fn set(kind: i32) -> *mut XmlSecNodeSet {
    // SAFETY: a set over no document and no listed nodes.
    let set = unsafe { xmlSecNodeSetCreate(std::ptr::null_mut(), std::ptr::null_mut(), kind) };
    assert!(!set.is_null());
    set
}

/// Each member combines with the result of those before it: intersection
/// and subtraction can only remove, union can only add back.
#[test]
fn operations_combine_in_list_order() {
    let mut element = node(XML_ELEMENT_NODE);
    let element = &raw mut element;
    // SAFETY: the sets are live until destroyed and the node is live.
    unsafe {
        let all = set(NORMAL);
        assert_eq!(xmlSecNodeSetContains(all, element, std::ptr::null_mut()), 1);
        let combined = xmlSecNodeSetAdd(all, set(INVERT), INTERSECTION);
        assert_eq!(combined, all);
        assert_eq!(xmlSecNodeSetContains(all, element, std::ptr::null_mut()), 0);
        xmlSecNodeSetAdd(all, set(NORMAL), UNION);
        assert_eq!(xmlSecNodeSetContains(all, element, std::ptr::null_mut()), 1);
        xmlSecNodeSetAdd(all, set(NORMAL), SUBTRACTION);
        assert_eq!(xmlSecNodeSetContains(all, element, std::ptr::null_mut()), 0);
        // An unknown operation fails the check rather than guessing.
        (*all).op = 9;
        assert_eq!(
            xmlSecNodeSetContains(all, element, std::ptr::null_mut()),
            -1
        );
        xmlSecNodeSetDestroy(all);
    }
}

/// Tree types without comments exclude comment nodes even when the list
/// contains everything; a null set contains every node.
#[test]
fn comments_and_null_sets() {
    let mut comment = node(XML_COMMENT_NODE);
    let comment = &raw mut comment;
    // SAFETY: as above.
    unsafe {
        let tree = set(TREE_WITHOUT_COMMENTS);
        assert_eq!(
            xmlSecNodeSetContains(tree, comment, std::ptr::null_mut()),
            0
        );
        xmlSecNodeSetDestroy(tree);
        assert_eq!(
            xmlSecNodeSetContains(std::ptr::null_mut(), comment, std::ptr::null_mut()),
            1
        );
        assert_eq!(
            xmlSecNodeSetContains(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            0
        );
    }
}

/// Only a single-member set over the same document is appended; the
/// deprecated list form and a missing document are refused.
#[test]
fn refusals() {
    // SAFETY: the sets are live until destroyed.
    unsafe {
        let first = set(NORMAL);
        let second = set(NORMAL);
        xmlSecNodeSetAdd(first, second, UNION);
        // `second` is now a member of a two-member ring.
        let lone = set(NORMAL);
        assert!(xmlSecNodeSetAdd(lone, second, UNION).is_null());
        xmlSecNodeSetDestroy(lone);
        let other_doc = set(NORMAL);
        (*other_doc).doc = std::ptr::without_provenance_mut(8);
        assert!(xmlSecNodeSetAdd(first, other_doc, UNION).is_null());
        (*other_doc).doc = std::ptr::null_mut();
        xmlSecNodeSetDestroy(other_doc);
        assert!(xmlSecNodeSetAddList(first, std::ptr::null_mut(), UNION).is_null());
        assert!(xmlSecNodeSetAdd(first, std::ptr::null_mut(), UNION).is_null());
        assert!(
            xmlSecNodeSetGetChildren(std::ptr::null_mut(), std::ptr::null_mut(), 1, 0).is_null()
        );
        xmlSecNodeSetDestroy(first);
    }
}

/// Counts the walk's calls per node name or text content.
unsafe extern "C" fn record(
    _set: *mut XmlSecNodeSet,
    node: *mut XmlNode,
    _parent: *mut XmlNode,
    data: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    // SAFETY: the walk passes live nodes and the vector the test owns.
    unsafe {
        let seen = &mut *data.cast::<Vec<String>>();
        let text = if (*node).kind == xml_sec_libxml2::ffi::XML_TEXT_NODE {
            (*node).content.cast_const()
        } else {
            (*node).name
        };
        seen.push(
            std::ffi::CStr::from_ptr(text.cast())
                .to_string_lossy()
                .into_owned(),
        );
    }
    0
}

/// The walk calls back once per node of the set (the documented contract),
/// also when a listed node lies inside another listed subtree or a later
/// member adds nodes by union; libxmlsec1 walks only the listed subtrees.
#[test]
fn walk_visits_each_member_node_once() {
    let xml = b"<r><a>x</a><b>y</b></r>";
    // SAFETY: the document and node sets are used while live; each set owns
    // its XPath node set.
    unsafe {
        let doc = crate::ffi::parser::xmlSecParseMemory(xml.as_ptr(), xml.len(), 0);
        assert!(!doc.is_null());
        let root = (*doc).children;
        let a = (*root).children;
        let b = (*a).next;
        let walk = |set: *mut XmlSecNodeSet| {
            let mut seen: Vec<String> = Vec::new();
            let data = (&raw mut seen).cast::<std::ffi::c_void>();
            assert_eq!(super::xmlSecNodeSetWalk(set, Some(record), data), 0);
            seen
        };

        let listed = crate::ffi::tree::xmlXPathNodeSetCreate(a);
        crate::ffi::tree::xmlXPathNodeSetAdd(listed, (*a).children);
        let overlapping = xmlSecNodeSetCreate(doc, listed, NORMAL);
        assert_eq!(walk(overlapping), ["a", "x"]);
        xmlSecNodeSetDestroy(overlapping);

        let left = xmlSecNodeSetCreate(doc, crate::ffi::tree::xmlXPathNodeSetCreate(a), TREE);
        let right = xmlSecNodeSetCreate(doc, crate::ffi::tree::xmlXPathNodeSetCreate(b), TREE);
        let union = xmlSecNodeSetAdd(left, right, UNION);
        assert_eq!(walk(union), ["a", "x", "b", "y"]);
        xmlSecNodeSetDestroy(union);
        crate::ffi::tree::xmlFreeDoc(doc);
    }
}

/// The walk is in document order whatever order a caller listed the nodes
/// in, and a lone member whose operation is not intersection is walked as
/// the set it stands for: a union holds every node, a subtraction every node
/// outside its list.
#[test]
fn walk_follows_document_order_and_the_member_operation() {
    let xml = b"<r><a>x</a><b>y</b></r>";
    // SAFETY: as above.
    unsafe {
        let doc = crate::ffi::parser::xmlSecParseMemory(xml.as_ptr(), xml.len(), 0);
        assert!(!doc.is_null());
        let root = (*doc).children;
        let a = (*root).children;
        let b = (*a).next;
        let walk = |set: *mut XmlSecNodeSet| {
            let mut seen: Vec<String> = Vec::new();
            let data = (&raw mut seen).cast::<std::ffi::c_void>();
            assert_eq!(super::xmlSecNodeSetWalk(set, Some(record), data), 0);
            seen
        };
        let listed = || {
            let nodes = crate::ffi::tree::xmlXPathNodeSetCreate(b);
            crate::ffi::tree::xmlXPathNodeSetAdd(nodes, a);
            nodes
        };

        let reversed = xmlSecNodeSetCreate(doc, listed(), TREE);
        assert_eq!(walk(reversed), ["a", "x", "b", "y"]);
        xmlSecNodeSetDestroy(reversed);

        let union = xmlSecNodeSetAdd(
            std::ptr::null_mut(),
            xmlSecNodeSetCreate(doc, listed(), TREE),
            UNION,
        );
        assert_eq!(walk(union), ["r", "a", "x", "b", "y"]);
        xmlSecNodeSetDestroy(union);

        let subtraction = xmlSecNodeSetAdd(
            std::ptr::null_mut(),
            xmlSecNodeSetCreate(doc, crate::ffi::tree::xmlXPathNodeSetCreate(a), TREE),
            SUBTRACTION,
        );
        assert_eq!(walk(subtraction), ["r", "b", "y"]);
        xmlSecNodeSetDestroy(subtraction);
        crate::ffi::tree::xmlFreeDoc(doc);
    }
}

/// CDATA characters are text (`XPath` 1.0 section 5.7), so the text dump
/// that feeds Base64 writes them like any text node.
#[test]
fn text_dump_includes_cdata() {
    let xml = b"<r>Zm9v<![CDATA[YmFy]]></r>";
    // SAFETY: the libxml2 document, set and output buffer are used while live.
    unsafe {
        // Recovery parses with libxml2, which keeps the CDATA section.
        let doc = crate::ffi::parser::xmlSecParseMemory(xml.as_ptr(), xml.len(), 1);
        assert!(!doc.is_null());
        let set = xmlSecNodeSetGetChildren(doc, std::ptr::null_mut(), 1, 0);
        let buffer = crate::ffi::buffer::xmlSecBufferCreate(0);
        let out = crate::ffi::transforms::io::xmlSecBufferCreateOutputBuffer(buffer);
        assert_eq!(super::xmlSecNodeSetDumpTextNodes(set, out), 0);
        crate::ffi::transforms::io::xmlOutputBufferClose(out);
        let written = std::slice::from_raw_parts(
            crate::ffi::buffer::xmlSecBufferGetData(buffer),
            crate::ffi::buffer::xmlSecBufferGetSize(buffer),
        );
        assert_eq!(written, b"Zm9vYmFy");
        crate::ffi::buffer::xmlSecBufferDestroy(buffer);
        xmlSecNodeSetDestroy(set);
        crate::ffi::tree::xmlFreeDoc(doc);
    }
}
