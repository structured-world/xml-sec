//! Node set algebra without a document: a member whose node list is null
//! contains every node, so the operations and types decide membership alone.
//! Trees are exercised against libxmlsec1 by the differential C program.

use super::{
    INTERSECTION, INVERT, NORMAL, SUBTRACTION, TREE_WITHOUT_COMMENTS, UNION, XmlSecNodeSet,
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
