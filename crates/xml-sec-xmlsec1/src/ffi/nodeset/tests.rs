//! Node set algebra and walks over documents the core parsed: a member
//! whose node list is null contains every node, so the operations and types
//! decide membership alone; listed members are read through node handles.

use std::ffi::{c_int, c_void};

use super::{
    INTERSECTION, INVERT, NORMAL, SUBTRACTION, TREE, TREE_WITHOUT_COMMENTS, UNION, XmlSecNodeSet,
    xmlSecNodeSetAdd, xmlSecNodeSetAddList, xmlSecNodeSetContains, xmlSecNodeSetCreate,
    xmlSecNodeSetDestroy, xmlSecNodeSetGetChildren,
};
use crate::ffi::tree::{XML_TEXT_NODE, XmlDoc, XmlNode, nodes};

fn parse(xml: &[u8]) -> *mut XmlDoc {
    // SAFETY: `xml` holds its length in bytes.
    let doc = unsafe { crate::ffi::parser::xmlSecParseMemory(xml.as_ptr(), xml.len(), 0) };
    assert!(!doc.is_null(), "the document parses");
    doc
}

fn set(kind: c_int) -> *mut XmlSecNodeSet {
    // SAFETY: a set over no document and no listed nodes.
    let set = unsafe { xmlSecNodeSetCreate(std::ptr::null_mut(), std::ptr::null_mut(), kind) };
    assert!(!set.is_null());
    set
}

/// A node set listing `listed` in that order.
fn listing(listed: &[*mut XmlNode]) -> *mut crate::ffi::tree::XmlNodeSet {
    let set = nodes::node_set(std::ptr::null::<XmlNode>());
    for &node in listed {
        nodes::node_set_add(set, node).expect("a live node is listed");
    }
    set
}

/// Each member combines with the result of those before it: intersection
/// and subtraction can only remove, union can only add back.
#[test]
fn operations_combine_in_list_order() {
    let doc = parse(b"<r/>");
    let element = nodes::root_element(doc);
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
    xml_sec_libxml2::document::free(doc);
}

/// Tree types without comments exclude comment nodes even when the list
/// contains everything; a null set contains every node.
#[test]
fn comments_and_null_sets() {
    let doc = parse(b"<r><!--c--></r>");
    let comment = nodes::first_child(nodes::root_element(doc));
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
    xml_sec_libxml2::document::free(doc);
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

/// Records each visited node's name, or a text node's content.
unsafe extern "C" fn record(
    _set: *mut XmlSecNodeSet,
    node: *mut XmlNode,
    _parent: *mut XmlNode,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `data` is the vector the test owns.
    let seen = unsafe { &mut *data.cast::<Vec<String>>() };
    let text = if nodes::kind(node) == XML_TEXT_NODE {
        nodes::text(node)
    } else {
        nodes::name(node)
    };
    seen.push(text.unwrap_or_default());
    0
}

fn walk(set: *mut XmlSecNodeSet) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let data = (&raw mut seen).cast::<c_void>();
    // SAFETY: a live set; `record` writes to `seen`.
    let status = unsafe { super::xmlSecNodeSetWalk(set, Some(record), data) };
    assert_eq!(status, 0);
    seen
}

/// The walk calls back once per node of the set (the documented contract),
/// also when a listed node lies inside another listed subtree or a later
/// member adds nodes by union; libxmlsec1 walks only the listed subtrees.
#[test]
fn walk_visits_each_member_node_once() {
    let doc = parse(b"<r><a>x</a><b>y</b></r>");
    let a = nodes::first_child(nodes::root_element(doc));
    let b = nodes::next(a);
    // SAFETY: the sets are live until destroyed; each owns its node list.
    unsafe {
        let overlapping = xmlSecNodeSetCreate(doc, listing(&[a, nodes::first_child(a)]), NORMAL);
        assert_eq!(walk(overlapping), ["a", "x"]);
        xmlSecNodeSetDestroy(overlapping);

        let left = xmlSecNodeSetCreate(doc, listing(&[a]), TREE);
        let right = xmlSecNodeSetCreate(doc, listing(&[b]), TREE);
        let union = xmlSecNodeSetAdd(left, right, UNION);
        assert_eq!(walk(union), ["a", "x", "b", "y"]);
        xmlSecNodeSetDestroy(union);
    }
    xml_sec_libxml2::document::free(doc);
}

/// The walk is in document order whatever order a caller listed the nodes
/// in, and a lone member whose operation is not intersection is walked as
/// the set it stands for: a union holds every node, a subtraction every node
/// outside its list.
#[test]
fn walk_follows_document_order_and_the_member_operation() {
    let doc = parse(b"<r><a>x</a><b>y</b></r>");
    let a = nodes::first_child(nodes::root_element(doc));
    let b = nodes::next(a);
    // SAFETY: as above.
    unsafe {
        let reversed = xmlSecNodeSetCreate(doc, listing(&[b, a]), TREE);
        assert_eq!(walk(reversed), ["a", "x", "b", "y"]);
        xmlSecNodeSetDestroy(reversed);

        let union = xmlSecNodeSetAdd(
            std::ptr::null_mut(),
            xmlSecNodeSetCreate(doc, listing(&[b, a]), TREE),
            UNION,
        );
        assert_eq!(walk(union), ["r", "a", "x", "b", "y"]);
        xmlSecNodeSetDestroy(union);

        let subtraction = xmlSecNodeSetAdd(
            std::ptr::null_mut(),
            xmlSecNodeSetCreate(doc, listing(&[a]), TREE),
            SUBTRACTION,
        );
        assert_eq!(walk(subtraction), ["r", "b", "y"]);
        xmlSecNodeSetDestroy(subtraction);
    }
    xml_sec_libxml2::document::free(doc);
}

/// A document a Rust caller parsed with an internal DTD and registered: its
/// entity references stay in the tree, the parsed replacement under each.
fn with_entity(xml: &str) -> *mut XmlDoc {
    let mut policy = xml_sec::policy::VerificationPolicy::default();
    policy.xml.allow_internal_dtd = true;
    let tree = xml_sec::document::owned_tree::OwnedTree::parse_with_policy(xml, &policy)
        .expect("the document parses");
    nodes::pointer_of(xml_sec_libxml2::handles::register(tree).expect("a handle"))
}

/// The replacement of an entity reference is content of the element that
/// holds the reference: a walk reaches it, and a tree set listing that
/// element holds it through the reference.
#[test]
fn entity_replacement_content_is_walked_and_held_by_its_element() {
    let doc = with_entity(r#"<!DOCTYPE r [<!ENTITY e "<b>t</b>">]><r>&e;</r>"#);
    let root = nodes::root_element(doc);
    let reference = nodes::first_child(root);
    let replaced = nodes::first_child(reference);
    // SAFETY: the sets are live until destroyed; each owns its node list.
    unsafe {
        let all = xmlSecNodeSetCreate(doc, std::ptr::null_mut(), TREE);
        assert!(
            walk(all).contains(&String::from("t")),
            "the walk enters the reference"
        );
        xmlSecNodeSetDestroy(all);
        let set = xmlSecNodeSetCreate(doc, listing(&[root]), TREE);
        assert_eq!(xmlSecNodeSetContains(set, replaced, reference), 1);
        xmlSecNodeSetDestroy(set);
    }
    xml_sec_libxml2::document::free(doc);
}

/// A tree set listing the document node holds the whole document, as the
/// subtree of `/` (`XPath` Filter 2.0 section 3.4: nodes with an ancestor in
/// the set); libxmlsec1 stops the ancestor walk at elements.
#[test]
fn a_tree_set_of_the_document_node_holds_the_whole_document() {
    let doc = parse(b"<r><a>x</a></r>");
    let root = nodes::root_element(doc);
    let a = nodes::first_child(root);
    // SAFETY: the set is used while live and owns its node list.
    unsafe {
        let set = xmlSecNodeSetCreate(doc, listing(&[doc.cast()]), TREE);
        assert_eq!(xmlSecNodeSetContains(set, root, doc.cast()), 1);
        assert_eq!(xmlSecNodeSetContains(set, nodes::first_child(a), a), 1);
        xmlSecNodeSetDestroy(set);
    }
    xml_sec_libxml2::document::free(doc);
}

/// A namespace node is in a listed set when the namespace node of the
/// element it is rendered on is listed, as libxmlsec1 compares them; for an
/// attribute parent that is the attribute's element.
#[test]
fn namespace_nodes_are_listed_by_their_element() {
    let doc = parse(br#"<r xmlns:p="urn:p"><c a="1"/></r>"#);
    let root = nodes::root_element(doc);
    let child = nodes::first_child(root);
    let attribute = nodes::attribute(child, "a", None);
    let declared = nodes::namespace_node(root, Some("p"));
    let inherited = nodes::namespace_node(child, Some("p"));
    // SAFETY: the set is used while live and owns its node list.
    unsafe {
        let set = xmlSecNodeSetCreate(doc, listing(&[inherited]), NORMAL);
        assert_eq!(xmlSecNodeSetContains(set, inherited, child), 1);
        assert_eq!(xmlSecNodeSetContains(set, declared, root), 0);
        assert_eq!(
            xmlSecNodeSetContains(set, declared, attribute.cast()),
            1,
            "an attribute parent stands for its element"
        );
        xmlSecNodeSetDestroy(set);
    }
    xml_sec_libxml2::document::free(doc);
}

/// A namespace node rendered on an element where its prefix is rebound to
/// another URI is not that element's namespace node: libxmlsec1 compares the
/// element, the prefix and the URI.
#[test]
fn a_shadowed_prefix_is_not_the_namespace_node_of_the_element() {
    let doc = parse(br#"<r xmlns:p="urn:a"><c xmlns:p="urn:b"/></r>"#);
    let root = nodes::root_element(doc);
    let child = nodes::first_child(root);
    let outer = nodes::namespace_node(root, Some("p"));
    let inner = nodes::namespace_node(child, Some("p"));
    // SAFETY: the set is used while live and owns its node list.
    unsafe {
        let set = xmlSecNodeSetCreate(doc, listing(&[inner]), NORMAL);
        assert_eq!(xmlSecNodeSetContains(set, inner, child), 1);
        assert_eq!(
            xmlSecNodeSetContains(set, outer, child),
            0,
            "urn:a is not what p binds at c"
        );
        xmlSecNodeSetDestroy(set);
    }
    xml_sec_libxml2::document::free(doc);
}

/// CDATA characters are text (`XPath` 1.0 section 5.7), so the text dump
/// that feeds Base64 writes them like any text node.
#[test]
fn text_dump_includes_cdata() {
    let doc = parse(b"<r>Zm9v<![CDATA[YmFy]]></r>");
    // SAFETY: the set and buffers are used while live.
    unsafe {
        let set = xmlSecNodeSetGetChildren(doc, std::ptr::null_mut(), 1, 0);
        let buffer = crate::ffi::buffer::xmlSecBufferCreate(0);
        let out = crate::ffi::transforms::io::xmlSecBufferCreateOutputBuffer(buffer);
        assert_eq!(super::xmlSecNodeSetDumpTextNodes(set, out), 0);
        assert!(crate::ffi::transforms::io::xmlOutputBufferClose(out) >= 0);
        let written = std::slice::from_raw_parts(
            crate::ffi::buffer::xmlSecBufferGetData(buffer),
            crate::ffi::buffer::xmlSecBufferGetSize(buffer),
        );
        assert_eq!(written, b"Zm9vYmFy");
        crate::ffi::buffer::xmlSecBufferDestroy(buffer);
        xmlSecNodeSetDestroy(set);
    }
    xml_sec_libxml2::document::free(doc);
}
