//! The tree functions as C code calls them: through opaque handles only.

use std::ffi::CStr;

use super::*;
use crate::ffi::memory::xsFree;
use crate::nodes::{XML_ATTRIBUTE_NODE, XML_ELEMENT_NODE, XML_NAMESPACE_DECL};

/// The text of a string a tree function returned, released afterwards.
fn take(pointer: *mut XmlChar) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated string `give` issued, read before release.
    let text = unsafe { CStr::from_ptr(pointer.cast()) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: released once.
    unsafe { xsFree(pointer.cast()) };
    Some(text)
}

fn parse(xml: &str) -> *mut Doc {
    let size = c_int::try_from(xml.len()).expect("a small document");
    // SAFETY: `xml` holds `size` bytes; the other arguments may be null.
    unsafe {
        xsReadMemory(
            xml.as_ptr().cast(),
            size,
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    }
}

fn dump(doc: *mut Doc) -> String {
    let mut mem = std::ptr::null_mut();
    let mut size = 0;
    // SAFETY: both out-pointers are writable locals.
    unsafe { xsDocDumpMemory(doc, &raw mut mem, &raw mut size) };
    let text = take(mem).expect("a dump");
    assert_eq!(usize::try_from(size).expect("a length"), text.len());
    text
}

#[test]
fn a_parsed_document_is_read_and_edited_through_handles() {
    // SAFETY: every call takes handles the calls above returned, or strings
    // these literals provide.
    unsafe {
        let doc = parse(r#"<r xmlns:p="urn:p"><c a="1"/></r>"#);
        assert!(!doc.is_null(), "the document parses");
        let root = xsDocGetRootElement(doc);
        assert_eq!(xsNodeGetType(root), XML_ELEMENT_NODE);
        assert_eq!(take(xsNodeGetName(root)).as_deref(), Some("r"));
        assert_eq!(xsNodeGetDoc(root), doc);
        let child = xsNodeGetChildren(root);
        assert_eq!(xsNodeGetParent(child), root);
        assert_eq!(
            take(xsGetProp(child, c"a".as_ptr().cast())).as_deref(),
            Some("1")
        );
        // A new element in a declared namespace, linked last.
        let ns = xsSearchNs(doc, root, c"p".as_ptr().cast());
        assert!(!ns.is_null());
        assert_eq!(take(xsNsGetHref(ns)).as_deref(), Some("urn:p"));
        let added = xsNewDocNode(doc, ns, c"d".as_ptr().cast(), c"t".as_ptr().cast());
        assert_eq!(xsAddChild(root, added), added);
        assert_eq!(xsNodeGetLast(root), added);
        assert!(!xsSetProp(added, c"b".as_ptr().cast(), c"2".as_ptr().cast()).is_null());
        assert_eq!(
            dump(doc),
            "<?xml version=\"1.0\"?>\n<r xmlns:p=\"urn:p\"><c a=\"1\"/><p:d b=\"2\">t</p:d></r>\n"
        );
        xsFreeDoc(doc);
        assert!(
            xsDocGetRootElement(doc).is_null(),
            "a freed document is refused"
        );
    }
}

#[test]
fn a_freed_node_and_forged_handles_are_refused_without_dereference() {
    // SAFETY: as above; the forged values are never dereferenced.
    unsafe {
        let doc = parse("<r><c/></r>");
        let root = xsDocGetRootElement(doc);
        let child = xsNodeGetChildren(root);
        xsFreeNode(child);
        assert!(xsNodeGetChildren(root).is_null());
        assert_eq!(xsNodeGetType(child), 0);
        assert!(take(xsNodeGetName(child)).is_none());
        let forged: *mut Node = pointer_of(usize::MAX - 7);
        assert!(xsNodeGetParent(forged).is_null());
        assert_eq!(xsNodeSetContent(forged, c"x".as_ptr().cast()), -1);
        xsFreeDoc(doc);
    }
}

#[test]
fn attributes_and_namespace_nodes_are_nodes_of_node_sets() {
    // SAFETY: as above.
    unsafe {
        let doc = parse(r#"<r xmlns:p="urn:p"><c a="1" p:b="2"/></r>"#);
        let root = xsDocGetRootElement(doc);
        let child = xsNodeGetChildren(root);
        // The attribute list, in document order, with each attribute's type
        // and element.
        let first = xsNodeGetProperties(child);
        let second = xsAttrGetNext(first);
        assert!(xsAttrGetNext(second).is_null());
        assert_eq!(xsNodeGetType(first.cast()), XML_ATTRIBUTE_NODE);
        assert_eq!(xsNodeGetParent(second.cast()), child);
        assert_eq!(
            take(xsNodeGetNsHref(second.cast())).as_deref(),
            Some("urn:p")
        );
        // A declaration inherited by `c` gives `c` its own namespace node.
        let ns = xsSearchNs(doc, child, c"p".as_ptr().cast());
        let set = xsXPathNodeSetCreate(child);
        assert_eq!(xsXPathNodeSetAddNs(set, child, ns), 0);
        assert_eq!(xsXPathNodeSetAdd(set, first.cast()), 0);
        assert_eq!(
            xsXPathNodeSetAdd(set, child),
            0,
            "a listed node is kept once"
        );
        assert_eq!(xsXPathNodeSetGetLength(set), 3);
        let namespace_node = xsXPathNodeSetItem(set, 1);
        assert_eq!(xsNodeGetType(namespace_node), XML_NAMESPACE_DECL);
        assert_eq!(xsNodeGetParent(namespace_node), child);
        assert_eq!(
            take(xsNsGetHref(namespace_node.cast())).as_deref(),
            Some("urn:p")
        );
        assert_eq!(xsXPathNodeSetContains(set, first.cast()), 1);
        assert_eq!(xsXPathNodeSetContains(set, root), 0);
        // Document order: the root precedes its child, not the reverse.
        assert_eq!(xsXPathCmpNodes(root, child), 1);
        assert_eq!(xsXPathCmpNodes(child, root), -1);
        xsXPathFreeNodeSet(set);
        assert_eq!(xsXPathNodeSetGetLength(set), 0, "a freed set lists nothing");
        xsFreeDoc(doc);
    }
}

#[test]
fn a_refused_link_leaves_the_document_unchanged() {
    // A link the tree refuses, such as one making a node its own ancestor
    // or placing a node beside one without a parent, must not have unlinked
    // the node first.
    // SAFETY: as above.
    unsafe {
        let doc = parse("<r><c><d/></c></r>");
        let root = xsDocGetRootElement(doc);
        let child = xsNodeGetChildren(root);
        let grandchild = xsNodeGetChildren(child);
        let before = dump(doc);
        assert!(xsAddChild(grandchild, child).is_null());
        assert_eq!(dump(doc), before);
        let detached = xsNewDocNode(
            doc,
            std::ptr::null_mut(),
            c"u".as_ptr().cast(),
            std::ptr::null(),
        );
        assert!(xsAddNextSibling(detached, child).is_null());
        assert!(xsReplaceNode(detached, child).is_null());
        assert_eq!(dump(doc), before);
        xsFreeDoc(doc);
    }
}

#[test]
fn a_uri_search_passes_a_shadowed_prefix_for_one_still_in_scope() {
    // `p` is redeclared at `c`, but `q` still binds the URI there, so the
    // search finds `q`, as libxml2's does.
    // SAFETY: as above.
    unsafe {
        let doc =
            parse(r#"<r xmlns:p="urn:wanted" xmlns:q="urn:wanted"><c xmlns:p="urn:other"/></r>"#);
        let child = xsNodeGetChildren(xsDocGetRootElement(doc));
        let ns = xsSearchNsByHref(doc, child, c"urn:wanted".as_ptr().cast());
        assert!(!ns.is_null(), "a binding in scope is found");
        assert_eq!(take(xsNsGetPrefix(ns)).as_deref(), Some("q"));
        xsFreeDoc(doc);
    }
}

#[test]
fn an_attribute_handle_takes_content_as_its_value() {
    // As libxml2's: the content of an attribute node is its value, so
    // setting or adding content changes the value.
    // SAFETY: as above.
    unsafe {
        let doc = parse(r#"<r a="old"/>"#);
        let root = xsDocGetRootElement(doc);
        let attribute = xsHasProp(root, c"a".as_ptr().cast());
        assert_eq!(
            xsNodeSetContent(attribute.cast(), c"new".as_ptr().cast()),
            0
        );
        assert_eq!(
            take(xsGetProp(root, c"a".as_ptr().cast())).as_deref(),
            Some("new")
        );
        assert_eq!(xsNodeAddContent(attribute.cast(), c"er".as_ptr().cast()), 0);
        assert_eq!(
            take(xsGetProp(root, c"a".as_ptr().cast())).as_deref(),
            Some("newer")
        );
        xsFreeDoc(doc);
    }
}

#[test]
fn a_borrowed_name_reads_as_the_name_field() {
    // The name libxmlsec1's xmlSecNodeGetName macro reads: not the caller's
    // to free, the same pointer for each read.
    // SAFETY: as above.
    unsafe {
        let doc = parse("<r><c/></r>");
        let child = xsNodeGetChildren(xsDocGetRootElement(doc));
        let name = xsNodeName(child);
        assert!(!name.is_null());
        assert_eq!(CStr::from_ptr(name.cast()).to_str(), Ok("c"));
        assert_eq!(xsNodeName(child), name);
        let forged: *mut Node = pointer_of(usize::MAX - 9);
        assert!(xsNodeName(forged).is_null());
        xsFreeDoc(doc);
    }
}

#[test]
fn text_that_is_not_utf8_is_refused_not_read_as_absent() {
    // A prefix, URI or content that is not UTF-8 names nothing the call can
    // act on; reading it as null would act on the default namespace, on no
    // namespace or on no content instead.
    let invalid = [0xFF_u8, 0];
    let invalid: *const XmlChar = invalid.as_ptr();
    // SAFETY: as above; `invalid` is NUL-terminated.
    unsafe {
        let doc = parse(r#"<r xmlns="urn:d" a="1"/>"#);
        let root = xsDocGetRootElement(doc);
        assert!(xsSearchNs(doc, root, invalid).is_null());
        assert!(xsNewNs(root, c"urn:x".as_ptr().cast(), invalid).is_null());
        assert!(take(xsGetNsProp(root, c"a".as_ptr().cast(), invalid)).is_none());
        assert!(xsHasNsProp(root, c"a".as_ptr().cast(), invalid).is_null());
        assert!(xsNewDocNode(doc, std::ptr::null_mut(), c"n".as_ptr().cast(), invalid).is_null());
        xsFreeDoc(doc);
    }
}

#[test]
fn content_ids_and_root_replacement_follow_libxml2() {
    // SAFETY: as above.
    unsafe {
        let doc = parse(r#"<r><c id="x">a<b/>c</c></r>"#);
        let root = xsDocGetRootElement(doc);
        let child = xsNodeGetChildren(root);
        assert_eq!(take(xsNodeGetContent(child)).as_deref(), Some("ac"));
        let attribute = xsHasProp(child, c"id".as_ptr().cast());
        assert_eq!(xsAddID(doc, c"x".as_ptr().cast(), attribute), 0);
        assert_eq!(xsGetID(doc, c"x".as_ptr().cast()), child);
        assert_eq!(xsNodeSetContent(child, c"new".as_ptr().cast()), 0);
        assert_eq!(xsNodeAddContent(child, c"er".as_ptr().cast()), 0);
        assert_eq!(take(xsNodeGetContent(child)).as_deref(), Some("newer"));
        let replacement = xsNewDocNode(
            doc,
            std::ptr::null_mut(),
            c"s".as_ptr().cast(),
            std::ptr::null(),
        );
        assert_eq!(xsDocSetRootElement(doc, replacement), root);
        assert_eq!(xsDocGetRootElement(doc), replacement);
        assert!(
            xsNodeGetParent(root).is_null(),
            "the former root is unlinked"
        );
        xsFreeDoc(doc);
    }
}

#[test]
fn a_fragment_reports_a_bad_context_apart_from_bad_content() {
    // xs_tree.h: 1 for a context that is neither an element nor the
    // document node, 5 for content that is not well-formed.
    let fragment = "<x/>";
    let size = c_int::try_from(fragment.len()).expect("a short fragment");
    // SAFETY: every call takes handles the calls above returned, or bytes
    // these literals provide; the out-pointer is a writable local.
    unsafe {
        let doc = parse("<r>text</r>");
        let root = xsDocGetRootElement(doc);
        let text = xsNodeGetChildren(root);
        let mut list = std::ptr::null_mut();
        assert_eq!(
            xsParseInNodeContext(text, fragment.as_ptr().cast(), size, 0, &raw mut list),
            1
        );
        assert!(list.is_null());
        assert_eq!(
            xsParseInNodeContext(root, c"<x>".as_ptr(), 3, 0, &raw mut list),
            5
        );
        assert!(list.is_null());
        xsFreeDoc(doc);
    }
}
