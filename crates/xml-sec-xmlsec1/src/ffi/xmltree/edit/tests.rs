//! The nodes an edit returns are the ones left in the tree.

use xml_sec_libxml2::ffi::tree::{
    xsDocGetRootElement, xsFreeDoc, xsFreeNode, xsGetID, xsNewDocNode, xsNewDocText, xsUnlinkNode,
};

use super::{xmlSecAddChildNode, xmlSecReplaceContentAndReturn, xmlSecReplaceNodeBufferAndReturn};
use crate::ffi::parser::xmlSecParseMemory;
use crate::ffi::tree::{XmlNode, nodes};

#[test]
fn an_added_text_child_is_returned_linked_under_the_parent() {
    // The returned node must be a child of the parent: a caller links it and
    // keeps using it.
    let xml = "<r/>";
    // SAFETY: handles are validated by each call; the document is freed once.
    unsafe {
        let doc = xmlSecParseMemory(xml.as_ptr(), xml.len(), 1);
        assert!(!doc.is_null(), "the document parses");
        let root = xsDocGetRootElement(doc);
        let text = xsNewDocText(doc, c"t".as_ptr().cast());
        assert!(!text.is_null());
        let added = xmlSecAddChildNode(root, text);
        assert!(!added.is_null());
        assert_eq!(nodes::parent(added), root);
        assert_eq!(nodes::content(root).as_deref(), Some("\nt\n"));
        xsFreeDoc(doc);
    }
}

#[test]
fn replaced_content_comes_back_as_an_unlinked_run_of_siblings() {
    // Adjacent text children come back as the nodes they were, in order,
    // each without a parent, and the new node is the only content.
    let xml = "<r>x<b/>y</r>";
    // SAFETY: handles are validated by each call; every returned node and
    // the document are freed once.
    unsafe {
        let doc = xmlSecParseMemory(xml.as_ptr(), xml.len(), 1);
        assert!(!doc.is_null(), "the document parses");
        let root = xsDocGetRootElement(doc);
        let element = nodes::next(nodes::first_child(root));
        xsUnlinkNode(element);
        xsFreeNode(element);
        let mut replaced: *mut XmlNode = std::ptr::null_mut();
        let new_node = xsNewDocNode(
            doc,
            std::ptr::null_mut(),
            c"n".as_ptr().cast(),
            std::ptr::null(),
        );
        assert_eq!(
            xmlSecReplaceContentAndReturn(root, new_node, &raw mut replaced),
            0
        );
        assert_eq!(nodes::first_child(root), new_node);
        assert!(nodes::next(new_node).is_null());
        let mut texts = Vec::new();
        let mut cur = replaced;
        while !cur.is_null() {
            let next = nodes::next(cur);
            assert!(nodes::parent(cur).is_null(), "a returned node is detached");
            texts.extend(nodes::content(cur));
            xsFreeNode(cur);
            cur = next;
        }
        assert_eq!(texts, ["x", "y"]);
        xsFreeDoc(doc);
    }
}

#[test]
fn a_child_can_become_the_whole_content_of_its_parent() {
    // The new node may be one of the children it replaces: it is taken out
    // before the others are freed, and stays as the only content.
    let xml = "<r><a/><n>kept</n><b/></r>";
    // SAFETY: handles are validated by each call; the document is freed once.
    unsafe {
        let doc = xmlSecParseMemory(xml.as_ptr(), xml.len(), 1);
        assert!(!doc.is_null(), "the document parses");
        let root = xsDocGetRootElement(doc);
        let child = nodes::next(nodes::first_child(root));
        assert_eq!(
            xmlSecReplaceContentAndReturn(root, child, std::ptr::null_mut()),
            0
        );
        assert_eq!(nodes::first_child(root), child);
        assert!(nodes::next(child).is_null());
        assert_eq!(nodes::content(root).as_deref(), Some("kept"));
        xsFreeDoc(doc);
    }
}

#[test]
fn a_node_that_cannot_be_linked_fails_the_replacement() {
    // A node of another document, the element itself or one of its ancestors
    // cannot become the content: the call fails and the element keeps its
    // content and its place.
    let xml = "<r><e>x</e></r>";
    // SAFETY: handles are validated by each call; both documents are freed
    // once.
    unsafe {
        let doc = xmlSecParseMemory(xml.as_ptr(), xml.len(), 1);
        let other = xmlSecParseMemory(xml.as_ptr(), xml.len(), 1);
        assert!(!doc.is_null() && !other.is_null(), "the documents parse");
        let root = xsDocGetRootElement(doc);
        let element = nodes::first_child(root);
        let foreign = xsNewDocNode(
            other,
            std::ptr::null_mut(),
            c"n".as_ptr().cast(),
            std::ptr::null(),
        );
        for refused in [foreign, element, root] {
            assert_eq!(
                xmlSecReplaceContentAndReturn(element, refused, std::ptr::null_mut()),
                -1
            );
            assert_eq!(nodes::content(element).as_deref(), Some("x"));
            assert_eq!(nodes::parent(element), root);
            assert_eq!(xsDocGetRootElement(doc), root);
        }
        xsFreeNode(foreign);
        xsFreeDoc(other);
        xsFreeDoc(doc);
    }
}

#[test]
fn a_buffer_replacement_takes_over_the_ids_of_the_node_it_replaces() {
    // The replaced node leaves the document, so the ID it held belongs to
    // the replacement that carries it, whether the old node is freed or
    // returned.
    for keep in [false, true] {
        let xml = r#"<r><old xml:id="x"/></r>"#;
        let buffer = r#"<new xml:id="x"/>"#;
        // SAFETY: handles are validated by each call; the returned node and
        // the document are freed once.
        unsafe {
            let doc = xmlSecParseMemory(xml.as_ptr(), xml.len(), 1);
            assert!(!doc.is_null(), "the document parses");
            let old = nodes::first_child(xsDocGetRootElement(doc));
            let mut replaced: *mut XmlNode = std::ptr::null_mut();
            let out = if keep {
                &raw mut replaced
            } else {
                std::ptr::null_mut()
            };
            assert_eq!(
                xmlSecReplaceNodeBufferAndReturn(old, buffer.as_ptr(), buffer.len(), out),
                0
            );
            let found = xsGetID(doc, c"x".as_ptr().cast());
            assert!(!found.is_null(), "the ID names an element (keep={keep})");
            assert_eq!(nodes::name(found).as_deref(), Some("new"));
            if keep {
                xsFreeNode(replaced);
            }
            xsFreeDoc(doc);
        }
    }
}

#[test]
fn a_buffer_replaces_the_document_element() {
    // The document element's parent is the document node, which libxml2
    // accepts as a parsing context: the buffer becomes the new root.
    let xml = "<old/>";
    let buffer = "<replacement>new</replacement>";
    // SAFETY: handles are validated by each call; the document is freed once.
    unsafe {
        let doc = xmlSecParseMemory(xml.as_ptr(), xml.len(), 1);
        assert!(!doc.is_null(), "the document parses");
        let old = xsDocGetRootElement(doc);
        assert_eq!(
            xmlSecReplaceNodeBufferAndReturn(
                old,
                buffer.as_ptr(),
                buffer.len(),
                std::ptr::null_mut()
            ),
            0
        );
        let root = xsDocGetRootElement(doc);
        assert_eq!(nodes::name(root).as_deref(), Some("replacement"));
        assert_eq!(nodes::content(root).as_deref(), Some("new"));
        xsFreeDoc(doc);
    }
}

#[test]
fn a_buffer_replaces_a_node_in_the_namespaces_of_its_parent() {
    // libxml2 parses the buffer in the context of the node's parent, so a
    // prefix declared there is bound in the replacement.
    let xml = r#"<r xmlns:p="urn:p"><old/></r>"#;
    let buffer = "<p:a>1</p:a><b/>";
    // SAFETY: handles are validated by each call; the replaced node and the
    // document are freed once.
    unsafe {
        let doc = xmlSecParseMemory(xml.as_ptr(), xml.len(), 1);
        assert!(!doc.is_null(), "the document parses");
        let root = xsDocGetRootElement(doc);
        let old = nodes::first_child(root);
        let mut replaced: *mut XmlNode = std::ptr::null_mut();
        assert_eq!(
            xmlSecReplaceNodeBufferAndReturn(old, buffer.as_ptr(), buffer.len(), &raw mut replaced),
            0
        );
        assert_eq!(replaced, old);
        assert!(nodes::parent(old).is_null());
        let first = nodes::first_child(root);
        assert_eq!(nodes::namespace(first).as_deref(), Some("urn:p"));
        assert_eq!(nodes::name(nodes::next(first)).as_deref(), Some("b"));
        xsFreeNode(old);
        let unbound = "<q:a/>";
        assert_eq!(
            xmlSecReplaceNodeBufferAndReturn(
                first,
                unbound.as_ptr(),
                unbound.len(),
                std::ptr::null_mut()
            ),
            -1,
            "an unbound prefix is refused"
        );
        xsFreeDoc(doc);
    }
}
