//! Accounted original-tree navigation and base64 values for extension formats.

#![cfg(feature = "xmldsig")]

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use xml_sec::XmlDocument;
use xml_sec::document::NodeIdentity;
use xml_sec::xmldsig::extension::{
    NodeView, TreeError, first_child, inspect_node, next_sibling, subtree_contains, with_base64,
};

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)))
}

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    Element(Option<String>, String),
    Text(String),
    Other,
}

fn kind(view: xml_sec::document::DocumentView<'_>, node: NodeIdentity, work: &Memory) -> Kind {
    inspect_node(view, node, work, |value| match value {
        NodeView::Element {
            namespace,
            local_name,
        } => Kind::Element(namespace.map(str::to_owned), local_name.to_owned()),
        NodeView::Text(text) => Kind::Text(text.to_owned()),
        NodeView::Other => Kind::Other,
    })
    .unwrap()
}

fn children(
    view: xml_sec::document::DocumentView<'_>,
    parent: NodeIdentity,
    work: &Memory,
) -> Vec<NodeIdentity> {
    let mut found = Vec::new();
    let mut next = first_child(view, parent, work).unwrap();
    while let Some(node) = next {
        found.push(node);
        next = next_sibling(view, parent, node, work).unwrap();
    }
    found
}

#[test]
fn siblings_follow_document_order_across_deep_subtrees() {
    // The constant-time sibling step skips a whole preorder subtree; it must
    // land on the next child of the same parent, including text and comments,
    // never on a descendant of the previous sibling.
    let document = XmlDocument::parse(
        r#"<r xmlns:p="urn:p"><a><b><c/></b><d/></a>text<!--note--><p:e/><?pi x?></r>"#,
    )
    .unwrap();
    let work = account();
    document.with_view(|view| {
        let root = view.root_element();
        let found = children(view, root, &work);
        let kinds: Vec<_> = found.iter().map(|node| kind(view, *node, &work)).collect();
        assert_eq!(
            kinds,
            [
                Kind::Element(None, "a".into()),
                Kind::Text("text".into()),
                Kind::Other,
                Kind::Element(Some("urn:p".into()), "e".into()),
                Kind::Other,
            ]
        );
        let nested = children(view, found[0], &work);
        assert_eq!(nested.len(), 2);
        assert_eq!(
            kind(view, nested[1], &work),
            Kind::Element(None, "d".into())
        );
        assert!(subtree_contains(view, found[0], nested[1], &work).unwrap());
        assert!(!subtree_contains(view, found[0], found[3], &work).unwrap());
        assert!(subtree_contains(view, root, root, &work).unwrap());
    });
}

#[test]
fn sibling_query_outside_the_parent_is_refused() {
    // A caller pinning the traversal boundary must not continue in another
    // subtree because it supplied a node that is not that parent's child.
    let document = XmlDocument::parse("<r><a><b/></a><c/></r>").unwrap();
    let work = account();
    document.with_view(|view| {
        let root = view.root_element();
        let a = first_child(view, root, &work).unwrap().unwrap();
        let b = first_child(view, a, &work).unwrap().unwrap();
        assert!(matches!(
            next_sibling(view, root, b, &work),
            Err(TreeError::NotChild)
        ));
        assert_eq!(next_sibling(view, a, b, &work).unwrap(), None);
    });
}

#[test]
fn identities_from_another_document_are_refused() {
    let first = XmlDocument::parse("<r><a/></r>").unwrap();
    let second = XmlDocument::parse("<r><a/></r>").unwrap();
    let foreign = first.with_view(|view| view.root_element());
    let work = account();
    second.with_view(|view| {
        assert!(matches!(
            first_child(view, foreign, &work),
            Err(TreeError::Document(_))
        ));
        assert!(matches!(
            inspect_node(view, foreign, &work, |_| ()),
            Err(TreeError::Document(_))
        ));
        assert!(matches!(
            with_base64(view, foreign, &work, |_| ()),
            Err(TreeError::Document(_))
        ));
    });
}

#[test]
fn base64_content_decodes_across_text_and_comment_boundaries() {
    // XML Schema base64Binary admits the four XML whitespace characters; a
    // comment splits text without becoming part of the value.
    let document = XmlDocument::parse("<v> AQID<!--split-->BA==\n</v>").unwrap();
    let work = account();
    document.with_view(|view| {
        let decoded = with_base64(view, view.root_element(), &work, <[u8]>::to_vec).unwrap();
        assert_eq!(decoded, [1, 2, 3, 4]);
    });
    assert_eq!(work.used(), 0, "scoped decode releases its buffer");
}

#[test]
fn malformed_base64_content_is_a_typed_refusal() {
    // Element children, non-canonical padding and foreign characters are not
    // base64Binary; none of them may decode to a truncated value.
    for xml in [
        "<v>AQID<x/></v>",
        "<v>AR==</v>",
        "<v>AQI</v>",
        "<v>AQ\u{a0}ID</v>",
    ] {
        let document = XmlDocument::parse(xml).unwrap();
        let work = account();
        document.with_view(|view| {
            assert!(
                matches!(
                    with_base64(view, view.root_element(), &work, |_| ()),
                    Err(TreeError::Base64(_))
                ),
                "{xml}"
            );
        });
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn base64_work_is_admitted_before_decoding() {
    // Both linear passes are charged before the first byte is scanned, so a
    // short account refuses without allocating the decoded buffer.
    let document = XmlDocument::parse("<v>AAECAwQFBgcICQoLDA0ODw==</v>").unwrap();
    let starved = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 4)));
    document.with_view(|view| {
        assert!(matches!(
            with_base64(view, view.root_element(), &starved, |_| ()),
            Err(TreeError::Resource(MemoryError::WorkExceeded))
        ));
    });
    assert_eq!(starved.used(), 0);
}
