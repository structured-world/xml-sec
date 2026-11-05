//! [`XmlDocument::insert_before`] and [`DocumentView::has_id`].

use super::{DocumentView, NodeIdentity, XmlDocument, XmlDocumentError};
use crate::IdAttributeRegistration;

fn element(document: &XmlDocument, id: &str) -> NodeIdentity {
    document
        .with_view(|view| view.node_for_id(id, &[]))
        .expect("fixture element has its ID")
}

fn root(view: DocumentView<'_>) -> NodeIdentity {
    view.root_element()
}

#[test]
fn a_fragment_lands_immediately_before_its_target() {
    // The target and everything around it keep their exact bytes; only the
    // fragment is new, and it may hold several nodes and text.
    let mut document =
        XmlDocument::parse("<r><a Id=\"a\"/> <b Id=\"b\" x='1'>t</b></r>").expect("fixture parses");
    let start = document.generation();
    let b = element(&document, "b");
    document
        .insert_before(b, "<n1/>text<n2/>")
        .expect("insertion commits");
    assert_eq!(
        document.as_xml(),
        "<r><a Id=\"a\"/> <n1/>text<n2/><b Id=\"b\" x='1'>t</b></r>"
    );
    assert_eq!(document.generation(), start + 1);
}

#[test]
fn a_fragment_that_breaks_its_context_is_refused_unchanged() {
    // Closing the parent or adding a second document element would change the
    // tree outside the insertion point; the document stays as it was.
    let source = "<r><a Id=\"a\"/></r>";
    for (target, fragment) in [("a", "</r><r>"), ("a", "<open>")] {
        let mut document = XmlDocument::parse(source).expect("fixture parses");
        let node = element(&document, target);
        assert!(
            document.insert_before(node, fragment).is_err(),
            "accepted {fragment:?}"
        );
        assert_eq!(document.as_xml(), source);
        assert_eq!(document.generation(), 0);
    }
    let mut document = XmlDocument::parse(source).expect("fixture parses");
    let root = document.with_view(root);
    assert!(document.insert_before(root, "<second/>").is_err());
    assert_eq!(document.as_xml(), source);
}

#[test]
fn insertion_respects_the_document_size_limit() {
    // The projected size is checked before the target is copied.
    let source = "<r><a Id=\"a\"/></r>";
    let mut document = XmlDocument::parse(source).expect("fixture parses");
    document.settings.max_bytes = source.len() + "<x/>".len();
    let a = element(&document, "a");
    assert!(matches!(
        document.insert_before(a, "<long/>"),
        Err(XmlDocumentError::DocumentTooLarge { maximum, actual })
            if maximum == source.len() + "<x/>".len() && actual == source.len() + "<long/>".len()
    ));
    assert_eq!(document.as_xml(), source);
    document
        .insert_before(a, "<x/>")
        .expect("a fitting fragment inserts");
}

#[test]
fn has_id_counts_every_declaration_including_duplicates() {
    // node_for_id refuses an ambiguous ID; a new ID must still count as taken.
    let document =
        XmlDocument::parse("<r><a Id=\"one\"/><b ID=\"dup\"/><c id=\"dup\"/><d ref=\"x\"/></r>")
            .expect("fixture parses");
    document.with_view(|view| {
        assert!(view.has_id("one", &[]));
        assert!(view.has_id("dup", &[]));
        assert!(view.node_for_id("dup", &[]).is_none());
        assert!(!view.has_id("absent", &[]));
        assert!(!view.has_id("x", &[]));
        assert!(view.has_id("x", &[IdAttributeRegistration::global("ref")]));
    });
}
