//! [`XmlDocument::carry`]: node identities across the commits of a transaction.

use super::{DocumentView, NodeIdentity, XmlDocument, XmlDocumentError, carried_range};

fn root(view: DocumentView<'_>) -> NodeIdentity {
    view.root_element()
}

/// The identity of the element with ID `id` in the current generation.
fn element(document: &XmlDocument, id: &str) -> NodeIdentity {
    document.with_view(|view| view.node_for_id(id, &[]).expect("element has its ID"))
}

const DOCUMENT: &str = "<root Id=\"root\"><before Id=\"before\"/><parent Id=\"parent\"><x Id=\"x\"/></parent><after Id=\"after\">text</after></root>";

#[test]
fn elements_outside_or_around_the_change_keep_their_identity() {
    // An element before, after or around every changed byte is the same
    // element in the new generation, which a check inside the transaction
    // needs to hold the caller's node requirements for it.
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let ids = ["root", "before", "parent", "x", "after"];
    let original: Vec<NodeIdentity> = ids.iter().map(|id| element(&document, id)).collect();
    document
        .transaction(|document| {
            let parent = element(document, "parent");
            document.append_child(parent, "<new Id=\"new\"/>")?;
            for (id, identity) in ids.iter().zip(&original) {
                assert_eq!(document.carry(*identity)?, element(document, id), "{id}");
            }
            Ok::<_, XmlDocumentError>(())
        })
        .expect("transaction succeeds");
}

#[test]
fn identities_carry_across_every_commit_of_the_transaction() {
    // The transaction's starting generation is the one the caller verified;
    // later commits to the same region do not lose the way back to it.
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let (before, after, x) = (
        element(&document, "before"),
        element(&document, "after"),
        element(&document, "x"),
    );
    document
        .transaction(|document| {
            let parent = element(document, "parent");
            document.append_child(parent, "<one/>")?;
            let parent = element(document, "parent");
            document.append_child(parent, "<two/>")?;
            for (id, identity) in [("before", before), ("after", after), ("x", x)] {
                assert_eq!(document.carry(identity)?, element(document, id), "{id}");
            }
            Ok::<_, XmlDocumentError>(())
        })
        .expect("transaction succeeds");
}

#[test]
fn an_element_between_two_separate_changes_is_not_carried() {
    // The commits are compared as one change from the first to the last
    // changed byte; an element between two separate edits falls inside it.
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let parent = element(&document, "parent");
    let result = document.transaction(|document| {
        let before = element(document, "before");
        document.insert_before(before, "<one/>")?;
        let root = document.with_view(root);
        document.append_child(root, "<two/>")?;
        document.carry(parent)
    });
    assert!(
        matches!(result, Err(XmlDocumentError::MissingNode)),
        "{result:?}"
    );
}

#[test]
fn a_replaced_element_has_no_counterpart() {
    // A node inside the changed bytes is not the same node any more, even when
    // the replacement has the same name.
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let x = element(&document, "x");
    let result = document.transaction(|document| {
        document.replace_element(x, "<x Id=\"x\" changed=\"yes\"/>")?;
        document.carry(x)
    });
    assert!(
        matches!(result, Err(XmlDocumentError::MissingNode)),
        "{result:?}"
    );
}

#[test]
fn only_identities_of_a_transaction_start_are_carried() {
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let other = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let current = element(&document, "before");
    // The current generation's own identity is returned unchanged.
    assert_eq!(document.carry(current).expect("current"), current);
    assert!(matches!(
        document.carry(element(&other, "before")),
        Err(XmlDocumentError::ForeignIdentity)
    ));
    let intermediate = document
        .transaction(|document| {
            let first = document.with_view(root);
            document.append_child(first, "<one/>")?;
            let intermediate = element(document, "before");
            let second = document.with_view(root);
            document.append_child(second, "<two/>")?;
            // An intermediate generation is no transaction's start.
            assert!(matches!(
                document.carry(intermediate),
                Err(XmlDocumentError::StaleIdentity { .. })
            ));
            Ok::<_, XmlDocumentError>(intermediate)
        })
        .expect("transaction succeeds");
    // Once the transaction ends, its starting generation is gone with it.
    for stale in [current, intermediate] {
        assert!(matches!(
            document.carry(stale),
            Err(XmlDocumentError::StaleIdentity { .. })
        ));
    }
}

#[test]
fn a_text_node_is_not_carried() {
    let mut document = XmlDocument::parse(DOCUMENT).expect("fixture parses");
    let text = document.with_view(|view| {
        let after = view
            .resolve_node(element(&document, "after"))
            .expect("after");
        view.node_identity(after.first_child().expect("text"))
    });
    let result = document.transaction(|document| {
        let root = document.with_view(root);
        document.append_child(root, "<one/>")?;
        document.carry(text)
    });
    assert!(
        matches!(result, Err(XmlDocumentError::MissingNode)),
        "{result:?}"
    );
}

#[test]
fn an_element_is_placed_by_the_alignment_that_keeps_it_whole() {
    // Appending "<n/>" to r: the prefix-first alignment cuts into r's end tag
    // and the suffix-first one into a's empty tag; each keeps one of them whole.
    let (old, new) = ("<r><a/></r>", "<r><a/><n/></r>");
    assert_eq!(carried_range(old, new, 3..7, None), Some(3..7));
    assert_eq!(carried_range(old, new, 0..11, Some(&(3..7))), Some(0..15));
    // A change inside an empty element's tag leaves no element whole.
    let (old, new) = ("<r><a/><b/><c/></r>", "<r><a/><bb/><c/></r>");
    assert_eq!(carried_range(old, new, 11..15, None), Some(12..16));
    assert_eq!(carried_range(old, new, 7..11, None), None);
    // Identical texts change nothing.
    assert_eq!(carried_range(old, old, 7..11, None), Some(7..11));
}

#[test]
fn of_two_equal_siblings_neither_is_carried() {
    // Inserting "<a/>" next to "<a/>" reads as an insertion before or after
    // it; the original could be either copy.
    let (old, new) = ("<r><a/></r>", "<r><a/><a/></r>");
    assert_eq!(carried_range(old, new, 3..7, None), None);
}
