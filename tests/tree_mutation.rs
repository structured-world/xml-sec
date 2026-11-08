//! Mutations of a tree-backed document change the tree itself, keep the nodes
//! they do not touch, and leave nothing behind when they fail.

#![cfg(all(feature = "external-tree", feature = "xmldsig-sign"))]

#[path = "support/model_tree.rs"]
mod model_tree;

use model_tree::ModelTree;
use xml_sec::document::external::ExternalNode;
use xml_sec::policy::VerificationPolicy;
use xml_sec::{NodeIdentity, XmlDocument, XmlDocumentError};

const XML: &str = concat!(
    r#"<root xmlns="urn:root" xmlns:p="urn:p">"#,
    r#"<first Id="first">one</first><p:second Id="second"><keep/></p:second>"#,
    "<third Id=\"third\"/></root>"
);

fn document(tree: &ModelTree) -> XmlDocument {
    XmlDocument::from_external_tree(Box::new(tree.clone()), &VerificationPolicy::default())
        .expect("the tree projects")
}

fn node(document: &XmlDocument, id: &str) -> NodeIdentity {
    document
        .with_view(|view| view.node_for_id(id, &[]))
        .expect("the element is present")
}

/// The references of every node except those in `changed`.
fn untouched(before: &[ExternalNode], changed: &[ExternalNode]) -> Vec<ExternalNode> {
    before
        .iter()
        .copied()
        .filter(|node| !changed.contains(node))
        .collect()
}

#[test]
fn replacing_an_element_changes_the_tree_and_keeps_every_other_node() {
    // In place: the caller's untouched nodes stay the same nodes, and the
    // new generation is read from the tree, not from a serialization.
    let tree = ModelTree::parse(XML);
    let mut document = document(&tree);
    let before = tree.nodes();
    let first = tree.element("first");
    let first_text = before[before
        .iter()
        .position(|&node| node == first)
        .expect("listed")
        + 1];
    let target = node(&document, "first");
    document
        .replace_element(target, "<first Id=\"first\" state=\"new\">two</first>")
        .expect("the element is replaced");
    assert_eq!(
        tree.to_xml(),
        concat!(
            r#"<root xmlns="urn:root" xmlns:p="urn:p">"#,
            r#"<first Id="first" state="new">two</first><p:second Id="second"><keep></keep></p:second>"#,
            "<third Id=\"third\"></third></root>"
        )
    );
    let after = tree.nodes();
    for kept in untouched(&before, &[first, first_text]) {
        assert!(after.contains(&kept), "{kept:?} was replaced");
    }
    assert!(!after.contains(&first));
    // The replaced element took the namespace of its context.
    document.with_view(|view| {
        let replaced = view
            .document()
            .root_element()
            .first_element_child()
            .expect("the replacement is the first child");
        assert_eq!(replaced.tag_name().namespace(), Some("urn:root"));
        assert_eq!(replaced.attribute("state"), Some("new"));
    });
    assert_eq!(
        tree.pending_undo(),
        0,
        "a committed edit keeps no undo records"
    );
}

#[test]
fn an_identity_of_the_replaced_generation_is_stale() {
    let tree = ModelTree::parse(XML);
    let mut document = document(&tree);
    let third = node(&document, "third");
    let first = node(&document, "first");
    document
        .replace_content(first, "changed")
        .expect("the content is replaced");
    assert!(matches!(
        document.replace_content(third, "x"),
        Err(XmlDocumentError::StaleIdentity { .. })
    ));
}

#[test]
fn every_edit_kind_reaches_the_tree() {
    let tree = ModelTree::parse(XML);
    let mut document = document(&tree);
    let second = node(&document, "second");
    document
        .insert_before(second, "<!--before-->")
        .expect("a comment is inserted");
    let third = node(&document, "third");
    document
        .append_child(third, "<p:added>text</p:added>")
        .expect("a child is appended");
    let first = node(&document, "first");
    document
        .replace_node_with_fragment(first, "a<b/>c")
        .expect("the element becomes a fragment");
    assert_eq!(
        tree.to_xml(),
        concat!(
            r#"<root xmlns="urn:root" xmlns:p="urn:p">"#,
            r#"a<b></b>c<!--before--><p:second Id="second"><keep></keep></p:second>"#,
            r#"<third Id="third"><p:added>text</p:added></third></root>"#
        )
    );
    // The fragment declares nothing its context already binds.
    assert!(!tree.to_xml().contains("p:added xmlns"));
}

#[test]
fn several_contents_change_as_one_generation() {
    let tree = ModelTree::parse(XML);
    let mut document = document(&tree);
    let generation = document.generation();
    let first = node(&document, "first");
    let third = node(&document, "third");
    document
        .replace_contents(&[(first, "1".into()), (third, "<x/>".into())])
        .expect("both contents are replaced");
    assert_eq!(document.generation(), generation + 1);
    assert!(tree.to_xml().contains("<first Id=\"first\">1</first>"));
    assert!(
        tree.to_xml()
            .contains("<third Id=\"third\"><x></x></third>")
    );
}

#[test]
fn an_invalid_fragment_leaves_the_tree_and_generation_unchanged() {
    // Validation runs before the first link changes the tree.
    let tree = ModelTree::parse(XML);
    let mut document = document(&tree);
    let before = tree.to_xml();
    let first = node(&document, "first");
    let error = document
        .replace_element(first, "<first><unclosed></first>")
        .expect_err("a malformed fragment is refused");
    assert!(matches!(error, XmlDocumentError::Parse(_)), "{error}");
    let error = document
        .replace_element(first, "<a/><b/>")
        .expect_err("two elements are not one element");
    assert!(
        matches!(error, XmlDocumentError::InvalidReplacement(_)),
        "{error}"
    );
    let error = document
        .append_child(first, "<q:x/>")
        .expect_err("an unbound prefix is refused in context");
    assert!(matches!(error, XmlDocumentError::Parse(_)), "{error}");
    assert_eq!(tree.to_xml(), before);
    assert_eq!(document.generation(), 0);
    // The identity is still current: nothing was committed.
    document.replace_content(first, "ok").expect("still valid");
}

#[test]
fn a_tree_backed_document_has_no_serialization_to_return() {
    // Signing that returns signed text needs a serialization; a tree's
    // signature is committed into the tree instead.
    let tree =
        ModelTree::parse(r#"<root><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/></root>"#);
    let document = document(&tree);
    let key = xml_sec::xmldsig::HmacSigningKey::new(vec![7; 32]).expect("a key");
    let error = xml_sec::xmldsig::SignContext::new(&key)
        .sign_template_document(document)
        .expect_err("there is no text to return");
    assert!(
        error.to_string().contains("tree"),
        "the refusal names the tree: {error}"
    );
}

#[test]
fn a_failed_transaction_rolls_the_tree_back() {
    // Every commit inside the transaction changed the tree; failure undoes
    // all of them, newest first.
    let tree = ModelTree::parse(XML);
    let mut document = document(&tree);
    let before = tree.to_xml();
    let nodes = tree.nodes();
    let result: Result<(), &str> = document.transaction(|document| {
        let first = node(document, "first");
        document.replace_content(first, "changed").expect("commits");
        let third = node(document, "third");
        document.append_child(third, "<x/>").expect("commits");
        Err("abandon")
    });
    assert_eq!(result, Err("abandon"));
    assert_eq!(tree.to_xml(), before);
    assert_eq!(tree.nodes(), nodes);
    assert_eq!(document.generation(), 0);
    assert_eq!(tree.pending_undo(), 0);
}

#[test]
fn a_successful_transaction_carries_untouched_elements() {
    // carry maps an element the commits did not replace through its tree
    // node; the replaced one is gone.
    let tree = ModelTree::parse(XML);
    let mut document = document(&tree);
    let start_third = node(&document, "third");
    let start_first = node(&document, "first");
    document
        .transaction(|document| {
            let first = node(document, "first");
            document
                .replace_element(first, "<first Id=\"first\"/>")
                .expect("commits");
            let carried = document.carry(start_third).expect("third is untouched");
            assert_eq!(carried, node(document, "third"));
            assert!(matches!(
                document.carry(start_first),
                Err(XmlDocumentError::MissingNode)
            ));
            Ok::<(), XmlDocumentError>(())
        })
        .expect("the transaction succeeds");
    assert_eq!(
        tree.pending_undo(),
        0,
        "the outermost success releases the records"
    );
}
