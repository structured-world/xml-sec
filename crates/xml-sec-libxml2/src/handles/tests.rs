use xml_sec::document::owned_tree::OwnedTree;
use xml_sec::policy::VerificationPolicy;

use super::*;

fn register_xml(xml: &str) -> usize {
    let tree = OwnedTree::parse_with_policy(xml, &VerificationPolicy::default())
        .expect("the document parses");
    register(tree).expect("a handle")
}

fn root(doc: usize) -> usize {
    let slot = document(doc).expect("a live document");
    let element = read(doc, |tree, _| tree.root_element())
        .expect("a live document")
        .expect("a document element");
    handle(slot, Target::Node(element)).expect("a live node")
}

#[test]
fn one_node_always_yields_the_same_handle() {
    // C code compares node pointers for identity.
    let doc = register_xml("<r/>");
    assert_eq!(root(doc), root(doc));
    assert_ne!(root(doc), doc);
}

#[test]
fn a_freed_node_and_a_forged_value_are_refused() {
    let doc = register_xml("<r><c/></r>");
    let slot = document(doc).expect("a live document");
    let child = read(root(doc), OwnedTree::first_child)
        .expect("a live node")
        .expect("a live node")
        .expect("a child");
    let child = handle(slot, Target::Node(child)).expect("a live node");
    edit(child, OwnedTree::free).expect("a live node");
    assert_eq!(resolve(child), Err(HandleError::Stale));
    assert_eq!(resolve(usize::MAX), Err(HandleError::Stale));
}

#[test]
fn declaration_and_attribute_handles_end_with_what_they_name() {
    let doc = register_xml(r#"<r xmlns:p="urn:p" a="v"/>"#);
    let slot = document(doc).expect("a live document");
    let element = node(root(doc)).expect("a node").1;
    let declaration = handle(
        slot,
        Target::Namespace {
            element,
            prefix: Some(String::from("p")),
        },
    )
    .expect("a declared prefix");
    let attribute = handle(
        slot,
        Target::Attribute {
            element,
            name: String::from("a"),
            namespace: None,
        },
    )
    .expect("a present attribute");
    // A node handle is refused where a node is needed but a declaration given.
    assert_eq!(node(declaration), Err(HandleError::WrongKind));
    edit(root(doc), |tree, element| {
        tree.remove_attribute(element, "a", None).map(drop)
    })
    .expect("a live element");
    assert_eq!(resolve(attribute), Err(HandleError::Stale));
    assert!(resolve(declaration).is_ok());
    // A target that does not exist gets no handle.
    assert_eq!(
        handle(
            slot,
            Target::Namespace {
                element,
                prefix: Some(String::from("q")),
            },
        ),
        Err(HandleError::Stale)
    );
}

#[test]
fn a_lent_document_is_busy_until_its_tree_comes_back() {
    let doc = register_xml("<r/>");
    let element = root(doc);
    let (slot, tree) = lend(doc).expect("a live document");
    assert_eq!(resolve(element), Err(HandleError::Busy));
    give_back(slot, tree).expect("the slot waits for its tree");
    assert!(resolve(element).is_ok());
}

#[test]
fn freeing_a_document_ends_every_handle_into_it() {
    let doc = register_xml("<r/>");
    let element = root(doc);
    free_document(doc).expect("a live document");
    assert_eq!(resolve(doc), Err(HandleError::Stale));
    assert_eq!(resolve(element), Err(HandleError::Stale));
    // A new document never reuses an old value.
    let other = register_xml("<s/>");
    assert_ne!(other, doc);
    assert_ne!(root(other), element);
}
