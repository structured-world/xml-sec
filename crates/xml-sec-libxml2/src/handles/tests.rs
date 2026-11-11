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

#[test]
fn work_on_one_document_does_not_hold_up_another() {
    // A projection or edit holds its own document only: another thread reads
    // a second document meanwhile.
    let first = document(register_xml("<a/>")).expect("a live document");
    let second = document(register_xml("<b/>")).expect("a live document");
    let (done, waiting) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        read_document(second, |tree| tree.root_element().is_some()).expect("a live document");
        done.send(()).expect("the first thread waits");
    });
    let answered = read_document(first, |_| {
        waiting.recv_timeout(std::time::Duration::from_secs(5))
    })
    .expect("a live document");
    reader.join().expect("the reader finishes");
    assert!(answered.is_ok(), "the second document was read meanwhile");
}

#[test]
fn a_freed_documents_slot_never_names_a_later_document() {
    // A clean C API document keeps the slot; once its document is freed, a
    // later document must not answer for it.
    let doc = register_xml("<r/>");
    let slot = document(doc).expect("a live document");
    free_document(doc).expect("a live document");
    let other = register_xml("<s/>");
    assert_ne!(document(other), Ok(slot));
    assert_eq!(read_document(slot, |_| ()), Err(HandleError::Stale));
}

#[test]
fn an_edit_drops_only_the_handles_of_what_it_removed() {
    // Removing an attribute ends its handle; a node handle of the same
    // document and every handle of another document stay.
    let doc = register_xml(r#"<r a="v"><c/></r>"#);
    let other = register_xml(r#"<s a="v"/>"#);
    let slot = document(doc).expect("a live document");
    let other_slot = document(other).expect("a live document");
    let element = node(root(doc)).expect("a node").1;
    let attribute = |slot, element| {
        handle(
            slot,
            Target::Attribute {
                element,
                name: String::from("a"),
                namespace: None,
            },
        )
        .expect("a present attribute")
    };
    let mine = attribute(slot, element);
    let theirs = attribute(other_slot, node(root(other)).expect("a node").1);
    let child = read(root(doc), OwnedTree::first_child)
        .expect("a live node")
        .expect("a live node")
        .expect("a child");
    let child = handle(slot, Target::Node(child)).expect("a live node");
    edit(root(doc), |tree, element| {
        tree.remove_attribute(element, "a", None).map(drop)
    })
    .expect("a live element");
    assert_eq!(resolve(mine), Err(HandleError::Stale));
    assert!(resolve(theirs).is_ok());
    assert!(resolve(child).is_ok());
}
