use super::*;
use crate::nodes::pointer_of;

/// The owned tree keeps documents whichever backend a build selects: a
/// build with only roxmltree parses tree documents and keeps roxmltree as
/// the backend of the clean C API.
#[cfg(all(
    feature = "xml-backend-roxmltree",
    not(feature = "xml-backend-xmloxide")
))]
#[test]
fn the_tree_leaves_the_selected_backend_alone() {
    assert_eq!(
        xml_sec::XmlBackend::default(),
        xml_sec::XmlBackend::Roxmltree
    );
    assert!(!xml_sec::XmlBackend::Xmloxide.is_available());
    let doc = parse(b"<r/>").expect("a tree document parses");
    handles::free_document(doc).expect("the document can be freed");
}

#[test]
fn a_utf16_document_parses() {
    // XML 1.0 section 4.3.3: every processor reads UTF-16; the byte-order
    // mark selects it.
    let mut bytes = vec![0xFF, 0xFE];
    for unit in "<r>\u{e9}</r>".encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let doc = parse(&bytes).expect("a UTF-16 document parses");
    let text = handles::read(doc, |tree, _| {
        let root = tree.root_element().expect("a document element");
        tree.text_content(root).expect("a live node")
    })
    .expect("a live document");
    assert_eq!(text, "\u{e9}");
}

#[test]
fn parts_too_large_together_are_the_document_limit_violation() {
    // Each part fits the limit; together they do not, and the refusal names
    // the combined length.
    let maximum = crate::policy::library()
        .expect("the library policy")
        .resources
        .max_xml_document_bytes;
    let half = vec![b' '; maximum / 2 + 1];
    let refused = parse_parts(&[&half, &half, b"<r/>"]);
    assert!(matches!(
        refused,
        Err(DocumentError::Document(XmlDocumentError::Policy(
            xml_sec::policy::PolicyViolation::ResourceLimit { actual, .. }
        ))) if actual == 2 * half.len() + 4
    ));
    // Parts that fit are parsed in sequence.
    let doc = parse_parts(&[b"<r>", b"t", b"</r>"]).expect("the parts parse");
    let text = handles::read(doc, |tree, _| {
        tree.text_content(tree.root_element().expect("a document element"))
            .expect("a live node")
    })
    .expect("a live document");
    assert_eq!(text, "t");
}

#[test]
fn a_panicking_operation_gives_the_tree_back() {
    // Every exported function catches a panic; the document it unwinds out
    // of must stay usable and freeable.
    let doc = parse(b"<r/>").expect("the document parses");
    let policy = crate::policy::library().expect("the library policy");
    let node = pointer_of::<u8>(doc).cast_const();
    let unwound = std::panic::catch_unwind(|| {
        with_document(node, policy, |_, _| -> () { panic!("an operation fails") })
    });
    assert!(unwound.is_err());
    assert!(
        handles::resolve(doc).is_ok(),
        "the tree is back in its slot"
    );
    handles::free_document(doc).expect("the document can be freed");
}
