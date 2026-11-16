use super::{XmlDocument, XmlDocumentError};

#[test]
fn identity_of_names_an_element_without_an_id() {
    // An element that carries no ID is reached by walking the view's tree; its
    // identity resolves to the same node and serves as request data.
    let document = XmlDocument::parse("<root><ring><value>1</value></ring><other/></root>")
        .expect("the test document parses");
    document.with_view(|view| {
        let ring = view
            .document()
            .root_element()
            .first_element_child()
            .expect("the root has a child element");
        let identity = view
            .identity_of(ring)
            .expect("the node belongs to the view");
        assert_ne!(identity, view.root_element());
        let resolved = view
            .resolve_node(identity)
            .expect("the identity resolves in its own generation");
        assert_eq!(resolved.tag_name().name(), "ring");
        assert_eq!(resolved.id(), ring.id());
    });
}

#[test]
fn identity_of_refuses_a_node_of_another_document() {
    // A node of another tree would otherwise borrow this view's document and
    // generation and name an unrelated node with the same position.
    let first = XmlDocument::parse("<root><a/></root>").expect("the first document parses");
    let second = XmlDocument::parse("<root><a/></root>").expect("the second document parses");
    first.with_view(|outer| {
        let foreign = outer
            .document()
            .root_element()
            .first_element_child()
            .expect("the root has a child element");
        second.with_view(|inner| {
            assert!(matches!(
                inner.identity_of(foreign),
                Err(XmlDocumentError::ForeignIdentity)
            ));
        });
    });
}
