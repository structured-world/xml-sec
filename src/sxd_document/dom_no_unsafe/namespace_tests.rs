use super::super::Package;

#[test]
fn a_prefix_rebound_by_a_nearer_element_is_not_reported_for_its_outer_uri() {
    // Namespaces 1.0 section 6.1: a declaration's scope ends where a nearer
    // element rebinds its prefix, so below that element the prefix names
    // only the new URI and the outer URI has no prefix in scope.
    // https://www.w3.org/TR/xml-names/#scoping
    let package = Package::new();
    let doc = package.as_document();
    let parent = doc.create_element("parent");
    parent.register_prefix("p", "urn:outer");
    let child = doc.create_element("child");
    child.register_prefix("p", "urn:inner");
    parent.append_child(child);
    assert_eq!(child.prefix_for_namespace_uri("urn:outer", None), None);
    assert_eq!(
        child.prefix_for_namespace_uri("urn:inner", None).as_deref(),
        Some("p")
    );
    // Another prefix still bound to the outer URI is the one reported.
    parent.register_prefix("q", "urn:outer");
    assert_eq!(
        child
            .prefix_for_namespace_uri("urn:outer", Some("p"))
            .as_deref(),
        Some("q")
    );
    // Above the rebinding the outer binding is in scope.
    assert_eq!(
        parent
            .prefix_for_namespace_uri("urn:outer", Some("p"))
            .as_deref(),
        Some("p")
    );
}
