use std::collections::BTreeSet;
use std::sync::Arc;

use super::{
    DOCUMENT_ELEMENT, DOCUMENTS_ELEMENT, Meter, Namespace, ProjectedSlots, changed_bindings,
    project_semantic_document,
};
use crate::{Document, ExecutionBudget, NodeKind};
use sxd_document_no_unsafe::dom::{ChildOfElement, ChildOfRoot, Element};

fn unlimited() -> ExecutionBudget {
    ExecutionBudget {
        source_bytes: usize::MAX,
        external_documents: usize::MAX,
        recursion_depth: usize::MAX,
        xpath_evaluations: usize::MAX,
        xpath_operations: usize::MAX,
        extension_operations: usize::MAX,
        pattern_evaluations: usize::MAX,
        template_applications: usize::MAX,
        sort_comparisons: usize::MAX,
        key_entries: usize::MAX,
        result_nodes: usize::MAX,
        serialized_bytes: usize::MAX,
        messages: usize::MAX,
        owned_bytes: usize::MAX,
    }
}

fn namespace(prefix: Option<&str>, uri: &str) -> Namespace {
    Namespace {
        prefix: prefix.map(Into::into),
        uri: uri.into(),
    }
}

/// The projected source elements in document order, wrappers skipped.
fn elements<'d>(element: Element<'d>, into: &mut Vec<Element<'d>>) {
    let name = element.name();
    let local = sxd_document_no_unsafe::as_qname!(name)
        .local_part()
        .to_owned();
    if local != DOCUMENTS_ELEMENT && local != DOCUMENT_ELEMENT {
        into.push(element);
    }
    for child in element.children() {
        if let ChildOfElement::Element(child) = child {
            elements(child, into);
        }
    }
}

#[test]
fn projected_elements_see_the_bindings_their_source_has_in_scope() {
    // The projection writes only the bindings an element changes, and every
    // reader resolves the rest through the ancestors, so each projected
    // element must see exactly its source element's in-scope list: rebound
    // prefixes, an undeclared default namespace and inherited bindings.
    let xml = concat!(
        r#"<a xmlns="urn:d" xmlns:p="urn:p1">"#,
        r#"<b xmlns:p="urn:p2" xmlns:q="urn:q"><c xmlns=""><d/></c></b>"#,
        r#"<e/></a>"#
    );
    let source = Document::parse(xml, None).expect("source parses");
    let mut meter = Meter::new(unlimited(), 0).expect("meter initializes");
    let mut slots = ProjectedSlots::default();
    let package =
        project_semantic_document(&source, &mut slots, &mut meter).expect("source projects");
    let document = package.as_document();
    let mut projected = Vec::new();
    for child in document.root().children() {
        if let ChildOfRoot::Element(element) = child {
            elements(element, &mut projected);
        }
    }
    let sources: Vec<_> = source
        .nodes()
        .filter_map(|(_, node)| match &node.kind {
            NodeKind::Element { namespaces, .. } => Some(namespaces),
            _ => None,
        })
        .collect();
    assert_eq!(projected.len(), sources.len());
    for (element, namespaces) in projected.iter().zip(&sources) {
        let expected: BTreeSet<(String, String)> = namespaces
            .iter()
            .map(|binding| {
                (
                    binding.prefix.clone().unwrap_or_default(),
                    binding.uri.clone(),
                )
            })
            .collect();
        let seen: BTreeSet<(String, String)> = element
            .namespaces_in_scope()
            .iter()
            .map(|binding| (binding.prefix().to_owned(), binding.uri().to_owned()))
            .collect();
        assert_eq!(seen, expected, "{:?}", element.name());
        for binding in namespaces.iter() {
            let resolved = match &binding.prefix {
                None => element.recursive_default_namespace_uri(),
                Some(prefix) => element.namespace_uri_for_prefix(prefix),
            };
            assert_eq!(resolved.as_deref(), Some(binding.uri.as_str()));
        }
    }
    // `d` and `e` declare nothing, so nothing is projected onto them.
    for element in &projected[3..] {
        assert_eq!(element.namespace_declaration_workspace_bytes(), 0);
    }
}

#[test]
fn bindings_are_projected_whole_unless_they_line_up_with_the_parent() {
    // Only a list that extends its parent's position by position may be
    // reduced to its changes; another order, or none to compare with,
    // projects every binding.
    let parent = Arc::new(vec![
        namespace(Some("xml"), "http://www.w3.org/XML/1998/namespace"),
        namespace(Some("p"), "urn:p1"),
    ]);
    let changed = |own: &Arc<Vec<Namespace>>, inherited| {
        changed_bindings(own, inherited)
            .map(|binding| (binding.prefix.clone(), binding.uri.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(changed(&parent, Some(&parent)), []);
    let extended = Arc::new(vec![
        namespace(Some("xml"), "http://www.w3.org/XML/1998/namespace"),
        namespace(Some("p"), "urn:p2"),
        namespace(None, "urn:d"),
    ]);
    assert_eq!(
        changed(&extended, Some(&parent)),
        [(Some("p".into()), "urn:p2".into()), (None, "urn:d".into())]
    );
    let reordered = Arc::new(vec![
        namespace(Some("p"), "urn:p1"),
        namespace(Some("xml"), "http://www.w3.org/XML/1998/namespace"),
    ]);
    assert_eq!(changed(&reordered, Some(&parent)).len(), 2);
    assert_eq!(changed(&parent, None).len(), 2);
}
