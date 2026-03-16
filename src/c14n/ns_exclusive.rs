//! Exclusive namespace rendering for Exclusive C14N 1.0.
//!
//! In exclusive mode, only **visibly utilized** namespace prefixes are emitted
//! on each element (plus any prefixes forced by the InclusiveNamespaces PrefixList).

use std::collections::{HashMap, HashSet};

use roxmltree::Node;

use super::ns_common::collect_ns_declarations;
use super::prefix::{attribute_prefix, element_prefix};
use super::serialize::NsRenderer;

/// Exclusive C14N namespace renderer.
///
/// Only emits namespace declarations for prefixes that are visibly utilized
/// by the element's tag name or attributes, plus any forced prefixes from
/// the `InclusiveNamespaces PrefixList`.
pub(crate) struct ExclusiveNsRenderer<'a> {
    inclusive_prefixes: &'a HashSet<String>,
}

impl<'a> ExclusiveNsRenderer<'a> {
    pub(crate) fn new(inclusive_prefixes: &'a HashSet<String>) -> Self {
        Self { inclusive_prefixes }
    }
}

impl NsRenderer for ExclusiveNsRenderer<'_> {
    fn render_namespaces<'n>(
        &self,
        node: Node<'n, '_>,
        parent_rendered: &HashMap<String, String>,
    ) -> (Vec<(String, String)>, HashMap<String, String>) {
        let utilized = visibly_utilized_prefixes(node);
        // Exclusive mode: only visibly-utilized prefixes and forced prefixes
        // from InclusiveNamespaces PrefixList are candidates.
        collect_ns_declarations(node, parent_rendered, |prefix, _| {
            utilized.contains(prefix) || self.inclusive_prefixes.contains(prefix)
        })
    }
}

/// Determine which namespace prefixes are visibly utilized by an element.
///
/// A prefix is visibly utilized if:
/// 1. The element's tag name uses that prefix, OR
/// 2. Any attribute on the element uses that prefix.
///
/// Uses lexical prefixes extracted from source XML byte positions,
/// avoiding ambiguity when multiple prefixes bind the same namespace URI.
fn visibly_utilized_prefixes<'a>(node: Node<'a, '_>) -> HashSet<&'a str> {
    let mut utilized = HashSet::new();

    // Element's own lexical prefix from source XML.
    let el_prefix = element_prefix(node);
    if !el_prefix.is_empty() {
        utilized.insert(el_prefix);
    } else {
        // Unprefixed element relies on the current default-namespace binding
        // (including xmlns="" undeclaration), so the default namespace is
        // visibly utilized. This ensures xmlns="" is emitted when needed
        // to undeclare an inherited default namespace in exclusive C14N.
        utilized.insert("");
    }

    // Attribute lexical prefixes from source XML.
    for attr in node.attributes() {
        let attr_prefix = attribute_prefix(node, &attr);
        if !attr_prefix.is_empty() {
            utilized.insert(attr_prefix);
        }
    }

    utilized
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::serialize::serialize_canonical;
    use super::*;
    use roxmltree::Document;
    use std::collections::HashSet;

    fn exc_c14n(xml: &str, prefix_list: &HashSet<String>) -> String {
        let doc = Document::parse(xml).expect("parse");
        let renderer = ExclusiveNsRenderer::new(prefix_list);
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, false, &mut out).expect("c14n");
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn only_utilized_ns_rendered() {
        let xml = r#"<root xmlns:a="http://a.com" xmlns:b="http://b.com"><a:child/></root>"#;
        let result = exc_c14n(xml, &HashSet::new());
        // root uses no prefix → no ns decls on root.
        // a:child uses a: → xmlns:a on child.
        // b: is not utilized anywhere → not rendered.
        assert!(!result.contains("xmlns:b"));
        assert!(result.contains(r#"<a:child xmlns:a="http://a.com">"#));
    }

    #[test]
    fn forced_prefix_via_prefix_list() {
        let xml = r#"<root xmlns:a="http://a.com" xmlns:b="http://b.com"><child/></root>"#;
        let mut forced = HashSet::new();
        forced.insert("b".to_string());
        let result = exc_c14n(xml, &forced);
        // b: is forced via PrefixList → should appear on root.
        assert!(result.contains(r#"xmlns:b="http://b.com""#));
    }

    #[test]
    fn sibling_elements_redeclare() {
        let xml = r#"<root xmlns:a="http://a.com"><a:one/><a:two/></root>"#;
        let result = exc_c14n(xml, &HashSet::new());
        // In exclusive mode, each sibling must independently declare a:.
        assert!(result.contains(r#"<a:one xmlns:a="http://a.com">"#));
        assert!(result.contains(r#"<a:two xmlns:a="http://a.com">"#));
    }

    #[test]
    fn default_ns_utilized() {
        let xml = r#"<root xmlns="http://example.com"><child/></root>"#;
        let result = exc_c14n(xml, &HashSet::new());
        // Both root and child use the default ns.
        assert!(result.contains(r#"<root xmlns="http://example.com">"#));
        // child inherits → parent already rendered → not redeclared.
        assert_eq!(
            result,
            r#"<root xmlns="http://example.com"><child></child></root>"#
        );
    }

    #[test]
    fn unprefixed_element_undeclares_default_ns() {
        // child undeclares default ns with xmlns="". In exclusive C14N,
        // the default namespace must be visibly utilized so xmlns="" is emitted.
        let xml = r#"<root xmlns="http://example.com"><child xmlns=""/></root>"#;
        let result = exc_c14n(xml, &HashSet::new());
        assert!(
            result.contains(r#"<child xmlns="">"#),
            "xmlns=\"\" must be emitted for undeclaration. Got: {result}"
        );
    }
}
