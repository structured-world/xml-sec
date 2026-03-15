//! Exclusive namespace rendering for Exclusive C14N 1.0.
//!
//! In exclusive mode, only **visibly utilized** namespace prefixes are emitted
//! on each element (plus any prefixes forced by the InclusiveNamespaces PrefixList).

use std::collections::{HashMap, HashSet};

use roxmltree::Node;

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
        // Clone is O(n) per element. Acceptable for typical XML depths (<20 levels).
        // Optimization: pass &mut and restore on backtrack — deferred to perf phase.
        let mut rendered = parent_rendered.clone();
        let mut decls: Vec<(String, String)> = Vec::new();

        for ns in node.namespaces() {
            let prefix = ns.name().unwrap_or("");
            let uri = ns.uri();

            // The `xml` prefix is never declared.
            if prefix == "xml" {
                continue;
            }

            // Include if visibly utilized OR in the forced prefix list.
            let dominated = utilized.contains(prefix) || self.inclusive_prefixes.contains(prefix);
            if !dominated {
                continue;
            }

            // Only render if different from nearest output ancestor.
            if parent_rendered.get(prefix).map(|s| s.as_str()) == Some(uri) {
                continue;
            }

            // Don't emit xmlns="" if no default ns was in scope.
            if prefix.is_empty() && uri.is_empty() && !parent_rendered.contains_key("") {
                continue;
            }

            decls.push((prefix.to_string(), uri.to_string()));
        }

        // Sort by prefix.
        decls.sort_by(|a, b| a.0.cmp(&b.0));

        for (prefix, uri) in &decls {
            rendered.insert(prefix.clone(), uri.clone());
        }

        (decls, rendered)
    }
}

/// Determine which namespace prefixes are visibly utilized by an element.
///
/// A prefix is visibly utilized if:
/// 1. The element's tag name uses that prefix, OR
/// 2. Any attribute on the element uses that prefix.
// NOTE: roxmltree does not expose the lexical prefix from parsed QNames.
// We reverse-map via lookup_prefix(namespace_uri). This is ambiguous when
// multiple prefixes bind the same URI (e.g., xmlns:a="u" xmlns:b="u").
// In practice this is extremely rare in SAML/XMLDSig documents.
// A proper fix requires a parser that preserves lexical prefixes.
fn visibly_utilized_prefixes<'a>(node: Node<'a, '_>) -> HashSet<&'a str> {
    let mut utilized = HashSet::new();

    // Element's own prefix (reverse-mapped from namespace URI).
    if let Some(ns_uri) = node.tag_name().namespace() {
        match node.lookup_prefix(ns_uri) {
            Some(prefix) if !prefix.is_empty() => {
                utilized.insert(prefix);
            }
            _ if !ns_uri.is_empty() => {
                // Element uses default namespace.
                utilized.insert("");
            }
            _ => {}
        }
    }

    // Attribute prefixes.
    for attr in node.attributes() {
        if let Some(ns_uri) = attr.namespace() {
            if let Some(prefix) = node.lookup_prefix(ns_uri) {
                if !prefix.is_empty() {
                    utilized.insert(prefix);
                }
            }
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
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
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
}
