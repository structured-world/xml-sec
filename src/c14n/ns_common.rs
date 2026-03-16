//! Shared namespace-declaration pipeline for C14N.
//!
//! Both inclusive and exclusive canonicalization follow the same pipeline:
//! filter candidates → suppress redundant → suppress spurious `xmlns=""` →
//! sort by prefix → update rendered map. The only difference is the predicate
//! that decides which namespace bindings are candidates for emission.

use std::collections::HashMap;

use roxmltree::Node;

use super::prefix::has_in_scope_default_namespace;

/// Collect, filter, and sort namespace declarations for a single element.
///
/// Walks every in-scope namespace binding reported by roxmltree, applies
/// `include_prefix` to decide whether the binding is a candidate, then runs
/// the shared suppression / sort / map-update pipeline.
///
/// # Arguments
///
/// * `node` — element being serialized.
/// * `parent_rendered` — prefix→URI map of what the nearest output ancestor
///   already declared in the canonical form.
/// * `include_prefix` — mode-specific predicate. Called with `(prefix, uri)`;
///   returns `true` if the binding is a candidate for emission.
///   - Inclusive C14N: always returns `true`.
///   - Exclusive C14N: returns `true` for visibly-utilized prefixes and
///     prefixes forced via InclusiveNamespaces PrefixList.
///
/// # Returns
///
/// `(sorted_ns_decls, updated_rendered_map)` — the declarations to emit and
/// the binding map to pass to child elements.
pub(crate) fn collect_ns_declarations(
    node: Node<'_, '_>,
    parent_rendered: &HashMap<String, String>,
    include_prefix: &dyn Fn(&str, &str) -> bool,
) -> (Vec<(String, String)>, HashMap<String, String>) {
    let mut rendered = parent_rendered.clone();
    let mut decls: Vec<(String, String)> = Vec::new();

    for ns in node.namespaces() {
        let prefix = ns.name().unwrap_or(""); // None = default namespace
        let uri = ns.uri();

        // The `xml` prefix namespace is never declared in canonical XML.
        if prefix == "xml" {
            continue;
        }

        // Mode-specific filter: inclusive accepts all, exclusive accepts
        // only visibly-utilized and forced prefixes.
        if !include_prefix(prefix, uri) {
            continue;
        }

        // Suppress redundant: skip if the nearest output ancestor already
        // rendered the same prefix→URI binding.
        if parent_rendered.get(prefix).map(|u| u.as_str()) == Some(uri) {
            continue;
        }

        // Suppress spurious xmlns="" when no non-empty default namespace is
        // in scope. Check the source tree (not just parent_rendered) to handle
        // document subsets where output ancestors may be absent.
        if prefix.is_empty() && uri.is_empty() {
            let has_rendered_default = parent_rendered.contains_key("");
            let has_in_scope_default = has_in_scope_default_namespace(node);
            if !has_rendered_default && !has_in_scope_default {
                continue;
            }
        }

        decls.push((prefix.to_string(), uri.to_string()));
    }

    // Sort namespace declarations by prefix (lexicographic, "" sorts first).
    decls.sort_by(|a, b| a.0.cmp(&b.0));

    // Update the rendered map for child elements.
    for (prefix, uri) in &decls {
        rendered.insert(prefix.clone(), uri.clone());
    }

    (decls, rendered)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use roxmltree::Document;

    /// Helper: run the pipeline with an accept-all predicate (inclusive behavior).
    fn collect_all(xml: &str) -> Vec<(String, String)> {
        let doc = Document::parse(xml).expect("parse");
        let root = doc.root_element();
        let (decls, _) = collect_ns_declarations(root, &HashMap::new(), &|_, _| true);
        decls
    }

    #[test]
    fn xml_prefix_excluded() {
        // xml: is always in scope but must never appear in declarations.
        let decls = collect_all(r#"<root xmlns:a="http://a.com"/>"#);
        assert!(
            decls.iter().all(|(p, _)| p != "xml"),
            "xml prefix must be excluded"
        );
    }

    #[test]
    fn sorted_by_prefix() {
        let decls =
            collect_all(r#"<root xmlns:z="http://z" xmlns:a="http://a" xmlns="http://d"/>"#);
        let prefixes: Vec<&str> = decls.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(prefixes, vec!["", "a", "z"]);
    }

    #[test]
    fn redundant_suppressed() {
        let doc = Document::parse(r#"<root xmlns:a="http://a"><child/></root>"#).expect("parse");
        let root = doc.root_element();
        let (_, rendered) = collect_ns_declarations(root, &HashMap::new(), &|_, _| true);

        let child = root.first_element_child().expect("child");
        let (decls, _) = collect_ns_declarations(child, &rendered, &|_, _| true);
        assert!(decls.is_empty(), "child must not redeclare a:");
    }

    #[test]
    fn spurious_xmlns_empty_suppressed() {
        // No default namespace in scope → xmlns="" must not appear.
        let decls = collect_all(r#"<root xmlns=""/>"#);
        assert!(
            decls.is_empty(),
            "xmlns=\"\" without a default ns in scope is spurious"
        );
    }

    #[test]
    fn xmlns_empty_emitted_for_undeclaration() {
        let doc = Document::parse(r#"<root xmlns="http://example.com"><child xmlns=""/></root>"#)
            .expect("parse");
        let root = doc.root_element();
        let (_, rendered) = collect_ns_declarations(root, &HashMap::new(), &|_, _| true);

        let child = root.first_element_child().expect("child");
        let (decls, _) = collect_ns_declarations(child, &rendered, &|_, _| true);
        assert!(
            decls.iter().any(|(p, u)| p.is_empty() && u.is_empty()),
            "xmlns=\"\" must be emitted to undeclare default ns"
        );
    }

    #[test]
    fn predicate_filters_prefixes() {
        let doc =
            Document::parse(r#"<root xmlns:a="http://a" xmlns:b="http://b" xmlns:c="http://c"/>"#)
                .expect("parse");
        let root = doc.root_element();
        // Only accept prefix "b".
        let (decls, _) = collect_ns_declarations(root, &HashMap::new(), &|p, _| p == "b");
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].0, "b");
    }
}
