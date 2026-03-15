//! Inclusive namespace rendering for C14N 1.0.
//!
//! In inclusive mode, all in-scope namespace declarations are rendered on each
//! element unless the same binding was already emitted by the nearest output
//! ancestor (suppressing redundant redeclarations). Unlike exclusive C14N,
//! namespaces are rendered even if not visibly used by the element's tag or
//! attributes.

use std::collections::HashMap;

use roxmltree::Node;

use super::serialize::NsRenderer;

/// Inclusive C14N namespace renderer.
///
/// Emits all in-scope namespace bindings that differ from what the nearest
/// output ancestor already rendered.
pub(crate) struct InclusiveNsRenderer;

impl NsRenderer for InclusiveNsRenderer {
    fn render_namespaces<'a>(
        &self,
        node: Node<'a, '_>,
        parent_rendered: &HashMap<String, String>,
    ) -> (Vec<(String, String)>, HashMap<String, String>) {
        let mut rendered = parent_rendered.clone();
        let mut decls: Vec<(String, String)> = Vec::new();

        // Collect all in-scope namespace declarations from roxmltree.
        // node.namespaces() yields every ns declared on this element or
        // inherited from ancestors.
        for ns in node.namespaces() {
            let prefix = ns.name().unwrap_or(""); // None = default namespace
            let uri = ns.uri();

            // The `xml` prefix namespace is never declared in canonical XML.
            if prefix == "xml" {
                continue;
            }

            // Emit only if different from what the nearest output ancestor rendered.
            if parent_rendered.get(prefix).map(|u| u.as_str()) == Some(uri) {
                continue;
            }

            // Suppress xmlns="" when no default namespace was previously in scope.
            // Only emit xmlns="" to undeclare a previously declared default ns.
            if prefix.is_empty() && uri.is_empty() && !parent_rendered.contains_key("") {
                continue;
            }

            decls.push((prefix.to_string(), uri.to_string()));
        }

        // Sort namespace declarations by prefix (lexicographic, "" sorts first).
        decls.sort_by(|a, b| a.0.cmp(&b.0));

        // Update the rendered map.
        for (prefix, uri) in &decls {
            rendered.insert(prefix.clone(), uri.clone());
        }

        (decls, rendered)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::serialize::serialize_canonical;
    use super::*;
    use roxmltree::Document;

    #[test]
    fn namespaces_rendered_on_first_element() {
        let xml = r#"<root xmlns="http://example.com" xmlns:a="http://a.com"><child/></root>"#;
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
        let result = String::from_utf8(out).expect("utf8");
        // Default ns and a: ns should appear on root.
        assert!(result.contains(r#"xmlns="http://example.com""#));
        assert!(result.contains(r#"xmlns:a="http://a.com""#));
    }

    #[test]
    fn inherited_ns_not_redeclared() {
        let xml = r#"<root xmlns:a="http://a.com"><child xmlns:a="http://a.com"/></root>"#;
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
        let result = String::from_utf8(out).expect("utf8");
        // xmlns:a should appear only once (on root), not redeclared on child.
        assert_eq!(
            result,
            r#"<root xmlns:a="http://a.com"><child></child></root>"#
        );
    }

    #[test]
    fn overridden_ns_is_redeclared() {
        let xml = r#"<root xmlns:a="http://a.com"><child xmlns:a="http://other.com"/></root>"#;
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
        let result = String::from_utf8(out).expect("utf8");
        // child should redeclare a: with different URI.
        assert!(result.contains(r#"<child xmlns:a="http://other.com">"#));
    }

    #[test]
    fn default_ns_undeclared() {
        let xml = r#"<root xmlns="http://example.com"><child xmlns=""/></root>"#;
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
        let result = String::from_utf8(out).expect("utf8");
        // child should have xmlns="" to undeclare the default namespace.
        assert!(result.contains(r#"<child xmlns="">"#));
    }

    #[test]
    fn ns_decls_sorted_by_prefix() {
        let xml =
            r#"<root xmlns:z="http://z.com" xmlns:a="http://a.com" xmlns="http://default.com"/>"#;
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
        let result = String::from_utf8(out).expect("utf8");
        // Order should be: xmlns="..." (default), xmlns:a, xmlns:z.
        // find(r#"xmlns=""#) matches the start of xmlns="http://default.com"
        let idx_default = result.find(r#"xmlns=""#).expect("default ns");
        let idx_a = result.find(r#"xmlns:a="#).expect("a ns");
        let idx_z = result.find(r#"xmlns:z="#).expect("z ns");
        assert!(idx_default < idx_a, "default before a");
        assert!(idx_a < idx_z, "a before z");
    }
}
