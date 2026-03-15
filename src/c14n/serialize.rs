//! Document-order serialization for canonical XML.
//!
//! Walks an XML document tree in document order, emitting canonical bytes.
//! Namespace rendering is delegated to the caller via [`NsRenderer`] trait.

use std::collections::HashMap;

use roxmltree::{Document, Node, NodeType};

use super::escape::{escape_attr, escape_cr, escape_text};
use super::C14nError;

/// Trait for namespace rendering strategies (inclusive vs exclusive).
pub(crate) trait NsRenderer {
    /// Compute namespace declarations to emit for this element.
    /// Returns (sorted_ns_decls, updated_rendered_map).
    ///
    /// `parent_rendered` maps prefix → URI for what the nearest output ancestor
    /// already declared in the canonical form.
    fn render_namespaces<'a>(
        &self,
        node: Node<'a, '_>,
        parent_rendered: &HashMap<String, String>,
    ) -> (Vec<(String, String)>, HashMap<String, String>);
}

/// Canonicalize a document (or subset) to the output buffer.
///
/// - `doc`: parsed roxmltree document
/// - `node_set`: optional predicate — if `Some`, only nodes where predicate
///   returns `true` are included in the output
/// - `with_comments`: whether to preserve comment nodes
/// - `ns_renderer`: namespace rendering strategy
/// - `output`: destination buffer
pub(crate) fn serialize_canonical(
    doc: &Document,
    node_set: Option<&dyn Fn(Node) -> bool>,
    with_comments: bool,
    ns_renderer: &dyn NsRenderer,
    output: &mut Vec<u8>,
) -> Result<(), C14nError> {
    let root = doc.root();
    serialize_children(
        root,
        node_set,
        with_comments,
        ns_renderer,
        &HashMap::new(),
        output,
    );
    Ok(())
}

/// Serialize children of a node in document order.
fn serialize_children(
    parent: Node,
    node_set: Option<&dyn Fn(Node) -> bool>,
    with_comments: bool,
    ns_renderer: &dyn NsRenderer,
    parent_rendered: &HashMap<String, String>,
    output: &mut Vec<u8>,
) {
    let is_doc_root = parent.node_type() == NodeType::Root;

    for child in parent.children() {
        // Node-set filtering: skip nodes not in the set.
        let in_set = node_set.map_or(true, |pred| pred(child));

        match child.node_type() {
            NodeType::Element => {
                if in_set {
                    // Before root element: emit \n if there was output before.
                    if is_doc_root && !output.is_empty() {
                        output.push(b'\n');
                    }
                    serialize_element(
                        child,
                        node_set,
                        with_comments,
                        ns_renderer,
                        parent_rendered,
                        output,
                    );
                } else {
                    // Element not in set, but descendants might be — walk children.
                    serialize_children(
                        child,
                        node_set,
                        with_comments,
                        ns_renderer,
                        parent_rendered,
                        output,
                    );
                }
            }
            NodeType::Text => {
                if in_set {
                    // Document-level text nodes are ignored by C14N.
                    // Only text inside elements is serialized.
                    if !is_doc_root {
                        if let Some(text) = child.text() {
                            escape_text(text, output);
                        }
                    }
                }
            }
            NodeType::Comment => {
                if with_comments && in_set {
                    if is_doc_root {
                        write_doc_level_separator(&child, output);
                    }
                    output.extend_from_slice(b"<!--");
                    if let Some(text) = child.text() {
                        // C14N spec: \r in comments must be escaped to &#xD;
                        escape_cr(text, output);
                    }
                    output.extend_from_slice(b"-->");
                }
            }
            NodeType::PI => {
                if in_set {
                    if let Some(pi) = child.pi() {
                        if is_doc_root {
                            write_doc_level_separator(&child, output);
                        }
                        output.extend_from_slice(b"<?");
                        output.extend_from_slice(pi.target.as_bytes());
                        if let Some(value) = pi.value {
                            output.push(b' ');
                            // C14N spec: \r in PI content must be escaped to &#xD;
                            escape_cr(value, output);
                        }
                        output.extend_from_slice(b"?>");
                    }
                }
            }
            NodeType::Root => {
                // Should not happen as a child.
            }
        }
    }
}

/// Serialize a single element node (start tag + children + end tag).
fn serialize_element(
    node: Node,
    node_set: Option<&dyn Fn(Node) -> bool>,
    with_comments: bool,
    ns_renderer: &dyn NsRenderer,
    parent_rendered: &HashMap<String, String>,
    output: &mut Vec<u8>,
) {
    let (ns_decls, rendered) = ns_renderer.render_namespaces(node, parent_rendered);

    // Start tag: <prefix:localname
    output.push(b'<');
    write_qualified_name(node, output);

    // Namespace declarations (already sorted by prefix).
    for (prefix, uri) in &ns_decls {
        if prefix.is_empty() {
            output.extend_from_slice(b" xmlns=\"");
        } else {
            output.extend_from_slice(b" xmlns:");
            output.extend_from_slice(prefix.as_bytes());
            output.extend_from_slice(b"=\"");
        }
        escape_attr(uri, output);
        output.push(b'"');
    }

    // Regular attributes, sorted by (namespace-uri, local-name).
    let mut attrs: Vec<_> = node.attributes().collect();

    // Filter attributes by node-set if applicable.
    if let Some(pred) = node_set {
        // For document subsets, only include attributes that are "in the set".
        // roxmltree doesn't give attribute nodes separate Node identity,
        // so when we have a node_set, all attributes of an included element
        // are included (matching xmlsec1 behavior for typical use cases).
        let _ = pred;
        // All attributes included if the element is in the set.
    }

    attrs.sort_by(|a, b| {
        let a_key = (a.namespace().unwrap_or(""), a.name());
        let b_key = (b.namespace().unwrap_or(""), b.name());
        a_key.cmp(&b_key)
    });

    for attr in &attrs {
        output.push(b' ');
        write_attribute_name(node, attr, output);
        output.extend_from_slice(b"=\"");
        escape_attr(attr.value(), output);
        output.push(b'"');
    }

    // Always use <tag></tag> form, never self-closing.
    output.push(b'>');

    // Children.
    serialize_children(
        node,
        node_set,
        with_comments,
        ns_renderer,
        &rendered,
        output,
    );

    // End tag.
    output.extend_from_slice(b"</");
    write_qualified_name(node, output);
    output.push(b'>');
}

/// Write `\n` separator for document-level nodes.
///
/// C14N spec: document-level comments and PIs get `\n` between them and the
/// root element. Specifically:
/// - Before root element: comment/PI followed by `\n`
/// - After root element: `\n` followed by comment/PI
///
/// This function emits `\n` either before or after the node, depending on
/// whether the root element has already been emitted.
fn write_doc_level_separator(node: &Node, output: &mut Vec<u8>) {
    let root_elem_seen = has_preceding_element_sibling(node);
    if root_elem_seen {
        // After root element: \n before this node.
        output.push(b'\n');
    } else if !output.is_empty() {
        // Before root element but not first output: \n after previous node.
        output.push(b'\n');
    }
}

/// Check if a node has a preceding sibling that is an element.
fn has_preceding_element_sibling(node: &Node) -> bool {
    let mut prev = node.prev_sibling();
    while let Some(p) = prev {
        if p.is_element() {
            return true;
        }
        prev = p.prev_sibling();
    }
    false
}

/// Write the qualified name (prefix:localname or just localname) of an element.
///
/// Uses `lookup_prefix()` to reverse-map namespace URI → prefix.
/// This is ambiguous when multiple prefixes bind the same URI; see
/// ns_exclusive.rs comment on `visibly_utilized_prefixes()`.
fn write_qualified_name(node: Node, output: &mut Vec<u8>) {
    if let Some(ns_uri) = node.tag_name().namespace() {
        if let Some(prefix) = node.lookup_prefix(ns_uri) {
            if !prefix.is_empty() {
                output.extend_from_slice(prefix.as_bytes());
                output.push(b':');
            }
        }
    }
    output.extend_from_slice(node.tag_name().name().as_bytes());
}

/// Write an attribute's qualified name (prefix:localname or just localname).
fn write_attribute_name(element: Node, attr: &roxmltree::Attribute, output: &mut Vec<u8>) {
    if let Some(ns_uri) = attr.namespace() {
        if let Some(prefix) = element.lookup_prefix(ns_uri) {
            if !prefix.is_empty() {
                output.extend_from_slice(prefix.as_bytes());
                output.push(b':');
            }
        }
    }
    output.extend_from_slice(attr.name().as_bytes());
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::ns_inclusive::InclusiveNsRenderer;
    use super::*;

    #[test]
    fn empty_element_expanded() {
        let xml = "<root><empty/></root>";
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "<root><empty></empty></root>"
        );
    }

    #[test]
    fn text_preserved() {
        let xml = "<root> hello &amp; world </root>";
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "<root> hello &amp; world </root>"
        );
    }

    #[test]
    fn comments_stripped_by_default() {
        let xml = "<root><!-- comment -->text</root>";
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
        assert_eq!(String::from_utf8(out).expect("utf8"), "<root>text</root>");
    }

    #[test]
    fn comments_preserved_with_flag() {
        let xml = "<root><!-- comment -->text</root>";
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, true, &renderer, &mut out).expect("c14n");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "<root><!-- comment -->text</root>"
        );
    }

    #[test]
    fn attribute_sorting() {
        let xml = r#"<root b="2" a="1" c="3"></root>"#;
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            r#"<root a="1" b="2" c="3"></root>"#
        );
    }

    #[test]
    fn pi_serialization() {
        let xml = "<?xml version=\"1.0\"?><root><?target data?></root>";
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
        // XML declaration is omitted by roxmltree parsing.
        // PI inside root is preserved.
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "<root><?target data?></root>"
        );
    }

    #[test]
    fn nested_elements_document_order() {
        let xml = "<a><b><c></c></b><d></d></a>";
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "<a><b><c></c></b><d></d></a>"
        );
    }

    #[test]
    fn document_level_comments() {
        let xml = "<!-- before --><root></root><!-- after -->";
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, true, &renderer, &mut out).expect("c14n");
        // C14N spec: \n between document-level nodes.
        // Before root: comment + \n + root
        // After root: root + \n + comment
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "<!-- before -->\n<root></root>\n<!-- after -->"
        );
    }

    #[test]
    fn document_level_pi_before_root() {
        let xml = "<?pi data?><root></root>";
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(&doc, None, false, &renderer, &mut out).expect("c14n");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "<?pi data?>\n<root></root>"
        );
    }
}
