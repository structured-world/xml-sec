//! Document-order serialization for canonical XML.
//!
//! Walks an XML document tree in document order, emitting canonical bytes.
//! Namespace rendering is delegated to the caller via [`NsRenderer`] trait.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use roxmltree::{Document, Node, NodeType};

use super::escape::{escape_attr, escape_cr, escape_text};
use super::prefix::{attribute_prefix, element_prefix};
use super::xml_base::{compute_effective_xml_base, resolve_uri};
use super::C14nError;

/// The XML namespace URI.
///
/// In C14N document subsets (W3C C14N §2.4), inheritable attributes in
/// this namespace are propagated from ancestors outside the node set:
/// - C14N 1.0 / Exclusive 1.0: `xml:lang`, `xml:space`, `xml:base`
/// - C14N 1.1: adds `xml:id` to the above set
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Check whether an xml:* attribute name is inheritable in the current mode.
///
/// Per C14N 1.0 §2.4: `xml:lang`, `xml:space`, `xml:base` are inherited.
/// Per C14N 1.1: `xml:id` is also inherited (xml:id propagation).
fn is_inheritable_xml_attr(local_name: &str, include_xml_id: bool) -> bool {
    matches!(local_name, "lang" | "space" | "base") || (include_xml_id && local_name == "id")
}

/// Configuration flags for C14N serialization that vary by mode.
#[derive(Clone, Copy)]
pub(crate) struct C14nConfig {
    /// Inherit xml:* attributes from ancestors outside the node set (§2.4).
    /// `true` for Inclusive C14N (1.0/1.1), `false` for Exclusive C14N (§3).
    pub inherit_xml_attrs: bool,
    /// Resolve relative xml:base URIs via RFC 3986 (C14N 1.1 only).
    pub fixup_xml_base: bool,
}

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
/// - `inherit_xml_attrs`: if `true` (Inclusive C14N), inherit `xml:lang`,
///   `xml:space`, `xml:base` (and `xml:id` for 1.1) from ancestors outside
///   the node set per C14N §2.4. If `false` (Exclusive C14N), skip this
///   search — per Exc-C14N §3, ancestor xml:* import is explicitly omitted.
/// - `fixup_xml_base`: if `true` (C14N 1.1), resolve `xml:base` relative
///   URIs in document subsets via RFC 3986. Only meaningful when
///   `inherit_xml_attrs` is `true`.
/// - `output`: destination buffer
pub(crate) fn serialize_canonical(
    doc: &Document,
    node_set: Option<&dyn Fn(Node) -> bool>,
    with_comments: bool,
    ns_renderer: &dyn NsRenderer,
    config: C14nConfig,
    output: &mut Vec<u8>,
) -> Result<(), C14nError> {
    let root = doc.root();
    serialize_children(
        root,
        node_set,
        with_comments,
        ns_renderer,
        config,
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
    config: C14nConfig,
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
                    // Before root element: emit \n separator if there was output before
                    // (e.g., a preceding comment/PI). Note: when node_set excludes the
                    // root element but includes preceding comments, those comments won't
                    // get a trailing \n — this is acceptable because document subsets
                    // that exclude the root element are only used with XPath transforms,
                    // which are not yet implemented.
                    if is_doc_root && !output.is_empty() {
                        output.push(b'\n');
                    }
                    serialize_element(
                        child,
                        node_set,
                        with_comments,
                        ns_renderer,
                        config,
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
                        config,
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
    config: C14nConfig,
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
    //
    // For Inclusive C14N document subsets: when the parent element is not in
    // the node set, xml:* attributes are inherited from ancestors per §2.4.
    //
    // For Exclusive C14N: this inheritance is explicitly OMITTED per Exc-C14N
    // §3: "This search and copying are omitted from the Exclusive XML
    // Canonicalization method."
    //
    // For C14N 1.1 (fixup_xml_base=true): xml:base values are additionally
    // resolved to effective URIs per RFC 3986.
    let inherited_xml = if config.inherit_xml_attrs {
        // xml:id inheritance gated on C14N 1.1 (same flag as xml:base fixup)
        let include_xml_id = config.fixup_xml_base;
        collect_inherited_xml_attrs(node, node_set, include_xml_id)
    } else {
        Vec::new()
    };

    // Compute effective parent xml:base for C14N 1.1 fixup. Needed when:
    // - fixup is enabled (C14N 1.1), AND
    // - parent is not in the node set (otherwise parent renders its own base)
    // The effective base is used for both inherited xml:base values and
    // resolving the element's own xml:base against the ancestor chain.
    let parent_not_in_set = if let Some(pred) = node_set {
        !node.parent().is_some_and(|p| p.is_element() && pred(p))
    } else {
        false
    };
    let effective_parent_base = if config.fixup_xml_base && parent_not_in_set {
        node.parent()
            .and_then(|p| compute_effective_xml_base(p, node_set))
    } else {
        None
    };

    // Build unified list: (ns_uri, local_name, prefix, value)
    // Using Cow to avoid allocations when no fixup is needed.
    let mut all_attrs: Vec<(&str, &str, &str, Cow<'_, str>)> = Vec::new();
    for attr in node.attributes() {
        let value = if let Some(ref base) = effective_parent_base {
            if attr.namespace() == Some(XML_NS) && attr.name() == "base" {
                // C14N 1.1: resolve element's own xml:base against parent's
                // effective base. Skip empty xml:base="" — it means "remove
                // the base", so we emit it unchanged (not resolved).
                let raw = attr.value();
                if raw.is_empty() {
                    Cow::Borrowed(raw)
                } else {
                    Cow::Owned(resolve_uri(base, raw))
                }
            } else {
                Cow::Borrowed(attr.value())
            }
        } else {
            Cow::Borrowed(attr.value())
        };
        all_attrs.push((
            attr.namespace().unwrap_or(""),
            attr.name(),
            attribute_prefix(node, &attr),
            value,
        ));
    }
    for &(name, value) in &inherited_xml {
        let resolved_value = if config.fixup_xml_base && name == "base" {
            // C14N 1.1: inherited xml:base uses the resolved effective value
            match effective_parent_base {
                Some(ref base) => Cow::Owned(base.clone()),
                None => Cow::Borrowed(value),
            }
        } else {
            Cow::Borrowed(value)
        };
        all_attrs.push((XML_NS, name, "xml", resolved_value));
    }
    all_attrs.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

    for (_, local_name, prefix, value) in &all_attrs {
        output.push(b' ');
        if !prefix.is_empty() {
            output.extend_from_slice(prefix.as_bytes());
            output.push(b':');
        }
        output.extend_from_slice(local_name.as_bytes());
        output.extend_from_slice(b"=\"");
        escape_attr(value, output);
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
        config,
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
///
/// Limitation: when `node_set` excludes the root element, the `\n` logic may
/// be incorrect for preceding comments/PIs. This only affects XPath-selected
/// subsets that exclude the root — not relevant for SAML enveloped signatures.
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

/// Collect inheritable `xml:*` attributes from ancestors for document subsets.
///
/// Per [W3C C14N 1.0 §2.4](https://www.w3.org/TR/xml-c14n/#ProcessingModel):
/// when an element is in the node set but its parent is NOT, `xml:lang`,
/// `xml:space`, and `xml:base` from ancestor elements must be emitted on
/// the element to preserve inherited semantics.
///
/// The `include_xml_id` flag (true for C14N 1.1) additionally inherits
/// `xml:id`. Other `xml:*` attributes are never inherited.
///
/// Returns `(local_name, value)` pairs. Closer ancestors take precedence.
/// Attributes already present on the element itself are excluded.
fn collect_inherited_xml_attrs<'a>(
    node: Node<'a, '_>,
    node_set: Option<&dyn Fn(Node) -> bool>,
    include_xml_id: bool,
) -> Vec<(&'a str, &'a str)> {
    let pred = match node_set {
        Some(p) => p,
        None => return Vec::new(), // Full document — no inheritance needed
    };

    // If parent element is in the node set, no inheritance needed — the parent
    // will render its own xml:* attributes, and the element inherits normally.
    if let Some(parent) = node.parent() {
        if parent.is_element() && pred(parent) {
            return Vec::new();
        }
    }

    // Collect inheritable xml:* attr names already on this element (own attrs
    // take precedence). Non-inheritable xml:* attrs are ignored.
    let mut seen: HashSet<&str> = HashSet::new();
    for attr in node.attributes() {
        if attr.namespace() == Some(XML_NS) {
            let local = attr.name();
            if is_inheritable_xml_attr(local, include_xml_id) {
                seen.insert(local);
            }
        }
    }

    // Walk ancestor chain. Closer ancestors take precedence: once a name is
    // seen, later (more distant) ancestors with the same name are skipped.
    // Stop at the nearest included ancestor — it renders its own xml:*
    // attributes in the canonical output, so inheriting past it would
    // incorrectly propagate attributes that are already visible.
    let mut inherited = Vec::new();
    let mut ancestor = node.parent();
    while let Some(anc) = ancestor {
        if anc.is_element() {
            // Stop at the nearest included ancestor (same logic as
            // compute_effective_xml_base).
            if pred(anc) {
                break;
            }
            for attr in anc.attributes() {
                if attr.namespace() == Some(XML_NS) {
                    let local = attr.name();
                    // Skip empty xml:base="" — per RFC 3986 an empty reference
                    // resolves to the current base, so it's a no-op.
                    if local == "base" && attr.value().is_empty() {
                        continue;
                    }
                    if is_inheritable_xml_attr(local, include_xml_id) && seen.insert(local) {
                        inherited.push((attr.name(), attr.value()));
                    }
                }
            }
        }
        ancestor = anc.parent();
    }

    inherited
}

/// Write the qualified name (prefix:localname or just localname) of an element.
///
/// Extracts the lexical prefix from the source XML via byte-range positions,
/// avoiding ambiguity when multiple prefixes bind the same namespace URI.
fn write_qualified_name(node: Node, output: &mut Vec<u8>) {
    let prefix = element_prefix(node);
    if !prefix.is_empty() {
        output.extend_from_slice(prefix.as_bytes());
        output.push(b':');
    }
    output.extend_from_slice(node.tag_name().name().as_bytes());
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::ns_inclusive::InclusiveNsRenderer;
    use super::*;
    use roxmltree::NodeId;

    #[test]
    fn empty_element_expanded() {
        let xml = "<root><empty/></root>";
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            None,
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .expect("c14n");
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
        serialize_canonical(
            &doc,
            None,
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .expect("c14n");
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
        serialize_canonical(
            &doc,
            None,
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .expect("c14n");
        assert_eq!(String::from_utf8(out).expect("utf8"), "<root>text</root>");
    }

    #[test]
    fn comments_preserved_with_flag() {
        let xml = "<root><!-- comment -->text</root>";
        let doc = Document::parse(xml).expect("parse");
        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            None,
            true,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .expect("c14n");
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
        serialize_canonical(
            &doc,
            None,
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .expect("c14n");
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
        serialize_canonical(
            &doc,
            None,
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .expect("c14n");
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
        serialize_canonical(
            &doc,
            None,
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .expect("c14n");
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
        serialize_canonical(
            &doc,
            None,
            true,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .expect("c14n");
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
        serialize_canonical(
            &doc,
            None,
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .expect("c14n");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "<?pi data?>\n<root></root>"
        );
    }

    // ── xml:* attribute inheritance tests (G001) ──────────────────────

    /// Helper: build a predicate that includes only nodes in `ids`.
    fn subset_predicate(ids: HashSet<NodeId>) -> impl Fn(Node) -> bool {
        move |n: Node| ids.contains(&n.id())
    }

    /// Helper: collect all node IDs in a subtree (element + descendants).
    fn subtree_ids(node: Node) -> HashSet<NodeId> {
        let mut ids = HashSet::new();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            ids.insert(n.id());
            for c in n.children() {
                stack.push(c);
            }
        }
        ids
    }

    #[test]
    fn xml_lang_inherited_in_subset() {
        // Root has xml:lang="en", child is in the subset but root is not.
        // Per W3C C14N §2.4, xml:lang must be inherited onto child.
        let xml = r#"<root xml:lang="en"><child>text</child></root>"#;
        let doc = Document::parse(xml).unwrap();
        let child = doc.root_element().first_element_child().unwrap();
        let ids = subtree_ids(child);
        let pred = subset_predicate(ids);

        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            Some(&pred),
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .unwrap();
        let result = String::from_utf8(out).unwrap();

        assert!(
            result.contains(r#"xml:lang="en""#),
            "xml:lang should be inherited from root; got: {result}"
        );
        assert!(
            !result.contains("<root"),
            "root should not appear in output"
        );
    }

    #[test]
    fn xml_space_inherited_in_subset() {
        let xml = r#"<root xml:space="preserve"><child>text</child></root>"#;
        let doc = Document::parse(xml).unwrap();
        let child = doc.root_element().first_element_child().unwrap();
        let ids = subtree_ids(child);
        let pred = subset_predicate(ids);

        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            Some(&pred),
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .unwrap();
        let result = String::from_utf8(out).unwrap();

        assert!(
            result.contains(r#"xml:space="preserve""#),
            "xml:space should be inherited; got: {result}"
        );
    }

    #[test]
    fn multiple_xml_attrs_inherited() {
        // Both xml:lang and xml:space should be inherited.
        let xml = r#"<root xml:lang="fr" xml:space="preserve"><child/></root>"#;
        let doc = Document::parse(xml).unwrap();
        let child = doc.root_element().first_element_child().unwrap();
        let ids = subtree_ids(child);
        let pred = subset_predicate(ids);

        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            Some(&pred),
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .unwrap();
        let result = String::from_utf8(out).unwrap();

        assert!(result.contains(r#"xml:lang="fr""#), "got: {result}");
        assert!(result.contains(r#"xml:space="preserve""#), "got: {result}");
        // Attributes sorted by (ns-uri, local-name): lang < space
        let lang_pos = result.find("xml:lang").unwrap();
        let space_pos = result.find("xml:space").unwrap();
        assert!(
            lang_pos < space_pos,
            "xml:lang should sort before xml:space"
        );
    }

    #[test]
    fn own_xml_attr_takes_precedence() {
        // Child has its own xml:lang="de" — ancestor's xml:lang="en" should NOT be inherited.
        let xml = r#"<root xml:lang="en"><child xml:lang="de">text</child></root>"#;
        let doc = Document::parse(xml).unwrap();
        let child = doc.root_element().first_element_child().unwrap();
        let ids = subtree_ids(child);
        let pred = subset_predicate(ids);

        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            Some(&pred),
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .unwrap();
        let result = String::from_utf8(out).unwrap();

        assert!(
            result.contains(r#"xml:lang="de""#),
            "child's own xml:lang should be used; got: {result}"
        );
        assert!(
            !result.contains(r#"xml:lang="en""#),
            "ancestor's xml:lang should not appear; got: {result}"
        );
    }

    #[test]
    fn closer_ancestor_xml_attr_wins() {
        // Grandparent has xml:lang="en", parent has xml:lang="fr".
        // Neither is in subset. Child should inherit "fr" (closer ancestor).
        let xml = r#"<a xml:lang="en"><b xml:lang="fr"><c>text</c></b></a>"#;
        let doc = Document::parse(xml).unwrap();
        let a = doc.root_element();
        let b = a.first_element_child().unwrap();
        let c = b.first_element_child().unwrap();
        let ids = subtree_ids(c);
        let pred = subset_predicate(ids);

        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            Some(&pred),
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .unwrap();
        let result = String::from_utf8(out).unwrap();

        assert!(
            result.contains(r#"xml:lang="fr""#),
            "closer ancestor's xml:lang='fr' should win; got: {result}"
        );
        assert!(
            !result.contains(r#"xml:lang="en""#),
            "distant ancestor's xml:lang='en' should not appear; got: {result}"
        );
    }

    #[test]
    fn no_inheritance_when_parent_in_set() {
        // Both root and child are in the set — no inheritance needed,
        // xml:lang stays on root naturally.
        let xml = r#"<root xml:lang="en"><child>text</child></root>"#;
        let doc = Document::parse(xml).unwrap();
        let root = doc.root_element();
        let child = root.first_element_child().unwrap();

        let mut ids = subtree_ids(root);
        // Include root and child both
        for c in child.children() {
            ids.insert(c.id());
        }
        let pred = subset_predicate(ids);

        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            Some(&pred),
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .unwrap();
        let result = String::from_utf8(out).unwrap();

        // xml:lang appears on root, NOT on child
        assert!(
            result.starts_with(r#"<root xml:lang="en">"#),
            "got: {result}"
        );
        assert!(
            result.contains("<child>text</child>"),
            "child should not have xml:lang; got: {result}"
        );
    }

    #[test]
    fn no_inheritance_past_included_ancestor() {
        // A (in set, xml:lang="en") → B (not in set) → C (in set)
        // C should NOT inherit xml:lang from A because A is in the set
        // and renders its own attributes. The walk must stop at A.
        let xml = r#"<a xml:lang="en"><b><c>text</c></b></a>"#;
        let doc = Document::parse(xml).unwrap();
        let a = doc.root_element();
        let b = a.first_element_child().unwrap();
        let c = b.first_element_child().unwrap();

        // Include a and c (not b)
        let mut ids = HashSet::new();
        ids.insert(a.id());
        ids.insert(c.id());
        for child in c.children() {
            ids.insert(child.id());
        }
        let pred = subset_predicate(ids);

        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            Some(&pred),
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .unwrap();
        let result = String::from_utf8(out).unwrap();

        // xml:lang should appear on <a> only, NOT inherited onto <c>
        assert!(
            result.contains(r#"<a xml:lang="en">"#),
            "a should have xml:lang; got: {result}"
        );
        assert!(
            !result.contains(r#"<c xml:lang"#),
            "c should NOT inherit xml:lang from a; got: {result}"
        );
    }

    #[test]
    fn no_inheritance_in_full_document() {
        // Full document (no node_set) — xml:lang stays on root only.
        let xml = r#"<root xml:lang="en"><child>text</child></root>"#;
        let doc = Document::parse(xml).unwrap();

        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            None,
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .unwrap();
        let result = String::from_utf8(out).unwrap();

        assert_eq!(result, r#"<root xml:lang="en"><child>text</child></root>"#);
    }

    #[test]
    fn xml_attrs_inherited_with_namespaces() {
        // Realistic scenario: namespaced element with xml:lang from ancestor.
        // Verifies xml:* attrs sort correctly among namespace declarations.
        let xml = r#"<foo:Root xmlns:foo="http://foo" xml:lang="en-ie"><foo:Child>data</foo:Child></foo:Root>"#;
        let doc = Document::parse(xml).unwrap();
        let child = doc.root_element().first_element_child().unwrap();
        let ids = subtree_ids(child);
        let pred = subset_predicate(ids);

        let renderer = InclusiveNsRenderer;
        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            Some(&pred),
            false,
            &renderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .unwrap();
        let result = String::from_utf8(out).unwrap();

        // Should have xmlns:foo (ns decl) then xml:lang (regular attr)
        assert!(
            result.contains(r#"xmlns:foo="http://foo""#),
            "got: {result}"
        );
        assert!(result.contains(r#"xml:lang="en-ie""#), "got: {result}");
        // Ns decls come before regular attrs
        let ns_pos = result.find("xmlns:foo").unwrap();
        let lang_pos = result.find("xml:lang").unwrap();
        assert!(
            ns_pos < lang_pos,
            "ns decls should come before regular attrs"
        );
    }
}
