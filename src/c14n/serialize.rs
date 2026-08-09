//! Document-order serialization for canonical XML.
//!
//! Walks an XML document tree in document order, emitting canonical bytes.
//! Namespace rendering is delegated to the caller via [`NsRenderer`] trait.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};

use roxmltree::{Document, Node, NodeId, NodeType};

#[cfg(test)]
use super::ClosureVisibility;
use super::escape::{escape_attr, escape_cr, escape_text};
use super::prefix::{attribute_prefix, element_prefix};
use super::xml_base::{
    XmlBaseResolutionBudget, XmlBaseResolutionError, compute_effective_xml_base_with_budget,
    preserves_xml_base_context, resolve_uri_with_budget,
};
use super::{C14nError, NodeVisibility};

#[derive(Debug)]
pub(super) struct CanonicalOutputLimitExceeded {
    max_bytes: usize,
}

impl std::fmt::Display for CanonicalOutputLimitExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "canonical output exceeds maximum of {} bytes",
            self.max_bytes
        )
    }
}

impl std::error::Error for CanonicalOutputLimitExceeded {}

fn output_limit_error(max_bytes: usize) -> C14nError {
    C14nError::Io(io::Error::other(CanonicalOutputLimitExceeded { max_bytes }))
}

/// The XML namespace URI.
///
/// In inclusive C14N document subsets, `xml:lang` and `xml:space` are simple
/// inheritable attributes. `xml:base` is inherited in C14N 1.0 and receives
/// dedicated fixup in C14N 1.1; `xml:id` is never inherited in C14N 1.1.
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

struct CanonicalOutput<'a> {
    bytes: &'a mut Vec<u8>,
    max_len: Option<usize>,
    limit_exceeded: bool,
    tracked_element: Option<NodeId>,
    tracked_position: Option<usize>,
    xml_base_resolution: &'a XmlBaseResolutionBudget,
}

impl Write for CanonicalOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next_len = self.bytes.len().checked_add(bytes.len());
        if self
            .max_len
            .is_some_and(|max_len| next_len.is_none_or(|next_len| next_len > max_len))
        {
            self.limit_exceeded = true;
            return Err(io::Error::other("canonical output limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl CanonicalOutput<'_> {
    fn track(&mut self, node: Node<'_, '_>) {
        if self.tracked_element == Some(node.id()) {
            self.tracked_position = Some(self.bytes.len());
        }
    }
}

/// Check whether an xml:* attribute participates in subset inheritance.
///
/// C14N 1.0 applies the general rule to `xml:id`; C14N 1.1 §2.4 explicitly
/// removes it from the simple inheritable attributes.
fn is_inheritable_xml_attr(local_name: &str, inherit_xml_id: bool) -> bool {
    matches!(local_name, "lang" | "space" | "base") || (inherit_xml_id && local_name == "id")
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

#[derive(Clone, Copy)]
pub(crate) struct CanonicalOutputOptions<'a> {
    tracked_element: Option<NodeId>,
    max_output_bytes: Option<usize>,
    xml_base_resolution: &'a XmlBaseResolutionBudget,
}

impl<'a> CanonicalOutputOptions<'a> {
    pub(crate) fn unbounded(
        tracked_element: Option<NodeId>,
        xml_base_resolution: &'a XmlBaseResolutionBudget,
    ) -> Self {
        Self {
            tracked_element,
            max_output_bytes: None,
            xml_base_resolution,
        }
    }

    pub(crate) fn bounded(
        tracked_element: Option<NodeId>,
        max_output_bytes: usize,
        xml_base_resolution: &'a XmlBaseResolutionBudget,
    ) -> Self {
        Self {
            tracked_element,
            max_output_bytes: Some(max_output_bytes),
            xml_base_resolution,
        }
    }
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
        visibility: Option<&dyn NodeVisibility>,
    ) -> (Vec<(String, String)>, HashMap<String, String>);

    fn renders_selected_namespace_of_omitted_element(&self, prefix: &str) -> bool;
}

/// Canonicalize a document (or subset) to the output buffer.
///
/// - `doc`: parsed roxmltree document
/// - `node_set`: optional predicate — if `Some`, only nodes where predicate
///   returns `true` are included in the output
/// - `with_comments`: whether to preserve comment nodes
/// - `ns_renderer`: namespace rendering strategy
/// - `inherit_xml_attrs`: if `true` (Inclusive C14N), inherit `xml:lang`,
///   `xml:space`, and process `xml:base` from ancestors outside the node set
///   per C14N §2.4. If `false` (Exclusive C14N), skip this
///   search — per Exc-C14N §3, ancestor xml:* import is explicitly omitted.
/// - `fixup_xml_base`: if `true` (C14N 1.1), resolve `xml:base` relative
///   URIs in document subsets via RFC 3986. Only meaningful when
///   `inherit_xml_attrs` is `true`.
/// - `output`: destination buffer
#[cfg(test)]
pub(crate) fn serialize_canonical(
    doc: &Document,
    node_set: Option<&dyn Fn(Node) -> bool>,
    with_comments: bool,
    ns_renderer: &dyn NsRenderer,
    config: C14nConfig,
    output: &mut Vec<u8>,
) -> Result<(), C14nError> {
    let visibility = node_set.map(|predicate| ClosureVisibility { predicate });
    serialize_canonical_visible_with_position(
        doc,
        visibility
            .as_ref()
            .map(|visibility| visibility as &dyn NodeVisibility),
        with_comments,
        ns_renderer,
        config,
        None,
        output,
    )?;
    Ok(())
}

pub(crate) fn serialize_canonical_visible_with_position(
    doc: &Document,
    visibility: Option<&dyn NodeVisibility>,
    with_comments: bool,
    ns_renderer: &dyn NsRenderer,
    config: C14nConfig,
    tracked_element: Option<NodeId>,
    output: &mut Vec<u8>,
) -> Result<Option<usize>, C14nError> {
    let xml_base_resolution = XmlBaseResolutionBudget::default();
    serialize_canonical_visible_with_position_bounded(
        doc,
        visibility,
        with_comments,
        ns_renderer,
        config,
        CanonicalOutputOptions::unbounded(tracked_element, &xml_base_resolution),
        output,
    )
}

pub(crate) fn serialize_canonical_visible_with_position_bounded(
    doc: &Document,
    visibility: Option<&dyn NodeVisibility>,
    with_comments: bool,
    ns_renderer: &dyn NsRenderer,
    config: C14nConfig,
    options: CanonicalOutputOptions<'_>,
    output: &mut Vec<u8>,
) -> Result<Option<usize>, C14nError> {
    let root = doc.root();
    let max_len = match options.max_output_bytes {
        Some(limit) => Some(
            output
                .len()
                .checked_add(limit)
                .ok_or_else(|| output_limit_error(limit))?,
        ),
        None => None,
    };
    let mut output = CanonicalOutput {
        bytes: output,
        max_len,
        limit_exceeded: false,
        tracked_element: options.tracked_element,
        tracked_position: None,
        xml_base_resolution: options.xml_base_resolution,
    };
    let result = serialize_children(
        root,
        visibility,
        with_comments,
        ns_renderer,
        config,
        &HashMap::new(),
        &mut output,
    );
    if output.limit_exceeded {
        return Err(output_limit_error(
            options.max_output_bytes.unwrap_or(usize::MAX),
        ));
    }
    result?;
    Ok(output.tracked_position)
}

/// Serialize children of a node in document order.
fn serialize_children(
    parent: Node,
    visibility: Option<&dyn NodeVisibility>,
    with_comments: bool,
    ns_renderer: &dyn NsRenderer,
    config: C14nConfig,
    parent_rendered: &HashMap<String, String>,
    output: &mut CanonicalOutput<'_>,
) -> Result<(), C14nError> {
    let is_doc_root = parent.node_type() == NodeType::Root;

    for child in parent.children() {
        // Node-set filtering: skip nodes not in the set.
        let in_set = visibility.is_none_or(|set| set.contains_node(child));

        match child.node_type() {
            NodeType::Element => {
                if in_set {
                    serialize_element(
                        child,
                        visibility,
                        with_comments,
                        ns_renderer,
                        config,
                        parent_rendered,
                        output,
                    )?;
                } else {
                    // Canonical XML §2.3 processes selected namespace and
                    // attribute axes even when their owner is omitted; only
                    // the owner's tags are suppressed. The canonical form is
                    // an octet stream and esoteric node-sets need not serialize
                    // as well-balanced XML (see Exclusive C14N §5.2).
                    serialize_selected_axes_of_omitted_element(
                        child,
                        visibility,
                        ns_renderer,
                        parent_rendered,
                        output,
                    )?;
                    // Element not in set, but descendants might be — walk children.
                    serialize_children(
                        child,
                        visibility,
                        with_comments,
                        ns_renderer,
                        config,
                        parent_rendered,
                        output,
                    )?;
                }
            }
            NodeType::Text => {
                if in_set {
                    // Document-level text nodes are ignored by C14N.
                    // Only text inside elements is serialized.
                    if !is_doc_root && let Some(text) = child.text() {
                        escape_text(text, output)?;
                    }
                }
            }
            NodeType::Comment => {
                if with_comments && in_set {
                    let follows_document_element =
                        is_doc_root && has_preceding_element_sibling(&child);
                    write_doc_level_prefix(is_doc_root, follows_document_element, output)?;
                    output.write_all(b"<!--")?;
                    if let Some(text) = child.text() {
                        // C14N spec: \r in comments must be escaped to &#xD;
                        escape_cr(text, output)?;
                    }
                    output.write_all(b"-->")?;
                    write_doc_level_suffix(is_doc_root, follows_document_element, output)?;
                }
            }
            NodeType::PI => {
                if in_set && let Some(pi) = child.pi() {
                    let follows_document_element =
                        is_doc_root && has_preceding_element_sibling(&child);
                    write_doc_level_prefix(is_doc_root, follows_document_element, output)?;
                    output.write_all(b"<?")?;
                    output.write_all(pi.target.as_bytes())?;
                    if let Some(value) = pi.value {
                        output.write_all(b" ")?;
                        // C14N spec: \r in PI content must be escaped to &#xD;
                        escape_cr(value, output)?;
                    }
                    output.write_all(b"?>")?;
                    write_doc_level_suffix(is_doc_root, follows_document_element, output)?;
                }
            }
            NodeType::Root => {
                // Should not happen as a child.
            }
        }
    }
    Ok(())
}

fn serialize_selected_axes_of_omitted_element(
    owner: Node,
    visibility: Option<&dyn NodeVisibility>,
    ns_renderer: &dyn NsRenderer,
    parent_rendered: &HashMap<String, String>,
    output: &mut CanonicalOutput<'_>,
) -> Result<(), C14nError> {
    let Some(visibility) = visibility else {
        return Ok(());
    };

    let mut namespaces = owner
        .namespaces()
        .filter_map(|namespace| {
            let prefix = namespace.name().unwrap_or("");
            (prefix != "xml"
                && ns_renderer.renders_selected_namespace_of_omitted_element(prefix)
                && visibility.contains_namespace(owner, prefix, namespace.uri())
                && parent_rendered.get(prefix).map(String::as_str) != Some(namespace.uri()))
            .then_some((prefix, namespace.uri()))
        })
        .collect::<Vec<_>>();
    namespaces.sort_by_key(|(prefix, _)| *prefix);
    for (prefix, uri) in namespaces {
        if prefix.is_empty() {
            output.write_all(b" xmlns=\"")?;
        } else {
            output.write_all(b" xmlns:")?;
            output.write_all(prefix.as_bytes())?;
            output.write_all(b"=\"")?;
        }
        escape_attr(uri, output)?;
        output.write_all(b"\"")?;
    }

    let mut attributes = owner
        .attributes()
        .filter(|attribute| {
            visibility.contains_attribute(owner, attribute.namespace(), attribute.name())
        })
        .collect::<Vec<_>>();
    attributes.sort_by(|left, right| {
        (left.namespace().unwrap_or(""), left.name())
            .cmp(&(right.namespace().unwrap_or(""), right.name()))
    });
    for attribute in attributes {
        output.write_all(b" ")?;
        let prefix = attribute_prefix(owner, &attribute);
        if !prefix.is_empty() {
            output.write_all(prefix.as_bytes())?;
            output.write_all(b":")?;
        }
        output.write_all(attribute.name().as_bytes())?;
        output.write_all(b"=\"")?;
        escape_attr(attribute.value(), output)?;
        output.write_all(b"\"")?;
    }
    Ok(())
}

/// Serialize a single element node (start tag + children + end tag).
fn serialize_element(
    node: Node,
    visibility: Option<&dyn NodeVisibility>,
    with_comments: bool,
    ns_renderer: &dyn NsRenderer,
    config: C14nConfig,
    parent_rendered: &HashMap<String, String>,
    output: &mut CanonicalOutput<'_>,
) -> Result<(), C14nError> {
    let (ns_decls, rendered) = ns_renderer.render_namespaces(node, parent_rendered, visibility);

    // Start tag: <prefix:localname
    output.track(node);
    output.write_all(b"<")?;
    write_qualified_name(node, output)?;

    // Namespace declarations (already sorted by prefix).
    for (prefix, uri) in &ns_decls {
        if prefix.is_empty() {
            output.write_all(b" xmlns=\"")?;
        } else {
            output.write_all(b" xmlns:")?;
            output.write_all(prefix.as_bytes())?;
            output.write_all(b"=\"")?;
        }
        escape_attr(uri, output)?;
        output.write_all(b"\"")?;
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
        collect_inherited_xml_attrs(node, visibility, config.fixup_xml_base)
    } else {
        Vec::new()
    };

    // Compute effective parent xml:base for C14N 1.1 fixup. Needed when:
    // - fixup is enabled (C14N 1.1), AND
    // - parent is not in the node set (otherwise parent renders its own base)
    // The effective base is used for both inherited xml:base values and
    // resolving the element's own xml:base against the ancestor chain.
    let parent_not_in_set = if let Some(set) = visibility {
        !node
            .parent()
            .is_some_and(|p| p.is_element() && set.contains_node(p))
    } else {
        false
    };
    let effective_parent_base = if config.fixup_xml_base && parent_not_in_set {
        match node.parent() {
            Some(parent) => compute_effective_xml_base_with_budget(
                parent,
                visibility,
                output.xml_base_resolution,
            )
            .map_err(map_xml_base_error)?,
            None => None,
        }
    } else {
        None
    };

    // Build unified list: (ns_uri, local_name, prefix, value)
    // Using Cow to avoid allocations when no fixup is needed.
    let mut all_attrs: Vec<(&str, &str, &str, Cow<'_, str>)> = Vec::new();
    for attr in node.attributes() {
        if visibility
            .is_some_and(|set| !set.contains_attribute(node, attr.namespace(), attr.name()))
        {
            continue;
        }
        let value = if let Some(base) = effective_parent_base.as_deref() {
            if attr.namespace() == Some(XML_NS) && attr.name() == "base" {
                // C14N 1.1: resolve the element's xml:base against the
                // parent's effective base when non-empty. For xml:base="",
                // emit the attribute value unchanged (do not resolve it).
                let raw = attr.value();
                if raw.is_empty() {
                    Cow::Borrowed(raw)
                } else {
                    Cow::Owned(
                        resolve_uri_with_budget(base, raw, output.xml_base_resolution)
                            .map_err(map_xml_base_error)?,
                    )
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
            match effective_parent_base.as_ref() {
                Some(base) => Cow::Owned(base.clone()),
                None => Cow::Borrowed(value),
            }
        } else {
            Cow::Borrowed(value)
        };
        all_attrs.push((XML_NS, name, "xml", resolved_value));
    }
    all_attrs.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

    for (_, local_name, prefix, value) in &all_attrs {
        output.write_all(b" ")?;
        if !prefix.is_empty() {
            output.write_all(prefix.as_bytes())?;
            output.write_all(b":")?;
        }
        output.write_all(local_name.as_bytes())?;
        output.write_all(b"=\"")?;
        escape_attr(value, output)?;
        output.write_all(b"\"")?;
    }

    // Always use <tag></tag> form, never self-closing.
    output.write_all(b">")?;

    // Children.
    serialize_children(
        node,
        visibility,
        with_comments,
        ns_renderer,
        config,
        &rendered,
        output,
    )?;

    // End tag.
    output.write_all(b"</")?;
    write_qualified_name(node, output)?;
    output.write_all(b">")?;
    Ok(())
}

fn map_xml_base_error(error: XmlBaseResolutionError) -> C14nError {
    match error {
        XmlBaseResolutionError::Components { maximum, actual } => {
            C14nError::XmlBaseComponentsTooLarge {
                max: maximum,
                actual,
            }
        }
        XmlBaseResolutionError::Bytes { maximum, actual } => C14nError::XmlBaseResolutionTooLarge {
            max_bytes: maximum,
            actual,
        },
    }
}

/// Emit the separator preceding a document-level comment or PI.
fn write_doc_level_prefix(
    is_doc_root: bool,
    follows_document_element: bool,
    output: &mut CanonicalOutput<'_>,
) -> io::Result<()> {
    if is_doc_root && follows_document_element {
        output.write_all(b"\n")?;
    }
    Ok(())
}

/// Emit the separator following a document-level comment or PI.
fn write_doc_level_suffix(
    is_doc_root: bool,
    follows_document_element: bool,
    output: &mut CanonicalOutput<'_>,
) -> io::Result<()> {
    if is_doc_root && !follows_document_element {
        output.write_all(b"\n")?;
    }
    Ok(())
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
/// when an element is in the node set but its parent is NOT, `xml:lang` and
/// `xml:space` are inherited from the nearest ancestor declarations whether
/// or not those attribute nodes are themselves in the node set. `xml:base`
/// follows the version-specific inheritance/fixup rules.
///
/// `xml:id` and other `xml:*` attributes are never inherited in C14N 1.1.
///
/// Returns `(local_name, value)` pairs. Closer ancestors take precedence.
/// Attributes already present on the element itself are excluded.
fn collect_inherited_xml_attrs<'a>(
    node: Node<'a, '_>,
    visibility: Option<&dyn NodeVisibility>,
    fixup_xml_base: bool,
) -> Vec<(&'a str, &'a str)> {
    let set = match visibility {
        Some(p) => p,
        None => return Vec::new(), // Full document — no inheritance needed
    };

    // If parent element is in the node set, no inheritance needed — the parent
    // will render its own xml:* attributes, and the element inherits normally.
    if let Some(parent) = node.parent()
        && parent.is_element()
        && set.contains_node(parent)
    {
        return Vec::new();
    }

    // C14N 1.1 is the only inclusive mode with xml:base fixup, and it is also
    // the version that removes xml:id from subset inheritance.
    let inherit_xml_id = !fixup_xml_base;

    // Collect inheritable xml:* attr names already on this element (own attrs
    // take precedence). Non-inheritable xml:* attrs are ignored.
    let mut seen: HashSet<&str> = HashSet::new();
    for attr in node.attributes() {
        if attr.namespace() == Some(XML_NS) {
            let local = attr.name();
            if is_inheritable_xml_attr(local, inherit_xml_id) {
                seen.insert(local);
            }
        }
    }

    // Walk ancestor chain. Closer ancestors take precedence: once a name is
    // seen, later (more distant) ancestors with the same name are skipped.
    // The direct source parent is absent from the node set at this point, so
    // Canonical XML treats this element as an apex even if a more distant
    // ancestor is also in the output. Search the complete source ancestry.
    let mut inherited = Vec::new();
    let mut xml_base_boundary_reached = false;
    let mut ancestor = node.parent();
    while let Some(anc) = ancestor {
        if anc.is_element() {
            // C14N 1.1 resolves xml:base only across the contiguous omitted
            // chain. An included ancestor already renders its own base, but
            // remains the resolution seed for bases on omitted descendants.
            xml_base_boundary_reached |= fixup_xml_base && preserves_xml_base_context(anc, set);
            for attr in anc.attributes() {
                if attr.namespace() == Some(XML_NS) {
                    let local = attr.name();
                    if local == "base" && xml_base_boundary_reached {
                        continue;
                    }
                    // Skip empty xml:base="" — per RFC 3986 an empty reference
                    // resolves to the current base, so it's a no-op.
                    if local == "base" && attr.value().is_empty() {
                        continue;
                    }
                    // C14N 1.1 §2.4 examines simple inheritable attributes
                    // whether or not their attribute nodes are in the input
                    // node-set. Filtering here would change inherited XML
                    // semantics at an apex element.
                    if is_inheritable_xml_attr(local, inherit_xml_id) && seen.insert(local) {
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
fn write_qualified_name(node: Node, output: &mut CanonicalOutput<'_>) -> io::Result<()> {
    let prefix = element_prefix(node);
    if !prefix.is_empty() {
        output.write_all(prefix.as_bytes())?;
        output.write_all(b":")?;
    }
    output.write_all(node.tag_name().name().as_bytes())?;
    Ok(())
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

    #[test]
    fn document_level_pi_keeps_separator_when_root_is_omitted() {
        // Document-level separators depend on source-document position, not
        // on whether the document element itself belongs to the node-set.
        let xml = "<?pi data?><root><child>text</child></root>";
        let doc = Document::parse(xml).expect("parse");
        let pi = doc
            .root()
            .children()
            .find(|node| node.node_type() == NodeType::PI)
            .expect("document PI");
        let child = doc.root_element().first_element_child().unwrap();
        let mut ids = subtree_ids(child);
        ids.insert(pi.id());
        let pred = subset_predicate(ids);

        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            Some(&pred),
            false,
            &InclusiveNsRenderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            &mut out,
        )
        .expect("c14n");

        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "<?pi data?>\n<child>text</child>"
        );
    }

    struct SelectedAxesOnly {
        owner: NodeId,
    }

    impl NodeVisibility for SelectedAxesOnly {
        fn contains_node(&self, _node: Node<'_, '_>) -> bool {
            false
        }

        fn contains_attribute(
            &self,
            owner: Node<'_, '_>,
            namespace: Option<&str>,
            local_name: &str,
        ) -> bool {
            owner.id() == self.owner && namespace.is_none() && local_name == "a"
        }

        fn contains_namespace(&self, owner: Node<'_, '_>, prefix: &str, uri: &str) -> bool {
            owner.id() == self.owner && prefix == "p" && uri == "urn:p"
        }
    }

    #[test]
    fn omitted_element_still_processes_its_selected_axes() {
        // C14N §2.3 suppresses only the omitted element's tags. Namespace and
        // attribute nodes independently selected into the node-set still emit.
        let document = Document::parse(r#"<root xmlns:p="urn:p" a="1"><child/></root>"#)
            .expect("fixed selected-axis fixture must parse");
        let visibility = SelectedAxesOnly {
            owner: document.root_element().id(),
        };
        let mut output = Vec::new();

        serialize_canonical_visible_with_position(
            &document,
            Some(&visibility),
            false,
            &InclusiveNsRenderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            },
            None,
            &mut output,
        )
        .expect("selected axes must canonicalize");

        assert_eq!(output, br#" xmlns:p="urn:p" a="1""#);
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
    fn apex_inherits_past_included_ancestor() {
        // A (in set, xml:lang="en") → B (not in set) → C (in set)
        // C is an apex because its direct parent is absent. C14N 1.0 §2.4
        // examines its complete ancestor axis, including ancestors that are
        // themselves in the node set, so C must materialize xml:lang.
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

        // Both elements carry xml:lang: A owns it and C materializes the
        // inherited value because the omitted B breaks the output ancestry.
        assert!(
            result.contains(r#"<a xml:lang="en">"#),
            "a should have xml:lang; got: {result}"
        );
        assert!(
            result.contains(r#"<c xml:lang="en">"#),
            "apex c should inherit xml:lang from a; got: {result}"
        );
    }

    #[test]
    fn c14n11_apex_does_not_repeat_base_from_included_ancestor() {
        // C14N 1.1 fixes up xml:base only across the contiguous omitted chain.
        // Repeating a base already rendered by an included ancestor changes the
        // canonical octets without preserving any additional URI semantics.
        let xml = r#"<a xml:base="u/"><b><c>text</c></b></a>"#;
        let doc = Document::parse(xml).unwrap();
        let a = doc.root_element();
        let b = a.first_element_child().unwrap();
        let c = b.first_element_child().unwrap();

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
                fixup_xml_base: true,
            },
            &mut out,
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"<a xml:base="u/"><c>text</c></a>"#
        );
    }

    #[test]
    fn c14n11_apex_base_uses_only_contiguous_omitted_ancestors() {
        // The included a already establishes u/ in the canonical output. The
        // apex c must fix up only the omitted b base plus its own base, or u/
        // would be applied twice when the canonical subset is interpreted.
        let xml = r#"<a xml:base="u/"><b xml:base="v/"><c xml:base="x">text</c></b></a>"#;
        let doc = Document::parse(xml).unwrap();
        let a = doc.root_element();
        let b = a.first_element_child().unwrap();
        let c = b.first_element_child().unwrap();

        let mut ids = HashSet::new();
        ids.insert(a.id());
        ids.insert(c.id());
        for child in c.children() {
            ids.insert(child.id());
        }
        let pred = subset_predicate(ids);

        let mut out = Vec::new();
        serialize_canonical(
            &doc,
            Some(&pred),
            false,
            &InclusiveNsRenderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: true,
            },
            &mut out,
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"<a xml:base="u/"><c xml:base="v/x">text</c></a>"#
        );
    }

    struct HiddenXmlBaseVisibility {
        included: HashSet<NodeId>,
        hidden_base_owner: NodeId,
    }

    impl NodeVisibility for HiddenXmlBaseVisibility {
        fn contains_node(&self, node: Node<'_, '_>) -> bool {
            self.included.contains(&node.id())
        }

        fn contains_attribute(
            &self,
            owner: Node<'_, '_>,
            namespace: Option<&str>,
            local_name: &str,
        ) -> bool {
            self.included.contains(&owner.id())
                && !(owner.id() == self.hidden_base_owner
                    && namespace == Some(XML_NS)
                    && local_name == "base")
        }

        fn contains_namespace(&self, owner: Node<'_, '_>, _prefix: &str, _uri: &str) -> bool {
            self.included.contains(&owner.id())
        }
    }

    #[test]
    fn c14n11_fixup_crosses_selected_owner_of_hidden_xml_base() {
        // b remains in the output but its xml:base attribute node does not.
        // The omitted c therefore requires d to materialize b's hidden base;
        // stopping at b would change d's effective URI in the canonical form.
        let xml = r#"<a xml:base="http://ex/"><b xml:base="hidden/"><c><d xml:base="leaf">text</d></c></b></a>"#;
        let doc = Document::parse(xml).unwrap();
        let a = doc.root_element();
        let b = a.first_element_child().unwrap();
        let c = b.first_element_child().unwrap();
        let d = c.first_element_child().unwrap();
        let mut included = HashSet::from([a.id(), b.id(), d.id()]);
        included.extend(d.children().map(|node| node.id()));
        let visibility = HiddenXmlBaseVisibility {
            included,
            hidden_base_owner: b.id(),
        };
        let mut out = Vec::new();

        serialize_canonical_visible_with_position(
            &doc,
            Some(&visibility),
            false,
            &InclusiveNsRenderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: true,
            },
            None,
            &mut out,
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"<a xml:base="http://ex/"><b><d xml:base="hidden/leaf">text</d></b></a>"#
        );
    }

    #[test]
    fn c14n11_inherits_hidden_base_past_selected_owner() {
        // Unlike the fixup case above, d has no base of its own. Its inherited
        // base must still cross selected b because b's base attribute is hidden.
        let xml = r#"<a xml:base="http://ex/"><b xml:base="hidden/"><c><d>text</d></c></b></a>"#;
        let doc = Document::parse(xml).unwrap();
        let a = doc.root_element();
        let b = a.first_element_child().unwrap();
        let c = b.first_element_child().unwrap();
        let d = c.first_element_child().unwrap();
        let mut included = HashSet::from([a.id(), b.id(), d.id()]);
        included.extend(d.children().map(|node| node.id()));
        let visibility = HiddenXmlBaseVisibility {
            included,
            hidden_base_owner: b.id(),
        };
        let mut out = Vec::new();

        serialize_canonical_visible_with_position(
            &doc,
            Some(&visibility),
            false,
            &InclusiveNsRenderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: true,
            },
            None,
            &mut out,
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"<a xml:base="http://ex/"><b><d xml:base="hidden/">text</d></b></a>"#
        );
    }

    #[test]
    fn c14n11_inherits_hidden_base_past_selected_baseless_element() {
        // Selected b has no base of its own and cannot restore a's hidden base
        // context. The omitted c makes d an apex, so d must materialize the
        // source base that is otherwise absent from the canonical output.
        let xml = r#"<a xml:base="hidden/"><b><c><d>text</d></c></b></a>"#;
        let doc = Document::parse(xml).unwrap();
        let a = doc.root_element();
        let b = a.first_element_child().unwrap();
        let c = b.first_element_child().unwrap();
        let d = c.first_element_child().unwrap();
        let mut included = HashSet::from([a.id(), b.id(), d.id()]);
        included.extend(d.children().map(|node| node.id()));
        let visibility = HiddenXmlBaseVisibility {
            included,
            hidden_base_owner: a.id(),
        };
        let mut out = Vec::new();

        serialize_canonical_visible_with_position(
            &doc,
            Some(&visibility),
            false,
            &InclusiveNsRenderer,
            C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: true,
            },
            None,
            &mut out,
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"<a><b><d xml:base="hidden/">text</d></b></a>"#
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
