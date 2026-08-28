//! Parser-independent retained XML tree consumed by XML Security algorithms.

#[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
use std::collections::HashMap;
use std::{
    hash::{Hash, Hasher},
    ops::Range,
};

use super::{ParseError, ParsingOptions, XmlBackend};

const XML_NAMESPACE_URI: &str = "http://www.w3.org/XML/1998/namespace";

/// Stable arena index for a node in one parsed document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(u32);

impl NodeId {
    pub(crate) const fn get(self) -> u32 {
        self.0
    }
    pub(crate) fn get_usize(self) -> usize {
        self.index()
    }
    fn index(self) -> usize {
        self.0 as usize
    }
}

impl From<u32> for NodeId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

/// Kind of a semantic XML node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodeType {
    /// Synthetic document root.
    Root,
    /// XML element.
    Element,
    /// Expanded character data.
    Text,
    /// XML comment.
    Comment,
    /// Processing instruction.
    PI,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NodeData {
    pub(super) parent: Option<NodeId>,
    pub(super) children: Vec<NodeId>,
    pub(super) kind: NodeKind,
    pub(super) range: Range<usize>,
    pub(super) range_actionable: bool,
    pub(super) subtree_end: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum NodeKind {
    Root,
    Element {
        name: String,
        namespace: Option<String>,
        prefix: Option<String>,
        attributes: Vec<AttributeData>,
        namespaces: Vec<NamespaceData>,
    },
    Text(String),
    Comment(String),
    PI {
        target: String,
        value: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AttributeData {
    pub(super) name: String,
    pub(super) namespace: Option<String>,
    pub(super) prefix: Option<String>,
    pub(super) value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct NamespaceData {
    pub(super) prefix: Option<String>,
    pub(super) uri: String,
}

/// Builder used by parser adapters to populate the shared semantic arena.
pub(super) struct TreeBuilder<'input> {
    input: &'input str,
    nodes: Vec<NodeData>,
}

impl<'input> TreeBuilder<'input> {
    pub(super) fn new(input: &'input str, capacity: usize) -> Self {
        Self {
            input,
            nodes: Vec::with_capacity(capacity),
        }
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    pub(super) fn push(
        &mut self,
        parent: Option<NodeId>,
        kind: NodeKind,
        range: Range<usize>,
    ) -> NodeId {
        self.push_with_actionability(parent, kind, range, true)
    }

    pub(super) fn push_with_actionability(
        &mut self,
        parent: Option<NodeId>,
        kind: NodeKind,
        range: Range<usize>,
        range_actionable: bool,
    ) -> NodeId {
        let id = NodeId(
            u32::try_from(self.nodes.len()).expect("bounded XML node count must fit into u32"),
        );
        self.nodes.push(NodeData {
            parent,
            children: Vec::new(),
            kind,
            range,
            range_actionable,
            subtree_end: id.0 + 1,
        });
        if let Some(parent) = parent {
            self.nodes[parent.index()].children.push(id);
        }
        id
    }

    pub(super) fn finish_subtree(&mut self, node: NodeId) {
        self.nodes[node.index()].subtree_end =
            u32::try_from(self.nodes.len()).expect("bounded XML node count must fit into u32");
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    pub(super) fn append_text(
        &mut self,
        parent: NodeId,
        value: &str,
        range: Range<usize>,
        range_actionable: bool,
    ) {
        if let Some(last) = self.nodes[parent.index()].children.last().copied()
            && let node = &mut self.nodes[last.index()]
            && let NodeKind::Text(existing) = &mut node.kind
        {
            existing.push_str(value);
            // One semantic text node can fold several adjacent lexical tokens
            // (plain text, CDATA, and references). Its source range must cover
            // every token so mutation never splices only a semantic prefix.
            node.range.start = node.range.start.min(range.start);
            node.range.end = node.range.end.max(range.end);
            node.range_actionable &= range_actionable;
            return;
        }
        self.push_with_actionability(
            Some(parent),
            NodeKind::Text(value.to_owned()),
            range,
            range_actionable,
        );
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    pub(super) fn len(&self) -> usize {
        self.nodes.len()
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    pub(super) fn namespaces(&self, node: NodeId) -> Option<&[NamespaceData]> {
        match &self.nodes[node.index()].kind {
            NodeKind::Element { namespaces, .. } => Some(namespaces),
            _ => None,
        }
    }

    pub(super) fn finish(self) -> Document<'input> {
        Document {
            input: self.input,
            nodes: self.nodes,
        }
    }

    #[cfg(feature = "xml-backend-roxmltree")]
    pub(super) fn input(&self) -> &'input str {
        self.input
    }
}

/// Parsed backend-neutral XML document.
///
/// The selected parser is used only while constructing this arena. C14N,
/// XPath, XMLDSig, XMLEnc, and mutation code never branch on the parser.
#[derive(Debug)]
pub struct Document<'input> {
    input: &'input str,
    nodes: Vec<NodeData>,
}

impl<'input> Document<'input> {
    /// Parses XML with default backend-neutral options.
    pub fn parse(input: &'input str) -> Result<Self, ParseError> {
        Self::parse_with_options(input, ParsingOptions::default())
    }

    /// Parses XML with the build's default backend.
    pub fn parse_with_options(
        input: &'input str,
        options: ParsingOptions,
    ) -> Result<Self, ParseError> {
        Self::parse_with_options_and_backend(input, options, XmlBackend::default())
    }

    /// Parses XML with an explicitly selected compiled backend.
    pub fn parse_with_backend(input: &'input str, backend: XmlBackend) -> Result<Self, ParseError> {
        Self::parse_with_options_and_backend(input, ParsingOptions::default(), backend)
    }

    /// Parses XML with explicit parser options and backend selection.
    pub fn parse_with_options_and_backend(
        input: &'input str,
        options: ParsingOptions,
        backend: XmlBackend,
    ) -> Result<Self, ParseError> {
        let options = crate::document::preflight_dom_limits(input, options)?;
        Self::parse_after_limit_preflight_with_backend(input, options, backend)
    }

    pub(crate) fn parse_after_limit_preflight_with_backend(
        input: &'input str,
        options: ParsingOptions,
        backend: XmlBackend,
    ) -> Result<Self, ParseError> {
        let preflight = super::LexicalPreflight::scan(input, options.allow_dtd)?;
        backend.parse(input, options, &preflight)
    }

    /// Returns the original UTF-8 source.
    pub fn input_text(&self) -> &'input str {
        self.input
    }

    /// Returns the synthetic document root.
    pub fn root(&self) -> Node<'_, 'input> {
        self.get_node(NodeId(0))
            .expect("parsed document has a root")
    }

    /// Returns the document element.
    pub fn root_element(&self) -> Node<'_, 'input> {
        self.root()
            .children()
            .find(Node::is_element)
            .expect("well-formed XML has a document element")
    }

    /// Iterates the document root and all descendants in document order.
    pub fn descendants(&self) -> Descendants<'_, 'input> {
        self.root().descendants()
    }

    /// Resolves an arena node ID in this document.
    pub fn get_node(&self, id: NodeId) -> Option<Node<'_, 'input>> {
        self.nodes
            .get(id.index())
            .map(|_| Node { document: self, id })
    }

    #[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
    pub(super) fn ensure_semantically_equivalent(
        &self,
        other: &Self,
        doctype: Option<&Range<usize>>,
    ) -> Result<(), ParseError> {
        if self.nodes.len() != other.nodes.len() {
            let detail = self
                .nodes
                .iter()
                .zip(&other.nodes)
                .position(|(left, right)| {
                    node_kind_label(&left.kind) != node_kind_label(&right.kind)
                })
                .map_or_else(
                    || "one adapter retained trailing nodes".to_owned(),
                    |index| {
                        format!(
                            "node {index} is {} versus {}",
                            node_kind_label(&self.nodes[index].kind),
                            node_kind_label(&other.nodes[index].kind)
                        )
                    },
                );
            return Err(ParseError::BackendDivergence {
                reason: format!(
                    "retained semantic node counts differ ({} versus {}): {detail}",
                    self.nodes.len(),
                    other.nodes.len()
                ),
            });
        }
        if let Some((index, (left, right))) = self
            .nodes
            .iter()
            .zip(&other.nodes)
            .enumerate()
            .find(|(_, (left, right))| !nodes_semantically_equivalent(left, right, doctype))
        {
            return Err(ParseError::BackendDivergence {
                reason: format!(
                    "retained semantic node {index} differs in {}",
                    node_difference(left, right, doctype)
                ),
            });
        }
        Ok(())
    }
}

#[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
fn node_kind_label(kind: &NodeKind) -> &'static str {
    match kind {
        NodeKind::Root => "root",
        NodeKind::Element { .. } => "element",
        NodeKind::Text(_) => "text",
        NodeKind::Comment(_) => "comment",
        NodeKind::PI { .. } => "processing instruction",
    }
}

#[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
fn nodes_semantically_equivalent(
    left: &NodeData,
    right: &NodeData,
    doctype: Option<&Range<usize>>,
) -> bool {
    left.parent == right.parent
        && left.children == right.children
        && node_kinds_semantically_equivalent(&left.kind, &right.kind)
        && source_ranges_equivalent(&left.range, &right.range, doctype)
        && range_actionability_equivalent(left, right)
        && left.subtree_end == right.subtree_end
}

#[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
fn node_difference(left: &NodeData, right: &NodeData, doctype: Option<&Range<usize>>) -> String {
    if left.parent != right.parent {
        "parent identity".to_owned()
    } else if left.children != right.children {
        "child identities".to_owned()
    } else if !node_kinds_semantically_equivalent(&left.kind, &right.kind) {
        node_kind_difference(&left.kind, &right.kind).to_owned()
    } else if !source_ranges_equivalent(&left.range, &right.range, doctype) {
        format!(
            "source range ({}..{} versus {}..{})",
            left.range.start, left.range.end, right.range.start, right.range.end
        )
    } else if !range_actionability_equivalent(left, right) {
        "source-range actionability".to_owned()
    } else {
        "subtree boundary".to_owned()
    }
}

#[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
fn range_actionability_equivalent(left: &NodeData, right: &NodeData) -> bool {
    // Mutation accepts any semantic node with a unique source span, so backend
    // disagreement about actionability is always security-relevant.
    left.range_actionable == right.range_actionable
}

#[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
fn source_ranges_equivalent(
    left: &Range<usize>,
    right: &Range<usize>,
    doctype: Option<&Range<usize>>,
) -> bool {
    if left == right {
        return true;
    }
    let Some(doctype) = doctype else {
        return false;
    };
    // Entity-expanded nodes have no single lexical span in the instance:
    // roxmltree reports declaration bytes while xmloxide reports reference
    // bytes. Both positions encode the same synthetic entity provenance.
    range_contains(doctype, left) != range_contains(doctype, right)
}

#[cfg(feature = "xml-backend-roxmltree")]
pub(super) fn range_contains(container: &Range<usize>, candidate: &Range<usize>) -> bool {
    candidate.start >= container.start && candidate.end <= container.end
}

#[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
fn node_kinds_semantically_equivalent(left: &NodeKind, right: &NodeKind) -> bool {
    match (left, right) {
        (
            NodeKind::Element {
                name: left_name,
                namespace: left_namespace,
                prefix: left_prefix,
                attributes: left_attributes,
                namespaces: left_namespaces,
            },
            NodeKind::Element {
                name: right_name,
                namespace: right_namespace,
                prefix: right_prefix,
                attributes: right_attributes,
                namespaces: right_namespaces,
            },
        ) => {
            left_name == right_name
                && left_namespace == right_namespace
                && left_prefix == right_prefix
                && left_attributes == right_attributes
                && namespace_axes_equivalent(left_namespaces, right_namespaces)
        }
        _ => left == right,
    }
}

#[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
fn namespace_axes_equivalent(left: &[NamespaceData], right: &[NamespaceData]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut remaining = HashMap::with_capacity(left.len());
    for item in left {
        *remaining.entry(item).or_insert(0_usize) += 1;
    }
    right.iter().all(|item| {
        remaining.get_mut(item).is_some_and(|count| {
            if *count == 0 {
                return false;
            }
            *count -= 1;
            true
        })
    })
}

#[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
fn node_kind_difference(left: &NodeKind, right: &NodeKind) -> &'static str {
    match (left, right) {
        (
            NodeKind::Element {
                name: left_name,
                namespace: left_namespace,
                prefix: left_prefix,
                attributes: left_attributes,
                namespaces: left_namespaces,
            },
            NodeKind::Element {
                name: right_name,
                namespace: right_namespace,
                prefix: right_prefix,
                attributes: right_attributes,
                namespaces: right_namespaces,
            },
        ) => {
            if left_name != right_name {
                "element local name"
            } else if left_namespace != right_namespace {
                match (left_namespace.as_deref(), right_namespace.as_deref()) {
                    (None, Some("")) => "element namespace URI (absent versus empty)",
                    (Some(""), None) => "element namespace URI (empty versus absent)",
                    (None, Some(_)) => "element namespace URI (absent versus non-empty)",
                    (Some(_), None) => "element namespace URI (non-empty versus absent)",
                    _ => "element namespace URI (different non-empty values)",
                }
            } else if left_prefix != right_prefix {
                "element prefix"
            } else if left_attributes != right_attributes {
                "attribute axis"
            } else if !namespace_axes_equivalent(left_namespaces, right_namespaces) {
                "namespace axis"
            } else {
                "element semantics"
            }
        }
        (NodeKind::Text(left), NodeKind::Text(right)) if left != right => "character data",
        (NodeKind::Comment(left), NodeKind::Comment(right)) if left != right => "comment data",
        (NodeKind::PI { .. }, NodeKind::PI { .. }) => "processing instruction data",
        _ => "node kind",
    }
}

/// Copyable handle into a backend-neutral document arena.
#[derive(Clone, Copy, Debug)]
pub struct Node<'a, 'input> {
    document: &'a Document<'input>,
    id: NodeId,
}

impl PartialEq for Node<'_, '_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.document, other.document) && self.id == other.id
    }
}
impl Eq for Node<'_, '_> {}
impl Hash for Node<'_, '_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::from_ref(self.document).hash(state);
        self.id.hash(state);
    }
}

impl<'a, 'input> Node<'a, 'input> {
    fn data(self) -> &'a NodeData {
        &self.document.nodes[self.id.index()]
    }
    /// Returns this node's stable arena ID.
    pub fn id(self) -> NodeId {
        self.id
    }
    /// Returns the owning document.
    pub fn document(self) -> &'a Document<'input> {
        self.document
    }
    /// Returns the semantic node kind.
    pub fn node_type(self) -> NodeType {
        match self.data().kind {
            NodeKind::Root => NodeType::Root,
            NodeKind::Element { .. } => NodeType::Element,
            NodeKind::Text(_) => NodeType::Text,
            NodeKind::Comment(_) => NodeType::Comment,
            NodeKind::PI { .. } => NodeType::PI,
        }
    }
    /// Returns whether this is the synthetic document root.
    pub fn is_root(&self) -> bool {
        self.node_type() == NodeType::Root
    }
    /// Returns whether this is an element.
    pub fn is_element(&self) -> bool {
        self.node_type() == NodeType::Element
    }
    /// Returns whether this is text.
    pub fn is_text(&self) -> bool {
        self.node_type() == NodeType::Text
    }
    /// Returns whether this is a comment.
    pub fn is_comment(&self) -> bool {
        self.node_type() == NodeType::Comment
    }
    /// Returns whether this is a processing instruction.
    pub fn is_pi(&self) -> bool {
        self.node_type() == NodeType::PI
    }
    /// Returns the source byte range represented by this node.
    pub fn range(self) -> Range<usize> {
        self.data().range.clone()
    }
    pub(crate) fn has_actionable_range(self) -> bool {
        self.data().range_actionable
    }
    /// Returns the parent node.
    pub fn parent(self) -> Option<Self> {
        self.data().parent.and_then(|id| self.document.get_node(id))
    }
    /// Returns the parent only when it is an element.
    pub fn parent_element(self) -> Option<Self> {
        self.parent()
            .and_then(|node| node.is_element().then_some(node))
    }
    /// Iterates direct children in document order.
    pub fn children(self) -> Children<'a, 'input> {
        Children {
            document: self.document,
            ids: self.data().children.iter(),
        }
    }
    /// Returns the first direct child node.
    pub fn first_child(self) -> Option<Self> {
        self.children().next()
    }
    /// Returns the first direct element child.
    pub fn first_element_child(self) -> Option<Self> {
        self.children().find(Node::is_element)
    }
    /// Returns the last direct element child.
    pub fn last_element_child(self) -> Option<Self> {
        self.children().rev().find(Node::is_element)
    }
    /// Iterates this node and its descendants in document order.
    pub fn descendants(self) -> Descendants<'a, 'input> {
        Descendants {
            document: self.document,
            ids: self.id.0..self.data().subtree_end,
        }
    }
    /// Iterates this node and then its ancestors.
    pub fn ancestors(self) -> Ancestors<'a, 'input> {
        Ancestors { next: Some(self) }
    }
    /// Returns the preceding sibling.
    pub fn prev_sibling(self) -> Option<Self> {
        let parent = self.parent()?;
        let position = parent
            .data()
            .children
            .iter()
            .position(|id| *id == self.id)?;
        position
            .checked_sub(1)
            .and_then(|index| self.document.get_node(parent.data().children[index]))
    }
    /// Returns the following sibling.
    pub fn next_sibling(self) -> Option<Self> {
        let parent = self.parent()?;
        let position = parent
            .data()
            .children
            .iter()
            .position(|id| *id == self.id)?;
        parent
            .data()
            .children
            .get(position + 1)
            .and_then(|id| self.document.get_node(*id))
    }
    /// Returns the next sibling that is an element.
    pub fn next_sibling_element(self) -> Option<Self> {
        let mut current = self.next_sibling();
        while let Some(node) = current {
            if node.is_element() {
                return Some(node);
            }
            current = node.next_sibling();
        }
        None
    }
    /// Returns the expanded element name, or an empty name for non-elements.
    pub fn tag_name(self) -> ExpandedName<'a> {
        match &self.data().kind {
            NodeKind::Element {
                name, namespace, ..
            } => ExpandedName {
                name,
                namespace: namespace.as_deref(),
                match_namespace: true,
            },
            _ => ExpandedName {
                name: "",
                namespace: None,
                match_namespace: true,
            },
        }
    }
    /// Tests an element against a local-name selector or an exact expanded name.
    ///
    /// A bare string matches any namespace, mirroring roxmltree. Tuple forms
    /// match the namespace exactly, including `(None, name)` for an
    /// unqualified element.
    pub fn has_tag_name<'n, N>(self, name: N) -> bool
    where
        N: Into<ExpandedName<'n>>,
    {
        if !self.is_element() {
            return false;
        }
        let name = name.into();
        self.tag_name().name() == name.name()
            && (!name.match_namespace || self.tag_name().namespace() == name.namespace())
    }
    /// Returns the element's lexical namespace prefix.
    pub fn prefix(self) -> Option<&'a str> {
        match &self.data().kind {
            NodeKind::Element { prefix, .. } => prefix.as_deref(),
            _ => None,
        }
    }
    /// Iterates non-namespace attributes in source order.
    pub fn attributes(self) -> Attributes<'a> {
        let values: &[AttributeData] = match &self.data().kind {
            NodeKind::Element { attributes, .. } => attributes.as_slice(),
            _ => &[],
        };
        Attributes {
            values: values.iter(),
        }
    }
    /// Looks up an unqualified attribute by local name.
    pub fn attribute<'n, N>(self, name: N) -> Option<&'a str>
    where
        N: Into<ExpandedName<'n>>,
    {
        let name = name.into();
        self.attributes()
            .find(|attr| attr.name() == name.name() && attr.namespace() == name.namespace())
            .map(Attribute::value)
    }
    /// Iterates in-scope namespace bindings.
    pub fn namespaces(self) -> Namespaces<'a> {
        let values: &[NamespaceData] = match &self.data().kind {
            NodeKind::Element { namespaces, .. } => namespaces.as_slice(),
            _ => &[],
        };
        Namespaces {
            values: values.iter(),
        }
    }
    /// Resolves a namespace prefix in this element's in-scope bindings.
    pub fn lookup_namespace_uri(self, prefix: Option<&str>) -> Option<&'a str> {
        if prefix == Some("xml") {
            return Some(XML_NAMESPACE_URI);
        }
        self.namespaces()
            .find(|ns| ns.name() == prefix)
            .map(Namespace::uri)
    }
    /// Finds an in-scope prefix for a namespace URI.
    pub fn lookup_prefix(self, uri: &str) -> Option<&'a str> {
        if uri == XML_NAMESPACE_URI {
            return Some("xml");
        }
        self.namespaces()
            .filter(|namespace| namespace.uri() == uri)
            .find_map(Namespace::name)
    }
    /// Returns direct character data, or the first direct text child of an element.
    pub fn text(self) -> Option<&'a str> {
        match &self.data().kind {
            NodeKind::Text(value) | NodeKind::Comment(value) => Some(value),
            NodeKind::Element { .. } => {
                self.first_child()
                    .and_then(|child| match &child.data().kind {
                        NodeKind::Text(value) => Some(value.as_str()),
                        _ => None,
                    })
            }
            NodeKind::PI { .. } => None,
            NodeKind::Root => None,
        }
    }
    /// Returns processing-instruction data for a PI node.
    pub fn pi(self) -> Option<PI<'a>> {
        match &self.data().kind {
            NodeKind::PI { target, value } => Some(PI {
                target,
                value: value.as_deref(),
            }),
            _ => None,
        }
    }
}

/// Expanded XML name used by element and attribute comparisons.
#[derive(Clone, Copy, Debug)]
pub struct ExpandedName<'a> {
    name: &'a str,
    namespace: Option<&'a str>,
    // Selector intent is separate from the represented expanded name so
    // equality remains a comparison of XML names, not matching syntax.
    match_namespace: bool,
}
impl<'a> ExpandedName<'a> {
    /// Returns the local name.
    pub fn name(self) -> &'a str {
        self.name
    }
    /// Returns the namespace URI.
    pub fn namespace(self) -> Option<&'a str> {
        self.namespace
    }
}
impl PartialEq for ExpandedName<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.namespace == other.namespace
    }
}
impl Eq for ExpandedName<'_> {}
impl<'a> From<&'a str> for ExpandedName<'a> {
    fn from(name: &'a str) -> Self {
        Self {
            name,
            namespace: None,
            match_namespace: false,
        }
    }
}
impl<'a> From<(Option<&'a str>, &'a str)> for ExpandedName<'a> {
    fn from((namespace, name): (Option<&'a str>, &'a str)) -> Self {
        Self {
            name,
            namespace,
            match_namespace: true,
        }
    }
}
impl<'a> From<(&'a str, &'a str)> for ExpandedName<'a> {
    fn from((namespace, name): (&'a str, &'a str)) -> Self {
        Self {
            name,
            namespace: Some(namespace),
            match_namespace: true,
        }
    }
}

/// Borrowed semantic XML attribute.
#[derive(Clone, Copy)]
pub struct Attribute<'a> {
    data: &'a AttributeData,
}
impl<'a> Attribute<'a> {
    /// Returns the local name.
    pub fn name(self) -> &'a str {
        &self.data.name
    }
    /// Returns the namespace URI.
    pub fn namespace(self) -> Option<&'a str> {
        self.data.namespace.as_deref()
    }
    /// Returns the expanded value.
    pub fn value(self) -> &'a str {
        &self.data.value
    }
    /// Returns the lexical namespace prefix.
    pub fn prefix(self) -> Option<&'a str> {
        self.data.prefix.as_deref()
    }
}

/// Iterator over element attributes.
pub struct Attributes<'a> {
    values: std::slice::Iter<'a, AttributeData>,
}
impl<'a> Iterator for Attributes<'a> {
    type Item = Attribute<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.values.next().map(|data| Attribute { data })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}
impl ExactSizeIterator for Attributes<'_> {}

/// Borrowed in-scope namespace binding.
#[derive(Clone, Copy)]
pub struct Namespace<'a> {
    data: &'a NamespaceData,
}
impl<'a> Namespace<'a> {
    /// Returns the prefix, or `None` for the default namespace.
    pub fn name(self) -> Option<&'a str> {
        self.data.prefix.as_deref()
    }
    /// Returns the namespace URI.
    pub fn uri(self) -> &'a str {
        &self.data.uri
    }
}

/// Iterator over in-scope namespace bindings.
pub struct Namespaces<'a> {
    values: std::slice::Iter<'a, NamespaceData>,
}
impl<'a> Iterator for Namespaces<'a> {
    type Item = Namespace<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.values.next().map(|data| Namespace { data })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}
impl ExactSizeIterator for Namespaces<'_> {}

/// Processing-instruction payload.
#[derive(Clone, Copy)]
pub struct PI<'a> {
    /// Processing-instruction target.
    pub target: &'a str,
    /// Optional processing-instruction data.
    pub value: Option<&'a str>,
}

/// Iterator over direct child nodes.
pub struct Children<'a, 'input> {
    document: &'a Document<'input>,
    ids: std::slice::Iter<'a, NodeId>,
}
impl<'a, 'input> Iterator for Children<'a, 'input> {
    type Item = Node<'a, 'input>;
    fn next(&mut self) -> Option<Self::Item> {
        self.ids.next().and_then(|id| self.document.get_node(*id))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ids.size_hint()
    }
}
impl ExactSizeIterator for Children<'_, '_> {}
impl<'a, 'input> DoubleEndedIterator for Children<'a, 'input> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.ids
            .next_back()
            .and_then(|id| self.document.get_node(*id))
    }
}

/// Pre-order iterator over a node and its descendants.
pub struct Descendants<'a, 'input> {
    document: &'a Document<'input>,
    ids: Range<u32>,
}
impl<'a, 'input> Iterator for Descendants<'a, 'input> {
    type Item = Node<'a, 'input>;
    fn next(&mut self) -> Option<Self::Item> {
        self.ids
            .next()
            .and_then(|id| self.document.get_node(NodeId(id)))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ids.size_hint()
    }
}
impl DoubleEndedIterator for Descendants<'_, '_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.ids
            .next_back()
            .and_then(|id| self.document.get_node(NodeId(id)))
    }
}
impl ExactSizeIterator for Descendants<'_, '_> {}

/// Iterator over a node and its ancestors.
pub struct Ancestors<'a, 'input> {
    next: Option<Node<'a, 'input>>,
}
impl<'a, 'input> Iterator for Ancestors<'a, 'input> {
    type Item = Node<'a, 'input>;
    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next?;
        self.next = current.parent();
        Some(current)
    }
}

#[cfg(test)]
mod tests {
    use super::Document;
    #[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
    use super::{NamespaceData, namespace_axes_equivalent};
    use crate::xml::dom::{ParseError, ParsingOptions, XmlBackend};

    #[test]
    fn runtime_selection_never_falls_back_to_a_compiled_backend() {
        // A stable selector can be supplied by application configuration even
        // in a thin build. Missing implementations must fail explicitly.
        for backend in [
            XmlBackend::Xmloxide,
            XmlBackend::Roxmltree,
            XmlBackend::Differential,
        ] {
            let result = Document::parse_with_backend("<r/>", backend);
            if backend.is_available() {
                assert!(result.is_ok(), "{backend:?} should be available");
            } else {
                assert_eq!(
                    result.expect_err("an unavailable backend must not fall back"),
                    ParseError::BackendUnavailable { backend }
                );
            }
        }
    }

    #[cfg(feature = "xml-backend-differential")]
    #[test]
    fn compatibility_feature_selects_differential_by_default() {
        assert_eq!(XmlBackend::default(), XmlBackend::Differential);
    }

    #[cfg(all(
        feature = "xml-backend-xmloxide",
        feature = "xml-backend-roxmltree",
        not(feature = "xml-backend-differential")
    ))]
    #[test]
    fn fat_build_defaults_to_xmloxide_without_implicit_double_parsing() {
        assert_eq!(XmlBackend::default(), XmlBackend::Xmloxide);
    }

    #[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
    #[test]
    fn fat_build_selects_each_semantically_equivalent_runtime_mode() {
        // Runtime selection changes only arena construction; downstream XML
        // Security semantics and stable source ranges remain identical.
        let xml = r#"<r xmlns:p="urn:p"><p:a x="1">value</p:a></r>"#;
        let snapshot = |backend| {
            let document = Document::parse_with_backend(xml, backend)
                .expect("every compiled runtime mode must parse the fixture");
            document
                .descendants()
                .map(|node| {
                    (
                        node.node_type(),
                        node.range(),
                        node.text().map(str::to_owned),
                    )
                })
                .collect::<Vec<_>>()
        };

        let xmloxide = snapshot(XmlBackend::Xmloxide);
        assert_eq!(snapshot(XmlBackend::Roxmltree), xmloxide);
        assert_eq!(snapshot(XmlBackend::Differential), xmloxide);
    }

    #[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
    #[test]
    fn differential_namespace_axis_comparison_preserves_multiplicity() {
        // The fail-closed gate must reject unequal axes even if a malformed
        // backend projection repeats one binding and hides another.
        let binding = |prefix: &str, uri: &str| NamespaceData {
            prefix: Some(prefix.to_owned()),
            uri: uri.to_owned(),
        };
        let a = binding("a", "urn:a");
        let b = binding("b", "urn:b");

        assert!(!namespace_axes_equivalent(
            &[a.clone(), a.clone()],
            &[a.clone(), b.clone()]
        ));
        assert!(!namespace_axes_equivalent(
            &[a.clone(), b],
            &[a.clone(), a.clone()]
        ));
        assert!(namespace_axes_equivalent(
            &[a.clone(), a.clone()],
            &[a.clone(), a]
        ));
    }

    #[test]
    fn selected_backend_preserves_element_source_ranges() {
        // Mutation must splice exact element ranges under either parser.
        let xml = "<?p before?><root><empty/><child>value</child></root><!--after-->";
        let document = Document::parse(xml).expect("fixture must parse");
        let root = document.root_element();
        let child = root
            .children()
            .find(|node| node.has_tag_name("child"))
            .expect("fixture must contain the child element");
        assert_eq!(
            &xml[root.range()],
            "<root><empty/><child>value</child></root>"
        );
        assert_eq!(&xml[child.range()], "<child>value</child>");
    }

    #[test]
    fn selected_backend_materializes_shadowed_namespace_axis() {
        // C14N observes the complete in-scope axis, including undeclarations.
        let document = Document::parse(
            r#"<r xmlns="urn:outer" xmlns:p="urn:p1"><p:a xmlns:p="urn:p2" xmlns=""><p:b/></p:a></r>"#,
        ).expect("fixture must parse");
        let child = document
            .descendants()
            .find(|node| node.has_tag_name(("urn:p2", "b")))
            .expect("fixture must contain the namespaced descendant");
        assert_eq!(child.lookup_namespace_uri(Some("p")), Some("urn:p2"));
        assert_eq!(child.lookup_namespace_uri(None), Some(""));
        assert_eq!(child.namespaces().count(), 2);
    }

    #[test]
    fn tag_name_matcher_distinguishes_local_from_unqualified_names() {
        // A bare string mirrors roxmltree's local-name selector, while an
        // explicit optional namespace represents exact expanded-name intent.
        let document = Document::parse(r#"<r xmlns:p="urn:p"><item/><p:item/></r>"#)
            .expect("namespace matching fixture must parse");
        let mut items = document
            .root_element()
            .children()
            .filter(|node| node.is_element());
        let unqualified = items.next().expect("unqualified item must exist");
        let namespaced = items.next().expect("namespaced item must exist");

        assert!(unqualified.has_tag_name("item"));
        assert!(namespaced.has_tag_name("item"));
        assert!(unqualified.has_tag_name((None, "item")));
        assert!(!namespaced.has_tag_name((None, "item")));
        assert!(namespaced.has_tag_name((Some("urn:p"), "item")));
    }

    #[test]
    fn namespace_lookup_includes_the_predefined_xml_binding() {
        // Namespaces in XML binds `xml` on every element without requiring a
        // lexical declaration in the source document.
        let document = Document::parse("<root><child xml:lang=\"en\"/></root>")
            .expect("predefined namespace fixture must parse");
        let child = document
            .root_element()
            .first_element_child()
            .expect("fixture must contain a child");

        assert_eq!(
            child.lookup_namespace_uri(Some("xml")),
            Some("http://www.w3.org/XML/1998/namespace")
        );
        assert_eq!(
            child.lookup_prefix("http://www.w3.org/XML/1998/namespace"),
            Some("xml")
        );
    }

    #[test]
    fn selected_backend_folds_cdata_and_entities_into_one_text_node() {
        // XMLDSig defines character data after entity and CDATA expansion.
        let document = Document::parse_with_options(
            "<!DOCTYPE r [<!ENTITY value 'two'>]><r>one<![CDATA[+]]>&value;three</r>",
            ParsingOptions {
                allow_dtd: true,
                nodes_limit: 8,
            },
        )
        .expect("bounded internal entity fixture must parse");
        let text = document
            .root_element()
            .children()
            .filter(|node| node.is_text())
            .collect::<Vec<_>>();
        assert_eq!(text.len(), 1);
        assert_eq!(text[0].text(), Some("one+twothree"));
    }

    #[test]
    fn selected_backend_maps_builtin_references_into_the_surrounding_text_range() {
        // xmloxide expands predefined references into its adjacent text node;
        // the lexical sidecar must mirror that boundary rather than invent a
        // second semantic text node or lose the original source range.
        let xml = "<r>left&amp;right</r>";
        let document = Document::parse(xml).expect("fixture must parse");
        let text = document
            .root_element()
            .first_child()
            .expect("text child must exist");

        assert_eq!(text.text(), Some("left&right"));
        assert_eq!(&xml[text.range()], "left&amp;right");
    }

    #[test]
    fn selected_backend_rejects_dtd_before_building_a_tree() {
        // The parser option must fail closed before backend-specific handling.
        assert_eq!(
            Document::parse("<!DOCTYPE r><r/>")
                .expect_err("DTD-disabled parsing must reject a document type"),
            ParseError::DtdDetected,
        );
    }

    #[test]
    fn selected_backend_enforces_semantic_node_limit_after_text_folding() {
        // The shared ceiling counts retained nodes rather than lexical events.
        let error = Document::parse_with_options(
            "<r><a/><b/></r>",
            ParsingOptions {
                allow_dtd: false,
                nodes_limit: 3,
            },
        )
        .expect_err("the semantic node limit must reject the fourth node");
        assert_eq!(error, ParseError::NodesLimitReached);
    }

    #[test]
    fn selected_backend_enforces_the_absolute_node_ceiling_before_dom_allocation() {
        // Direct DOM callers may request an unbounded parser, but the crate's
        // process-safety ceiling must still stop a compact wide document before
        // either backend allocates its complete native tree.
        let count = crate::hard_limits::XML_DOCUMENT_NODE_CEILING as usize;
        let xml = format!("<r>{}</r>", "<n/>".repeat(count));

        assert_eq!(
            Document::parse_with_options(
                &xml,
                ParsingOptions {
                    allow_dtd: false,
                    nodes_limit: u32::MAX,
                },
            )
            .expect_err("the absolute retained-node ceiling must remain effective"),
            ParseError::NodesLimitReached,
        );
    }

    #[test]
    fn selected_backend_enforces_the_absolute_byte_ceiling_before_dom_allocation() {
        // Direct semantic-DOM callers have no policy object that can bound the
        // source, so the crate ceiling must run before either native backend.
        let maximum = crate::hard_limits::XML_DOCUMENT_BYTE_CEILING;
        let xml = format!("<r>{}</r>", "x".repeat(maximum));
        let expected = ParseError::ByteLimitReached {
            maximum,
            actual: xml.len(),
        };

        assert_eq!(
            Document::parse(&xml)
                .expect_err("default direct parsing must enforce the byte ceiling"),
            expected,
        );
        assert_eq!(
            Document::parse_with_options(
                &xml,
                ParsingOptions {
                    allow_dtd: false,
                    nodes_limit: u32::MAX,
                },
            )
            .expect_err("custom direct parsing must retain the absolute byte ceiling"),
            expected,
        );
    }

    #[test]
    fn selected_backend_bounds_direct_entity_expansion_count() {
        // A shallow sequence of references bypasses roxmltree's nested-entity
        // loop detector. Direct DOM parsing still needs a finite aggregate cap.
        let references =
            "&value;".repeat(crate::hard_limits::XML_ENTITY_EXPANSION_CEILING as usize + 1);
        let xml = format!("<!DOCTYPE r [<!ENTITY value 'x'>]><r>{references}</r>");

        assert!(matches!(
            Document::parse_with_options(
                &xml,
                ParsingOptions {
                    allow_dtd: true,
                    nodes_limit: u32::MAX,
                },
            ),
            Err(ParseError::EntityExpansionLimitReached { maximum, actual })
                if maximum == crate::hard_limits::XML_ENTITY_EXPANSION_CEILING
                    && actual == maximum + 1
        ));
    }

    #[test]
    fn selected_backend_bounds_source_positions_after_semantic_text_folding() {
        // Many adjacent CDATA tokens retain one semantic text node, but the
        // xmloxide range adapter still needs one source position per token.
        // Bound that sidecar independently before constructing a backend DOM.
        let segments = crate::hard_limits::XML_SOURCE_POSITION_CEILING + 1;
        let xml = format!("<r>{}</r>", "<![CDATA[x]]>".repeat(segments));

        assert!(matches!(
            Document::parse_with_options(
                &xml,
                ParsingOptions {
                    allow_dtd: false,
                    nodes_limit: 3,
                },
            ),
            Err(ParseError::SourcePositionLimitReached { maximum, actual })
                if maximum == crate::hard_limits::XML_SOURCE_POSITION_CEILING
                    && actual == maximum + 1
        ));
    }

    #[test]
    fn unqualified_attribute_lookup_requires_no_namespace() {
        // Schema attributes such as Algorithm and URI are unqualified. A
        // same-local-name extension attribute must never satisfy that lookup.
        let document = Document::parse(
            r#"<r xmlns:evil="urn:evil" evil:Algorithm="extension" Algorithm="schema"/>"#,
        )
        .expect("fixture must parse");
        let root = document.root_element();

        assert_eq!(root.attribute("Algorithm"), Some("schema"));
        assert_eq!(root.attribute(("urn:evil", "Algorithm")), Some("extension"));

        let extension_only =
            Document::parse(r#"<r xmlns:evil="urn:evil" evil:Algorithm="extension"/>"#)
                .expect("fixture must parse");
        assert_eq!(extension_only.root_element().attribute("Algorithm"), None);
    }

    #[test]
    fn node_text_preserves_character_data_contract() {
        // PI data is not character data, and element text follows the first
        // direct child contract rather than searching later descendants.
        let document = Document::parse("<r><?p hidden?>visible</r>").expect("fixture must parse");
        let root = document.root_element();
        let pi = root.first_child().expect("PI must exist");

        assert_eq!(pi.text(), None);
        assert_eq!(pi.pi().and_then(|value| value.value), Some("hidden"));
        assert_eq!(root.text(), None);
        assert_eq!(
            pi.next_sibling().and_then(|node| node.text()),
            Some("visible")
        );

        let nested =
            Document::parse("<r><child>nested</child>later</r>").expect("fixture must parse");
        assert_eq!(nested.root_element().text(), None);
    }

    #[test]
    fn selected_backend_rejects_deep_documents_before_dom_parsing() {
        // Direct DOM callers do not run operation-policy preflight. The common
        // lexical pass must enforce the absolute ceiling before either DOM.
        const DEPTH: usize = 20_000;
        let mut xml = String::with_capacity(DEPTH * 7);
        xml.push_str(&"<n>".repeat(DEPTH));
        xml.push_str(&"</n>".repeat(DEPTH));

        assert!(matches!(
            Document::parse(&xml),
            Err(ParseError::DepthLimitReached { maximum, actual })
                if maximum == crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING
                    && actual == maximum + 1
        ));
    }

    #[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
    #[test]
    fn differential_comparison_fails_closed_on_semantic_divergence() {
        // Differential mode must reject adapter disagreement rather than
        // silently selecting one parser's interpretation of attacker input.
        let left = Document::parse("<r><a/></r>").expect("fixture must parse");
        let mut right = Document::parse("<r><a/></r>").expect("fixture must parse");
        right.nodes[2].range.end -= 1;

        assert!(matches!(
            left.ensure_semantically_equivalent(&right, None),
            Err(ParseError::BackendDivergence { .. })
        ));
    }

    #[test]
    fn dtd_internal_comments_are_not_document_nodes() {
        // A `]` or `>` in an internal-subset comment must not terminate DTD
        // range detection and leak that comment into the semantic document.
        let document = Document::parse_with_options(
            "<!--before--><!DOCTYPE r [<!-- ] > --><!ENTITY value 'ok'>]><r>&value;</r><!--after-->",
            ParsingOptions {
                allow_dtd: true,
                ..ParsingOptions::default()
            },
        )
        .expect("DTD fixture must parse");
        let root = document.root();
        let comments = root
            .descendants()
            .filter(|node| node.is_comment())
            .filter_map(|node| node.text())
            .collect::<Vec<_>>();

        assert_eq!(comments, ["before", "after"]);
        assert_eq!(
            root.descendants()
                .find(|node| node.is_text())
                .and_then(|node| node.text()),
            Some("ok")
        );
    }

    #[test]
    fn dtd_range_ignores_doctype_text_in_prolog_nodes() {
        // DOCTYPE-like text in ordinary prolog nodes must not redirect DTD
        // filtering away from the actual declaration and leak subset nodes.
        let document = Document::parse_with_options(
            "<!-- <!DOCTYPE fake> --><?probe <!DOCTYPE fake> ?><!DOCTYPE r [<!--hidden-->]><r/>",
            ParsingOptions {
                allow_dtd: true,
                ..ParsingOptions::default()
            },
        )
        .expect("DTD fixture must parse");
        let root = document.root();
        let comments = root
            .children()
            .filter(|node| node.is_comment())
            .filter_map(|node| node.text())
            .collect::<Vec<_>>();
        let processing_instructions = root
            .children()
            .filter(|node| node.is_pi())
            .filter_map(|node| node.pi())
            .collect::<Vec<_>>();

        assert_eq!(comments, [" <!DOCTYPE fake> "]);
        assert_eq!(processing_instructions.len(), 1);
        assert_eq!(processing_instructions[0].target, "probe");
    }

    #[cfg(feature = "xml-backend-roxmltree")]
    #[test]
    fn dtd_range_scanning_accepts_unicode_names() {
        // Scanner offsets are bytes; a multibyte XML name must not become an
        // invalid UTF-8 slicing boundary while locating the DTD terminator.
        let input = "<!DOCTYPE r [<!ENTITY café 'ok'>]><r/>";
        let end = input.find("><r/>").expect("fixture has document root") + 1;

        let preflight = super::super::LexicalPreflight::scan(input, true)
            .expect("Unicode DTD fixture must pass lexical preflight");
        assert_eq!(preflight.doctype_range(), Some(&(0..end)));
    }
}
