//! Parser-independent retained XML tree consumed by XML Security algorithms.

use std::{
    hash::{Hash, Hasher},
    ops::Range,
};

use super::{ParseError, ParsingOptions, SelectedBackend, XmlBackend};

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

#[derive(Clone, Debug)]
pub(super) struct NodeData {
    pub(super) parent: Option<NodeId>,
    pub(super) children: Vec<NodeId>,
    pub(super) kind: NodeKind,
    pub(super) range: Range<usize>,
    pub(super) subtree_end: u32,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub(super) struct AttributeData {
    pub(super) name: String,
    pub(super) namespace: Option<String>,
    pub(super) prefix: Option<String>,
    pub(super) value: String,
}

#[derive(Clone, Debug)]
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

    pub(super) fn push(
        &mut self,
        parent: Option<NodeId>,
        kind: NodeKind,
        range: Range<usize>,
    ) -> NodeId {
        let id = NodeId(
            u32::try_from(self.nodes.len()).expect("bounded XML node count must fit into u32"),
        );
        self.nodes.push(NodeData {
            parent,
            children: Vec::new(),
            kind,
            range,
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
    pub(super) fn append_text(&mut self, parent: NodeId, value: &str, range: Range<usize>) {
        if let Some(last) = self.nodes[parent.index()].children.last().copied()
            && let NodeKind::Text(existing) = &mut self.nodes[last.index()].kind
        {
            existing.push_str(value);
            self.nodes[last.index()].range.end = range.end;
            return;
        }
        self.push(Some(parent), NodeKind::Text(value.to_owned()), range);
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

    /// Parses XML with the compile-time selected backend.
    pub fn parse_with_options(
        input: &'input str,
        options: ParsingOptions,
    ) -> Result<Self, ParseError> {
        SelectedBackend::parse(input, options)
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
            },
            _ => ExpandedName {
                name: "",
                namespace: None,
            },
        }
    }
    /// Tests an element against a local or expanded name.
    pub fn has_tag_name<'n, N>(self, name: N) -> bool
    where
        N: Into<ExpandedName<'n>>,
    {
        if !self.is_element() {
            return false;
        }
        let name = name.into();
        self.tag_name().name() == name.name()
            && name
                .namespace()
                .is_none_or(|namespace| self.tag_name().namespace() == Some(namespace))
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
            .find(|attr| {
                attr.name() == name.name()
                    && name
                        .namespace()
                        .is_none_or(|namespace| attr.namespace() == Some(namespace))
            })
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
        self.namespaces()
            .find(|ns| ns.name() == prefix)
            .map(Namespace::uri)
    }
    /// Finds an in-scope prefix for a namespace URI.
    pub fn lookup_prefix(self, uri: &str) -> Option<&'a str> {
        self.namespaces()
            .find(|ns| ns.uri() == uri)
            .and_then(Namespace::name)
    }
    /// Returns direct character data, or the first direct text child of an element.
    pub fn text(self) -> Option<&'a str> {
        match &self.data().kind {
            NodeKind::Text(value) | NodeKind::Comment(value) => Some(value),
            NodeKind::Element { .. } => self.children().find_map(Node::text),
            NodeKind::PI { value, .. } => value.as_deref(),
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpandedName<'a> {
    name: &'a str,
    namespace: Option<&'a str>,
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
impl<'a> From<&'a str> for ExpandedName<'a> {
    fn from(name: &'a str) -> Self {
        Self {
            name,
            namespace: None,
        }
    }
}
impl<'a> From<(Option<&'a str>, &'a str)> for ExpandedName<'a> {
    fn from((namespace, name): (Option<&'a str>, &'a str)) -> Self {
        Self { name, namespace }
    }
}
impl<'a> From<(&'a str, &'a str)> for ExpandedName<'a> {
    fn from((namespace, name): (&'a str, &'a str)) -> Self {
        Self {
            name,
            namespace: Some(namespace),
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
    use crate::xml::dom::{ParseError, ParsingOptions};

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
}
