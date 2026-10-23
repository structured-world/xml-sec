//! Parser-independent retained XML tree consumed by XML Security algorithms.

use std::{
    hash::{Hash, Hasher},
    ops::Range,
};

use super::storage::{Native, Storage, Values};
use super::{ParseError, ParsingOptions, XmlBackend};

#[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
pub(super) mod comparison;

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

pub(super) struct NodeData<S: Storage = Native> {
    pub(super) parent: Option<NodeId>,
    pub(super) children: S::Values<NodeId>,
    pub(super) kind: NodeKind<S>,
    pub(super) range: Range<usize>,
    pub(super) range_actionable: bool,
    pub(super) subtree_end: u32,
    // Document-order XPath index: the node itself, then its attribute and
    // namespace nodes, so every subtree occupies one contiguous index range.
    #[cfg(feature = "xmldsig")]
    pub(super) xpath_start: u32,
}

pub(super) enum NodeKind<S: Storage = Native> {
    Root,
    Element {
        name: S::Text,
        namespace: Option<S::Text>,
        prefix: Option<S::Text>,
        attributes: S::Values<AttributeData<S>>,
        namespaces: S::Values<NamespaceData<S>>,
    },
    Text(S::Text),
    Comment(S::Text),
    PI {
        target: S::Text,
        value: Option<S::Text>,
    },
}

pub(super) struct AttributeData<S: Storage = Native> {
    pub(super) name: S::Text,
    pub(super) namespace: Option<S::Text>,
    pub(super) prefix: Option<S::Text>,
    pub(super) value: S::Text,
    pub(super) is_id: bool,
    pub(super) xml_id_error: Option<XmlIdError>,
}

/// Non-fatal xml:id constraint diagnostic; ID type assignment is preserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmlIdError {
    /// The normalized value is not an XML `NCName`.
    InvalidNcName,
    /// A declaration assigns a type other than ID to this xml:id attribute.
    InvalidDeclaredType,
    /// Both the normalized value and a declared type violate the constraints.
    InvalidNcNameAndDeclaredType,
}

pub(super) struct NamespaceData<S: Storage = Native> {
    pub(super) prefix: Option<S::Text>,
    pub(super) uri: S::Text,
}

impl<S: Storage> std::fmt::Debug for AttributeData<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttributeData")
            .field("name", &self.name)
            .field("namespace", &self.namespace)
            .field("prefix", &self.prefix)
            .field("value", &self.value)
            .field("is_id", &self.is_id)
            .field("xml_id_error", &self.xml_id_error)
            .finish()
    }
}
impl<S: Storage> PartialEq for AttributeData<S> {
    fn eq(&self, other: &Self) -> bool {
        self.name.as_ref() == other.name.as_ref()
            && self.namespace.as_deref() == other.namespace.as_deref()
            && self.prefix.as_deref() == other.prefix.as_deref()
            && self.value.as_ref() == other.value.as_ref()
            && self.is_id == other.is_id
            && self.xml_id_error == other.xml_id_error
    }
}
impl<S: Storage> Eq for AttributeData<S> {}
impl<S: Storage> std::fmt::Debug for NamespaceData<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamespaceData")
            .field("prefix", &self.prefix)
            .field("uri", &self.uri)
            .finish()
    }
}
impl<S: Storage> PartialEq for NamespaceData<S> {
    fn eq(&self, other: &Self) -> bool {
        self.prefix.as_deref() == other.prefix.as_deref() && self.uri.as_ref() == other.uri.as_ref()
    }
}
impl<S: Storage> Eq for NamespaceData<S> {}
impl<S: Storage> Hash for NamespaceData<S> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.prefix.as_deref().hash(state);
        self.uri.as_ref().hash(state);
    }
}
impl<S: Storage> Clone for NamespaceData<S>
where
    S::Text: Clone,
{
    fn clone(&self) -> Self {
        Self {
            prefix: self.prefix.clone(),
            uri: self.uri.clone(),
        }
    }
}
impl<S: Storage> std::fmt::Debug for NodeKind<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => f.write_str("Root"),
            Self::Text(value) => f.debug_tuple("Text").field(value).finish(),
            Self::Comment(value) => f.debug_tuple("Comment").field(value).finish(),
            Self::PI { target, value } => f
                .debug_struct("PI")
                .field("target", target)
                .field("value", value)
                .finish(),
            Self::Element {
                name,
                namespace,
                prefix,
                attributes,
                namespaces,
            } => f
                .debug_struct("Element")
                .field("name", name)
                .field("namespace", namespace)
                .field("prefix", prefix)
                .field("attributes", &&attributes[..])
                .field("namespaces", &&namespaces[..])
                .finish(),
        }
    }
}
impl<S: Storage> PartialEq for NodeKind<S> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Root, Self::Root) => true,
            (Self::Text(a), Self::Text(b)) | (Self::Comment(a), Self::Comment(b)) => {
                a.as_ref() == b.as_ref()
            }
            (
                Self::PI {
                    target: a,
                    value: av,
                },
                Self::PI {
                    target: b,
                    value: bv,
                },
            ) => a.as_ref() == b.as_ref() && av.as_deref() == bv.as_deref(),
            (
                Self::Element {
                    name: a,
                    namespace: an,
                    prefix: ap,
                    attributes: aa,
                    namespaces: ans,
                },
                Self::Element {
                    name: b,
                    namespace: bn,
                    prefix: bp,
                    attributes: ba,
                    namespaces: bns,
                },
            ) => {
                a.as_ref() == b.as_ref()
                    && an.as_deref() == bn.as_deref()
                    && ap.as_deref() == bp.as_deref()
                    && aa[..] == ba[..]
                    && ans[..] == bns[..]
            }
            _ => false,
        }
    }
}
impl<S: Storage> Eq for NodeKind<S> {}
impl<S: Storage> std::fmt::Debug for NodeData<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeData")
            .field("parent", &self.parent)
            .field("children", &&self.children[..])
            .field("kind", &self.kind)
            .field("range", &self.range)
            .field("range_actionable", &self.range_actionable)
            .field("subtree_end", &self.subtree_end)
            .finish_non_exhaustive()
    }
}

/// Builder used by parser adapters to populate the shared semantic arena.
pub(super) struct TreeBuilder<'input, S: Storage = Native> {
    input: &'input str,
    nodes: S::Values<NodeData<S>>,
    storage: S,
}

impl<'input, S: Storage> TreeBuilder<'input, S> {
    pub(super) fn storage(&self) -> S {
        self.storage
    }
    pub(super) fn new(input: &'input str, capacity: usize, storage: S) -> Result<Self, ParseError> {
        Ok(Self {
            input,
            nodes: storage.values(capacity)?,
            storage,
        })
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    pub(super) fn push(
        &mut self,
        parent: Option<NodeId>,
        kind: NodeKind<S>,
        range: Range<usize>,
    ) -> Result<NodeId, ParseError> {
        self.push_with_actionability(parent, kind, range, true)
    }

    pub(super) fn push_with_actionability(
        &mut self,
        parent: Option<NodeId>,
        kind: NodeKind<S>,
        range: Range<usize>,
        range_actionable: bool,
    ) -> Result<NodeId, ParseError> {
        let id = NodeId(
            u32::try_from(self.nodes.len()).expect("bounded XML node count must fit into u32"),
        );
        self.nodes.push(NodeData {
            parent,
            children: self.storage.values(0)?,
            kind,
            range,
            range_actionable,
            subtree_end: id.0 + 1,
            #[cfg(feature = "xmldsig")]
            xpath_start: 0,
        })?;
        if let Some(parent) = parent {
            self.nodes[parent.index()].children.push(id)?;
        }
        Ok(id)
    }

    pub(super) fn finish_subtree(&mut self, node: NodeId) {
        self.nodes[node.index()].subtree_end =
            u32::try_from(self.nodes.len()).expect("bounded XML node count must fit into u32");
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    pub(super) fn has_text_tail(&self, parent: NodeId) -> bool {
        self.nodes[parent.index()]
            .children
            .last()
            .is_some_and(|last| matches!(self.nodes[last.index()].kind, NodeKind::Text(_)))
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    pub(super) fn append_text(
        &mut self,
        parent: NodeId,
        value: &str,
        range: Range<usize>,
        range_actionable: bool,
    ) -> Result<(), ParseError> {
        if let Some(last) = self.nodes[parent.index()].children.last().copied()
            && let node = &mut self.nodes[last.index()]
            && let NodeKind::Text(existing) = &mut node.kind
        {
            self.storage.append(existing, value)?;
            // One semantic text node can fold several adjacent lexical tokens
            // (plain text, CDATA, and references). Its source range must cover
            // every token so mutation never splices only a semantic prefix.
            node.range.start = node.range.start.min(range.start);
            node.range.end = node.range.end.max(range.end);
            node.range_actionable &= range_actionable;
            return Ok(());
        }
        self.push_with_actionability(
            Some(parent),
            NodeKind::Text(self.storage.text(value)?),
            range,
            range_actionable,
        )?;
        Ok(())
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    pub(super) fn len(&self) -> usize {
        self.nodes.len()
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    pub(super) fn namespaces(&self, node: NodeId) -> Option<&[NamespaceData<S>]> {
        match &self.nodes[node.index()].kind {
            NodeKind::Element { namespaces, .. } => Some(namespaces),
            _ => None,
        }
    }

    pub(super) fn finish<P: Storage>(
        mut self,
        preflight: &super::LexicalPreflight<'_, P>,
    ) -> Result<Document<'input, S>, ParseError> {
        self.storage.charge(self.nodes.len())?;
        #[cfg(feature = "xmldsig")]
        let mut xpath_nodes = 0_u32;
        for node in &mut *self.nodes {
            #[cfg(feature = "xmldsig")]
            {
                node.xpath_start = xpath_nodes;
                let axes = match &node.kind {
                    NodeKind::Element {
                        attributes,
                        namespaces,
                        ..
                    } => attributes.len().checked_add(namespaces.len()),
                    _ => Some(0),
                };
                xpath_nodes = axes
                    .and_then(|axes| u32::try_from(axes).ok())
                    .and_then(|axes| axes.checked_add(1))
                    .and_then(|count| xpath_nodes.checked_add(count))
                    .ok_or(ParseError::NodesLimitReached)?;
            }
            if let NodeKind::Element {
                name,
                prefix,
                attributes,
                ..
            } = &mut node.kind
            {
                self.storage.charge(attributes.len())?;
                for attribute in &mut **attributes {
                    let xml_id = attribute.namespace.as_deref() == Some(XML_NAMESPACE_URI)
                        && attribute.name.as_ref() == "id";
                    let declaration = preflight.attribute_declaration(
                        prefix.as_deref(),
                        name.as_ref(),
                        attribute.prefix.as_deref(),
                        attribute.name.as_ref(),
                    )?;
                    attribute.is_id = xml_id
                        || declaration
                            .is_some_and(|info| info.kind == crate::document::DtdAttributeType::Id);
                    if attribute.is_id {
                        // xml:id section 4 and XML 1.0 section 3.3.3 require
                        // ID normalization in the infoset, not just the index.
                        // https://www.w3.org/TR/2005/REC-xml-id-20050909/#processing
                        // https://www.w3.org/TR/2008/REC-xml-20081126/#AVNormalize
                        self.storage.normalize_id(&mut attribute.value)?;
                        if xml_id {
                            // xml:id sections 4/6: report constraints without
                            // suppressing assignment or making parsing fatal.
                            // https://www.w3.org/TR/2005/REC-xml-id-20050909/#processing
                            self.storage.charge(attribute.value.as_ref().len())?;
                            let invalid_value =
                                !crate::xml::is_xml_ncname(attribute.value.as_ref());
                            let invalid_type =
                                declaration.is_some_and(|info| info.has_non_id_declaration);
                            attribute.xml_id_error = match (invalid_value, invalid_type) {
                                (true, false) => Some(XmlIdError::InvalidNcName),
                                (false, true) => Some(XmlIdError::InvalidDeclaredType),
                                (true, true) => Some(XmlIdError::InvalidNcNameAndDeclaredType),
                                (false, false) => None,
                            };
                        }
                    }
                }
            }
        }
        Ok(Document {
            input: self.input,
            nodes: self.nodes,
            #[cfg(feature = "xmldsig")]
            xpath_nodes,
        })
    }

    #[cfg(feature = "xml-backend-roxmltree")]
    pub(super) fn input(&self) -> &'input str {
        self.input
    }
}

/// Parsed backend-neutral XML document.
///
/// The selected parser is used only while constructing this arena. C14N,
/// `XPath`, `XMLDSig`, `XMLEnc`, and mutation code never branch on the parser.
pub struct Document<'input, S: Storage = Native> {
    input: &'input str,
    nodes: S::Values<NodeData<S>>,
    #[cfg(feature = "xmldsig")]
    xpath_nodes: u32,
}

impl<S: Storage> std::fmt::Debug for Document<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Document")
            .field("input", &self.input)
            .field("nodes", &&self.nodes[..])
            .finish()
    }
}

impl<'input> Document<'input> {
    /// Parses XML with default backend-neutral options.
    ///
    /// # Errors
    /// Rejects malformed XML and inputs exceeding parser safety ceilings.
    pub fn parse(input: &'input str) -> Result<Self, ParseError> {
        Self::parse_with_options(input, ParsingOptions::default())
    }

    /// Parses XML with the build's default backend.
    ///
    /// # Errors
    /// Rejects malformed XML, disallowed DTDs and inputs exceeding `options`.
    pub fn parse_with_options(
        input: &'input str,
        options: ParsingOptions,
    ) -> Result<Self, ParseError> {
        Self::parse_with_options_and_backend(input, options, XmlBackend::default())
    }

    /// Parses XML with an explicitly selected compiled backend.
    ///
    /// # Errors
    /// Returns parse/limit, unavailable-backend or differential-mismatch errors.
    pub fn parse_with_backend(input: &'input str, backend: XmlBackend) -> Result<Self, ParseError> {
        Self::parse_with_options_and_backend(input, ParsingOptions::default(), backend)
    }

    /// Parses XML with explicit parser options and backend selection.
    ///
    /// # Errors
    /// Returns parse/limit, unavailable-backend or differential-mismatch errors.
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

    #[cfg(feature = "xmldsig")]
    pub(crate) fn parse_after_limit_preflight_in<'w, W: structured_asn1::memory::Work>(
        input: &'input str,
        options: ParsingOptions,
        backend: XmlBackend,
        storage: super::storage::Accounted<'w, W>,
    ) -> Result<Document<'input, super::storage::Accounted<'w, W>>, super::AccountedParseError>
    {
        let preflight = super::LexicalPreflight::scan_in(input, options.allow_dtd, storage)?;
        backend.parse_in(input, options, &preflight, storage)
    }
}

impl<'input, S: Storage> Document<'input, S> {
    #[cfg(feature = "xmldsig")]
    pub(crate) fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the original UTF-8 source.
    pub fn input_text(&self) -> &'input str {
        self.input
    }

    /// Returns the synthetic document root.
    ///
    /// # Panics
    /// Panics only if the internally constructed arena lacks its mandatory root.
    pub fn root(&self) -> Node<'_, 'input, S> {
        self.get_node(NodeId(0))
            .expect("parsed document has a root")
    }

    /// Returns the document element.
    ///
    /// # Panics
    /// Panics only if the internally validated arena lacks a document element.
    pub fn root_element(&self) -> Node<'_, 'input, S> {
        self.root()
            .children()
            .find(Node::is_element)
            .expect("well-formed XML has a document element")
    }

    /// Iterates the document root and all descendants in document order.
    pub fn descendants(&self) -> Descendants<'_, 'input, S> {
        self.root().descendants()
    }

    /// Resolves an arena node ID in this document.
    pub fn get_node(&self, id: NodeId) -> Option<Node<'_, 'input, S>> {
        self.nodes
            .get(id.index())
            .map(|_| Node { document: self, id })
    }

    /// Number of `XPath` nodes: tree nodes with their attribute and namespace nodes.
    #[cfg(feature = "xmldsig")]
    pub(crate) fn xpath_node_count(&self) -> u32 {
        self.xpath_nodes
    }

    /// Tree node owning a document-order `XPath` index (itself for tree nodes).
    #[cfg(feature = "xmldsig")]
    pub(crate) fn xpath_owner(&self, index: u32) -> Option<Node<'_, 'input, S>> {
        if index >= self.xpath_nodes {
            return None;
        }
        // The root starts at index zero, so every valid index has an owner.
        let owner = self.nodes.partition_point(|node| node.xpath_start <= index) - 1;
        self.get_node(NodeId(
            u32::try_from(owner).expect("bounded XML node count must fit into u32"),
        ))
    }
}

impl Document<'_> {
    #[cfg(all(
        test,
        feature = "xml-backend-roxmltree",
        feature = "xml-backend-xmloxide"
    ))]
    pub(super) fn ensure_semantically_equivalent(
        &self,
        other: &Self,
        doctype: Option<&Range<usize>>,
    ) -> Result<(), ParseError> {
        self.ensure_semantically_equivalent_in(other, doctype, Native)
    }
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

/// Copyable handle into a backend-neutral document arena.
#[derive(Clone, Copy)]
pub struct Node<'a, 'input, S: Storage = Native> {
    document: &'a Document<'input, S>,
    id: NodeId,
}

impl<S: Storage> std::fmt::Debug for Node<'_, '_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("document", &self.document)
            .field("id", &self.id)
            .finish()
    }
}
impl<S: Storage> PartialEq for Node<'_, '_, S> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.document, other.document) && self.id == other.id
    }
}
impl<S: Storage> Eq for Node<'_, '_, S> {}
impl<S: Storage> Hash for Node<'_, '_, S> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::from_ref(self.document).hash(state);
        self.id.hash(state);
    }
}

impl<'a, 'input, S: Storage> Node<'a, 'input, S> {
    fn data(self) -> &'a NodeData<S> {
        &self.document.nodes[self.id.index()]
    }
    /// Returns this node's stable arena ID.
    #[must_use]
    pub fn id(self) -> NodeId {
        self.id
    }
    /// Returns the owning document.
    #[must_use]
    pub fn document(self) -> &'a Document<'input, S> {
        self.document
    }
    /// Returns the semantic node kind.
    #[must_use]
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
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.node_type() == NodeType::Root
    }
    /// Returns whether this is an element.
    #[must_use]
    pub fn is_element(&self) -> bool {
        self.node_type() == NodeType::Element
    }
    /// Returns whether this is text.
    #[must_use]
    pub fn is_text(&self) -> bool {
        self.node_type() == NodeType::Text
    }
    /// Returns whether this is a comment.
    #[must_use]
    pub fn is_comment(&self) -> bool {
        self.node_type() == NodeType::Comment
    }
    /// Returns whether this is a processing instruction.
    #[must_use]
    pub fn is_pi(&self) -> bool {
        self.node_type() == NodeType::PI
    }
    /// Returns the source byte range represented by this node.
    #[must_use]
    pub fn range(self) -> Range<usize> {
        self.data().range.clone()
    }
    pub(crate) fn has_actionable_range(self) -> bool {
        self.data().range_actionable
    }
    /// Returns the parent node.
    #[must_use]
    pub fn parent(self) -> Option<Self> {
        self.data().parent.and_then(|id| self.document.get_node(id))
    }
    /// Returns the parent only when it is an element.
    #[must_use]
    pub fn parent_element(self) -> Option<Self> {
        self.parent()
            .and_then(|node| node.is_element().then_some(node))
    }
    /// Iterates direct children in document order.
    #[must_use]
    pub fn children(self) -> Children<'a, 'input, S> {
        Children {
            document: self.document,
            ids: self.data().children.iter(),
        }
    }
    /// Returns the first direct child node.
    #[must_use]
    pub fn first_child(self) -> Option<Self> {
        self.children().next()
    }
    /// Returns the first direct element child.
    #[must_use]
    pub fn first_element_child(self) -> Option<Self> {
        self.children().find(Node::is_element)
    }
    /// Returns the last direct element child.
    #[must_use]
    pub fn last_element_child(self) -> Option<Self> {
        self.children().rev().find(Node::is_element)
    }
    /// Iterates this node and its descendants in document order.
    #[must_use]
    pub fn descendants(self) -> Descendants<'a, 'input, S> {
        Descendants {
            document: self.document,
            ids: self.id.0..self.data().subtree_end,
        }
    }
    /// Document-order `XPath` index of this tree node.
    #[cfg(feature = "xmldsig")]
    pub(crate) fn xpath_index(self) -> u32 {
        self.data().xpath_start
    }
    /// End of the contiguous `XPath` index range covering this subtree and its axes.
    #[cfg(feature = "xmldsig")]
    pub(crate) fn xpath_subtree_end(self) -> u32 {
        self.document
            .nodes
            .get(self.data().subtree_end as usize)
            .map_or(self.document.xpath_nodes, |next| next.xpath_start)
    }
    /// Iterates this node and then its ancestors.
    #[must_use]
    pub fn ancestors(self) -> Ancestors<'a, 'input, S> {
        Ancestors { next: Some(self) }
    }
    /// Returns the preceding sibling.
    #[must_use]
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
    #[must_use]
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
    /// Returns the following sibling in constant time. The arena stores each
    /// subtree contiguously in preorder, so the node after this subtree is the
    /// next sibling exactly when it has the same parent.
    #[cfg(feature = "xmldsig")]
    pub(crate) fn following_sibling(self) -> Option<Self> {
        let parent = self.data().parent?;
        let next = NodeId(self.data().subtree_end);
        let data = self.document.nodes.get(next.index())?;
        (data.parent == Some(parent)).then_some(Self {
            document: self.document,
            id: next,
        })
    }
    /// Returns the next sibling that is an element.
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub fn prefix(self) -> Option<&'a str> {
        match &self.data().kind {
            NodeKind::Element { prefix, .. } => prefix.as_deref(),
            _ => None,
        }
    }
    /// Iterates non-namespace attributes in source order.
    #[must_use]
    pub fn attributes(self) -> Attributes<'a, S> {
        let values: &[AttributeData<S>] = match &self.data().kind {
            NodeKind::Element { attributes, .. } => &attributes[..],
            _ => &[],
        };
        Attributes {
            values: values.iter(),
        }
    }
    /// Looks up an unqualified attribute by local name.
    #[must_use]
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
    #[must_use]
    pub fn namespaces(self) -> Namespaces<'a, S> {
        let values: &[NamespaceData<S>] = match &self.data().kind {
            NodeKind::Element { namespaces, .. } => &namespaces[..],
            _ => &[],
        };
        Namespaces {
            values: values.iter(),
        }
    }
    /// Resolves a namespace prefix in this element's in-scope bindings.
    #[must_use]
    pub fn lookup_namespace_uri(self, prefix: Option<&str>) -> Option<&'a str> {
        if prefix == Some("xml") {
            return Some(XML_NAMESPACE_URI);
        }
        self.namespaces()
            .find(|ns| ns.name() == prefix)
            .map(Namespace::uri)
    }
    /// Finds an in-scope prefix for a namespace URI.
    #[must_use]
    pub fn lookup_prefix(self, uri: &str) -> Option<&'a str> {
        if uri == XML_NAMESPACE_URI {
            return Some("xml");
        }
        self.namespaces()
            .filter(|namespace| namespace.uri() == uri)
            .find_map(Namespace::name)
    }
    /// Returns direct character data, or the first direct text child of an element.
    #[must_use]
    pub fn text(self) -> Option<&'a str> {
        match &self.data().kind {
            NodeKind::Text(value) | NodeKind::Comment(value) => Some(value),
            NodeKind::Element { .. } => {
                self.first_child()
                    .and_then(|child| match &child.data().kind {
                        NodeKind::Text(value) => Some(value.as_ref()),
                        _ => None,
                    })
            }
            NodeKind::PI { .. } | NodeKind::Root => None,
        }
    }
    /// Returns processing-instruction data for a PI node.
    #[must_use]
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
    #[must_use]
    pub fn name(self) -> &'a str {
        self.name
    }
    /// Returns the namespace URI.
    #[must_use]
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
pub struct Attribute<'a, S: Storage = Native> {
    data: &'a AttributeData<S>,
}
impl<'a, S: Storage> Attribute<'a, S> {
    /// Report non-fatal xml:id errors without changing ID type assignment.
    ///
    /// xml:id 1.0 sections 4 and 6 require assignment even for invalid values;
    /// applications may inspect this diagnostic before relying on an ID.
    /// <https://www.w3.org/TR/2005/REC-xml-id-20050909/#processing>
    #[must_use]
    pub fn xml_id_error(self) -> Option<XmlIdError> {
        self.data.xml_id_error
    }
    /// Whether XML processing assigned the ID type (DTD or xml:id).
    #[must_use]
    pub fn is_id(self) -> bool {
        self.data.is_id
    }
    /// Returns the local name.
    #[must_use]
    pub fn name(self) -> &'a str {
        &self.data.name
    }
    /// Returns the namespace URI.
    #[must_use]
    pub fn namespace(self) -> Option<&'a str> {
        self.data.namespace.as_deref()
    }
    /// Returns the expanded value.
    #[must_use]
    pub fn value(self) -> &'a str {
        &self.data.value
    }
    /// Returns the lexical namespace prefix.
    #[must_use]
    pub fn prefix(self) -> Option<&'a str> {
        self.data.prefix.as_deref()
    }
}

/// Iterator over element attributes.
pub struct Attributes<'a, S: Storage = Native> {
    values: std::slice::Iter<'a, AttributeData<S>>,
}
impl<'a, S: Storage> Iterator for Attributes<'a, S> {
    type Item = Attribute<'a, S>;
    fn next(&mut self) -> Option<Self::Item> {
        self.values.next().map(|data| Attribute { data })
    }
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.values.nth(n).map(|data| Attribute { data })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}
impl<S: Storage> ExactSizeIterator for Attributes<'_, S> {}

/// Borrowed in-scope namespace binding.
#[derive(Clone, Copy)]
pub struct Namespace<'a, S: Storage = Native> {
    data: &'a NamespaceData<S>,
}
impl<'a, S: Storage> Namespace<'a, S> {
    /// Returns the prefix, or `None` for the default namespace.
    #[must_use]
    pub fn name(self) -> Option<&'a str> {
        self.data.prefix.as_deref()
    }
    /// Returns the namespace URI.
    #[must_use]
    pub fn uri(self) -> &'a str {
        &self.data.uri
    }
}

/// Iterator over in-scope namespace bindings.
pub struct Namespaces<'a, S: Storage = Native> {
    values: std::slice::Iter<'a, NamespaceData<S>>,
}
impl<'a, S: Storage> Iterator for Namespaces<'a, S> {
    type Item = Namespace<'a, S>;
    fn next(&mut self) -> Option<Self::Item> {
        self.values.next().map(|data| Namespace { data })
    }
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.values.nth(n).map(|data| Namespace { data })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}
impl<S: Storage> ExactSizeIterator for Namespaces<'_, S> {}

/// Processing-instruction payload.
#[derive(Clone, Copy)]
pub struct PI<'a> {
    /// Processing-instruction target.
    pub target: &'a str,
    /// Optional processing-instruction data.
    pub value: Option<&'a str>,
}

/// Iterator over direct child nodes.
pub struct Children<'a, 'input, S: Storage = Native> {
    document: &'a Document<'input, S>,
    ids: std::slice::Iter<'a, NodeId>,
}
impl<'a, 'input, S: Storage> Iterator for Children<'a, 'input, S> {
    type Item = Node<'a, 'input, S>;
    fn next(&mut self) -> Option<Self::Item> {
        self.ids.next().and_then(|id| self.document.get_node(*id))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ids.size_hint()
    }
}
impl<S: Storage> ExactSizeIterator for Children<'_, '_, S> {}
impl<S: Storage> DoubleEndedIterator for Children<'_, '_, S> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.ids
            .next_back()
            .and_then(|id| self.document.get_node(*id))
    }
}

/// Pre-order iterator over a node and its descendants.
pub struct Descendants<'a, 'input, S: Storage = Native> {
    document: &'a Document<'input, S>,
    ids: Range<u32>,
}
impl<'a, 'input, S: Storage> Iterator for Descendants<'a, 'input, S> {
    type Item = Node<'a, 'input, S>;
    fn next(&mut self) -> Option<Self::Item> {
        self.ids
            .next()
            .and_then(|id| self.document.get_node(NodeId(id)))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ids.size_hint()
    }
}
impl<S: Storage> DoubleEndedIterator for Descendants<'_, '_, S> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.ids
            .next_back()
            .and_then(|id| self.document.get_node(NodeId(id)))
    }
}
impl<S: Storage> ExactSizeIterator for Descendants<'_, '_, S> {}

/// Iterator over a node and its ancestors.
pub struct Ancestors<'a, 'input, S: Storage = Native> {
    next: Option<Node<'a, 'input, S>>,
}
impl<'a, 'input, S: Storage> Iterator for Ancestors<'a, 'input, S> {
    type Item = Node<'a, 'input, S>;
    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next?;
        self.next = current.parent();
        Some(current)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "xmldsig")]
    fn assert_scoped_projection<S: super::Storage>(document: &super::Document<'_, S>) {
        let root = document.root_element();
        assert_eq!(root.tag_name().name(), "r");
        assert_eq!(root.attribute(("urn:p", "x")), Some("value"));
        assert_eq!(root.lookup_namespace_uri(Some("p")), Some("urn:p"));
        let id = root
            .attributes()
            .find(|attribute| attribute.name() == "id")
            .expect("xml:id retained");
        assert!(id.is_id());
        assert_eq!(id.value(), "a b");
        assert_eq!(id.xml_id_error(), Some(super::XmlIdError::InvalidNcName));
        assert_eq!(root.children().len(), 1);
        assert_eq!(root.text(), Some("leftmiddleright"));
    }

    #[cfg(all(feature = "xmldsig", feature = "xml-backend-roxmltree"))]
    #[test]
    fn roxmltree_projection_uses_the_actual_scoped_tree_storage() {
        // The source parser is deliberately outside this component test's
        // account. Every *semantic projection* allocation must be retained by
        // the supplied execution without changing IDs, namespaces or text.
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let xml = "<r xmlns:p='urn:p' xml:id=' a  b ' p:x='value'>left<![CDATA[middle]]>right</r>";
        let preflight =
            super::super::LexicalPreflight::scan(xml, false).expect("fixed XML preflight");
        let raw = crate::parser_roxmltree::Document::parse(xml).expect("fixed backend XML");
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
        let document = super::super::roxmltree::project_in(
            xml,
            &raw,
            &preflight,
            super::super::storage::Accounted(&memory),
        )
        .expect("paid projection fits");
        assert_scoped_projection(&document);
        assert!(memory.used() > 0);
        drop(document);
        assert_eq!(memory.used(), 0);
        let denied = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 1 << 20)));
        assert!(matches!(
            super::super::roxmltree::project_in(
                xml,
                &raw,
                &preflight,
                super::super::storage::Accounted(&denied)
            ),
            Err(super::ParseError::SharedExecution(
                MemoryError::LimitExceeded
            ))
        ));
        assert_eq!(denied.used(), 0);
    }

    #[cfg(all(feature = "xmldsig", feature = "xml-backend-roxmltree"))]
    #[test]
    fn scoped_parser_tree_and_canonicalizer_share_the_same_semantic_kernel() {
        // Switching both parser and semantic-tree storage must not require a
        // second serializer or alter canonical bytes, axes, IDs or comments.
        use crate::c14n::{C14nAlgorithm, C14nMode};
        use crate::xmldsig::types::{
            NodeSetMaterializationBudget,
            projection::{PaidKeys, Projection},
        };
        use structured_asn1::memory::{Memory, MemoryAccount};
        let source = "<r xmlns:p='urn:p' xml:id=' a  b ' p:x='value'>left<![CDATA[middle]]><!--c--><p:leaf/>right</r>";
        let expected = super::Document::parse(source).expect("native semantic baseline");
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let storage = super::super::storage::Accounted(&memory);
        let preflight = super::super::LexicalPreflight::scan_in(source, false, storage)
            .expect("funded lexical preflight");
        let document = super::super::roxmltree::RoxmltreeBackend::parse_in(
            source,
            ParsingOptions::default(),
            &preflight,
            storage,
        )
        .expect("funded roxmltree parse");
        let nodes = Projection::subtree(
            document.root(),
            true,
            &NodeSetMaterializationBudget::default(),
            PaidKeys::new(&memory),
        )
        .expect("funded node projection");
        for mode in [
            C14nMode::Inclusive1_0,
            C14nMode::Inclusive1_1,
            C14nMode::Exclusive1_0,
        ] {
            for comments in [false, true] {
                let algorithm = C14nAlgorithm::new(mode, comments);
                let mut canonical = Vec::new();
                crate::c14n::canonicalize(&expected, None, &algorithm, &mut canonical)
                    .expect("native canonical baseline");
                let (actual, _) = crate::c14n::canonicalize_buffer_in(
                    &document,
                    &nodes,
                    (&algorithm, None),
                    None,
                    1 << 20,
                    &crate::c14n::xml_base::XmlBaseResolutionBudget::default(),
                    &crate::c14n::scratch::Accounted(&memory),
                )
                .expect("funded canonicalization");
                assert_eq!(&*actual, &canonical);
            }
        }
        assert!(memory.used() > 0);
        drop(nodes);
        drop(document);
        drop(preflight);
        assert_eq!(memory.used(), 0);
    }

    #[cfg(all(feature = "xmldsig", feature = "xml-backend-xmloxide"))]
    #[test]
    fn xmloxide_projection_uses_the_actual_scoped_tree_storage() {
        // The same tree kernel must retain paid coalescing, normalized xml:id,
        // namespace axes and attributes with the alternate selected backend.
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let xml = "<r xmlns:p='urn:p' xml:id=' a  b ' p:x='value'>left<![CDATA[middle]]>right</r>";
        let preflight =
            super::super::LexicalPreflight::scan(xml, false).expect("fixed XML preflight");
        let raw = crate::parser_xmloxide::parser::parse_str_with_options(
            xml,
            &super::super::xmloxide::backend_options(),
        )
        .expect("fixed backend XML");
        let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
        let document = super::super::xmloxide::project_in(
            xml,
            &raw,
            super::ParsingOptions::default(),
            &preflight,
            super::super::storage::Accounted(&memory),
        )
        .expect("paid projection fits");
        assert_scoped_projection(&document);
        assert!(memory.used() > 0);
        drop(document);
        assert_eq!(memory.used(), 0);
        let denied = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 1 << 20)));
        assert!(matches!(
            super::super::xmloxide::project_in(
                xml,
                &raw,
                super::ParsingOptions::default(),
                &preflight,
                super::super::storage::Accounted(&denied)
            ),
            Err(super::ParseError::SharedExecution(
                MemoryError::LimitExceeded
            ))
        ));
        assert_eq!(denied.used(), 0);
    }

    #[cfg(all(feature = "xmldsig", feature = "xml-backend-xmloxide"))]
    #[test]
    fn projection_node_admission_precedes_arena_and_payload_growth() {
        // A disallowed semantic node must not allocate its attributes or text
        // first, nor reserve a larger arena based on the source backend count.
        use super::super::storage::Accounted;
        use structured_asn1::memory::{Memory, MemoryAccount};
        let source = format!("<r a='{}'/>", "x".repeat(65536));
        let preflight =
            super::super::LexicalPreflight::scan(&source, false).expect("native lexical baseline");
        let raw = crate::parser_xmloxide::parser::parse_str_with_options(
            &source,
            &super::super::xmloxide::backend_options(),
        )
        .expect("native raw XML baseline");
        for (limit, capacity) in [(0, 0), (1, 4096)] {
            let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(capacity, 1 << 24)));
            let result = super::super::xmloxide::project_in(
                &source,
                &raw,
                super::ParsingOptions {
                    nodes_limit: limit,
                    allow_dtd: false,
                },
                &preflight,
                Accounted(&memory),
            );
            assert!(matches!(result, Err(super::ParseError::NodesLimitReached)));
            assert_eq!(memory.used(), 0);
        }
    }

    use super::{Document, Node};
    #[cfg(all(feature = "xml-backend-roxmltree", feature = "xml-backend-xmloxide"))]
    use super::{NamespaceData, comparison::namespaces_equal};
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

    #[test]
    fn every_backend_enforces_the_same_active_namespace_ceiling() {
        use std::fmt::Write as _;
        // Backend selection must not change whether an adversarial namespace
        // stack is accepted. The 1024th binding is valid; the 1025th is not.
        let mut declarations = String::new();
        for index in 0..1_023 {
            write!(declarations, r#" xmlns:n{index}="urn:namespace:{index}""#)
                .expect("namespace boundary");
        }
        let accepted = format!(r#"<root{declarations}><child xmlns:p="urn:p"/></root>"#);
        let rejected = format!(
            r#"<root{declarations} xmlns:overflow="urn:overflow"><child xmlns:p="urn:p"/></root>"#
        );

        for backend in XmlBackend::available() {
            Document::parse_with_backend(&accepted, backend)
                .unwrap_or_else(|error| panic!("{backend:?} rejected the ceiling: {error}"));
            assert_eq!(
                Document::parse_with_backend(&rejected, backend)
                    .expect_err("the 1025th active binding must be rejected"),
                ParseError::NamespaceBindingLimitReached {
                    maximum: 1_024,
                    actual: 1_025,
                },
                "{backend:?} must share the lexical namespace contract"
            );
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
        let binding = |prefix: &str, uri: &str| NamespaceData::<super::Native> {
            prefix: Some(prefix.to_owned()),
            uri: uri.to_owned(),
        };
        let a = binding("a", "urn:a");
        let b = binding("b", "urn:b");

        assert!(
            !namespaces_equal(
                &[a.clone(), a.clone()],
                &[a.clone(), b.clone()],
                super::Native,
            )
            .expect("duplicate axis comparison")
        );
        assert!(
            !namespaces_equal(&[a.clone(), b], &[a.clone(), a.clone()], super::Native,)
                .expect("reversed duplicate axis comparison")
        );
        assert!(
            namespaces_equal(&[a.clone(), a.clone()], &[a.clone(), a], super::Native,)
                .expect("equal multiplicities")
        );
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
        let mut items = document.root_element().children().filter(Node::is_element);
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
            .filter(Node::is_text)
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
        assert_eq!(pi.next_sibling().and_then(Node::text), Some("visible"));

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
            .filter(Node::is_comment)
            .filter_map(Node::text)
            .collect::<Vec<_>>();

        assert_eq!(comments, ["before", "after"]);
        assert_eq!(
            root.descendants().find(Node::is_text).and_then(Node::text),
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
            .filter(Node::is_comment)
            .filter_map(Node::text)
            .collect::<Vec<_>>();
        let processing_instructions = root
            .children()
            .filter(Node::is_pi)
            .filter_map(Node::pi)
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
