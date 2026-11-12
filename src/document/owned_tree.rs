//! A document tree this crate owns: built by its own parser, changed node by
//! node, and read and edited by every operation through [`ExternalTree`].
//!
//! It is the tree a C surface hands out as opaque handles. Every node is
//! named by a [`TreeNode`] that stays valid while the node exists; a node an
//! edit frees is refused from then on, never reused, so a stale name is an
//! error rather than a different node. No caller reaches the tree's memory.

use alloc::{string::String, vec, vec::Vec};
use core::num::NonZeroU32;

use super::external::{
    ExternalNode, ExternalTree, Fragment, FragmentEvent, TreeEdit, TreeEditError, TreeSink,
};
use super::{DocumentParseSettings, XmlDocumentError, XmlDocumentPolicy};
use crate::ParseError;
use crate::parser_xmloxide as xmloxide;
use crate::xml::dom::storage::{Native, Storage as _};
use ids::{IdSource, IdTable};

mod ids;
use xmloxide::tree::{Attribute, NodeId, NodeKind};

/// The namespace the `xml` prefix is bound to (Namespaces in XML 1.0
/// section 3).
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

/// One node of an [`OwnedTree`], valid while the node exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TreeNode(NonZeroU32);

impl TreeNode {
    /// The node's number within its tree, never zero.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// The node numbered `raw`, if `raw` is not zero; the tree checks that it
    /// names a live node before using it.
    #[must_use]
    pub const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    fn id(self) -> Option<NodeId> {
        NodeId::from_raw(self.0.get())
    }

    fn of(id: NodeId) -> Self {
        // A `NodeId` is never zero.
        Self(NonZeroU32::new(id.into_raw()).expect("a node id is not zero"))
    }
}

/// The node a document built from this tree reports for it.
impl From<TreeNode> for ExternalNode {
    fn from(node: TreeNode) -> Self {
        Self(u64::from(node.get()))
    }
}

/// The tree node an external node of an [`OwnedTree`] document names; an
/// out-of-range number is refused.
impl TryFrom<ExternalNode> for TreeNode {
    type Error = TreeError;

    fn try_from(node: ExternalNode) -> Result<Self, TreeError> {
        u32::try_from(node.0)
            .ok()
            .and_then(Self::new)
            .ok_or(TreeError::StaleNode)
    }
}

/// What a [`TreeNode`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeNodeKind {
    /// The node standing for the whole document.
    Document,
    /// An element.
    Element,
    /// Character data.
    Text,
    /// A CDATA section.
    CData,
    /// A comment.
    Comment,
    /// A processing instruction.
    ProcessingInstruction,
    /// An entity reference the parser kept unexpanded.
    EntityReference,
    /// The document type declaration.
    DocumentType,
}

/// An attribute of an element, namespace declarations excluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeAttribute<'a> {
    /// Its local name.
    pub local_name: &'a str,
    /// Its prefix, if any.
    pub prefix: Option<&'a str>,
    /// Its namespace URI, if any.
    pub namespace: Option<&'a str>,
    /// Its value, unescaped.
    pub value: &'a str,
}

/// A namespace declaration of an element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeNamespace<'a> {
    /// The declared prefix; `None` for the default namespace.
    pub prefix: Option<&'a str>,
    /// The bound URI; empty undeclares the default namespace.
    pub uri: &'a str,
}

/// A refused tree operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TreeError {
    /// The node was freed, or never belonged to this tree.
    #[error("the node is not a live node of this tree")]
    StaleNode,
    /// The operation needs an element.
    #[error("the node is not an element")]
    NotAnElement,
    /// The operation needs a node with a parent.
    #[error("the node has no parent")]
    NoParent,
    /// The node is already linked into the tree; unlink it first.
    #[error("the node is already linked")]
    AlreadyLinked,
    /// Linking would make a node its own ancestor.
    #[error("the node would become its own ancestor")]
    Cycle,
    /// The document node cannot be linked, unlinked or freed.
    #[error("the document node cannot be moved or freed")]
    DocumentNode,
    /// A name or value holds a character XML does not admit.
    #[error("a name or value holds a character XML does not admit")]
    InvalidText,
    /// Another live element already holds the ID.
    #[error("another element already holds the ID")]
    DuplicateId,
    /// The element has no attribute of that name carrying the ID.
    #[error("the attribute does not carry the ID")]
    IdNotCarried,
}

/// An undo record of an edit applied through [`ExternalTree::apply`].
#[derive(Clone, Debug)]
enum Undo {
    /// A node an edit created and linked.
    Linked(NodeId),
    /// A node an edit unlinked from `parent`, before `next`.
    Unlinked {
        node: NodeId,
        parent: NodeId,
        next: Option<NodeId>,
    },
    /// An ID an edit registered, and the attribute it named before.
    Id {
        value: String,
        previous: Option<IdSource>,
    },
}

/// A document tree owned by this crate.
pub struct OwnedTree {
    document: xmloxide::Document,
    /// Freed nodes, by number; the arena never reuses a number.
    freed: Vec<bool>,
    journal: Vec<Undo>,
    /// The tree's ID table: `xml:id` values and the IDs a caller registered,
    /// as libxml2's is without a DTD. The parser's own index, which also
    /// names every unprefixed `id` attribute, is not consulted.
    ids: IdTable,
}

impl core::fmt::Debug for OwnedTree {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OwnedTree")
            .field("nodes", &self.document.node_count())
            .finish_non_exhaustive()
    }
}

impl Default for OwnedTree {
    fn default() -> Self {
        Self::new()
    }
}

impl OwnedTree {
    /// An empty document: its document node and nothing else.
    #[must_use]
    pub fn new() -> Self {
        Self {
            document: xmloxide::Document::new(),
            freed: Vec::new(),
            journal: Vec::new(),
            ids: IdTable::default(),
        }
    }

    /// Parse `xml` under the XML input policy and resource limits of
    /// `policy`'s operation, enforced while the parser reads: bytes, nodes,
    /// depth, namespace bindings and the DTD allowance.
    ///
    /// # Errors
    /// The policy's typed violation for a limit the document passes, an
    /// invalid policy, a document type declaration the policy does not
    /// allow, or a syntax error.
    pub fn parse_with_policy(
        xml: &str,
        policy: &impl XmlDocumentPolicy,
    ) -> Result<Self, XmlDocumentError> {
        Self::under_policy(policy, |settings| Self::parse_with_settings(xml, settings))
    }

    /// Parse `bytes` as [`Self::parse_with_policy`] parses text, after
    /// decoding them: a byte-order mark or the XML declaration selects the
    /// encoding (XML 1.0 section 4.3.3 and appendix F), and the declaration
    /// of the decoded text names UTF-8.
    ///
    /// # Errors
    /// As for [`Self::parse_with_policy`], or bytes that are not in the
    /// encoding they select.
    pub fn parse_bytes_with_policy(
        bytes: &[u8],
        policy: &impl XmlDocumentPolicy,
    ) -> Result<Self, XmlDocumentError> {
        Self::parse_parts_with_policy(&[bytes], policy)
    }

    /// Parse the bytes of `parts` in sequence as
    /// [`Self::parse_bytes_with_policy`] parses one buffer. Their combined
    /// length meets the document byte limit before they are joined, so
    /// parts too large together are refused without a copy.
    ///
    /// # Errors
    /// As for [`Self::parse_bytes_with_policy`].
    pub fn parse_parts_with_policy(
        parts: &[&[u8]],
        policy: &impl XmlDocumentPolicy,
    ) -> Result<Self, XmlDocumentError> {
        Self::under_policy(policy, |settings| {
            let maximum = settings.max_bytes;
            match parts
                .iter()
                .try_fold(0_usize, |total, part| total.checked_add(part.len()))
            {
                Some(actual) if actual <= maximum => {}
                // A sum beyond `usize` is reported as the largest size there is.
                actual => {
                    return Err(XmlDocumentError::DocumentTooLarge {
                        maximum,
                        actual: actual.unwrap_or(usize::MAX),
                    });
                }
            }
            let joined;
            let bytes: &[u8] = if let [only] = parts {
                only
            } else {
                joined = parts.concat();
                &joined
            };
            let xml = super::decode_xml_with_budget(bytes, maximum, None)?;
            Self::parse_with_settings(&xml, settings)
        })
    }

    /// Run `parse` under the settings of `policy`, its limit refusals
    /// reported as the policy's typed violations.
    fn under_policy(
        policy: &impl XmlDocumentPolicy,
        parse: impl FnOnce(DocumentParseSettings) -> Result<Self, XmlDocumentError>,
    ) -> Result<Self, XmlDocumentError> {
        policy.resource_policy().validate()?;
        let settings = DocumentParseSettings::from_policy(
            *policy.xml_input_policy(),
            policy.resource_policy(),
        );
        parse(settings).map_err(|error| match error.into_policy_violation(settings) {
            Ok(violation) => XmlDocumentError::Policy(violation),
            Err(error) => error,
        })
    }

    fn parse_with_settings(
        xml: &str,
        settings: DocumentParseSettings,
    ) -> Result<Self, XmlDocumentError> {
        super::check_document_size(xml, settings)?;
        // A document type declaration brings declarations and entity
        // expansion: the lexical scan every other parse runs refuses one the
        // policy does not allow before its internal subset is read, and
        // bounds the entities it expands.
        if crate::xml::dom::declares_document_type(xml) {
            let mut pass = super::LimitPass::new(settings, None, super::NativeXmlStorage)?;
            crate::xml::dom::scan_declared_document(xml, settings.allow_dtd, &mut pass)
                .map_err(|error| pass.refusal_or(XmlDocumentError::Parse(error)))?;
        }
        let tree = xmloxide::Document::try_with_storage(
            xmloxide::parser::initial_node_capacity(xml.len()).min(settings.nodes_limit as usize),
            crate::xml::dom::storage::Native,
        )
        .map_err(|_| XmlDocumentError::Parse(ParseError::AllocationFailed))?;
        let (parsed, counter) = xmloxide::parser::parse_str_enforcing_limits(
            xml,
            &crate::xml::dom::xmloxide_parse_options(),
            super::parse_limits(settings),
            tree,
        )
        .map_err(|error| XmlDocumentError::Parse(syntax(error)))?;
        let mut document = parsed.map_err(|error| match counter.refusal() {
            Some(refusal) => super::limit_refusal(refusal),
            None => XmlDocumentError::Parse(syntax(error)),
        })?;
        // The text is UTF-8 whatever the source declared, and so is every
        // serialization (XML 1.0 section 4.3.3: the declaration names the
        // encoding the bytes use).
        if document.encoding.is_some() {
            document.encoding = Some(String::from("UTF-8"));
        }
        let mut tree = Self {
            document,
            freed: Vec::new(),
            journal: Vec::new(),
            ids: IdTable::default(),
        };
        tree.settle_parsed_attributes();
        Ok(tree)
    }

    /// Registers every `xml:id` attribute as its element's ID, in document
    /// order: `xml:id` is an ID without any declaration (xml:id 1.0 section
    /// 4). A value repeated later keeps its first element, as libxml2 keeps
    /// the first.
    ///
    /// The parser's copy of each attribute's source text is dropped on the
    /// way: the serialization writes the normalized value, since source text
    /// with literal whitespace beside a reference would reparse to another
    /// value (XML 1.0 section 3.3.3).
    fn settle_parsed_attributes(&mut self) {
        let mut pending = vec![self.document.root()];
        while let Some(id) = pending.pop() {
            if let NodeKind::Element { attributes, .. } = &mut self.document.node_mut(id).kind {
                for attribute in attributes.iter_mut() {
                    attribute.raw_value = None;
                }
            }
            // A value repeated later keeps its first element, as libxml2's
            // parser keeps the first: the repeat is not registered, only
            // shadowed, so a lookup of the value finds it ambiguous.
            self.register_or_shadow_xml_id(id, &[]);
            let first = pending.len();
            pending.extend(self.document.children(id));
            // Children are popped first to last.
            pending[first..].reverse();
        }
    }

    /// Normalize the `xml:id` attribute of `element`, if it has one, and
    /// register its element under the normalized value: xml:id 1.0 section 4
    /// normalizes the value as an ID before assigning it and keeps the
    /// normalized value in the infoset. Returns the undo record of a
    /// registration it made.
    ///
    /// # Errors
    /// [`TreeError::DuplicateId`] when another element holds the value (see
    /// [`Self::claim`]); the attribute is normalized all the same.
    fn register_xml_id(
        &mut self,
        element: NodeId,
        released: &[NodeId],
    ) -> Result<Option<Undo>, TreeError> {
        let NodeKind::Element { attributes, .. } = &mut self.document.node_mut(element).kind else {
            return Ok(None);
        };
        let Some(attribute) = attributes
            .iter_mut()
            .find(|attribute| is_xml_id(&attribute.name, attribute.namespace.as_deref()))
        else {
            return Ok(None);
        };
        normalize_id_value(&mut attribute.value);
        attribute.raw_value = None;
        let value = attribute.value.clone();
        self.claim(value, xml_id_source(TreeNode::of(element)), released)
    }

    /// Register the `xml:id` of `element` as [`Self::register_xml_id`] does,
    /// for a path that does not refuse a repeated value: a value another
    /// element holds leaves this one shadowed rather than unseen, and a
    /// registration taken over from a released element shadows that one, so
    /// a lookup finds the value ambiguous once both are linked.
    fn register_or_shadow_xml_id(&mut self, element: NodeId, released: &[NodeId]) {
        match self.register_xml_id(element, released) {
            Ok(Some(Undo::Id {
                value,
                previous: Some(previous),
            })) => self.ids.shadow(value, previous),
            Err(TreeError::DuplicateId) => {
                if let Some(value) = self.xml_id_value(element) {
                    self.ids.shadow(value, xml_id_source(TreeNode::of(element)));
                }
            }
            _ => {}
        }
    }

    /// The `xml:id` value `element` carries, if any.
    fn xml_id_value(&self, element: NodeId) -> Option<String> {
        let NodeKind::Element { attributes, .. } = &self.document.node(element).kind else {
            return None;
        };
        attributes
            .iter()
            .find(|attribute| is_xml_id(&attribute.name, attribute.namespace.as_deref()))
            .map(|attribute| attribute.value.clone())
    }

    /// Make `value` the ID `source` carries. The undo record of a change is
    /// returned; `None` when `source` already held it.
    ///
    /// # Errors
    /// [`TreeError::DuplicateId`] when another element holds `value` (see
    /// [`Self::check_claim`]).
    fn claim(
        &mut self,
        value: String,
        source: IdSource,
        released: &[NodeId],
    ) -> Result<Option<Undo>, TreeError> {
        let previous = self.ids.get(&value).cloned();
        if previous.as_ref() == Some(&source) {
            return Ok(None);
        }
        self.check_claim(&value, &source, released)?;
        self.ids.insert(value.clone(), source);
        Ok(Some(Undo::Id { value, previous }))
    }

    /// Whether `source` may take the ID `value`: it may unless an attribute
    /// of another element that still holds IDs carries it.
    ///
    /// # Errors
    /// [`TreeError::DuplicateId`] when such an element holds `value`.
    fn check_claim(
        &self,
        value: &str,
        source: &IdSource,
        released: &[NodeId],
    ) -> Result<(), TreeError> {
        match self.ids.get(value) {
            Some(held)
                if held.element != source.element && self.holds_ids(held.element, released) =>
            {
                Err(TreeError::DuplicateId)
            }
            _ => Ok(()),
        }
    }

    /// Whether `element` still holds its IDs: it is live, linked or not, as
    /// libxml2 keeps the IDs of an unlinked node, unless it hangs in a
    /// subtree the running edit unlinked from the place it fills (`released`).
    fn holds_ids(&self, element: TreeNode, released: &[NodeId]) -> bool {
        let Ok(mut top) = self.live(element) else {
            return false;
        };
        while let Some(parent) = self.document.parent(top) {
            top = parent;
        }
        !released.contains(&top)
    }

    /// Register the `xml:id` attributes of the inserted subtrees `built`,
    /// after the edit unlinked what it replaces (`released`), so a restored
    /// element takes the ID its replaced one held.
    ///
    /// # Errors
    /// [`TreeError::DuplicateId`] when an inserted ID is held elsewhere; the
    /// registrations made so far are journaled and roll back with the edit.
    fn register_inserted_ids(
        &mut self,
        built: &[NodeId],
        released: &[NodeId],
    ) -> Result<(), TreeError> {
        for &top in built {
            let elements: Vec<NodeId> = core::iter::once(top)
                .chain(self.document.descendants(top))
                .collect();
            for element in elements {
                if let Some(undo) = self.register_xml_id(element, released)? {
                    self.journal.push(undo);
                }
            }
        }
        Ok(())
    }

    /// The document as XML text: the XML declaration, then every node linked
    /// under the document node, then a newline, as libxml2 writes a document.
    #[must_use]
    pub fn serialize(&self) -> String {
        xmloxide::serial::serialize(&self.document)
    }

    /// The node standing for the whole document.
    #[must_use]
    pub fn document_node(&self) -> TreeNode {
        TreeNode::of(self.document.root())
    }

    /// The document element, if the document has one.
    #[must_use]
    pub fn root_element(&self) -> Option<TreeNode> {
        self.document.root_element().map(TreeNode::of)
    }

    /// Whether `node` names a live node of this tree.
    #[must_use]
    pub fn contains(&self, node: TreeNode) -> bool {
        self.live(node).is_ok()
    }

    fn live(&self, node: TreeNode) -> Result<NodeId, TreeError> {
        let raw = node.get() as usize;
        if raw > self.document.node_count() || self.freed.get(raw).copied().unwrap_or(false) {
            return Err(TreeError::StaleNode);
        }
        let id = node.id().ok_or(TreeError::StaleNode)?;
        // A holder is the tree's own bookkeeping, never a caller's node.
        if self.is_holder(id) {
            return Err(TreeError::StaleNode);
        }
        Ok(id)
    }

    /// Whether `id` is a holder: a document-kind node that is not the
    /// document node, never linked, whose children form one run of unlinked
    /// siblings. libxml2 hands such runs out (the former content of an
    /// element, a parsed fragment); a holder keeps their order here while
    /// every node of the run reports no parent.
    fn is_holder(&self, id: NodeId) -> bool {
        id != self.document.root() && matches!(self.document.node(id).kind, NodeKind::Document)
    }

    /// The parent of `id`, a holder excepted.
    fn linked_parent(&self, id: NodeId) -> Option<NodeId> {
        self.document
            .parent(id)
            .filter(|&parent| !self.is_holder(parent))
    }

    /// Take `id` out of the run its holder keeps, freeing the holder with its
    /// last node.
    fn leave_holder(&mut self, id: NodeId) {
        let Some(holder) = self.document.parent(id).filter(|&p| self.is_holder(p)) else {
            return;
        };
        self.document.detach(id);
        if self.document.first_child(holder).is_none() {
            self.mark_freed(holder);
        }
    }

    /// A new holder keeping `nodes`, unlinked and in this order, as one run of
    /// siblings; the first is returned.
    fn hold(&mut self, nodes: &[NodeId]) -> Option<TreeNode> {
        let (&first, _) = nodes.split_first()?;
        let holder = self.document.create_node(NodeKind::Document);
        for &node in nodes {
            self.document.append_child(holder, node);
        }
        Some(TreeNode::of(first))
    }

    /// Unlink every child of `node` and return the first: the children stay
    /// live and keep their order as siblings, each reporting no parent, as
    /// libxml2 hands back the content an edit replaced. `None` when `node`
    /// has no children.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn unlink_children(&mut self, node: TreeNode) -> Result<Option<TreeNode>, TreeError> {
        let id = self.live(node)?;
        let children: Vec<NodeId> = self.document.children(id).collect();
        for &child in &children {
            self.document.detach(child);
        }
        Ok(self.hold(&children))
    }

    /// Parse `fragment` as the content of `context` and return its first
    /// node, as libxml2's `xmlParseInNodeContext` does: the fragment sees the
    /// namespace bindings in scope at `context`, and its nodes come back
    /// unlinked as one run of siblings. `None` for a fragment without nodes.
    /// The context is an element or the document node, which binds nothing.
    ///
    /// The fragment is parsed under `policy` as a document whose element
    /// declares those bindings, so its bytes count against the document
    /// limits with that element's.
    ///
    /// # Errors
    /// [`XmlDocumentError::MissingNode`] for a `context` that is not live,
    /// [`XmlDocumentError::TargetNotElement`] for one that is neither an
    /// element nor the document node, or the parse error of a fragment that
    /// is not well-formed content.
    pub fn parse_in_context(
        &mut self,
        context: TreeNode,
        fragment: &str,
        policy: &impl XmlDocumentPolicy,
    ) -> Result<Option<TreeNode>, XmlDocumentError> {
        let id = self
            .live(context)
            .map_err(|_| XmlDocumentError::MissingNode)?;
        let bindings = if id == self.document.root() {
            Vec::new()
        } else {
            let element = self.element(context).map_err(|error| match error {
                TreeError::NotAnElement => XmlDocumentError::TargetNotElement,
                _ => XmlDocumentError::MissingNode,
            })?;
            self.bindings_in_scope(element)
        };
        let mut wrapped = String::from("<w");
        for (prefix, uri) in bindings {
            match prefix {
                Some(prefix) => {
                    wrapped.push_str(" xmlns:");
                    wrapped.push_str(prefix);
                }
                None => wrapped.push_str(" xmlns"),
            }
            wrapped.push_str("=\"");
            push_attribute_value(&mut wrapped, uri);
            wrapped.push('"');
        }
        wrapped.push('>');
        wrapped.push_str(fragment);
        wrapped.push_str("</w>");
        // A fragment closing the wrapper early leaves a second document
        // element or stray content, which the parse refuses.
        let parsed = Self::parse_with_policy(&wrapped, policy)?;
        let Some(element) = parsed.document.root_element() else {
            return Ok(None);
        };
        let tops: Vec<NodeId> = parsed
            .document
            .children(element)
            .map(|child| self.import(&parsed.document, child, None))
            .collect();
        for &top in &tops {
            self.register_imported_ids(top);
        }
        Ok(self.hold(&tops))
    }

    /// A copy of `node` of `source` and its subtree in this tree, unlinked,
    /// as libxml2's `xmlDocCopyNode` makes one: an element copy declares
    /// the bindings its source had in scope from its ancestors, so it reads
    /// the same wherever it is linked. `source` may be this tree's own state
    /// before the copy.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live in `source`, or
    /// [`TreeError::DocumentNode`] for its document node.
    pub fn copy_from(&mut self, source: &Self, node: TreeNode) -> Result<TreeNode, TreeError> {
        let from = source.live(node)?;
        if from == source.document.root() {
            return Err(TreeError::DocumentNode);
        }
        let mut copied = Vec::new();
        let copy = self.import(&source.document, from, Some(&mut copied));
        if source.linked_parent(from).is_none() {
            // An unlinked node has no ancestors to inherit from, yet may use
            // bindings it was parsed or edited under: its copy declares what
            // it uses, as libxml2's copy reconciles namespaces.
            self.declare_used_bindings(copy);
        } else if let Some(parent) = source.linked_parent(from) {
            let declared: Vec<Option<String>> = source
                .document
                .attributes(from)
                .iter()
                .filter_map(declaration)
                .map(|declared| declared.prefix.map(String::from))
                .collect();
            let inherited: Vec<(Option<String>, String)> = source
                .bindings_in_scope(parent)
                .into_iter()
                .filter(|(prefix, _)| !declared.iter().any(|own| own.as_deref() == *prefix))
                .map(|(prefix, uri)| (prefix.map(String::from), String::from(uri)))
                .collect();
            if matches!(self.document.node(copy).kind, NodeKind::Element { .. }) {
                for (prefix, uri) in inherited {
                    let (name, attribute_prefix) = match prefix.as_deref() {
                        Some(prefix) => (prefix, Some("xmlns")),
                        None => ("xmlns", None),
                    };
                    self.put_attribute(copy, name, attribute_prefix, None, &uri);
                }
            }
        }
        self.register_imported_ids(copy);
        // The IDs a caller registered on attributes of the subtree carry over
        // with the attributes, as libxml2's copy re-adds a copied ID
        // attribute; a value held here already keeps its element, and the
        // copy is shadowed, so a lookup finds the value ambiguous once both
        // are linked. An attribute shadowed in the source still carries its
        // ID into the copy, where it may be the only carrier.
        for (original, element) in copied {
            let original = TreeNode::of(original);
            let still_carried = |(attribute, value): &(&IdSource, &str)| {
                !source.ids.carries(attribute)
                    && source
                        .attribute(original, &attribute.name, attribute.namespace.as_deref())
                        .ok()
                        .flatten()
                        == Some(*value)
            };
            let shadowed = source
                .ids
                .shadowed_of_element(original)
                .filter(still_carried);
            for (attribute, value) in source.ids.of_element(original).chain(shadowed) {
                let carrier = id_source(
                    TreeNode::of(element),
                    &attribute.name,
                    attribute.namespace.as_deref(),
                );
                if let Err(TreeError::DuplicateId) =
                    self.claim(String::from(value), carrier.clone(), &[])
                {
                    self.ids.shadow(String::from(value), carrier);
                }
            }
        }
        Ok(TreeNode::of(copy))
    }

    /// Declare, on each element of the subtree at `top`, the bindings its
    /// name and attributes use that no declaration in scope within the
    /// subtree provides, so the subtree reads the same on its own.
    fn declare_used_bindings(&mut self, top: NodeId) {
        type Scope = Vec<(Option<String>, String)>;
        fn bound<'a>(scope: &'a Scope, prefix: Option<&str>) -> Option<&'a str> {
            scope
                .iter()
                .rev()
                .find(|(declared, _)| declared.as_deref() == prefix)
                .map(|(_, uri)| uri.as_str())
        }
        let mut pending: Vec<(NodeId, Scope)> = vec![(top, Vec::new())];
        while let Some((id, mut scope)) = pending.pop() {
            let NodeKind::Element {
                prefix,
                namespace,
                attributes,
                ..
            } = &self.document.node(id).kind
            else {
                continue;
            };
            for declared in attributes.iter().filter_map(declaration) {
                scope.push((
                    declared.prefix.map(String::from),
                    String::from(declared.uri),
                ));
            }
            let mut uses: Vec<(Option<&str>, &str)> = Vec::new();
            match namespace.as_deref() {
                Some(uri) => uses.push((prefix.as_deref(), uri)),
                // An element in no namespace under a default one undeclares it.
                None if prefix.is_none()
                    && bound(&scope, None).is_some_and(|uri| !uri.is_empty()) =>
                {
                    uses.push((None, ""));
                }
                None => {}
            }
            for attribute in attributes
                .iter()
                .filter(|attribute| !is_declaration(attribute))
            {
                if let (Some(prefix), Some(uri)) =
                    (attribute.prefix.as_deref(), attribute.namespace.as_deref())
                {
                    uses.push((Some(prefix), uri));
                }
            }
            let missing: Scope = uses
                .into_iter()
                .filter(|(prefix, uri)| {
                    *prefix != Some("xml") && bound(&scope, *prefix) != Some(*uri)
                })
                .map(|(prefix, uri)| (prefix.map(String::from), String::from(uri)))
                .collect();
            for (prefix, uri) in missing {
                match prefix.as_deref() {
                    Some(name) => self.put_attribute(id, name, Some("xmlns"), None, &uri),
                    None => self.put_attribute(id, "xmlns", None, None, &uri),
                }
                scope.push((prefix, uri));
            }
            let children: Vec<NodeId> = self.document.children(id).collect();
            for child in children.into_iter().rev() {
                pending.push((child, scope.clone()));
            }
        }
    }

    /// Register the `xml:id` attributes of the imported subtree at `top`; a
    /// value another element holds keeps that element, as libxml2's parser
    /// keeps the first, and the repeat is shadowed.
    fn register_imported_ids(&mut self, top: NodeId) {
        let elements: Vec<NodeId> = core::iter::once(top)
            .chain(self.document.descendants(top))
            .collect();
        for element in elements {
            self.register_or_shadow_xml_id(element, &[]);
        }
    }

    /// The namespace bindings in scope at `element`, nearest declaration of
    /// each prefix first; `xml` is bound without a declaration.
    fn bindings_in_scope(&self, element: NodeId) -> Vec<(Option<&str>, &str)> {
        let mut bindings: Vec<(Option<&str>, &str)> = Vec::new();
        let mut current = Some(element);
        while let Some(id) = current {
            for declared in self.document.attributes(id).iter().filter_map(declaration) {
                if declared.prefix != Some("xml")
                    && !bindings
                        .iter()
                        .any(|(prefix, _)| *prefix == declared.prefix)
                {
                    bindings.push((declared.prefix, declared.uri));
                }
            }
            current = self.linked_parent(id);
        }
        bindings
    }

    /// A copy of the subtree at `from` of `source` in this tree, unlinked.
    fn import(
        &mut self,
        source: &xmloxide::Document,
        from: NodeId,
        mut copied: Option<&mut Vec<(NodeId, NodeId)>>,
    ) -> NodeId {
        let top = self.document.create_node(source.node(from).kind.clone());
        let mut pending = vec![(from, top)];
        while let Some((original, copy)) = pending.pop() {
            if let Some(copied) = copied.as_deref_mut() {
                copied.push((original, copy));
            }
            for child in source.children(original) {
                let child_copy = self.document.create_node(source.node(child).kind.clone());
                self.document.append_child(copy, child_copy);
                pending.push((child, child_copy));
            }
        }
        top
    }

    /// What `node` is.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn kind(&self, node: TreeNode) -> Result<TreeNodeKind, TreeError> {
        let id = self.live(node)?;
        Ok(match self.document.node(id).kind {
            NodeKind::Document => TreeNodeKind::Document,
            NodeKind::Element { .. } => TreeNodeKind::Element,
            NodeKind::Text { .. } => TreeNodeKind::Text,
            NodeKind::CData { .. } => TreeNodeKind::CData,
            NodeKind::Comment { .. } => TreeNodeKind::Comment,
            NodeKind::ProcessingInstruction { .. } => TreeNodeKind::ProcessingInstruction,
            NodeKind::EntityRef { .. } => TreeNodeKind::EntityReference,
            NodeKind::DocumentType { .. } => TreeNodeKind::DocumentType,
        })
    }

    /// The parent of `node`, if it is linked.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn parent(&self, node: TreeNode) -> Result<Option<TreeNode>, TreeError> {
        Ok(self.linked_parent(self.live(node)?).map(TreeNode::of))
    }

    /// The first child of `node`.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn first_child(&self, node: TreeNode) -> Result<Option<TreeNode>, TreeError> {
        Ok(self
            .document
            .first_child(self.live(node)?)
            .map(TreeNode::of))
    }

    /// The last child of `node`.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn last_child(&self, node: TreeNode) -> Result<Option<TreeNode>, TreeError> {
        Ok(self.document.last_child(self.live(node)?).map(TreeNode::of))
    }

    /// The sibling after `node`.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn next_sibling(&self, node: TreeNode) -> Result<Option<TreeNode>, TreeError> {
        Ok(self
            .document
            .next_sibling(self.live(node)?)
            .map(TreeNode::of))
    }

    /// The sibling before `node`.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn previous_sibling(&self, node: TreeNode) -> Result<Option<TreeNode>, TreeError> {
        Ok(self
            .document
            .prev_sibling(self.live(node)?)
            .map(TreeNode::of))
    }

    /// The local name of an element, the target of a processing instruction,
    /// the name of an entity reference or of the document type; `None` for
    /// other nodes.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn name(&self, node: TreeNode) -> Result<Option<&str>, TreeError> {
        let id = self.live(node)?;
        Ok(match &self.document.node(id).kind {
            NodeKind::Element { name, .. }
            | NodeKind::EntityRef { name, .. }
            | NodeKind::DocumentType { name, .. } => Some(name.as_str()),
            NodeKind::ProcessingInstruction { target, .. } => Some(target.as_str()),
            _ => None,
        })
    }

    /// The prefix of an element.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn prefix(&self, node: TreeNode) -> Result<Option<&str>, TreeError> {
        let id = self.live(node)?;
        Ok(match &self.document.node(id).kind {
            NodeKind::Element { prefix, .. } => prefix.as_deref(),
            _ => None,
        })
    }

    /// The namespace URI of an element.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn namespace(&self, node: TreeNode) -> Result<Option<&str>, TreeError> {
        let id = self.live(node)?;
        Ok(match &self.document.node(id).kind {
            NodeKind::Element { namespace, .. } => namespace.as_deref(),
            _ => None,
        })
    }

    /// The character data of a text, CDATA or comment node, or the value of a
    /// processing instruction; `None` for other nodes.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn text(&self, node: TreeNode) -> Result<Option<&str>, TreeError> {
        let id = self.live(node)?;
        Ok(match &self.document.node(id).kind {
            NodeKind::Text { content }
            | NodeKind::CData { content }
            | NodeKind::Comment { content } => Some(content.as_str()),
            NodeKind::ProcessingInstruction { data, .. } => data.as_deref(),
            _ => None,
        })
    }

    /// The character data of `node` and its descendants, in document order.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn text_content(&self, node: TreeNode) -> Result<String, TreeError> {
        Ok(self.document.text_content(self.live(node)?))
    }

    /// The attributes of an element, namespace declarations excluded; empty
    /// for other nodes.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn attributes(
        &self,
        node: TreeNode,
    ) -> Result<impl Iterator<Item = TreeAttribute<'_>>, TreeError> {
        let id = self.live(node)?;
        Ok(self
            .document
            .attributes(id)
            .iter()
            .filter(|attribute| !is_declaration(attribute))
            .map(|attribute| TreeAttribute {
                local_name: attribute.name.as_str(),
                prefix: attribute.prefix.as_deref(),
                namespace: attribute.namespace.as_deref(),
                value: attribute.value.as_str(),
            }))
    }

    /// The namespace declarations of an element; empty for other nodes.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn namespace_declarations(
        &self,
        node: TreeNode,
    ) -> Result<impl Iterator<Item = TreeNamespace<'_>>, TreeError> {
        let id = self.live(node)?;
        Ok(self.document.attributes(id).iter().filter_map(declaration))
    }

    /// The value of the attribute of `node` with `local_name` in `namespace`
    /// (`None`: no namespace).
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] for a node that is not live.
    pub fn attribute(
        &self,
        node: TreeNode,
        local_name: &str,
        namespace: Option<&str>,
    ) -> Result<Option<&str>, TreeError> {
        let namespace = namespace.filter(|uri| !uri.is_empty());
        Ok(self
            .attributes(node)?
            .find(|attribute| {
                attribute.local_name == local_name && attribute.namespace == namespace
            })
            .map(|attribute| attribute.value))
    }

    /// The one live, linked element whose attribute carries the ID `value`:
    /// the registered one or a carrier the table shadows. `None` when no
    /// linked element carries it, or when two do, since a reference to an
    /// ambiguous ID names neither (an ID is unique in a valid document, XML
    /// 1.0 section 3.3.1, and xml:id 1.0 section 4).
    #[must_use]
    pub fn element_by_id(&self, value: &str) -> Option<TreeNode> {
        let carries = |source: &IdSource| {
            self.contains(source.element)
                && self.attached(source.element)
                && self
                    .attribute(source.element, &source.name, source.namespace.as_deref())
                    .ok()
                    .flatten()
                    == Some(value)
        };
        let mut found = None;
        for source in self
            .ids
            .get(value)
            .into_iter()
            .chain(self.ids.shadowed(value))
        {
            if !carries(source) {
                continue;
            }
            match found {
                None => found = Some(source.element),
                Some(element) if element == source.element => {}
                Some(_) => return None,
            }
        }
        found
    }

    /// Whether `node` hangs under the document node.
    fn attached(&self, node: TreeNode) -> bool {
        let root = self.document.root();
        let mut current = node.id();
        while let Some(id) = current {
            if id == root {
                return true;
            }
            current = self.document.parent(id);
        }
        false
    }

    /// Register the attribute `name` in `namespace` of `element` as carrying
    /// the ID `value`; a later change of that attribute moves or ends the
    /// registration.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`], [`TreeError::NotAnElement`], or
    /// [`TreeError::DuplicateId`] when another live element holds `value`,
    /// as libxml2's `xmlAddID` refuses it.
    pub fn register_id(
        &mut self,
        element: TreeNode,
        name: &str,
        namespace: Option<&str>,
        value: &str,
    ) -> Result<(), TreeError> {
        self.element(element)?;
        // The registration names the attribute and the value it carries, so
        // lookup and projection agree on it.
        if self.attribute(element, name, namespace)? != Some(value) {
            return Err(TreeError::IdNotCarried);
        }
        let source = id_source(element, name, namespace);
        // A caller's registration is not journaled, so its undo record is not kept.
        self.claim(String::from(value), source, &[]).map(drop)
    }

    fn element(&self, node: TreeNode) -> Result<NodeId, TreeError> {
        let id = self.live(node)?;
        match self.document.node(id).kind {
            NodeKind::Element { .. } => Ok(id),
            _ => Err(TreeError::NotAnElement),
        }
    }

    /// A new unlinked element named `local_name`, with `prefix` and in
    /// `namespace`; it declares nothing until a declaration is added.
    ///
    /// # Errors
    /// [`TreeError::InvalidText`] for a name holding NUL.
    pub fn create_element(
        &mut self,
        local_name: &str,
        prefix: Option<&str>,
        namespace: Option<&str>,
    ) -> Result<TreeNode, TreeError> {
        valid(local_name)?;
        prefix.map(valid).transpose()?;
        namespace.map(valid).transpose()?;
        Ok(TreeNode::of(self.document.create_node(NodeKind::Element {
            name: String::from(local_name),
            prefix: prefix.map(String::from),
            namespace: namespace.filter(|uri| !uri.is_empty()).map(String::from),
            attributes: Vec::new(),
        })))
    }

    /// A new unlinked text node.
    ///
    /// # Errors
    /// [`TreeError::InvalidText`] for text holding NUL.
    pub fn create_text(&mut self, text: &str) -> Result<TreeNode, TreeError> {
        valid(text)?;
        Ok(TreeNode::of(self.document.create_text(text)))
    }

    /// A new unlinked comment.
    ///
    /// # Errors
    /// [`TreeError::InvalidText`] for text holding NUL.
    pub fn create_comment(&mut self, text: &str) -> Result<TreeNode, TreeError> {
        valid(text)?;
        Ok(TreeNode::of(self.document.create_comment(text)))
    }

    /// A new unlinked processing instruction.
    ///
    /// # Errors
    /// [`TreeError::InvalidText`] for a target or value holding NUL.
    pub fn create_processing_instruction(
        &mut self,
        target: &str,
        value: Option<&str>,
    ) -> Result<TreeNode, TreeError> {
        valid(target)?;
        value.map(valid).transpose()?;
        Ok(TreeNode::of(
            self.document.create_processing_instruction(target, value),
        ))
    }

    /// Declare `prefix` (`None`: the default namespace) for `uri` on
    /// `element`, replacing a declaration of the same prefix.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`], [`TreeError::NotAnElement`] or
    /// [`TreeError::InvalidText`].
    pub fn declare_namespace(
        &mut self,
        element: TreeNode,
        prefix: Option<&str>,
        uri: &str,
    ) -> Result<(), TreeError> {
        let id = self.element(element)?;
        valid(uri)?;
        prefix.map(valid).transpose()?;
        let (name, attribute_prefix) = match prefix {
            Some(prefix) => (prefix, Some("xmlns")),
            None => ("xmlns", None),
        };
        self.put_attribute(id, name, attribute_prefix, None, uri);
        Ok(())
    }

    /// Set the attribute of `element` named `local_name` in `namespace` with
    /// `prefix` to `value`, adding it if absent.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`], [`TreeError::NotAnElement`] or
    /// [`TreeError::InvalidText`].
    pub fn set_attribute(
        &mut self,
        element: TreeNode,
        local_name: &str,
        prefix: Option<&str>,
        namespace: Option<&str>,
        value: &str,
    ) -> Result<(), TreeError> {
        let id = self.element(element)?;
        valid(local_name)?;
        valid(value)?;
        prefix.map(valid).transpose()?;
        namespace.map(valid).transpose()?;
        // An ID the attribute carries moves with its value: libxml2 removes
        // the ID of a changed attribute and adds the new value. A value
        // another element holds refuses the change before anything moves
        // (xml:id 1.0 section 4: a repeated ID is an error).
        let source = id_source(element, local_name, namespace);
        let xml_id = is_xml_id(local_name, namespace);
        let carries = self.ids.carries(&source);
        if xml_id || carries {
            let mut next = String::from(value);
            if xml_id {
                normalize_id_value(&mut next);
            }
            self.check_claim(&next, &source, &[])?;
        }
        self.ids.remove_source(&source);
        self.put_attribute(id, local_name, prefix, namespace, value);
        // A caller's edit is not journaled, so its undo records are not kept;
        // the check above already admitted the value.
        if xml_id {
            self.register_xml_id(id, &[])?;
        } else if carries {
            self.claim(String::from(value), source, &[])?;
        }
        Ok(())
    }

    fn put_attribute(
        &mut self,
        id: NodeId,
        local_name: &str,
        prefix: Option<&str>,
        namespace: Option<&str>,
        value: &str,
    ) {
        let declaration = prefix == Some("xmlns") || (prefix.is_none() && local_name == "xmlns");
        // An empty URI is no namespace, as the stored attribute keeps it.
        let namespace = namespace.filter(|uri| !uri.is_empty());
        if let NodeKind::Element { attributes, .. } = &mut self.document.node_mut(id).kind {
            // A declaration `xmlns:p` and an attribute `p` share a local name
            // and no namespace; only one of the same sort is the same.
            let same = |attribute: &&mut Attribute| {
                attribute.name == local_name
                    && is_declaration(attribute) == declaration
                    && if declaration {
                        attribute.prefix.as_deref() == prefix
                    } else {
                        attribute.namespace.as_deref() == namespace
                    }
            };
            match attributes.iter_mut().find(same) {
                Some(attribute) => {
                    attribute.value = String::from(value);
                    attribute.prefix = prefix.map(String::from);
                    attribute.raw_value = None;
                }
                None => attributes.push(Attribute {
                    name: String::from(local_name),
                    value: String::from(value),
                    prefix: prefix.map(String::from),
                    namespace: namespace.map(String::from),
                    raw_value: None,
                }),
            }
        }
    }

    /// Give `element` the prefix `prefix` and the namespace `namespace`,
    /// keeping its local name; the binding must be declared for the document
    /// to serialize as it reads.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`], [`TreeError::NotAnElement`] or
    /// [`TreeError::InvalidText`].
    pub fn set_element_namespace(
        &mut self,
        element: TreeNode,
        prefix: Option<&str>,
        namespace: Option<&str>,
    ) -> Result<(), TreeError> {
        let id = self.element(element)?;
        prefix.map(valid).transpose()?;
        namespace.map(valid).transpose()?;
        if let NodeKind::Element {
            prefix: current_prefix,
            namespace: current_namespace,
            ..
        } = &mut self.document.node_mut(id).kind
        {
            *current_prefix = prefix.map(String::from);
            *current_namespace = namespace.filter(|uri| !uri.is_empty()).map(String::from);
        }
        Ok(())
    }

    /// Remove the attribute of `element` named `local_name` in `namespace`.
    /// Whether one was removed.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] or [`TreeError::NotAnElement`].
    pub fn remove_attribute(
        &mut self,
        element: TreeNode,
        local_name: &str,
        namespace: Option<&str>,
    ) -> Result<bool, TreeError> {
        let id = self.element(element)?;
        let namespace = namespace.filter(|uri| !uri.is_empty());
        // A removed attribute carries its ID away.
        self.ids
            .remove_source(&id_source(element, local_name, namespace));
        let NodeKind::Element { attributes, .. } = &mut self.document.node_mut(id).kind else {
            return Err(TreeError::NotAnElement);
        };
        let before = attributes.len();
        attributes.retain(|attribute| {
            is_declaration(attribute)
                || attribute.name != local_name
                || attribute.namespace.as_deref() != namespace
        });
        Ok(attributes.len() < before)
    }

    /// Make the content of `node` one text node holding `text` (an element),
    /// or its character data `text` (a text, CDATA, comment or processing
    /// instruction node). The element's former children are freed.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`], [`TreeError::InvalidText`], or
    /// [`TreeError::DocumentNode`] for a node that holds no text.
    pub fn set_text(&mut self, node: TreeNode, text: &str) -> Result<(), TreeError> {
        let id = self.live(node)?;
        valid(text)?;
        if matches!(self.document.node(id).kind, NodeKind::Element { .. }) {
            while let Some(child) = self.document.first_child(id) {
                self.free(TreeNode::of(child))?;
            }
            if !text.is_empty() {
                let created = self.document.create_text(text);
                self.document.append_child(id, created);
            }
            return Ok(());
        }
        if self.document.set_text_content(id, text) {
            Ok(())
        } else {
            Err(TreeError::DocumentNode)
        }
    }

    /// Link the unlinked `child` as the last child of `parent`.
    ///
    /// # Errors
    /// A node that is not live, a linked `child`, the document node as
    /// `child`, or a link that would make `child` its own ancestor.
    pub fn append_child(&mut self, parent: TreeNode, child: TreeNode) -> Result<(), TreeError> {
        let (parent, child) = self.linkable(parent, child)?;
        self.leave_holder(child);
        self.document.append_child(parent, child);
        Ok(())
    }

    /// Link the unlinked `node` just before `reference`.
    ///
    /// # Errors
    /// As for [`Self::append_child`], or a `reference` without a parent.
    pub fn insert_before(&mut self, reference: TreeNode, node: TreeNode) -> Result<(), TreeError> {
        let parent = self.parent(reference)?.ok_or(TreeError::NoParent)?;
        let (_, node) = self.linkable(parent, node)?;
        let reference = self.live(reference)?;
        self.leave_holder(node);
        self.document.insert_before(reference, node);
        Ok(())
    }

    /// Put the unlinked run of siblings that starts at `first` (as
    /// [`Self::parse_in_context`] returns one) in the place of `old`, which
    /// is unlinked, as libxml2 replaces a node with parsed content. The IDs
    /// `old` and its subtree held pass to the run's `xml:id` attributes that
    /// carry them, since `old` has left the document.
    ///
    /// # Errors
    /// As for [`Self::insert_before`], checked for every node of the run
    /// before anything moves; [`TreeError::DocumentNode`] for the document
    /// node as `old`.
    pub fn replace_with_run(&mut self, old: TreeNode, first: TreeNode) -> Result<(), TreeError> {
        let parent = self.parent(old)?.ok_or(TreeError::NoParent)?;
        let old_id = self.live(old)?;
        let mut run = Vec::new();
        let mut current = Some(self.live(first)?);
        while let Some(id) = current {
            run.push(id);
            current = self.document.next_sibling(id);
        }
        for &id in &run {
            self.linkable(parent, TreeNode::of(id))?;
        }
        for &id in &run {
            self.leave_holder(id);
            self.document.insert_before(old_id, id);
        }
        self.unlink(old)?;
        // The run's IDs were claimed while `old` held them; with `old`
        // released they take them and `old` is shadowed, so linking it again
        // makes the value ambiguous rather than silently taken. A value held
        // elsewhere keeps its element and shadows the run's.
        for &top in &run {
            let elements: Vec<NodeId> = core::iter::once(top)
                .chain(self.document.descendants(top))
                .collect();
            for element in elements {
                self.register_or_shadow_xml_id(element, &[old_id]);
            }
        }
        Ok(())
    }

    /// Link the unlinked `node` just after `reference`.
    ///
    /// # Errors
    /// As for [`Self::insert_before`].
    pub fn insert_after(&mut self, reference: TreeNode, node: TreeNode) -> Result<(), TreeError> {
        let parent = self.parent(reference)?.ok_or(TreeError::NoParent)?;
        let (_, node) = self.linkable(parent, node)?;
        let reference = self.live(reference)?;
        self.leave_holder(node);
        self.document.insert_after(reference, node);
        Ok(())
    }

    /// The nodes of a link of `child` under `parent`; a child kept in an
    /// unlinked run counts as unlinked.
    fn linkable(&self, parent: TreeNode, child: TreeNode) -> Result<(NodeId, NodeId), TreeError> {
        let parent_id = self.live(parent)?;
        let child_id = self.live(child)?;
        if child_id == self.document.root() {
            return Err(TreeError::DocumentNode);
        }
        if self.linked_parent(child_id).is_some() {
            return Err(TreeError::AlreadyLinked);
        }
        // The child must not be `parent` or one of its ancestors.
        let mut current = Some(parent_id);
        while let Some(id) = current {
            if id == child_id {
                return Err(TreeError::Cycle);
            }
            current = self.document.parent(id);
        }
        Ok((parent_id, child_id))
    }

    /// Unlink `node` from its parent, or take it out of the unlinked run it
    /// belongs to; it and its subtree stay live.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] or [`TreeError::DocumentNode`].
    pub fn unlink(&mut self, node: TreeNode) -> Result<(), TreeError> {
        let id = self.live(node)?;
        if id == self.document.root() {
            return Err(TreeError::DocumentNode);
        }
        self.leave_holder(id);
        self.document.detach(id);
        Ok(())
    }

    /// Unlink `node` and free it with its subtree; every name of those nodes
    /// is refused from now on.
    ///
    /// # Errors
    /// [`TreeError::StaleNode`] or [`TreeError::DocumentNode`].
    pub fn free(&mut self, node: TreeNode) -> Result<(), TreeError> {
        self.unlink(node)?;
        let id = self.live(node)?;
        self.mark_freed(id);
        Ok(())
    }

    fn mark_freed(&mut self, id: NodeId) {
        let mut stack = alloc::vec![id];
        while let Some(current) = stack.pop() {
            let raw = current.into_raw() as usize;
            if self.freed.len() <= raw {
                self.freed.resize(self.document.node_count() + 1, false);
            }
            self.freed[raw] = true;
            stack.extend(self.document.children(current));
            // The number stays refused, but its names, text and attributes
            // are released now rather than with the document.
            self.document.node_mut(current).kind = NodeKind::Text {
                content: String::new(),
            };
        }
    }

    /// Report every node of the tree from `first` on to `sink`.
    fn walk(&self, first: Option<NodeId>, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
        // Each entry is the next sibling to visit at one open level and what
        // closes when that level ends.
        let mut stack: Vec<(Option<NodeId>, Closes)> = alloc::vec![(first, Closes::Nothing)];
        while let Some((current, closes)) = stack.pop() {
            let Some(id) = current else {
                match closes {
                    Closes::Nothing => {}
                    Closes::Element => sink.end_element()?,
                    Closes::Entity => sink.leave_entity()?,
                }
                continue;
            };
            let next = self.document.next_sibling(id);
            stack.push((next, closes));
            let node = TreeNode::of(id);
            let reference = ExternalNode(u64::from(node.get()));
            match &self.document.node(id).kind {
                NodeKind::Element {
                    name,
                    prefix,
                    namespace,
                    attributes,
                } => {
                    sink.begin_element(reference, name, prefix.as_deref(), namespace.as_deref())?;
                    for attribute in attributes {
                        if let Some(declared) = declaration(attribute) {
                            sink.declare_namespace(declared.prefix, declared.uri)?;
                        } else {
                            let is_id = self.is_id(id, attribute);
                            sink.attribute(
                                &attribute.name,
                                attribute.prefix.as_deref(),
                                attribute.namespace.as_deref(),
                                &attribute.value,
                                is_id,
                            )?;
                        }
                    }
                    sink.open_element()?;
                    stack.push((self.document.first_child(id), Closes::Element));
                }
                NodeKind::Text { content } | NodeKind::CData { content } => {
                    sink.text(reference, content)?;
                }
                NodeKind::Comment { content } => sink.comment(reference, content)?,
                NodeKind::ProcessingInstruction { target, data } => {
                    sink.processing_instruction(reference, target, data.as_deref())?;
                }
                // The parser hangs the parsed replacement under the reference;
                // its markup is markup (XML 1.0 section 4.4.2), so the children
                // are reported, not the replacement text.
                NodeKind::EntityRef { .. } => {
                    sink.enter_entity()?;
                    stack.push((self.document.first_child(id), Closes::Entity));
                }
                NodeKind::DocumentType { .. } | NodeKind::Document => {}
            }
        }
        Ok(())
    }

    /// Whether `attribute` of `element` is an ID: `xml:id` (xml:id 1.0
    /// section 4), registered in the document's ID table, or a further
    /// carrier of a registered value the table shadows.
    fn is_id(&self, element: NodeId, attribute: &Attribute) -> bool {
        let value = attribute.value.as_str();
        let this = |source: &IdSource| {
            source.is(
                TreeNode::of(element),
                &attribute.name,
                attribute.namespace.as_deref(),
            )
        };
        is_xml_id(&attribute.name, attribute.namespace.as_deref())
            || self.ids.get(value).is_some_and(this)
            || self.ids.shadowed(value).iter().any(this)
    }

    /// Build the fragment's nodes unlinked, in order.
    fn build(&mut self, fragment: &Fragment<'_>) -> Result<Vec<NodeId>, TreeEditError> {
        let mut top = Vec::new();
        let mut open: Vec<NodeId> = Vec::new();
        let mut failure = None;
        let result = fragment.walk(&mut |event| {
            let built = match event {
                FragmentEvent::StartElement {
                    local_name,
                    prefix,
                    namespace,
                } => {
                    let element = self.document.create_node(NodeKind::Element {
                        name: String::from(local_name),
                        prefix: prefix.map(String::from),
                        namespace: namespace.map(String::from),
                        attributes: Vec::new(),
                    });
                    open.push(element);
                    return Ok(());
                }
                FragmentEvent::Namespace { prefix, uri } => {
                    let element = *open
                        .last()
                        .ok_or_else(|| edit_error("a stray declaration"))?;
                    let (name, attribute_prefix) = match prefix {
                        Some(prefix) => (prefix, Some("xmlns")),
                        None => ("xmlns", None),
                    };
                    self.put_attribute(element, name, attribute_prefix, None, uri);
                    return Ok(());
                }
                FragmentEvent::Attribute {
                    local_name,
                    prefix,
                    namespace,
                    value,
                } => {
                    let element = *open.last().ok_or_else(|| edit_error("a stray attribute"))?;
                    // An `xml:id` is registered once the edit is in place
                    // (`register_inserted_ids`).
                    self.put_attribute(element, local_name, prefix, namespace, value);
                    return Ok(());
                }
                FragmentEvent::OpenElement => return Ok(()),
                FragmentEvent::EndElement => {
                    open.pop().ok_or_else(|| edit_error("a stray end tag"))?
                }
                FragmentEvent::Text(text) => self.document.create_text(text),
                FragmentEvent::Comment(text) => self.document.create_comment(text),
                FragmentEvent::ProcessingInstruction { target, value } => {
                    self.document.create_processing_instruction(target, value)
                }
            };
            match open.last() {
                Some(&parent) => self.document.append_child(parent, built),
                None => top.push(built),
            }
            Ok(())
        });
        if let Err(error) = result {
            failure = Some(error);
        }
        if let Some(error) = failure {
            for node in open.into_iter().chain(top) {
                self.mark_freed(node);
            }
            return Err(error);
        }
        Ok(top)
    }

    fn attach(&mut self, parent: NodeId, next: Option<NodeId>, built: &[NodeId]) {
        for &node in built {
            match next {
                Some(next) => self.document.insert_before(next, node),
                None => self.document.append_child(parent, node),
            }
            self.journal.push(Undo::Linked(node));
        }
    }

    fn detach_recorded(&mut self, node: NodeId) {
        if let Some(parent) = self.document.parent(node) {
            let next = self.document.next_sibling(node);
            self.document.detach(node);
            self.journal.push(Undo::Unlinked { node, parent, next });
        }
    }

    fn apply_one(&mut self, edit: &TreeEdit<'_>) -> Result<(), TreeEditError> {
        match *edit {
            TreeEdit::SetText { target, text } => {
                let target = self.target(target)?;
                while let Some(child) = self.document.first_child(target) {
                    self.detach_recorded(child);
                }
                if !text.is_empty() {
                    let created = self.document.create_text(text);
                    self.attach(target, None, &[created]);
                }
            }
            TreeEdit::ReplaceContent { target, fragment } => {
                let target = self.target(target)?;
                let built = self.build(&fragment)?;
                let mut released = Vec::new();
                while let Some(child) = self.document.first_child(target) {
                    self.detach_recorded(child);
                    released.push(child);
                }
                self.attach(target, None, &built);
                self.register_edit_ids(&built, &released)?;
            }
            TreeEdit::AppendChild { target, fragment } => {
                let target = self.target(target)?;
                let built = self.build(&fragment)?;
                self.attach(target, None, &built);
                self.register_edit_ids(&built, &[])?;
            }
            TreeEdit::InsertBefore { target, fragment }
            | TreeEdit::ReplaceNode { target, fragment } => {
                let target = self.target(target)?;
                let parent = self
                    .document
                    .parent(target)
                    .ok_or_else(|| edit_error("the target has no parent"))?;
                let built = self.build(&fragment)?;
                self.attach(parent, Some(target), &built);
                let released = if matches!(edit, TreeEdit::ReplaceNode { .. }) {
                    self.detach_recorded(target);
                    alloc::vec![target]
                } else {
                    Vec::new()
                };
                self.register_edit_ids(&built, &released)?;
            }
        }
        Ok(())
    }

    /// [`Self::register_inserted_ids`] within an edit: a refusal fails the
    /// edit, whose journal then rolls back.
    fn register_edit_ids(
        &mut self,
        built: &[NodeId],
        released: &[NodeId],
    ) -> Result<(), TreeEditError> {
        self.register_inserted_ids(built, released)
            .map_err(|error| edit_error(&alloc::format!("{error}")))
    }

    fn target(&self, node: ExternalNode) -> Result<NodeId, TreeEditError> {
        let raw = u32::try_from(node.0).map_err(|_| edit_error("a foreign node"))?;
        TreeNode::new(raw)
            .ok_or_else(|| edit_error("a foreign node"))
            .and_then(|node| {
                self.live(node)
                    .map_err(|error| edit_error(&alloc::format!("{error}")))
            })
    }
}

impl ExternalTree for OwnedTree {
    fn document(&self) -> ExternalNode {
        ExternalNode(u64::from(self.document_node().get()))
    }

    fn project(&self, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
        let root = self.document.root();
        if self
            .document
            .children(root)
            .any(|id| matches!(self.document.node(id).kind, NodeKind::DocumentType { .. }))
        {
            sink.document_type()?;
        }
        self.walk(self.document.first_child(root), sink)
    }

    fn apply(&mut self, edits: &[TreeEdit<'_>]) -> Result<(), TreeEditError> {
        for edit in edits {
            self.apply_one(edit)?;
        }
        Ok(())
    }

    fn checkpoint(&mut self) -> usize {
        self.journal.len()
    }

    fn rollback(&mut self, mark: usize) {
        while self.journal.len() > mark {
            match self.journal.pop() {
                Some(Undo::Linked(node)) => {
                    self.document.detach(node);
                    self.mark_freed(node);
                }
                Some(Undo::Unlinked { node, parent, next }) => match next {
                    Some(next) => self.document.insert_before(next, node),
                    None => self.document.append_child(parent, node),
                },
                Some(Undo::Id { value, previous }) => match previous {
                    Some(previous) => {
                        self.ids.insert(value, previous);
                    }
                    None => {
                        self.ids.remove(value.as_str());
                    }
                },
                None => break,
            }
        }
    }

    fn into_owned_tree(self: alloc::boxed::Box<Self>) -> Option<OwnedTree> {
        Some(*self)
    }

    fn release(&mut self, mark: usize) {
        let removed: Vec<NodeId> = self
            .journal
            .drain(mark..)
            .filter_map(|undo| match undo {
                Undo::Unlinked { node, .. } => Some(node),
                Undo::Linked(_) | Undo::Id { .. } => None,
            })
            .collect();
        for node in removed {
            // A node a later edit of the batch relinked is still in the tree.
            if self.document.parent(node).is_none() {
                self.mark_freed(node);
            }
        }
    }
}

/// What ends with one open level of a walk.
#[derive(Clone, Copy)]
enum Closes {
    /// The level of the walk's first node.
    Nothing,
    /// An element's content.
    Element,
    /// An entity reference's replacement.
    Entity,
}

/// The ID table's key for the attribute `name` in `namespace` of `element`;
/// an empty URI is no namespace.
fn id_source(element: TreeNode, name: &str, namespace: Option<&str>) -> IdSource {
    IdSource {
        element,
        name: String::from(name),
        namespace: namespace.filter(|uri| !uri.is_empty()).map(String::from),
    }
}

/// Normalize `value` in place as an ID value (xml:id 1.0 section 4).
fn normalize_id_value(value: &mut String) {
    Native
        .normalize_id(value)
        .expect("normalizing in place allocates nothing");
}

/// The ID table's key for the `xml:id` attribute of `element`.
fn xml_id_source(element: TreeNode) -> IdSource {
    IdSource {
        element,
        name: String::from("id"),
        namespace: Some(String::from(XML_NAMESPACE)),
    }
}

/// Whether `local_name` in `namespace` names `xml:id` (xml:id 1.0 section 4).
fn is_xml_id(local_name: &str, namespace: Option<&str>) -> bool {
    local_name == "id" && namespace == Some(XML_NAMESPACE)
}

/// Whether `attribute` is a namespace declaration.
fn is_declaration(attribute: &Attribute) -> bool {
    attribute.prefix.as_deref() == Some("xmlns")
        || (attribute.prefix.is_none() && attribute.name == "xmlns")
}

/// The declaration `attribute` makes, if it is one.
fn declaration(attribute: &Attribute) -> Option<TreeNamespace<'_>> {
    if attribute.prefix.as_deref() == Some("xmlns") {
        Some(TreeNamespace {
            prefix: Some(attribute.name.as_str()),
            uri: attribute.value.as_str(),
        })
    } else if attribute.prefix.is_none() && attribute.name == "xmlns" {
        Some(TreeNamespace {
            prefix: None,
            uri: attribute.value.as_str(),
        })
    } else {
        None
    }
}

/// Append `value` to `out` as the content of a double-quoted attribute value
/// (XML 1.0 section 2.3, production `AttValue`).
fn push_attribute_value(out: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
}

/// XML 1.0 section 2.2: no NUL in names or character data.
fn valid(text: &str) -> Result<&str, TreeError> {
    if text.contains('\0') {
        Err(TreeError::InvalidText)
    } else {
        Ok(text)
    }
}

fn edit_error(message: &str) -> TreeEditError {
    TreeEditError(String::from(message))
}

fn syntax(error: xmloxide::error::ParseError) -> ParseError {
    match error {
        xmloxide::error::ParseError::Resource(error) => error,
        error @ xmloxide::error::ParseError::Syntax { .. } => ParseError::Backend {
            backend: "xmloxide",
            message: alloc::format!("{error}"),
        },
    }
}

#[cfg(test)]
mod tests;
