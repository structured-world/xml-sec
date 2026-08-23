//! Core types for the XMLDSig transform pipeline.
//!
//! These types flow between URI dereference, transforms, and digest computation.
//!
//! These types are consumed by URI dereference, the transform chain (P1-014,
//! P1-015), and reference processing (P1-018).

use std::cell::Cell;
use std::collections::HashSet;
use std::ops::RangeInclusive;

use roxmltree::{Document, Node, NodeId};

const MAX_NODE_SET_ENTRIES: usize = crate::hard_limits::NODE_SET_ENTRY_CEILING;
const MAX_NODE_SET_OWNED_STRING_BYTES: usize =
    crate::hard_limits::NODE_SET_OWNED_STRING_BYTE_CEILING;
const MAX_NODE_SET_CUMULATIVE_OWNED_STRING_BYTES: usize =
    crate::hard_limits::NODE_SET_CUMULATIVE_OWNED_STRING_BYTE_CEILING;

use crate::c14n::NodeVisibility;

// roxmltree 0.21 uses `Node<'a, 'input: 'a>`. We tie both lifetimes together
// with a single `'a` by requiring `'input = 'a` at every use site (`Node<'a, 'a>`).
// This is safe because our NodeSet borrows the Document which owns the input.

/// Data flowing between transforms in the verification/signing pipeline.
///
/// Transforms consume and produce either a node set (XML-level) or raw bytes
/// (after canonicalization or base64 decode).
pub enum TransformData<'a> {
    /// A set of nodes from the parsed XML document.
    NodeSet(NodeSet<'a>),
    /// Raw bytes (e.g., after canonicalization).
    Binary(Vec<u8>),
}

impl std::fmt::Debug for TransformData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NodeSet(_) => f.debug_tuple("NodeSet").field(&"...").finish(),
            Self::Binary(b) => f.debug_tuple("Binary").field(&b.len()).finish(),
        }
    }
}

impl<'a> TransformData<'a> {
    /// Convert to `NodeSet`, returning an error if this is `Binary` data.
    pub fn into_node_set(self) -> Result<NodeSet<'a>, TransformError> {
        match self {
            Self::NodeSet(ns) => Ok(ns),
            Self::Binary(_) => Err(TransformError::TypeMismatch {
                expected: "NodeSet",
                got: "Binary",
            }),
        }
    }

    /// Convert to binary bytes, returning an error if this is a `NodeSet`.
    pub fn into_binary(self) -> Result<Vec<u8>, TransformError> {
        match self {
            Self::Binary(b) => Ok(b),
            Self::NodeSet(_) => Err(TransformError::TypeMismatch {
                expected: "Binary",
                got: "NodeSet",
            }),
        }
    }
}

/// A set of nodes from a roxmltree document.
///
/// Represents the exact XPath nodes included for canonicalization and transforms.
///
/// Attributes and namespace bindings are first-class XPath nodes even though
/// roxmltree exposes them through their owner element. Materializing them here
/// lets XPath filters independently include or remove those nodes as required
/// by canonical XML document-subset processing.
pub struct NodeSet<'a> {
    /// Reference to the parsed document.
    doc: &'a Document<'a>,
    nodes: HashSet<XmlNodeKey>,
    owned_string_bytes: usize,
    /// Whether comment nodes are included. For empty URI dereference (whole
    /// document), comments are excluded per XMLDSig spec.
    with_comments: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum XmlNodeKey {
    Tree(NodeId),
    Attribute {
        owner: NodeId,
        namespace: Option<String>,
        local_name: String,
    },
    Namespace {
        owner: NodeId,
        prefix: String,
        uri: String,
    },
}

pub(crate) struct NodeSetMaterializationBudget {
    remaining_owned_string_bytes: Cell<usize>,
    max_entries: usize,
    max_owned_string_bytes: usize,
    max_cumulative_owned_string_bytes: usize,
}

impl Default for NodeSetMaterializationBudget {
    fn default() -> Self {
        Self {
            remaining_owned_string_bytes: Cell::new(MAX_NODE_SET_CUMULATIVE_OWNED_STRING_BYTES),
            max_entries: MAX_NODE_SET_ENTRIES,
            max_owned_string_bytes: MAX_NODE_SET_OWNED_STRING_BYTES,
            max_cumulative_owned_string_bytes: MAX_NODE_SET_CUMULATIVE_OWNED_STRING_BYTES,
        }
    }
}

impl NodeSetMaterializationBudget {
    fn charge(&self, owned_string_bytes: usize) -> Result<(), TransformError> {
        let remaining_before = self.remaining_owned_string_bytes.get();
        let Some(remaining) = self
            .remaining_owned_string_bytes
            .get()
            .checked_sub(owned_string_bytes)
        else {
            self.remaining_owned_string_bytes.set(0);
            let consumed = self
                .max_cumulative_owned_string_bytes
                .saturating_sub(remaining_before);
            return Err(transform_resource_limit(
                crate::policy::resource_name::NODE_SET_CUMULATIVE_OWNED_STRING_BYTES,
                self.max_cumulative_owned_string_bytes,
                consumed.saturating_add(owned_string_bytes),
            ));
        };
        self.remaining_owned_string_bytes.set(remaining);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            remaining_owned_string_bytes: Cell::new(limit),
            max_cumulative_owned_string_bytes: limit,
            ..Self::default()
        }
    }

    pub(crate) fn with_limits(
        max_entries: usize,
        max_owned_string_bytes: usize,
        max_cumulative_owned_string_bytes: usize,
    ) -> Self {
        Self {
            remaining_owned_string_bytes: Cell::new(max_cumulative_owned_string_bytes),
            max_entries,
            max_owned_string_bytes,
            max_cumulative_owned_string_bytes,
        }
    }
}

impl XmlNodeKey {
    fn owner_id(&self) -> NodeId {
        match self {
            Self::Tree(id) => *id,
            Self::Attribute { owner, .. } | Self::Namespace { owner, .. } => *owner,
        }
    }

    fn owned_string_bytes(&self) -> usize {
        match self {
            Self::Tree(_) => 0,
            Self::Attribute {
                namespace,
                local_name,
                ..
            } => namespace
                .as_ref()
                .map_or(0, String::len)
                .saturating_add(local_name.len()),
            Self::Namespace { prefix, uri, .. } => prefix.len().saturating_add(uri.len()),
        }
    }

    fn checked_owned_string_bytes(&self) -> Option<usize> {
        match self {
            Self::Tree(_) => Some(0),
            Self::Attribute {
                namespace,
                local_name,
                ..
            } => namespace
                .as_ref()
                .map_or(0, String::len)
                .checked_add(local_name.len()),
            Self::Namespace { prefix, uri, .. } => prefix.len().checked_add(uri.len()),
        }
    }
}

impl<'a> NodeSet<'a> {
    /// Create a node set representing the entire document without comments.
    ///
    /// Per XMLDSig §4.3.3.2: "An empty URI [...] is a reference to the document
    /// [...] and the comment nodes are not included."
    ///
    /// # Errors
    ///
    /// Returns [`TransformError::Policy`] when projecting the document's tree,
    /// attribute, namespace, or owned string data would exceed its budget.
    pub fn entire_document_without_comments(doc: &'a Document<'a>) -> Result<Self, TransformError> {
        Self::ensure_subtree_materialization_fits(doc.root(), false)?;
        Ok(Self::collect_document(doc, false))
    }

    pub(crate) fn entire_document_without_comments_with_budget(
        doc: &'a Document<'a>,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<Self, TransformError> {
        Self::charge_subtree_materialization(doc.root(), false, budget)?;
        Ok(Self::collect_document(doc, false))
    }

    /// Create a node set representing the entire document with comments.
    ///
    /// Used for `#xpointer(/)` which, unlike empty URI, includes comment nodes.
    ///
    /// # Errors
    ///
    /// Returns [`TransformError::Policy`] when projecting the document's tree,
    /// attribute, namespace, or owned string data would exceed its budget.
    pub fn entire_document_with_comments(doc: &'a Document<'a>) -> Result<Self, TransformError> {
        Self::ensure_subtree_materialization_fits(doc.root(), true)?;
        Ok(Self::collect_document(doc, true))
    }

    pub(crate) fn entire_document_with_comments_with_budget(
        doc: &'a Document<'a>,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<Self, TransformError> {
        Self::charge_subtree_materialization(doc.root(), true, budget)?;
        Ok(Self::collect_document(doc, true))
    }

    /// Create a node set rooted at `element`, containing that element and all
    /// of its descendant nodes (elements, text, and, for this constructor,
    /// comment nodes).
    ///
    /// # Errors
    ///
    /// Returns [`TransformError::Policy`] when projecting the subtree's tree,
    /// attribute, namespace, or owned string data would exceed its budget.
    pub fn subtree(element: Node<'a, 'a>) -> Result<Self, TransformError> {
        Self::ensure_subtree_materialization_fits(element, true)?;
        Ok(Self::collect_subtree(element))
    }

    /// Create a bare-name same-document fragment node-set, which excludes
    /// comment nodes before any transforms are applied.
    pub(crate) fn subtree_without_comments_with_budget(
        element: Node<'a, 'a>,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<Self, TransformError> {
        match budget {
            Some(budget) => Self::charge_subtree_materialization(element, false, budget)?,
            None => {
                Self::ensure_subtree_materialization_fits(element, false)?;
            }
        }
        let mut set = Self {
            doc: element.document(),
            nodes: HashSet::new(),
            owned_string_bytes: 0,
            with_comments: false,
        };
        for node in element.descendants().filter(|node| !node.is_comment()) {
            set.insert_node(node);
            if node.is_element() {
                for attribute in node.attributes() {
                    set.insert_attribute(node, attribute.namespace(), attribute.name());
                }
                for namespace in node.namespaces() {
                    set.insert_namespace(node, namespace.name().unwrap_or(""), namespace.uri());
                }
            }
        }
        Ok(set)
    }

    pub(crate) fn subtree_with_budget(
        element: Node<'a, 'a>,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<Self, TransformError> {
        Self::charge_subtree_materialization(element, true, budget)?;
        Ok(Self::collect_subtree(element))
    }

    fn collect_subtree(element: Node<'a, 'a>) -> Self {
        let mut set = Self {
            doc: element.document(),
            nodes: HashSet::new(),
            owned_string_bytes: 0,
            with_comments: true,
        };
        set.insert_subtree(element);
        set
    }

    /// Reference to the underlying document.
    pub fn document(&self) -> &'a Document<'a> {
        self.doc
    }

    /// Check whether a node is in this set.
    ///
    /// Returns `false` for nodes from a different document than this set's
    /// owning document (prevents cross-document NodeId collisions).
    pub fn contains(&self, node: Node<'_, '_>) -> bool {
        // Guard: reject nodes from a different document. NodeIds are
        // per-document indices — the same index from another document
        // would reference a completely different node.
        if !std::ptr::eq(node.document() as *const _, self.doc as *const _) {
            return false;
        }

        self.nodes.contains(&XmlNodeKey::Tree(node.id()))
    }

    /// Exclude a node and all its descendants from this set.
    ///
    /// No-op for nodes from a different document.
    pub fn exclude_subtree(&mut self, node: Node<'_, '_>) {
        // Guard: only exclude nodes from our document
        if !std::ptr::eq(node.document() as *const _, self.doc as *const _) {
            return;
        }
        let excluded_ids = subtree_node_id_range(node);
        // roxmltree NodeIds index a document-order Vec, and descendants() is a
        // contiguous slice of that Vec. Attribute and namespace keys carry the
        // owner NodeId, so one range check excludes every XPath node kind without
        // either walking ancestors per key or materializing the excluded subtree.
        self.nodes
            .retain(|key| !excluded_ids.contains(&key.owner_id().get()));
        self.refresh_owned_string_bytes();
    }

    /// Whether comments are included in this node set.
    pub fn with_comments(&self) -> bool {
        self.with_comments
    }

    pub(crate) fn empty(doc: &'a Document<'a>) -> Self {
        Self {
            doc,
            nodes: HashSet::new(),
            owned_string_bytes: 0,
            with_comments: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn try_entire_document(doc: &'a Document<'a>) -> Result<Self, TransformError> {
        Self::entire_document_with_comments(doc)
    }

    pub(crate) fn try_entire_document_with_budget(
        doc: &'a Document<'a>,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<Self, TransformError> {
        Self::entire_document_with_comments_with_budget(doc, budget)
    }

    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn insert_node(&mut self, node: Node<'_, '_>) {
        if self.owns(node) {
            self.with_comments |= node.is_comment();
            self.nodes.insert(XmlNodeKey::Tree(node.id()));
        }
    }

    pub(crate) fn insert_attribute(
        &mut self,
        owner: Node<'_, '_>,
        namespace: Option<&str>,
        local_name: &str,
    ) {
        if self.owns(owner) {
            let key = XmlNodeKey::Attribute {
                owner: owner.id(),
                namespace: namespace.map(str::to_owned),
                local_name: local_name.to_owned(),
            };
            if self.nodes.insert(key) {
                self.owned_string_bytes = self
                    .owned_string_bytes
                    .saturating_add(namespace.map_or(0, str::len))
                    .saturating_add(local_name.len());
            }
        }
    }

    pub(crate) fn insert_attribute_with_budget(
        &mut self,
        owner: Node<'_, '_>,
        namespace: Option<&str>,
        local_name: &str,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        if self.owns(owner) {
            self.insert_projected_key_with_budget(
                XmlNodeKey::Attribute {
                    owner: owner.id(),
                    namespace: namespace.map(str::to_owned),
                    local_name: local_name.to_owned(),
                },
                budget,
            )?;
        }
        Ok(())
    }

    pub(crate) fn insert_namespace(&mut self, owner: Node<'_, '_>, prefix: &str, uri: &str) {
        if self.owns(owner) {
            let key = XmlNodeKey::Namespace {
                owner: owner.id(),
                prefix: prefix.to_owned(),
                uri: uri.to_owned(),
            };
            if self.nodes.insert(key) {
                self.owned_string_bytes = self
                    .owned_string_bytes
                    .saturating_add(prefix.len())
                    .saturating_add(uri.len());
            }
        }
    }

    pub(crate) fn insert_namespace_with_budget(
        &mut self,
        owner: Node<'_, '_>,
        prefix: &str,
        uri: &str,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        if self.owns(owner) {
            self.insert_projected_key_with_budget(
                XmlNodeKey::Namespace {
                    owner: owner.id(),
                    prefix: prefix.to_owned(),
                    uri: uri.to_owned(),
                },
                budget,
            )?;
        }
        Ok(())
    }

    fn insert_projected_key_with_budget(
        &mut self,
        key: XmlNodeKey,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        if self.nodes.contains(&key) {
            return Ok(());
        }
        let additional_bytes = key.checked_owned_string_bytes().ok_or_else(|| {
            transform_resource_limit(
                crate::policy::resource_name::NODE_SET_OWNED_STRING_BYTES,
                budget.max_owned_string_bytes,
                usize::MAX,
            )
        })?;
        let total_bytes = self.owned_string_bytes.saturating_add(additional_bytes);
        if total_bytes > budget.max_owned_string_bytes {
            return Err(transform_resource_limit(
                crate::policy::resource_name::NODE_SET_OWNED_STRING_BYTES,
                budget.max_owned_string_bytes,
                total_bytes,
            ));
        }
        if self.nodes.len() >= budget.max_entries {
            return Err(transform_resource_limit(
                crate::policy::resource_name::NODE_SET_ENTRIES,
                budget.max_entries,
                self.nodes.len().saturating_add(1),
            ));
        }
        budget.charge(additional_bytes)?;
        let inserted = self.nodes.insert(key);
        debug_assert!(inserted, "the duplicate key was checked before insertion");
        if inserted {
            self.owned_string_bytes = total_bytes;
        }
        Ok(())
    }

    pub(crate) fn insert_subtree(&mut self, root: Node<'_, '_>) {
        if !self.owns(root) {
            return;
        }
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            self.insert_node(node);
            if node.is_element() {
                for attribute in node.attributes() {
                    self.insert_attribute(node, attribute.namespace(), attribute.name());
                }
                for namespace in node.namespaces() {
                    self.insert_namespace(node, namespace.name().unwrap_or(""), namespace.uri());
                }
            }
            stack.extend(node.children());
        }
    }

    pub(crate) fn intersect_with(&mut self, other: &Self) {
        if !std::ptr::eq(self.doc as *const _, other.doc as *const _) {
            self.nodes.clear();
            self.owned_string_bytes = 0;
            self.with_comments = false;
            return;
        }
        self.nodes.retain(|key| other.nodes.contains(key));
        self.refresh_owned_string_bytes();
        self.with_comments &= other.with_comments;
    }

    pub(crate) fn subtract(&mut self, other: &Self) {
        if std::ptr::eq(self.doc as *const _, other.doc as *const _) {
            self.nodes.retain(|key| !other.nodes.contains(key));
            self.refresh_owned_string_bytes();
        }
    }

    pub(crate) fn union_with_budget(
        &mut self,
        other: &Self,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        if std::ptr::eq(self.doc as *const _, other.doc as *const _) {
            for key in &other.nodes {
                if self.nodes.contains(key) {
                    continue;
                }
                let owned_string_bytes = key.owned_string_bytes();
                let total_bytes = self.owned_string_bytes.saturating_add(owned_string_bytes);
                if total_bytes > budget.max_owned_string_bytes {
                    return Err(transform_resource_limit(
                        crate::policy::resource_name::NODE_SET_OWNED_STRING_BYTES,
                        budget.max_owned_string_bytes,
                        total_bytes,
                    ));
                }
                if self.nodes.len() >= budget.max_entries {
                    return Err(transform_resource_limit(
                        crate::policy::resource_name::NODE_SET_ENTRIES,
                        budget.max_entries,
                        self.nodes.len().saturating_add(1),
                    ));
                }
                budget.charge(owned_string_bytes)?;
                self.nodes.insert(key.clone());
                self.owned_string_bytes = total_bytes;
            }
            self.with_comments |= other.with_comments;
        }
        Ok(())
    }

    fn collect_document(doc: &'a Document<'a>, with_comments: bool) -> Self {
        let mut set = Self::empty(doc);
        set.insert_subtree(doc.root());
        if !with_comments {
            set.nodes.retain(|key| match key {
                XmlNodeKey::Tree(id) => !doc.get_node(*id).is_some_and(|node| node.is_comment()),
                _ => true,
            });
        }
        set.with_comments = with_comments;
        set
    }

    fn refresh_owned_string_bytes(&mut self) {
        self.owned_string_bytes = self.nodes.iter().fold(0_usize, |total, key| {
            total.saturating_add(key.owned_string_bytes())
        });
    }

    pub(crate) fn ensure_subtree_materialization_fits(
        root: Node<'_, '_>,
        with_comments: bool,
    ) -> Result<usize, TransformError> {
        Ok(Self::subtree_materialization(root, with_comments)?.entries)
    }

    pub(crate) fn ensure_subtree_materialization_fits_with_budget(
        root: Node<'_, '_>,
        with_comments: bool,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<usize, TransformError> {
        Ok(Self::subtree_materialization_with_limits(
            root,
            with_comments,
            budget.max_entries,
            budget.max_owned_string_bytes,
        )?
        .entries)
    }

    fn charge_subtree_materialization(
        root: Node<'_, '_>,
        with_comments: bool,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        let materialization = Self::subtree_materialization_with_limits(
            root,
            with_comments,
            budget.max_entries,
            budget.max_owned_string_bytes,
        )?;
        budget.charge(materialization.owned_string_bytes)
    }

    fn subtree_materialization(
        root: Node<'_, '_>,
        with_comments: bool,
    ) -> Result<NodeSetMaterialization, TransformError> {
        Self::subtree_materialization_with_limits(
            root,
            with_comments,
            MAX_NODE_SET_ENTRIES,
            MAX_NODE_SET_OWNED_STRING_BYTES,
        )
    }

    fn subtree_materialization_with_limits(
        root: Node<'_, '_>,
        with_comments: bool,
        max_entries: usize,
        max_owned_string_bytes: usize,
    ) -> Result<NodeSetMaterialization, TransformError> {
        let mut entries = 0_usize;
        let mut owned_string_bytes = 0_usize;
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.is_comment() && !with_comments {
                continue;
            }
            let projected = if node.is_element() {
                for attribute in node.attributes() {
                    owned_string_bytes = charge_node_set_string_bytes(
                        owned_string_bytes,
                        attribute.namespace().map_or(0, str::len),
                        max_owned_string_bytes,
                    )?;
                    owned_string_bytes = charge_node_set_string_bytes(
                        owned_string_bytes,
                        attribute.name().len(),
                        max_owned_string_bytes,
                    )?;
                }
                for namespace in node.namespaces() {
                    owned_string_bytes = charge_node_set_string_bytes(
                        owned_string_bytes,
                        namespace.name().map_or(0, str::len),
                        max_owned_string_bytes,
                    )?;
                    owned_string_bytes = charge_node_set_string_bytes(
                        owned_string_bytes,
                        namespace.uri().len(),
                        max_owned_string_bytes,
                    )?;
                }
                1_usize
                    .checked_add(node.attributes().len())
                    .and_then(|count| count.checked_add(node.namespaces().len()))
            } else {
                Some(1)
            }
            .ok_or_else(|| {
                transform_resource_limit(
                    crate::policy::resource_name::NODE_SET_ENTRIES,
                    max_entries,
                    usize::MAX,
                )
            })?;
            entries = entries.checked_add(projected).ok_or_else(|| {
                transform_resource_limit(
                    crate::policy::resource_name::NODE_SET_ENTRIES,
                    max_entries,
                    usize::MAX,
                )
            })?;
            if entries > max_entries {
                return Err(transform_resource_limit(
                    crate::policy::resource_name::NODE_SET_ENTRIES,
                    max_entries,
                    entries,
                ));
            }
            stack.extend(node.children());
        }
        Ok(NodeSetMaterialization {
            entries,
            owned_string_bytes,
        })
    }

    fn owns(&self, node: Node<'_, '_>) -> bool {
        std::ptr::eq(node.document() as *const _, self.doc as *const _)
    }
}

struct NodeSetMaterialization {
    entries: usize,
    owned_string_bytes: usize,
}

fn charge_node_set_string_bytes(
    current: usize,
    additional: usize,
    max_bytes: usize,
) -> Result<usize, TransformError> {
    let total = current.checked_add(additional).ok_or_else(|| {
        transform_resource_limit(
            crate::policy::resource_name::NODE_SET_OWNED_STRING_BYTES,
            max_bytes,
            usize::MAX,
        )
    })?;
    if total > max_bytes {
        return Err(transform_resource_limit(
            crate::policy::resource_name::NODE_SET_OWNED_STRING_BYTES,
            max_bytes,
            total,
        ));
    }
    Ok(total)
}

fn subtree_node_id_range(node: Node<'_, '_>) -> RangeInclusive<u32> {
    let last_id = node
        .descendants()
        .next_back()
        .map_or(node.id(), |descendant| descendant.id());
    node.id().get()..=last_id.get()
}

impl NodeVisibility for NodeSet<'_> {
    fn contains_node(&self, node: Node<'_, '_>) -> bool {
        self.contains(node)
    }

    fn contains_attribute(
        &self,
        owner: Node<'_, '_>,
        namespace: Option<&str>,
        local_name: &str,
    ) -> bool {
        self.owns(owner)
            && self.nodes.contains(&XmlNodeKey::Attribute {
                owner: owner.id(),
                namespace: namespace.map(str::to_owned),
                local_name: local_name.to_owned(),
            })
    }

    fn contains_namespace(&self, owner: Node<'_, '_>, prefix: &str, uri: &str) -> bool {
        self.owns(owner)
            && self.nodes.contains(&XmlNodeKey::Namespace {
                owner: owner.id(),
                prefix: prefix.to_owned(),
                uri: uri.to_owned(),
            })
    }
}

/// Errors during transform processing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransformError {
    /// The active operation policy rejected transform processing.
    #[error("transform policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),

    /// Data type mismatch between transforms.
    #[error("type mismatch: expected {expected}, got {got}")]
    TypeMismatch {
        /// Expected data type.
        expected: &'static str,
        /// Actual data type.
        got: &'static str,
    },

    /// Element not found by ID.
    #[error("element not found by ID: {0}")]
    ElementNotFound(String),

    /// Unsupported URI scheme or format.
    #[error("unsupported URI: {0}")]
    UnsupportedUri(String),

    /// Unsupported transform algorithm.
    #[error("unsupported transform: {0}")]
    UnsupportedTransform(String),

    /// Canonicalization error during transform.
    #[error("C14N error: {0}")]
    C14n(#[from] crate::c14n::C14nError),

    /// Base64 decoding failed during the standard XMLDSig Base64 transform.
    #[error("base64 transform decode error: {0}")]
    Base64(String),

    /// XPath parsing or evaluation failed.
    #[error("XPath transform error: {0}")]
    XPath(String),

    /// XML octets could not be parsed while adapting binary transform output
    /// to the node-set required by a subsequent transform.
    #[error("XML transform input parse error: {0}")]
    XmlParse(String),

    /// The Signature node passed to the enveloped transform belongs to a
    /// different `Document` than the input `NodeSet`.
    #[error("enveloped-signature transform: invalid Signature node for this document")]
    CrossDocumentSignatureNode,
}

pub(crate) fn transform_resource_limit(
    resource: &'static str,
    maximum: usize,
    actual: usize,
) -> TransformError {
    crate::policy::PolicyViolation::ResourceLimit {
        resource,
        maximum,
        actual,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c14n::{C14nAlgorithm, C14nMode, canonicalize_with_visibility};

    #[test]
    fn incremental_projection_enforces_aggregate_owned_string_policy() {
        // XPath builds arbitrary projected sets incrementally. Individually small
        // attribute keys must not bypass the per-set aggregate string ceiling.
        let document = Document::parse("<root/>").expect("fixed XML must parse");
        let root = document.root_element();
        let mut nodes = NodeSet::empty(&document);
        let budget = NodeSetMaterializationBudget::with_limits(16, 3, 16);

        nodes
            .insert_attribute_with_budget(root, None, "a", &budget)
            .expect("the first one-byte attribute name must fit");
        let error = nodes
            .insert_attribute_with_budget(root, None, "bbb", &budget)
            .expect_err("aggregate projected names must exceed three bytes");

        assert!(matches!(
            error,
            TransformError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "node-set owned string bytes",
                maximum: 3,
                actual: 4,
            })
        ));
    }

    #[test]
    fn projected_attribute_and_namespace_share_one_budget_path() {
        // Duplicate projected keys are free, while distinct attributes and
        // namespaces consume the same operation-wide owned-string allowance.
        let document = Document::parse("<root/>").expect("fixed XML must parse");
        let root = document.root_element();
        let mut nodes = NodeSet::empty(&document);
        let budget = NodeSetMaterializationBudget::with_limits(16, 16, 3);

        nodes
            .insert_namespace_with_budget(root, "p", "u", &budget)
            .expect("two namespace bytes must fit");
        nodes
            .insert_namespace_with_budget(root, "p", "u", &budget)
            .expect("a duplicate namespace must not consume budget twice");
        nodes
            .insert_attribute_with_budget(root, None, "a", &budget)
            .expect("one remaining byte must admit an attribute");
        let error = nodes
            .insert_attribute_with_budget(root, None, "b", &budget)
            .expect_err("distinct projected keys must share cumulative accounting");

        assert!(matches!(
            error,
            TransformError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "cumulative node-set owned string bytes",
                maximum: 3,
                actual: 4,
            })
        ));
    }

    #[test]
    fn document_without_comments_preserves_comment_policy() {
        // Empty-URI dereferencing strips comment nodes and must not retain a
        // stale flag merely because comments were seen while materializing.
        let document = Document::parse("<root><!-- excluded --><child/></root>")
            .expect("fixed comment fixture must parse");
        let nodes = NodeSet::entire_document_without_comments(&document)
            .expect("fixed fixture must fit the node-set materialization budget");
        let comment = document
            .descendants()
            .find(|node| node.is_comment())
            .expect("fixed fixture contains one comment");

        assert!(!nodes.contains(comment));
        assert!(!nodes.with_comments());
    }

    #[test]
    fn document_without_comments_preflights_the_materialized_set() {
        // Empty-URI dereference excludes comments before the node-set exists, so
        // comments must not consume the configured entry ceiling during preflight.
        let document = Document::parse("<root><!-- one --><child/><!-- two --></root>")
            .expect("fixed comment fixture must parse");
        let budget = NodeSetMaterializationBudget::with_limits(3, 1, 1);

        let nodes = NodeSet::entire_document_without_comments_with_budget(&document, &budget)
            .expect("the three materialized tree nodes must fit exactly");

        assert_eq!(nodes.nodes.len(), 3);
        assert!(nodes.nodes.iter().all(|key| match key {
            XmlNodeKey::Tree(id) => !document.get_node(*id).is_some_and(|node| node.is_comment()),
            _ => true,
        }));
    }

    #[test]
    fn bare_fragment_preflights_the_materialized_set_without_comments() {
        // Bare-name fragments apply the same XMLDSig comment omission rule to a
        // subtree and therefore must charge only nodes that reach the result.
        let document =
            Document::parse("<root><target><!-- one --><child/><!-- two --></target></root>")
                .expect("fixed comment fixture must parse");
        let target = document
            .descendants()
            .find(|node| node.has_tag_name("target"))
            .expect("fixed fixture contains the selected target");
        let budget = NodeSetMaterializationBudget::with_limits(2, 1, 1);

        let nodes = NodeSet::subtree_without_comments_with_budget(target, Some(&budget))
            .expect("the target and child must fit exactly");

        assert_eq!(nodes.nodes.len(), 2);
        assert!(!nodes.with_comments());
    }

    #[test]
    fn excluding_disjoint_oversized_subtree_only_scans_input_keys() {
        // The excluded Signature subtree is intentionally larger than the
        // constructor budget; a small referenced subtree must remain unchanged
        // without attempting to materialize the irrelevant Signature content.
        let xml = format!(
            "<root><target Id=\"selected\"><child/></target><Signature>{}</Signature></root>",
            "<Object/>".repeat(MAX_NODE_SET_ENTRIES + 1)
        );
        let document = Document::parse(&xml).expect("fixed oversized fixture must parse");
        let target = document
            .descendants()
            .find(|node| node.attribute("Id") == Some("selected"))
            .expect("fixed fixture contains the selected subtree");
        let signature = document
            .descendants()
            .find(|node| node.has_tag_name("Signature"))
            .expect("fixed fixture contains the excluded Signature subtree");
        let mut nodes = NodeSet::subtree(target)
            .expect("small selected subtree must fit the materialization budget");
        let entries_before = nodes.nodes.len();

        nodes.exclude_subtree(signature);

        assert_eq!(nodes.nodes.len(), entries_before);
        assert!(nodes.contains(target));
        assert!(
            nodes.contains(
                target
                    .first_element_child()
                    .expect("fixed target subtree contains a child")
            )
        );
    }

    #[test]
    fn materialization_rejects_inherited_namespace_byte_amplification() {
        // One declaration is cheap in the source XML, but XPath exposes the
        // inherited binding on every descendant. Materializing owned namespace
        // keys must reject the amplified bytes before cloning those strings.
        let namespace_uri = "x".repeat(8_192);
        let xml = format!(
            "<root xmlns:amplified=\"{namespace_uri}\">{}</root>",
            "<child/>".repeat(1_025)
        );
        let document = Document::parse(&xml).expect("fixed namespace fixture must parse");

        let error = NodeSet::entire_document_without_comments(&document)
            .err()
            .expect("amplified namespace bytes must exceed the materialization budget");

        assert!(matches!(
            error,
            TransformError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "node-set owned string bytes",
                ..
            })
        ));
    }

    #[test]
    fn subtree_node_id_range_contains_only_the_selected_subtree() {
        // roxmltree stores a subtree in one contiguous document-order span.
        // The exclusion fast path relies on that span including attributes and
        // namespaces through their owner element, but no adjacent siblings.
        let document = Document::parse(
            "<root><before/><excluded xmlns:gone=\"urn:gone\" a=\"1\"><child/></excluded><after/></root>",
        )
        .expect("fixed subtree range fixture must parse");
        let excluded = document
            .descendants()
            .find(|node| node.has_tag_name("excluded"))
            .expect("fixed fixture contains the excluded subtree");
        let range = subtree_node_id_range(excluded);
        let before = document
            .descendants()
            .find(|node| node.has_tag_name("before"))
            .expect("fixed fixture contains the preceding sibling");
        let child = excluded
            .first_element_child()
            .expect("fixed fixture contains an excluded child");
        let after = document
            .descendants()
            .find(|node| node.has_tag_name("after"))
            .expect("fixed fixture contains the following sibling");

        assert!(!range.contains(&before.id().get()));
        assert!(range.contains(&excluded.id().get()));
        assert!(range.contains(&child.id().get()));
        assert!(!range.contains(&after.id().get()));

        let mut nodes = NodeSet::entire_document_with_comments(&document)
            .expect("fixed fixture must fit the node-set materialization budget");
        nodes.exclude_subtree(excluded);

        assert!(nodes.contains(before));
        assert!(!nodes.contains(excluded));
        assert!(!nodes.contains(child));
        assert!(!nodes.contains_attribute(excluded, None, "a"));
        assert!(!nodes.contains_namespace(excluded, "gone", "urn:gone"));
        assert!(nodes.contains(after));
    }

    #[test]
    fn excluding_subtree_removes_trailing_text_and_comments_from_canonical_output() {
        // Pretty-printed Signature elements can end in text or comments rather
        // than an element. The contiguous owner-ID range must exclude those tail
        // nodes while preserving text and elements surrounding the subtree.
        let document = Document::parse(
            "<root><before/>keep-before<excluded><child/>drop-text<!--drop-comment--></excluded>keep-after<after/></root>",
        )
        .expect("fixed trailing-node fixture must parse");
        let excluded = document
            .descendants()
            .find(|node| node.has_tag_name("excluded"))
            .expect("fixed fixture contains the excluded subtree");
        let trailing_text = excluded
            .children()
            .find(|node| node.is_text())
            .expect("fixed fixture contains trailing text");
        let trailing_comment = excluded
            .children()
            .find(|node| node.is_comment())
            .expect("fixed fixture contains a trailing comment");
        let mut nodes = NodeSet::entire_document_with_comments(&document)
            .expect("fixed fixture must fit the node-set materialization budget");

        nodes.exclude_subtree(excluded);

        assert!(!nodes.contains(trailing_text));
        assert!(!nodes.contains(trailing_comment));
        let mut output = Vec::new();
        canonicalize_with_visibility(
            &document,
            Some(&nodes),
            &C14nAlgorithm::new(C14nMode::Inclusive1_0, true),
            &mut output,
        )
        .expect("the retained node set must canonicalize");
        assert_eq!(
            output,
            b"<root><before></before>keep-beforekeep-after<after></after></root>"
        );
    }
}
