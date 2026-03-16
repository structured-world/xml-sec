//! Core types for the XMLDSig transform pipeline.
//!
//! These types flow between URI dereference, transforms, and digest computation.
//!
//! These types are consumed by URI dereference, the transform chain (P1-014,
//! P1-015), and reference processing (P1-018).

use std::collections::HashSet;

use roxmltree::{Document, Node, NodeId};

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
/// Represents "which nodes are included" for canonicalization and transforms.
/// Two modes:
/// - **Whole document**: `included` is `None`, meaning all nodes are in the set
///   (minus any in `excluded`).
/// - **Subset**: `included` is `Some(ids)`, meaning only those node IDs are in
///   the set (minus any in `excluded`).
pub struct NodeSet<'a> {
    /// Reference to the parsed document.
    doc: &'a Document<'a>,
    /// If `None`, all nodes are included. If `Some`, only these nodes.
    included: Option<HashSet<NodeId>>,
    /// Nodes explicitly excluded (e.g., `<Signature>` subtree for enveloped transform).
    excluded: HashSet<NodeId>,
    /// Whether comment nodes are included. For empty URI dereference (whole
    /// document), comments are excluded per XMLDSig spec.
    with_comments: bool,
}

impl<'a> NodeSet<'a> {
    /// Create a node set representing the entire document without comments.
    ///
    /// Per XMLDSig §4.3.3.2: "An empty URI [...] is a reference to the document
    /// [...] and the comment nodes are not included."
    pub fn entire_document_without_comments(doc: &'a Document<'a>) -> Self {
        Self {
            doc,
            included: None,
            excluded: HashSet::new(),
            with_comments: false,
        }
    }

    /// Create a node set representing the entire document with comments.
    ///
    /// Used for `#xpointer(/)` which, unlike empty URI, includes comment nodes.
    pub fn entire_document_with_comments(doc: &'a Document<'a>) -> Self {
        Self {
            doc,
            included: None,
            excluded: HashSet::new(),
            with_comments: true,
        }
    }

    /// Create a node set representing an element and all its descendants
    /// (including attributes, namespaces, and text nodes), with comments.
    pub fn subtree(doc: &'a Document<'a>, element: Node<'a, 'a>) -> Self {
        let mut ids = HashSet::new();
        collect_subtree_ids(element, &mut ids);
        Self {
            doc,
            included: Some(ids),
            excluded: HashSet::new(),
            with_comments: true,
        }
    }

    /// Reference to the underlying document.
    pub fn document(&self) -> &'a Document<'a> {
        self.doc
    }

    /// Check whether a node is in this set.
    pub fn contains(&self, node: Node<'_, '_>) -> bool {
        let id = node.id();

        // Check exclusion first
        if self.excluded.contains(&id) {
            return false;
        }

        // Filter comments if not included
        if !self.with_comments && node.is_comment() {
            return false;
        }

        // Check inclusion
        match &self.included {
            None => true,
            Some(ids) => ids.contains(&id),
        }
    }

    /// Exclude a node and all its descendants from this set.
    pub fn exclude_subtree(&mut self, node: Node<'_, '_>) {
        collect_subtree_ids(node, &mut self.excluded);
    }

    /// Whether comments are included in this node set.
    pub fn with_comments(&self) -> bool {
        self.with_comments
    }
}

/// Collect a node and all its descendants into a set of `NodeId`s.
///
/// Uses an explicit stack instead of recursion to avoid stack overflow
/// on deeply nested XML (attacker-controlled input in SAML contexts).
fn collect_subtree_ids(node: Node<'_, '_>, ids: &mut HashSet<NodeId>) {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        ids.insert(current.id());
        for child in current.children() {
            stack.push(child);
        }
    }
    // roxmltree models attributes as children only for elements,
    // but they're accessible via node.attributes(). For node-set
    // membership, we need to track the element ID — the C14N
    // serializer checks element membership and then serializes
    // all its attributes. Individual attribute NodeIds are not
    // needed because roxmltree doesn't expose them as separate nodes
    // in the tree traversal.
}

/// Errors during transform processing.
#[derive(Debug, thiserror::Error)]
pub enum TransformError {
    /// Data type mismatch between transforms.
    #[error("type mismatch: expected {expected}, got {got}")]
    TypeMismatch {
        /// Expected data type.
        expected: &'static str,
        /// Actual data type.
        got: &'static str,
    },

    /// URI dereference failed.
    #[error("URI dereference failed: {0}")]
    UriDeref(String),

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
    C14n(String),
}
