//! Core types for the XMLDSig transform pipeline.
//!
//! These types flow between URI dereference, transforms, and digest computation.
//!
//! These types are consumed by URI dereference, the transform chain (P1-014,
//! P1-015), and reference processing (P1-018).

use std::collections::HashSet;

use roxmltree::{Document, Node, NodeId};

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

impl<'a> NodeSet<'a> {
    /// Create a node set representing the entire document without comments.
    ///
    /// Per XMLDSig §4.3.3.2: "An empty URI [...] is a reference to the document
    /// [...] and the comment nodes are not included."
    pub fn entire_document_without_comments(doc: &'a Document<'a>) -> Self {
        Self::collect_document(doc, false)
    }

    /// Create a node set representing the entire document with comments.
    ///
    /// Used for `#xpointer(/)` which, unlike empty URI, includes comment nodes.
    pub fn entire_document_with_comments(doc: &'a Document<'a>) -> Self {
        Self::collect_document(doc, true)
    }

    /// Create a node set rooted at `element`, containing that element and all
    /// of its descendant nodes (elements, text, and, for this constructor,
    /// comment nodes).
    ///
    pub fn subtree(element: Node<'a, 'a>) -> Self {
        let mut set = Self {
            doc: element.document(),
            nodes: HashSet::new(),
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
        let mut removed = Self {
            doc: self.doc,
            nodes: HashSet::new(),
            with_comments: true,
        };
        removed.insert_subtree(node);
        self.nodes.retain(|key| !removed.nodes.contains(key));
    }

    /// Whether comments are included in this node set.
    pub fn with_comments(&self) -> bool {
        self.with_comments
    }

    pub(crate) fn empty(doc: &'a Document<'a>) -> Self {
        Self {
            doc,
            nodes: HashSet::new(),
            with_comments: false,
        }
    }

    pub(crate) fn entire_document(doc: &'a Document<'a>) -> Self {
        Self::collect_document(doc, true)
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
            self.nodes.insert(XmlNodeKey::Attribute {
                owner: owner.id(),
                namespace: namespace.map(str::to_owned),
                local_name: local_name.to_owned(),
            });
        }
    }

    pub(crate) fn insert_namespace(&mut self, owner: Node<'_, '_>, prefix: &str, uri: &str) {
        if self.owns(owner) {
            self.nodes.insert(XmlNodeKey::Namespace {
                owner: owner.id(),
                prefix: prefix.to_owned(),
                uri: uri.to_owned(),
            });
        }
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
            self.with_comments = false;
            return;
        }
        self.nodes.retain(|key| other.nodes.contains(key));
        self.with_comments &= other.with_comments;
    }

    pub(crate) fn subtract(&mut self, other: &Self) {
        if std::ptr::eq(self.doc as *const _, other.doc as *const _) {
            self.nodes.retain(|key| !other.nodes.contains(key));
        }
    }

    pub(crate) fn union_with(&mut self, other: &Self) {
        if std::ptr::eq(self.doc as *const _, other.doc as *const _) {
            self.nodes.extend(other.nodes.iter().cloned());
            self.with_comments |= other.with_comments;
        }
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

    fn owns(&self, node: Node<'_, '_>) -> bool {
        std::ptr::eq(node.document() as *const _, self.doc as *const _)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_without_comments_preserves_comment_policy() {
        // Empty-URI dereferencing strips comment nodes and must not retain a
        // stale flag merely because comments were seen while materializing.
        let document = Document::parse("<root><!-- excluded --><child/></root>")
            .expect("fixed comment fixture must parse");
        let nodes = NodeSet::entire_document_without_comments(&document);
        let comment = document
            .descendants()
            .find(|node| node.is_comment())
            .expect("fixed fixture contains one comment");

        assert!(!nodes.contains(comment));
        assert!(!nodes.with_comments());
    }
}
