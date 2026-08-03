//! Core types for the XMLDSig transform pipeline.
//!
//! These types flow between URI dereference, transforms, and digest computation.
//!
//! These types are consumed by URI dereference, the transform chain (P1-014,
//! P1-015), and reference processing (P1-018).

use std::collections::HashSet;
use std::ops::RangeInclusive;

use roxmltree::{Document, Node, NodeId};

const MAX_NODE_SET_ENTRIES: usize = 65_536;
const MAX_NODE_SET_OWNED_STRING_BYTES: usize = 8 * 1024 * 1024;

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

impl XmlNodeKey {
    fn owner_id(&self) -> NodeId {
        match self {
            Self::Tree(id) => *id,
            Self::Attribute { owner, .. } | Self::Namespace { owner, .. } => *owner,
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
    /// Returns [`TransformError::NodeSetTooLarge`] or
    /// [`TransformError::NodeSetStringsTooLarge`] when projecting the document's
    /// tree, attribute, namespace, or owned string data would exceed its budget.
    pub fn entire_document_without_comments(doc: &'a Document<'a>) -> Result<Self, TransformError> {
        Self::ensure_subtree_materialization_fits(doc.root())?;
        Ok(Self::collect_document(doc, false))
    }

    /// Create a node set representing the entire document with comments.
    ///
    /// Used for `#xpointer(/)` which, unlike empty URI, includes comment nodes.
    ///
    /// # Errors
    ///
    /// Returns [`TransformError::NodeSetTooLarge`] or
    /// [`TransformError::NodeSetStringsTooLarge`] when projecting the document's
    /// tree, attribute, namespace, or owned string data would exceed its budget.
    pub fn entire_document_with_comments(doc: &'a Document<'a>) -> Result<Self, TransformError> {
        Self::ensure_subtree_materialization_fits(doc.root())?;
        Ok(Self::collect_document(doc, true))
    }

    /// Create a node set rooted at `element`, containing that element and all
    /// of its descendant nodes (elements, text, and, for this constructor,
    /// comment nodes).
    ///
    /// # Errors
    ///
    /// Returns [`TransformError::NodeSetTooLarge`] or
    /// [`TransformError::NodeSetStringsTooLarge`] when projecting the subtree's
    /// tree, attribute, namespace, or owned string data would exceed its budget.
    pub fn subtree(element: Node<'a, 'a>) -> Result<Self, TransformError> {
        Self::ensure_subtree_materialization_fits(element)?;
        let mut set = Self {
            doc: element.document(),
            nodes: HashSet::new(),
            with_comments: true,
        };
        set.insert_subtree(element);
        Ok(set)
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

    pub(crate) fn try_entire_document(doc: &'a Document<'a>) -> Result<Self, TransformError> {
        Self::entire_document_with_comments(doc)
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

    pub(crate) fn ensure_subtree_materialization_fits(
        root: Node<'_, '_>,
    ) -> Result<usize, TransformError> {
        let mut entries = 0_usize;
        let mut owned_string_bytes = 0_usize;
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            let projected = if node.is_element() {
                for attribute in node.attributes() {
                    owned_string_bytes = charge_node_set_string_bytes(
                        owned_string_bytes,
                        attribute.namespace().map_or(0, str::len),
                    )?;
                    owned_string_bytes =
                        charge_node_set_string_bytes(owned_string_bytes, attribute.name().len())?;
                }
                for namespace in node.namespaces() {
                    owned_string_bytes = charge_node_set_string_bytes(
                        owned_string_bytes,
                        namespace.name().map_or(0, str::len),
                    )?;
                    owned_string_bytes =
                        charge_node_set_string_bytes(owned_string_bytes, namespace.uri().len())?;
                }
                1_usize
                    .checked_add(node.attributes().len())
                    .and_then(|count| count.checked_add(node.namespaces().len()))
            } else {
                Some(1)
            }
            .ok_or(TransformError::NodeSetTooLarge {
                max: MAX_NODE_SET_ENTRIES,
            })?;
            entries = entries
                .checked_add(projected)
                .ok_or(TransformError::NodeSetTooLarge {
                    max: MAX_NODE_SET_ENTRIES,
                })?;
            if entries > MAX_NODE_SET_ENTRIES {
                return Err(TransformError::NodeSetTooLarge {
                    max: MAX_NODE_SET_ENTRIES,
                });
            }
            stack.extend(node.children());
        }
        Ok(entries)
    }

    fn owns(&self, node: Node<'_, '_>) -> bool {
        std::ptr::eq(node.document() as *const _, self.doc as *const _)
    }
}

fn charge_node_set_string_bytes(
    current: usize,
    additional: usize,
) -> Result<usize, TransformError> {
    let total = current
        .checked_add(additional)
        .ok_or(TransformError::NodeSetStringsTooLarge {
            max_bytes: MAX_NODE_SET_OWNED_STRING_BYTES,
        })?;
    if total > MAX_NODE_SET_OWNED_STRING_BYTES {
        return Err(TransformError::NodeSetStringsTooLarge {
            max_bytes: MAX_NODE_SET_OWNED_STRING_BYTES,
        });
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

    /// A reference declared more transforms than the implementation permits.
    #[error("transform chain exceeds maximum length of {max}")]
    TooManyTransforms {
        /// Maximum accepted transforms in one reference.
        max: usize,
    },

    /// Exact XPath node projection would exceed the materialization budget.
    #[error("node-set materialization exceeds maximum of {max} entries")]
    NodeSetTooLarge {
        /// Maximum tree, attribute, and namespace entries accepted.
        max: usize,
    },

    /// Owned names and namespace bindings would exceed the byte budget.
    #[error("node-set materialization exceeds maximum of {max_bytes} owned string bytes")]
    NodeSetStringsTooLarge {
        /// Maximum string bytes cloned into one exact XPath node projection.
        max_bytes: usize,
    },

    /// Node-set filtering would exceed the cumulative transform work budget.
    #[error("node-set filtering exceeds signature-wide maximum of {max_entries} entry visits")]
    NodeSetFilterWorkTooLarge {
        /// Maximum node-set entries visited across one signature execution.
        max_entries: usize,
    },

    /// Temporary XPath documents would cumulatively copy too many strings.
    #[error(
        "XPath mirrors exceed signature-wide maximum of {max_bytes} cumulative copied string bytes"
    )]
    XPathMirrorTooLarge {
        /// Maximum string bytes copied across one signature execution.
        max_bytes: usize,
    },

    /// Non-interruptible XPath evaluations would scan too much source text.
    #[error(
        "XPath transform exceeds signature-wide maximum of {max_bytes} string-processing work bytes"
    )]
    XPathStringWorkTooLarge {
        /// Maximum conservatively charged source-string bytes per signature.
        max_bytes: usize,
    },

    /// Canonicalization error during transform.
    #[error("C14N error: {0}")]
    C14n(#[from] crate::c14n::C14nError),

    /// Explicit canonicalization produced too much output in one execution.
    #[error("cumulative canonical output exceeds signature-wide maximum of {max_bytes} bytes")]
    C14nOutputTooLarge {
        /// Maximum canonical bytes produced across one signature execution.
        max_bytes: usize,
    },

    /// Base64 decoding failed during the standard XMLDSig Base64 transform.
    #[error("base64 transform decode error: {0}")]
    Base64(String),

    /// Raw Base64 transform input exceeded its cumulative execution budget.
    #[error("cumulative base64 transform input exceeds maximum of {max_bytes} bytes")]
    Base64InputTooLarge {
        /// Maximum raw input bytes accepted across one signature execution.
        max_bytes: usize,
    },

    /// Decoded Base64 transform output exceeded its allocation budget.
    #[error("base64 transform output exceeds maximum of {max_bytes} bytes")]
    Base64OutputTooLarge {
        /// Maximum decoded output bytes produced by one Base64 transform.
        max_bytes: usize,
    },

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
    use crate::c14n::{C14nAlgorithm, C14nMode, canonicalize_with_visibility};

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
            TransformError::NodeSetStringsTooLarge { .. }
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
