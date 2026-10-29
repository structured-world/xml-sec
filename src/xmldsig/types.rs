//! Core types for the `XMLDSig` transform pipeline.
//!
//! These types flow between URI dereference, transforms, and digest computation.
//!
//! These types are consumed by URI dereference, the transform chain (P1-014,
//! P1-015), and reference processing (P1-018).

use alloc::{string::String, vec::Vec};
use core::cell::Cell;
use core::ops::RangeInclusive;

use crate::xml::dom::{Document, Node};

const MAX_NODE_SET_ENTRIES: usize = crate::hard_limits::NODE_SET_ENTRY_CEILING;
const MAX_NODE_SET_OWNED_STRING_BYTES: usize =
    crate::hard_limits::NODE_SET_OWNED_STRING_BYTE_CEILING;
const MAX_NODE_SET_CUMULATIVE_OWNED_STRING_BYTES: usize =
    crate::hard_limits::NODE_SET_CUMULATIVE_OWNED_STRING_BYTE_CEILING;

use crate::c14n::NodeVisibility;

pub(crate) mod projection;

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
    /// Original caller-supplied bytes, borrowed for a scoped transform chain.
    BorrowedBinary(&'a [u8]),
    /// Caller-owned detached bytes and their resolved document-entity URI.
    /// XSLT uses the borrowed URI as the input document-entity base URI.
    Resource {
        /// Original bytes supplied by the caller's external-resource map.
        bytes: &'a [u8],
        /// Resolved RFC 3986 identity of that map entry, not a filesystem path.
        uri: &'a str,
    },
}

impl core::fmt::Debug for TransformData<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NodeSet(_) => f.debug_tuple("NodeSet").field(&"...").finish(),
            Self::Binary(b) => f.debug_tuple("Binary").field(&b.len()).finish(),
            Self::BorrowedBinary(b) => f.debug_tuple("BorrowedBinary").field(&b.len()).finish(),
            Self::Resource { bytes, uri } => f
                .debug_struct("Resource")
                .field("bytes", &bytes.len())
                .field("uri", uri)
                .finish(),
        }
    }
}

impl<'a> TransformData<'a> {
    /// Convert to `NodeSet`, returning an error if this is `Binary` data.
    ///
    /// # Errors
    /// Returns `TypeMismatch` for owned, borrowed or resource binary data.
    pub fn into_node_set(self) -> Result<NodeSet<'a>, TransformError> {
        match self {
            Self::NodeSet(ns) => Ok(ns),
            Self::Binary(_) | Self::BorrowedBinary(_) | Self::Resource { .. } => {
                Err(TransformError::TypeMismatch {
                    expected: "NodeSet",
                    got: "Binary",
                })
            }
        }
    }

    /// Convert to binary bytes, returning an error if this is a `NodeSet`.
    ///
    /// # Errors
    /// Returns `TypeMismatch` if the value is a node set.
    pub fn into_binary(self) -> Result<Vec<u8>, TransformError> {
        match self {
            Self::Binary(b) => Ok(b),
            Self::BorrowedBinary(b) => Ok(b.to_vec()),
            Self::Resource { bytes, .. } => Ok(bytes.to_vec()),
            Self::NodeSet(_) => Err(TransformError::TypeMismatch {
                expected: "Binary",
                got: "NodeSet",
            }),
        }
    }
}

/// A set of nodes from a roxmltree document.
///
/// Represents the exact `XPath` nodes included for canonicalization and transforms.
///
/// Attributes and namespace bindings are first-class `XPath` nodes even though
/// roxmltree exposes them through their owner element. Materializing them here
/// lets `XPath` filters independently include or remove those nodes as required
/// by canonical XML document-subset processing.
pub struct NodeSet<'a> {
    pub(crate) projection: projection::Projection<'a, projection::NativeKeys>,
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
    pub(crate) fn reserve_workspace(&self, bytes: usize) -> Result<(), TransformError> {
        if bytes > self.max_owned_string_bytes {
            return Err(transform_resource_limit(
                crate::policy::resource_name::NODE_SET_OWNED_STRING_BYTES,
                self.max_owned_string_bytes,
                bytes,
            ));
        }
        self.charge(bytes)
    }

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

impl<'a> NodeSet<'a> {
    pub(crate) fn projected(
        root: Node<'a, 'a>,
        comments: bool,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<Self, TransformError> {
        let default;
        let budget = if let Some(budget) = budget {
            budget
        } else {
            default = NodeSetMaterializationBudget::default();
            &default
        };
        Ok(Self {
            projection: projection::Projection::subtree(
                root,
                comments,
                budget,
                projection::NativeKeys,
            )?,
        })
    }

    /// Project the complete document with comment nodes omitted.
    ///
    /// `XMLDSig` 1.1 section 4.4.3.3 excludes comments for an empty Reference URI.
    ///
    /// # Errors
    /// Returns a policy error when the projection allowance is exceeded.
    pub fn entire_document_without_comments(doc: &'a Document<'a>) -> Result<Self, TransformError> {
        Self::projected(doc.root(), false, None)
    }
    pub(crate) fn entire_document_without_comments_with_budget(
        doc: &'a Document<'a>,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<Self, TransformError> {
        Self::projected(doc.root(), false, Some(budget))
    }
    pub(crate) fn entire_document_without_comments_from_view(
        view: crate::DocumentView<'a>,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<Self, TransformError> {
        Self::projected(view.document().root(), false, budget)
    }

    /// Project the complete document including comments.
    ///
    /// # Errors
    /// Returns a policy error when the projection allowance is exceeded.
    pub fn entire_document_with_comments(doc: &'a Document<'a>) -> Result<Self, TransformError> {
        Self::projected(doc.root(), true, None)
    }

    /// Project a subtree including its attribute, namespace and comment nodes.
    ///
    /// # Errors
    /// Returns a policy error when the projection allowance is exceeded.
    pub fn subtree(element: Node<'a, 'a>) -> Result<Self, TransformError> {
        Self::projected(element, true, None)
    }
    #[cfg(test)]
    pub(crate) fn subtree_without_comments_with_budget(
        element: Node<'a, 'a>,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<Self, TransformError> {
        Self::projected(element, false, budget)
    }
    #[cfg(test)]
    pub(crate) fn subtree_with_budget(
        element: Node<'a, 'a>,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<Self, TransformError> {
        Self::projected(element, true, Some(budget))
    }

    /// Return the original source document.
    #[must_use]
    pub fn document(&self) -> &'a Document<'a> {
        self.projection.document()
    }
    /// Test tree membership; a node from another document is never included.
    ///
    /// # Panics
    /// Panics only if the internal native projection violates its infallible lookup invariant.
    #[must_use]
    pub fn contains(&self, node: Node<'_, '_>) -> bool {
        self.projection
            .contains_tree(node)
            .expect("native projection lookup is infallible")
    }
    /// Exclude a subtree and every projected axis owned by its nodes.
    ///
    /// # Panics
    /// Panics only if the internal native projection violates its infallible retention invariant.
    pub fn exclude_subtree(&mut self, node: Node<'_, '_>) {
        self.projection
            .exclude_subtree(node)
            .expect("native projection retention is infallible");
    }
    /// Whether this projection permits comment nodes.
    #[must_use]
    pub fn with_comments(&self) -> bool {
        self.projection.with_comments()
    }

    #[cfg(test)]
    pub(crate) fn empty(doc: &'a Document<'a>) -> Self {
        Self {
            projection: projection::Projection::empty(doc, projection::NativeKeys),
        }
    }
    #[cfg(test)]
    pub(crate) fn try_entire_document(doc: &'a Document<'a>) -> Result<Self, TransformError> {
        Self::entire_document_with_comments(doc)
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.projection.len()
    }
    #[cfg(test)]
    pub(crate) fn insert_attribute_with_budget(
        &mut self,
        owner: Node<'_, '_>,
        namespace: Option<&str>,
        local: &str,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        self.projection
            .insert_attribute(owner, namespace, local, Some(budget))
    }
    #[cfg(test)]
    pub(crate) fn insert_namespace_with_budget(
        &mut self,
        owner: Node<'_, '_>,
        prefix: &str,
        uri: &str,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        self.projection
            .insert_namespace(owner, prefix, uri, Some(budget))
    }
    pub(crate) fn ensure_subtree_materialization_fits_with_budget(
        root: Node<'_, '_>,
        comments: bool,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<usize, TransformError> {
        Ok(projection::measure(
            root,
            comments,
            budget.max_entries,
            budget.max_owned_string_bytes,
            &projection::NativeKeys,
        )?
        .entries)
    }
}

pub(super) fn charge_resource_bytes(
    current: usize,
    additional: usize,
    max_bytes: usize,
    resource: &'static str,
) -> Result<usize, TransformError> {
    let total = current
        .checked_add(additional)
        .ok_or_else(|| transform_resource_limit(resource, max_bytes, usize::MAX))?;
    if total > max_bytes {
        return Err(transform_resource_limit(resource, max_bytes, total));
    }
    Ok(total)
}

pub(crate) fn subtree_node_id_range<D: crate::xml::dom::storage::Storage>(
    node: Node<'_, '_, D>,
) -> RangeInclusive<u32> {
    let last_id = node.descendants().next_back().map_or(node.id(), Node::id);
    node.id().get()..=last_id.get()
}

impl NodeSet<'_> {
    pub(crate) fn contains_attribute(
        &self,
        owner: Node<'_, '_>,
        namespace: Option<&str>,
        local_name: &str,
    ) -> bool {
        self.projection
            .contains_attribute(owner, namespace, local_name)
            .expect("native projection lookup is infallible")
    }

    pub(crate) fn contains_namespace(&self, owner: Node<'_, '_>, prefix: &str, uri: &str) -> bool {
        self.projection
            .contains_namespace(owner, prefix, uri)
            .expect("native projection lookup is infallible")
    }
}

impl NodeVisibility for NodeSet<'_> {
    fn contains_node(&self, node: Node<'_, '_>) -> Result<bool, crate::c14n::C14nError> {
        Ok(self.contains(node))
    }
    fn contains_attribute(
        &self,
        owner: Node<'_, '_>,
        namespace: Option<&str>,
        local_name: &str,
    ) -> Result<bool, crate::c14n::C14nError> {
        Ok(self.contains_attribute(owner, namespace, local_name))
    }
    fn contains_namespace(
        &self,
        owner: Node<'_, '_>,
        prefix: &str,
        uri: &str,
    ) -> Result<bool, crate::c14n::C14nError> {
        Ok(self.contains_namespace(owner, prefix, uri))
    }
    fn contains_attribute_at(
        &self,
        owner: Node<'_, '_>,
        ordinal: usize,
        _: crate::xml::dom::Attribute<'_>,
    ) -> Result<bool, crate::c14n::C14nError> {
        self.projection.contains_attribute_at(owner, ordinal)
    }
    fn contains_namespace_at(
        &self,
        owner: Node<'_, '_>,
        ordinal: usize,
        _: crate::xml::dom::Namespace<'_>,
    ) -> Result<bool, crate::c14n::C14nError> {
        self.projection.contains_namespace_at(owner, ordinal)
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

    /// Missing ID whose diagnostic retains its current-query capacity charge.
    #[error("element not found by ID: {0}")]
    AccountedElementNotFound(structured_asn1::memory::OwnedText),

    /// Unsupported URI scheme or format.
    #[error("unsupported URI: {0}")]
    UnsupportedUri(String),

    /// Rejected URI whose diagnostic retains its current-query capacity charge.
    #[error("unsupported URI: {0}")]
    AccountedUnsupportedUri(structured_asn1::memory::OwnedText),

    /// The caller supplied no bytes for this external URI.
    #[error("external resource not supplied: {0}")]
    ExternalResourceUnavailable(String),

    /// Malformed same-document syntax, requiring no diagnostic allocation.
    #[error("unsupported URI: invalid same-document fragment")]
    InvalidFragment,

    /// Unsupported transform algorithm.
    #[error("unsupported transform: {0}")]
    UnsupportedTransform(String),

    /// Rejected transform syntax retaining current-query diagnostic capacity.
    #[error("unsupported transform: {0}")]
    AccountedUnsupportedTransform(structured_asn1::memory::OwnedText),

    /// Canonicalization error during transform.
    #[error("C14N error: {0}")]
    C14n(#[from] crate::c14n::C14nError),

    /// Base64 decoding failed during the standard `XMLDSig` Base64 transform.
    #[error("base64 transform decode error: {0}")]
    // base64 implements `Error` only with its `std` feature.
    Base64(#[cfg_attr(feature = "std", source)] base64::DecodeSliceError),

    /// `XPath` parsing or evaluation failed.
    #[error("XPath transform error: {0}")]
    XPath(String),

    /// `XPath` diagnostic whose capacity remains charged to its current query.
    #[error("XPath transform error: {0}")]
    AccountedXPath(structured_asn1::memory::OwnedText),

    /// OPC relationship parameters, MCE, or part structure are invalid.
    #[error("OPC relationship transform error: {0}")]
    Relationship(&'static str),

    /// The XSLT stylesheet, its input document, or its execution failed.
    #[cfg(feature = "xslt")]
    #[error("XSLT transform error: {0}")]
    Xslt(String),

    /// XSLT diagnostic whose capacity remains charged to its current query.
    #[cfg(feature = "xslt")]
    #[error("XSLT transform error: {0}")]
    AccountedXslt(structured_asn1::memory::OwnedText),

    /// XML octets could not be parsed while adapting binary transform output
    /// to the node-set required by a subsequent transform.
    #[error("XML transform input parse error: {0}")]
    XmlParse(#[source] crate::document::XmlDocumentError),

    /// Encoding rejection whose diagnostic label retains its admitted storage.
    #[error("XML transform encoding error: {0}")]
    AccountedXmlEncoding(
        #[source] crate::encoding::XmlEncodingError<structured_asn1::memory::OwnedText>,
    ),

    /// The Signature node passed to the enveloped transform belongs to a
    /// different `Document` than the input `NodeSet`.
    #[error("enveloped-signature transform: invalid Signature node for this document")]
    CrossDocumentSignatureNode,

    /// A retained document view and a projected node came from different documents.
    #[error("node-set projection: input node belongs to a different document")]
    CrossDocumentNodeSetInput,
}

impl From<structured_asn1::memory::MemoryError> for TransformError {
    fn from(error: structured_asn1::memory::MemoryError) -> Self {
        Self::C14n(crate::c14n::C14nError::SharedExecution(error))
    }
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
        let document = Document::parse("<root a='1' bbb='2'/>").expect("fixed XML must parse");
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
        let document =
            Document::parse("<root xmlns:p='u' a='1' b='2'/>").expect("fixed XML must parse");
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
    fn denied_attribute_projection_does_not_insert_key() {
        // The compact key cannot own copied names. A zero projection allowance
        // must still reject before growing the table or selecting the axis.
        let document = Document::parse("<root a='1'/>").expect("fixed XML must parse");
        let root = document.root_element();
        let mut nodes = NodeSet::empty(&document);
        let budget = NodeSetMaterializationBudget::with_limits(16, 0, 0);
        let error = nodes
            .insert_attribute_with_budget(root, None, "a", &budget)
            .expect_err("the borrowed attribute name exceeds the zero-byte budget");

        assert_eq!(nodes.len(), 0);
        assert!(!nodes.contains_attribute(root, None, "a"));
        assert!(matches!(
            error,
            TransformError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "node-set owned string bytes",
                maximum: 0,
                actual: 1,
            })
        ));
    }

    #[test]
    fn denied_namespace_projection_does_not_insert_key() {
        // Prefix/URI policy checks precede table growth; source names remain
        // borrowed and a denied namespace must not become visible.
        let document = Document::parse("<root xmlns:p='u'/>").expect("fixed XML must parse");
        let root = document.root_element();
        let mut nodes = NodeSet::empty(&document);
        let budget = NodeSetMaterializationBudget::with_limits(16, 16, 0);
        let error = nodes
            .insert_namespace_with_budget(root, "p", "u", &budget)
            .expect_err("borrowed namespace strings exceed the zero-byte budget");

        assert_eq!(nodes.len(), 0);
        assert!(!nodes.contains_namespace(root, "p", "u"));
        assert!(matches!(
            error,
            TransformError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "cumulative node-set owned string bytes",
                maximum: 0,
                actual: 2,
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
            .find(Node::is_comment)
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

        assert_eq!(nodes.len(), 3);
        assert!(
            document
                .descendants()
                .filter(Node::is_comment)
                .all(|comment| !nodes.contains(comment))
        );
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

        assert_eq!(nodes.len(), 2);
        assert!(!nodes.with_comments());
    }

    #[test]
    fn excluding_disjoint_oversized_subtree_only_scans_input_keys() {
        // The excluded Signature subtree is intentionally larger than the
        // constructor budget; a small referenced subtree must remain unchanged
        // without attempting to materialize the irrelevant Signature content.
        let xml = format!(
            "<root><target Id=\"selected\"><child/></target><Signature>{}</Signature></root>",
            "<Object/>".repeat(129)
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
        let budget = NodeSetMaterializationBudget::with_limits(3, 8, 8);
        let mut nodes = NodeSet::subtree_with_budget(target, &budget)
            .expect("small selected subtree must fit the materialization budget");
        let entries_before = nodes.len();

        nodes.exclude_subtree(signature);

        assert_eq!(nodes.len(), entries_before);
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
            .find(Node::is_text)
            .expect("fixed fixture contains trailing text");
        let trailing_comment = excluded
            .children()
            .find(Node::is_comment)
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
