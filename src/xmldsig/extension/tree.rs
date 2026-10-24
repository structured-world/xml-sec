//! Accounted original-tree navigation and binary values for extension formats.
//!
//! Every read resolves its identity against the original view and charges the
//! caller's current execution before data-dependent work. Nothing here
//! authenticates the node it reads.

use crate::document::{DocumentView, NodeIdentity, XmlDocumentError};
use structured_asn1::memory::{MemoryError, Work};

/// Original tree read failure, independent of the content it would have read.
#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    /// The identity is absent, foreign or stale in this original document view.
    #[error(transparent)]
    Document(#[from] XmlDocumentError),
    /// A sibling query named a node outside the selected parent's children.
    #[error("XML node is not a direct child of the selected parent")]
    NotChild,
    /// Binary content can only be read from an element.
    #[error("XML binary value owner is not an element")]
    NotElement,
    /// The element content is not XML Schema base64Binary.
    #[error("malformed XML base64 content: {0}")]
    Base64(&'static str),
    /// Current shared execution refused the work before it was performed.
    #[error("XML tree resource failure: {0}")]
    Resource(MemoryError),
}

/// One original node, borrowed only for the visitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeView<'a> {
    /// An element's expanded name; prefixes do not participate.
    Element {
        /// Namespace name, or None for an unqualified element.
        namespace: Option<&'a str>,
        /// Local name after namespace processing.
        local_name: &'a str,
    },
    /// Expanded character data, including CDATA; not original source bytes.
    Text(&'a str),
    /// A comment, processing instruction or the document root.
    Other,
}

fn charge<W: Work>(work: &W, units: usize) -> Result<(), TreeError> {
    let units = u64::try_from(units).map_err(|_| TreeError::Resource(MemoryError::WorkExceeded))?;
    work.charge_work(units).map_err(TreeError::Resource)
}

/// Inspect one original node. The visitor cannot retain the borrowed names.
///
/// # Errors
///
/// Returns [`TreeError::Document`] for a foreign or stale identity and
/// [`TreeError::Resource`] when current work is exhausted.
pub fn inspect_node<W: Work, R>(
    view: DocumentView<'_>,
    node: NodeIdentity,
    work: &W,
    visitor: impl for<'a> FnOnce(NodeView<'a>) -> R,
) -> Result<R, TreeError> {
    charge(work, 1)?;
    let node = view.resolve_node(node)?;
    Ok(visitor(if node.is_element() {
        let name = node.tag_name();
        NodeView::Element {
            namespace: name.namespace(),
            local_name: name.name(),
        }
    } else if node.is_text() {
        NodeView::Text(node.text().unwrap_or_default())
    } else {
        NodeView::Other
    }))
}

/// Return the first direct child, including text and non-element children.
///
/// # Errors
///
/// Returns [`TreeError::Document`] for a foreign or stale identity and
/// [`TreeError::Resource`] when current work is exhausted.
pub fn first_child<W: Work>(
    view: DocumentView<'_>,
    parent: NodeIdentity,
    work: &W,
) -> Result<Option<NodeIdentity>, TreeError> {
    charge(work, 1)?;
    let parent = view.resolve_node(parent)?;
    Ok(parent.first_child().map(|child| view.node_identity(child)))
}

/// Return the next direct sibling within `parent`, in original document order.
/// A node outside that parent's children is refused rather than followed.
///
/// # Errors
///
/// Returns [`TreeError::NotChild`] for a node outside `parent`,
/// [`TreeError::Document`] for a foreign or stale identity and
/// [`TreeError::Resource`] when current work is exhausted.
pub fn next_sibling<W: Work>(
    view: DocumentView<'_>,
    parent: NodeIdentity,
    node: NodeIdentity,
    work: &W,
) -> Result<Option<NodeIdentity>, TreeError> {
    charge(work, 1)?;
    let parent = view.resolve_node(parent)?;
    let node = view.resolve_node(node)?;
    if node.parent() != Some(parent) {
        return Err(TreeError::NotChild);
    }
    Ok(node
        .following_sibling()
        .map(|sibling| view.node_identity(sibling)))
}

/// Whether `node` is `ancestor` itself or one of its descendants.
///
/// # Errors
///
/// Returns [`TreeError::Document`] for a foreign or stale identity and
/// [`TreeError::Resource`] when current work is exhausted.
pub fn subtree_contains<W: Work>(
    view: DocumentView<'_>,
    ancestor: NodeIdentity,
    node: NodeIdentity,
    work: &W,
) -> Result<bool, TreeError> {
    charge(work, 1)?;
    let ancestor = view.resolve_node(ancestor)?;
    let node = view.resolve_node(node)?;
    Ok(crate::xmldsig::types::subtree_node_id_range(ancestor).contains(&node.id().get()))
}

/// Decode an element's base64Binary simple content into storage admitted by
/// `work`, then lend the octets to the visitor. Comments and processing
/// instructions contribute no text; element children are malformed content.
/// XML Schema 1.0 Part 2 §3.2.16 fixes the alphabet, padding and the four
/// XML whitespace characters (`whiteSpace` collapse).
/// <https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary>
///
/// # Errors
///
/// Returns [`TreeError::NotElement`] for a non-element owner,
/// [`TreeError::Base64`] for malformed content, [`TreeError::Document`] for a
/// foreign or stale identity and [`TreeError::Resource`] when current work or
/// storage is exhausted.
pub fn with_base64<W: Work, R>(
    view: DocumentView<'_>,
    owner: NodeIdentity,
    work: &W,
    visitor: impl for<'a> FnOnce(&'a [u8]) -> R,
) -> Result<R, TreeError> {
    // Zero-fill source for initialized decode storage, in bounded chunks.
    const ZEROS: [u8; 512] = [0; 512];
    charge(work, 1)?;
    let node = view.resolve_node(owner)?;
    if !node.is_element() {
        return Err(TreeError::NotElement);
    }
    // Admit the child visit and both linear passes (lexical check, decode)
    // before scanning any text.
    let mut text = 0usize;
    for child in node.children() {
        charge(work, 1)?;
        if child.is_text() {
            text = text
                .checked_add(child.text().map_or(0, str::len))
                .ok_or(TreeError::Resource(MemoryError::WorkExceeded))?;
        }
    }
    charge(
        work,
        text.checked_mul(2)
            .ok_or(TreeError::Resource(MemoryError::WorkExceeded))?,
    )?;
    let payload =
        crate::xmldsig::whitespace::XmlBase64Payload::new(node).map_err(TreeError::Base64)?;
    let mut decoded = work.vector();
    decoded
        .try_reserve_exact(payload.decoded_len)
        .map_err(TreeError::Resource)?;
    // The decoder writes into initialized storage; the zero fill is its own
    // admitted pass within the exact capacity reserved above.
    let mut remaining = payload.decoded_len;
    while remaining != 0 {
        let chunk = remaining.min(ZEROS.len());
        decoded
            .try_extend_from_slice(&ZEROS[..chunk])
            .map_err(TreeError::Resource)?;
        remaining -= chunk;
    }
    payload
        .decode_into(&mut decoded)
        .map_err(TreeError::Base64)?;
    Ok(visitor(&decoded))
}
