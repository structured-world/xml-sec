//! The library's documents: parsed by the core under the library policy, and
//! lent to an operation as a core [`XmlDocument`] for its duration.

use xml_sec::XmlDocument;
use xml_sec::XmlDocumentError;
use xml_sec::document::XmlDocumentPolicy;
use xml_sec::document::owned_tree::{OwnedTree, TreeError, TreeNodeKind};

use crate::handles::{self, HandleError};
use crate::nodes::handle_of;

/// Why a document could not be parsed or lent.
#[derive(Debug, thiserror::Error)]
pub enum DocumentError {
    /// The handle names nothing live, or the document is already lent.
    #[error(transparent)]
    Handle(#[from] HandleError),
    /// The library policy could not be compiled.
    #[error("the library policy is unavailable")]
    Policy,
    /// The core refused the document, its encoding included.
    #[error(transparent)]
    Document(#[from] XmlDocumentError),
}

// no-std: a caller-provided error slot.
std::thread_local! {
    /// The last parse failure on this thread, as libxml2 keeps its last
    /// error per thread.
    static LAST_ERROR: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// The code reported for a refused document; the message carries the
/// core's reason.
const PARSE_FAILED: i32 = 1;

/// The last parse failure on this thread: a code and the reason, as
/// libxmlsec1 reports libxml2's last error.
#[must_use]
pub fn last_error() -> Option<(i32, String)> {
    LAST_ERROR.with_borrow(|error| error.clone().map(|message| (PARSE_FAILED, message)))
}

/// Parse `bytes` under the library policy into a new document; its handle
/// names the document node. A failure is also this thread's [`last_error`].
///
/// The bytes are decoded in the encoding their byte-order mark or XML
/// declaration selects, UTF-16 included.
///
/// # Errors
/// The core's refusal (an encoding error among them), or an unavailable
/// policy.
pub fn parse(bytes: &[u8]) -> Result<usize, DocumentError> {
    parse_parts(&[bytes])
}

/// Parse the bytes of `parts` in sequence as [`parse`] parses one buffer.
/// Their combined length meets the document byte limit before they are
/// joined, so parts too large together are refused without a copy.
///
/// # Errors
/// As for [`parse`].
pub fn parse_parts(parts: &[&[u8]]) -> Result<usize, DocumentError> {
    let parsed = parse_tree(parts);
    if let Err(error) = &parsed {
        record_error(error);
    }
    parsed
}

/// Make `error` this thread's [`last_error`], as libxml2 records each
/// parser failure.
pub(crate) fn record_error(error: &impl std::fmt::Display) {
    let message = error.to_string();
    LAST_ERROR.with_borrow_mut(|last| *last = Some(message));
}

fn parse_tree(parts: &[&[u8]]) -> Result<usize, DocumentError> {
    let policy = crate::policy::library().ok_or(DocumentError::Policy)?;
    let tree = OwnedTree::parse_parts_with_policy(parts, &*policy)?;
    Ok(handles::register(tree)?)
}

/// Free the document any handle of it names; a value that names no live
/// document is ignored, as libxml2's `xmlFreeDoc` ignores null.
pub fn free<T>(doc: *mut T) {
    if handles::free_document(handle_of(doc)).is_err() {
        // Nothing live to free.
    }
}

/// The document `node` belongs to as it is now, read under `policy` into a
/// core document that keeps no hold on the tree, with the document's slot.
/// Handles into the tree keep working while the snapshot is used, so a
/// read-only operation may call back into C code that reads the tree, and
/// the snapshot's external nodes are the tree's.
///
/// # Errors
/// A handle that names nothing live or a lent document, or the core's
/// refusal of the tree under `policy`.
pub fn snapshot<T>(
    node: *const T,
    policy: &impl XmlDocumentPolicy,
) -> Result<(XmlDocument, usize), DocumentError> {
    let slot = handles::document(handle_of(node))?;
    let document = handles::read_document(slot, |tree| {
        XmlDocument::snapshot_of_external_tree(tree, policy)
    })??;
    Ok((document, slot))
}

/// The element `node` and its subtree as a document of its own, read under
/// `policy`: the element is copied, declaring the bindings it inherited, so
/// it reads as it does in place while only its subtree is projected.
///
/// # Errors
/// A handle that names no live element or a lent document, or the core's
/// refusal of the copy under `policy`.
pub fn subtree<T>(
    node: *const T,
    policy: &impl XmlDocumentPolicy,
) -> Result<XmlDocument, DocumentError> {
    let (slot, element) = handles::node(handle_of(node))?;
    let staged = handles::read_document(slot, |tree| {
        if tree.kind(element)? != TreeNodeKind::Element {
            return Err(TreeError::NotAnElement);
        }
        let mut staged = OwnedTree::new();
        let copy = staged.copy_from(tree, element)?;
        let root = staged.document_node();
        staged.append_child(root, copy)?;
        Ok(staged)
    })?
    .map_err(HandleError::from)?;
    XmlDocument::from_owned_tree(staged, policy).map_err(|refused| refused.0.into())
}

/// Run `work` over the document `node` belongs to, read under `policy`,
/// with the document's slot; the tree, with what `work` changed, returns to
/// the slot afterwards, and handles into it are refused as busy meanwhile.
///
/// # Errors
/// A handle that names nothing live or a lent document, or the core's
/// refusal of the tree under `policy`; the tree stays the document's.
///
/// # Panics
/// When `work` panics, after the tree is back in its slot; otherwise never:
/// a document built from an owned tree gives it back, and a lent document's
/// slot can be neither freed nor refilled.
pub fn with_document<T, R>(
    node: *const T,
    policy: &impl XmlDocumentPolicy,
    work: impl FnOnce(&mut XmlDocument, usize) -> R,
) -> Result<R, DocumentError> {
    let (slot, tree) = handles::lend(handle_of(node))?;
    let mut document = match XmlDocument::from_owned_tree(tree, policy) {
        Ok(document) => document,
        Err(refused) => {
            let (error, tree) = *refused;
            restore(slot, tree);
            return Err(error.into());
        }
    };
    // The tree goes back to its slot even when `work` unwinds; otherwise the
    // slot would stay lent, and the document unusable and unfreeable.
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(&mut document, slot)));
    // A document built from an owned tree keeps it to the end.
    let tree = document
        .into_owned_tree()
        .expect("a document built from an owned tree returns it");
    restore(slot, tree);
    match result {
        Ok(result) => Ok(result),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Return a lent tree to its slot, which no one else can fill or free while
/// it is lent.
fn restore(slot: usize, tree: OwnedTree) {
    handles::give_back(slot, tree).expect("a lent document's slot waits for its tree");
}

#[cfg(test)]
mod tests;
