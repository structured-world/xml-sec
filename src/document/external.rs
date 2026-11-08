//! Documents backed by an external tree instead of a serialization.
//!
//! An application that already holds its document as a tree (for example a
//! libxml2 `xmlDoc`) implements [`ExternalTree`] over it. The resulting
//! [`XmlDocument`](super::XmlDocument) is read by every operation exactly like
//! a parsed one: its semantic view is built by walking the tree into a
//! [`TreeSink`], under the operation's XML input policy and resource limits.

pub use crate::xml::dom::external::{ExternalNode, TreeSink};

use crate::ParseError;

/// A document tree owned outside this crate.
///
/// Implementations report the tree as it is when [`Self::project`] runs; the
/// tree must not change while a document built from it is in use, except
/// through that document.
pub trait ExternalTree: Send + Sync {
    /// The node that stands for the whole document.
    fn document(&self) -> ExternalNode;

    /// Report the whole tree to `sink` in document order: a document type
    /// declaration first if there is one, then the children of the document
    /// node with their descendants.
    ///
    /// # Errors
    /// Whatever `sink` refuses, returned unchanged, or a tree the
    /// implementation cannot read.
    fn project(&self, sink: &mut TreeSink<'_>) -> Result<(), ParseError>;
}

#[cfg(all(test, feature = "xmldsig"))]
mod tests;
