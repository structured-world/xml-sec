//! A document of the handle table as the core's external tree, for the clean
//! C API's document handle: every operation reads and changes the tree in
//! its slot as it is at that moment, so the caller may change the tree
//! through the tree functions between operations, and handles of nodes an
//! operation leaves stay valid.

use xml_sec::ParseError;
use xml_sec::document::external::{ExternalNode, ExternalTree, TreeEdit, TreeEditError, TreeSink};

use crate::handles::{self, HandleError};

/// The tree in one slot of the handle table.
pub struct SlotTree {
    slot: usize,
    document: ExternalNode,
}

impl SlotTree {
    /// The tree in `slot`, if it holds a document no operation holds.
    ///
    /// # Errors
    /// [`HandleError::Stale`] or [`HandleError::Busy`].
    pub fn new(slot: usize) -> Result<Self, HandleError> {
        let document = handles::read_document(slot, ExternalTree::document)?;
        Ok(Self { slot, document })
    }
}

fn unreadable(error: HandleError) -> ParseError {
    ParseError::Backend {
        backend: "document tree",
        message: error.to_string(),
    }
}

fn uneditable(error: HandleError) -> TreeEditError {
    TreeEditError(error.to_string())
}

impl ExternalTree for SlotTree {
    fn document(&self) -> ExternalNode {
        self.document
    }

    fn project(&self, sink: &mut TreeSink<'_>) -> Result<(), ParseError> {
        handles::read_document(self.slot, |tree| tree.project(sink)).map_err(unreadable)?
    }

    fn apply(&mut self, edits: &[TreeEdit<'_>]) -> Result<(), TreeEditError> {
        handles::update_document(self.slot, |tree| tree.apply(edits)).map_err(uneditable)?
    }

    fn checkpoint(&mut self) -> usize {
        // A freed document has nothing to undo; the mark is never used.
        handles::update_document(self.slot, ExternalTree::checkpoint).unwrap_or(0)
    }

    fn rollback(&mut self, mark: usize) {
        if handles::update_document(self.slot, |tree| tree.rollback(mark)).is_err() {
            // A freed document has nothing to restore.
        }
    }

    fn release(&mut self, mark: usize) {
        if handles::update_document(self.slot, |tree| tree.release(mark)).is_err() {
            // As for `rollback`.
        }
    }
}
