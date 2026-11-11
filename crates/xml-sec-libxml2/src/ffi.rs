//! The C boundary: the crate's only `unsafe` code. `SAFETY.md` records the
//! invariants every `unsafe` block relies on.
//!
//! The submodules export the tree functions, the heap, the I/O buffers and
//! the generic error channel; this module exports the clean C API's entry
//! point for a tree document.

use xml_sec_capi::ffi::{XsDocument, XsError, XsPolicy};
use xml_sec_capi::status::{XS_INVALID_ARGUMENT, XsStatus};

use crate::nodes::{self, Doc, XML_DOCUMENT_NODE};
use crate::slot_tree::SlotTree;

pub mod errors;
pub mod io;
pub mod memory;
#[cfg(test)]
mod tests;
pub mod tree;

/// Create a clean C API document handle over the tree `doc` names, read
/// under the compiled policy of `operation` in `policy`. Each operation on
/// the handle reads and changes the tree as it is when the operation runs;
/// between operations the caller may change the tree through the tree
/// functions. Returns `XS_INVALID_ARGUMENT` for a value that names no live
/// document.
///
/// # Safety
/// `out` and `error` are null or writable, as for the clean C API's
/// document constructors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xs_tree_document(
    policy: XsPolicy,
    operation: u32,
    doc: *mut Doc,
    out: *mut XsDocument,
    error: *mut XsError,
) -> XsStatus {
    let refuse = || {
        if !error.is_null() && error.is_aligned() {
            // SAFETY: non-null, aligned and writable by the caller's contract.
            unsafe { error.write(XsError::default()) };
        }
        XS_INVALID_ARGUMENT
    };
    if nodes::kind(doc) != XML_DOCUMENT_NODE {
        return refuse();
    }
    let Some(tree) = nodes::document_of(doc).and_then(|slot| SlotTree::new(slot).ok()) else {
        return refuse();
    };
    // SAFETY: forwarded contract for `out` and `error`.
    unsafe { xml_sec_capi::ffi::document_from_tree(policy, operation, Box::new(tree), out, error) }
}
