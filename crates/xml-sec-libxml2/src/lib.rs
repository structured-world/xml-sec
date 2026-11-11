//! The document tree of the libxmlsec1 surface, without libxml2 or any other
//! C library.
//!
//! A document is a core [`OwnedTree`](xml_sec::document::owned_tree::OwnedTree)
//! kept in the [`handles`] table. C code holds opaque handles (`xmlDocPtr`,
//! `xmlNodePtr`, ...) and reads and changes the tree through our own tree
//! functions, shaped like libxml2's and exported under the `xs` prefix
//! (`include/xs_tree.h`); every handle is validated, none is dereferenced.
//! [`nodes`] is the same tree for Rust code, such as the libxmlsec1-compatible
//! library. No function reads a file or a URL.
//!
//! `xs_tree_document` (`include/xml_sec_libxml2.h`) makes a clean C API
//! document handle over a tree document: signing, verification, encryption
//! and decryption read and change the tree itself, and nodes an operation
//! leaves keep their handles. The library exports the clean C API
//! (`xml_sec.h`) as well; `SAFETY.md` records the invariants of the crate's
//! single `unsafe` module.

#![deny(
    unsafe_op_in_unsafe_fn,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unnecessary_safety_doc
)]

pub mod document;
pub mod handles;
pub mod nodes;
pub mod policy;
pub mod slot_tree;

// The one boundary where C pointers are read and written.
#[expect(
    unsafe_code,
    reason = "the C boundary; its invariants are recorded in SAFETY.md"
)]
pub mod ffi;

pub use xml_sec_capi::ffi::{XsDocument, XsError, XsPolicy};
pub use xml_sec_capi::status::XsStatus;
