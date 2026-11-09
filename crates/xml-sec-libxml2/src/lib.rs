//! xml-sec operations on a caller's libxml2 document, in place.
//!
//! `xs_libxml2_document` turns an `xmlDocPtr` into a document handle of the
//! clean C API: signing a template, verification, encryption and decryption
//! through that handle read and change the caller's tree itself. Nodes an
//! operation does not touch keep their pointers; nodes it creates belong to
//! the document. Every operation reads the tree as it is when it starts.
//!
//! The library exports the clean C API (`xml_sec.h`) as well; the header is
//! `include/xml_sec_libxml2.h`, and `SAFETY.md` records the invariants of the
//! crate's single `unsafe` module.

#![deny(
    unsafe_op_in_unsafe_fn,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unnecessary_safety_doc
)]

// The one boundary where libxml2 pointers are read and written.
#[expect(
    unsafe_code,
    reason = "the libxml2 boundary; its invariants are recorded in SAFETY.md"
)]
pub mod ffi;

pub use xml_sec_capi::ffi::{XsDocument, XsError, XsPolicy};
pub use xml_sec_capi::status::XsStatus;
