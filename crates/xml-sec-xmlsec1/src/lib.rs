//! libxmlsec1 source and extension compatibility over the xml-sec core.
//!
//! The library is what C programs written against libxmlsec1's generic
//! headers compile and link against: the headers in `include/xmlsec/` are
//! libxmlsec1 1.3.13's own, and the exported functions keep its structure
//! layouts, return values and memory ownership. Objects and strings handed
//! to the caller are allocated with libxml2's allocator, as libxmlsec1's are,
//! so the caller releases them with `xmlFree`. The library does not link
//! libxml2: it uses the program's, found in the running process, and offers
//! libxmlsec1's functionality only. `SAFETY.md` records the invariants of the
//! crate's single `unsafe` module.

#![warn(unreachable_pub)]
#![deny(
    unsafe_op_in_unsafe_fn,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unnecessary_safety_doc
)]

// The one boundary where C pointers are read and written.
#[expect(
    unsafe_code,
    reason = "the xmlsec1 boundary; its invariants are recorded in SAFETY.md"
)]
mod ffi;
