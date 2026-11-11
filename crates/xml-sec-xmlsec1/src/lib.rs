//! libxmlsec1 source and extension compatibility over the xml-sec core.
//!
//! The library is what C programs written against libxmlsec1's generic
//! headers compile and link against: the headers in `include/xmlsec/` are
//! libxmlsec1 1.3.13's own with its tree header (`xs_tree.h` of
//! `xml-sec-libxml2`) in place of libxml2's, and the exported functions keep
//! its structure layouts, return values and memory ownership. It uses no C
//! library: documents are the core's trees behind opaque handles, read and
//! changed through tree functions shaped like libxml2's; objects and strings
//! handed to the caller come from the library heap and are released with
//! `xsFree`. Functions that read a file, a URL or an external entity
//! themselves are not offered: the caller passes the bytes. `SAFETY.md`
//! records the invariants of the crate's single `unsafe` module.

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
