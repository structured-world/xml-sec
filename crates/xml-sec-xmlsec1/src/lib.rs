//! libxmlsec1 source and extension compatibility over the xml-sec core.
//!
//! The library is what C programs written against libxmlsec1's generic
//! headers compile and link against: the headers in `include/xmlsec/` are
//! those of upstream libxmlsec1's development line, with its tree header
//! (`xs_tree.h` of `xml-sec-libxml2`) in place of libxml2's; the version they
//! declare is the one `xmlSecCheckVersion` checks. The exported functions keep
//! its structure layouts, return values and memory ownership. It uses no C
//! library: documents are the core's trees behind opaque handles, read and
//! changed through tree functions shaped like libxml2's; objects and strings
//! handed to the caller come from the library heap and are released with
//! `xsFree`. Functions that read a file, a URL or an external entity
//! themselves are not offered: the caller passes the bytes. libxmlsec1's
//! backend headers (`xmlsec/openssl`, `nss`, `gnutls`, `gcrypt`, `mscng`,
//! `mscrypto`) are not shipped, since they hand out the backend's own
//! objects: the generic crypto entry points dispatch to the built-in
//! provider. `SAFETY.md` records the invariants of the crate's single
//! `unsafe` module.

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
