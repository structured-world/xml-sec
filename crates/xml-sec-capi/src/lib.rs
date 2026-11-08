//! The stable C ABI of xml-sec.
//!
//! C and C++ callers reach the policy-bound Rust API through opaque handles:
//! a handle is a typed slot index and generation in a library-owned table,
//! never a pointer, so a wrong, stale, destroyed or concurrently used handle
//! is reported as a status rather than undefined behaviour. Every function
//! returns an [`status::XsStatus`]; a failing call may also create an error
//! handle carrying a redacted message. Values crossing the boundary are plain
//! structures and byte slices; buffers the library allocates are released
//! with `xs_buffer_free`. No Rust panic crosses the boundary.
//!
//! Policy comes only from schema-v1 TOML configuration compiled into a policy
//! store; operations run against one immutable snapshot loaded from it. The
//! header is `include/xml_sec.h`; `SAFETY.md` records the invariants of the
//! crate's single `unsafe` module.

#![deny(
    unsafe_op_in_unsafe_fn,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unnecessary_safety_doc
)]

// The workspace denies `unsafe_code` in every library; this module is the one
// boundary where C pointers become Rust values. Every other module forbids it.
#[expect(
    unsafe_code,
    reason = "the C ABI boundary; its invariants are recorded in SAFETY.md"
)]
pub mod ffi;
mod objects;
pub mod status;
mod table;
#[cfg(test)]
mod test_support;
