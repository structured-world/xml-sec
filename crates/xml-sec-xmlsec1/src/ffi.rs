//! The xmlsec1 boundary: the crate's only `unsafe` code.
//!
//! Every exported function keeps libxmlsec1's name, signature and observable
//! behavior: the same return values for the same arguments, the same memory
//! contents after the call, and the same ownership of what it returns. The
//! submodules follow libxmlsec1's headers. `SAFETY.md` records the invariants
//! every `unsafe` block relies on.

use std::ffi::{c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(crate) mod buffer;
pub(crate) mod list;
pub(crate) mod nodeset;
pub(crate) mod tree;
pub(crate) mod xmltree;

#[cfg(test)]
mod tests;

/// `xmlSecAllocModeExact`: grow to the requested size plus a little.
pub(crate) const ALLOC_MODE_EXACT: c_int = 0;
/// `xmlSecAllocModeDouble`: grow to twice the requested size.
pub(crate) const ALLOC_MODE_DOUBLE: c_int = 1;

unsafe extern "C" {
    fn xs_xmlsec1_malloc(size: usize) -> *mut c_void;
    fn xs_xmlsec1_realloc(mem: *mut c_void, size: usize) -> *mut c_void;
    fn xs_xmlsec1_free(mem: *mut c_void);
    fn xs_xmlsec1_fputs(stream: *mut c_void, text: *const std::ffi::c_char) -> c_int;
    #[cfg(test)]
    static xs_xmlsec1_layout: [usize; 0];
    #[cfg(test)]
    static xs_xmlsec1_layout_len: usize;
}

/// Allocates `size` bytes with libxml2's allocator; null when it fails.
fn malloc(size: usize) -> *mut c_void {
    // SAFETY: `xmlMalloc` accepts any size and reports failure as null.
    unsafe { xs_xmlsec1_malloc(size) }
}

/// Resizes `mem`, which libxml2's allocator returned, to `size` bytes; null
/// when it fails, leaving `mem` allocated.
///
/// # Safety
/// `mem` came from [`malloc`] or [`realloc`] and was not freed.
unsafe fn realloc(mem: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: the caller passes a live libxml2 allocation.
    unsafe { xs_xmlsec1_realloc(mem, size) }
}

/// Releases `mem`, which libxml2's allocator returned.
///
/// # Safety
/// `mem` is null or came from [`malloc`] or [`realloc`] and was not freed.
unsafe fn free(mem: *mut c_void) {
    // SAFETY: the caller passes null or a live libxml2 allocation.
    unsafe { xs_xmlsec1_free(mem) }
}

/// Writes `text` to the C stream `stream`; text with an interior NUL is
/// written up to it, as C would.
///
/// # Safety
/// `stream` is a live C `FILE*`.
unsafe fn write_stream(stream: *mut c_void, text: &str) {
    let end = text.find('\0').unwrap_or(text.len());
    let Ok(text) = std::ffi::CString::new(&text[..end]) else {
        return;
    };
    // SAFETY: `stream` is a live stream and `text` is NUL-terminated. A
    // short write is the stream's state to report, as with fprintf.
    unsafe { xs_xmlsec1_fputs(stream, text.as_ptr()) };
}

/// The size an allocation grows to for `size` bytes or items under
/// `alloc_mode`, never below `initial`; `None` on overflow. An unknown mode
/// grows to `initial`, as libxmlsec1's mode switch without a default does.
pub(crate) fn grown(alloc_mode: c_int, size: usize, initial: usize) -> Option<usize> {
    let wanted = match alloc_mode {
        ALLOC_MODE_EXACT => size.checked_add(8)?,
        ALLOC_MODE_DOUBLE => size.checked_mul(2)?.checked_add(32)?,
        _ => 0,
    };
    Some(wanted.max(initial))
}

/// Runs an exported function's body; a panic returns `fallback` instead of
/// unwinding into C.
fn contain<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(fallback)
}

/// The layout record of the crate's headers, in the order of `layout.c`. The
/// headers are part of the crate, so a mismatch is a build defect the tests
/// catch, not a property of the environment to check at run time.
#[cfg(test)]
pub(crate) fn header_layout() -> &'static [usize] {
    // SAFETY: `layout.c` defines `xs_xmlsec1_layout` as an array of
    // `xs_xmlsec1_layout_len` initialized `size_t` values with static
    // storage, and `size_t` is `usize` on every target Rust supports.
    unsafe {
        std::slice::from_raw_parts(
            (&raw const xs_xmlsec1_layout).cast::<usize>(),
            xs_xmlsec1_layout_len,
        )
    }
}
