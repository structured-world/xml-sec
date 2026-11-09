//! The xmlsec1 boundary: the crate's only `unsafe` code.
//!
//! Every exported function keeps libxmlsec1's name, signature and observable
//! behavior: the same return values for the same arguments, the same memory
//! contents after the call, and the same ownership of what it returns. The
//! submodules follow libxmlsec1's headers. `SAFETY.md` records the invariants
//! every `unsafe` block relies on.

use std::ffi::{c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(crate) mod base64;
pub(crate) mod buffer;
pub(crate) mod keysdata;
pub(crate) mod list;
pub(crate) mod nodeset;
pub(crate) mod parser;
pub(crate) mod policy;
pub(crate) mod strings;
pub(crate) mod transforms;
pub(crate) mod tree;
pub(crate) mod xmltree;

#[cfg(test)]
mod tests;

/// `xmlSecAllocModeExact`: grow to the requested size plus a little.
pub(crate) const ALLOC_MODE_EXACT: c_int = 0;
/// `xmlSecAllocModeDouble`: grow to twice the requested size.
pub(crate) const ALLOC_MODE_DOUBLE: c_int = 1;

use xml_sec_libxml2::ffi::libxml2;

/// Allocates `size` bytes with the caller's libxml2 allocator, which
/// libxmlsec1 hands memory out from and callers release with `xmlFree`; null
/// when it fails or no libxml2 is loaded.
fn malloc(size: usize) -> *mut c_void {
    if !libxml2::available() {
        return std::ptr::null_mut();
    }
    // SAFETY: libxml2 is available; `xmlMalloc` accepts any size and reports
    // failure as null.
    unsafe { libxml2::xml_malloc(size) }
}

/// Resizes `mem`, which libxml2's allocator returned, to `size` bytes; null
/// when it fails, leaving `mem` allocated.
///
/// # Safety
/// `mem` came from [`malloc`] or [`realloc`] and was not freed.
unsafe fn realloc(mem: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: a live allocation proves libxml2 was available, and it stays
    // resolved; the caller passes such an allocation.
    unsafe { libxml2::xml_realloc(mem, size) }
}

/// Releases `mem`, which libxml2's allocator returned.
///
/// # Safety
/// `mem` is null or came from [`malloc`] or [`realloc`] and was not freed.
unsafe fn free(mem: *mut c_void) {
    if mem.is_null() {
        return;
    }
    // SAFETY: as for `realloc`.
    unsafe { libxml2::xml_free(mem) }
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
    unsafe { libc::fputs(text.as_ptr(), stream.cast()) };
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
