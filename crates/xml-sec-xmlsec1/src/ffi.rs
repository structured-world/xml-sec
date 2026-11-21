//! The xmlsec1 boundary: the crate's only `unsafe` code.
//!
//! Every exported function keeps libxmlsec1's name, signature and observable
//! behavior: the same return values for the same arguments, the same memory
//! contents after the call, and the same ownership of what it returns. The
//! submodules follow libxmlsec1's headers. `SAFETY.md` records the invariants
//! every `unsafe` block relies on.

use std::ffi::{c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(crate) mod app;
pub(crate) mod asymkeys;
pub(crate) mod base64;
pub(crate) mod buffer;
pub(crate) mod crypto;
pub(crate) mod errors;
pub(crate) mod keyinfo;
pub(crate) mod keys;
pub(crate) mod keysdata;
pub(crate) mod keysmngr;
pub(crate) mod library;
pub(crate) mod list;
pub(crate) mod nodeset;
pub(crate) mod parser;
pub(crate) mod policy;
pub(crate) mod strings;
pub(crate) mod symkeys;
pub(crate) mod templates;
pub(crate) mod transforms;
pub(crate) mod tree;
pub(crate) mod version;
pub(crate) mod x509;
pub(crate) mod xdhkeys;
pub(crate) mod xmldsig;
pub(crate) mod xmlenc;
pub(crate) mod xmltree;

#[cfg(test)]
mod tests;

/// `xmlSecAllocModeExact`: grow to the requested size plus a little.
pub(crate) const ALLOC_MODE_EXACT: c_int = 0;
/// `xmlSecAllocModeDouble`: grow to twice the requested size.
pub(crate) const ALLOC_MODE_DOUBLE: c_int = 1;

use xml_sec_libxml2::ffi::memory;

/// Allocates `size` bytes of the library's heap, which libxmlsec1 hands
/// memory out from and callers release with `xmlFree`; null when it fails.
fn malloc(size: usize) -> *mut c_void {
    memory::malloc(size)
}

/// A copy of `bytes` with a NUL on the library's heap; null when the
/// allocation fails.
fn duplicate(bytes: &[u8]) -> *mut u8 {
    memory::copy(bytes)
}

/// Resizes `mem` to `size` bytes; null when it fails, leaving `mem`
/// allocated.
///
/// # Safety
/// `mem` came from [`malloc`] or [`realloc`] and was not freed.
unsafe fn realloc(mem: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: by the caller's contract.
    unsafe { memory::realloc(mem, size) }
}

/// Releases `mem`.
///
/// # Safety
/// `mem` is null or came from [`malloc`] or [`realloc`] and was not freed.
unsafe fn free(mem: *mut c_void) {
    // SAFETY: by the caller's contract.
    unsafe { memory::free(mem) }
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

/// Why an allocation cannot grow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrowthRefused {
    /// The size is more than `limit`, past which the grown size overflows.
    TooLarge { limit: usize },
    /// The allocation mode is none of libxmlsec1's.
    UnknownMode,
}

/// The size an allocation grows to for `size` bytes or items under
/// `alloc_mode`, never below `initial`.
pub(crate) fn grown(
    alloc_mode: c_int,
    size: usize,
    initial: usize,
) -> Result<usize, GrowthRefused> {
    let wanted = match alloc_mode {
        ALLOC_MODE_EXACT => {
            let limit = usize::MAX - 8;
            if size > limit {
                return Err(GrowthRefused::TooLarge { limit });
            }
            size + 8
        }
        ALLOC_MODE_DOUBLE => {
            let limit = (usize::MAX - 32) / 2;
            if size > limit {
                return Err(GrowthRefused::TooLarge { limit });
            }
            2 * size + 32
        }
        _ => return Err(GrowthRefused::UnknownMode),
    };
    Ok(wanted.max(initial))
}

/// Reports `refused` as libxmlsec1 reports a refused growth of `size` in
/// `alloc_mode`.
fn report_growth(
    here: errors::Here,
    object: *const std::ffi::c_char,
    refused: GrowthRefused,
    size: usize,
    alloc_mode: c_int,
) {
    match refused {
        GrowthRefused::TooLarge { limit } => {
            errors::size_more_than(here, object, "size", size, limit);
        }
        GrowthRefused::UnknownMode => {
            errors::unsupported_enum(here, object, "alloc mode", alloc_mode);
        }
    }
}

/// Runs an exported function's body; a panic is reported as an internal
/// error and returns `fallback` instead of unwinding into C.
fn contain<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("panic");
            errors::report(
                errors::here!("contain"),
                std::ptr::null(),
                c"panic".as_ptr(),
                errors::R_XMLSEC_FAILED,
                message,
            );
            fallback
        }
    }
}
