//! The heap memory the C surface hands out: our own functions shaped like
//! libxml2's `xmlMalloc`, `xmlRealloc`, `xmlFree` and `xmlStrdup`, over the
//! platform's C heap.
//!
//! Every string or block a function of the library returns for the caller to
//! own comes from here, and the caller releases it with [`xsFree`], as a
//! libxml2 program releases libxmlsec1's with `xmlFree`. As with `free`, the
//! pointer passed is one these functions returned and did not release yet.

use std::ffi::{c_char, c_void};

use super::tree::XmlChar;

/// `size` bytes of the C heap, or null when it is exhausted; a zero size
/// still returns a block the caller can release.
#[must_use]
pub fn malloc(size: usize) -> *mut c_void {
    // SAFETY: `malloc` accepts any size and reports failure as null.
    unsafe { libc::malloc(size.max(1)) }
}

/// `mem` resized to `size` bytes, or null when the heap is exhausted, which
/// leaves `mem` allocated.
///
/// # Safety
/// `mem` is null or a live block [`malloc`] or [`realloc`] returned.
pub unsafe fn realloc(mem: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: a live block or null, by the caller's contract.
    unsafe { libc::realloc(mem, size.max(1)) }
}

/// Release `mem`; null is ignored.
///
/// # Safety
/// `mem` is null or a live block [`malloc`] or [`realloc`] returned.
pub unsafe fn free(mem: *mut c_void) {
    // SAFETY: by the caller's contract; `free` ignores null.
    unsafe { libc::free(mem) }
}

/// A NUL-terminated copy of `bytes` on the C heap, or null when the heap is
/// exhausted. The copy ends at the first NUL of `bytes`, as C reads it.
#[must_use]
pub fn copy(bytes: &[u8]) -> *mut XmlChar {
    let bytes = bytes
        .iter()
        .position(|&byte| byte == 0)
        .map_or(bytes, |end| &bytes[..end]);
    let Some(size) = bytes.len().checked_add(1) else {
        return std::ptr::null_mut();
    };
    let block = malloc(size).cast::<XmlChar>();
    if !block.is_null() {
        // SAFETY: the block holds `size` bytes: the text and its NUL.
        unsafe {
            block.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
            block.add(bytes.len()).write(0);
        }
    }
    block
}

/// `xmlMalloc`: `size` bytes the caller releases with [`xsFree`].
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsMalloc(size: usize) -> *mut c_void {
    malloc(size)
}

/// `xmlRealloc`: `mem` resized to `size` bytes; null leaves `mem` allocated.
///
/// # Safety
/// `mem` is null or a live block of these functions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsRealloc(mem: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: by the caller's contract.
    unsafe { realloc(mem, size) }
}

/// `xmlFree`: release memory a function of the library returned.
///
/// # Safety
/// `mem` is null or a live block of the library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsFree(mem: *mut c_void) {
    // SAFETY: by the caller's contract.
    unsafe { free(mem) }
}

/// `xmlStrdup`: a copy of the NUL-terminated `text`, or null for null.
///
/// # Safety
/// `text` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsStrdup(text: *const XmlChar) -> *mut XmlChar {
    if text.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: NUL-terminated by the caller's contract.
    copy(unsafe { std::ffi::CStr::from_ptr(text.cast::<c_char>()) }.to_bytes())
}
