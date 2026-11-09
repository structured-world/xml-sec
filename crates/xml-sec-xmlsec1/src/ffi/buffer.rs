//! `xmlsec/buffer.h`: the growable byte buffer.
//!
//! The bytes between `size` and `maxSize` are kept zero, as libxmlsec1 keeps
//! them, because callers read `data` up to `maxSize` (a NUL terminator for
//! text, a scratch area for in-place decoding).

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use super::{ALLOC_MODE_DOUBLE, contain, free, grown, malloc, realloc};

#[cfg(test)]
mod tests;

/// `xmlSecBuffer`.
#[repr(C)]
pub(crate) struct XmlSecBuffer {
    pub(crate) data: *mut u8,
    pub(crate) size: usize,
    pub(crate) max_size: usize,
    pub(crate) alloc_mode: c_int,
}

/// The allocation mode of buffers initialized from now on.
static DEFAULT_ALLOC_MODE: AtomicI32 = AtomicI32::new(ALLOC_MODE_DOUBLE);
/// The smallest allocation of a buffer.
static DEFAULT_INITIAL_SIZE: AtomicUsize = AtomicUsize::new(1024);

/// The size libxmlsec1 reads a file in, which decides how the buffer grows.
const FILE_CHUNK: usize = 1024;

/// Zeroes `buf`'s bytes from `size` up to `maxSize`.
///
/// # Safety
/// `buf` is a valid buffer whose `data` holds `maxSize` bytes, and
/// `size <= maxSize`.
unsafe fn zero_tail(buf: &mut XmlSecBuffer) {
    // SAFETY: `size..maxSize` lies inside the `maxSize` bytes of `data`.
    unsafe {
        buf.data
            .add(buf.size)
            .write_bytes(0, buf.max_size - buf.size);
    }
}

/// `xmlSecBufferSetDefaultAllocMode`: the mode and smallest allocation of
/// buffers initialized from now on. A zero size is refused.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferSetDefaultAllocMode(
    def_alloc_mode: c_int,
    def_initial_size: usize,
) {
    if def_initial_size == 0 {
        return;
    }
    DEFAULT_ALLOC_MODE.store(def_alloc_mode, Ordering::Relaxed);
    DEFAULT_INITIAL_SIZE.store(def_initial_size, Ordering::Relaxed);
}

/// `xmlSecBufferCreate`: a new buffer with room for `size` bytes, released
/// with [`xmlSecBufferDestroy`]; null on failure.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferCreate(size: usize) -> *mut XmlSecBuffer {
    contain(std::ptr::null_mut(), || {
        let buf = malloc(size_of::<XmlSecBuffer>()).cast::<XmlSecBuffer>();
        if buf.is_null() {
            return buf;
        }
        // SAFETY: `buf` is a fresh allocation of a buffer's size.
        if unsafe { xmlSecBufferInitialize(buf, size) } < 0 {
            // SAFETY: initialization left `buf` a valid, empty buffer.
            unsafe { xmlSecBufferDestroy(buf) };
            return std::ptr::null_mut();
        }
        buf
    })
}

/// `xmlSecBufferDestroy`: finalizes and frees a buffer from
/// [`xmlSecBufferCreate`].
///
/// # Safety
/// `buf` is null or came from [`xmlSecBufferCreate`] and was not destroyed.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferDestroy(buf: *mut XmlSecBuffer) {
    contain((), || {
        if buf.is_null() {
            return;
        }
        // SAFETY: the caller passes a live created buffer.
        unsafe {
            xmlSecBufferFinalize(buf);
            free(buf.cast::<c_void>());
        }
    });
}

/// `xmlSecBufferInitialize`: makes `buf` an empty buffer with room for
/// `size` bytes, for a buffer the caller owns (on the stack, in a struct).
///
/// # Safety
/// `buf` is null or points to writable memory of a buffer's size; its
/// previous contents are not read.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferInitialize(
    buf: *mut XmlSecBuffer,
    size: usize,
) -> c_int {
    contain(-1, || {
        if buf.is_null() {
            return -1;
        }
        // SAFETY: `buf` is writable; the write does not read the old value.
        unsafe {
            buf.write(XmlSecBuffer {
                data: std::ptr::null_mut(),
                size: 0,
                max_size: 0,
                alloc_mode: DEFAULT_ALLOC_MODE.load(Ordering::Relaxed),
            });
            xmlSecBufferSetMaxSize(buf, size)
        }
    })
}

/// `xmlSecBufferFinalize`: releases the data of an initialized buffer,
/// leaving it empty.
///
/// # Safety
/// `buf` is null or a valid buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferFinalize(buf: *mut XmlSecBuffer) {
    contain((), || {
        if buf.is_null() {
            return;
        }
        // SAFETY: the caller passes a valid buffer, whose data is null or a
        // libxml2 allocation it owns.
        unsafe {
            xmlSecBufferEmpty(buf);
            let buf = &mut *buf;
            free(buf.data.cast::<c_void>());
            buf.data = std::ptr::null_mut();
            buf.size = 0;
            buf.max_size = 0;
        }
    });
}

/// `xmlSecBufferEmpty`: zeroes the data and sets the size to zero, keeping
/// the allocation.
///
/// # Safety
/// `buf` is null or a valid buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferEmpty(buf: *mut XmlSecBuffer) {
    contain((), || {
        // SAFETY: the caller passes null or a valid buffer.
        let Some(buf) = (unsafe { buf.as_mut() }) else {
            return;
        };
        if !buf.data.is_null() {
            if buf.max_size == 0 {
                // libxmlsec1's assertion: data without an allocation size.
                return;
            }
            // SAFETY: `data` holds `maxSize` bytes.
            unsafe { buf.data.write_bytes(0, buf.max_size) };
        }
        buf.size = 0;
    });
}

/// `xmlSecBufferIsEmpty`: 1 when `buf` is null, has no data or has size 0.
///
/// # Safety
/// `buf` is null or a valid buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferIsEmpty(buf: *mut XmlSecBuffer) -> c_int {
    contain(1, || {
        // SAFETY: the caller passes null or a valid buffer.
        match unsafe { buf.as_ref() } {
            Some(buf) if !buf.data.is_null() && buf.size > 0 => 0,
            _ => 1,
        }
    })
}

/// `xmlSecBufferGetData`: the buffer's data, null for a null buffer.
///
/// # Safety
/// `buf` is null or a valid buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferGetData(buf: *mut XmlSecBuffer) -> *mut u8 {
    contain(std::ptr::null_mut(), || {
        // SAFETY: the caller passes null or a valid buffer.
        unsafe { buf.as_ref() }.map_or(std::ptr::null_mut(), |buf| buf.data)
    })
}

/// `xmlSecBufferSetData`: replaces the contents with `size` bytes of `data`.
///
/// # Safety
/// `buf` is null or a valid buffer; `data` is null or readable for `size`
/// bytes and does not point into `buf`'s data.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferSetData(
    buf: *mut XmlSecBuffer,
    data: *const u8,
    size: usize,
) -> c_int {
    contain(-1, || {
        if buf.is_null() {
            return -1;
        }
        // SAFETY: the caller passes a valid buffer and `size` readable bytes
        // at `data`; after growing, `buf`'s data holds at least `size` bytes.
        unsafe {
            xmlSecBufferEmpty(buf);
            if size > 0 {
                if data.is_null() || xmlSecBufferSetMaxSize(buf, size) < 0 {
                    return -1;
                }
                data.copy_to((*buf).data, size);
            }
            (*buf).size = size;
        }
        0
    })
}

/// `xmlSecBufferGetSize`: the data size, 0 for a null buffer.
///
/// # Safety
/// `buf` is null or a valid buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferGetSize(buf: *mut XmlSecBuffer) -> usize {
    contain(0, || {
        // SAFETY: the caller passes null or a valid buffer.
        unsafe { buf.as_ref() }.map_or(0, |buf| buf.size)
    })
}

/// `xmlSecBufferSetSize`: sets the data size, growing the allocation when
/// needed; bytes dropped from the end are zeroed.
///
/// # Safety
/// `buf` is null or a valid buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferSetSize(buf: *mut XmlSecBuffer, size: usize) -> c_int {
    contain(-1, || {
        if buf.is_null() {
            return -1;
        }
        // SAFETY: the caller passes a valid buffer; after growing, its data
        // holds `maxSize >= max(size, old size)` bytes.
        unsafe {
            if xmlSecBufferSetMaxSize(buf, size) < 0 {
                return -1;
            }
            let buf = &mut *buf;
            if size < buf.size {
                if buf.data.is_null() {
                    return -1;
                }
                buf.data.add(size).write_bytes(0, buf.size - size);
            }
            buf.size = size;
        }
        0
    })
}

/// `xmlSecBufferGetMaxSize`: the allocation size, 0 for a null buffer.
///
/// # Safety
/// `buf` is null or a valid buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferGetMaxSize(buf: *mut XmlSecBuffer) -> usize {
    contain(0, || {
        // SAFETY: the caller passes null or a valid buffer.
        unsafe { buf.as_ref() }.map_or(0, |buf| buf.max_size)
    })
}

/// `xmlSecBufferSetMaxSize`: grows the allocation to hold at least `size`
/// bytes by the buffer's allocation mode; never shrinks it.
///
/// # Safety
/// `buf` is null or a valid buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferSetMaxSize(
    buf: *mut XmlSecBuffer,
    size: usize,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid buffer.
        let Some(buf) = (unsafe { buf.as_mut() }) else {
            return -1;
        };
        if size <= buf.max_size {
            return 0;
        }
        let Some(new_size) = grown(
            buf.alloc_mode,
            size,
            DEFAULT_INITIAL_SIZE.load(Ordering::Relaxed),
        ) else {
            return -1;
        };
        let data = if buf.data.is_null() {
            malloc(new_size)
        } else {
            // SAFETY: a non-null `data` is the buffer's libxml2 allocation.
            unsafe { realloc(buf.data.cast::<c_void>(), new_size) }
        };
        if data.is_null() {
            return -1;
        }
        buf.data = data.cast::<u8>();
        buf.max_size = new_size;
        if buf.size < buf.max_size {
            // SAFETY: `data` now holds `maxSize > size` bytes.
            unsafe { zero_tail(buf) };
        }
        0
    })
}

/// `xmlSecBufferSwap`: exchanges the contents of two buffers.
///
/// # Safety
/// Each pointer is null or a valid buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferSwap(buf1: *mut XmlSecBuffer, buf2: *mut XmlSecBuffer) {
    contain((), || {
        if buf1.is_null() || buf2.is_null() {
            return;
        }
        // SAFETY: both are valid buffers; `swap` allows them to be the same.
        unsafe { std::ptr::swap(buf1, buf2) };
    });
}

/// `xmlSecBufferAppend`: adds `size` bytes of `data` after the contents.
///
/// # Safety
/// `buf` is null or a valid buffer; `data` is null or readable for `size`
/// bytes and does not point into `buf`'s data.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferAppend(
    buf: *mut XmlSecBuffer,
    data: *const u8,
    size: usize,
) -> c_int {
    contain(-1, || {
        if buf.is_null() {
            return -1;
        }
        if size == 0 {
            return 0;
        }
        // SAFETY: the caller passes a valid buffer and `size` readable bytes
        // at `data`; after growing, the buffer holds `old size + size` bytes.
        unsafe {
            let Some(total) = (*buf).size.checked_add(size) else {
                return -1;
            };
            if data.is_null() || xmlSecBufferSetMaxSize(buf, total) < 0 {
                return -1;
            }
            let buf = &mut *buf;
            data.copy_to(buf.data.add(buf.size), size);
            buf.size = total;
        }
        0
    })
}

/// `xmlSecBufferPrepend`: adds `size` bytes of `data` before the contents.
///
/// # Safety
/// `buf` is null or a valid buffer; `data` is null or readable for `size`
/// bytes and does not point into `buf`'s data.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferPrepend(
    buf: *mut XmlSecBuffer,
    data: *const u8,
    size: usize,
) -> c_int {
    contain(-1, || {
        if buf.is_null() {
            return -1;
        }
        if size == 0 {
            return 0;
        }
        // SAFETY: as for append; the old contents move within the grown data.
        unsafe {
            let Some(total) = (*buf).size.checked_add(size) else {
                return -1;
            };
            if data.is_null() || xmlSecBufferSetMaxSize(buf, total) < 0 {
                return -1;
            }
            let buf = &mut *buf;
            buf.data.copy_to(buf.data.add(size), buf.size);
            data.copy_to(buf.data, size);
            buf.size = total;
        }
        0
    })
}

/// `xmlSecBufferRemoveHead`: drops `size` bytes from the start; dropping
/// more than the contents empties the buffer.
///
/// # Safety
/// `buf` is null or a valid buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferRemoveHead(
    buf: *mut XmlSecBuffer,
    size: usize,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid buffer.
        let Some(buf) = (unsafe { buf.as_mut() }) else {
            return -1;
        };
        if size < buf.size {
            if buf.data.is_null() {
                return -1;
            }
            buf.size -= size;
            // SAFETY: both ranges lie inside the old `size` bytes of data.
            unsafe { buf.data.add(size).copy_to(buf.data, buf.size) };
        } else {
            buf.size = 0;
        }
        if buf.size < buf.max_size {
            if buf.data.is_null() {
                return -1;
            }
            // SAFETY: data holds `maxSize > size` bytes.
            unsafe { zero_tail(buf) };
        }
        0
    })
}

/// `xmlSecBufferRemoveTail`: drops `size` bytes from the end; dropping more
/// than the contents empties the buffer.
///
/// # Safety
/// `buf` is null or a valid buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferRemoveTail(
    buf: *mut XmlSecBuffer,
    size: usize,
) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid buffer.
        let Some(buf) = (unsafe { buf.as_mut() }) else {
            return -1;
        };
        // libxmlsec1's contract: removing more than the contents empties the
        // buffer, so clamping at zero is the specified result.
        buf.size = buf.size.saturating_sub(size);
        if buf.size < buf.max_size {
            if buf.data.is_null() {
                return -1;
            }
            // SAFETY: data holds `maxSize > size` bytes.
            unsafe { zero_tail(buf) };
        }
        0
    })
}

/// `xmlSecBufferReverse`: reverses the order of the bytes.
///
/// # Safety
/// `buf` is null or a valid buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferReverse(buf: *mut XmlSecBuffer) -> c_int {
    contain(-1, || {
        // SAFETY: the caller passes null or a valid buffer.
        let Some(buf) = (unsafe { buf.as_mut() }) else {
            return -1;
        };
        if buf.size <= 1 {
            return 0;
        }
        if buf.data.is_null() {
            return -1;
        }
        // SAFETY: data holds `size` initialized bytes the buffer owns.
        unsafe { std::slice::from_raw_parts_mut(buf.data, buf.size) }.reverse();
        0
    })
}

/// `xmlSecBufferReadFile`: appends the contents of the file `filename`.
///
/// # Safety
/// `buf` is null or a valid buffer; `filename` is null or a NUL-terminated
/// string.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferReadFile(
    buf: *mut XmlSecBuffer,
    filename: *const c_char,
) -> c_int {
    contain(-1, || {
        if buf.is_null() || filename.is_null() {
            return -1;
        }
        // SAFETY: the caller passes a NUL-terminated name.
        let name = unsafe { CStr::from_ptr(filename) };
        let Ok(contents) = std::fs::read(path(name)) else {
            return -1;
        };
        // Appended in libxmlsec1's read size, so the buffer grows the same way.
        for chunk in contents.chunks(FILE_CHUNK) {
            // SAFETY: `buf` is valid and `chunk` is readable.
            if unsafe { xmlSecBufferAppend(buf, chunk.as_ptr(), chunk.len()) } < 0 {
                return -1;
            }
        }
        0
    })
}

/// The file a C file name names: its bytes as the platform's path.
#[cfg(unix)]
fn path(name: &CStr) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::OsStr::from_bytes(name.to_bytes()).into()
}

/// The file a C file name names; on Windows the narrow C runtime takes the
/// active code page, which for the supported case is UTF-8.
#[cfg(not(unix))]
fn path(name: &CStr) -> std::path::PathBuf {
    name.to_string_lossy().into_owned().into()
}

/// The value of an ASCII hex digit.
fn hex_digit(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

/// `xmlSecBufferHexRead`: replaces the contents with the bytes the hex string
/// `hex_str` encodes. A bad digit fails after the bytes before it are stored,
/// as in libxmlsec1.
///
/// # Safety
/// `buf` is null or a valid buffer; `hex_str` is null or a NUL-terminated
/// string.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferHexRead(
    buf: *mut XmlSecBuffer,
    hex_str: *const u8,
) -> c_int {
    contain(-1, || {
        if buf.is_null() || hex_str.is_null() {
            return -1;
        }
        // SAFETY: the caller passes a NUL-terminated string.
        let hex = unsafe { CStr::from_ptr(hex_str.cast::<c_char>()) }.to_bytes();
        if hex.is_empty() {
            // SAFETY: `buf` is valid.
            unsafe { xmlSecBufferEmpty(buf) };
            return 0;
        }
        if hex.len() % 2 != 0 {
            return -1;
        }
        // SAFETY: `buf` is valid; after sizing, its data holds `hex.len() / 2`
        // bytes.
        unsafe {
            if xmlSecBufferSetSize(buf, hex.len() / 2) < 0 {
                return -1;
            }
            let data = (*buf).data;
            if data.is_null() {
                return -1;
            }
            for (index, [first, second]) in hex.as_chunks::<2>().0.iter().enumerate() {
                let (Some(high), Some(low)) = (hex_digit(*first), hex_digit(*second)) else {
                    return -1;
                };
                data.add(index).write((high << 4) | low);
            }
        }
        0
    })
}

/// `xmlSecMemEqual`: 1 when the `size` bytes at `buf1` and `buf2` are equal,
/// in time independent of where they differ; 0 when they differ, -1 for a
/// null pointer with a nonzero size.
///
/// # Safety
/// Each pointer is null or readable for `size` bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecMemEqual(
    buf1: *const u8,
    buf2: *const u8,
    size: usize,
) -> c_int {
    contain(-1, || {
        if size == 0 {
            return 1;
        }
        if buf1.is_null() || buf2.is_null() {
            return -1;
        }
        // SAFETY: both are readable for `size` bytes.
        let (left, right) = unsafe {
            (
                std::slice::from_raw_parts(buf1, size),
                std::slice::from_raw_parts(buf2, size),
            )
        };
        let mut diff = 0u8;
        for (a, b) in left.iter().zip(right) {
            // The opaque accumulator keeps the loop from ending at the first
            // difference.
            diff = std::hint::black_box(diff | (a ^ b));
        }
        c_int::from(diff == 0)
    })
}
