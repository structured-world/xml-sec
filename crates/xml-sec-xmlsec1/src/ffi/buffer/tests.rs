//! The buffer against libxmlsec1's own semantics: sizes, growth, the zeroed
//! tail callers rely on, and the return values of every refusal.

use super::{
    XmlSecBuffer, xmlSecBufferAppend, xmlSecBufferCreate, xmlSecBufferDestroy, xmlSecBufferEmpty,
    xmlSecBufferFinalize, xmlSecBufferGetData, xmlSecBufferGetMaxSize, xmlSecBufferGetSize,
    xmlSecBufferHexRead, xmlSecBufferInitialize, xmlSecBufferIsEmpty, xmlSecBufferPrepend,
    xmlSecBufferRemoveHead, xmlSecBufferRemoveTail, xmlSecBufferReverse, xmlSecBufferSetData,
    xmlSecBufferSetDefaultAllocMode, xmlSecBufferSetMaxSize, xmlSecBufferSetSize, xmlSecBufferSwap,
    xmlSecMemEqual,
};
use crate::ffi::{ALLOC_MODE_DOUBLE, ALLOC_MODE_EXACT};
use std::mem::MaybeUninit;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Held by every test whose sizes depend on the process-wide default mode
/// and initial size, so the test that changes them never runs beside one
/// that reads them, whatever the runner's threading.
fn defaults() -> MutexGuard<'static, ()> {
    static DEFAULTS: Mutex<()> = Mutex::new(());
    DEFAULTS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A created buffer, destroyed on drop.
struct Buffer(*mut XmlSecBuffer);

impl Buffer {
    fn new(size: usize) -> Self {
        // SAFETY: creation takes any size.
        let buf = unsafe { xmlSecBufferCreate(size) };
        assert!(!buf.is_null(), "the buffer is created");
        Self(buf)
    }

    /// The `size` bytes of data.
    fn contents(&self) -> Vec<u8> {
        self.bytes(self.size())
    }

    /// The first `count` bytes of the allocation.
    fn bytes(&self, count: usize) -> Vec<u8> {
        // SAFETY: the buffer is live and its data holds `maxSize >= count`
        // bytes.
        unsafe {
            assert!(count <= xmlSecBufferGetMaxSize(self.0));
            let data = xmlSecBufferGetData(self.0);
            if count == 0 {
                return Vec::new();
            }
            std::slice::from_raw_parts(data, count).to_vec()
        }
    }

    fn size(&self) -> usize {
        // SAFETY: the buffer is live.
        unsafe { xmlSecBufferGetSize(self.0) }
    }

    fn max_size(&self) -> usize {
        // SAFETY: the buffer is live.
        unsafe { xmlSecBufferGetMaxSize(self.0) }
    }

    fn append(&self, data: &[u8]) -> i32 {
        // SAFETY: the buffer is live and `data` is readable.
        unsafe { xmlSecBufferAppend(self.0, data.as_ptr(), data.len()) }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: the buffer was created and is destroyed once.
        unsafe { xmlSecBufferDestroy(self.0) };
    }
}

std::thread_local! {
    /// The blocks growth released on this thread, as they were at release.
    static RELEASED: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Records a block growth releases, called just before it is freed.
pub(super) fn released(block: &[u8]) {
    RELEASED.with(|blocks| blocks.borrow_mut().push(block.to_vec()));
}

/// Growth moves the contents to a new block and releases the old one wiped:
/// a key the buffer held does not stay in freed heap memory.
#[test]
fn growth_wipes_the_block_it_leaves() {
    let _defaults = defaults();
    let buf = Buffer::new(16);
    let secret = [0xA5_u8; 16];
    assert_eq!(buf.append(&secret), 0);
    let old_max = buf.max_size();
    RELEASED.with(|blocks| blocks.borrow_mut().clear());
    // SAFETY: the buffer is live.
    assert_eq!(unsafe { xmlSecBufferSetMaxSize(buf.0, old_max + 1) }, 0);
    let released = RELEASED.with(std::cell::RefCell::take);
    assert_eq!(released.len(), 1, "one block is released");
    assert_eq!(released[0].len(), old_max);
    assert!(
        released[0].iter().all(|&byte| byte == 0),
        "the old block is wiped"
    );
    assert_eq!(buf.contents(), secret);
}

/// A zero-size buffer allocates nothing; any other gets at least the
/// default 1024 bytes, all zero.
#[test]
fn creation_allocates_like_libxmlsec1() {
    let _defaults = defaults();
    let empty = Buffer::new(0);
    assert_eq!((empty.size(), empty.max_size()), (0, 0));
    // SAFETY: the buffer is live.
    assert!(unsafe { xmlSecBufferGetData(empty.0) }.is_null());
    // SAFETY: the buffer is live.
    assert_eq!(unsafe { xmlSecBufferIsEmpty(empty.0) }, 1);

    let sized = Buffer::new(10);
    assert_eq!((sized.size(), sized.max_size()), (0, 1024));
    assert!(sized.bytes(1024).iter().all(|&byte| byte == 0));
}

/// Appending and prepending keep the order, and growth follows the
/// buffer's mode: double mode grows to twice the needed size plus 32.
#[test]
fn append_and_prepend_grow_by_the_mode() {
    let _defaults = defaults();
    let buf = Buffer::new(0);
    assert_eq!(buf.append(b"world"), 0);
    // SAFETY: the buffer is live and the slice readable.
    let prepended = unsafe { xmlSecBufferPrepend(buf.0, b"hello ".as_ptr(), 6) };
    assert_eq!(prepended, 0);
    assert_eq!(buf.contents(), b"hello world");
    assert_eq!(buf.max_size(), 1024);
    assert_eq!(buf.append(&[7; 2000]), 0);
    assert_eq!(buf.size(), 2011);
    assert_eq!(buf.max_size(), 2 * 2011 + 32);
    // A zero-length append with a null pointer is accepted, a non-zero one
    // is refused.
    // SAFETY: the buffer is live; a null pointer is read for no bytes.
    unsafe {
        assert_eq!(xmlSecBufferAppend(buf.0, std::ptr::null(), 0), 0);
        assert_eq!(xmlSecBufferAppend(buf.0, std::ptr::null(), 1), -1);
    }
}

/// Exact mode adds 8 bytes, and the default mode applies to buffers
/// initialized after it is set.
#[test]
fn default_mode_applies_to_new_buffers() {
    /// Puts the process-wide defaults back when the test ends, also by panic,
    /// before the lock taken below is released.
    struct Restore(i32, usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            super::DEFAULT_ALLOC_MODE.store(self.0, std::sync::atomic::Ordering::Relaxed);
            super::DEFAULT_INITIAL_SIZE.store(self.1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let _defaults = defaults();
    let _restore = Restore(
        super::DEFAULT_ALLOC_MODE.load(std::sync::atomic::Ordering::Relaxed),
        super::DEFAULT_INITIAL_SIZE.load(std::sync::atomic::Ordering::Relaxed),
    );
    // SAFETY: setting the defaults is always allowed.
    unsafe { xmlSecBufferSetDefaultAllocMode(ALLOC_MODE_EXACT, 16) };
    let buf = Buffer::new(100);
    assert_eq!(buf.max_size(), 108);
    // A zero initial size is refused and leaves the defaults unchanged.
    // SAFETY: as above.
    unsafe { xmlSecBufferSetDefaultAllocMode(ALLOC_MODE_DOUBLE, 0) };
    assert_eq!(Buffer::new(100).max_size(), 108);
}

/// Removed bytes are zeroed, as callers read the data up to `maxSize`.
#[test]
fn removed_bytes_are_zeroed() {
    let buf = Buffer::new(0);
    buf.append(b"abcdefgh");
    // SAFETY: the buffer is live.
    unsafe {
        assert_eq!(xmlSecBufferRemoveHead(buf.0, 2), 0);
        assert_eq!(buf.contents(), b"cdefgh");
        assert_eq!(buf.bytes(8), b"cdefgh\0\0");
        assert_eq!(xmlSecBufferRemoveTail(buf.0, 3), 0);
        assert_eq!(buf.bytes(8), b"cde\0\0\0\0\0");
        assert_eq!(xmlSecBufferSetSize(buf.0, 1), 0);
        assert_eq!(buf.bytes(8), b"c\0\0\0\0\0\0\0");
        // Removing more than the contents empties the buffer.
        assert_eq!(xmlSecBufferRemoveHead(buf.0, 10), 0);
        assert_eq!(buf.size(), 0);
        buf.append(b"xy");
        assert_eq!(xmlSecBufferRemoveTail(buf.0, 10), 0);
        assert_eq!(buf.size(), 0);
    }
}

/// Setting the data replaces it; emptying zeroes it but keeps the
/// allocation, and finalizing releases it.
#[test]
fn set_empty_and_finalize() {
    let _defaults = defaults();
    let buf = Buffer::new(0);
    // SAFETY: the buffer is live and the slices readable.
    unsafe {
        assert_eq!(xmlSecBufferSetData(buf.0, b"one".as_ptr(), 3), 0);
        assert_eq!(xmlSecBufferSetData(buf.0, b"xy".as_ptr(), 2), 0);
        assert_eq!(buf.contents(), b"xy");
        assert_eq!(buf.bytes(3), b"xy\0");
        xmlSecBufferEmpty(buf.0);
        assert_eq!(buf.size(), 0);
        assert_eq!(buf.max_size(), 1024);
        xmlSecBufferFinalize(buf.0);
        assert_eq!((buf.size(), buf.max_size()), (0, 0));
        assert!(xmlSecBufferGetData(buf.0).is_null());
    }
}

/// A buffer the caller owns is initialized and finalized in place.
#[test]
fn caller_owned_buffer_initializes_in_place() {
    let _defaults = defaults();
    let mut storage = MaybeUninit::<XmlSecBuffer>::uninit();
    let buf = storage.as_mut_ptr();
    // SAFETY: `storage` is writable memory of a buffer's size.
    unsafe {
        assert_eq!(xmlSecBufferInitialize(buf, 5), 0);
        assert_eq!(xmlSecBufferGetMaxSize(buf), 1024);
        assert_eq!(xmlSecBufferAppend(buf, b"in place".as_ptr(), 8), 0);
        assert_eq!(xmlSecBufferGetSize(buf), 8);
        xmlSecBufferFinalize(buf);
        assert_eq!(xmlSecBufferGetMaxSize(buf), 0);
    }
}

/// Growing never shrinks the allocation; swap exchanges whole contents.
#[test]
fn max_size_and_swap() {
    let _defaults = defaults();
    let left = Buffer::new(0);
    let right = Buffer::new(0);
    left.append(b"left");
    right.append(b"right side");
    // SAFETY: both buffers are live.
    unsafe {
        assert_eq!(xmlSecBufferSetMaxSize(left.0, 10), 0);
        assert_eq!(left.max_size(), 1024);
        xmlSecBufferSwap(left.0, right.0);
    }
    assert_eq!(left.contents(), b"right side");
    assert_eq!(right.contents(), b"left");
}

/// Hex input of either case decodes; an odd length is refused, and a bad
/// digit fails after storing the bytes before it, as libxmlsec1 does.
#[test]
fn hex_read_decodes_and_refuses() {
    let buf = Buffer::new(0);
    // SAFETY: the buffer is live and the strings NUL-terminated.
    unsafe {
        assert_eq!(xmlSecBufferHexRead(buf.0, c"0aFf10".as_ptr().cast()), 0);
        assert_eq!(buf.contents(), [0x0a, 0xff, 0x10]);
        assert_eq!(xmlSecBufferHexRead(buf.0, c"abc".as_ptr().cast()), -1);
        assert_eq!(xmlSecBufferHexRead(buf.0, c"11zz".as_ptr().cast()), -1);
        // The size is already set and the first byte stored; the second
        // keeps the previous contents, which sizing does not clear.
        assert_eq!(buf.contents(), [0x11, 0xff]);
        assert_eq!(xmlSecBufferHexRead(buf.0, c"".as_ptr().cast()), 0);
        assert_eq!(buf.size(), 0);
    }
}

/// Bytes reverse in place; zero and one bytes are trivially reversed.
#[test]
fn reverse_in_place() {
    let buf = Buffer::new(0);
    // SAFETY: the buffer is live.
    unsafe {
        assert_eq!(xmlSecBufferReverse(buf.0), 0);
        buf.append(b"abc");
        assert_eq!(xmlSecBufferReverse(buf.0), 0);
    }
    assert_eq!(buf.contents(), b"cba");
}

/// Equality is a 1/0 answer over exactly `size` bytes; null pointers are an
/// error unless nothing is compared.
#[test]
fn mem_equal_answers() {
    // SAFETY: the slices are readable for the sizes given.
    unsafe {
        assert_eq!(xmlSecMemEqual(b"abc".as_ptr(), b"abc".as_ptr(), 3), 1);
        assert_eq!(xmlSecMemEqual(b"abc".as_ptr(), b"abd".as_ptr(), 3), 0);
        assert_eq!(xmlSecMemEqual(b"abc".as_ptr(), b"abd".as_ptr(), 2), 1);
        assert_eq!(xmlSecMemEqual(std::ptr::null(), std::ptr::null(), 0), 1);
        assert_eq!(xmlSecMemEqual(std::ptr::null(), b"a".as_ptr(), 1), -1);
    }
}

/// Every function refuses a null buffer with libxmlsec1's value instead of
/// dereferencing it.
#[test]
fn null_buffers_are_refused() {
    let null = std::ptr::null_mut();
    // SAFETY: every function accepts a null buffer.
    unsafe {
        assert_eq!(xmlSecBufferInitialize(null, 1), -1);
        assert_eq!(xmlSecBufferIsEmpty(null), 1);
        assert!(xmlSecBufferGetData(null).is_null());
        assert_eq!(xmlSecBufferGetSize(null), 0);
        assert_eq!(xmlSecBufferGetMaxSize(null), 0);
        assert_eq!(xmlSecBufferSetSize(null, 1), -1);
        assert_eq!(xmlSecBufferSetMaxSize(null, 1), -1);
        assert_eq!(xmlSecBufferSetData(null, b"a".as_ptr(), 1), -1);
        assert_eq!(xmlSecBufferAppend(null, b"a".as_ptr(), 1), -1);
        assert_eq!(xmlSecBufferPrepend(null, b"a".as_ptr(), 1), -1);
        assert_eq!(xmlSecBufferRemoveHead(null, 1), -1);
        assert_eq!(xmlSecBufferRemoveTail(null, 1), -1);
        assert_eq!(xmlSecBufferReverse(null), -1);
        assert_eq!(xmlSecBufferHexRead(null, c"00".as_ptr().cast()), -1);
        xmlSecBufferEmpty(null);
        xmlSecBufferFinalize(null);
        xmlSecBufferDestroy(null);
        xmlSecBufferSwap(null, null);
    }
}

/// An append whose total size overflows fails instead of wrapping around to
/// a small allocation.
#[test]
fn overflowing_sizes_are_refused() {
    let buf = Buffer::new(0);
    buf.append(b"x");
    // SAFETY: the buffer is live; the pointer is not read on refusal.
    unsafe {
        assert_eq!(xmlSecBufferAppend(buf.0, b"y".as_ptr(), usize::MAX), -1);
        assert_eq!(xmlSecBufferSetMaxSize(buf.0, usize::MAX), -1);
    }
    assert_eq!(buf.contents(), b"x");
}
