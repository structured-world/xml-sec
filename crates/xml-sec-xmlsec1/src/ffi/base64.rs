//! `xmlsec/base64.h`: libxmlsec1's streaming Base64 API over the shared
//! [`Base64Codec`] of `structured-base64`.
//!
//! The codec and its rules live in that crate; this module keeps
//! `xmlSecBase64Ctx` in libxmlsec1's layout (the Base64 transform holds one
//! in its object tail, so the klass reports the same object size), moves the
//! state between that structure and the codec around each call, and adds the
//! C conventions: failure values and the terminating NUL.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::atomic::{AtomicI32, Ordering};

use structured_base64::Base64Codec;

use super::{contain, free, malloc};

#[cfg(test)]
mod tests;

/// `XMLSEC_BASE64_LINESIZE`.
const DEFAULT_LINE_SIZE: c_int = 64;

/// The line size of Base64 transforms initialized from now on.
static LINE_SIZE: AtomicI32 = AtomicI32::new(DEFAULT_LINE_SIZE);

/// `xmlSecBase64Ctx`, in libxmlsec1's member order.
#[repr(C)]
pub(crate) struct XmlSecBase64Ctx {
    pub(crate) encode: c_int,
    pub(crate) columns: usize,
    in_byte: c_int,
    in_pos: usize,
    line_pos: usize,
    finished: c_int,
}

impl XmlSecBase64Ctx {
    /// A context for `encode` with `columns` per line; `None` for a
    /// negative line size.
    fn new(encode: c_int, columns: c_int) -> Option<Self> {
        Some(Self {
            encode,
            columns: usize::try_from(columns).ok()?,
            in_byte: 0,
            in_pos: 0,
            line_pos: 0,
            finished: 0,
        })
    }

    /// The codec in the state this context holds.
    fn codec(&self) -> Base64Codec {
        Base64Codec {
            encode: self.encode != 0,
            columns: self.columns,
            // libxmlsec1 keeps the carried byte in an `int`.
            carry: self.in_byte.to_le_bytes()[0],
            position: self.in_pos,
            line_position: self.line_pos,
            finished: self.finished != 0,
        }
    }

    /// Stores the codec's state back.
    fn store(&mut self, codec: &Base64Codec) {
        self.in_byte = c_int::from(codec.carry);
        self.in_pos = codec.position;
        self.line_pos = codec.line_position;
        self.finished = c_int::from(codec.finished);
    }
}

/// The output size libxmlsec1 reserves to encode `size` bytes.
pub(crate) fn encode_size(columns: usize, size: usize) -> Option<usize> {
    Base64Codec::encoded_capacity(columns, size)
}

/// The output size libxmlsec1 reserves to decode `size` characters.
pub(crate) fn decode_size(size: usize) -> Option<usize> {
    Base64Codec::decoded_capacity(size)
}

/// Initializes `ctx` for `encode` with `columns` per line; `None` for a
/// negative line size.
pub(crate) fn initialize(ctx: &mut XmlSecBase64Ctx, encode: c_int, columns: c_int) -> Option<()> {
    *ctx = XmlSecBase64Ctx::new(encode, columns)?;
    Some(())
}

/// Encodes or decodes all of `input`; the bytes written, or `None` when the
/// input fails or does not fit.
pub(crate) fn update(ctx: &mut XmlSecBase64Ctx, input: &[u8], output: &mut [u8]) -> Option<usize> {
    let mut codec = ctx.codec();
    let result = codec.update(input, output);
    ctx.store(&codec);
    result.ok()
}

/// Finishes the stream; the bytes written, or `None` when output does not
/// fit or decoding stopped inside a group. As libxmlsec1 does, a NUL follows
/// the encoded characters when room remains, and the decoder writes one when
/// more than one byte of room remains.
pub(crate) fn finish(ctx: &mut XmlSecBase64Ctx, output: &mut [u8]) -> Option<usize> {
    let mut codec = ctx.codec();
    let result = codec.finish(output);
    ctx.store(&codec);
    let written = result.ok()?;
    let room = if codec.encode { written } else { written + 1 };
    if room < output.len() {
        output[written] = 0;
    }
    Some(written)
}

/// A mutable byte slice over a C buffer; empty for a zero size.
///
/// # Safety
/// `data` is writable for `size` bytes, or `size` is 0.
unsafe fn out_slice<'a>(data: *mut u8, size: usize) -> &'a mut [u8] {
    if size == 0 {
        return &mut [];
    }
    // SAFETY: by the caller's contract.
    unsafe { std::slice::from_raw_parts_mut(data, size) }
}

/// A byte slice over a C buffer; empty for a zero size.
///
/// # Safety
/// `data` is readable for `size` bytes, or `size` is 0.
unsafe fn in_slice<'a>(data: *const u8, size: usize) -> &'a [u8] {
    if size == 0 {
        return &[];
    }
    // SAFETY: by the caller's contract.
    unsafe { std::slice::from_raw_parts(data, size) }
}

/// `xmlSecBase64GetDefaultLineSize`.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64GetDefaultLineSize() -> c_int {
    LINE_SIZE.load(Ordering::Relaxed)
}

/// `xmlSecBase64SetDefaultLineSize`: the line size of Base64 transforms
/// created from now on.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64SetDefaultLineSize(columns: c_int) {
    LINE_SIZE.store(columns, Ordering::Relaxed);
}

/// `xmlSecBase64CtxCreate`: a new context, released with
/// [`xmlSecBase64CtxDestroy`]; null for a negative line size.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64CtxCreate(
    encode: c_int,
    columns: c_int,
) -> *mut XmlSecBase64Ctx {
    contain(std::ptr::null_mut(), || {
        let ctx = malloc(size_of::<XmlSecBase64Ctx>()).cast::<XmlSecBase64Ctx>();
        if ctx.is_null() {
            return ctx;
        }
        // SAFETY: `ctx` is a fresh allocation of a context's size.
        if unsafe { xmlSecBase64CtxInitialize(ctx, encode, columns) } < 0 {
            // SAFETY: the allocation is ours.
            unsafe { free(ctx.cast::<c_void>()) };
            return std::ptr::null_mut();
        }
        ctx
    })
}

/// `xmlSecBase64CtxDestroy`.
///
/// # Safety
/// `ctx` is null or came from [`xmlSecBase64CtxCreate`] and was not
/// destroyed.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64CtxDestroy(ctx: *mut XmlSecBase64Ctx) {
    contain((), || {
        if ctx.is_null() {
            return;
        }
        // SAFETY: a live created context, finalized then freed.
        unsafe {
            xmlSecBase64CtxFinalize(ctx);
            free(ctx.cast::<c_void>());
        }
    });
}

/// `xmlSecBase64CtxInitialize`.
///
/// # Safety
/// `ctx` is null or writable memory of a context's size.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64CtxInitialize(
    ctx: *mut XmlSecBase64Ctx,
    encode: c_int,
    columns: c_int,
) -> c_int {
    contain(-1, || {
        if ctx.is_null() {
            return -1;
        }
        // SAFETY: `ctx` is writable; it is zeroed before any field is read.
        unsafe {
            ctx.write_bytes(0, 1);
            match initialize(&mut *ctx, encode, columns) {
                Some(()) => 0,
                None => -1,
            }
        }
    })
}

/// `xmlSecBase64CtxFinalize`: zeroes the context.
///
/// # Safety
/// `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64CtxFinalize(ctx: *mut XmlSecBase64Ctx) {
    if !ctx.is_null() {
        // SAFETY: `ctx` is a writable context.
        unsafe { ctx.write_bytes(0, 1) };
    }
}

/// `xmlSecBase64CtxUpdate_ex`: processes all of `input`, writing at most
/// `out_size` bytes.
///
/// # Safety
/// `ctx` is null or a context; `input` is null or readable for `in_size`
/// bytes; `out` is null or writable for `out_size` bytes; `out_written` is
/// null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64CtxUpdate_ex(
    ctx: *mut XmlSecBase64Ctx,
    input: *const u8,
    in_size: usize,
    out: *mut u8,
    out_size: usize,
    out_written: *mut usize,
) -> c_int {
    contain(-1, || {
        if ctx.is_null() || input.is_null() || out.is_null() || out_written.is_null() {
            return -1;
        }
        // SAFETY: by the caller's contract.
        unsafe {
            match update(
                &mut *ctx,
                in_slice(input, in_size),
                out_slice(out, out_size),
            ) {
                Some(written) => {
                    out_written.write(written);
                    0
                }
                None => -1,
            }
        }
    })
}

/// `xmlSecBase64CtxFinal_ex`: finishes the stream.
///
/// # Safety
/// As for [`xmlSecBase64CtxUpdate_ex`], without input.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64CtxFinal_ex(
    ctx: *mut XmlSecBase64Ctx,
    out: *mut u8,
    out_size: usize,
    out_written: *mut usize,
) -> c_int {
    contain(-1, || {
        if ctx.is_null() || out.is_null() || out_size == 0 || out_written.is_null() {
            return -1;
        }
        // SAFETY: by the caller's contract.
        unsafe {
            match finish(&mut *ctx, out_slice(out, out_size)) {
                Some(written) => {
                    out_written.write(written);
                    0
                }
                None => -1,
            }
        }
    })
}

/// `xmlSecBase64Encode`: `in_size` bytes as a NUL-terminated Base64 string
/// with `columns` characters per line (0 for none), released with `xmlFree`.
///
/// # Safety
/// `input` is null or readable for `in_size` bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64Encode(
    input: *const u8,
    in_size: usize,
    columns: c_int,
) -> *mut u8 {
    contain(std::ptr::null_mut(), || {
        if input.is_null() {
            return std::ptr::null_mut();
        }
        let Some(mut ctx) = XmlSecBase64Ctx::new(1, columns) else {
            return std::ptr::null_mut();
        };
        let Some(size) = encode_size(ctx.columns, in_size) else {
            return std::ptr::null_mut();
        };
        let result = malloc(size).cast::<u8>();
        if result.is_null() {
            return result;
        }
        // SAFETY: `result` holds `size` bytes; `input` is readable.
        let output = unsafe { out_slice(result, size) };
        // SAFETY: as above.
        let encoded = update(&mut ctx, unsafe { in_slice(input, in_size) }, output)
            .and_then(|written| Some((written, finish(&mut ctx, &mut output[written..])?)));
        let Some((written, last)) = encoded else {
            // SAFETY: the allocation is ours.
            unsafe { free(result.cast::<c_void>()) };
            return std::ptr::null_mut();
        };
        output[written + last] = 0;
        result
    })
}

/// `xmlSecBase64Decode_ex`: decodes the NUL-terminated string `text` into
/// at most `out_size` bytes.
///
/// # Safety
/// `text` is null or NUL-terminated; `out` is null or writable for
/// `out_size` bytes (it may be `text` itself, as for in-place decoding);
/// `out_written` is null or writable.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64Decode_ex(
    text: *const u8,
    out: *mut u8,
    out_size: usize,
    out_written: *mut usize,
) -> c_int {
    contain(-1, || {
        if text.is_null() || out.is_null() || out_written.is_null() {
            return -1;
        }
        // Decoding never writes ahead of reading (three bytes out per four
        // characters in), so `out` may alias `text`. The input is copied
        // first so that the slices do not alias.
        // SAFETY: `text` is NUL-terminated.
        let input = unsafe { CStr::from_ptr(text.cast::<c_char>()) }
            .to_bytes()
            .to_vec();
        let Some(mut ctx) = XmlSecBase64Ctx::new(0, 0) else {
            return -1;
        };
        // SAFETY: `out` is writable for `out_size` bytes.
        let output = unsafe { out_slice(out, out_size) };
        let Some(written) = update(&mut ctx, &input, output) else {
            return -1;
        };
        let Some(last) = finish(&mut ctx, &mut output[written..]) else {
            return -1;
        };
        // SAFETY: `out_written` is writable.
        unsafe { out_written.write(written + last) };
        0
    })
}

/// `xmlSecBase64DecodeInPlace`: decodes the string into its own storage.
///
/// # Safety
/// `text` is null or a writable NUL-terminated string.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64DecodeInPlace(
    text: *mut u8,
    out_written: *mut usize,
) -> c_int {
    contain(-1, || {
        if text.is_null() {
            return -1;
        }
        // SAFETY: the string is NUL-terminated and writable through its NUL.
        unsafe {
            let size = CStr::from_ptr(text.cast::<c_char>()).to_bytes().len() + 1;
            xmlSecBase64Decode_ex(text, text, size, out_written)
        }
    })
}
