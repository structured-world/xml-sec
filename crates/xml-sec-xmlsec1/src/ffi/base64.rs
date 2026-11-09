//! `xmlsec/base64.h`: libxmlsec1's streaming Base64 codec.
//!
//! The codec is a byte-at-a-time state machine with libxmlsec1's exact
//! rules: line breaks after `columns` output characters (none for 0), `=`
//! padding, whitespace skipped while decoding, and any character after the
//! padding refused. The Base64 transform keeps one context in the object
//! tail, so its layout matches libxmlsec1's and the klass reports the same
//! object size.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::atomic::{AtomicI32, Ordering};

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

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The outcome of one step of the state machine.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    /// The input byte is used and an output byte written.
    ConsumeAndNext,
    /// An output byte is written; the same input byte is offered again.
    ConsumeAndRepeat,
    /// The input byte is used without output.
    Next,
    /// Nothing remains.
    Done,
    Failed,
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// The 6-bit value of a Base64 character, `None` for any other byte.
fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(26 + byte - b'a'),
        b'0'..=b'9' => Some(52 + byte - b'0'),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The low byte of the carried value; libxmlsec1 stores a byte in an `int`.
fn carried(ctx: &XmlSecBase64Ctx) -> u8 {
    ctx.in_byte.to_le_bytes()[0]
}

fn encode_byte(ctx: &mut XmlSecBase64Ctx, input: u8, output: &mut u8) -> Status {
    if ctx.columns > 0 && ctx.line_pos >= ctx.columns {
        *output = b'\n';
        ctx.line_pos = 0;
        return Status::ConsumeAndRepeat;
    }
    let previous = carried(ctx);
    let (value, next) = match ctx.in_pos {
        0 => ((input >> 2) & 0x3f, Status::ConsumeAndNext),
        1 => (
            ((previous << 4) & 0x30) | ((input >> 4) & 0x0f),
            Status::ConsumeAndNext,
        ),
        2 => (
            ((previous << 2) & 0x3c) | ((input >> 6) & 0x03),
            Status::ConsumeAndRepeat,
        ),
        3 => (previous & 0x3f, Status::ConsumeAndNext),
        _ => return Status::Failed,
    };
    *output = ALPHABET[usize::from(value)];
    ctx.line_pos += 1;
    if ctx.in_pos == 3 {
        ctx.in_byte = 0;
        ctx.in_pos = 0;
    } else {
        ctx.in_byte = c_int::from(input);
        ctx.in_pos += 1;
    }
    next
}

fn encode_byte_final(ctx: &mut XmlSecBase64Ctx, output: &mut u8) -> Status {
    if ctx.in_pos == 0 {
        return Status::Done;
    }
    if ctx.columns > 0 && ctx.line_pos >= ctx.columns {
        *output = b'\n';
        ctx.line_pos = 0;
        return Status::ConsumeAndRepeat;
    }
    if ctx.finished == 0 {
        ctx.finished = 1;
        return encode_byte(ctx, 0, output);
    }
    match ctx.in_pos {
        1 | 2 => {
            *output = b'=';
            ctx.in_pos += 1;
            ctx.line_pos += 1;
            Status::ConsumeAndRepeat
        }
        3 => {
            *output = b'=';
            ctx.line_pos += 1;
            ctx.in_pos = 0;
            Status::ConsumeAndRepeat
        }
        _ => Status::Failed,
    }
}

fn decode_byte(ctx: &mut XmlSecBase64Ctx, input: u8, output: &mut u8) -> Status {
    if ctx.finished != 0 && ctx.in_pos == 0 {
        return Status::Done;
    }
    if input == b'=' {
        ctx.finished = 1;
        return match ctx.in_pos {
            2 => {
                ctx.in_pos += 1;
                Status::Next
            }
            3 => {
                ctx.in_pos = 0;
                Status::Next
            }
            _ => Status::Failed,
        };
    }
    if is_space(input) {
        return Status::Next;
    }
    let Some(value) = sextet(input).filter(|_| ctx.finished == 0) else {
        return Status::Failed;
    };
    let previous = carried(ctx);
    match ctx.in_pos {
        0 => {
            ctx.in_byte = c_int::from(value);
            ctx.in_pos += 1;
            Status::Next
        }
        1 => {
            *output = (previous << 2) | (value >> 4);
            ctx.in_byte = c_int::from(value);
            ctx.in_pos += 1;
            Status::ConsumeAndNext
        }
        2 => {
            *output = (previous << 4) | (value >> 2);
            ctx.in_byte = c_int::from(value);
            ctx.in_pos += 1;
            Status::ConsumeAndNext
        }
        3 => {
            *output = (previous << 6) | value;
            ctx.in_byte = 0;
            ctx.in_pos = 0;
            Status::ConsumeAndNext
        }
        _ => Status::Failed,
    }
}

/// Encodes `input` into `output`; the number of input bytes read and output
/// bytes written, or `None` on failure.
fn encode(ctx: &mut XmlSecBase64Ctx, input: &[u8], output: &mut [u8]) -> Option<(usize, usize)> {
    let (mut read, mut written) = (0, 0);
    while read < input.len() && written < output.len() {
        match encode_byte(ctx, input[read], &mut output[written]) {
            Status::ConsumeAndNext => {
                read += 1;
                written += 1;
            }
            Status::ConsumeAndRepeat => written += 1,
            Status::Next | Status::Done | Status::Failed => return None,
        }
    }
    Some((read, written))
}

/// Writes the final characters and padding; the bytes written, or `None`
/// when the output is too small or the state is invalid.
fn encode_final(ctx: &mut XmlSecBase64Ctx, output: &mut [u8]) -> Option<usize> {
    let mut written = 0;
    let mut status = Status::Next;
    while written < output.len() && status != Status::Done {
        status = encode_byte_final(ctx, &mut output[written]);
        match status {
            Status::ConsumeAndNext | Status::ConsumeAndRepeat => written += 1,
            Status::Done => {}
            Status::Next | Status::Failed => return None,
        }
    }
    if status != Status::Done {
        return None;
    }
    if written < output.len() {
        output[written] = 0;
    }
    Some(written)
}

/// Decodes `input` into `output`, then skips trailing whitespace; the input
/// bytes read and output bytes written, or `None` on failure.
fn decode(ctx: &mut XmlSecBase64Ctx, input: &[u8], output: &mut [u8]) -> Option<(usize, usize)> {
    let (mut read, mut written) = (0, 0);
    let mut status = Status::Next;
    while read < input.len() && written < output.len() && status != Status::Done {
        status = decode_byte(ctx, input[read], &mut output[written]);
        match status {
            Status::ConsumeAndNext => {
                read += 1;
                written += 1;
            }
            Status::ConsumeAndRepeat => written += 1,
            Status::Next => read += 1,
            Status::Done => {}
            Status::Failed => return None,
        }
    }
    while read < input.len() && is_space(input[read]) {
        read += 1;
    }
    Some((read, written))
}

/// The output size libxmlsec1 reserves to encode `size` bytes.
pub(crate) fn encode_size(columns: usize, size: usize) -> Option<usize> {
    let mut total = size.checked_mul(4)? / 3 + 4;
    if let Some(breaks) = total.checked_div(columns) {
        total = total.checked_add(breaks)?.checked_add(4)?;
    }
    total.checked_add(1)
}

/// The output size libxmlsec1 reserves to decode `size` characters.
pub(crate) fn decode_size(size: usize) -> Option<usize> {
    size.checked_mul(3).map(|bytes| bytes / 4 + 8)
}

/// Initializes `ctx` for `encode` with `columns` per line; `None` for a
/// negative line size.
pub(crate) fn initialize(ctx: &mut XmlSecBase64Ctx, encode: c_int, columns: c_int) -> Option<()> {
    *ctx = XmlSecBase64Ctx {
        encode,
        columns: usize::try_from(columns).ok()?,
        in_byte: 0,
        in_pos: 0,
        line_pos: 0,
        finished: 0,
    };
    Some(())
}

/// Encodes or decodes all of `input`; the bytes written, or `None` when the
/// input fails or does not fit.
pub(crate) fn update(ctx: &mut XmlSecBase64Ctx, input: &[u8], output: &mut [u8]) -> Option<usize> {
    let (read, written) = if ctx.encode != 0 {
        encode(ctx, input, output)?
    } else {
        decode(ctx, input, output)?
    };
    (read == input.len()).then_some(written)
}

/// Finishes the stream; the bytes written, or `None` when output does not
/// fit or decoding stopped inside a group. A NUL follows when room remains.
pub(crate) fn finish(ctx: &mut XmlSecBase64Ctx, output: &mut [u8]) -> Option<usize> {
    if output.is_empty() {
        return None;
    }
    let written = if ctx.encode != 0 {
        encode_final(ctx, output)?
    } else {
        if ctx.in_pos != 0 {
            return None;
        }
        0
    };
    if written + 1 < output.len() {
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
        let mut ctx = XmlSecBase64Ctx {
            encode: 1,
            columns: 0,
            in_byte: 0,
            in_pos: 0,
            line_pos: 0,
            finished: 0,
        };
        if initialize(&mut ctx, 1, columns).is_none() {
            return std::ptr::null_mut();
        }
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
        let mut ctx = XmlSecBase64Ctx {
            encode: 0,
            columns: 0,
            in_byte: 0,
            in_pos: 0,
            line_pos: 0,
            finished: 0,
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
