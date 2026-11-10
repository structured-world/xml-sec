//! `xmlsec/base64.h`: libxmlsec1's streaming Base64 API over the shared
//! [`Base64Codec`] of `structured-base64`.
//!
//! The codec and its rules live in that crate; this module keeps
//! `xmlSecBase64Ctx` in libxmlsec1's layout (the Base64 transform holds one
//! in its object tail, so the klass reports the same object size), moves the
//! state between that structure and the codec around each call, and adds the
//! C conventions: failure values, error reports and the terminating NUL. The
//! one-shot functions run through the streaming entry points, as libxmlsec1's
//! do, so a failure reports the same chain.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::atomic::{AtomicI32, Ordering};

use structured_base64::{Base64Codec, Base64Error};

use super::errors::{self, check, here};
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

    /// An empty decoder, the state `xmlSecBase64CtxInitialize` writes first.
    const fn empty() -> Self {
        Self {
            encode: 0,
            columns: 0,
            in_byte: 0,
            in_pos: 0,
            line_pos: 0,
            finished: 0,
        }
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

/// Encodes or decodes all of `input`; the bytes written.
pub(crate) fn update(
    ctx: &mut XmlSecBase64Ctx,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, Base64Error> {
    let mut codec = ctx.codec();
    let result = codec.update(input, output);
    ctx.store(&codec);
    result
}

/// Finishes the stream; the bytes written. As libxmlsec1 does, a NUL follows
/// the encoded characters when room remains, and the decoder writes one when
/// more than one byte of room remains.
pub(crate) fn finish(ctx: &mut XmlSecBase64Ctx, output: &mut [u8]) -> Result<usize, Base64Error> {
    let mut codec = ctx.codec();
    let result = codec.finish(output);
    ctx.store(&codec);
    let written = result?;
    let room = if codec.encode { written } else { written + 1 };
    if room < output.len() {
        output[written] = 0;
    }
    Ok(written)
}

/// The byte-level cause libxmlsec1's decoder reports when decoding `input`
/// from the state `before` fails: the state itself, misplaced padding, or a
/// byte that is not Base64. `None` when it reports none: the stream had
/// already ended, or the output filled up.
///
/// The codec finds the failing byte itself: a copy of the state before the
/// call is fed the input one byte at a time until it refuses one.
fn decode_cause(before: Base64Codec, input: &[u8]) -> Option<String> {
    let mut codec = before;
    // One input byte decodes to at most one output byte.
    let mut room = [0u8; 1];
    if codec.update(&[], &mut room).is_err() {
        return Some(format!(
            "invalid data for 'ctx->inPos': actual={} and expected 0,1,2,3",
            before.position
        ));
    }
    for &byte in input {
        // libxmlsec1 stops at the end of the stream without inspecting the
        // byte and reports only that input was left over.
        if codec.finished && codec.position == 0 {
            return None;
        }
        let position = codec.position;
        match codec.update(&[byte], &mut room) {
            Ok(_) => {}
            Err(Base64Error::Invalid) if byte == b'=' => {
                return Some(format!(
                    "invalid data for 'ctx->inPos': actual={position} and expected 2,3"
                ));
            }
            Err(Base64Error::Invalid) => {
                return Some(format!(
                    "invalid data for 'inByte': actual={byte} and expected base64 character"
                ));
            }
            Err(_) => return None,
        }
    }
    None
}

/// Reports a failed update from the state `before` over `input` with the
/// reports libxmlsec1's codec makes below `xmlSecBase64CtxUpdate_ex`: for a
/// byte the decoder refuses, the byte's cause and the failed decoding step.
fn report_update_failure(before: Base64Codec, input: &[u8], error: Base64Error) {
    if before.encode || error != Base64Error::Invalid {
        return;
    }
    if let Some(cause) = decode_cause(before, input) {
        errors::invalid_data(here!("xmlSecBase64CtxDecodeByte"), std::ptr::null(), &cause);
        // `xmlSecBase64StatusFailed`.
        errors::internal_with(
            here!("xmlSecBase64CtxDecode"),
            std::ptr::null(),
            c"xmlSecBase64CtxDecodeByte",
            "status=4",
        );
    }
}

/// Reports a failed finish with the reports libxmlsec1 makes for it: an
/// unfinished decoder group, or an encoder whose output does not fit.
fn report_final_failure(here: errors::Here, encode: bool, error: Base64Error, out_size: usize) {
    if !encode {
        errors::internal(here, std::ptr::null(), c"xmlSecBase64CtxDecodeIsFinished");
        return;
    }
    let encode_final = here!("xmlSecBase64CtxEncodeFinal");
    if error == Base64Error::Invalid {
        errors::invalid_data(
            encode_final,
            std::ptr::null(),
            "invalid data for 'ctx->inPos': expected 0,1,2,3",
        );
    } else {
        errors::report(
            encode_final,
            std::ptr::null(),
            std::ptr::null(),
            errors::R_INVALID_SIZE,
            "invalid size: invalid base64 buffer size",
        );
    }
    errors::internal_with(
        here,
        std::ptr::null(),
        c"xmlSecBase64CtxEncodeFinal",
        &format!("outSize={out_size}"),
    );
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
            errors::malloc_failed(
                here!("xmlSecBase64CtxCreate"),
                std::ptr::null(),
                size_of::<XmlSecBase64Ctx>(),
            );
            return ctx;
        }
        // SAFETY: `ctx` is a fresh allocation of a context's size.
        if unsafe { xmlSecBase64CtxInitialize(ctx, encode, columns) } < 0 {
            errors::internal(
                here!("xmlSecBase64CtxCreate"),
                std::ptr::null(),
                c"xmlSecBase64CtxInitialize",
            );
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
        check!(!ctx.is_null(), "xmlSecBase64CtxDestroy", c"ctx != NULL");
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
        check!(
            !ctx.is_null(),
            "xmlSecBase64CtxInitialize",
            c"ctx != NULL",
            -1
        );
        // SAFETY: `ctx` is writable; it is zeroed before any field is read.
        unsafe {
            ctx.write(XmlSecBase64Ctx::empty());
            (*ctx).encode = encode;
            if initialize(&mut *ctx, encode, columns).is_none() {
                errors::int_to_size_impossible(here!("xmlSecBase64CtxInitialize"), columns);
                return -1;
            }
        }
        0
    })
}

/// `xmlSecBase64CtxFinalize`: zeroes the context.
///
/// # Safety
/// `ctx` is null or a context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64CtxFinalize(ctx: *mut XmlSecBase64Ctx) {
    contain((), || {
        check!(!ctx.is_null(), "xmlSecBase64CtxFinalize", c"ctx != NULL");
        // SAFETY: `ctx` is a writable context.
        unsafe { ctx.write(XmlSecBase64Ctx::empty()) };
    });
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
        check!(
            !ctx.is_null(),
            "xmlSecBase64CtxUpdate_ex",
            c"ctx != NULL",
            -1
        );
        check!(
            !input.is_null(),
            "xmlSecBase64CtxUpdate_ex",
            c"in != NULL",
            -1
        );
        check!(
            !out.is_null(),
            "xmlSecBase64CtxUpdate_ex",
            c"out != NULL",
            -1
        );
        check!(
            !out_written.is_null(),
            "xmlSecBase64CtxUpdate_ex",
            c"outWritten != NULL",
            -1
        );
        // SAFETY: by the caller's contract.
        unsafe {
            let before = (*ctx).codec();
            let encode = before.encode;
            let data = in_slice(input, in_size);
            match update(&mut *ctx, data, out_slice(out, out_size)) {
                Ok(written) => {
                    out_written.write(written);
                    0
                }
                Err(error) => {
                    let here = here!("xmlSecBase64CtxUpdate_ex");
                    report_update_failure(before, data, error);
                    let failed = if encode {
                        c"xmlSecBase64CtxEncode"
                    } else {
                        c"xmlSecBase64CtxDecode"
                    };
                    errors::internal(here, std::ptr::null(), failed);
                    -1
                }
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
        check!(
            !ctx.is_null(),
            "xmlSecBase64CtxFinal_ex",
            c"ctx != NULL",
            -1
        );
        check!(
            !out.is_null(),
            "xmlSecBase64CtxFinal_ex",
            c"out != NULL",
            -1
        );
        check!(out_size > 0, "xmlSecBase64CtxFinal_ex", c"outSize > 0", -1);
        check!(
            !out_written.is_null(),
            "xmlSecBase64CtxFinal_ex",
            c"outWritten != NULL",
            -1
        );
        // SAFETY: by the caller's contract.
        unsafe {
            match finish(&mut *ctx, out_slice(out, out_size)) {
                Ok(written) => {
                    out_written.write(written);
                    0
                }
                Err(error) => {
                    let here = here!("xmlSecBase64CtxFinal_ex");
                    report_final_failure(here, (*ctx).encode != 0, error, out_size);
                    -1
                }
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
        check!(
            !input.is_null(),
            "xmlSecBase64Encode",
            c"in != NULL",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecBase64Encode");
        let mut ctx = XmlSecBase64Ctx::empty();
        // SAFETY: `ctx` is a context on the stack.
        if unsafe { xmlSecBase64CtxInitialize(&raw mut ctx, 1, columns) } < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecBase64CtxInitialize");
            return std::ptr::null_mut();
        }
        let Some(size) = encode_size(ctx.columns, in_size) else {
            errors::internal(here, std::ptr::null(), c"xmlSecBase64GetEncodeSize");
            return std::ptr::null_mut();
        };
        let result = malloc(size).cast::<u8>();
        if result.is_null() {
            errors::malloc_failed(here, std::ptr::null(), size);
            return result;
        }
        let (mut written, mut last) = (0, 0);
        // SAFETY: `result` holds `size` bytes; `input` is readable for
        // `in_size` bytes.
        unsafe {
            if xmlSecBase64CtxUpdate_ex(
                &raw mut ctx,
                input,
                in_size,
                result,
                size,
                &raw mut written,
            ) < 0
            {
                errors::internal_with(
                    here,
                    std::ptr::null(),
                    c"xmlSecBase64CtxUpdate_ex",
                    &format!("inSize={in_size}; outSize={size}"),
                );
            } else if xmlSecBase64CtxFinal_ex(
                &raw mut ctx,
                result.add(written),
                size - written,
                &raw mut last,
            ) < 0
            {
                errors::internal(here, std::ptr::null(), c"xmlSecBase64CtxFinal_ex");
            } else {
                result.add(written + last).write(0);
                return result;
            }
            free(result.cast::<c_void>());
        }
        std::ptr::null_mut()
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
        check!(!text.is_null(), "xmlSecBase64Decode_ex", c"str != NULL", -1);
        check!(!out.is_null(), "xmlSecBase64Decode_ex", c"out != NULL", -1);
        check!(
            !out_written.is_null(),
            "xmlSecBase64Decode_ex",
            c"outWritten != NULL",
            -1
        );
        let here = here!("xmlSecBase64Decode_ex");
        // Decoding never writes ahead of reading (three bytes out per four
        // characters in), so `out` may alias `text`. The input is copied
        // first so that the slices do not alias.
        // SAFETY: `text` is NUL-terminated.
        let input = unsafe { CStr::from_ptr(text.cast::<c_char>()) }
            .to_bytes()
            .to_vec();
        let mut ctx = XmlSecBase64Ctx::empty();
        let (mut written, mut last) = (0, 0);
        // SAFETY: `ctx` is on the stack; `out` is writable for `out_size`
        // bytes and the input is our copy.
        unsafe {
            if xmlSecBase64CtxUpdate_ex(
                &raw mut ctx,
                input.as_ptr(),
                input.len(),
                out,
                out_size,
                &raw mut written,
            ) < 0
            {
                errors::internal(here, std::ptr::null(), c"xmlSecBase64CtxUpdate_ex");
                return -1;
            }
            if xmlSecBase64CtxFinal_ex(
                &raw mut ctx,
                out.add(written),
                out_size - written,
                &raw mut last,
            ) < 0
            {
                errors::internal(here, std::ptr::null(), c"xmlSecBase64CtxFinal_ex");
                return -1;
            }
            out_written.write(written + last);
        }
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
        check!(
            !text.is_null(),
            "xmlSecBase64DecodeInPlace",
            c"str != NULL",
            -1
        );
        // SAFETY: the string is NUL-terminated and writable through its NUL.
        unsafe {
            let size = CStr::from_ptr(text.cast::<c_char>()).to_bytes().len() + 1;
            xmlSecBase64Decode_ex(text, text, size, out_written)
        }
    })
}
