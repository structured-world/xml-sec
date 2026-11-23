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

/// libxmlsec1's `xmlSecBase64IsValidColumns`: no line breaks (0) or lines of
/// at least two characters.
pub(crate) fn valid_columns(columns: c_int) -> bool {
    columns == 0 || columns > 1
}

impl XmlSecBase64Ctx {
    /// A context for `encode` with `columns` per line; `None` for a line
    /// size [`valid_columns`] refuses.
    fn new(encode: c_int, columns: c_int) -> Option<Self> {
        valid_columns(columns).then_some(())?;
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
            // libxmlsec1 reports no input offsets.
            input_offset: 0,
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

/// Initializes `ctx` for `encode` with `columns` per line; `None` for a line
/// size [`valid_columns`] refuses.
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

/// Finishes the stream; the bytes written, and a NUL after them when room
/// remains, as libxmlsec1 terminates its output.
pub(crate) fn finish(ctx: &mut XmlSecBase64Ctx, output: &mut [u8]) -> Result<usize, Base64Error> {
    let mut codec = ctx.codec();
    let result = codec.finish(output);
    ctx.store(&codec);
    let written = result?;
    if written < output.len() {
        output[written] = 0;
    }
    Ok(written)
}

/// Why libxmlsec1's decoder stops on `input` from a state.
enum DecodeStop {
    /// A byte, or the state itself, is refused with this report.
    Refused(String),
    /// The stream ended before the input did: the rest is left unread.
    Ended,
    /// No byte is refused.
    Nothing,
}

/// Where libxmlsec1's decoder stops when decoding `input` from the state
/// `before` fails: the state itself, misplaced padding or a byte that is not
/// Base64, or the end of the stream before the end of the input.
///
/// The codec finds the stopping byte itself: a copy of the state before the
/// call is fed the input one byte at a time until it refuses one.
fn decode_stop(before: Base64Codec, input: &[u8]) -> DecodeStop {
    let mut codec = before;
    // One input byte decodes to at most one output byte.
    let mut room = [0u8; 1];
    if codec.update(&[], &mut room).is_err() {
        return DecodeStop::Refused(format!(
            "invalid data for 'ctx->inPos': actual={} and expected 0,1,2,3",
            before.position
        ));
    }
    for &byte in input {
        // libxmlsec1 stops at the end of the stream without inspecting the
        // byte; trailing whitespace is read past.
        if codec.finished && codec.position == 0 {
            if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                continue;
            }
            return DecodeStop::Ended;
        }
        let position = codec.position;
        match codec.update(&[byte], &mut room) {
            Ok(_) => {}
            Err(Base64Error::InvalidByte(_, b'=')) => {
                return DecodeStop::Refused(format!(
                    "invalid data for 'ctx->inPos': actual={position} and expected 2,3"
                ));
            }
            Err(Base64Error::InvalidByte(..)) => {
                return DecodeStop::Refused(format!(
                    "invalid data for 'inByte': actual={byte} and expected base64 character"
                ));
            }
            Err(_) => return DecodeStop::Nothing,
        }
    }
    DecodeStop::Nothing
}

/// Reports a failed update from the state `before` over `input` as libxmlsec1
/// reports it at and below `xmlSecBase64CtxUpdate_ex` (`here`).
fn report_update_failure(
    here: errors::Here,
    before: Base64Codec,
    input: &[u8],
    error: Base64Error,
) {
    let too_small = || {
        errors::report(
            here,
            std::ptr::null(),
            std::ptr::null(),
            errors::R_INVALID_SIZE,
            "invalid size: output base64 buffer size is too small",
        );
    };
    if before.encode {
        // The encoder stops at a full output and leaves the rest unread.
        if error == Base64Error::OutputFull {
            too_small();
        } else {
            errors::internal(here, std::ptr::null(), c"xmlSecBase64CtxEncode");
        }
        return;
    }
    let decode = here!("xmlSecBase64CtxDecode");
    match error {
        Base64Error::OutputFull => {
            errors::report(
                decode,
                std::ptr::null(),
                std::ptr::null(),
                errors::R_INVALID_SIZE,
                "invalid size: output base64 buffer size is too small",
            );
        }
        _ => match decode_stop(before, input) {
            DecodeStop::Ended => {
                errors::report(
                    here,
                    std::ptr::null(),
                    std::ptr::null(),
                    errors::R_INVALID_SIZE,
                    "invalid size: input base64 buffer size is too large",
                );
                return;
            }
            DecodeStop::Refused(cause) => {
                errors::invalid_data(here!("xmlSecBase64CtxDecodeByte"), std::ptr::null(), &cause);
                // `xmlSecBase64StatusFailed`.
                errors::internal_with(
                    decode,
                    std::ptr::null(),
                    c"xmlSecBase64CtxDecodeByte",
                    "status=4",
                );
            }
            DecodeStop::Nothing => {}
        },
    }
    errors::internal(here, std::ptr::null(), c"xmlSecBase64CtxDecode");
}

/// Reports a failed finish with the reports libxmlsec1 makes for it: an
/// unfinished decoder group, or an encoder whose output does not fit.
fn report_final_failure(here: errors::Here, encode: bool, error: Base64Error, out_size: usize) {
    if !encode {
        errors::report(
            here,
            std::ptr::null(),
            std::ptr::null(),
            errors::R_INVALID_SIZE,
            "invalid size: Base64 data is incomplete",
        );
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
/// created from now on; a size [`valid_columns`] refuses is refused.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBase64SetDefaultLineSize(columns: c_int) {
    contain((), || {
        check!(
            valid_columns(columns),
            "xmlSecBase64SetDefaultLineSize",
            c"xmlSecBase64IsValidColumns(columns)",
        );
        LINE_SIZE.store(columns, Ordering::Relaxed);
    });
}

/// `xmlSecBase64CtxCreate`: a new context, released with
/// [`xmlSecBase64CtxDestroy`]; null for a line size [`valid_columns`]
/// refuses.
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
        check!(
            valid_columns(columns),
            "xmlSecBase64CtxInitialize",
            c"xmlSecBase64IsValidColumns(columns)",
            -1
        );
        // SAFETY: `ctx` is writable.
        unsafe { ctx.write(XmlSecBase64Ctx::empty()) };
        // SAFETY: as above; the line size is valid, so this cannot fail.
        if initialize(unsafe { &mut *ctx }, encode, columns).is_none() {
            return -1;
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
            !input.is_null() || in_size == 0,
            "xmlSecBase64CtxUpdate_ex",
            c"(in != NULL) || (inSize == 0)",
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
            if in_size == 0 {
                out_written.write(0);
                return 0;
            }
            let before = (*ctx).codec();
            let data = in_slice(input, in_size);
            match update(&mut *ctx, data, out_slice(out, out_size)) {
                Ok(written) => {
                    out_written.write(written);
                    0
                }
                Err(error) => {
                    report_update_failure(here!("xmlSecBase64CtxUpdate_ex"), before, data, error);
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
        check!(
            !out_written.is_null(),
            "xmlSecBase64CtxFinal_ex",
            c"outWritten != NULL",
            -1
        );
        // An encoder writes its pending group, so it needs room for it.
        // SAFETY: a non-null context by the caller's contract.
        let (encode, pending) = unsafe { ((*ctx).encode != 0, (*ctx).in_pos) };
        check!(
            !encode || pending == 0 || out_size > 0,
            "xmlSecBase64CtxFinal_ex",
            c"(ctx->inPos == 0) || (outSize > 0)",
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
            !input.is_null() || in_size == 0,
            "xmlSecBase64Encode",
            c"(in != NULL) || (inSize == 0)",
            std::ptr::null_mut()
        );
        let here = here!("xmlSecBase64Encode");
        let mut ctx = XmlSecBase64Ctx::empty();
        // SAFETY: `ctx` is a context on the stack.
        if unsafe { xmlSecBase64CtxInitialize(&raw mut ctx, 1, columns) } < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecBase64CtxInitialize");
            return std::ptr::null_mut();
        }
        let Some(size) = Base64Codec::encoded_capacity(ctx.columns, in_size) else {
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
        // first so that the slices do not alias. The text may encode a
        // secret key, so the copy is wiped on every path out.
        // SAFETY: `text` is NUL-terminated.
        let input = zeroize::Zeroizing::new(
            unsafe { CStr::from_ptr(text.cast::<c_char>()) }
                .to_bytes()
                .to_vec(),
        );
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
