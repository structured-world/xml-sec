//! libxml2 I/O buffers over transforms and buffers: writing pushes binary
//! data into a transform (or appends it to a buffer), reading pops it.

use std::ffi::{c_char, c_int, c_void};

use super::super::buffer::{XmlSecBuffer, xmlSecBufferAppend};
use super::super::{contain, free, malloc};
use super::{
    DATA_BIN, MODE_POP, MODE_PUSH, XmlSecTransform, XmlSecTransformCtx, valid,
    xmlSecTransformDefaultGetDataType, xmlSecTransformPopBin, xmlSecTransformPushBin,
};

type WriteCallback = unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int;
type ReadCallback = unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> c_int;
type CloseCallback = unsafe extern "C" fn(*mut c_void) -> c_int;

unsafe extern "C" {
    fn xmlOutputBufferCreateIO(
        write: Option<WriteCallback>,
        close: Option<CloseCallback>,
        context: *mut c_void,
        encoder: *mut c_void,
    ) -> *mut c_void;
    fn xmlParserInputBufferCreateIO(
        read: Option<ReadCallback>,
        close: Option<CloseCallback>,
        context: *mut c_void,
        encoding: c_int,
    ) -> *mut c_void;
    pub(crate) fn xmlOutputBufferWrite(out: *mut c_void, len: c_int, data: *const c_char) -> c_int;
    pub(crate) fn xmlOutputBufferClose(out: *mut c_void) -> c_int;
}

/// `XML_CHAR_ENCODING_NONE`.
const ENCODING_NONE: c_int = 0;

/// What an I/O buffer over a transform reads from or writes to.
#[repr(C)]
struct TransformIo {
    write: bool,
    transform: *mut XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
}

/// The transform I/O state for a callback.
///
/// # Safety
/// `context` is null or a live [`TransformIo`].
unsafe fn state<'a>(context: *mut c_void) -> Option<&'a TransformIo> {
    // SAFETY: by the caller's contract.
    unsafe { context.cast::<TransformIo>().as_ref() }.filter(|io| {
        // SAFETY: the state names a transform it was created for.
        unsafe { valid(io.transform) }.is_some() && !io.ctx.is_null()
    })
}

unsafe extern "C" fn transform_write(
    context: *mut c_void,
    data: *const c_char,
    len: c_int,
) -> c_int {
    // SAFETY: libxml2 passes the state it was created with and `len`
    // readable bytes at `data`.
    unsafe {
        let Some(io) = state(context).filter(|io| io.write) else {
            return -1;
        };
        let Ok(size) = usize::try_from(len) else {
            return -1;
        };
        if data.is_null() || xmlSecTransformPushBin(io.transform, data.cast(), size, 0, io.ctx) < 0
        {
            return -1;
        }
    }
    len
}

unsafe extern "C" fn transform_read(context: *mut c_void, data: *mut c_char, len: c_int) -> c_int {
    // SAFETY: libxml2 passes the state it was created with and `len`
    // writable bytes at `data`.
    unsafe {
        let Some(io) = state(context).filter(|io| !io.write) else {
            return -1;
        };
        let Ok(mut size) = usize::try_from(len) else {
            return -1;
        };
        if data.is_null()
            || xmlSecTransformPopBin(io.transform, data.cast(), size, &raw mut size, io.ctx) < 0
        {
            return -1;
        }
        c_int::try_from(size).unwrap_or(-1)
    }
}

unsafe extern "C" fn transform_close(context: *mut c_void) -> c_int {
    // SAFETY: libxml2 passes the state it was created with, closing it once.
    unsafe {
        let Some(io) = state(context) else {
            return -1;
        };
        // Writing ends with the final push that flushes the chain.
        let result = if io.write
            && xmlSecTransformPushBin(io.transform, std::ptr::null(), 0, 1, io.ctx) < 0
        {
            -1
        } else {
            0
        };
        free(context);
        result
    }
}

/// A new I/O state for `transform`.
fn create(
    write: bool,
    transform: *mut XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
) -> *mut c_void {
    let io = malloc(size_of::<TransformIo>()).cast::<TransformIo>();
    if !io.is_null() {
        // SAFETY: a fresh allocation of the state's size.
        unsafe {
            io.write(TransformIo {
                write,
                transform,
                ctx,
            });
        }
    }
    io.cast()
}

/// `xmlSecTransformCreateOutputBuffer`: a libxml2 output buffer whose writes
/// push binary data into `transform`; closing it pushes the final call.
///
/// # Safety
/// `transform` is null or a valid transform; `ctx` is null or a context;
/// both outlive the buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCreateOutputBuffer(
    transform: *mut XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
) -> *mut c_void {
    contain(std::ptr::null_mut(), || {
        // SAFETY: by the caller's contract.
        unsafe {
            if valid(transform).is_none() || ctx.is_null() {
                return std::ptr::null_mut();
            }
            if xmlSecTransformDefaultGetDataType(transform, MODE_PUSH, ctx) & DATA_BIN == 0 {
                return std::ptr::null_mut();
            }
            let io = create(true, transform, ctx);
            if io.is_null() {
                return io;
            }
            let output = xmlOutputBufferCreateIO(
                Some(transform_write),
                Some(transform_close),
                io,
                std::ptr::null_mut(),
            );
            if output.is_null() {
                free(io);
            }
            output
        }
    })
}

/// `xmlSecTransformCreateInputBuffer`: a libxml2 input buffer whose reads pop
/// binary data from `transform`.
///
/// # Safety
/// As for [`xmlSecTransformCreateOutputBuffer`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformCreateInputBuffer(
    transform: *mut XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
) -> *mut c_void {
    contain(std::ptr::null_mut(), || {
        // SAFETY: by the caller's contract.
        unsafe {
            if valid(transform).is_none() || ctx.is_null() {
                return std::ptr::null_mut();
            }
            if xmlSecTransformDefaultGetDataType(transform, MODE_POP, ctx) & DATA_BIN == 0 {
                return std::ptr::null_mut();
            }
            let io = create(false, transform, ctx);
            if io.is_null() {
                return io;
            }
            let input = xmlParserInputBufferCreateIO(
                Some(transform_read),
                Some(transform_close),
                io,
                ENCODING_NONE,
            );
            if input.is_null() {
                free(io);
            }
            input
        }
    })
}

unsafe extern "C" fn buffer_write(context: *mut c_void, data: *const c_char, len: c_int) -> c_int {
    let Ok(size) = usize::try_from(len) else {
        return -1;
    };
    if context.is_null() || data.is_null() {
        return -1;
    }
    // SAFETY: libxml2 passes the buffer it was created with and `len`
    // readable bytes at `data`.
    if unsafe { xmlSecBufferAppend(context.cast(), data.cast(), size) } < 0 {
        return -1;
    }
    len
}

unsafe extern "C" fn buffer_close(context: *mut c_void) -> c_int {
    if context.is_null() { -1 } else { 0 }
}

/// `xmlSecBufferCreateOutputBuffer`: a libxml2 output buffer appending to
/// `buf`, which the caller keeps owning.
///
/// # Safety
/// `buf` is null or a valid buffer that outlives the output buffer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecBufferCreateOutputBuffer(
    buf: *mut XmlSecBuffer,
) -> *mut c_void {
    contain(std::ptr::null_mut(), || {
        // SAFETY: libxml2 keeps `buf` as the callbacks' context only.
        unsafe {
            xmlOutputBufferCreateIO(
                Some(buffer_write),
                Some(buffer_close),
                buf.cast(),
                std::ptr::null_mut(),
            )
        }
    })
}
