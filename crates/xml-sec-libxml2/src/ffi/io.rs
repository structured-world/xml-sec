//! I/O buffers: our own objects shaped like libxml2's `xmlOutputBuffer` and
//! `xmlParserInputBuffer`, as opaque handles.
//!
//! An output buffer writes through the caller's callbacks or into memory; an
//! input buffer reads through the caller's callbacks. Neither opens a file
//! or a URL: every byte comes from or goes to code the caller supplied. No
//! lock is held while a callback runs, so a callback may use other buffers.

use std::collections::HashMap;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::panic::AssertUnwindSafe;

use parking_lot::Mutex;

use super::tree::XmlChar;
use crate::handles;
use crate::nodes::{handle_of, pointer_of};

/// An `xmlOutputBuffer`: never dereferenced, a handle only.
pub enum OutputBuffer {}
/// An `xmlParserInputBuffer`: never dereferenced, a handle only.
pub enum InputBuffer {}

/// libxml2's `xmlOutputWriteCallback`.
pub type WriteCallback = unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int;
/// libxml2's `xmlInputReadCallback`.
pub type ReadCallback = unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> c_int;
/// libxml2's `xmlOutputCloseCallback` and `xmlInputCloseCallback`.
pub type CloseCallback = unsafe extern "C" fn(*mut c_void) -> c_int;

/// Where an output buffer's bytes go.
enum Sink {
    /// The caller's callbacks, with their context's address.
    Callbacks {
        write: Option<WriteCallback>,
        close: Option<CloseCallback>,
        context: usize,
    },
    /// Memory, kept NUL-terminated for [`xsOutputBufferGetContent`].
    Memory(Vec<u8>),
}

struct Output {
    sink: Sink,
    written: usize,
    failed: bool,
}

struct Input {
    read: Option<ReadCallback>,
    close: Option<CloseCallback>,
    context: usize,
    /// What reads returned so far, NUL-terminated.
    content: Vec<u8>,
    failed: bool,
}

static OUTPUTS: Mutex<Option<HashMap<usize, Output>>> = Mutex::new(None);
static INPUTS: Mutex<Option<HashMap<usize, Input>>> = Mutex::new(None);

fn outputs<R>(work: impl FnOnce(&mut HashMap<usize, Output>) -> R) -> R {
    work(OUTPUTS.lock().get_or_insert_with(HashMap::new))
}

fn inputs<R>(work: impl FnOnce(&mut HashMap<usize, Input>) -> R) -> R {
    work(INPUTS.lock().get_or_insert_with(HashMap::new))
}

fn contain<R>(fallback: R, work: impl FnOnce() -> R) -> R {
    std::panic::catch_unwind(AssertUnwindSafe(work)).unwrap_or(fallback)
}

fn register_output(sink: Sink) -> *mut OutputBuffer {
    let Ok(handle) = handles::fresh() else {
        return std::ptr::null_mut();
    };
    outputs(|outputs| {
        outputs.insert(
            handle,
            Output {
                sink,
                written: 0,
                failed: false,
            },
        )
    });
    pointer_of(handle)
}

/// A new output buffer writing through `write` with `context`, closed with
/// `close`.
#[must_use]
pub fn output_with_callbacks(
    write: Option<WriteCallback>,
    close: Option<CloseCallback>,
    context: *mut c_void,
) -> *mut OutputBuffer {
    register_output(Sink::Callbacks {
        write,
        close,
        context: context.expose_provenance(),
    })
}

/// A new output buffer collecting its bytes in memory.
#[must_use]
pub fn output_in_memory() -> *mut OutputBuffer {
    register_output(Sink::Memory(vec![0]))
}

/// Write `bytes` to `out`: the number written, or -1 when `out` is not live
/// or a write failed, after which every write fails.
///
/// # Safety
/// The callbacks `out` was created with are callable with its context.
pub unsafe fn output_write(out: *mut OutputBuffer, bytes: &[u8]) -> c_int {
    /// What a write does once the table is read.
    enum Step {
        Refused,
        Written,
        Call(Option<WriteCallback>, usize),
    }
    let Ok(length) = c_int::try_from(bytes.len()) else {
        return -1;
    };
    let handle = handle_of(out);
    let step = outputs(|outputs| match outputs.get_mut(&handle) {
        None => Step::Refused,
        Some(output) if output.failed => Step::Refused,
        Some(output) => match &mut output.sink {
            Sink::Memory(memory) => {
                memory.pop();
                memory.extend_from_slice(bytes);
                memory.push(0);
                output.written += bytes.len();
                Step::Written
            }
            Sink::Callbacks { write, context, .. } => Step::Call(*write, *context),
        },
    });
    let (write, context) = match step {
        Step::Refused | Step::Call(None, _) => return -1,
        Step::Written => return length,
        Step::Call(Some(write), context) => (write, context),
    };
    if bytes.is_empty() {
        return 0;
    }
    // SAFETY: the caller's callback with its context, given `length`
    // readable bytes.
    let result = unsafe {
        write(
            std::ptr::with_exposed_provenance_mut(context),
            bytes.as_ptr().cast(),
            length,
        )
    };
    outputs(|outputs| {
        if let Some(output) = outputs.get_mut(&handle) {
            if result < 0 {
                output.failed = true;
            } else {
                output.written += bytes.len();
            }
        }
    });
    if result < 0 { -1 } else { length }
}

/// Close `out`: its close callback runs and the buffer is gone. Returns the
/// number of bytes written, or -1 when a write or the close failed or `out`
/// is not live.
///
/// # Safety
/// As for [`output_write`].
pub unsafe fn output_close(out: *mut OutputBuffer) -> c_int {
    let Some(output) = outputs(|outputs| outputs.remove(&handle_of(out))) else {
        return -1;
    };
    let mut failed = output.failed;
    if let Sink::Callbacks {
        close: Some(close),
        context,
        ..
    } = output.sink
    {
        // SAFETY: the caller's callback with its context, called once.
        failed |= unsafe { close(std::ptr::with_exposed_provenance_mut(context)) } < 0;
    }
    if failed {
        -1
    } else {
        c_int::try_from(output.written).unwrap_or(c_int::MAX)
    }
}

/// `xmlOutputBufferCreateIO`: an output buffer over the caller's callbacks;
/// the encoder is accepted for the shape of the call, the bytes are written
/// as given.
///
/// # Safety
/// The callbacks are callable with `context` until the buffer is closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsOutputBufferCreateIO(
    write: Option<WriteCallback>,
    close: Option<CloseCallback>,
    context: *mut c_void,
    _encoder: *mut c_void,
) -> *mut OutputBuffer {
    contain(std::ptr::null_mut(), || {
        output_with_callbacks(write, close, context)
    })
}

/// `xmlAllocOutputBuffer`: an output buffer collecting its bytes in memory.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsAllocOutputBuffer(_encoder: *mut c_void) -> *mut OutputBuffer {
    contain(std::ptr::null_mut(), output_in_memory)
}

/// `xmlOutputBufferWrite`: write `len` bytes at `buf`; the number written or
/// -1.
///
/// # Safety
/// `buf` holds `len` bytes; the buffer's callbacks are callable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsOutputBufferWrite(
    out: *mut OutputBuffer,
    len: c_int,
    buf: *const c_char,
) -> c_int {
    contain(-1, || {
        let Ok(size) = usize::try_from(len) else {
            return -1;
        };
        if buf.is_null() {
            return -1;
        }
        // SAFETY: `buf` holds `len` bytes; the callbacks by the contract.
        unsafe { output_write(out, std::slice::from_raw_parts(buf.cast(), size)) }
    })
}

/// `xmlOutputBufferWriteString`: write the NUL-terminated `text`.
///
/// # Safety
/// `text` is NUL-terminated; the buffer's callbacks are callable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsOutputBufferWriteString(
    out: *mut OutputBuffer,
    text: *const c_char,
) -> c_int {
    contain(-1, || {
        if text.is_null() {
            return -1;
        }
        // SAFETY: NUL-terminated; the callbacks by the contract.
        unsafe { output_write(out, CStr::from_ptr(text).to_bytes()) }
    })
}

/// `xmlOutputBufferFlush`: every write already reached its callback, so
/// there is nothing to flush; 0, or -1 for a buffer that is not live.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsOutputBufferFlush(out: *mut OutputBuffer) -> c_int {
    contain(-1, || {
        if outputs(|outputs| outputs.contains_key(&handle_of(out))) {
            0
        } else {
            -1
        }
    })
}

/// `xmlOutputBufferClose`: close the buffer; the number of bytes written or
/// -1.
///
/// # Safety
/// The buffer's callbacks are callable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsOutputBufferClose(out: *mut OutputBuffer) -> c_int {
    // SAFETY: by the caller's contract.
    contain(-1, || unsafe { output_close(out) })
}

/// `xmlOutputBufferGetContent`: the bytes a memory buffer collected,
/// NUL-terminated, valid until the next write or close; null otherwise.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsOutputBufferGetContent(out: *mut OutputBuffer) -> *const XmlChar {
    contain(std::ptr::null(), || {
        outputs(|outputs| match outputs.get(&handle_of(out)) {
            Some(Output {
                sink: Sink::Memory(memory),
                ..
            }) => memory.as_ptr(),
            _ => std::ptr::null(),
        })
    })
}

/// `xmlOutputBufferGetSize`: the number of bytes a memory buffer collected;
/// 0 otherwise.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsOutputBufferGetSize(out: *mut OutputBuffer) -> usize {
    contain(0, || {
        outputs(|outputs| match outputs.get(&handle_of(out)) {
            Some(Output {
                sink: Sink::Memory(memory),
                ..
            }) => memory.len() - 1,
            _ => 0,
        })
    })
}

/// A new input buffer reading through `read` with `context`, closed with
/// `close`.
#[must_use]
pub fn input_with_callbacks(
    read: Option<ReadCallback>,
    close: Option<CloseCallback>,
    context: *mut c_void,
) -> *mut InputBuffer {
    let Ok(handle) = handles::fresh() else {
        return std::ptr::null_mut();
    };
    inputs(|inputs| {
        inputs.insert(
            handle,
            Input {
                read,
                close,
                context: context.expose_provenance(),
                content: vec![0],
                failed: false,
            },
        )
    });
    pointer_of(handle)
}

/// Read up to `len` more bytes into the buffer's content: the number read,
/// 0 at the end, -1 on failure or for a buffer that is not live.
///
/// # Safety
/// The callbacks `input` was created with are callable with its context.
pub unsafe fn input_read(input: *mut InputBuffer, len: usize) -> c_int {
    let handle = handle_of(input);
    let Some((Some(read), context)) = inputs(|inputs| {
        inputs
            .get(&handle)
            .filter(|input| !input.failed)
            .map(|input| (input.read, input.context))
    }) else {
        return -1;
    };
    let Ok(wanted) = c_int::try_from(len) else {
        return -1;
    };
    let mut chunk = vec![0_u8; len];
    // SAFETY: the caller's callback with its context and `len` writable
    // bytes.
    let got = unsafe {
        read(
            std::ptr::with_exposed_provenance_mut(context),
            chunk.as_mut_ptr().cast(),
            wanted,
        )
    };
    inputs(|inputs| {
        let Some(input) = inputs.get_mut(&handle) else {
            return -1;
        };
        match usize::try_from(got) {
            Ok(got) if got <= len => {
                input.content.pop();
                input.content.extend_from_slice(&chunk[..got]);
                input.content.push(0);
                // At most `len`, which fits an `int`.
                c_int::try_from(got).unwrap_or(-1)
            }
            _ => {
                input.failed = true;
                -1
            }
        }
    })
}

/// The bytes `input` read so far.
#[must_use]
pub fn input_content(input: *const InputBuffer) -> Option<Vec<u8>> {
    inputs(|inputs| {
        inputs.get(&handle_of(input)).map(|input| {
            let mut content = input.content.clone();
            content.pop();
            content
        })
    })
}

/// Free `input`, running its close callback.
///
/// # Safety
/// As for [`input_read`].
pub unsafe fn input_free(input: *mut InputBuffer) {
    let Some(input) = inputs(|inputs| inputs.remove(&handle_of(input))) else {
        return;
    };
    if let Some(close) = input.close {
        // SAFETY: the caller's callback with its context, called once. Like
        // libxml2's `xmlFreeParserInputBuffer`, the result is not reported.
        let _status: c_int = unsafe { close(std::ptr::with_exposed_provenance_mut(input.context)) };
    }
}

/// `xmlParserInputBufferCreateIO`: an input buffer over the caller's
/// callbacks; the encoding is accepted for the shape of the call.
///
/// # Safety
/// The callbacks are callable with `context` until the buffer is freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsParserInputBufferCreateIO(
    read: Option<ReadCallback>,
    close: Option<CloseCallback>,
    context: *mut c_void,
    _encoding: c_int,
) -> *mut InputBuffer {
    contain(std::ptr::null_mut(), || {
        input_with_callbacks(read, close, context)
    })
}

/// `xmlParserInputBufferRead`: read up to `len` more bytes into the buffer;
/// the number read, 0 at the end, or -1.
///
/// # Safety
/// The buffer's callbacks are callable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsParserInputBufferRead(input: *mut InputBuffer, len: c_int) -> c_int {
    contain(-1, || match usize::try_from(len) {
        // SAFETY: by the caller's contract.
        Ok(len) => unsafe { input_read(input, len) },
        Err(_) => -1,
    })
}

/// The bytes the input buffer read so far, NUL-terminated, valid until the
/// next read or free; libxml2 keeps them in the buffer's `buffer` member,
/// which a handle does not expose.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsParserInputBufferGetContent(input: *mut InputBuffer) -> *const XmlChar {
    contain(std::ptr::null(), || {
        inputs(|inputs| {
            inputs
                .get(&handle_of(input))
                .map_or(std::ptr::null(), |input| input.content.as_ptr())
        })
    })
}

/// The number of bytes the input buffer read so far.
///
/// # Safety
/// Callable with any pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsParserInputBufferGetSize(input: *mut InputBuffer) -> usize {
    contain(0, || {
        inputs(|inputs| {
            inputs
                .get(&handle_of(input))
                .map_or(0, |input| input.content.len() - 1)
        })
    })
}

/// `xmlFreeParserInputBuffer`: free the buffer, running its close callback.
///
/// # Safety
/// The buffer's callbacks are callable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsFreeParserInputBuffer(input: *mut InputBuffer) {
    // SAFETY: by the caller's contract.
    contain((), || unsafe { input_free(input) });
}
