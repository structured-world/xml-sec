//! `xmlsec/io.h` and the libxml2 I/O buffers over transforms and buffers.
//!
//! The process-global list of input callbacks keeps libxmlsec1's order and
//! lifetime: the caller registers callbacks during initialization and the
//! input-URI transform reads a URI through the most recently registered set
//! that matches it. The library registers no callbacks of its own, so it
//! reads no resource the caller does not read for it; every read is bounded
//! by the policy's external-resource budgets.
//!
//! Writing to an output buffer over a transform pushes binary data into it
//! (or appends it to a buffer); reading from an input buffer pops it.

use std::ffi::{CStr, c_char, c_int, c_void};

use super::super::buffer::{XmlSecBuffer, xmlSecBufferAppend};
use super::super::errors::{self, check, here};
use super::super::list::{
    XmlSecPtrList, XmlSecPtrListKlass, xmlSecPtrListAdd, xmlSecPtrListEmpty, xmlSecPtrListFinalize,
    xmlSecPtrListInitialize,
};
use super::super::{contain, free, malloc, policy};
use super::builtin::klass;
use super::ctx::{Limit, charge, run_budget};
use super::{
    DATA_BIN, Global, MODE_POP, MODE_PUSH, WithContext, XmlSecTransform, XmlSecTransformCtx,
    XmlSecTransformKlass, context_or, valid, xmlSecTransformDefaultGetDataType,
    xmlSecTransformPopBin, xmlSecTransformPushBin, zero_list,
};

#[cfg(test)]
mod tests;

/// libxml2's `xmlInputMatchCallback`.
pub(crate) type MatchCallback = Option<unsafe extern "C" fn(*const c_char) -> c_int>;
/// libxml2's `xmlInputOpenCallback`.
pub(crate) type OpenCallback = Option<unsafe extern "C" fn(*const c_char) -> *mut c_void>;
/// libxml2's `xmlInputReadCallback`.
pub(crate) type ReadCallback =
    Option<unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> c_int>;
/// libxml2's `xmlInputCloseCallback`.
pub(crate) type CloseCallback = Option<unsafe extern "C" fn(*mut c_void) -> c_int>;

/// One registered set of input callbacks.
struct IoCallbacks {
    matches: unsafe extern "C" fn(*const c_char) -> c_int,
    open: OpenCallback,
    read: ReadCallback,
    close: CloseCallback,
}

unsafe extern "C" fn destroy_callbacks(item: *mut c_void) {
    if !item.is_null() {
        // SAFETY: every item of the callback list is a leaked `IoCallbacks`.
        drop(unsafe { Box::from_raw(item.cast::<IoCallbacks>()) });
    }
}

static IO_CALLBACK_LIST: XmlSecPtrListKlass = XmlSecPtrListKlass {
    name: c"io-callbacks-list".as_ptr().cast(),
    duplicate_item: None,
    destroy_item: Some(destroy_callbacks),
    debug_dump_item: None,
    debug_xml_dump_item: None,
};

/// The registered input callbacks, oldest first.
static IO_CALLBACKS: Global<XmlSecPtrList> = Global::new(zero_list());

/// `xmlSecIOInit`: an empty callback list with the default callbacks, of
/// which there are none.
///
/// # Safety
/// Called during initialization, while nothing reads the list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecIOInit() -> c_int {
    contain(-1, || {
        let here = here!("xmlSecIOInit");
        // SAFETY: the list has a fixed address and is not in use.
        if unsafe { xmlSecPtrListInitialize(IO_CALLBACKS.get(), &raw const IO_CALLBACK_LIST) } < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecPtrListInitialize");
            return -1;
        }
        // SAFETY: registering during initialization.
        if unsafe { xmlSecIORegisterDefaultCallbacks() } < 0 {
            errors::internal(here, std::ptr::null(), c"xmlSecIORegisterDefaultCallbacks");
            return -1;
        }
        0
    })
}

/// `xmlSecIOShutdown`: releases every registered set.
///
/// # Safety
/// Called during shutdown, while nothing reads the list.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecIOShutdown() {
    // SAFETY: the list has a fixed address and is not in use.
    contain((), || unsafe { xmlSecPtrListFinalize(IO_CALLBACKS.get()) });
}

/// `xmlSecIOCleanupCallbacks`: removes every registered set.
///
/// # Safety
/// As for [`xmlSecIOShutdown`].
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecIOCleanupCallbacks() {
    // SAFETY: the list has a fixed address and is not in use.
    contain((), || unsafe { xmlSecPtrListEmpty(IO_CALLBACKS.get()) });
}

/// `xmlSecIORegisterDefaultCallbacks`: libxmlsec1 registers file, HTTP and
/// FTP readers here; this library reads no resource itself, so it registers
/// none and the caller's own callbacks are the only way a URI is read.
///
/// # Safety
/// Callable during initialization.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecIORegisterDefaultCallbacks() -> c_int {
    0
}

/// `xmlSecIORegisterCallbacks`: adds a set of input callbacks, which takes
/// precedence over every set registered before it.
///
/// # Safety
/// Called during initialization; the callbacks are null or functions of
/// their signatures, callable while they stay registered.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecIORegisterCallbacks(
    matches: MatchCallback,
    open: OpenCallback,
    read: ReadCallback,
    close: CloseCallback,
) -> c_int {
    contain(-1, || {
        let Some(matches) = matches else {
            errors::assertion(here!("xmlSecIORegisterCallbacks"), c"matchFunc != NULL");
            return -1;
        };
        let item = Box::into_raw(Box::new(IoCallbacks {
            matches,
            open,
            read,
            close,
        }));
        // SAFETY: the list has a fixed address; it owns the item from here.
        if unsafe { xmlSecPtrListAdd(IO_CALLBACKS.get(), item.cast()) } < 0 {
            errors::internal(
                here!("xmlSecIORegisterCallbacks"),
                std::ptr::null(),
                c"xmlSecPtrListAdd",
            );
            // SAFETY: the list did not take the item.
            unsafe { destroy_callbacks(item.cast()) };
            return -1;
        }
        0
    })
}

/// The most recently registered set whose match callback accepts `uri`.
///
/// # Safety
/// `uri` is NUL-terminated; the list is initialized.
unsafe fn find_callbacks(uri: *const c_char) -> *mut IoCallbacks {
    let here = here!("xmlSecIOCallbackPtrListFind");
    // SAFETY: the list has a fixed address.
    let list = unsafe { &*IO_CALLBACKS.get() };
    if !std::ptr::eq(list.id, &raw const IO_CALLBACK_LIST) {
        errors::assertion(
            here,
            c"xmlSecPtrListCheckId(list, xmlSecIOCallbackPtrListId)",
        );
        return std::ptr::null_mut();
    }
    let items: &[*mut IoCallbacks] = if list.used == 0 || list.data.is_null() {
        &[]
    } else {
        // SAFETY: a list's first `used` items are its entries.
        unsafe { std::slice::from_raw_parts(list.data.cast(), list.used) }
    };
    for &item in items.iter().rev() {
        // SAFETY: the list holds the sets `xmlSecIORegisterCallbacks` made.
        let Some(callbacks) = (unsafe { item.as_ref() }) else {
            errors::assertion(here, c"callbacks != NULL");
            return std::ptr::null_mut();
        };
        // SAFETY: the caller's match callback, given a NUL-terminated URI.
        if unsafe { (callbacks.matches)(uri) } != 0 {
            return item;
        }
    }
    std::ptr::null_mut()
}

/// `uri` with `%XX` escapes decoded, as libxml2's `xmlURIUnescapeString`
/// decodes them: a `%` followed by two hexadecimal digits is one octet; any
/// other byte is kept.
fn unescape(uri: &[u8]) -> Vec<u8> {
    let hex = |byte: u8| char::from(byte).to_digit(16);
    let mut out = Vec::with_capacity(uri.len());
    let mut position = 0;
    while position < uri.len() {
        let byte = uri[position];
        if byte == b'%'
            && let (Some(high), Some(low)) = (
                uri.get(position + 1).copied().and_then(hex),
                uri.get(position + 2).copied().and_then(hex),
            )
        {
            // Two hexadecimal digits make one octet.
            out.push(u8::try_from(high * 16 + low).expect("two hexadecimal digits fit an octet"));
            position += 3;
        } else {
            out.push(byte);
            position += 1;
        }
    }
    out
}

/// The state of an input-URI transform: the callbacks reading its resource,
/// their context, and the octets read from it so far.
#[repr(C)]
struct InputUri {
    callbacks: *mut IoCallbacks,
    context: *mut c_void,
    read: usize,
}

static INPUT_URI: XmlSecTransformKlass = XmlSecTransformKlass {
    initialize: Some(input_uri_initialize),
    finalize: Some(input_uri_finalize),
    pop_bin: Some(input_uri_pop_bin),
    ..klass(
        size_of::<WithContext<InputUri>>(),
        c"input-uri".as_ptr().cast(),
        std::ptr::null(),
        0,
    )
};

/// The URI input klass.
pub(crate) fn input_uri() -> *const XmlSecTransformKlass {
    &raw const INPUT_URI
}

/// `xmlSecTransformInputURIGetKlass`.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformInputURIGetKlass() -> *const XmlSecTransformKlass {
    input_uri()
}

/// The state of the input-URI transform `$transform`, after libxmlsec1's
/// assertion inside the entry point `$func`, or `$ret` (nothing, without
/// `$ret`).
macro_rules! input_uri_or {
    ($transform:expr, $func:literal $(, $ret:expr)?) => {
        context_or!(
            $transform,
            InputUri,
            input_uri(),
            $func,
            c"xmlSecTransformCheckId(transform, xmlSecTransformInputURIId)"
            $(, $ret)?
        )
    };
}

/// `xmlSecTransformInputURIOpen`: opens `uri` through the most recently
/// registered callbacks that match it, trying the unescaped URI first and
/// the URI as given when no set matches that.
///
/// # Safety
/// `transform` is null or a valid transform; `uri` is null or
/// NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformInputURIOpen(
    transform: *mut XmlSecTransform,
    uri: *const u8,
) -> c_int {
    contain(-1, || {
        let state = input_uri_or!(transform, "xmlSecTransformInputURIOpen", -1);
        check!(
            !uri.is_null(),
            "xmlSecTransformInputURIOpen",
            c"uri != NULL",
            -1
        );
        check!(
            state.callbacks.is_null(),
            "xmlSecTransformInputURIOpen",
            c"ctx->clbks == NULL",
            -1
        );
        check!(
            state.context.is_null(),
            "xmlSecTransformInputURIOpen",
            c"ctx->clbksCtx == NULL",
            -1
        );
        // SAFETY: `uri` is NUL-terminated.
        let text = unsafe { CStr::from_ptr(uri.cast()) }.to_bytes();
        // The unescaped URI has no NUL unless an escape decodes one, which
        // ends the C string as it ends libxml2's.
        let mut unescaped = unescape(text);
        unescaped.push(0);
        for candidate in [unescaped.as_ptr().cast::<c_char>(), uri.cast()] {
            if !state.callbacks.is_null() {
                break;
            }
            // SAFETY: both candidates are NUL-terminated; a found set is a
            // registered one, whose open callback takes the URI.
            unsafe {
                state.callbacks = find_callbacks(candidate);
                if let Some(open) = state.callbacks.as_ref().and_then(|set| set.open) {
                    state.context = open(candidate);
                }
            }
        }
        if state.callbacks.is_null() || state.context.is_null() {
            errors::internal_with(
                here!("xmlSecTransformInputURIOpen"),
                c"input-uri".as_ptr(),
                c"ctx->clbks->opencallback",
                &format!("uri={}", String::from_utf8_lossy(text)),
            );
            return -1;
        }
        state.read = 0;
        0
    })
}

/// `xmlSecTransformInputURIClose`: closes the resource, when it is open and
/// its callbacks can close it.
///
/// # Safety
/// `transform` is null or a valid transform.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecTransformInputURIClose(
    transform: *mut XmlSecTransform,
) -> c_int {
    contain(-1, || {
        let state = input_uri_or!(transform, "xmlSecTransformInputURIClose", -1);
        // SAFETY: the set the transform opened with, while registered.
        let close = unsafe { state.callbacks.as_ref() }.and_then(|set| set.close);
        if let Some(close) = close
            && !state.context.is_null()
        {
            // libxmlsec1 ignores the close callback's result.
            // SAFETY: the context the open callback returned.
            unsafe { close(state.context) };
            state.context = std::ptr::null_mut();
            state.callbacks = std::ptr::null_mut();
        }
        0
    })
}

unsafe extern "C" fn input_uri_initialize(transform: *mut XmlSecTransform) -> c_int {
    let state = input_uri_or!(transform, "xmlSecTransformInputURIInitialize", -1);
    *state = InputUri {
        callbacks: std::ptr::null_mut(),
        context: std::ptr::null_mut(),
        read: 0,
    };
    0
}

unsafe extern "C" fn input_uri_finalize(transform: *mut XmlSecTransform) {
    let state = input_uri_or!(transform, "xmlSecTransformInputURIFinalize");
    // SAFETY: an input-URI transform being destroyed.
    let closed = unsafe { xmlSecTransformInputURIClose(transform) };
    if closed < 0 {
        // libxmlsec1 reports the failure and goes on finalizing.
        errors::internal_with(
            here!("xmlSecTransformInputURIFinalize"),
            c"input-uri".as_ptr(),
            c"xmlSecTransformInputURIClose",
            &format!("ret={closed}"),
        );
    }
    *state = InputUri {
        callbacks: std::ptr::null_mut(),
        context: std::ptr::null_mut(),
        read: 0,
    };
}

/// Reads the next octets of the resource through the caller's read
/// callback, within the policy's per-resource and per-run external-resource
/// budgets: a read asks for at most one octet more than both still allow,
/// so the resource cannot make the run read past them unnoticed.
unsafe extern "C" fn input_uri_pop_bin(
    transform: *mut XmlSecTransform,
    data: *mut u8,
    max_size: usize,
    size: *mut usize,
    ctx: *mut XmlSecTransformCtx,
) -> c_int {
    let state = input_uri_or!(transform, "xmlSecTransformInputURIPopBin", -1);
    check!(
        !data.is_null(),
        "xmlSecTransformInputURIPopBin",
        c"data != NULL",
        -1
    );
    check!(
        !size.is_null(),
        "xmlSecTransformInputURIPopBin",
        c"dataSize != NULL",
        -1
    );
    check!(
        !ctx.is_null(),
        "xmlSecTransformInputURIPopBin",
        c"transformCtx != NULL",
        -1
    );
    let here = here!("xmlSecTransformInputURIPopBin");
    let name = c"input-uri".as_ptr();
    // SAFETY: the set the transform opened with, while registered.
    let read = unsafe { state.callbacks.as_ref() }.and_then(|set| set.read);
    let Some(read) = read.filter(|_| !state.context.is_null()) else {
        // SAFETY: `size` is writable.
        unsafe { size.write(0) };
        return 0;
    };
    let Some(policy) = policy::verification_at(here) else {
        return -1;
    };
    let resources = &policy.resources;
    // SAFETY: the context's run budget.
    let budget = unsafe { run_budget(ctx) };
    let per_resource = Limit {
        name: "max_external_resource_bytes",
        max: resources.max_external_resource_bytes,
    };
    let per_run = Limit {
        name: "max_external_resource_total_bytes",
        max: resources.max_external_resource_total_bytes,
    };
    // Both counters stay within their limits: every charge below is checked.
    let allowance = (per_resource.max - state.read).min(per_run.max - budget.external_resources);
    let wanted = allowance
        .checked_add(1)
        .map_or(max_size, |room| room.min(max_size));
    let Ok(len) = c_int::try_from(wanted) else {
        errors::size_to_int_impossible(here, wanted);
        return -1;
    };
    // SAFETY: the caller's read callback with its context and `wanted`
    // writable bytes at `data`.
    let got = unsafe { read(state.context, data.cast(), len) };
    let Ok(got) = usize::try_from(got) else {
        errors::internal(here, name, c"ctx->clbks->readcallback");
        return -1;
    };
    if got > wanted {
        errors::invalid_data(
            here,
            name,
            &format!("the read callback returned {got} bytes for {wanted}"),
        );
        return -1;
    }
    if charge(&mut state.read, got, per_resource, here, name).is_none()
        || charge(&mut budget.external_resources, got, per_run, here, name).is_none()
    {
        return -1;
    }
    // SAFETY: `size` is writable.
    unsafe { size.write(got) };
    0
}

pub(crate) use xml_sec_libxml2::ffi::libxml2::{
    xml_output_buffer_close as xmlOutputBufferClose,
    xml_output_buffer_write as xmlOutputBufferWrite,
};
use xml_sec_libxml2::ffi::libxml2::{
    xml_output_buffer_create_io as xmlOutputBufferCreateIO,
    xml_parser_input_buffer_create_io as xmlParserInputBufferCreateIO,
};

/// `XML_CHAR_ENCODING_NONE`.
const ENCODING_NONE: c_int = 0;

/// What an I/O buffer over a transform reads from or writes to.
struct TransformIo {
    write: bool,
    transform: *mut XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
    /// The octets reading may return in all; reading past them fails.
    limit: Limit,
    /// The octets read so far.
    read: usize,
}

/// The transform I/O state of a callback, after libxmlsec1's assertions
/// inside the entry point at `here` (`write` is the mode the callback
/// serves, `None` for closing); the transform's name comes with it.
///
/// # Safety
/// `context` is null or a live [`TransformIo`].
unsafe fn state<'a>(
    context: *mut c_void,
    write: Option<bool>,
    here: errors::Here,
) -> Option<(&'a mut TransformIo, *const c_char)> {
    // SAFETY: by the caller's contract.
    let Some(io) = (unsafe { context.cast::<TransformIo>().as_mut() }) else {
        errors::assertion(here, c"buffer != NULL");
        return None;
    };
    if write.is_some_and(|write| write != io.write) {
        let mode = if io.write {
            c"buffer->mode == xmlSecTransformIOBufferModeRead"
        } else {
            c"buffer->mode == xmlSecTransformIOBufferModeWrite"
        };
        errors::assertion(here, mode);
        return None;
    }
    // SAFETY: the state names the transform it was created for.
    let Some((_, klass)) = (unsafe { valid(io.transform) }) else {
        errors::assertion(here, c"xmlSecTransformIsValid(buffer->transform)");
        return None;
    };
    if io.ctx.is_null() {
        errors::assertion(here, c"buffer->transformCtx != NULL");
        return None;
    }
    Some((io, klass.name.cast()))
}

unsafe extern "C" fn transform_write(
    context: *mut c_void,
    data: *const c_char,
    len: c_int,
) -> c_int {
    let here = here!("xmlSecTransformIOBufferWrite");
    // SAFETY: libxml2 passes the state it was created with.
    let Some((io, name)) = (unsafe { state(context, Some(true), here) }) else {
        return -1;
    };
    check!(
        !data.is_null(),
        "xmlSecTransformIOBufferWrite",
        c"buf != NULL",
        -1
    );
    let Ok(size) = usize::try_from(len) else {
        errors::int_to_size_impossible(here, len);
        return -1;
    };
    // SAFETY: `len` readable bytes at `data`.
    if unsafe { xmlSecTransformPushBin(io.transform, data.cast(), size, 0, io.ctx) } < 0 {
        errors::internal(here, name, c"xmlSecTransformPushBin");
        return -1;
    }
    len
}

unsafe extern "C" fn transform_read(context: *mut c_void, data: *mut c_char, len: c_int) -> c_int {
    let here = here!("xmlSecTransformIOBufferRead");
    // SAFETY: libxml2 passes the state it was created with.
    let Some((io, name)) = (unsafe { state(context, Some(false), here) }) else {
        return -1;
    };
    check!(
        !data.is_null(),
        "xmlSecTransformIOBufferRead",
        c"buf != NULL",
        -1
    );
    let Ok(mut size) = usize::try_from(len) else {
        errors::int_to_size_impossible(here, len);
        return -1;
    };
    // SAFETY: `len` writable bytes at `data`.
    if unsafe { xmlSecTransformPopBin(io.transform, data.cast(), size, &raw mut size, io.ctx) } < 0
    {
        errors::internal(here, name, c"xmlSecTransformPopBin");
        return -1;
    }
    if charge(&mut io.read, size, io.limit, here, name).is_none() {
        return -1;
    }
    // A pop returns at most the `len` octets asked for.
    c_int::try_from(size).expect("a pop returns at most the requested size")
}

unsafe extern "C" fn transform_close(context: *mut c_void) -> c_int {
    let here = here!("xmlSecTransformIOBufferClose");
    // SAFETY: libxml2 passes the state it was created with, closing it once.
    let Some((io, name)) = (unsafe { state(context, None, here) }) else {
        return -1;
    };
    // Writing ends with the final push that flushes the chain.
    let mut result = 0;
    if io.write {
        // SAFETY: the state's live transform and context.
        let flushed =
            unsafe { xmlSecTransformPushBin(io.transform, std::ptr::null(), 0, 1, io.ctx) };
        if flushed < 0 {
            errors::internal(here, name, c"xmlSecTransformPushBin");
            result = -1;
        }
    }
    // SAFETY: the state `create` allocated, closed once.
    unsafe { free(context) };
    result
}

/// A new I/O state for `transform`, reported from the entry point at `here`
/// when it cannot be allocated.
fn create(
    write: bool,
    (transform, ctx): (*mut XmlSecTransform, *mut XmlSecTransformCtx),
    limit: Limit,
    here: errors::Here,
) -> *mut c_void {
    let io = malloc(size_of::<TransformIo>()).cast::<TransformIo>();
    if io.is_null() {
        errors::malloc_failed(here, std::ptr::null(), size_of::<TransformIo>());
        return io.cast();
    }
    // SAFETY: a fresh allocation of the state's size.
    unsafe {
        io.write(TransformIo {
            write,
            transform,
            ctx,
            limit,
            read: 0,
        });
    }
    io.cast()
}

/// The checks both buffer constructors make: a valid transform, a context
/// and binary data in the direction `mode`; the transform's name.
///
/// # Safety
/// `transform` is null or a valid transform; `ctx` is null or a context.
unsafe fn buffer_target(
    transform: *mut XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
    mode: c_int,
    here: errors::Here,
) -> Option<*const c_char> {
    // SAFETY: by the caller's contract.
    let Some((_, klass)) = (unsafe { valid(transform) }) else {
        errors::assertion(here, c"xmlSecTransformIsValid(transform)");
        return None;
    };
    if ctx.is_null() {
        errors::assertion(here, c"transformCtx != NULL");
        return None;
    }
    let name = klass.name.cast();
    // SAFETY: by the caller's contract.
    let kind = unsafe { xmlSecTransformDefaultGetDataType(transform, mode, ctx) };
    if kind & DATA_BIN == 0 {
        let direction = if mode == MODE_PUSH { "push" } else { "pop" };
        errors::report(
            here,
            name,
            std::ptr::null(),
            errors::R_INVALID_TRANSFORM,
            &format!("{direction} binary data not supported, type=\"{kind}\""),
        );
        return None;
    }
    Some(name)
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
        let here = here!("xmlSecTransformCreateOutputBuffer");
        // SAFETY: by the caller's contract.
        let Some(name) = (unsafe { buffer_target(transform, ctx, MODE_PUSH, here) }) else {
            return std::ptr::null_mut();
        };
        let unbounded = Limit {
            name: "none",
            max: usize::MAX,
        };
        let io = create(
            true,
            (transform, ctx),
            unbounded,
            here!("xmlSecTransformIOBufferCreate"),
        );
        if io.is_null() {
            errors::internal(here, name, c"xmlSecTransformIOBufferCreate");
            return io;
        }
        // SAFETY: libxml2 keeps the state as the callbacks' context.
        let output = unsafe {
            xmlOutputBufferCreateIO(
                Some(transform_write),
                Some(transform_close),
                io,
                std::ptr::null_mut(),
            )
        };
        if output.is_null() {
            errors::xml_failed(here, name, c"xmlOutputBufferCreateIO");
            // SAFETY: the state libxml2 did not take.
            unsafe { free(io) };
        }
        output
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
        let unbounded = Limit {
            name: "none",
            max: usize::MAX,
        };
        // SAFETY: by the caller's contract.
        unsafe {
            bounded_input_buffer(
                transform,
                ctx,
                unbounded,
                here!("xmlSecTransformCreateInputBuffer"),
            )
        }
    })
}

/// A libxml2 input buffer popping binary data from `transform` that fails a
/// read past `limit` in all; failures are reported from the entry point at
/// `here`.
///
/// # Safety
/// As for [`xmlSecTransformCreateOutputBuffer`].
pub(crate) unsafe fn bounded_input_buffer(
    transform: *mut XmlSecTransform,
    ctx: *mut XmlSecTransformCtx,
    limit: Limit,
    here: errors::Here,
) -> *mut c_void {
    // SAFETY: by the caller's contract.
    let Some(name) = (unsafe { buffer_target(transform, ctx, MODE_POP, here) }) else {
        return std::ptr::null_mut();
    };
    let io = create(
        false,
        (transform, ctx),
        limit,
        here!("xmlSecTransformIOBufferCreate"),
    );
    if io.is_null() {
        errors::internal(here, name, c"xmlSecTransformIOBufferCreate");
        return io;
    }
    // SAFETY: libxml2 keeps the state as the callbacks' context.
    let input = unsafe {
        xmlParserInputBufferCreateIO(
            Some(transform_read),
            Some(transform_close),
            io,
            ENCODING_NONE,
        )
    };
    if input.is_null() {
        errors::xml_failed(here, name, c"xmlParserInputBufferCreateIO");
        // SAFETY: the state libxml2 did not take.
        unsafe { free(io) };
    }
    input
}

unsafe extern "C" fn buffer_write(context: *mut c_void, data: *const c_char, len: c_int) -> c_int {
    check!(
        !context.is_null(),
        "xmlSecBufferIOWrite",
        c"buf != NULL",
        -1
    );
    check!(!data.is_null(), "xmlSecBufferIOWrite", c"data != NULL", -1);
    let Ok(size) = usize::try_from(len) else {
        errors::assertion(here!("xmlSecBufferIOWrite"), c"len >= 0");
        return -1;
    };
    let here = here!("xmlSecBufferIOWrite");
    // SAFETY: libxml2 passes the buffer it was created with and `len`
    // readable bytes at `data`.
    if unsafe { xmlSecBufferAppend(context.cast(), data.cast(), size) } < 0 {
        errors::internal_with(
            here,
            std::ptr::null(),
            c"xmlSecBufferAppend",
            &format!("size={size}"),
        );
        return -1;
    }
    len
}

unsafe extern "C" fn buffer_close(context: *mut c_void) -> c_int {
    check!(
        !context.is_null(),
        "xmlSecBufferIOClose",
        c"buf != NULL",
        -1
    );
    0
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
