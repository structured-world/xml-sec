//! The generic error channel: our own function shaped like libxml2's
//! `xmlSetGenericErrorFunc`, through which the library's default error
//! reports are written, as libxmlsec1 writes them through libxml2's.
//! Without a handler the text goes to the standard error stream, as
//! libxml2's default handler writes it.

use std::cell::Cell;
use std::ffi::{CString, c_char, c_void};

/// libxml2's `xmlGenericErrorFunc`: a printf-style handler and its context.
pub type GenericErrorFunc = unsafe extern "C" fn(*mut c_void, *const c_char, ...);

// no-std: a caller-provided error sink.
std::thread_local! {
    /// The handler this thread installed, with its context's address: each
    /// thread has its own, as libxml2 keeps the generic error handler in its
    /// per-thread state.
    static HANDLER: Cell<Option<(GenericErrorFunc, usize)>> = const { Cell::new(None) };
}

/// `xmlSetGenericErrorFunc`: install `handler` with `context` for this
/// thread's default error reports; null restores the standard error
/// stream.
///
/// # Safety
/// `handler` is null or callable with `context` and a `"%s"` format.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsSetGenericErrorFunc(
    context: *mut c_void,
    handler: Option<GenericErrorFunc>,
) {
    HANDLER.set(handler.map(|handler| (handler, context.expose_provenance())));
}

/// The handler this thread installed, with its context's address.
fn installed() -> Option<(GenericErrorFunc, usize)> {
    HANDLER.get()
}

/// Write `text` through this thread's handler, or to the standard error
/// stream. Text holding NUL is written up to it, as C reads it.
pub fn generic_error(text: &str) {
    let Some((handler, context)) = installed() else {
        eprint!("{text}");
        return;
    };
    let end = text.find('\0').unwrap_or(text.len());
    let Ok(text) = CString::new(&text[..end]) else {
        return;
    };
    // SAFETY: the caller installed a handler of this signature, callable
    // with its context; the format consumes the one string argument. The
    // handler was copied out, so it may report again.
    unsafe {
        handler(
            std::ptr::with_exposed_provenance_mut(context),
            c"%s".as_ptr(),
            text.as_ptr(),
        );
    }
}

#[cfg(test)]
mod tests;
