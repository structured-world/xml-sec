//! The generic error channel: our own function shaped like libxml2's
//! `xmlSetGenericErrorFunc`, through which the library's default error
//! reports are written, as libxmlsec1 writes them through libxml2's.
//! Without a handler the text goes to the standard error stream, as
//! libxml2's default handler writes it.

use std::ffi::{CString, c_char, c_void};

use parking_lot::Mutex;

/// libxml2's `xmlGenericErrorFunc`: a printf-style handler and its context.
pub type GenericErrorFunc = unsafe extern "C" fn(*mut c_void, *const c_char, ...);

/// The handler a caller installed, with its context's address.
static HANDLER: Mutex<Option<(GenericErrorFunc, usize)>> = Mutex::new(None);

/// `xmlSetGenericErrorFunc`: install `handler` with `context` for the
/// library's default error reports; null restores the standard error
/// stream.
///
/// # Safety
/// `handler` is null or callable with `context` and a `"%s"` format.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xsSetGenericErrorFunc(
    context: *mut c_void,
    handler: Option<GenericErrorFunc>,
) {
    *HANDLER.lock() = handler.map(|handler| (handler, context.expose_provenance()));
}

/// Write `text` through the installed handler, or to the standard error
/// stream. Text holding NUL is written up to it, as C reads it.
pub fn generic_error(text: &str) {
    let installed = *HANDLER.lock();
    let Some((handler, context)) = installed else {
        eprint!("{text}");
        return;
    };
    let end = text.find('\0').unwrap_or(text.len());
    let Ok(text) = CString::new(&text[..end]) else {
        return;
    };
    // SAFETY: the caller installed a handler of this signature, callable
    // with its context; the format consumes the one string argument. No lock
    // is held, so the handler may report again.
    unsafe {
        handler(
            std::ptr::with_exposed_provenance_mut(context),
            c"%s".as_ptr(),
            text.as_ptr(),
        );
    }
}
