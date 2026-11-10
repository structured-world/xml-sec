//! Error reporting (`errors.h`): libxmlsec1's reason table, its user and
//! system callbacks with their priority, `xmlSecError`, and the helpers the
//! library reports its own failures through.
//!
//! Every failing entry point reports through the callback with the reason
//! libxmlsec1 reports for the same condition; a layer that fails because of a
//! nested call reports that call, so a failure produces a chain of the same
//! shape. The file, line and function fields name this library's code.

use std::ffi::{CStr, VaList, c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use xml_sec_libxml2::ffi::libxml2;

use super::contain;

#[cfg(test)]
mod tests;

/// `xmlSecErrorsCallback`.
pub(crate) type ErrorsCallback = unsafe extern "C" fn(
    *const c_char,
    c_int,
    *const c_char,
    *const c_char,
    *const c_char,
    c_int,
    *const c_char,
);

/// `XMLSEC_ERRORS_R_XMLSEC_FAILED`.
pub(crate) const R_XMLSEC_FAILED: c_int = 1;
/// `XMLSEC_ERRORS_R_MALLOC_FAILED`.
pub(crate) const R_MALLOC_FAILED: c_int = 2;
/// `XMLSEC_ERRORS_R_XML_FAILED`.
pub(crate) const R_XML_FAILED: c_int = 5;
/// `XMLSEC_ERRORS_R_IO_FAILED`.
pub(crate) const R_IO_FAILED: c_int = 7;
/// `XMLSEC_ERRORS_R_NOT_IMPLEMENTED`.
pub(crate) const R_NOT_IMPLEMENTED: c_int = 9;
/// `XMLSEC_ERRORS_R_INVALID_SIZE`.
pub(crate) const R_INVALID_SIZE: c_int = 11;
/// `XMLSEC_ERRORS_R_INVALID_DATA`.
pub(crate) const R_INVALID_DATA: c_int = 12;
/// `XMLSEC_ERRORS_R_INVALID_TYPE`.
pub(crate) const R_INVALID_TYPE: c_int = 14;
/// `XMLSEC_ERRORS_R_INVALID_OPERATION`.
pub(crate) const R_INVALID_OPERATION: c_int = 15;
/// `XMLSEC_ERRORS_R_INVALID_STATUS`.
pub(crate) const R_INVALID_STATUS: c_int = 16;
/// `XMLSEC_ERRORS_R_INVALID_VERSION`.
pub(crate) const R_INVALID_VERSION: c_int = 19;
/// `XMLSEC_ERRORS_R_INVALID_NODE`.
pub(crate) const R_INVALID_NODE: c_int = 21;
/// `XMLSEC_ERRORS_R_INVALID_TRANSFORM`.
pub(crate) const R_INVALID_TRANSFORM: c_int = 31;
/// `XMLSEC_ERRORS_R_INVALID_URI_TYPE`.
pub(crate) const R_INVALID_URI_TYPE: c_int = 33;
/// `XMLSEC_ERRORS_R_TRANSFORM_DISABLED`.
pub(crate) const R_TRANSFORM_DISABLED: c_int = 35;
/// `XMLSEC_ERRORS_R_ASSERTION`.
pub(crate) const R_ASSERTION: c_int = 100;

/// libxmlsec1's reason table, in its order; positions past it hold no code
/// and no message.
static TABLE: [(c_int, &CStr); 53] = [
    (1, c"xmlsec library function failed"),
    (2, c"malloc function failed"),
    (3, c"strdup function failed"),
    (4, c"crypto library function failed"),
    (5, c"libxml2 library function failed"),
    (6, c"libxslt library function failed"),
    (7, c"io function failed"),
    (8, c"feature is disabled"),
    (9, c"feature is not implemented"),
    (10, c"invalid configuration"),
    (11, c"invalid size"),
    (12, c"invalid data"),
    (13, c"invalid result"),
    (14, c"invalid type"),
    (15, c"invalid operation"),
    (16, c"invalid status"),
    (17, c"invalid format"),
    (18, c"data do not match"),
    (19, c"invalid version"),
    (21, c"invalid node"),
    (22, c"invalid node content"),
    (23, c"invalid node attribute"),
    (25, c"missing node attribute"),
    (26, c"node already present"),
    (27, c"unexpected node"),
    (28, c"node node found"),
    (31, c"invalid transform"),
    (32, c"invalid transform key"),
    (33, c"invalid URI type"),
    (34, c"same document is required for transform"),
    (35, c"transform is disabled"),
    (36, c"invalid or unsupported algorithm"),
    (41, c"invalid key data"),
    (42, c"key data is not found"),
    (43, c"key data already exist"),
    (44, c"invalid key data size"),
    (45, c"key is not found"),
    (46, c"key data is disabled"),
    (51, c"maximum key retrieval level"),
    (52, c"key retrieval type mismatch"),
    (61, c"maximum encrypted key level"),
    (71, c"certificate verification failed"),
    (72, c"certificate is not found"),
    (73, c"certificate is revoked"),
    (74, c"certificate issuer check failed"),
    (75, c"certificate is not yet valid"),
    (76, c"certificate has expired"),
    (77, c"CRL verification failed"),
    (78, c"CRL is not yet valid"),
    (79, c"CRL has expired"),
    (81, c"Reference nodes are not found"),
    (82, c"Reference verification failed"),
    (100, c"assertion"),
];

/// `XMLSEC_ERRORS_MAX_NUMBER`.
const MAX_NUMBER: usize = 256;

/// The capacity of a formatted message, terminator included.
const MESSAGE_CAPACITY: usize = 1024;

/// The message a format that cannot be expanded reports instead.
const FATAL: &CStr = c"Can not format error message";

/// A callback slot: whether it was set, and the callback set (null disables
/// reporting). Unset, the system slot holds the default callback.
struct Slot {
    set: AtomicBool,
    callback: AtomicPtr<c_void>,
}

impl Slot {
    const fn new() -> Self {
        Self {
            set: AtomicBool::new(false),
            callback: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    fn store(&self, callback: Option<ErrorsCallback>) {
        let pointer = callback.map_or(std::ptr::null_mut(), |callback| callback as *mut c_void);
        self.callback.store(pointer, Ordering::Relaxed);
        self.set.store(true, Ordering::Release);
    }

    /// The callback set, or `None` when the slot was never set.
    fn load(&self) -> Option<Option<ErrorsCallback>> {
        if !self.set.load(Ordering::Acquire) {
            return None;
        }
        let pointer = self.callback.load(Ordering::Relaxed);
        // SAFETY: the slot holds null or a pointer `store` made from an
        // `ErrorsCallback`.
        Some(
            (!pointer.is_null())
                .then(|| unsafe { std::mem::transmute::<*mut c_void, ErrorsCallback>(pointer) }),
        )
    }
}

/// The callback the crypto layer sets; the default callback until then.
static SYSTEM: Slot = Slot::new();
/// The application's callback, which takes priority once set, even as null.
static USER: Slot = Slot::new();
/// Whether the default callback writes its line.
static PRINT: AtomicBool = AtomicBool::new(true);

/// The callback a report goes to now, if any.
fn current() -> Option<ErrorsCallback> {
    USER.load()
        .unwrap_or_else(|| SYSTEM.load().unwrap_or(Some(xmlSecErrorsDefaultCallback)))
}

/// `xmlSecErrorsInit`: nothing to initialize.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecErrorsInit() {}

/// `xmlSecErrorsShutdown`: nothing to release.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecErrorsShutdown() {}

/// `xmlSecErrorsSetCallback`: the application's callback, which takes
/// priority over the system one; null disables reporting.
///
/// # Safety
/// `callback` is null or a function of the callback's signature.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecErrorsSetCallback(callback: Option<ErrorsCallback>) {
    USER.store(callback);
}

/// `xmlSecErrorsSetSystemCallback`: the crypto layer's callback, used while
/// the application set none.
///
/// # Safety
/// `callback` is null or a function of the callback's signature.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecErrorsSetSystemCallback(callback: Option<ErrorsCallback>) {
    SYSTEM.store(callback);
}

/// `xmlSecErrorsDefaultCallbackEnableOutput`.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecErrorsDefaultCallbackEnableOutput(enabled: c_int) {
    PRINT.store(enabled != 0, Ordering::Relaxed);
}

/// `xmlSecErrorsGetCode`: the code at `pos` of the reason table, 0 past it.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecErrorsGetCode(pos: usize) -> c_int {
    TABLE.get(pos).map_or(0, |(code, _)| *code)
}

/// `xmlSecErrorsGetMsg`: the message at `pos` of the reason table, null past
/// it.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecErrorsGetMsg(pos: usize) -> *const c_char {
    TABLE
        .get(pos)
        .map_or(std::ptr::null(), |(_, message)| message.as_ptr())
}

/// `xmlSecErrorsPrintCryptoLibraryLogOnExitSet`: libxmlsec1 keeps the flag
/// for its OpenSSL layer to dump that library's error log at exit; the
/// providers here keep no such log, so the flag has no reader.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecErrorsPrintCryptoLibraryLogOnExitSet(_enabled: c_int) {}

/// `text` as bytes, or `fallback` for null.
///
/// # Safety
/// `text` is null or NUL-terminated.
unsafe fn bytes_or<'a>(text: *const c_char, fallback: &'a [u8]) -> &'a [u8] {
    if text.is_null() {
        fallback
    } else {
        // SAFETY: by the caller's contract.
        unsafe { CStr::from_ptr(text) }.to_bytes()
    }
}

/// `xmlSecErrorsDefaultCallback`: writes
/// `func=..:file=..:line=..:obj=..:subj=..:error=<reason>:<reason text>:<msg>`
/// through libxml2's generic error handler while output is enabled.
///
/// # Safety
/// Each string is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecErrorsDefaultCallback(
    file: *const c_char,
    line: c_int,
    func: *const c_char,
    object: *const c_char,
    subject: *const c_char,
    reason: c_int,
    msg: *const c_char,
) {
    contain((), || {
        if !PRINT.load(Ordering::Relaxed) {
            return;
        }
        let known = TABLE
            .iter()
            .take(MAX_NUMBER)
            .find(|(code, _)| *code == reason)
            .map_or(&b""[..], |(_, text)| text.to_bytes());
        let mut text = Vec::new();
        // SAFETY: the caller passes null or NUL-terminated strings.
        unsafe {
            text.extend_from_slice(b"func=");
            text.extend_from_slice(bytes_or(func, b"unknown"));
            text.extend_from_slice(b":file=");
            text.extend_from_slice(bytes_or(file, b"unknown"));
            text.extend_from_slice(format!(":line={line}:obj=").as_bytes());
            text.extend_from_slice(bytes_or(object, b"unknown"));
            text.extend_from_slice(b":subj=");
            text.extend_from_slice(bytes_or(subject, b"unknown"));
            text.extend_from_slice(format!(":error={reason}:").as_bytes());
            text.extend_from_slice(known);
            text.push(b':');
            text.extend_from_slice(bytes_or(msg, b""));
        }
        text.extend_from_slice(b"\n");
        let Ok(text) = std::ffi::CString::new(text) else {
            return;
        };
        if libxml2::available() {
            // SAFETY: libxml2 is available.
            unsafe { libxml2::xml_generic_error(&text) };
        } else {
            // libxml2's own handler writes to the standard error stream.
            eprint!("{}", text.to_string_lossy());
        }
    });
}

unsafe extern "C" {
    fn vsnprintf(buffer: *mut c_char, size: usize, format: *const c_char, args: VaList) -> c_int;
}

/// `xmlSecError`: formats `msg` with its arguments, as printf does, into at
/// most 1023 bytes and passes the report to the current callback.
///
/// # Safety
/// Each string is null or NUL-terminated; the arguments match `msg`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecError(
    file: *const c_char,
    line: c_int,
    func: *const c_char,
    object: *const c_char,
    subject: *const c_char,
    reason: c_int,
    msg: *const c_char,
    args: ...
) {
    let Some(callback) = current() else {
        return;
    };
    let mut message = [0 as c_char; MESSAGE_CAPACITY];
    if !msg.is_null() {
        // SAFETY: the buffer holds its capacity; the caller's arguments match
        // the format.
        let written = unsafe { vsnprintf(message.as_mut_ptr(), MESSAGE_CAPACITY, msg, args) };
        if written < 0 {
            for (slot, byte) in message.iter_mut().zip(FATAL.to_bytes_with_nul()) {
                *slot = byte.cast_signed();
            }
        }
        message[MESSAGE_CAPACITY - 1] = 0;
    }
    // SAFETY: the callback has the callback's signature; every string is
    // the caller's or the NUL-terminated buffer.
    unsafe { callback(file, line, func, object, subject, reason, message.as_ptr()) };
}

/// Where the library reports a failure from: its source file and line, and
/// the entry point that failed.
#[derive(Clone, Copy)]
pub(crate) struct Here {
    pub(crate) file: *const c_char,
    pub(crate) line: u32,
    pub(crate) func: *const c_char,
}

/// The location of the call, inside the entry point named `$func`.
macro_rules! here {
    ($func:literal) => {
        $crate::ffi::errors::Here {
            file: concat!(file!(), "\0").as_ptr().cast(),
            line: line!(),
            func: concat!($func, "\0").as_ptr().cast(),
        }
    };
}
pub(crate) use here;

/// Reports one failure of the library to the current callback; `message` is
/// truncated to 1023 bytes, as `xmlSecError` truncates.
pub(crate) fn report(
    here: Here,
    object: *const c_char,
    subject: *const c_char,
    reason: c_int,
    message: &str,
) {
    let Some(callback) = current() else {
        return;
    };
    let mut bytes: Vec<u8> = message.bytes().take_while(|byte| *byte != 0).collect();
    bytes.truncate(MESSAGE_CAPACITY - 1);
    let Ok(message) = std::ffi::CString::new(bytes) else {
        return;
    };
    let line = c_int::try_from(here.line).unwrap_or(c_int::MAX);
    // SAFETY: the callback has the callback's signature; the strings are
    // static, the caller's live ones, or the NUL-terminated message.
    unsafe {
        callback(
            here.file,
            line,
            here.func,
            object,
            subject,
            reason,
            message.as_ptr(),
        );
    }
}

/// libxmlsec1's `xmlSecInternalError`: the call `failed` failed.
pub(crate) fn internal(here: Here, object: *const c_char, failed: &CStr) {
    report(here, object, failed.as_ptr(), R_XMLSEC_FAILED, " ");
}

/// libxmlsec1's `xmlSecAssert`: the precondition `expression` does not hold.
pub(crate) fn assertion(here: Here, expression: &CStr) {
    report(
        here,
        std::ptr::null(),
        expression.as_ptr(),
        R_ASSERTION,
        " ",
    );
}

/// libxmlsec1's `xmlSecMallocError`: an allocation of `size` bytes failed.
pub(crate) fn malloc_failed(here: Here, object: *const c_char, size: usize) {
    report(
        here,
        object,
        c"xmlMalloc".as_ptr(),
        R_MALLOC_FAILED,
        &format!("size={size}"),
    );
}
