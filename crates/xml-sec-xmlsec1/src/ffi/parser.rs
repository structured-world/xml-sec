//! `xmlsec/parser.h`: libxml2 parsing with libxmlsec1's parser options.
//!
//! The documents are libxml2's own trees, the representation every caller
//! of this tier works on, so libxml2 builds them with the options
//! libxmlsec1 documents (and a caller may change). The core's XML input and
//! resource policy applies when an operation projects the tree, as for a
//! tree the caller parsed itself.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use xml_sec_libxml2::ffi::XmlDoc;

use super::contain;

/// libxml2's `xmlParserCtxtPtr`, used only through libxml2 and the shim.
pub(crate) type ParserCtxt = *mut c_void;

unsafe extern "C" {
    fn xs_xmlsec1_default_parser_options() -> c_int;
    pub(crate) fn xs_xmlsec1_prepare_ctxt(ctxt: ParserCtxt, options: c_int);
    pub(crate) fn xs_xmlsec1_take_doc(ctxt: ParserCtxt) -> *mut XmlDoc;
    fn xs_xmlsec1_well_formed(ctxt: ParserCtxt) -> c_int;
    fn xs_xmlsec1_set_directory(ctxt: ParserCtxt, filename: *const c_char) -> c_int;
    pub(crate) fn xs_xmlsec1_push_input(ctxt: ParserCtxt, input: *mut c_void) -> c_int;
    pub(crate) fn xs_xmlsec1_free_ctxt(ctxt: ParserCtxt);

    fn xmlInitParser();
    fn xmlCreateFileParserCtxt(filename: *const c_char) -> ParserCtxt;
    fn xmlCreateMemoryParserCtxt(buffer: *const c_char, size: c_int) -> ParserCtxt;
    pub(crate) fn xmlCreatePushParserCtxt(
        sax: *mut c_void,
        user: *mut c_void,
        chunk: *const c_char,
        size: c_int,
        filename: *const c_char,
    ) -> ParserCtxt;
    pub(crate) fn xmlParseChunk(
        ctxt: ParserCtxt,
        chunk: *const c_char,
        size: c_int,
        terminate: c_int,
    ) -> c_int;
    pub(crate) fn xmlParseDocument(ctxt: ParserCtxt) -> c_int;
}

/// Whether a caller replaced the default options, and the replacement.
static OPTIONS_SET: AtomicBool = AtomicBool::new(false);
static OPTIONS: AtomicI32 = AtomicI32::new(0);

/// The parser options in effect.
pub(crate) fn options() -> c_int {
    if OPTIONS_SET.load(Ordering::Acquire) {
        OPTIONS.load(Ordering::Relaxed)
    } else {
        // SAFETY: a constant of the linked libxml2.
        unsafe { xs_xmlsec1_default_parser_options() }
    }
}

/// `xmlSecParserGetDefaultOptions`.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecParserGetDefaultOptions() -> c_int {
    contain(0, options)
}

/// `xmlSecParserSetDefaultOptions`: the options every later parse uses.
///
/// # Safety
/// Callable during initialization, like libxmlsec1's other globals.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecParserSetDefaultOptions(options: c_int) {
    contain((), || {
        OPTIONS.store(options, Ordering::Relaxed);
        OPTIONS_SET.store(true, Ordering::Release);
    });
}

/// `xmlSecParsePrepareCtxt`: applies the parser options to `ctxt`.
///
/// # Safety
/// `ctxt` is null or a live parser context.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecParsePrepareCtxt(ctxt: ParserCtxt) {
    contain((), || {
        if !ctxt.is_null() {
            // SAFETY: a live parser context.
            unsafe { xs_xmlsec1_prepare_ctxt(ctxt, options()) };
        }
    });
}

/// The document `ctxt` parsed when `parsed` holds, freeing the context.
///
/// # Safety
/// `ctxt` is a live parser context the caller gives up.
unsafe fn finish(ctxt: ParserCtxt, parsed: bool) -> *mut XmlDoc {
    // SAFETY: by the caller's contract; the context is freed last.
    unsafe {
        let doc = if parsed {
            xs_xmlsec1_take_doc(ctxt)
        } else {
            std::ptr::null_mut()
        };
        xs_xmlsec1_free_ctxt(ctxt);
        doc
    }
}

/// `xmlSecParseFile`: the well-formed document in `filename`.
///
/// # Safety
/// `filename` is null or NUL-terminated.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecParseFile(filename: *const c_char) -> *mut XmlDoc {
    contain(std::ptr::null_mut(), || {
        if filename.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: a NUL-terminated file name; the context is freed on every
        // path.
        unsafe {
            xmlInitParser();
            let ctxt = xmlCreateFileParserCtxt(filename);
            if ctxt.is_null() {
                return std::ptr::null_mut();
            }
            xs_xmlsec1_prepare_ctxt(ctxt, options());
            let parsed = xs_xmlsec1_set_directory(ctxt, filename) == 0
                && xmlParseDocument(ctxt) >= 0
                && xs_xmlsec1_well_formed(ctxt) != 0;
            finish(ctxt, parsed)
        }
    })
}

/// Pushes `size` bytes at `data` into a push parser; nothing to push
/// succeeds.
///
/// # Safety
/// `ctxt` is a live push parser; `data` is null or holds `size` bytes.
unsafe fn push(ctxt: ParserCtxt, data: *const u8, size: usize) -> bool {
    if data.is_null() || size == 0 {
        return true;
    }
    let Ok(len) = c_int::try_from(size) else {
        return false;
    };
    // SAFETY: by the caller's contract.
    unsafe { xmlParseChunk(ctxt, data.cast(), len, 0) == 0 }
}

/// `xmlSecParseMemoryExt`: the document of the three chunks in sequence.
///
/// # Safety
/// Each chunk is null or holds its size in bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecParseMemoryExt(
    prefix: *const u8,
    prefix_size: usize,
    buffer: *const u8,
    buffer_size: usize,
    postfix: *const u8,
    postfix_size: usize,
) -> *mut XmlDoc {
    contain(std::ptr::null_mut(), || {
        // SAFETY: the chunks by the caller's contract; the context is freed
        // on every path.
        unsafe {
            let ctxt = xmlCreatePushParserCtxt(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
                0,
                std::ptr::null(),
            );
            if ctxt.is_null() {
                return std::ptr::null_mut();
            }
            xs_xmlsec1_prepare_ctxt(ctxt, options());
            let parsed = push(ctxt, prefix, prefix_size)
                && push(ctxt, buffer, buffer_size)
                && push(ctxt, postfix, postfix_size)
                && xmlParseChunk(ctxt, std::ptr::null(), 0, 1) == 0;
            finish(ctxt, parsed)
        }
    })
}

/// `xmlSecParseMemory`: the document in `buffer`, which must be well formed
/// unless `recovery` is set.
///
/// # Safety
/// `buffer` is null or holds `size` bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecParseMemory(
    buffer: *const u8,
    size: usize,
    recovery: c_int,
) -> *mut XmlDoc {
    contain(std::ptr::null_mut(), || {
        let Ok(len) = c_int::try_from(size) else {
            return std::ptr::null_mut();
        };
        if buffer.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: `buffer` holds `size` bytes; the context is freed on every
        // path.
        unsafe {
            let ctxt = xmlCreateMemoryParserCtxt(buffer.cast(), len);
            if ctxt.is_null() {
                return std::ptr::null_mut();
            }
            xs_xmlsec1_prepare_ctxt(ctxt, options());
            let parsed =
                xmlParseDocument(ctxt) >= 0 && (xs_xmlsec1_well_formed(ctxt) != 0 || recovery != 0);
            finish(ctxt, parsed)
        }
    })
}
