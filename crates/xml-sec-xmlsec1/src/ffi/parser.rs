//! `xmlsec/parser.h`: libxml2 parsing with libxmlsec1's parser options.
//!
//! The documents are libxml2's own trees, the representation every caller
//! of this tier works on, so libxml2 builds them with the options
//! libxmlsec1 documents (and a caller may change). The core's XML input and
//! resource policy applies when an operation projects the tree, as for a
//! tree the caller parsed itself.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use xml_sec_libxml2::ffi::libxml2::{
    self, xml_create_file_parser_ctxt as xmlCreateFileParserCtxt,
    xml_create_memory_parser_ctxt as xmlCreateMemoryParserCtxt, xml_init_parser as xmlInitParser,
};
pub(crate) use xml_sec_libxml2::ffi::libxml2::{
    xml_create_push_parser_ctxt as xmlCreatePushParserCtxt, xml_parse_chunk as xmlParseChunk,
    xml_parse_document as xmlParseDocument,
};
use xml_sec_libxml2::ffi::{XmlDoc, XmlParserCtxt};

use super::contain;

#[cfg(test)]
mod tests;

/// libxml2's `xmlParserCtxtPtr`, opaque except for its leading members.
pub(crate) type ParserCtxt = *mut c_void;

// libxml2's `xmlParserOption` values, part of its ABI.
const XML_PARSE_NOENT: c_int = 1 << 1;
const XML_PARSE_DTDLOAD: c_int = 1 << 2;
const XML_PARSE_DTDATTR: c_int = 1 << 3;
const XML_PARSE_NONET: c_int = 1 << 11;
const XML_PARSE_NODICT: c_int = 1 << 12;
const XML_PARSE_HUGE: c_int = 1 << 19;
const XML_PARSE_NO_XXE: c_int = 1 << 23;

/// The release, as `LIBXML_VERSION`, that added `XML_PARSE_NO_XXE`.
const NO_XXE_RELEASE: u32 = 21300;

/// libxmlsec1's default parser options for the loaded libxml2: no network,
/// no external entity or external DTD, no shared dictionary, no libxml2 size
/// ceilings. From libxml2 2.13 these are libxmlsec1's options:
/// `XML_PARSE_NO_XXE` keeps internal entity substitution and DTD attribute
/// defaults inside the document. Older libxml2 has no such switch, and the
/// same entity and DTD options would read local files an untrusted document
/// names, so they stay off there; internal entity references then remain
/// reference nodes.
fn default_options() -> c_int {
    let base = XML_PARSE_NONET | XML_PARSE_NODICT | XML_PARSE_HUGE;
    match libxml2::version() {
        Some(version) if version >= NO_XXE_RELEASE => {
            base | XML_PARSE_NO_XXE | XML_PARSE_NOENT | XML_PARSE_DTDLOAD | XML_PARSE_DTDATTR
        }
        _ => base,
    }
}

/// Whether a caller replaced the default options, and the replacement.
static OPTIONS_SET: AtomicBool = AtomicBool::new(false);
static OPTIONS: AtomicI32 = AtomicI32::new(0);

/// The parser options in effect.
pub(crate) fn options() -> c_int {
    if OPTIONS_SET.load(Ordering::Acquire) {
        OPTIONS.load(Ordering::Relaxed)
    } else {
        default_options()
    }
}

/// Applies `options` and nothing else to `ctxt`: libxmlsec1 additionally
/// forces entity substitution and external-subset loading on libxml2 older
/// than 2.13, which loads external entities whatever the options say.
///
/// # Safety
/// libxml2 is available; `ctxt` is a live parser context.
pub(crate) unsafe fn prepare_ctxt(ctxt: ParserCtxt, options: c_int) {
    // SAFETY: by the caller's contract. `xmlCtxtSetOptions` exists from
    // 2.13 on, where it also resets options `xmlCtxtUseOptions` only adds.
    unsafe {
        let _ = libxml2::xml_ctxt_set_options(ctxt, options);
        libxml2::xml_ctxt_use_options(ctxt, options);
    }
}

/// The document `ctxt` parsed, which the context no longer owns.
///
/// # Safety
/// `ctxt` is a live parser context.
pub(crate) unsafe fn take_doc(ctxt: ParserCtxt) -> *mut XmlDoc {
    let ctxt = ctxt.cast::<XmlParserCtxt>();
    // SAFETY: `myDoc` is among the leading members every release shares.
    unsafe {
        let doc = (*ctxt).my_doc;
        (*ctxt).my_doc = std::ptr::null_mut();
        doc
    }
}

/// Whether the document `ctxt` parsed is well formed.
///
/// # Safety
/// `ctxt` is a live parser context.
unsafe fn well_formed(ctxt: ParserCtxt) -> bool {
    // SAFETY: `wellFormed` is among the leading members every release shares.
    unsafe { (*ctxt.cast::<XmlParserCtxt>()).well_formed != 0 }
}

/// Pushes `input` on the context's input stack.
///
/// # Safety
/// libxml2 is available; `ctxt` is a live parser context and `input` a live
/// input stream.
pub(crate) unsafe fn push_input(ctxt: ParserCtxt, input: *mut c_void) -> c_int {
    // SAFETY: by the caller's contract.
    unsafe { libxml2::xml_ctxt_push_input(ctxt, input) }
}

/// Frees the context and any document it still owns.
///
/// # Safety
/// libxml2 is available; `ctxt` is a live parser context the caller gives up.
pub(crate) unsafe fn free_ctxt(ctxt: ParserCtxt) {
    // SAFETY: by the caller's contract; the document is freed before the
    // context that refers to it.
    unsafe {
        let doc = take_doc(ctxt);
        if !doc.is_null() {
            libxml2::xml_free_doc(doc);
        }
        libxml2::xml_free_parser_ctxt(ctxt);
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
        if !ctxt.is_null() && libxml2::available() {
            // SAFETY: a live parser context of the loaded libxml2.
            unsafe { prepare_ctxt(ctxt, options()) };
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
            take_doc(ctxt)
        } else {
            std::ptr::null_mut()
        };
        free_ctxt(ctxt);
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
        if filename.is_null() || !libxml2::available() {
            return std::ptr::null_mut();
        }
        // SAFETY: a NUL-terminated file name; the context is freed on every
        // path. libxml2's file context records the file's directory itself,
        // which libxmlsec1 sets again.
        unsafe {
            xmlInitParser();
            let ctxt = xmlCreateFileParserCtxt(filename);
            if ctxt.is_null() {
                return std::ptr::null_mut();
            }
            prepare_ctxt(ctxt, options());
            let parsed = xmlParseDocument(ctxt) >= 0 && well_formed(ctxt);
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
        if !libxml2::available() {
            return std::ptr::null_mut();
        }
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
            prepare_ctxt(ctxt, options());
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
        if buffer.is_null() || !libxml2::available() {
            return std::ptr::null_mut();
        }
        // SAFETY: `buffer` holds `size` bytes; the context is freed on every
        // path.
        unsafe {
            let ctxt = xmlCreateMemoryParserCtxt(buffer.cast(), len);
            if ctxt.is_null() {
                return std::ptr::null_mut();
            }
            prepare_ctxt(ctxt, options());
            let parsed = xmlParseDocument(ctxt) >= 0 && (well_formed(ctxt) || recovery != 0);
            finish(ctxt, parsed)
        }
    })
}
