//! `xmlsec/parser.h`: documents parsed from memory by the core, under the
//! library policy.
//!
//! The library reads no file: a program reads its document and passes the
//! bytes, so `xmlSecParseFile` is not part of the surface. libxml2 parser
//! contexts do not exist either, so `xmlSecParsePrepareCtxt` is not offered;
//! the parser options are kept for the shape of the interface and do not
//! change a parse, which the library policy governs.

use std::ffi::c_int;
use std::sync::atomic::{AtomicI32, Ordering};

use super::contain;
use super::errors::{self, check, here};
use super::tree::XmlDoc;

#[cfg(test)]
mod tests;

// libxml2's `xmlParserOption` values libxmlsec1 sets by default, part of
// libxmlsec1's interface: `XML_PARSE_NONET`, `XML_PARSE_NODICT`,
// `XML_PARSE_HUGE`, `XML_PARSE_NO_XXE`, `XML_PARSE_NOENT`,
// `XML_PARSE_DTDLOAD` and `XML_PARSE_DTDATTR`.
const DEFAULT_OPTIONS: c_int =
    (1 << 11) | (1 << 12) | (1 << 19) | (1 << 23) | (1 << 1) | (1 << 2) | (1 << 3);

/// The parser options a caller set, returned as set.
static OPTIONS: AtomicI32 = AtomicI32::new(DEFAULT_OPTIONS);

/// `xmlSecParserGetDefaultOptions`.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecParserGetDefaultOptions() -> c_int {
    contain(0, || OPTIONS.load(Ordering::Relaxed))
}

/// `xmlSecParserSetDefaultOptions`: the options later calls return; parsing
/// follows the library policy whatever they are.
///
/// # Safety
/// Callable at any time.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecParserSetDefaultOptions(options: c_int) {
    contain((), || OPTIONS.store(options, Ordering::Relaxed));
}

/// The document in `bytes`, parsed by the core; failures are reported from
/// the entry point at `here`.
pub(crate) fn parse(bytes: &[u8], here: errors::Here) -> *mut XmlDoc {
    parse_parts(&[bytes], here)
}

/// The document in `bytes`, as [`parse`], under `policy`, the revision of
/// the operation that parses it.
pub(crate) fn parse_under(
    bytes: &[u8],
    here: errors::Here,
    policy: &impl xml_sec::document::XmlDocumentPolicy,
) -> *mut XmlDoc {
    parsed(
        &xml_sec_libxml2::document::parse_parts_under(&[bytes], policy),
        here,
    )
}

/// The document of `parts` in sequence, as [`parse`]; parts too large
/// together are refused before they are joined.
fn parse_parts(parts: &[&[u8]], here: errors::Here) -> *mut XmlDoc {
    parsed(&xml_sec_libxml2::document::parse_parts(parts), here)
}

/// The document a parse returned, or null with the failure reported from
/// the entry point at `here`.
fn parsed(
    result: &Result<usize, xml_sec_libxml2::document::DocumentError>,
    here: errors::Here,
) -> *mut XmlDoc {
    if let Ok(doc) = result {
        xml_sec_libxml2::nodes::pointer_of(*doc)
    } else {
        // The reason is the tree layer's last error, which the report reads.
        errors::xml_failed(here, std::ptr::null(), c"xmlReadMemory");
        std::ptr::null_mut()
    }
}

/// The bytes of a chunk, empty for null.
///
/// # Safety
/// `data` is null or holds `size` bytes.
unsafe fn chunk<'a>(data: *const u8, size: usize) -> &'a [u8] {
    if data.is_null() {
        &[]
    } else {
        // SAFETY: by the caller's contract.
        unsafe { std::slice::from_raw_parts(data, size) }
    }
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
        // SAFETY: the chunks by the caller's contract.
        let parts = unsafe {
            [
                chunk(prefix, prefix_size),
                chunk(buffer, buffer_size),
                chunk(postfix, postfix_size),
            ]
        };
        parse_parts(&parts, here!("xmlSecParseMemoryExt"))
    })
}

/// `xmlSecParseMemory`: the document in `buffer`. The core produces only
/// well-formed documents, so `recovery` changes nothing.
///
/// # Safety
/// `buffer` is null or holds `size` bytes.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xmlSecParseMemory(
    buffer: *const u8,
    size: usize,
    _recovery: c_int,
) -> *mut XmlDoc {
    contain(std::ptr::null_mut(), || {
        check!(
            !buffer.is_null(),
            "xmlSecParseMemory",
            c"buffer != NULL",
            std::ptr::null_mut()
        );
        // SAFETY: `buffer` holds `size` bytes by the caller's contract.
        parse(unsafe { chunk(buffer, size) }, here!("xmlSecParseMemory"))
    })
}
